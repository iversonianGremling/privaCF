//! The node engine — the heart of the MVP. Ties identity, the mock beacon, the chain, the trait
//! seams, and TCP gossip into the per-epoch loop (SPEC §4.1 / §6.4):
//! derive `epoch_id`, build + publish `commit_T`, gossip, and append the round-robin proposer's
//! block. Block-driven: each height's designated proposer assembles after a window; everyone else
//! appends the broadcast block (and syncs on timeout).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::SeedableRng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tracing::{debug, info};

use crate::beacon::next_beacon;
use crate::chain::{Block, BlockHeader, Chain};
use crate::commit::{CommitT, StubVerEnc, VerEnc};
use crate::consensus::{Proposer, RoundRobinProposer};
use crate::epoch::EpochTransaction;
use crate::field::{add_mod, from_u64, random_field, sub_mod, to_u64};
use crate::identity::NodeIdentity;
use crate::message::Message;
use crate::transport::{read_frame, write_frame};

type PeersMap = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

/// The genesis validator set for a seed-derived demo/test network: node `i` has identity
/// `from_seed(i)` and listens on `127.0.0.1:(base_port + i)`. Lets every node know every peer id
/// up front (the round-robin proposer set) without a config file.
pub fn genesis_validator_set(nodes: u64, base_port: u16) -> Vec<([u8; 32], String)> {
    (0..nodes)
        .map(|i| {
            let id = NodeIdentity::from_seed(i);
            (id.peer_id(), format!("127.0.0.1:{}", base_port + i as u16))
        })
        .collect()
}

/// Static genesis configuration for a node.
#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: String,
    /// All genesis validators `(peer_id, addr)` — including this node.
    pub genesis_validators: Vec<([u8; 32], String)>,
    pub window_ms: u64,
    /// Stop after producing this height (demo/test bound).
    pub max_height: u64,
    /// Keep serving peers for this long after reaching `max_height`.
    pub grace_ms: u64,
}

/// What a finished node reports (for the demo summary / test assertions).
#[derive(Clone, Debug)]
pub struct NodeOutcome {
    pub peer_id: [u8; 32],
    pub head_hash: [u8; 32],
    pub blocks_len: usize,
    /// (height, epoch_id) this node used each epoch — for rotation/distinctness checks.
    pub epoch_ids: Vec<(u64, u64)>,
    /// True iff `s₁ + s₂ = null_v` held for every epoch (publish-`s₁` split correctness).
    pub split_ok: bool,
}

pub struct Node {
    identity: Arc<NodeIdentity>,
    config: NodeConfig,
    proposer: RoundRobinProposer,
    verenc: StubVerEnc,
    validators_sorted: Vec<[u8; 32]>,
}

impl Node {
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> Self {
        let mut validators_sorted: Vec<[u8; 32]> =
            config.genesis_validators.iter().map(|(id, _)| *id).collect();
        validators_sorted.sort();
        validators_sorted.dedup();
        Self {
            identity: Arc::new(identity),
            config,
            proposer: RoundRobinProposer,
            verenc: StubVerEnc,
            validators_sorted,
        }
    }

    fn proposer_for(&self, height: u64) -> [u8; 32] {
        self.proposer.proposer_for(height, &self.validators_sorted)
    }

    /// Semantic block validity (the checks the chain itself can't make — it lacks the validator set).
    fn valid_block(&self, chain: &Chain, b: &Block) -> bool {
        let head = &chain.head().header;
        if b.header.height != head.height + 1 {
            return false;
        }
        if b.header.prev_block_hash != chain.head_hash() {
            return false;
        }
        if b.header.beacon_t != next_beacon(head.beacon_t, b.header.height) {
            return false;
        }
        if b.header.proposer_peer != self.proposer_for(b.header.height) {
            return false;
        }
        b.header.verify_sig()
    }

    /// Proposer assembles block `T` from the pending pool.
    fn assemble_block(
        &self,
        chain: &Chain,
        t: u64,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
    ) -> Block {
        let beacon_t = next_beacon(chain.head().header.beacon_t, t);
        let prev = chain.head_hash();
        let my_epoch_id = to_u64(self.identity.epoch_id(from_u64(beacon_t)));
        let mut txs: Vec<EpochTransaction> =
            pending.iter().filter(|((h, _), _)| *h == t).map(|(_, v)| v.clone()).collect();
        txs.sort_by_key(|t| t.epoch_id);
        pending.retain(|(h, _), _| *h != t);
        let header = BlockHeader::create(&self.identity, t, beacon_t, prev, my_epoch_id);
        Block { header, txs }
    }

    fn gossip(peers: &PeersMap, msg: Message) {
        let map = peers.lock().unwrap();
        for tx in map.values() {
            let _ = tx.send(msg.clone());
        }
    }

    /// Run the node to completion (until `max_height` + grace). Returns its outcome.
    pub async fn run(self) -> NodeOutcome {
        let peers: PeersMap = Arc::new(Mutex::new(HashMap::new()));
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<Message>();
        let _keepalive = inbox_tx.clone(); // keep the inbox open even with zero connections
        let my_id = self.identity.peer_id();
        let my_hello = Message::Hello { peer_id: my_id, listen_addr: self.config.listen_addr.clone() };

        // --- networking: listener (accept peers with id < mine) + dialers (peers with id > mine) ---
        let listener = TcpListener::bind(&self.config.listen_addr).await.expect("bind");
        {
            let peers = peers.clone();
            let inbox = inbox_tx.clone();
            let hello = my_hello.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        tokio::spawn(run_conn(stream, hello.clone(), inbox.clone(), peers.clone()));
                    }
                }
            });
        }
        for (pid, addr) in self.config.genesis_validators.iter() {
            if *pid > my_id {
                let addr = addr.clone();
                let peers = peers.clone();
                let inbox = inbox_tx.clone();
                let hello = my_hello.clone();
                tokio::spawn(async move {
                    loop {
                        if let Ok(stream) = TcpStream::connect(&addr).await {
                            run_conn(stream, hello.clone(), inbox.clone(), peers.clone()).await;
                        }
                        tokio::time::sleep(Duration::from_millis(150)).await; // retry on drop
                    }
                });
            }
        }
        // give connections a moment to establish
        tokio::time::sleep(Duration::from_millis(400)).await;
        info!(peer = %hex::encode(&my_id[..4]), "node up, entering epoch loop");

        // --- epoch engine ---
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut chain = Chain::genesis();
        let mut pending: HashMap<(u64, u64), EpochTransaction> = HashMap::new();
        let mut epoch_ids: Vec<(u64, u64)> = Vec::new();
        let mut split_ok = true;
        let mut submitted: Option<u64> = None;
        let mut propose_deadline: Option<Instant> = None;
        let mut sync_deadline: Option<Instant> = None;
        let mut done_at: Option<Instant> = None;
        let window = Duration::from_millis(self.config.window_ms);
        let mut ticker = interval(Duration::from_millis(15));

        loop {
            let head_h = chain.head().header.height;

            // termination: produced up to max_height, then serve a grace period
            if head_h >= self.config.max_height {
                let dl = *done_at.get_or_insert_with(|| {
                    Instant::now() + Duration::from_millis(self.config.grace_ms)
                });
                if Instant::now() >= dl {
                    break;
                }
            }

            // entering a new height: derive identity, build + gossip our tx, arm timers
            let t = head_h + 1;
            if head_h < self.config.max_height && submitted != Some(t) {
                let beacon_t = next_beacon(chain.head().header.beacon_t, t);
                let epoch_id_fp = self.identity.epoch_id(from_u64(beacon_t));
                let epoch_id = to_u64(epoch_id_fp);
                let s2 = random_field(&mut rng);
                let s1 = sub_mod(self.identity.null_v, s2);
                split_ok &= add_mod(s1, s2) == self.identity.null_v;
                let commit = CommitT { s1: to_u64(s1), d_t: self.verenc.encrypt(s2, epoch_id_fp) };
                let tx = EpochTransaction::create(&self.identity, t, epoch_id, commit);
                pending.insert((t, epoch_id), tx.clone());
                epoch_ids.push((t, epoch_id));
                Self::gossip(&peers, Message::Tx(tx));
                submitted = Some(t);
                if self.proposer_for(t) == my_id {
                    propose_deadline = Some(Instant::now() + window);
                    sync_deadline = None;
                    debug!(height = t, "i am proposer");
                } else {
                    propose_deadline = None;
                    sync_deadline = Some(Instant::now() + window * 4);
                }
            }

            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(dl) = propose_deadline {
                        if Instant::now() >= dl {
                            let block = self.assemble_block(&chain, t, &mut pending);
                            info!(height = t, txs = block.txs.len(), "proposing block");
                            let _ = chain.try_append(block.clone());
                            Self::gossip(&peers, Message::Block(block));
                            propose_deadline = None;
                        }
                    }
                    if let Some(dl) = sync_deadline {
                        if Instant::now() >= dl {
                            Self::gossip(&peers, Message::GetChain {
                                from_height: chain.head().header.height + 1,
                            });
                            sync_deadline = Some(Instant::now() + window * 4);
                        }
                    }
                }
                Some(msg) = inbox_rx.recv() => {
                    match msg {
                        Message::Tx(tx) => {
                            if tx.verify_sig() {
                                pending.insert((tx.height, tx.epoch_id), tx);
                            }
                        }
                        Message::Block(b) => {
                            if self.valid_block(&chain, &b) {
                                debug!(height = b.header.height, "appending peer block");
                                let _ = chain.try_append(b);
                            }
                        }
                        Message::GetChain { from_height } => {
                            let bs = chain.blocks_from(from_height);
                            if !bs.is_empty() {
                                Self::gossip(&peers, Message::ChainRange(bs));
                            }
                        }
                        Message::ChainRange(bs) => {
                            for b in bs {
                                if self.valid_block(&chain, &b) {
                                    let _ = chain.try_append(b);
                                }
                            }
                        }
                        Message::Hello { .. } => {}
                    }
                }
            }
        }

        info!(
            peer = %hex::encode(&my_id[..4]),
            blocks = chain.blocks.len(),
            head = %hex::encode(&chain.head_hash()[..4]),
            "node done"
        );
        NodeOutcome {
            peer_id: my_id,
            head_hash: chain.head_hash(),
            blocks_len: chain.blocks.len(),
            epoch_ids,
            split_ok,
        }
    }
}

/// Drive one peer connection: handshake (exchange Hello), register a writer, forward reads to inbox.
async fn run_conn(stream: TcpStream, my_hello: Message, inbox: mpsc::UnboundedSender<Message>, peers: PeersMap) {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    if write_frame(&mut wr, &my_hello).await.is_err() {
        return;
    }
    let remote = match read_frame(&mut rd).await {
        Ok(Message::Hello { peer_id, .. }) => peer_id,
        _ => return,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    peers.lock().unwrap().insert(remote, tx);
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if write_frame(&mut wr, &m).await.is_err() {
                break;
            }
        }
    });
    loop {
        match read_frame(&mut rd).await {
            Ok(m) => {
                if inbox.send(m).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    peers.lock().unwrap().remove(&remote);
    writer.abort();
}
