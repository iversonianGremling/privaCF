//! The node engine — the heart of the MVP. Ties identity, the mock beacon, the chain, the trait
//! seams, and TCP gossip into the per-epoch loop (SPEC §4.1 / §6.4). Consensus is a simplified
//! single-round BFT: each height the validators broadcast VRF claims, deterministically elect the
//! lowest-output leader, vote on its block, and finalize once a quorum certificate (≥ ⌊2N/3⌋+1
//! votes) forms.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::SeedableRng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tracing::{debug, info};

use crate::beacon::next_beacon;
use crate::bls;
use crate::chain::{block_id, qc_valid, Block, BlockHeader, Chain, QuorumCert, Vote};
use crate::commit::{CommitT, StubVerEnc, VerEnc};
use crate::consensus::{leader_for, quorum};
use crate::epoch::EpochTransaction;
use crate::field::{add_mod, from_u64, random_field, sub_mod, to_u64};
use crate::identity::NodeIdentity;
use crate::message::Message;
use crate::transport::{read_frame, write_frame};
use crate::vrf::VrfClaim;

type PeersMap = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

/// The genesis validator set for a seed-derived demo/test network: node `i` has identity
/// `from_seed(i)`, listens on `127.0.0.1:(base_port + i)`, and advertises its BLS public key.
pub fn genesis_validator_set(nodes: u64, base_port: u16) -> Vec<([u8; 32], String, [u8; 48])> {
    (0..nodes)
        .map(|i| {
            let id = NodeIdentity::from_seed(i);
            (id.peer_id(), format!("127.0.0.1:{}", base_port + i as u16), id.bls_pk())
        })
        .collect()
}

#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: String,
    /// Genesis validators: (stable peer id, listen addr, BLS public key).
    pub genesis_validators: Vec<([u8; 32], String, [u8; 48])>,
    pub window_ms: u64,
    pub max_height: u64,
    pub grace_ms: u64,
}

#[derive(Clone, Debug)]
pub struct NodeOutcome {
    pub peer_id: [u8; 32],
    pub head_hash: [u8; 32],
    pub blocks_len: usize,
    pub epoch_ids: Vec<(u64, u64)>,
    /// True iff `s₁ + s₂ = null_v` held for every epoch.
    pub split_ok: bool,
    /// True iff every non-genesis block carries a valid quorum certificate.
    pub all_qc_valid: bool,
    /// Highest view any finalized block used (> 0 means view-change fired — a leader was skipped).
    pub max_view: u64,
}

/// Per-height consensus state.
struct Round {
    height: u64,
    view: u64,                                         // current view (advances on leader timeout)
    beacon_t: u64,
    my_vrf: VrfClaim,
    claims: HashMap<[u8; 32], [u8; 32]>,               // peer -> vrf output
    blocks: HashMap<[u8; 32], Block>,                  // block_id -> proposed block
    votes: HashMap<[u8; 32], HashMap<[u8; 32], Vote>>, // block_id -> voter -> vote
    proposed_views: HashSet<u64>,                      // views I have already proposed in
    voted: Option<[u8; 32]>,                           // block_id voted for in the CURRENT view
    vrf_deadline: Instant,                             // when claim collection ends
    view_deadline: Instant,                            // when to advance to the next view
}

pub struct Node {
    identity: Arc<NodeIdentity>,
    config: NodeConfig,
    verenc: StubVerEnc,
    validators: Vec<[u8; 32]>,
    bls_pks: HashMap<[u8; 32], [u8; 48]>,
    /// Test fault injection: participate in VRF + voting but never propose when elected leader,
    /// forcing the other validators to view-change past us. Honest default is `false`.
    withhold_proposals: bool,
}

impl Node {
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> Self {
        let mut validators: Vec<[u8; 32]> =
            config.genesis_validators.iter().map(|(id, _, _)| *id).collect();
        validators.sort();
        validators.dedup();
        let bls_pks: HashMap<[u8; 32], [u8; 48]> =
            config.genesis_validators.iter().map(|(id, _, pk)| (*id, *pk)).collect();
        Self { identity: Arc::new(identity), config, verenc: StubVerEnc, validators, bls_pks, withhold_proposals: false }
    }

    /// Fault-injection builder: this node will never propose (Byzantine leader that withholds its
    /// block), exercising the other validators' view-change path.
    pub fn byzantine_withhold(mut self) -> Self {
        self.withhold_proposals = true;
        self
    }

    fn me(&self) -> [u8; 32] {
        self.identity.peer_id()
    }

    fn gossip(peers: &PeersMap, msg: Message) {
        let map = peers.lock().unwrap();
        for tx in map.values() {
            let _ = tx.send(msg.clone());
        }
    }

    /// Begin a new height: submit our `commit_T` transaction and broadcast our VRF claim.
    #[allow(clippy::too_many_arguments)]
    fn start_round(
        &self,
        height: u64,
        chain: &Chain,
        peers: &PeersMap,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
        epoch_ids: &mut Vec<(u64, u64)>,
        split_ok: &mut bool,
        rng: &mut impl rand::RngCore,
    ) -> Round {
        let beacon_t = next_beacon(chain.head().header.beacon_t, height);
        // per-epoch commitment (publish-s1)
        let epoch_id_fp = self.identity.epoch_id(from_u64(beacon_t));
        let epoch_id = to_u64(epoch_id_fp);
        let s2 = random_field(rng);
        let s1 = sub_mod(self.identity.null_v, s2);
        *split_ok &= add_mod(s1, s2) == self.identity.null_v;
        let commit = CommitT { s1: to_u64(s1), d_t: self.verenc.encrypt(s2, epoch_id_fp) };
        let tx = EpochTransaction::create(&self.identity, height, epoch_id, commit);
        pending.insert((height, epoch_id), tx.clone());
        epoch_ids.push((height, epoch_id));
        Self::gossip(peers, Message::Tx(tx));
        // VRF leadership claim
        let my_vrf = VrfClaim::create(&self.identity, height, beacon_t);
        Self::gossip(peers, Message::Vrf(my_vrf.clone()));
        let mut claims = HashMap::new();
        claims.insert(self.me(), my_vrf.output);
        let now = Instant::now();
        let vrf_deadline = now + Duration::from_millis(self.config.window_ms / 3);
        // view 0 runs from vrf_deadline until one view_timeout (= window) later.
        let view_deadline = vrf_deadline + Duration::from_millis(self.config.window_ms);
        Round {
            height,
            view: 0,
            beacon_t,
            my_vrf,
            claims,
            blocks: HashMap::new(),
            votes: HashMap::new(),
            proposed_views: HashSet::new(),
            voted: None,
            vrf_deadline,
            view_deadline,
        }
    }

    fn assemble_block(&self, chain: &Chain, r: &Round, pending: &HashMap<(u64, u64), EpochTransaction>) -> Block {
        let prev = chain.head_hash();
        let my_epoch_id = to_u64(self.identity.epoch_id(from_u64(r.beacon_t)));
        let mut txs: Vec<EpochTransaction> =
            pending.iter().filter(|((h, _), _)| *h == r.height).map(|(_, v)| v.clone()).collect();
        txs.sort_by_key(|t| t.epoch_id);
        let header = BlockHeader::create(
            &self.identity, r.height, r.view, r.beacon_t, prev, my_epoch_id, &r.my_vrf,
        );
        Block { header, txs, qc: QuorumCert::default() }
    }

    fn cast_vote(&self, r: &mut Round, bid: [u8; 32], peers: &PeersMap) {
        if r.voted.is_some() {
            return;
        }
        let vote = Vote::create(&self.identity, r.height, bid);
        r.votes.entry(bid).or_default().insert(self.me(), vote.clone());
        r.voted = Some(bid);
        Self::gossip(peers, Message::Vote(vote));
    }

    /// Structural validity + a verifiable VRF leadership proof (does not check WHICH view's leader).
    fn structural_and_vrf_ok(&self, chain: &Chain, b: &Block) -> bool {
        let head = &chain.head().header;
        if b.header.height != head.height + 1 || b.header.prev_block_hash != chain.head_hash() {
            return false;
        }
        if b.header.beacon_t != next_beacon(head.beacon_t, b.header.height) {
            return false;
        }
        if !self.validators.contains(&b.header.proposer_peer) {
            return false;
        }
        let claim = VrfClaim {
            height: b.header.height,
            peer: b.header.proposer_peer,
            output: b.header.vrf_output,
            proof: b.header.vrf_proof.clone(),
        };
        claim.verify(b.header.beacon_t)
    }

    /// Live-proposal validity (deciding whether to VOTE): structural + VRF + the proposer is the
    /// correct leader for the block's view, per our claim set.
    fn valid_proposal(&self, chain: &Chain, b: &Block, claims: &HashMap<[u8; 32], [u8; 32]>) -> bool {
        self.structural_and_vrf_ok(chain, b)
            && leader_for(claims, b.header.view) == Some(b.header.proposer_peer)
    }

    /// Append validity for a finalized/synced block: structural + VRF + a valid quorum certificate.
    /// The QC (≥ quorum honest votes) is itself the proof the proposer was the legitimate leader,
    /// so this does not need the per-height claim set (which past/synced heights lack).
    fn valid_block(&self, chain: &Chain, b: &Block) -> bool {
        self.structural_and_vrf_ok(chain, b) && qc_valid(b, &self.validators, &self.bls_pks)
    }

    /// After claim collection: advance the view on leader timeout, the current view's leader
    /// proposes, and everyone votes for that leader's block.
    fn on_tick(
        &self,
        r: &mut Round,
        chain: &mut Chain,
        pending: &HashMap<(u64, u64), EpochTransaction>,
        peers: &PeersMap,
    ) {
        let now = Instant::now();
        if now < r.vrf_deadline {
            return; // still collecting VRF claims
        }
        // view-change: the current leader didn't get us to a quorum certificate in time.
        if now >= r.view_deadline {
            r.view += 1;
            r.voted = None;
            r.view_deadline = now + Duration::from_millis(self.config.window_ms);
            debug!(height = r.height, view = r.view, "view-change (leader timeout)");
        }
        if let Some(ldr) = leader_for(&r.claims, r.view) {
            if ldr == self.me() && !r.proposed_views.contains(&r.view) && !self.withhold_proposals {
                let block = self.assemble_block(chain, r, pending);
                let bid = block_id(&block.header, &block.txs);
                debug!(height = r.height, view = r.view, txs = block.txs.len(), "proposing as VRF leader");
                r.blocks.insert(bid, block.clone());
                r.proposed_views.insert(r.view);
                Self::gossip(peers, Message::Proposal(block));
                self.cast_vote(r, bid, peers);
            }
            if r.voted.is_none() {
                if let Some((bid, _)) = r
                    .blocks
                    .iter()
                    .find(|(_, b)| b.header.view == r.view && b.header.proposer_peer == ldr)
                    .map(|(k, v)| (*k, v.clone()))
                {
                    self.cast_vote(r, bid, peers);
                }
            }
        }
        self.try_finalize(r, chain, peers);
    }

    /// Once a block has a quorum of votes, aggregate them into a quorum certificate, append, broadcast.
    fn try_finalize(&self, r: &mut Round, chain: &mut Chain, peers: &PeersMap) {
        let q = quorum(self.validators.len());
        let ready = r
            .votes
            .iter()
            .find(|(bid, vs)| vs.len() >= q && r.blocks.contains_key(*bid))
            .map(|(bid, _)| *bid);
        if let Some(bid) = ready {
            let mut signers = Vec::new();
            let mut sigs: Vec<[u8; 96]> = Vec::new();
            for (peer, vote) in &r.votes[&bid] {
                if let Ok(sig) = <[u8; 96]>::try_from(vote.bls_sig.as_slice()) {
                    signers.push(*peer);
                    sigs.push(sig);
                }
            }
            let agg = match bls::aggregate(&sigs) {
                Some(a) => a,
                None => return,
            };
            let mut fb = r.blocks[&bid].clone();
            fb.qc = QuorumCert { signers: signers.clone(), agg_sig: agg.to_vec() };
            if chain.try_append(fb.clone()).is_ok() {
                info!(height = fb.header.height, signers = signers.len(), leader = %hex::encode(&fb.header.proposer_peer[..3]), "finalized block (aggregate BLS quorum cert)");
                Self::gossip(peers, Message::Finalized(fb));
            }
        }
    }

    fn on_msg(
        &self,
        msg: Message,
        round: Option<&mut Round>,
        chain: &mut Chain,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
        peers: &PeersMap,
    ) {
        match msg {
            Message::Tx(tx) => {
                if tx.verify_sig() {
                    pending.insert((tx.height, tx.epoch_id), tx);
                }
            }
            Message::Vrf(c) => {
                if let Some(r) = round {
                    if c.height == r.height && c.verify(r.beacon_t) {
                        r.claims.insert(c.peer, c.output);
                    }
                }
            }
            Message::Proposal(b) => {
                if let Some(r) = round {
                    if b.header.height == r.height && self.valid_proposal(chain, &b, &r.claims) {
                        let bview = b.header.view;
                        let bid = block_id(&b.header, &b.txs);
                        r.blocks.entry(bid).or_insert(b);
                        // valid_proposal already confirmed the proposer is the leader for `bview`,
                        // so vote iff it matches our current view and we haven't voted in it yet.
                        if Instant::now() >= r.vrf_deadline && r.voted.is_none() && bview == r.view {
                            self.cast_vote(r, bid, peers);
                        }
                        self.try_finalize(r, chain, peers);
                    }
                }
            }
            Message::Vote(v) => {
                if let Some(r) = round {
                    let ok = v.height == r.height
                        && self.validators.contains(&v.voter)
                        && self.bls_pks.get(&v.voter).is_some_and(|pk| v.verify(pk));
                    if ok {
                        r.votes.entry(v.block_id).or_default().insert(v.voter, v);
                        self.try_finalize(r, chain, peers);
                    }
                }
            }
            Message::Finalized(b) => {
                if self.valid_block(chain, &b) {
                    let _ = chain.try_append(b);
                }
            }
            Message::GetChain { from_height } => {
                let bs = chain.blocks_from(from_height);
                if !bs.is_empty() {
                    Self::gossip(peers, Message::ChainRange(bs));
                }
            }
            Message::ChainRange(bs) => {
                for b in bs {
                    if self.valid_block(chain, &b) {
                        let _ = chain.try_append(b);
                    }
                }
            }
            Message::Hello { .. } => {}
        }
    }

    pub async fn run(self) -> NodeOutcome {
        let peers: PeersMap = Arc::new(Mutex::new(HashMap::new()));
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<Message>();
        let _keepalive = inbox_tx.clone();
        let my_id = self.me();
        let my_hello = Message::Hello { peer_id: my_id, listen_addr: self.config.listen_addr.clone() };

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
        for (pid, addr, _bls) in self.config.genesis_validators.iter() {
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
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                });
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        info!(peer = %hex::encode(&my_id[..4]), validators = self.validators.len(), quorum = quorum(self.validators.len()), "node up, entering consensus loop");

        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut chain = Chain::genesis();
        let mut pending: HashMap<(u64, u64), EpochTransaction> = HashMap::new();
        let mut epoch_ids: Vec<(u64, u64)> = Vec::new();
        let mut split_ok = true;
        let mut round: Option<Round> = None;
        let mut done_at: Option<Instant> = None;
        let mut ticker = interval(Duration::from_millis(10));

        loop {
            let head_h = chain.head().header.height;
            if head_h >= self.config.max_height {
                let dl = *done_at
                    .get_or_insert_with(|| Instant::now() + Duration::from_millis(self.config.grace_ms));
                if Instant::now() >= dl {
                    break;
                }
            } else {
                let need = head_h + 1;
                if round.as_ref().map(|r| r.height) != Some(need) {
                    round = Some(self.start_round(
                        need, &chain, &peers, &mut pending, &mut epoch_ids, &mut split_ok, &mut rng,
                    ));
                    pending.retain(|(h, _), _| *h > head_h); // prune finalized heights
                }
            }

            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(r) = round.as_mut() {
                        self.on_tick(r, &mut chain, &pending, &peers);
                    }
                }
                Some(msg) = inbox_rx.recv() => {
                    self.on_msg(msg, round.as_mut(), &mut chain, &mut pending, &peers);
                }
            }
        }

        let all_qc_valid =
            chain.blocks.iter().skip(1).all(|b| qc_valid(b, &self.validators, &self.bls_pks));
        let max_view = chain.blocks.iter().map(|b| b.header.view).max().unwrap_or(0);
        info!(peer = %hex::encode(&my_id[..4]), blocks = chain.blocks.len(), head = %hex::encode(&chain.head_hash()[..4]), all_qc_valid, max_view, "node done");
        NodeOutcome {
            peer_id: my_id,
            head_hash: chain.head_hash(),
            blocks_len: chain.blocks.len(),
            epoch_ids,
            split_ok,
            all_qc_valid,
            max_view,
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
