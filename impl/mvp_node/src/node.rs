//! The node engine — the heart of the MVP. Ties identity, the mock beacon, the chain, the trait
//! seams, and TCP gossip into the per-epoch loop (SPEC §4.1 / §6.4). Consensus is a simplified
//! single-round BFT: each height the validators broadcast VRF claims, deterministically elect the
//! lowest-output leader, vote on its block, and finalize once a quorum certificate (≥ ⌊2N/3⌋+1
//! votes) forms.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::SeedableRng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};
use tracing::{debug, info};

use num_bigint::BigUint;

use crate::admission::VdfAdmission;
use crate::beacon::{next_beacon, next_beacon_vdf};
use crate::bls;
use crate::chain::{
    block_id, proposal_sig_bytes, qc_valid, Block, BlockHeader, Chain, EquivocationProof,
    QuorumCert, Vote, VoteEquivocationProof,
};
use crate::commit::{CommitT, NativeGroupVerEnc, StubVerEnc, VerEnc};
use crate::consensus::{leader_for, quorum};
use crate::dkg;
use crate::epoch::EpochTransaction;
use crate::field::{add_mod, from_u64, random_field, sub_mod, to_u64};
use crate::identity::{verify as verify_ed25519, NodeIdentity};
use crate::loopix::{fragment, sample_delays, select_full_path, MixDirectory, Reassembler};
use crate::membership::{MembershipOp, ValidatorRecord, ValidatorSet};
use crate::message::Message;
use crate::sphinx::{self, Processed, SphinxPacket};
use crate::transport::{noise_handshake, read_frame, write_frame};
use crate::vrf::VrfClaim;

type PeersMap = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

/// Settings for routing consensus gossip through the Loopix mixnet (`loopix.rs`/`sphinx.rs`) instead
/// of broadcasting it in the clear over the Noise mesh. Supplied via `Node::with_mixnet`.
#[derive(Clone)]
pub struct MixSettings {
    /// The genesis mix directory (peer_id → mix public key) — presupposed trusted, the relay set.
    pub directory: MixDirectory,
    /// Hops per Sphinx path (including the destination); needs ≥ `hops-1` other mixes available.
    pub hops: usize,
    /// Mean per-hop Poisson delay (ms). Kept small so the BFT round timers still close on time.
    pub mean_delay_ms: u64,
}

/// Routes outbound consensus messages either by mixnet (small control-plane messages, when enabled)
/// or by direct Noise broadcast (block-bearing messages, and everything when mixing is off), and
/// peels inbound Sphinx packets — forwarding relays and re-injecting delivered messages into the
/// consensus inbox. The mixnet rides the *existing* validator Noise mesh (a Sphinx packet is just a
/// `Message::Sphinx` frame), so no second network is stood up.
struct Mixer {
    enabled: bool,
    me: [u8; 32],
    mix_sk: [u8; 32],
    settings: MixSettings,
    /// Per-fragment nonce diversifying chain-seeded paths (each fragment to each peer takes a path).
    nonce: AtomicU64,
    /// Monotonic id for the messages we originate, so a message's fragments share one `msg_id`.
    msg_seq: AtomicU64,
    /// Reassembles inbound fragments into whole messages before re-injection.
    reasm: Mutex<Reassembler>,
    /// Re-injects mixnet-delivered consensus messages so they flow through the normal inbox path.
    inbox_tx: mpsc::UnboundedSender<Message>,
}

impl Mixer {
    /// Everything routes through the mixnet (when enabled) EXCEPT the two transport-level frames that
    /// must precede or carry the mixnet itself: `Hello` (the pre-mixnet peer handshake) and `Sphinx`
    /// (the mix packet itself). Fragmentation lets even block-bearing/bulk messages route, so the
    /// whole consensus + chain-sync surface is mixed. (The chain-sync path — `GetChain`/`ChainRange` —
    /// is currently dormant: laggards catch up via the mixnet-routed `Finalized` broadcast; routing it
    /// here closes the seam so any future explicit sync is mixed too.)
    fn is_routable(msg: &Message) -> bool {
        !matches!(msg, Message::Hello { .. } | Message::Sphinx(_))
    }

    /// Publish a consensus message. When mixing is enabled and the message is routable, fragment it
    /// and send each fragment as a chain-routed Sphinx packet to every other mix-directory member;
    /// otherwise broadcast directly.
    fn publish(&self, peers: &PeersMap, beacon: u64, msg: Message) {
        if !self.enabled || !Self::is_routable(&msg) {
            Node::gossip(peers, msg);
            return;
        }
        let bytes = match bincode::serialize(&msg) {
            Ok(b) => b,
            Err(_) => {
                Node::gossip(peers, msg);
                return;
            }
        };
        // One msg_id for all fragments of this message (reused across destinations, which reassemble
        // independently); the sender-id prefix keeps it distinct from other nodes' ids.
        let sid = self.msg_seq.fetch_add(1, Ordering::Relaxed);
        let mut msg_id = [0u8; 16];
        msg_id[..8].copy_from_slice(&self.me[..8]);
        msg_id[8..].copy_from_slice(&sid.to_le_bytes());
        let frags = fragment(msg_id, &bytes);
        for dest in self.settings.directory.ids() {
            if dest == self.me {
                continue;
            }
            for frag in &frags {
                let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
                let path = match select_full_path(
                    &self.settings.directory, &self.me, &dest, self.settings.hops, beacon, nonce,
                ) {
                    Some(p) => p,
                    None => continue,
                };
                let delays =
                    sample_delays(path.len(), self.settings.mean_delay_ms, beacon, nonce ^ 0x5d);
                if let Ok(pkt) = sphinx::create(&path, &delays, frag) {
                    if let Some(first) = path.first() {
                        Node::send_to(peers, &first.id, Message::Sphinx(pkt));
                    }
                }
            }
        }
    }

    /// Peel an inbound Sphinx packet: deliver (reassemble fragments, then re-inject the recovered
    /// consensus message once complete) or forward to the next hop after its per-hop delay.
    fn handle_sphinx(&self, pkt: SphinxPacket, peers: &PeersMap) {
        match sphinx::process(&self.mix_sk, &pkt) {
            Ok(Processed::Deliver { data }) => {
                let complete = self.reasm.lock().unwrap().accept(&data);
                if let Some(bytes) = complete {
                    if let Ok(inner) = bincode::deserialize::<Message>(&bytes) {
                        let _ = self.inbox_tx.send(inner);
                    }
                }
            }
            Ok(Processed::Forward { next, delay_ms, packet }) => {
                let peers = peers.clone();
                tokio::spawn(async move {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    Node::send_to(&peers, &next, Message::Sphinx(packet));
                });
            }
            // Consensus does not use SURB replies; ignore if one is ever routed here.
            Ok(Processed::SurbReply { .. }) => debug!("ignoring unexpected SURB reply at consensus mixer"),
            Err(e) => debug!(?e, "dropping un-processable mix packet"),
        }
    }
}

/// A membership change recorded in block `H` activates for consensus at height `H + ACTIVATION_DELAY`.
/// With a delay of 1, the change is live as soon as the block carrying it is finalized — at which
/// point that block is identical for every node, so all derive the same active set (no split-brain).
const ACTIVATION_DELAY: u64 = 1;

/// The genesis validator set for a seed-derived demo/test network: node `i` has identity
/// `from_seed(i)`, listens on `127.0.0.1:(base_port + i)`, and advertises its BLS + VRF public keys.
pub fn genesis_validator_set(nodes: u64, base_port: u16) -> Vec<ValidatorRecord> {
    (0..nodes)
        .map(|i| {
            let id = NodeIdentity::from_seed(i);
            ValidatorRecord {
                peer_id: id.peer_id(),
                addr: format!("127.0.0.1:{}", base_port + i as u16),
                bls_pk: id.bls_pk(),
                vrf_pk: id.vrf_pk(),
            }
        })
        .collect()
}

#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: String,
    pub genesis_validators: Vec<ValidatorRecord>,
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
    /// The realized `(height, beacon)` chain — VRF-chained, so not predictable from genesis alone.
    pub beacons: Vec<(u64, u64)>,
    /// True iff `s₁ + s₂ = null_v` held for every epoch.
    pub split_ok: bool,
    /// True iff every non-genesis block carries a valid quorum certificate.
    pub all_qc_valid: bool,
    /// Highest view any finalized block used (> 0 means view-change fired — a leader was skipped).
    pub max_view: u64,
    /// Validators this node slashed for equivocation (sorted), network-consistent under honest majority.
    pub slashed: Vec<[u8; 32]>,
    /// The active validator set in effect at the height AFTER the final block (sorted) — reflects
    /// every finalized membership change, so all honest nodes agree on it.
    pub final_active: Vec<[u8; 32]>,
}

/// Per-height consensus state.
struct Round {
    height: u64,
    view: u64,                                         // current view (advances on leader timeout)
    beacon_t: u64,
    vset: ValidatorSet,                                // active validator set for THIS height (fixed)
    my_vrf: VrfClaim,
    claims: HashMap<[u8; 32], [u8; 32]>,               // peer -> vrf output
    blocks: HashMap<[u8; 32], Block>,                  // block_id -> proposed block
    votes: HashMap<[u8; 32], HashMap<[u8; 32], Vote>>, // block_id -> voter -> vote
    proposed_views: HashSet<u64>,                      // views I have already proposed in
    voted: Option<[u8; 32]>,                           // block_id voted for in the CURRENT view
    seen_proposals: HashMap<([u8; 32], u64), ([u8; 32], Vec<u8>)>, // (proposer,view) -> (id, sig)
    seen_votes: HashMap<([u8; 32], u64), ([u8; 32], Vec<u8>)>, // (voter,view) -> (block_id, bls_sig)
    vrf_deadline: Instant,                             // when claim collection ends
    view_deadline: Instant,                            // when to advance to the next view
}

/// This validator's share of the genesis DKG threshold key `VA_pub` — a presupposed-good-genesis
/// artifact. `va_pub` seals `s₂` (`NativeGroupVerEnc`); `share`/`index`/`threshold` let it
/// threshold-sign verdicts so any `threshold` validators reconstruct `σ_VERDICT` (P1.4).
#[derive(Clone)]
pub struct ThresholdKey {
    pub va_pub: [u8; 48],
    pub share: [u8; 32],
    pub index: u64, // 1-based party index in the sorted validator order
    pub threshold: usize,
}

/// Run the genesis DKG over `idents` and assign each its `ThresholdKey` — the trusted genesis
/// ceremony (presupposed-good-genesis). Used by the demo/tests to provision the validator set.
pub fn genesis_threshold_keys(
    idents: &[NodeIdentity],
    threshold: usize,
) -> HashMap<[u8; 32], ThresholdKey> {
    let mut parties: Vec<([u8; 32], Vec<u8>)> =
        idents.iter().map(|id| (id.peer_id(), id.dkg_ikm().to_vec())).collect();
    parties.sort_by_key(|(p, _)| *p);
    let (va_pub, shares) = dkg::genesis_keys(threshold, &parties);
    parties
        .iter()
        .enumerate()
        .map(|(idx, (pid, _))| {
            (*pid, ThresholdKey { va_pub, share: shares[pid], index: idx as u64 + 1, threshold })
        })
        .collect()
}

pub struct Node {
    identity: Arc<NodeIdentity>,
    config: NodeConfig,
    verenc: Box<dyn VerEnc>,
    /// This validator's genesis threshold-key share (`None` ⇒ no real sealing; `StubVerEnc`).
    threshold_key: Option<ThresholdKey>,
    /// The genesis validator records — the base the active set is folded forward from.
    genesis: Vec<ValidatorRecord>,
    /// Test fault injection: participate in VRF + voting but never propose when elected leader,
    /// forcing the other validators to view-change past us. Honest default is `false`.
    withhold_proposals: bool,
    /// Test fault injection: when elected leader, propose TWO conflicting blocks for the slot
    /// (double-sign), to exercise equivocation detection + slashing. Honest default is `false`.
    equivocate: bool,
    /// Test fault injection: whenever this node votes, also emit a second vote for a different
    /// block id in the same slot (double-vote), to exercise vote-equivocation slashing. Honest
    /// default is `false`.
    double_vote: bool,
    /// If set, this node gossips a self-signed leave op upon reaching this height, exercising
    /// dynamic membership: from the next height the active set (and quorum) no longer include it.
    leave_at: Option<u64>,
    /// If true, this node is NOT in the genesis set and seeks to join: each height until admitted it
    /// gossips a self-signed join op (`config.genesis_validators` is its bootstrap peer list).
    joining: bool,
    /// If set, consensus control messages are routed through the Loopix mixnet rather than
    /// broadcast in the clear (see `Mixer`); `None` keeps the original direct-gossip behavior.
    mix_settings: Option<MixSettings>,
    /// If set, a join op must carry a valid admission VDF proof (genesis-consistent network-wide);
    /// `None` keeps AcceptAll admission.
    admission: Option<VdfAdmission>,
    /// Memoised admission VDF proof for our own join — deterministic in our peer_id, computed once.
    join_vdf: std::sync::OnceLock<Vec<u8>>,
    /// If set `(modulus, delay)`, the per-height beacon folds in a VDF output over the previous
    /// beacon (genesis-consistent network-wide), removing the residual last-revealer grinding bias.
    beacon_vdf: Option<(BigUint, u64)>,
    /// If set, this node has a clean Layer-5 preference vector: each epoch it attaches a
    /// `PreferencePayload` (obfuscated gossip + `C_p` + `M_v`) to its tx, putting real recommendation
    /// substrate on-chain (§4.4–§4.6). `dp_epsilon` is the Laplace-DP budget for the gossip (§4.5).
    preferences: Option<Vec<i64>>,
    dp_epsilon: f64,
}

impl Node {
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> Self {
        let mut genesis = config.genesis_validators.clone();
        genesis.sort_by_key(|r| r.peer_id);
        genesis.dedup_by_key(|r| r.peer_id);
        Self {
            identity: Arc::new(identity),
            config,
            verenc: Box::new(StubVerEnc),
            threshold_key: None,
            genesis,
            withhold_proposals: false,
            equivocate: false,
            double_vote: false,
            leave_at: None,
            joining: false,
            mix_settings: None,
            admission: None,
            join_vdf: std::sync::OnceLock::new(),
            beacon_vdf: None,
            preferences: None,
            dp_epsilon: 5.0,
        }
    }

    /// Builder: provision this validator with its genesis DKG threshold-key share. Switches sealing to
    /// the real `NativeGroupVerEnc` (so `s₂` is encrypted to `VA_pub`) and enables verdict
    /// threshold-signing (P1.4). Without it the node uses `StubVerEnc`.
    pub fn with_threshold_key(mut self, tk: ThresholdKey) -> Self {
        self.verenc = Box::new(NativeGroupVerEnc { va_pub: tk.va_pub });
        self.threshold_key = Some(tk);
        self
    }

    /// This validator's verdict threshold signature on `verdict_id(epoch_id)` — its partial of
    /// `σ_VERDICT`. `(index, partial)` combine via `dkg::combine_signatures` once `threshold` of them
    /// exist. `None` if this node holds no threshold-key share.
    pub fn verdict_partial(&self, epoch_id: u64) -> Option<(u64, [u8; 96])> {
        let tk = self.threshold_key.as_ref()?;
        let id = crate::verenc::verdict_id(epoch_id);
        Some((tk.index, crate::bls::sign_dst(&tk.share, &id, crate::verenc::VERENC_DST)))
    }

    /// Builder: give this node a clean Layer-5 preference vector (per-item integer weights). Each
    /// epoch it attaches a `PreferencePayload` to its tx — Laplace-DP-obfuscated gossip (budget
    /// `epsilon`) plus the `C_p`/`M_v` commitments — so the finalized chain carries real
    /// recommendation substrate (§4.4–§4.6).
    pub fn with_preferences(mut self, prefs: Vec<i64>, epsilon: f64) -> Self {
        self.preferences = Some(prefs);
        self.dp_epsilon = epsilon;
        self
    }

    /// Deterministic 32-byte secret handle for per-epoch preference derivations (obfuscation seed,
    /// Pedersen blinding, leaf salt) — bound to `sk` but never exposing it.
    fn pref_sk_handle(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"privacf-pref-sk-handle-v1");
        h.update(&to_u64(self.identity.sk).to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Builder: gate joins behind an admission VDF proof-of-work (`VdfAdmission`). The parameters must
    /// be genesis-consistent across the network so every validator agrees on admissibility.
    pub fn with_vdf_admission(mut self, admission: VdfAdmission) -> Self {
        self.admission = Some(admission);
        self
    }

    /// Builder: fold a VDF (over the previous beacon, `delay` sequential squarings, modulus `n`) into
    /// each height's beacon, removing the residual last-revealer bias. Genesis-consistent network-wide.
    pub fn with_vdf_beacon(mut self, n: BigUint, delay: u64) -> Self {
        self.beacon_vdf = Some((n, delay));
        self
    }

    /// The beacon at `height` given the finalized `head` — VRF-chained, optionally VDF-folded. Both
    /// the proposer (in `start_round`) and every validator (in `structural_and_vrf_ok`) call this, so
    /// they derive the identical beacon (a pure function of the finalized chain + genesis params).
    fn beacon_for(&self, head: &BlockHeader, height: u64) -> u64 {
        match &self.beacon_vdf {
            Some((n, delay)) => {
                let mut seed = head.beacon_t.to_le_bytes().to_vec();
                seed.extend_from_slice(&height.to_le_bytes());
                let x = crate::vdf::input_from_bytes(n, &seed);
                let y = crate::vdf::eval(n, &x, *delay).y;
                next_beacon_vdf(head.beacon_t, &head.vrf_output, height, &y.to_bytes_be())
            }
            None => next_beacon(head.beacon_t, &head.vrf_output, height),
        }
    }

    /// A membership op is admissible iff it is self-signed AND (for a join under `VdfAdmission`) it
    /// carries a valid admission VDF proof. This is the network-wide gate enforced at pooling, block
    /// assembly, and block validation, so all honest nodes agree.
    fn op_admissible(&self, op: &MembershipOp) -> bool {
        op.verify()
            && match (&self.admission, op) {
                (Some(adm), MembershipOp::Add { record, vdf, .. }) => adm.admits(&record.peer_id, vdf),
                _ => true,
            }
    }

    /// Builder: route consensus control messages (VRF claims, votes, txs, membership/slash) through
    /// the Loopix mixnet instead of broadcasting them in the clear, hiding the who-talks-to-whom
    /// pattern. Block-bearing/sync messages still go direct (too large for one fixed Sphinx packet).
    pub fn with_mixnet(mut self, settings: MixSettings) -> Self {
        self.mix_settings = Some(settings);
        self
    }

    /// The active validator set in effect AT `height`: genesis folded forward by every membership op
    /// in finalized blocks strictly below `height - (ACTIVATION_DELAY - 1)`. Pure function of the
    /// finalized chain, so every node computes the identical set (the reconfiguration-safety crux).
    fn active_set_at(&self, blocks: &[Block], height: u64) -> ValidatorSet {
        let cutoff = height.saturating_sub(ACTIVATION_DELAY - 1); // ops in blocks at h < cutoff apply
        let mut vs = ValidatorSet::from_records(&self.genesis);
        for b in blocks {
            if b.header.height >= 1 && b.header.height < cutoff {
                for op in &b.header.membership_ops {
                    vs.apply(op);
                }
            }
        }
        vs
    }

    /// The SUSP_SMT and DECRYPTION_SMT roots in effect AT `height` — a pure function of the finalized
    /// chain below it (like `active_set_at`), so every node derives identical roots. Suspended
    /// `null_v`s and their `dec_nullifier`s are folded from the `SuspendRecord`s in finalized blocks
    /// (dark-node extractions, `verdict.rs`); empty until the first suspension, but a real empty-tree
    /// root either way.
    fn smt_roots_at(&self, blocks: &[Block], height: u64) -> ([u8; 32], [u8; 32]) {
        let cutoff = height.saturating_sub(ACTIVATION_DELAY - 1);
        let mut suspended: Vec<u64> = Vec::new();
        let mut decrypted: Vec<u64> = Vec::new();
        for b in blocks {
            if b.header.height >= 1 && b.header.height < cutoff {
                for s in &b.header.suspensions {
                    suspended.push(s.null_v);
                    decrypted.push(s.dec_nullifier());
                }
            }
        }
        (crate::smt::Smt::from_keys(&suspended).root(), crate::smt::Smt::from_keys(&decrypted).root())
    }

    /// Fault-injection builder: this node will never propose (Byzantine leader that withholds its
    /// block), exercising the other validators' view-change path.
    pub fn byzantine_withhold(mut self) -> Self {
        self.withhold_proposals = true;
        self
    }

    /// Fault-injection builder: this node double-signs its slot (proposes two conflicting blocks),
    /// exercising equivocation detection + slashing.
    pub fn byzantine_equivocate(mut self) -> Self {
        self.equivocate = true;
        self
    }

    /// Fault-injection builder: this node double-votes (signs two different block ids per slot),
    /// exercising validator vote-equivocation detection + slashing.
    pub fn byzantine_double_vote(mut self) -> Self {
        self.double_vote = true;
        self
    }

    /// Builder: this node gracefully leaves the validator set on reaching `height` (gossips a
    /// self-signed leave op), exercising dynamic membership + quorum reconfiguration.
    pub fn leaves_at(mut self, height: u64) -> Self {
        self.leave_at = Some(height);
        self
    }

    /// Builder: this node is a newcomer (not in the genesis set) that wants to join. It uses
    /// `genesis_validators` purely as a bootstrap peer list and gossips a self-signed join op until
    /// admitted, after which it is a full validator.
    pub fn joining(mut self) -> Self {
        self.joining = true;
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

    /// Send a message to a single connected peer (used for unicast mixnet hops).
    fn send_to(peers: &PeersMap, peer: &[u8; 32], msg: Message) {
        if let Some(tx) = peers.lock().unwrap().get(peer) {
            let _ = tx.send(msg);
        }
    }

    /// Begin a new height: submit our `commit_T` transaction and broadcast our VRF claim.
    #[allow(clippy::too_many_arguments)]
    fn start_round(
        &self,
        height: u64,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
        epoch_ids: &mut Vec<(u64, u64)>,
        beacons: &mut Vec<(u64, u64)>,
        split_ok: &mut bool,
        rng: &mut impl rand::RngCore,
    ) -> Round {
        let head = &chain.head().header;
        let beacon_t = self.beacon_for(head, height);
        beacons.push((height, beacon_t));
        // Active validator set for this height — fixed by the finalized chain below it.
        let vset = self.active_set_at(&chain.blocks, height);
        // Dynamic membership: if configured to leave at this height (and still a member), gossip a
        // self-signed leave op for the current leader to record; it activates at the next height.
        if self.leave_at == Some(height) && vset.contains(&self.me()) {
            debug!(height, "broadcasting self-signed LEAVE op");
            mixer.publish(peers, beacon_t, Message::Membership(MembershipOp::remove(&self.identity)));
        }
        // A newcomer keeps gossiping its self-signed join op until it is admitted (self-healing: it
        // stops once it appears in the active set).
        if self.joining && !vset.contains(&self.me()) {
            debug!(height, "broadcasting self-signed JOIN op");
            let addr = self.config.listen_addr.clone();
            let op = match &self.admission {
                // Attach the (memoised) admission VDF proof over our peer_id.
                Some(adm) => {
                    let vdf = self.join_vdf.get_or_init(|| adm.prove(&self.me())).clone();
                    MembershipOp::add_with_vdf(&self.identity, addr, vdf)
                }
                None => MembershipOp::add(&self.identity, addr),
            };
            mixer.publish(peers, beacon_t, Message::Membership(op));
        }
        // per-epoch commitment (publish-s1)
        let epoch_id_fp = self.identity.epoch_id(from_u64(beacon_t));
        let epoch_id = to_u64(epoch_id_fp);
        let s2 = random_field(rng);
        let s1 = sub_mod(self.identity.null_v, s2);
        *split_ok &= add_mod(s1, s2) == self.identity.null_v;
        let commit = CommitT { s1: to_u64(s1), d_t: self.verenc.encrypt(s2, epoch_id_fp) };
        // Layer-5: when this node has preferences, attach the obfuscated gossip + C_p + M_v payload,
        // putting real recommendation substrate on-chain (§4.4–§4.6).
        let pref = self.preferences.as_ref().map(|prefs| {
            crate::epoch::PreferencePayload::build(prefs, &self.pref_sk_handle(), epoch_id, self.dp_epsilon)
        });
        let tx = EpochTransaction::create_with_pref(&self.identity, height, epoch_id, commit, pref);
        pending.insert((height, epoch_id), tx.clone());
        epoch_ids.push((height, epoch_id));
        mixer.publish(peers, beacon_t, Message::Tx(tx));
        // VRF leadership claim
        let my_vrf = VrfClaim::create(&self.identity, height, beacon_t);
        mixer.publish(peers, beacon_t, Message::Vrf(my_vrf.clone()));
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
            vset,
            my_vrf,
            claims,
            blocks: HashMap::new(),
            votes: HashMap::new(),
            proposed_views: HashSet::new(),
            voted: None,
            seen_proposals: HashMap::new(),
            seen_votes: HashMap::new(),
            vrf_deadline,
            view_deadline,
        }
    }

    /// The elected leader for `(view)`, considering only active (non-slashed) validators. A VRF
    /// claim from a non-member (e.g. a just-departed validator) cannot win the lottery.
    fn elected_leader(
        &self,
        claims: &HashMap<[u8; 32], [u8; 32]>,
        view: u64,
        slashed: &HashSet<[u8; 32]>,
        vset: &ValidatorSet,
    ) -> Option<[u8; 32]> {
        let live: HashMap<[u8; 32], [u8; 32]> = claims
            .iter()
            .filter(|(p, _)| !slashed.contains(*p) && vset.contains(p))
            .map(|(p, o)| (*p, *o))
            .collect();
        leader_for(&live, view)
    }

    fn assemble_block(
        &self,
        chain: &Chain,
        r: &Round,
        pending: &HashMap<(u64, u64), EpochTransaction>,
        pending_membership: &[MembershipOp],
        alt: bool,
    ) -> Block {
        let prev = chain.head_hash();
        let my_epoch_id = to_u64(self.identity.epoch_id(from_u64(r.beacon_t)));
        let mut txs: Vec<EpochTransaction> =
            pending.iter().filter(|((h, _), _)| *h == r.height).map(|(_, v)| v.clone()).collect();
        txs.sort_by_key(|t| t.epoch_id);
        // Include self-authorized membership ops that actually change the current set, one per
        // subject (so finalizing this block applies each exactly once).
        let mut ops: Vec<MembershipOp> = Vec::new();
        let mut subjects: HashSet<[u8; 32]> = HashSet::new();
        for op in pending_membership {
            if !self.op_admissible(op) || !subjects.insert(op.subject()) {
                continue;
            }
            let changes = match op {
                MembershipOp::Add { record, .. } => !r.vset.contains(&record.peer_id),
                MembershipOp::Remove { peer_id, .. } => r.vset.contains(peer_id),
            };
            if changes {
                ops.push(op.clone());
            }
        }
        if alt {
            txs.clear(); // a conflicting variant of the same slot -> a different block id
            ops.clear();
        }
        let mut header = BlockHeader::create(
            &self.identity, r.height, r.view, r.beacon_t, prev, my_epoch_id, &r.my_vrf,
        );
        header.membership_ops = ops;
        let (susp_root, decr_root) = self.smt_roots_at(&chain.blocks, r.height);
        header.susp_smt_root = susp_root;
        header.decryption_smt_root = decr_root;
        let bid = block_id(&header, &txs);
        let proposer_sig =
            self.identity.sign(&proposal_sig_bytes(r.height, r.view, &bid)).to_bytes().to_vec();
        Block { header, txs, proposer_sig, qc: QuorumCert::default() }
    }

    fn cast_vote(&self, r: &mut Round, bid: [u8; 32], peers: &PeersMap, mixer: &Mixer) {
        if r.voted.is_some() || !r.vset.contains(&self.me()) {
            return; // only active validators vote (a departed validator no longer does)
        }
        let vote = Vote::create(&self.identity, r.height, r.view, bid);
        r.votes.entry(bid).or_default().insert(self.me(), vote.clone());
        r.voted = Some(bid);
        mixer.publish(peers, r.beacon_t, Message::Vote(vote));
        if self.double_vote {
            // Byzantine: sign a second, different block id at this same (height, view). The id need
            // not correspond to a real block — signing two ids in one slot is itself the offense.
            let mut alt = bid;
            alt[0] ^= 0xff;
            debug!(height = r.height, view = r.view, "DOUBLE-VOTING (signing a second block id)");
            let alt_vote = Vote::create(&self.identity, r.height, r.view, alt);
            mixer.publish(peers, r.beacon_t, Message::Vote(alt_vote));
        }
    }

    /// Structural validity + a verifiable VRF leadership proof (does not check WHICH view's leader).
    /// `vset` is the active validator set in effect at the block's height.
    fn structural_and_vrf_ok(&self, chain: &Chain, b: &Block, vset: &ValidatorSet) -> bool {
        let head = &chain.head().header;
        if b.header.height != head.height + 1 || b.header.prev_block_hash != chain.head_hash() {
            return false;
        }
        if b.header.beacon_t != self.beacon_for(head, b.header.height) {
            return false;
        }
        // The SMT roots must be the chain-derived roots for this height (no forged suspension state).
        let (susp_root, decr_root) = self.smt_roots_at(&chain.blocks, b.header.height);
        if b.header.susp_smt_root != susp_root || b.header.decryption_smt_root != decr_root {
            return false;
        }
        // Every membership op the block carries must be self-authorized AND admissible (VDF gate).
        if !b.header.membership_ops.iter().all(|op| self.op_admissible(op)) {
            return false;
        }
        if !vset.contains(&b.header.proposer_peer) {
            return false;
        }
        let vrf_pk = match vset.vrf.get(&b.header.proposer_peer) {
            Some(pk) => pk,
            None => return false,
        };
        let claim = VrfClaim {
            height: b.header.height,
            peer: b.header.proposer_peer,
            output: b.header.vrf_output,
            preout: b.header.vrf_preout,
            proof: b.header.vrf_proof.clone(),
        };
        claim.verify(b.header.beacon_t, vrf_pk) && b.verify_proposer_sig()
    }

    /// Live-proposal validity (deciding whether to VOTE): structural + VRF + proposer signature +
    /// the proposer is the correct (non-slashed) leader for the block's view, per our claim set and
    /// the round's active validator set.
    fn valid_proposal(
        &self,
        chain: &Chain,
        b: &Block,
        claims: &HashMap<[u8; 32], [u8; 32]>,
        slashed: &HashSet<[u8; 32]>,
        vset: &ValidatorSet,
    ) -> bool {
        self.structural_and_vrf_ok(chain, b, vset)
            && self.elected_leader(claims, b.header.view, slashed, vset)
                == Some(b.header.proposer_peer)
    }

    /// Append validity for a finalized/synced block: structural + VRF + a valid quorum certificate
    /// under the active set in effect at the block's height. The QC (≥ quorum honest votes) is
    /// itself the proof the proposer was the legitimate leader, so this does not need the per-height
    /// claim set (which past/synced heights lack). The active set IS reconstructible from the chain.
    fn valid_block(&self, chain: &Chain, b: &Block) -> bool {
        let vset = self.active_set_at(&chain.blocks, b.header.height);
        self.structural_and_vrf_ok(chain, b, &vset) && qc_valid(b, &vset.peers, &vset.bls)
    }

    /// After claim collection: advance the view on leader timeout, the current view's leader
    /// proposes, and everyone votes for that leader's block.
    fn on_tick(
        &self,
        r: &mut Round,
        chain: &mut Chain,
        pending: &HashMap<(u64, u64), EpochTransaction>,
        pending_membership: &[MembershipOp],
        peers: &PeersMap,
        mixer: &Mixer,
        slashed: &HashSet<[u8; 32]>,
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
        if let Some(ldr) = self.elected_leader(&r.claims, r.view, slashed, &r.vset) {
            if ldr == self.me() && !r.proposed_views.contains(&r.view) && !self.withhold_proposals {
                r.proposed_views.insert(r.view);
                if self.equivocate {
                    // Byzantine: double-sign two conflicting blocks for this slot.
                    let a = self.assemble_block(chain, r, pending, pending_membership, false);
                    let b = self.assemble_block(chain, r, pending, pending_membership, true);
                    debug!(height = r.height, view = r.view, "EQUIVOCATING (double-signing the slot)");
                    mixer.publish(peers, r.beacon_t, Message::Proposal(a));
                    mixer.publish(peers, r.beacon_t, Message::Proposal(b));
                } else {
                    let block = self.assemble_block(chain, r, pending, pending_membership, false);
                    let bid = block_id(&block.header, &block.txs);
                    debug!(height = r.height, view = r.view, txs = block.txs.len(), "proposing as VRF leader");
                    r.blocks.insert(bid, block.clone());
                    mixer.publish(peers, r.beacon_t, Message::Proposal(block));
                    self.cast_vote(r, bid, peers, mixer);
                }
            }
            if r.voted.is_none() {
                if let Some((bid, _)) = r
                    .blocks
                    .iter()
                    .find(|(_, b)| b.header.view == r.view && b.header.proposer_peer == ldr)
                    .map(|(k, v)| (*k, v.clone()))
                {
                    self.cast_vote(r, bid, peers, mixer);
                }
            }
        }
        self.try_finalize(r, chain, peers, mixer);
    }

    /// Once a block has a quorum of votes, aggregate them into a quorum certificate, append, broadcast.
    fn try_finalize(&self, r: &mut Round, chain: &mut Chain, peers: &PeersMap, mixer: &Mixer) {
        let q = quorum(r.vset.len());
        // A block finalizes on a quorum of votes from CURRENT members whose view matches the block's
        // own view (a vote claiming a different view signed different bytes and cannot count, and a
        // non-member's vote — e.g. a departed validator — does not count toward the new quorum).
        let ready = r.blocks.iter().find_map(|(bid, b)| {
            let bview = b.header.view;
            let n = r
                .votes
                .get(bid)
                .map(|vs| vs.values().filter(|v| v.view == bview && r.vset.contains(&v.voter)).count())
                .unwrap_or(0);
            (n >= q).then_some(*bid)
        });
        if let Some(bid) = ready {
            let bview = r.blocks[&bid].header.view;
            let mut signers = Vec::new();
            let mut sigs: Vec<[u8; 96]> = Vec::new();
            for (peer, vote) in &r.votes[&bid] {
                if vote.view != bview || !r.vset.contains(peer) {
                    continue;
                }
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
                mixer.publish(peers, r.beacon_t, Message::Finalized(fb));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_msg(
        &self,
        msg: Message,
        round: Option<&mut Round>,
        chain: &mut Chain,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
        pending_membership: &mut Vec<MembershipOp>,
        peers: &PeersMap,
        mixer: &Mixer,
        slashed: &mut HashSet<[u8; 32]>,
    ) {
        // Best-available beacon to seed any mixnet path entropy for messages we re-gossip here.
        let beacon_hint =
            round.as_deref().map(|r| r.beacon_t).unwrap_or_else(|| chain.head().header.beacon_t);
        match msg {
            Message::Tx(tx) => {
                if tx.verify_sig() {
                    pending.insert((tx.height, tx.epoch_id), tx);
                }
            }
            Message::Membership(op) => {
                // Pool self-authorized membership ops for the next leader to record on-chain, and
                // re-gossip the first time we see one so it reaches the full mesh even when the
                // originator is only partially connected (bounded: dedup by subject stops the flood).
                if self.op_admissible(&op)
                    && !pending_membership.iter().any(|o| o.subject() == op.subject())
                {
                    pending_membership.push(op.clone());
                    mixer.publish(peers, beacon_hint, Message::Membership(op));
                }
            }
            Message::Vrf(c) => {
                if let Some(r) = round {
                    // Only a current member's VRF claim counts (its vrf_pk is in the active set).
                    let ok = c.height == r.height
                        && r.vset.vrf.get(&c.peer).is_some_and(|pk| c.verify(r.beacon_t, pk));
                    if ok {
                        r.claims.insert(c.peer, c.output);
                    }
                }
            }
            Message::Proposal(b) => {
                if let Some(r) = round {
                    if b.header.height == r.height
                        && self.valid_proposal(chain, &b, &r.claims, slashed, &r.vset)
                    {
                        let bview = b.header.view;
                        let bid = block_id(&b.header, &b.txs);
                        let proposer = b.header.proposer_peer;
                        let key = (proposer, bview);
                        // equivocation: same proposer already signed a DIFFERENT block at this slot.
                        if let Some((prev_id, prev_sig)) = r.seen_proposals.get(&key).cloned() {
                            if prev_id != bid {
                                let proof = EquivocationProof {
                                    proposer,
                                    height: r.height,
                                    view: bview,
                                    id_a: prev_id,
                                    sig_a: prev_sig,
                                    id_b: bid,
                                    sig_b: b.proposer_sig.clone(),
                                };
                                if proof.verify() && slashed.insert(proposer) {
                                    info!(slashed = %hex::encode(&proposer[..4]), height = r.height, view = bview, "slashed equivocating proposer");
                                    mixer.publish(peers, r.beacon_t, Message::Slash(proof));
                                }
                                return; // never store or vote for an equivocator's block
                            }
                        } else {
                            r.seen_proposals.insert(key, (bid, b.proposer_sig.clone()));
                        }
                        r.blocks.entry(bid).or_insert(b);
                        // valid_proposal already confirmed the proposer is the leader for `bview`,
                        // so vote iff it matches our current view and we haven't voted in it yet.
                        if Instant::now() >= r.vrf_deadline && r.voted.is_none() && bview == r.view {
                            self.cast_vote(r, bid, peers, mixer);
                        }
                        self.try_finalize(r, chain, peers, mixer);
                    }
                }
            }
            Message::Vote(v) => {
                if let Some(r) = round {
                    if slashed.contains(&v.voter) {
                        return; // ignore votes from an already-slashed validator
                    }
                    let ok = v.height == r.height
                        && r.vset.contains(&v.voter)
                        && r.vset.bls.get(&v.voter).is_some_and(|pk| v.verify(pk));
                    if ok {
                        let key = (v.voter, v.view);
                        // double-vote: this voter already signed a DIFFERENT block id at this slot.
                        if let Some((prev_id, prev_sig)) = r.seen_votes.get(&key).cloned() {
                            if prev_id != v.block_id {
                                let proof = VoteEquivocationProof {
                                    voter: v.voter,
                                    height: r.height,
                                    view: v.view,
                                    id_a: prev_id,
                                    sig_a: prev_sig,
                                    id_b: v.block_id,
                                    sig_b: v.bls_sig.clone(),
                                };
                                let verified =
                                    r.vset.bls.get(&v.voter).is_some_and(|pk| proof.verify(pk));
                                if verified && slashed.insert(v.voter) {
                                    info!(slashed = %hex::encode(&v.voter[..4]), height = r.height, view = v.view, "slashed double-voting validator");
                                    mixer.publish(peers, r.beacon_t, Message::SlashVote(proof));
                                }
                                return; // never count an equivocator's vote
                            }
                        } else {
                            r.seen_votes.insert(key, (v.block_id, v.bls_sig.clone()));
                        }
                        r.votes.entry(v.block_id).or_default().insert(v.voter, v);
                        self.try_finalize(r, chain, peers, mixer);
                    }
                }
            }
            Message::Finalized(b) => {
                if self.valid_block(chain, &b) {
                    let _ = chain.try_append(b);
                }
            }
            Message::Slash(proof) => {
                let vset = self.active_set_at(&chain.blocks, proof.height);
                if vset.contains(&proof.proposer) && proof.verify() && slashed.insert(proof.proposer) {
                    info!(slashed = %hex::encode(&proof.proposer[..4]), "slashed via gossiped equivocation evidence");
                }
            }
            Message::SlashVote(proof) => {
                let vset = self.active_set_at(&chain.blocks, proof.height);
                if vset.contains(&proof.voter)
                    && vset.bls.get(&proof.voter).is_some_and(|pk| proof.verify(pk))
                    && slashed.insert(proof.voter)
                {
                    info!(slashed = %hex::encode(&proof.voter[..4]), "slashed via gossiped double-vote evidence");
                }
            }
            Message::GetChain { from_height } => {
                let bs = chain.blocks_from(from_height);
                if !bs.is_empty() {
                    // Routed through the mixnet when enabled (fragmented if large), else direct.
                    mixer.publish(peers, beacon_hint, Message::ChainRange(bs));
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
            // A mix packet: peel one layer and forward to the next hop, or — if we are the
            // destination — re-inject the recovered consensus message into our inbox.
            Message::Sphinx(pkt) => mixer.handle_sphinx(pkt, peers),
        }
    }

    pub async fn run(self) -> NodeOutcome {
        let peers: PeersMap = Arc::new(Mutex::new(HashMap::new()));
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<Message>();
        let _keepalive = inbox_tx.clone();
        let my_id = self.me();
        let listen_addr = self.config.listen_addr.clone();

        // Shared address book of known validators (peer_id -> dial addr), seeded from the bootstrap
        // set and grown as the chain admits new members (and from peers' Hellos). The dial task
        // consults it, so a newly-joined validator becomes dialable once the network learns its addr.
        let known: Arc<Mutex<HashMap<[u8; 32], String>>> = Arc::new(Mutex::new(
            self.config.genesis_validators.iter().map(|v| (v.peer_id, v.addr.clone())).collect(),
        ));

        let listener = TcpListener::bind(&self.config.listen_addr).await.expect("bind");
        {
            let peers = peers.clone();
            let inbox = inbox_tx.clone();
            let identity = self.identity.clone();
            let listen_addr = listen_addr.clone();
            let known = known.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        // Inbound dial: we are the Noise responder.
                        tokio::spawn(run_conn(
                            stream, identity.clone(), listen_addr.clone(), false, inbox.clone(),
                            peers.clone(), known.clone(),
                        ));
                    }
                }
            });
        }
        // Dynamic dial task: periodically dial every known peer with a larger id we are not already
        // connected to (the smaller-id side dials, so each pair forms exactly one connection). Driven
        // by `known`, it naturally picks up validators that join after genesis.
        {
            let peers = peers.clone();
            let inbox = inbox_tx.clone();
            let identity = self.identity.clone();
            let listen_addr = listen_addr.clone();
            let known = known.clone();
            let inflight: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_millis(150));
                loop {
                    ticker.tick().await;
                    let targets: Vec<([u8; 32], String)> = {
                        let k = known.lock().unwrap();
                        k.iter().filter(|(pid, _)| **pid > my_id).map(|(p, a)| (*p, a.clone())).collect()
                    };
                    for (pid, addr) in targets {
                        let busy = peers.lock().unwrap().contains_key(&pid)
                            || !inflight.lock().unwrap().insert(pid);
                        if busy {
                            continue;
                        }
                        let (peers, inbox, identity, listen_addr, known, inflight) = (
                            peers.clone(), inbox.clone(), identity.clone(), listen_addr.clone(),
                            known.clone(), inflight.clone(),
                        );
                        tokio::spawn(async move {
                            if let Ok(stream) = TcpStream::connect(&addr).await {
                                // Outbound dial: we are the Noise initiator.
                                run_conn(stream, identity, listen_addr, true, inbox, peers, known).await;
                            }
                            inflight.lock().unwrap().remove(&pid);
                        });
                    }
                }
            });
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        info!(peer = %hex::encode(&my_id[..4]), validators = self.genesis.len(), quorum = quorum(self.genesis.len()), "node up, entering consensus loop");

        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut chain = Chain::genesis();
        let mut pending: HashMap<(u64, u64), EpochTransaction> = HashMap::new();
        let mut pending_membership: Vec<MembershipOp> = Vec::new();
        let mut epoch_ids: Vec<(u64, u64)> = Vec::new();
        let mut beacons: Vec<(u64, u64)> = Vec::new();
        let mut split_ok = true;
        let mut round: Option<Round> = None;
        let mut slashed: HashSet<[u8; 32]> = HashSet::new();
        let mut done_at: Option<Instant> = None;
        let mut ticker = interval(Duration::from_millis(10));

        // The mixnet router: enabled when `with_mixnet` supplied settings, else a transparent
        // pass-through that broadcasts directly (preserving the original behavior exactly).
        let mixer = match &self.mix_settings {
            Some(s) => {
                info!(hops = s.hops, mean_delay_ms = s.mean_delay_ms, mixes = s.directory.len(), "consensus gossip routed through the Loopix mixnet");
                Mixer {
                    enabled: true,
                    me: my_id,
                    mix_sk: self.identity.mix_sk(),
                    settings: s.clone(),
                    nonce: AtomicU64::new(0),
                    msg_seq: AtomicU64::new(0),
                    reasm: Mutex::new(Reassembler::new(512)),
                    inbox_tx: inbox_tx.clone(),
                }
            }
            None => Mixer {
                enabled: false,
                me: my_id,
                mix_sk: self.identity.mix_sk(),
                settings: MixSettings { directory: MixDirectory::default(), hops: 0, mean_delay_ms: 0 },
                nonce: AtomicU64::new(0),
                msg_seq: AtomicU64::new(0),
                reasm: Mutex::new(Reassembler::new(512)),
                inbox_tx: inbox_tx.clone(),
            },
        };

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
                        need, &chain, &peers, &mixer, &mut pending, &mut epoch_ids, &mut beacons,
                        &mut split_ok, &mut rng,
                    ));
                    pending.retain(|(h, _), _| *h > head_h); // prune finalized heights
                    // Drop membership ops already realized by the finalized chain (self-healing: an
                    // op still pending here means no finalized block has applied it yet).
                    let next = self.active_set_at(&chain.blocks, need);
                    pending_membership.retain(|op| match op {
                        MembershipOp::Add { record, .. } => !next.contains(&record.peer_id),
                        MembershipOp::Remove { peer_id, .. } => next.contains(peer_id),
                    });
                    // Learn the dial addresses of all current members so the dial task can reach a
                    // newly-admitted validator.
                    {
                        let mut k = known.lock().unwrap();
                        for (p, a) in &next.addr {
                            k.insert(*p, a.clone());
                        }
                    }
                }
            }

            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(r) = round.as_mut() {
                        self.on_tick(r, &mut chain, &pending, &pending_membership, &peers, &mixer, &slashed);
                    }
                }
                Some(msg) = inbox_rx.recv() => {
                    self.on_msg(msg, round.as_mut(), &mut chain, &mut pending, &mut pending_membership, &peers, &mixer, &mut slashed);
                }
            }
        }

        let all_qc_valid = chain.blocks.iter().skip(1).all(|b| {
            let vs = self.active_set_at(&chain.blocks, b.header.height);
            qc_valid(b, &vs.peers, &vs.bls)
        });
        let max_view = chain.blocks.iter().map(|b| b.header.view).max().unwrap_or(0);
        let mut slashed_vec: Vec<[u8; 32]> = slashed.iter().copied().collect();
        slashed_vec.sort();
        let final_active = self.active_set_at(&chain.blocks, chain.head().header.height + 1).peers;
        info!(peer = %hex::encode(&my_id[..4]), blocks = chain.blocks.len(), head = %hex::encode(&chain.head_hash()[..4]), all_qc_valid, max_view, slashed = slashed_vec.len(), active = final_active.len(), "node done");
        NodeOutcome {
            peer_id: my_id,
            head_hash: chain.head_hash(),
            blocks_len: chain.blocks.len(),
            epoch_ids,
            beacons,
            split_ok,
            all_qc_valid,
            max_view,
            slashed: slashed_vec,
            final_active,
        }
    }
}

/// Domain-separated channel-binding message: the ed25519 signature in `Hello` covers this, binding
/// the long-term identity to the specific Noise handshake (see `transport.rs`).
const NOISE_BINDING_DOMAIN: &[u8] = b"privacf-noise-binding-v1";
fn binding_msg(hs_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(NOISE_BINDING_DOMAIN.len() + 32);
    m.extend_from_slice(NOISE_BINDING_DOMAIN);
    m.extend_from_slice(hs_hash);
    m
}

/// Drive one peer connection: run the Noise XX handshake, then exchange a `Hello` whose ed25519
/// `binding` authenticates the remote's identity against the handshake hash (defeating a MITM on
/// the anonymous-static XX exchange), register a writer, and forward decrypted reads to the inbox.
#[allow(clippy::too_many_arguments)]
async fn run_conn(
    stream: TcpStream,
    identity: Arc<NodeIdentity>,
    listen_addr: String,
    initiator: bool,
    inbox: mpsc::UnboundedSender<Message>,
    peers: PeersMap,
    known: Arc<Mutex<HashMap<[u8; 32], String>>>,
) {
    let _ = stream.set_nodelay(true);
    let mut stream = stream;
    let (chan, hs_hash) = match noise_handshake(&mut stream, initiator).await {
        Ok(x) => x,
        Err(_) => return,
    };
    let chan = Arc::new(chan);
    let (mut rd, mut wr) = stream.into_split();

    // Bind our long-term ed25519 identity to THIS Noise channel by signing its handshake hash.
    let binding = identity.sign(&binding_msg(&hs_hash)).to_bytes().to_vec();
    let my_hello =
        Message::Hello { peer_id: identity.peer_id(), listen_addr, binding };

    let mut send_nonce: u64 = 0;
    let mut recv_nonce: u64 = 0;
    if write_frame(&mut wr, &chan, &mut send_nonce, &my_hello).await.is_err() {
        return;
    }
    let remote = match read_frame(&mut rd, &chan, &mut recv_nonce).await {
        Ok(Message::Hello { peer_id, listen_addr: remote_addr, binding }) => {
            // The remote must prove it controls `peer_id` AND that this is the same channel — a
            // valid ed25519 signature over our shared handshake hash establishes both.
            let sig = match ed25519_dalek::Signature::from_slice(&binding) {
                Ok(s) => s,
                Err(_) => return,
            };
            if !verify_ed25519(&peer_id, &binding_msg(&hs_hash), &sig) {
                return;
            }
            // Learn the peer's advertised dial address (helps reverse-dial a newcomer we have not
            // yet seen on-chain).
            known.lock().unwrap().insert(peer_id, remote_addr);
            peer_id
        }
        _ => return,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    {
        // Dedup: if we already hold a connection to this peer, drop this redundant one.
        let mut p = peers.lock().unwrap();
        if p.contains_key(&remote) {
            return;
        }
        p.insert(remote, tx);
    }
    let chan_w = chan.clone();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if write_frame(&mut wr, &chan_w, &mut send_nonce, &m).await.is_err() {
                break;
            }
        }
    });
    loop {
        match read_frame(&mut rd, &chan, &mut recv_nonce).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transport_frames_bypass_the_mixnet() {
        // Chain-sync and every consensus message route through the mixnet; only the pre-mixnet
        // handshake and the mix packet itself stay direct.
        assert!(Mixer::is_routable(&Message::GetChain { from_height: 0 }));
        assert!(!Mixer::is_routable(&Message::Hello {
            peer_id: [0u8; 32],
            listen_addr: String::new(),
            binding: Vec::new(),
        }));
    }
}
