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
use crate::audit::FirstObservation;
use crate::beacon::{next_beacon, next_beacon_vdf};
use crate::bls;
use crate::arbitration::{CustodyParcel, HandoffReceipt, ReshareParcel};
use crate::rewind::RewindSignal;
use crate::verdict::VerdictCommit;
use crate::watchdog::WatchdogSignal;
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
                mix_pk: id.mix_pk(),
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
    /// The `target_epoch_id`s suspended by a finalized dark-node verdict on this node's chain (sorted).
    /// With autonomous verdicts (`with_verdict_authority`) this is non-empty when a malformed tx was
    /// objectively suspended; all honest nodes converge on the same set.
    pub suspended_targets: Vec<u64>,
    /// The audit subjects flagged as a likely Sybil cohort by the admission-time burst detector over
    /// the finalized first-observation reports (sorted). A pure function of the chain, so all honest
    /// nodes agree (see `flagged_cohort` / `audit.rs`).
    pub flagged_cohort: Vec<u64>,
    /// Count of first-observation audit reports recorded across this node's finalized chain — evidence
    /// the in-loop observers (`with_audit_authority`) actually attested.
    pub audit_reports_recorded: usize,
    /// Whether the in-loop §4.9.8 watchdog reached a signal quorum on this node's finalized chain — a
    /// recursive-oversight trigger over an anomalous verdict-commit burst. A pure function of the chain,
    /// so all honest nodes converge (see `oversight_triggered` / `watchdog.rs`).
    pub oversight_triggered: bool,
    /// Count of watchdog signals recorded across this node's finalized chain (evidence the in-loop
    /// watchers attested), and of public verdict-commits (the burst they flagged).
    pub watchdog_signals_recorded: usize,
    pub verdict_commits_recorded: usize,
    /// Whether the in-loop §6.6 rewind path reached a Class-3 trigger on this node's finalized chain: a
    /// quorum of distinct rewind signals spanning ≥2 interest clusters, all naming the on-chain
    /// item-velocity spike epoch. A pure function of the chain, so all honest nodes converge (see
    /// `class3_triggered` / `rewind.rs`).
    pub class3_triggered: bool,
    /// Count of rewind signals recorded across this node's finalized chain — evidence the in-loop
    /// recommendation participants (`with_rewind_authority`) actually attested to the poisoning cohort.
    pub rewind_signals_recorded: usize,
    /// Count of §4.1/§6.4 arbitration handoff receipts recorded across this node's finalized chain.
    pub handoff_receipts_recorded: usize,
    /// Whether every departed node with a live handoff reached a custody threshold of valid recorded
    /// receipts — the §4.1 handoff completed under the new committee's custody. A pure function of the
    /// chain, so all honest nodes agree (see `handoff_completed_count` / `arbitration.rs`).
    pub handoff_complete: bool,
    /// Committee members slashed for §6.4 handoff default — selected but filed no valid receipt by the
    /// deadline (sorted). A pure function of the chain, so all honest nodes derive the same set; these
    /// also appear in `slashed` (leadership exclusion).
    pub handoff_defaults: Vec<[u8; 32]>,
    /// Whether every **re-handoff** (proactive custody rotation triggered when an original committee member
    /// departs) reached a custody threshold of valid round-1 receipts under its fresh beacon-selected
    /// committee — the departed-custodian rotation completed without the subject's profile ever losing
    /// threshold custody. A pure function of the chain (`rehandoff_complete`); `false` if none was triggered.
    pub rehandoff_complete: bool,
    /// The §5.3/§5.4 PSI-discovered interest-peers (sorted): peers this node privately found to share at
    /// least `PSI_THRESHOLD` liked items, via DH-PSI over the mesh. Local, off-chain discovery — empty
    /// unless this node ran `with_psi_discovery`. Distinct nodes legitimately discover different sets.
    pub interest_peers: Vec<[u8; 32]>,
}

/// The public, chain-derived context of one arbitration handoff (`handoff_context`).
struct HandoffCtx {
    subject_peer: [u8; 32],
    height: u64,
    c_old: [u8; 32],
    width: usize,
    committee: Vec<[u8; 32]>,
}

/// The public, chain-derived context of a **re-handoff** (`rehandoff_context`) — the proactive custody
/// rotation triggered when an original committee member departs. Everything is re-derived identically by
/// every node from the chain: the same on-chain `c_old`, the `trigger_height` (the departing custodian's
/// `Remove`), the fresh beacon-selected `new_committee`, and the canonical set of surviving dealers
/// (`canonical` = the `CUSTODY_THRESHOLD` survivors with the lowest original share index, paired with that
/// index) whose distributed re-share every new member must combine over identically.
struct ReHandoffCtx {
    nonce: u64, // rehandoff_subject(orig_subject, round)
    subject_peer: [u8; 32],
    c_old: [u8; 32],
    width: usize,
    trigger_height: u64,
    new_committee: Vec<[u8; 32]>,
    canonical: Vec<(u64, [u8; 32])>, // (original 1-based share index, original member) — the dealers
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
    /// If set with `joining`, the node holds back its join op until this height — so it is admitted only
    /// after an earlier event (e.g. a handoff already formed its committee), not from boot.
    join_at: Option<u64>,
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
    /// If true and this node holds a threshold-key share, it autonomously drives *objective* verdicts
    /// in-loop: each tick it scans finalized epoch txs, and for any whose published gossip row is
    /// objectively malformed (`verdict_policy`) it emits its `σ_VERDICT` partial; `⌊K/2⌋+1` partials
    /// combine into a dark-node suspension with no off-chain coordination. Honest default `false`.
    verdict_authority: bool,
    /// Test fault injection: when attaching a `PreferencePayload`, overwrite the obfuscated gossip row
    /// with an out-of-bound vector (the cheap CF-amplification attack), making the tx objectively
    /// malformed so the autonomous verdict path can suspend it. Honest default `false`.
    malform_pref: bool,
    /// If true, this node acts as a Class-2 audit observer in-loop: each tick it scans the finalized
    /// chain for newly-admitted subjects, and for any it is VRF-selected to observe (`audit.rs`) it
    /// emits a signed `FirstObservation` report for the next leader to record in
    /// `BlockHeader::audit_reports`. Every node then derives the admission-time burst (Sybil-cohort)
    /// flag from the on-chain reports. Honest default `false`.
    audit_authority: bool,
    /// If true, this node is an in-loop §4.9.8 watchdog: each tick it scans the on-chain verdict-commit
    /// count, and if it is anomalous (a burst beyond `THRESHOLD_WATCHDOG` unmatched by behavioral
    /// signals) it raises a signed `WatchdogSignal` for the next leader to record in
    /// `BlockHeader::watchdog_signals`. A quorum of distinct signers triggers recursive oversight. Every
    /// node then derives the trigger from the on-chain signals. Honest default `false`.
    watchdog_authority: bool,
    /// Fault injection: if non-empty, this node is a rogue committee mounting mass-deanonymization —
    /// each tick it publicly posts a `verdict_commit` (SUSPEND) against each configured *innocent*
    /// `target_epoch_id`. The §4.9.6 commit-reveal ordering forces these to be public before any `null_v`
    /// is decryptable, so the burst (with no behavioral justification) is what the watchdog catches.
    /// Honest default empty.
    rogue_commit_targets: Vec<u64>,
    /// If true, this node is an in-loop §6.6 rewind participant: each tick it scans the on-chain gossip
    /// columns for an item-velocity spike (`rewind.rs`); when a *foreign* item (not its own dominant
    /// interest) spikes, it raises a signed `RewindSignal` for the next leader to record in
    /// `BlockHeader::rewind_signals`. A quorum of distinct signers across ≥2 clusters triggers a Class-3
    /// audit. Every node then derives the trigger from the on-chain signals. Honest default `false`.
    rewind_authority: bool,
    /// If true, this node serves on §4.1/§6.4 arbitration committees: when it is beacon-selected for a
    /// departing node's handoff and receives its custody parcel, it re-encrypts the subject's on-chain
    /// `C_p` under a fresh blinding it holds and files a signed `HandoffReceipt`. Honest default `false`.
    arbitration_authority: bool,
    /// Fault injection: a committee member that opens its custody parcel but files NO handoff receipt —
    /// the non-completion the §6.4 slashing path defaults and slashes. Honest default `false`.
    withhold_handoff: bool,
    /// If true, this node runs §5.3/§5.4 PSI interest-peer discovery as an additive logical overlay: each
    /// tick it offers its blinded liked-item set to one not-yet-probed peer (`psi.rs` DH-PSI); on the
    /// response it learns only the intersection SIZE and records the peer as an interest-peer when the
    /// overlap meets `PSI_THRESHOLD`. Purely local (never on-chain), fully decoupled from consensus — it
    /// does NOT gate validator dialing (that would partition the BFT mesh). Honest default `false`.
    psi_discovery: bool,
    /// Fault injection: if `Some((item, weight, from_epoch))`, this node is part of a coordinated push
    /// cohort — from epoch `from_epoch` it overwrites its obfuscated gossip with a single, within-bound
    /// concentration on `item` (weight `weight`). Several such nodes spike `item`'s on-chain gossip
    /// velocity — an individually-valid but coordinated push the rewind path catches. Honest default `None`.
    push_item: Option<(usize, f32, u64)>,
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
            join_at: None,
            mix_settings: None,
            admission: None,
            join_vdf: std::sync::OnceLock::new(),
            beacon_vdf: None,
            preferences: None,
            dp_epsilon: 5.0,
            verdict_authority: false,
            malform_pref: false,
            audit_authority: false,
            watchdog_authority: false,
            rogue_commit_targets: Vec::new(),
            rewind_authority: false,
            arbitration_authority: false,
            withhold_handoff: false,
            psi_discovery: false,
            push_item: None,
        }
    }

    /// Builder: let this node act as an in-loop Class-2 first-observation audit observer
    /// (`drive_audit`) — VRF-selecting itself per newly-admitted subject and emitting signed reports
    /// the next leader records on-chain, driving the admission-time burst detector.
    pub fn with_audit_authority(mut self) -> Self {
        self.audit_authority = true;
        self
    }

    /// Builder: let this node act as an in-loop §4.9.8 watchdog (`drive_watchdog`) — raising a signed
    /// `WatchdogSignal` when the on-chain verdict-commit burst is anomalous, for the next leader to
    /// record. A quorum of distinct signers triggers recursive oversight network-wide.
    pub fn with_watchdog_authority(mut self) -> Self {
        self.watchdog_authority = true;
        self
    }

    /// Builder: let this node act as an in-loop §6.6 rewind participant (`drive_rewind`) — raising a
    /// signed `RewindSignal` when an on-chain gossip cohort spikes a *foreign* item into its
    /// recommendations, for the next leader to record. A quorum of distinct signers across ≥2 interest
    /// clusters, all naming the same cohort epoch, triggers a Class-3 audit network-wide. Requires
    /// preferences (`with_preferences`) so the node has a dominant interest to judge foreignness against.
    pub fn with_rewind_authority(mut self) -> Self {
        self.rewind_authority = true;
        self
    }

    /// Builder: let this node serve on §4.1/§6.4 arbitration committees (`drive`/`on_msg` custody +
    /// handoff). When beacon-selected for a departing node it re-encrypts the subject's on-chain `C_p`
    /// under a fresh blinding and files a signed `HandoffReceipt` the next leader records.
    pub fn with_arbitration_authority(mut self) -> Self {
        self.arbitration_authority = true;
        self
    }

    /// Fault-injection builder: a committee member that takes custody but files no handoff receipt,
    /// exercising the §6.4 default detection + slashing path.
    pub fn byzantine_withhold_handoff(mut self) -> Self {
        self.arbitration_authority = true;
        self.withhold_handoff = true;
        self
    }

    /// Builder: run §5.3/§5.4 PSI interest-peer discovery (`drive_psi`) as an additive logical overlay over
    /// the existing mesh. Discovers, privately, which peers share enough liked items to be cluster peers —
    /// purely local, never on-chain, and decoupled from consensus connectivity. Requires `with_preferences`
    /// (the node's clean liked items are the PSI input; only blinded points and the overlap size leave it).
    pub fn with_psi_discovery(mut self) -> Self {
        self.psi_discovery = true;
        self
    }

    /// Fault-injection builder: from epoch `from_epoch`, concentrate this node's obfuscated gossip on a
    /// single `item` at `weight` (within the public `[0, B]` bound, so the tx stays objectively valid and
    /// the verdict path cannot suspend it). A cohort of such nodes spikes the item's gossip velocity — a
    /// coordinated push that only the §6.6 rewind / Class-3 path catches.
    pub fn byzantine_push_item(mut self, item: usize, weight: f32, from_epoch: u64) -> Self {
        self.push_item = Some((item, weight, from_epoch));
        self
    }

    /// Fault-injection builder: a rogue committee that publicly posts a burst of verdict-commits
    /// (SUSPEND) against `targets` (innocent pseudonyms), modelling the §4.9.8 mass-deanonymization the
    /// watchdog defends against. Because the commit is public before any `null_v` is decryptable, the
    /// burst is caught at the commit stage — before a single identity is exposed.
    pub fn byzantine_rogue_verdict_commits(mut self, targets: Vec<u64>) -> Self {
        self.rogue_commit_targets = targets;
        self
    }

    /// Builder: let this node autonomously drive *objective* dark-node verdicts inside the consensus
    /// loop (`verdict_policy` + `drive_verdicts`). Requires a threshold-key share to emit partials;
    /// without one the flag is inert. See `with_threshold_key`.
    pub fn with_verdict_authority(mut self) -> Self {
        self.verdict_authority = true;
        self
    }

    /// Fault-injection builder: publish an objectively-malformed gossip row each epoch (over the public
    /// `[0, B]` clamp), so a verdict-authority validator suspends this node via the autonomous path.
    pub fn byzantine_malformed_pref(mut self) -> Self {
        self.malform_pref = true;
        self
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

    /// The set of `null_v`s already suspended somewhere in `blocks` (any height) — used to dedup new
    /// suspensions so a block never re-records an existing one.
    fn already_suspended(&self, blocks: &[Block]) -> HashSet<u64> {
        blocks.iter().flat_map(|b| b.header.suspensions.iter().map(|s| s.null_v)).collect()
    }

    /// Find the on-chain commitment `(s₁, d_T)` published by the pseudonym `target_epoch_id`.
    fn commitment_for(&self, blocks: &[Block], target_epoch_id: u64) -> Option<(u64, Vec<u8>)> {
        blocks
            .iter()
            .flat_map(|b| b.txs.iter())
            .find(|tx| tx.epoch_id == target_epoch_id)
            .map(|tx| (tx.commit.s1, tx.commit.d_t.clone()))
    }

    /// Build a [`SuspendRecord`] from a verdict signature: look up the target's on-chain `(s₁, d_T)`,
    /// extract `null_v = s₁ + s₂` with NO node cooperation, and bind the record to `σ_VERDICT`
    /// (`verdict_hash = H(σ)`). `None` if the target's commitment is not on-chain or `σ` does not
    /// decrypt it (the pairing only yields `null_v` under the `VA_pub` that sealed `d_T`).
    fn make_suspension(&self, blocks: &[Block], target_epoch_id: u64, sigma: &[u8; 96]) -> Option<crate::verdict::SuspendRecord> {
        let (s1, d_t) = self.commitment_for(blocks, target_epoch_id)?;
        let null_v = crate::verdict::extract_null_v(s1, &d_t, sigma, target_epoch_id)?;
        Some(crate::verdict::SuspendRecord { target_epoch_id, null_v, verdict_hash: *blake3::hash(sigma).as_bytes() })
    }

    /// Independently validate that `record` is a legitimate suspension authorized by `sigma`: the
    /// `verdict_hash` binds `σ`, and re-extracting from the target's on-chain `(s₁, d_T)` reproduces
    /// `record.null_v`. Self-contained from public chain data — a successful extraction proves a verdict
    /// threshold quorum signed `verdict_id(target_epoch_id)` (only such a `σ` decrypts `d_T`), so the
    /// proposer cannot fabricate a suspension.
    fn validate_suspension(&self, blocks: &[Block], record: &crate::verdict::SuspendRecord, sigma: &[u8; 96]) -> bool {
        record.verdict_hash == *blake3::hash(sigma).as_bytes()
            && self.make_suspension(blocks, record.target_epoch_id, sigma).is_some_and(|r| r.null_v == record.null_v)
    }

    /// The set of `target_epoch_id`s already suspended by a finalized `SuspendRecord` — the dedup the
    /// autonomous verdict driver uses to stop re-opening a verdict on an already-suspended target.
    fn suspended_targets(&self, blocks: &[Block]) -> HashSet<u64> {
        blocks.iter().flat_map(|b| b.header.suspensions.iter().map(|s| s.target_epoch_id)).collect()
    }

    /// Is the pseudonym `target_epoch_id` published on-chain with an *objectively malformed* preference
    /// row (`verdict_policy`)? The publicly-checkable predicate every honest validator agrees on, and
    /// the gate for both emitting and pooling verdict partials (so the partial flood is bounded to
    /// genuine targets).
    fn target_is_malformed(&self, blocks: &[Block], target_epoch_id: u64) -> bool {
        blocks
            .iter()
            .flat_map(|b| b.txs.iter())
            .any(|tx| tx.epoch_id == target_epoch_id && crate::verdict_policy::objective_suspend(&tx.pref))
    }

    /// Autonomous *objective* verdict driver (SPEC §4.9.6, objective branch). Each tick, a
    /// verdict-authority validator scans finalized epoch txs; for every target whose published gossip
    /// is objectively malformed and not already suspended, it emits its `σ_VERDICT` partial **once**
    /// (`emitted`), pools its own partial, and tries to combine. The partial *is* the SUSPEND vote —
    /// only emitted because the local deterministic policy flagged the on-chain tx — so `⌊K/2⌋+1`
    /// partials reconstruct exactly the verdict signature the commit-reveal path would produce, with no
    /// off-chain coordination.
    #[allow(clippy::too_many_arguments)]
    fn drive_verdicts(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        emitted: &mut HashSet<u64>,
        partials: &mut HashMap<u64, HashMap<u64, [u8; 96]>>,
        pending_suspensions: &mut Vec<(crate::verdict::SuspendRecord, [u8; 96])>,
    ) {
        if !self.verdict_authority || self.threshold_key.is_none() {
            return;
        }
        let suspended = self.suspended_targets(&chain.blocks);
        // Distinct malformed targets currently on-chain.
        let targets: Vec<u64> = {
            let mut seen = HashSet::new();
            chain
                .blocks
                .iter()
                .flat_map(|b| b.txs.iter())
                .filter(|tx| crate::verdict_policy::objective_suspend(&tx.pref))
                .map(|tx| tx.epoch_id)
                .filter(|t| seen.insert(*t))
                .collect()
        };
        for target in targets {
            if suspended.contains(&target) || emitted.contains(&target) {
                continue;
            }
            if let Some((index, partial)) = self.verdict_partial(target) {
                emitted.insert(target);
                partials.entry(target).or_default().insert(index, partial);
                mixer.publish(
                    peers,
                    beacon,
                    Message::VerdictPartial { target_epoch_id: target, index, partial: partial.to_vec() },
                );
                self.try_combine_verdict(chain, target, partials, pending_suspensions, peers, mixer, beacon);
            }
        }
    }

    /// Once `threshold` distinct-index partials are pooled for `target`, Lagrange-combine them
    /// (`dkg::combine_signatures`) and gate the result through `make_suspension`/`validate_suspension`:
    /// only a real quorum's `σ_VERDICT` decrypts the target's on-chain `d_T`, so a malformed partial
    /// can at worst delay (liveness), never forge (safety). On success the suspension joins the pending
    /// pool and is broadcast so the existing `Message::Suspension` path carries it network-wide.
    #[allow(clippy::too_many_arguments)]
    fn try_combine_verdict(
        &self,
        chain: &Chain,
        target: u64,
        partials: &HashMap<u64, HashMap<u64, [u8; 96]>>,
        pending_suspensions: &mut Vec<(crate::verdict::SuspendRecord, [u8; 96])>,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
    ) {
        let threshold = match &self.threshold_key {
            Some(tk) => tk.threshold,
            None => return,
        };
        let Some(parts) = partials.get(&target) else { return };
        if parts.len() < threshold {
            return;
        }
        if self.already_suspended(&chain.blocks).contains(&target)
            || pending_suspensions.iter().any(|(r, _)| r.target_epoch_id == target)
        {
            return; // already finalized or pooled
        }
        // Combine the lowest-index `threshold` partials (any valid subset interpolates identically).
        let mut collected: Vec<(u64, [u8; 96])> = parts.iter().map(|(i, p)| (*i, *p)).collect();
        collected.sort_by_key(|(i, _)| *i);
        let subset = &collected[..threshold];
        let Some(sigma) = crate::dkg::combine_signatures(subset) else { return };
        if let Some(record) = self.make_suspension(&chain.blocks, target, &sigma) {
            if self.validate_suspension(&chain.blocks, &record, &sigma)
                && !self.already_suspended(&chain.blocks).contains(&record.null_v)
                && !pending_suspensions.iter().any(|(r, _)| r.null_v == record.null_v)
            {
                debug!(target, null_v = record.null_v, "objective verdict reached σ_VERDICT — suspending");
                pending_suspensions.push((record, sigma));
                mixer.publish(
                    peers,
                    beacon,
                    Message::Suspension { target_epoch_id: target, sigma: sigma.to_vec() },
                );
            }
        }
    }

    /// Post-genesis admission events on-chain: `subject_id` → (peer_id, admission height, admission
    /// beacon). A subject is a peer first added by a finalized `MembershipOp::Add`; genesis members are
    /// the presupposed-good bootstrap and are NOT audit subjects. A pure function of the finalized
    /// chain, so every node derives identical admissions — the ground truth the audit reports attest to.
    fn admissions(&self, blocks: &[Block]) -> HashMap<u64, ([u8; 32], u64, u64)> {
        let genesis: HashSet<[u8; 32]> = self.genesis.iter().map(|r| r.peer_id).collect();
        let mut out: HashMap<u64, ([u8; 32], u64, u64)> = HashMap::new();
        for b in blocks {
            for op in &b.header.membership_ops {
                if let MembershipOp::Add { record, .. } = op {
                    if genesis.contains(&record.peer_id) {
                        continue;
                    }
                    out.entry(crate::audit::subject_id(&record.peer_id))
                        .or_insert((record.peer_id, b.header.height, b.header.beacon_t));
                }
            }
        }
        out
    }

    /// The `(observer, subject)` keys of every audit report already finalized on `blocks` — the dedup
    /// the proposer and validators use so a report is recorded at most once.
    fn recorded_audit_keys(&self, blocks: &[Block]) -> HashSet<([u8; 32], u64)> {
        blocks
            .iter()
            .flat_map(|b| b.header.audit_reports.iter())
            .map(|r| (r.observer, r.subject_epoch_id))
            .collect()
    }

    /// Independently validate a first-observation report against public chain data: the subject must be
    /// a genuinely post-genesis-admitted peer, the claimed `first_seen_epoch` must equal its on-chain
    /// admission height (pinning the attestation to truth — no fabricated timing), the observer must
    /// have been a validator at that height with the report's registered `vrf_pk`, and the VRF proof +
    /// signature must verify under the admission beacon. Self-contained, so every node agrees.
    fn validate_audit_report(&self, blocks: &[Block], r: &FirstObservation) -> bool {
        let Some((_, h_admit, beacon_admit)) = self.admissions(blocks).get(&r.subject_epoch_id).copied()
        else {
            return false; // not a real newly-admitted subject
        };
        if r.first_seen_epoch != h_admit {
            return false; // the report must attest the true admission epoch
        }
        // The observer must have been a registered validator at the admission height, binding its
        // claimed vrf_pk to its peer id (the registry check `FirstObservation::verify` defers to us).
        if self.active_set_at(blocks, h_admit).vrf.get(&r.observer) != Some(&r.vrf_pk) {
            return false;
        }
        r.verify(beacon_admit, crate::audit::SELECT_THRESHOLD)
    }

    /// The admission-time first-seen map derived from the finalized audit reports: subject → median
    /// observed epoch ([`audit::first_seen_map`](crate::audit::first_seen_map)). Built only from reports
    /// that re-validate, so a node never folds in unauthenticated timing.
    fn audit_first_seen(&self, blocks: &[Block]) -> std::collections::BTreeMap<u64, u64> {
        let valid: Vec<FirstObservation> = blocks
            .iter()
            .flat_map(|b| b.header.audit_reports.iter())
            .filter(|r| self.validate_audit_report(blocks, r))
            .cloned()
            .collect();
        crate::audit::first_seen_map(&valid)
    }

    /// The Sybil-cohort flag: subjects whose admission-time burst (over the on-chain attestation
    /// reports) trips [`audit::BURST_THRESHOLD`](crate::audit::BURST_THRESHOLD) within
    /// [`audit::BURST_WINDOW`](crate::audit::BURST_WINDOW). A pure function of the finalized chain, so
    /// all honest nodes converge on the same flagged set (exposed in `NodeOutcome`).
    fn flagged_cohort(&self, blocks: &[Block]) -> Vec<u64> {
        crate::audit::flagged_cohort(
            &self.audit_first_seen(blocks),
            crate::audit::BURST_WINDOW,
            crate::audit::BURST_THRESHOLD,
        )
    }

    /// Autonomous Class-2 audit observer (SPEC §4.9.7/§7). Each tick, an audit-authority validator
    /// scans the finalized chain for newly-admitted subjects; for each one it has not yet observed and
    /// is VRF-selected for (`audit.rs`), it emits a signed `FirstObservation` (pinned to the on-chain
    /// admission epoch), pools it, and gossips it for the next leader to record in
    /// `BlockHeader::audit_reports`. Recording is idempotent — a report already on-chain is skipped —
    /// so the report flood is bounded to one per (observer, subject).
    fn drive_audit(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        observed: &mut HashSet<u64>,
        audit_pool: &mut Vec<FirstObservation>,
    ) {
        if !self.audit_authority {
            return;
        }
        let on_chain = self.recorded_audit_keys(&chain.blocks);
        for (sid, (_peer, h_admit, beacon_admit)) in self.admissions(&chain.blocks) {
            if observed.contains(&sid) {
                continue;
            }
            observed.insert(sid);
            // The report carries its VRF proof + lottery; emit only if this node is a selected observer.
            let report = FirstObservation::create(&self.identity, sid, h_admit, beacon_admit);
            if !crate::audit::selected(&report.lottery, crate::audit::SELECT_THRESHOLD) {
                continue;
            }
            let key = (self.me(), sid);
            if on_chain.contains(&key) || audit_pool.iter().any(|r| (r.observer, r.subject_epoch_id) == key) {
                continue;
            }
            audit_pool.push(report.clone());
            mixer.publish(peers, beacon, Message::Audit(report));
        }
    }

    // ───────────────────────────── §4.9.8 watchdog / recursive oversight ─────────────────────────────

    /// Every `(member, target_epoch_id, commit_hash)` verdict-commit already finalized on `blocks` — the
    /// dedup the proposer and validators use so a public commit is recorded at most once.
    fn recorded_commit_keys(&self, blocks: &[Block]) -> HashSet<([u8; 32], u64, [u8; 32])> {
        blocks
            .iter()
            .flat_map(|b| b.header.verdict_commits.iter())
            .map(|c| (c.member, c.target_epoch_id, c.commit_hash))
            .collect()
    }

    /// Every `(signer, round)` watchdog signal already finalized on `blocks` — the recording dedup.
    fn recorded_watchdog_keys(&self, blocks: &[Block]) -> HashSet<([u8; 32], u64)> {
        blocks
            .iter()
            .flat_map(|b| b.header.watchdog_signals.iter())
            .map(|s| (s.epoch_id, s.epoch_t))
            .collect()
    }

    /// The cumulative count of valid on-chain verdict-commits, and how many are *behaviorally justified*
    /// (their target carries an objectively-malformed on-chain tx). The watchdog fires only when the
    /// commit burst outruns the behavioral signals — a genuine misbehavior wave would carry matching
    /// behavioral evidence (`anomalous`). A pure function of the finalized chain.
    fn commit_counts(&self, blocks: &[Block]) -> (u64, u64) {
        let (mut observed, mut justified) = (0u64, 0u64);
        for c in blocks.iter().flat_map(|b| b.header.verdict_commits.iter()) {
            if !c.verify() {
                continue;
            }
            observed += 1;
            if self.target_is_malformed(blocks, c.target_epoch_id) {
                justified += 1;
            }
        }
        (observed, justified)
    }

    /// The canonical oversight round for the current chain: the height of the first finalized block
    /// carrying any verdict-commit (the epoch the burst began). `None` until a commit is on-chain.
    /// Deterministic, so every node keys its watchdog signal to the same round and they tally together.
    fn oversight_round(&self, blocks: &[Block]) -> Option<u64> {
        blocks.iter().find(|b| !b.header.verdict_commits.is_empty()).map(|b| b.header.height)
    }

    /// Independently validate a watchdog signal against public chain data: the signature checks, the
    /// claimed rate band matches `EXPECTED_RATE`, the signer was a validator at the round it names, the
    /// round is the chain's canonical oversight round, the on-chain verdict-commit burst is genuinely
    /// anomalous *now*, and the claimed count does not exceed what is actually on-chain (no inflation).
    /// Self-contained, so a proposer cannot inject a false oversight trigger and every node agrees.
    fn validate_watchdog_signal(&self, blocks: &[Block], s: &WatchdogSignal) -> bool {
        if !s.verify() || s.expected_rate_milli != crate::watchdog::expected_rate_milli() {
            return false;
        }
        if !self.active_set_at(blocks, s.epoch_t).contains(&s.epoch_id) {
            return false;
        }
        if self.oversight_round(blocks) != Some(s.epoch_t) {
            return false;
        }
        let (observed, justified) = self.commit_counts(blocks);
        crate::watchdog::anomalous(
            observed,
            crate::watchdog::EXPECTED_RATE,
            crate::watchdog::THRESHOLD_WATCHDOG,
            justified,
        ) && s.observed_commits <= observed
    }

    /// Whether the in-loop watchdog has reached a signal quorum on `blocks`: a recursive-oversight
    /// trigger over an anomalous verdict-commit burst. A pure function of the finalized chain (the
    /// signals and the burst both live on-chain), so all honest nodes converge on the same verdict.
    fn oversight_triggered(&self, blocks: &[Block]) -> bool {
        let Some(round) = self.oversight_round(blocks) else { return false };
        let signals: Vec<WatchdogSignal> =
            blocks.iter().flat_map(|b| b.header.watchdog_signals.iter().cloned()).collect();
        crate::watchdog::tally_signals(&signals, round) >= crate::watchdog::SIGNAL_QUORUM
    }

    /// Rogue mass-deanonymization driver (fault injection, §4.9.8). Each tick a rogue node publicly
    /// posts a `verdict_commit` (SUSPEND) against each configured innocent `target` exactly once
    /// (`committed`), pools it, and gossips it for the next leader to record. The verdict stays hidden
    /// (the matching reveal is never sent); the *public commitment* is what the watchdog counts.
    fn drive_rogue_commits(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        committed: &mut HashSet<u64>,
        commit_pool: &mut Vec<VerdictCommit>,
    ) {
        if self.rogue_commit_targets.is_empty() {
            return;
        }
        let recorded = self.recorded_commit_keys(&chain.blocks);
        for &target in &self.rogue_commit_targets {
            if !committed.insert(target) {
                continue;
            }
            // Deterministic nonce: the value stays hidden behind the commit hash, but the commitment is
            // reproducible (no stored state) and uniquely this node's.
            let mut h = blake3::Hasher::new();
            h.update(b"privacf-rogue-commit-nonce-v1");
            h.update(&target.to_le_bytes());
            h.update(&self.me());
            let nonce = *h.finalize().as_bytes();
            let (commit, _reveal) =
                crate::verdict::cast(&self.identity, target, crate::verdict::SUSPEND, nonce);
            let key = (commit.member, commit.target_epoch_id, commit.commit_hash);
            if recorded.contains(&key)
                || commit_pool.iter().any(|c| (c.member, c.target_epoch_id, c.commit_hash) == key)
            {
                continue;
            }
            commit_pool.push(commit.clone());
            mixer.publish(peers, beacon, Message::VerdictCommit(commit));
        }
    }

    /// Autonomous §4.9.8 watchdog driver. Once the on-chain verdict-commit burst is anomalous, a
    /// watchdog-authority node raises its signed `WatchdogSignal` for the canonical oversight round
    /// **once** (`raised`), pools it, and gossips it for the next leader to record. `SIGNAL_QUORUM`
    /// distinct signers on-chain then trigger recursive oversight — all derived from public chain data.
    fn drive_watchdog(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        raised: &mut bool,
        watchdog_pool: &mut Vec<WatchdogSignal>,
    ) {
        if !self.watchdog_authority || *raised {
            return;
        }
        let (observed, justified) = self.commit_counts(&chain.blocks);
        if !crate::watchdog::anomalous(
            observed,
            crate::watchdog::EXPECTED_RATE,
            crate::watchdog::THRESHOLD_WATCHDOG,
            justified,
        ) {
            return;
        }
        let Some(round) = self.oversight_round(&chain.blocks) else { return };
        *raised = true;
        let signal =
            WatchdogSignal::raise(&self.identity, round, observed, crate::watchdog::EXPECTED_RATE);
        let key = (signal.epoch_id, signal.epoch_t);
        if self.recorded_watchdog_keys(&chain.blocks).contains(&key)
            || watchdog_pool.iter().any(|s| (s.epoch_id, s.epoch_t) == key)
        {
            return;
        }
        watchdog_pool.push(signal.clone());
        mixer.publish(peers, beacon, Message::Watchdog(signal));
    }

    // ───────────────────────────────── §6.6 rewind / Class-3 trigger ─────────────────────────────────

    /// Every `(signer, cohort_epoch)` rewind signal already finalized on `blocks` — the recording dedup.
    fn recorded_rewind_keys(&self, blocks: &[Block]) -> HashSet<([u8; 32], u64)> {
        blocks
            .iter()
            .flat_map(|b| b.header.rewind_signals.iter())
            .map(|s| (s.epoch_id, s.cohort_epoch))
            .collect()
    }

    /// Per-epoch on-chain gossip column sums: `height → Σ gossip` over every preference-carrying epoch
    /// tx finalized at that height. The aggregate the item-velocity detector differences across epochs.
    fn gossip_column_sums(&self, blocks: &[Block]) -> std::collections::BTreeMap<u64, Vec<f64>> {
        let mut by_h: std::collections::BTreeMap<u64, Vec<f64>> = std::collections::BTreeMap::new();
        for b in blocks {
            for tx in &b.txs {
                if let Some(p) = tx.pref.as_ref() {
                    let row = by_h.entry(b.header.height).or_default();
                    if row.len() < p.gossip.len() {
                        row.resize(p.gossip.len(), 0.0);
                    }
                    for (j, &v) in p.gossip.iter().enumerate() {
                        row[j] += v as f64;
                    }
                }
            }
        }
        by_h
    }

    /// The chain's canonical item-velocity spike (§6.6 / §7.1a T.8): the earliest epoch at which some
    /// item's total on-chain gossip weight jumps by more than `VELOCITY_THRESHOLD` over the previous
    /// epoch, and the item with the largest such jump there. The public signature of a coordinated push
    /// cohort — a pure function of the finalized chain, so every node agrees on `(cohort_epoch, item)`.
    fn velocity_spike(&self, blocks: &[Block]) -> Option<(u64, usize)> {
        let sums = self.gossip_column_sums(blocks);
        let epochs: Vec<u64> = sums.keys().copied().collect();
        for w in epochs.windows(2) {
            let (prev, cur) = (w[0], w[1]);
            let (pv, cv) = (&sums[&prev], &sums[&cur]);
            let mut best: Option<(usize, f64)> = None;
            for j in 0..cv.len() {
                let vel = cv[j] - pv.get(j).copied().unwrap_or(0.0);
                if vel > crate::rewind::VELOCITY_THRESHOLD && best.map_or(true, |(_, bv)| vel > bv) {
                    best = Some((j, vel));
                }
            }
            if let Some((item, _)) = best {
                return Some((cur, item));
            }
        }
        None
    }

    /// This node's own dominant interest — the argmax of its clean preference vector. `None` if it has no
    /// preferences (then it cannot judge an item's foreignness and never raises a rewind signal).
    fn my_dominant_item(&self) -> Option<usize> {
        let prefs = self.preferences.as_ref()?;
        prefs.iter().enumerate().max_by(|(_, a), (_, b)| a.cmp(b)).map(|(i, _)| i)
    }

    /// The interest cluster of `signer`, derived deterministically from public chain data: the dominant
    /// item (argmax) of its most recent on-chain gossip row. Every node reads the same finalized gossip,
    /// so all agree on each signer's cluster (the cross-cluster correlation `class3_trigger` needs).
    fn signaler_cluster(&self, blocks: &[Block], signer: &[u8; 32]) -> Option<usize> {
        let gossip = blocks
            .iter()
            .rev()
            .flat_map(|b| b.txs.iter().rev())
            .find(|tx| &tx.submitter == signer && tx.pref.is_some())
            .and_then(|tx| tx.pref.as_ref())
            .map(|p| &p.gossip)?;
        gossip.iter().enumerate().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)).map(|(i, _)| i)
    }

    /// Independently validate a rewind signal against public chain data: the signature checks, the named
    /// `cohort_epoch` is the chain's canonical item-velocity spike, `preferred_t` is the epoch before it,
    /// the signer was a participant at that epoch, and the signer's own interest cluster differs from the
    /// pushed item (it is a cross-niche victim, the §6.6 structural requirement). Self-contained, so a
    /// proposer cannot inject a false Class-3 trigger and every node agrees on the recorded signals.
    fn validate_rewind_signal(&self, blocks: &[Block], s: &RewindSignal) -> bool {
        if !s.verify() {
            return false;
        }
        let Some((cohort_epoch, item)) = self.velocity_spike(blocks) else { return false };
        if s.cohort_epoch != cohort_epoch || cohort_epoch == 0 || s.preferred_t != cohort_epoch - 1 {
            return false;
        }
        if !self.active_set_at(blocks, cohort_epoch).contains(&s.epoch_id) {
            return false;
        }
        self.signaler_cluster(blocks, &s.epoch_id).map_or(false, |c| c != item)
    }

    /// Whether the in-loop rewind path has reached a §6.6 Class-3 trigger on `blocks`: a quorum of
    /// distinct recorded rewind signals spanning ≥2 interest clusters, all naming the canonical
    /// item-velocity spike epoch. A pure function of the finalized chain (signals and clusters both live
    /// on-chain), so all honest nodes converge.
    fn class3_triggered(&self, blocks: &[Block]) -> bool {
        let Some((cohort_epoch, _item)) = self.velocity_spike(blocks) else { return false };
        let signals: Vec<RewindSignal> =
            blocks.iter().flat_map(|b| b.header.rewind_signals.iter().cloned()).collect();
        let mut clusters: Vec<([u8; 32], u64)> = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for s in &signals {
            if seen.insert(s.epoch_id) {
                if let Some(c) = self.signaler_cluster(blocks, &s.epoch_id) {
                    clusters.push((s.epoch_id, c as u64));
                }
            }
        }
        crate::rewind::class3_trigger(&signals, &clusters, crate::rewind::REWIND_Q, crate::rewind::MIN_CLUSTERS)
            .iter()
            .any(|t| t.cohort_epoch == cohort_epoch)
    }

    /// Autonomous §6.6 rewind driver. Once the on-chain gossip shows an item-velocity spike in an item
    /// *foreign* to this node's own interest, a rewind-authority node raises its signed `RewindSignal`
    /// **once** (`raised`), pools it, and gossips it for the next leader to record. `REWIND_Q` distinct
    /// signers across `MIN_CLUSTERS` clusters then trigger a Class-3 audit — all from public chain data.
    fn drive_rewind(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        raised: &mut bool,
        rewind_pool: &mut Vec<RewindSignal>,
    ) {
        if !self.rewind_authority || *raised {
            return;
        }
        let Some((cohort_epoch, item)) = self.velocity_spike(&chain.blocks) else { return };
        if cohort_epoch == 0 {
            return;
        }
        // Only a *foreign* spike (not our own dominant interest) implicates a poisoning cohort.
        match self.my_dominant_item() {
            Some(d) if d != item => {}
            _ => return,
        }
        let current_t = chain.head().header.height;
        let preferred_t = cohort_epoch - 1;
        if preferred_t >= current_t {
            return;
        }
        *raised = true;
        let signal = RewindSignal::raise(&self.identity, current_t, preferred_t, cohort_epoch);
        let key = (signal.epoch_id, signal.cohort_epoch);
        if self.recorded_rewind_keys(&chain.blocks).contains(&key)
            || rewind_pool.iter().any(|s| (s.epoch_id, s.cohort_epoch) == key)
        {
            return;
        }
        rewind_pool.push(signal.clone());
        mixer.publish(peers, beacon, Message::Rewind(signal));
    }

    // ───────────────────────────────── §4.1/§6.4 arbitration handoff ─────────────────────────────────

    /// Every `(member, subject)` handoff receipt already finalized on `blocks` — the recording dedup.
    fn recorded_handoff_keys(&self, blocks: &[Block]) -> HashSet<([u8; 32], u64)> {
        blocks
            .iter()
            .flat_map(|b| b.header.handoff_receipts.iter())
            .map(|r| (r.member, r.subject))
            .collect()
    }

    /// The public context of a `subject`'s handoff, re-derived identically by every node from the chain:
    /// the departed node's peer, the height/beacon it last committed at, its on-chain `c_old` and vector
    /// width, and the beacon-selected committee (the subject itself excluded). `None` until the subject's
    /// preference-carrying transaction is finalized.
    fn handoff_context(&self, blocks: &[Block], subject: u64) -> Option<HandoffCtx> {
        let (subject_peer, height, beacon, c_old, width) = blocks.iter().find_map(|b| {
            b.txs.iter().find(|t| t.epoch_id == subject && t.pref.is_some()).map(|t| {
                let p = t.pref.as_ref().unwrap();
                (t.submitter, b.header.height, b.header.beacon_t, p.c_p, p.gossip.len())
            })
        })?;
        let pool: Vec<[u8; 32]> =
            self.active_set_at(blocks, height).peers.into_iter().filter(|p| *p != subject_peer).collect();
        let committee = crate::arbitration::select_committee(&pool, beacon, subject, crate::arbitration::COMMITTEE_SIZE);
        Some(HandoffCtx { subject_peer, height, c_old, width, committee })
    }

    /// This member's deterministic fresh blinding `r_new` for `subject`'s re-encrypted commitment — bound
    /// to its own `sk` and the subject, so it is reproducible (no stored per-handoff state) and the
    /// committee never shares a blinding.
    fn handoff_r_new(&self, subject: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"privacf-arbitration-r-new-v1");
        h.update(&to_u64(self.identity.sk).to_le_bytes());
        h.update(&subject.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// How many committee members have a valid recorded receipt for `subject` (`arbitration::settle` over
    /// the on-chain receipts). A pure function of the finalized chain, so all nodes agree.
    fn handoff_completed_count(&self, blocks: &[Block], subject: u64) -> usize {
        let Some(ctx) = self.any_handoff_context(blocks, subject) else { return 0 };
        let pc = crate::pedersen::Pedersen::new(ctx.width.max(1));
        let receipts: Vec<HandoffReceipt> =
            blocks.iter().flat_map(|b| b.header.handoff_receipts.iter().cloned()).collect();
        let (completed, _) = crate::arbitration::settle(&pc, &ctx.c_old, &ctx.committee, subject, &receipts);
        completed.len()
    }

    /// The committee members that **defaulted** on a handoff (§6.4): for every subject whose deadline
    /// (`HANDOFF_DEADLINE` epochs past its departure) has elapsed on `blocks`, the selected members with
    /// no valid recorded receipt. A pure function of the finalized chain (committee, receipts, and
    /// deadline all on-chain), so every node slashes the same set with no extra evidence message.
    fn handoff_defaults(&self, blocks: &[Block]) -> Vec<[u8; 32]> {
        let head = blocks.last().map(|b| b.header.height).unwrap_or(0);
        let receipts: Vec<HandoffReceipt> =
            blocks.iter().flat_map(|b| b.header.handoff_receipts.iter().cloned()).collect();
        let mut out: Vec<[u8; 32]> = Vec::new();
        // Both rounds default-slash identically: a round-0 subject (an `epoch_id`) and, when a re-handoff
        // was triggered, its round-1 nonce — each settled over its own committee via `any_handoff_context`.
        for subject in self.defaultable_subjects(blocks) {
            let Some(ctx) = self.any_handoff_context(blocks, subject) else { continue };
            if head < ctx.height + crate::arbitration::HANDOFF_DEADLINE {
                continue; // the round is still open
            }
            let pc = crate::pedersen::Pedersen::new(ctx.width.max(1));
            let (_, defaulted) = crate::arbitration::settle(&pc, &ctx.c_old, &ctx.committee, subject, &receipts);
            for d in defaulted {
                if !out.contains(&d.member) {
                    out.push(d.member);
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Every subject that can incur a handoff default: each departed node's round-0 `epoch_id`, plus the
    /// round-1 re-handoff nonce for any subject whose re-handoff has been triggered. A pure function of the
    /// chain, so every node settles the same default set across both rounds.
    fn defaultable_subjects(&self, blocks: &[Block]) -> Vec<u64> {
        let mut subjects = self.handoff_subjects(blocks);
        for orig in self.handoff_subjects(blocks) {
            if let Some(rctx) = self.rehandoff_context(blocks, orig) {
                subjects.push(rctx.nonce);
            }
        }
        subjects
    }

    /// Independently validate a handoff receipt against public chain data: its subject has a finalized
    /// `c_old`, the member is in the beacon-selected committee, and the signed re-encryption proof binds
    /// `c_new` to `c_old`. Self-contained, so a proposer cannot inject a forged handoff.
    fn validate_handoff_receipt(&self, blocks: &[Block], r: &HandoffReceipt) -> bool {
        let Some(ctx) = self.any_handoff_context(blocks, r.subject) else { return false };
        let pc = crate::pedersen::Pedersen::new(ctx.width.max(1));
        r.verify(&pc, &ctx.c_old, &ctx.committee)
    }

    /// The subjects with a live handoff on `blocks`: each departed node (a finalized `Remove`) contributes
    /// exactly the preference epoch_id of its **profile at departure** — the latest preference transaction
    /// at or before the height its `Remove` was recorded (so a removed node's post-departure gossip can't
    /// move the subject). A pure function of the chain, so every node derives the same subject set with no
    /// off-chain signal.
    fn handoff_subjects(&self, blocks: &[Block]) -> Vec<u64> {
        // earliest height each departed peer's Remove was recorded at
        let mut remove_h: HashMap<[u8; 32], u64> = HashMap::new();
        for b in blocks {
            for op in &b.header.membership_ops {
                if let MembershipOp::Remove { peer_id, .. } = op {
                    remove_h.entry(*peer_id).or_insert(b.header.height);
                }
            }
        }
        // per departed peer, its preference epoch_id at the greatest height ≤ its remove height
        let mut best: HashMap<[u8; 32], (u64, u64)> = HashMap::new();
        for b in blocks {
            for t in &b.txs {
                if !t.pref.is_some() {
                    continue;
                }
                if let Some(&rh) = remove_h.get(&t.submitter) {
                    if b.header.height <= rh {
                        let e = best.entry(t.submitter).or_insert((0, 0));
                        if b.header.height >= e.0 {
                            *e = (b.header.height, t.epoch_id);
                        }
                    }
                }
            }
        }
        let mut out: Vec<u64> = best.values().map(|(_, e)| *e).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Leaver-side custody dispatch (§4.1/§6.4). Once this node's departure is finalized, it Shamir-splits
    /// its custody secret across its beacon-selected committee and seals each share + the on-chain
    /// commitment blinding `r_old` to that member's `mix_pk` (`arbitration::seal_custody`), gossiping one
    /// confidential parcel per member. Re-dispatched at most once per height (`last_height`) until a
    /// threshold of custodians have filed — so a dropped parcel self-heals without flooding.
    fn drive_custody_dispatch(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        last_height: &mut Option<u64>,
    ) {
        if self.leave_at.is_none() || self.preferences.is_none() {
            return; // only a configured leaver with a profile dispatches custody
        }
        let head = chain.head().header.height;
        if *last_height == Some(head) {
            return; // at most one dispatch per height (re-dispatch self-heals dropped parcels)
        }
        // Our own departure subject — derived from the chain exactly as every other node derives it, so
        // the committee files for the same subject we dispatch for.
        let mine: Vec<(u64, HandoffCtx)> = self
            .handoff_subjects(&chain.blocks)
            .into_iter()
            .filter_map(|s| self.handoff_context(&chain.blocks, s).map(|c| (s, c)))
            .filter(|(_, c)| c.subject_peer == self.me())
            .collect();
        if mine.is_empty() {
            return; // our Remove is not finalized yet
        }
        *last_height = Some(head);
        let sk_handle = self.pref_sk_handle();
        for (subject, ctx) in mine {
            if self.handoff_completed_count(&chain.blocks, subject) >= crate::arbitration::CUSTODY_THRESHOLD {
                continue; // enough custodians already hold this handoff
            }
            let r_old = crate::epoch::pref_blinding(&sk_handle, subject);
            let vset = self.active_set_at(&chain.blocks, ctx.height);
            let custody = crate::dkg::shamir_split(
                &sk_handle,
                crate::arbitration::CUSTODY_THRESHOLD,
                ctx.committee.len().max(1),
                b"handoff-custody",
            );
            for (i, member) in ctx.committee.iter().enumerate() {
                let Some(mix_pk) = vset.mix.get(member).copied() else { continue };
                let mut hs = blake3::Hasher::new();
                hs.update(b"privacf-arbitration-eph-seed-v1");
                hs.update(&to_u64(self.identity.sk).to_le_bytes());
                hs.update(&subject.to_le_bytes());
                hs.update(member);
                let eph_seed = *hs.finalize().as_bytes();
                if let Some(parcel) =
                    crate::arbitration::seal_custody(&mix_pk, subject, member, &r_old, &custody[i].1, &eph_seed)
                {
                    mixer.publish(peers, beacon, Message::CustodyDispatch(parcel));
                }
            }
        }
    }

    /// Committee-member reaction to a custody parcel addressed to this node: open it, re-blind the
    /// subject's on-chain `c_old` to a fresh `r_new` it controls (homomorphically, never seeing the
    /// vector), prove the re-encryption, and file a signed receipt for the next leader to record. Pools
    /// once per subject (`recorded`/`pool` dedup).
    #[allow(clippy::too_many_arguments)]
    fn handle_custody_parcel(
        &self,
        chain: &Chain,
        parcel: &CustodyParcel,
        handoff_pool: &mut Vec<HandoffReceipt>,
        custody_held: &mut HashMap<u64, ([u8; 32], [u8; 32])>,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
    ) {
        if !self.arbitration_authority || parcel.member != self.me() || self.withhold_handoff {
            return; // a withholding member opens nothing it would have to file
        }
        let subject = parcel.subject;
        let key = (self.me(), subject);
        if self.recorded_handoff_keys(&chain.blocks).contains(&key)
            || handoff_pool.iter().any(|r| (r.member, r.subject) == key)
        {
            return;
        }
        let Some(ctx) = self.handoff_context(&chain.blocks, subject) else { return };
        if !ctx.committee.contains(&self.me()) {
            return;
        }
        let Some((r_old, share)) = crate::arbitration::open_custody(&self.identity.mix_sk(), parcel) else { return };
        let pc = crate::pedersen::Pedersen::new(ctx.width.max(1));
        let r_new = self.handoff_r_new(subject);
        let Some(c_new) = crate::arbitration::reencrypt(&pc, &ctx.c_old, &r_old, &r_new) else { return };
        let mut hs = blake3::Hasher::new();
        hs.update(b"privacf-arbitration-reenc-seed-v1");
        hs.update(&to_u64(self.identity.sk).to_le_bytes());
        hs.update(&subject.to_le_bytes());
        let seed = *hs.finalize().as_bytes();
        let proof = crate::arbitration::prove_reencryption(&pc, &ctx.c_old, &c_new, &r_old, &r_new, &seed);
        let receipt = HandoffReceipt::create(&self.identity, subject, c_new, proof, &share);
        if !receipt.verify(&pc, &ctx.c_old, &ctx.committee) {
            return;
        }
        handoff_pool.push(receipt.clone());
        mixer.publish(peers, beacon, Message::Handoff(receipt));
        // Remember our custody (the on-chain blinding + our Shamir share) so that, if an original
        // committee member later departs, we can proactively re-share it to a fresh committee.
        custody_held.insert(subject, (r_old, share));
    }

    // ─────────────────────────── §4.1/§6.4 re-handoff (proactive custody rotation) ───────────────────────────

    /// The single supported re-handoff round (round 1). Generalising to round ≥ 2 (a re-handoff of a
    /// re-handoff) is mechanical — re-key the nonce/committee off the previous round — but bounded here.
    const REHANDOFF_ROUND: u32 = 1;

    /// Earliest height each peer's `Remove` was finalized at (a departure), across `blocks`.
    fn remove_heights(&self, blocks: &[Block]) -> HashMap<[u8; 32], u64> {
        let mut out: HashMap<[u8; 32], u64> = HashMap::new();
        for b in blocks {
            for op in &b.header.membership_ops {
                if let MembershipOp::Remove { peer_id, .. } = op {
                    out.entry(*peer_id).or_insert(b.header.height);
                }
            }
        }
        out
    }

    /// The re-handoff context for an original `orig_subject`, or `None` if no re-handoff is triggered: it
    /// requires (1) a completed round-0 handoff and (2) at least one original committee member departed
    /// after the handoff. Pure function of the chain, so every node derives the identical fresh committee
    /// and canonical dealer set.
    fn rehandoff_context(&self, blocks: &[Block], orig_subject: u64) -> Option<ReHandoffCtx> {
        let base = self.handoff_context(blocks, orig_subject)?;
        if self.handoff_completed_count(blocks, orig_subject) < crate::arbitration::CUSTODY_THRESHOLD {
            return None; // round 0 never reached custody — nothing to rotate
        }
        let removes = self.remove_heights(blocks);
        // Surviving original custodians, each tagged with its 1-based original share index (= committee
        // position + 1, matching the round-0 `shamir_split` ordering). A departure after the handoff
        // height triggers the rotation.
        let mut survivors: Vec<(u64, [u8; 32])> = Vec::new();
        let mut any_departed = false;
        for (pos, member) in base.committee.iter().enumerate() {
            match removes.get(member) {
                Some(&rh) if rh >= base.height => any_departed = true, // departed custodian
                _ => survivors.push((pos as u64 + 1, *member)),
            }
        }
        if !any_departed || survivors.len() < crate::arbitration::CUSTODY_THRESHOLD {
            return None; // no trigger, or too few survivors to re-share the secret
        }
        // Canonical dealer set: the threshold survivors with the lowest original share index. Every node
        // and every new member combines the re-share over EXACTLY this set.
        survivors.sort_unstable_by_key(|(idx, _)| *idx);
        let canonical: Vec<(u64, [u8; 32])> =
            survivors.into_iter().take(crate::arbitration::CUSTODY_THRESHOLD).collect();
        // The trigger height: the earliest departure of an original custodian after the handoff.
        let trigger_height = base
            .committee
            .iter()
            .filter_map(|m| removes.get(m).copied().filter(|&rh| rh >= base.height))
            .min()?;
        let beacon = blocks.iter().find(|b| b.header.height == trigger_height).map(|b| b.header.beacon_t)?;
        let nonce = crate::arbitration::rehandoff_subject(orig_subject, Self::REHANDOFF_ROUND);
        // Fresh committee: validators active at the trigger, excluding the subject AND the entire original
        // committee — a genuinely rotated custody. Falls back to including survivors if the pool is thin.
        let active = self.active_set_at(blocks, trigger_height).peers;
        let exclude: HashSet<[u8; 32]> =
            base.committee.iter().copied().chain(std::iter::once(base.subject_peer)).collect();
        let mut pool: Vec<[u8; 32]> = active.iter().copied().filter(|p| !exclude.contains(p)).collect();
        if pool.len() < crate::arbitration::CUSTODY_THRESHOLD {
            // Thin validator set: allow surviving originals back in (still excludes the subject + departed).
            let departed: HashSet<[u8; 32]> = base
                .committee
                .iter()
                .copied()
                .filter(|m| removes.get(m).map(|&rh| rh >= base.height).unwrap_or(false))
                .collect();
            pool = active
                .iter()
                .copied()
                .filter(|p| *p != base.subject_peer && !departed.contains(p))
                .collect();
        }
        let new_committee =
            crate::arbitration::select_committee(&pool, beacon, nonce, crate::arbitration::COMMITTEE_SIZE);
        Some(ReHandoffCtx {
            nonce,
            subject_peer: base.subject_peer,
            c_old: base.c_old,
            width: base.width,
            trigger_height,
            new_committee,
            canonical,
        })
    }

    /// Unified handoff context resolving EITHER a round-0 subject (an `epoch_id` with an on-chain pref tx)
    /// or a round-1 re-handoff nonce — used by the generic settle/validate paths so round-1 receipts ride
    /// the same recording/validation machinery as round-0, keyed only by their distinct subject nonce.
    fn any_handoff_context(&self, blocks: &[Block], subject: u64) -> Option<HandoffCtx> {
        if let Some(ctx) = self.handoff_context(blocks, subject) {
            return Some(ctx); // round 0
        }
        // round 1: is `subject` the re-handoff nonce of some departed node's original subject?
        for orig in self.handoff_subjects(blocks) {
            if crate::arbitration::rehandoff_subject(orig, Self::REHANDOFF_ROUND) == subject {
                let r = self.rehandoff_context(blocks, orig)?;
                return Some(HandoffCtx {
                    subject_peer: r.subject_peer,
                    height: r.trigger_height,
                    c_old: r.c_old,
                    width: r.width,
                    committee: r.new_committee,
                });
            }
        }
        None
    }

    /// Whether every triggered re-handoff has reached a custody threshold of valid round-1 receipts under
    /// its fresh committee — the proactive rotation completed. A pure function of the chain.
    fn rehandoff_complete(&self, blocks: &[Block]) -> bool {
        let triggered: Vec<u64> = self
            .handoff_subjects(blocks)
            .into_iter()
            .filter_map(|orig| self.rehandoff_context(blocks, orig).map(|r| r.nonce))
            .collect();
        !triggered.is_empty()
            && triggered
                .iter()
                .all(|&nonce| self.handoff_completed_count(blocks, nonce) >= crate::arbitration::CUSTODY_THRESHOLD)
    }

    /// Dealer side of the re-handoff: a canonical surviving custodian proactively re-shares the custody it
    /// holds (its round-0 Shamir share + the on-chain blinding `r_old`, from `custody_held`) to the fresh
    /// committee — `dkg::reshare_subdeal` of its share, sealed per new member (`arbitration::seal_reshare`),
    /// so the secret is rotated without anyone reconstructing it. Re-dispatched at most once per height
    /// until a threshold of new custodians have filed.
    #[allow(clippy::too_many_arguments)]
    fn drive_rehandoff(
        &self,
        chain: &Chain,
        custody_held: &HashMap<u64, ([u8; 32], [u8; 32])>,
        reshare_held: &mut HashMap<u64, Vec<(u64, [u8; 32], [u8; 32])>>,
        handoff_pool: &mut Vec<HandoffReceipt>,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        last_height: &mut Option<u64>,
    ) {
        if !self.arbitration_authority {
            return;
        }
        let head = chain.head().header.height;
        if *last_height == Some(head) {
            return;
        }
        let mut dispatched = false;
        for orig in self.handoff_subjects(&chain.blocks) {
            let Some(rctx) = self.rehandoff_context(&chain.blocks, orig) else { continue };
            // Am I a canonical dealer for this re-handoff, and do I still hold the custody?
            let Some(&(my_index, _)) = rctx.canonical.iter().find(|(_, m)| *m == self.me()) else { continue };
            let Some(&(r_old, share)) = custody_held.get(&orig) else { continue };
            if self.handoff_completed_count(&chain.blocks, rctx.nonce) >= crate::arbitration::CUSTODY_THRESHOLD {
                continue; // enough fresh custodians already hold it
            }
            let vset = self.active_set_at(&chain.blocks, rctx.trigger_height);
            let subdeal = crate::dkg::reshare_subdeal(
                crate::arbitration::CUSTODY_THRESHOLD,
                rctx.new_committee.len().max(1),
                &share,
                &my_index.to_le_bytes(),
            );
            for (k, member) in rctx.new_committee.iter().enumerate() {
                if *member == self.me() {
                    // I am both a dealer AND on the fresh committee: there is no network loopback to self,
                    // so deliver my own sub-share to myself directly (it counts toward my canonical set).
                    self.accumulate_reshare(&chain.blocks, &rctx, my_index, r_old, subdeal[k].1, reshare_held, handoff_pool, peers, mixer, beacon);
                    dispatched = true;
                    continue;
                }
                let Some(mix_pk) = vset.mix.get(member).copied() else { continue };
                let mut hs = blake3::Hasher::new();
                hs.update(b"privacf-arbitration-reshare-eph-seed-v1");
                hs.update(&to_u64(self.identity.sk).to_le_bytes());
                hs.update(&orig.to_le_bytes());
                hs.update(&my_index.to_le_bytes());
                hs.update(member);
                let eph_seed = *hs.finalize().as_bytes();
                if let Some(parcel) = crate::arbitration::seal_reshare(
                    &mix_pk,
                    orig,
                    Self::REHANDOFF_ROUND,
                    my_index,
                    member,
                    &r_old,
                    &subdeal[k].1,
                    &eph_seed,
                ) {
                    mixer.publish(peers, beacon, Message::Reshare(parcel));
                    dispatched = true;
                }
            }
        }
        if dispatched {
            *last_height = Some(head);
        }
    }

    /// Fresh-committee-member reaction to a re-share parcel: open it, accumulate one sub-share per canonical
    /// dealer (`reshare_held`), and once it holds the full canonical set, combine them into its fresh custody
    /// share (`dkg::reshare_combine`), homomorphically re-blind the subject's on-chain `c_old` to a fresh
    /// `r_new`, prove the re-encryption, and file a round-1 receipt (keyed by the re-handoff nonce).
    #[allow(clippy::too_many_arguments)]
    fn handle_reshare_parcel(
        &self,
        chain: &Chain,
        parcel: &ReshareParcel,
        reshare_held: &mut HashMap<u64, Vec<(u64, [u8; 32], [u8; 32])>>,
        handoff_pool: &mut Vec<HandoffReceipt>,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
    ) {
        if !self.arbitration_authority || parcel.member != self.me() || self.withhold_handoff {
            return;
        }
        if parcel.round != Self::REHANDOFF_ROUND {
            return;
        }
        let Some(rctx) = self.rehandoff_context(&chain.blocks, parcel.subject) else { return };
        let Some((r_old, subshare)) = crate::arbitration::open_reshare(&self.identity.mix_sk(), parcel) else { return };
        self.accumulate_reshare(&chain.blocks, &rctx, parcel.old_index, r_old, subshare, reshare_held, handoff_pool, peers, mixer, beacon);
    }

    /// Accumulate one canonical-dealer sub-share for re-handoff `rctx` and, once this fresh-committee member
    /// holds the full canonical set, combine them into its fresh custody share, re-blind `c_old`, and file a
    /// round-1 receipt. Shared by the gossip path (`handle_reshare_parcel`) and a dealer's own self-delivery
    /// when it is itself on the fresh committee (`drive_rehandoff`) — there is no network loopback to self.
    #[allow(clippy::too_many_arguments)]
    fn accumulate_reshare(
        &self,
        blocks: &[Block],
        rctx: &ReHandoffCtx,
        old_index: u64,
        r_old: [u8; 32],
        subshare: [u8; 32],
        reshare_held: &mut HashMap<u64, Vec<(u64, [u8; 32], [u8; 32])>>,
        handoff_pool: &mut Vec<HandoffReceipt>,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
    ) {
        if !rctx.new_committee.contains(&self.me()) {
            return; // not on the fresh committee
        }
        if !rctx.canonical.iter().any(|(idx, _)| *idx == old_index) {
            return; // a non-canonical dealer's contribution would corrupt the Lagrange set
        }
        let key = (self.me(), rctx.nonce);
        if self.recorded_handoff_keys(blocks).contains(&key)
            || handoff_pool.iter().any(|r| (r.member, r.subject) == key)
        {
            return; // already filed
        }
        let acc = reshare_held.entry(rctx.nonce).or_default();
        if acc.iter().any(|(idx, _, _)| *idx == old_index) {
            return; // dedup this dealer
        }
        acc.push((old_index, r_old, subshare));
        if acc.len() < crate::arbitration::CUSTODY_THRESHOLD {
            return; // wait for the full canonical dealer set before combining
        }
        // Combine the sub-shares into our fresh custody share, and re-blind the SAME on-chain c_old.
        let contributions: Vec<(u64, [u8; 32])> = acc.iter().map(|(idx, _, sub)| (*idx, *sub)).collect();
        let fresh_share = crate::dkg::reshare_combine(&contributions);
        let r_old = acc[0].1;
        let pc = crate::pedersen::Pedersen::new(rctx.width.max(1));
        let r_new = self.handoff_r_new(rctx.nonce);
        let Some(c_new) = crate::arbitration::reencrypt(&pc, &rctx.c_old, &r_old, &r_new) else { return };
        let mut hs = blake3::Hasher::new();
        hs.update(b"privacf-arbitration-reshare-reenc-seed-v1");
        hs.update(&to_u64(self.identity.sk).to_le_bytes());
        hs.update(&rctx.nonce.to_le_bytes());
        let seed = *hs.finalize().as_bytes();
        let proof = crate::arbitration::prove_reencryption(&pc, &rctx.c_old, &c_new, &r_old, &r_new, &seed);
        let receipt = HandoffReceipt::create(&self.identity, rctx.nonce, c_new, proof, &fresh_share);
        if !receipt.verify(&pc, &rctx.c_old, &rctx.new_committee) {
            return;
        }
        handoff_pool.push(receipt.clone());
        mixer.publish(peers, beacon, Message::Handoff(receipt));
    }

    // ─────────────────────────────── §5.3/§5.4 PSI interest-peer discovery ───────────────────────────────

    /// Overlap of shared liked items at/above which two nodes are cluster peers (`psi::should_connect`).
    const PSI_THRESHOLD: usize = 2;

    /// This node's stable private PSI exponent, bound to its identity (never leaves the node).
    fn psi_secret(&self) -> [u8; 32] {
        crate::psi::secret(&to_u64(self.identity.sk).to_le_bytes())
    }

    /// This node's clean liked items as PSI inputs: a stable 32-byte id per preference dimension it likes
    /// (positive clean preference). The clean vector never leaves the node — only blinded points do.
    fn psi_items(&self) -> Vec<[u8; 32]> {
        let Some(prefs) = &self.preferences else { return Vec::new() };
        prefs
            .iter()
            .enumerate()
            .filter(|(_, &p)| p > 0)
            .map(|(i, _)| {
                let mut h = blake3::Hasher::new();
                h.update(b"privacf-psi-item-id-v1");
                h.update(&(i as u64).to_le_bytes());
                *h.finalize().as_bytes()
            })
            .collect()
    }

    /// PSI initiator driver: once consensus is warm, offer this node's blinded liked-item set to ONE
    /// not-yet-probed current validator per tick (`psi_initiated` dedup), so discovery never floods the
    /// consensus inbox. Purely additive — gated on `with_psi_discovery`, no effect on the chain.
    fn drive_psi(
        &self,
        chain: &Chain,
        peers: &PeersMap,
        mixer: &Mixer,
        beacon: u64,
        psi_initiated: &mut HashSet<[u8; 32]>,
    ) {
        if !self.psi_discovery {
            return;
        }
        let items = self.psi_items();
        if items.is_empty() {
            return;
        }
        // Probe current validators (excluding ourselves) we have not offered to yet — one per tick.
        let active = self.active_set_at(&chain.blocks, chain.head().header.height).peers;
        let Some(target) = active.into_iter().find(|p| *p != self.me() && !psi_initiated.contains(p)) else {
            return;
        };
        psi_initiated.insert(target);
        let u = crate::psi::blind(&items, &self.psi_secret());
        mixer.publish(peers, beacon, Message::PsiOffer { from: self.me(), to: target, u });
    }

    /// PSI responder: on an offer addressed to us, reply with our own blinded set `v` and the initiator's
    /// set re-blinded `w` — revealing only the eventual intersection SIZE to the initiator, never our items.
    fn handle_psi_offer(&self, from: [u8; 32], to: [u8; 32], u: &[[u8; 32]], peers: &PeersMap, mixer: &Mixer, beacon: u64) {
        if !self.psi_discovery || to != self.me() {
            return;
        }
        let secret = self.psi_secret();
        let v = crate::psi::blind(&self.psi_items(), &secret);
        let w = crate::psi::reblind(u, &secret);
        mixer.publish(peers, beacon, Message::PsiResponse { from: self.me(), to: from, v, w });
    }

    /// PSI initiator response handler: re-blind the responder's set, count the double-blinded overlap, and
    /// record the responder as an interest-peer when it meets `PSI_THRESHOLD`. Only acts on a response to an
    /// offer we actually sent (`psi_initiated`), once per peer.
    fn handle_psi_response(
        &self,
        from: [u8; 32],
        to: [u8; 32],
        v: &[[u8; 32]],
        w: &[[u8; 32]],
        psi_initiated: &HashSet<[u8; 32]>,
        interest_peers: &mut HashSet<[u8; 32]>,
    ) {
        if !self.psi_discovery || to != self.me() || !psi_initiated.contains(&from) {
            return;
        }
        let z = crate::psi::reblind(v, &self.psi_secret());
        let overlap = crate::psi::intersection_size(w, &z);
        if crate::psi::should_connect(overlap, Self::PSI_THRESHOLD) {
            interest_peers.insert(from);
        }
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

    /// Builder: a newcomer that holds back its join until `height` (then behaves like [`joining`]) — so it
    /// is admitted only after an earlier on-chain event, e.g. a handoff committee has already formed.
    pub fn joins_at(mut self, height: u64) -> Self {
        self.joining = true;
        self.join_at = Some(height);
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
        if self.joining && !vset.contains(&self.me()) && self.join_at.map_or(true, |h| height >= h) {
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
            let mut p = crate::epoch::PreferencePayload::build(prefs, &self.pref_sk_handle(), epoch_id, self.dp_epsilon);
            if self.malform_pref {
                // Byzantine: bypass the honest obfuscation pipeline and publish an over-bound row to
                // amplify CF weight — objectively malformed, so verdict authorities suspend us.
                p.gossip = vec![crate::verdict_policy::GOSSIP_BOUND * 8.0; prefs.len().max(1)];
            }
            if let Some((item, weight, from_epoch)) = self.push_item {
                if height >= from_epoch {
                    // Byzantine push cohort (§6.6): from `from_epoch`, concentrate within-bound gossip on
                    // `item`. Individually valid (no malformation), but the cohort's correlated weight
                    // spikes `item`'s on-chain velocity — the signature the rewind path catches.
                    let mut row = vec![0.0f32; prefs.len().max(item + 1)];
                    row[item] = weight;
                    p.gossip = row;
                }
            }
            p
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

    #[allow(clippy::too_many_arguments)]
    fn assemble_block(
        &self,
        chain: &Chain,
        r: &Round,
        pending: &HashMap<(u64, u64), EpochTransaction>,
        pending_membership: &[MembershipOp],
        pending_suspensions: &[(crate::verdict::SuspendRecord, [u8; 96])],
        audit_pool: &[FirstObservation],
        verdict_commit_pool: &[VerdictCommit],
        watchdog_pool: &[WatchdogSignal],
        rewind_pool: &[RewindSignal],
        handoff_pool: &[HandoffReceipt],
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
        // Include verdict-backed suspensions that re-validate against public chain data and aren't
        // already recorded — each carried with its σ_VERDICT so every validator re-checks it.
        let on_chain = self.already_suspended(&chain.blocks);
        let mut susp_subjects: HashSet<u64> = HashSet::new();
        let mut suspensions: Vec<crate::verdict::SuspendRecord> = Vec::new();
        let mut verdict_sigs: Vec<Vec<u8>> = Vec::new();
        for (record, sigma) in pending_suspensions {
            if !on_chain.contains(&record.null_v)
                && susp_subjects.insert(record.null_v)
                && self.validate_suspension(&chain.blocks, record, sigma)
            {
                suspensions.push(record.clone());
                verdict_sigs.push(sigma.to_vec());
            }
        }
        // Include first-observation audit reports that re-validate against public chain data and
        // aren't already recorded — one per (observer, subject), so each attestation lands once.
        let recorded = self.recorded_audit_keys(&chain.blocks);
        let mut audit_keys: HashSet<([u8; 32], u64)> = HashSet::new();
        let mut audit_reports: Vec<FirstObservation> = Vec::new();
        for rep in audit_pool {
            let key = (rep.observer, rep.subject_epoch_id);
            if !recorded.contains(&key)
                && audit_keys.insert(key)
                && self.validate_audit_report(&chain.blocks, rep)
            {
                audit_reports.push(rep.clone());
            }
        }
        // Include public verdict-commits awaiting inclusion — one per (member, target, hash),
        // signature-checked, not already recorded (the burst the watchdog counts).
        let recorded_commits = self.recorded_commit_keys(&chain.blocks);
        let mut commit_keys: HashSet<([u8; 32], u64, [u8; 32])> = HashSet::new();
        let mut verdict_commits: Vec<VerdictCommit> = Vec::new();
        for c in verdict_commit_pool {
            let key = (c.member, c.target_epoch_id, c.commit_hash);
            if !recorded_commits.contains(&key) && commit_keys.insert(key) && c.verify() {
                verdict_commits.push(c.clone());
            }
        }
        // Include watchdog signals awaiting inclusion — one per (signer, round), re-validated against
        // the on-chain burst, not already recorded (a quorum of these triggers oversight).
        let recorded_wd = self.recorded_watchdog_keys(&chain.blocks);
        let mut wd_keys: HashSet<([u8; 32], u64)> = HashSet::new();
        let mut watchdog_signals: Vec<WatchdogSignal> = Vec::new();
        for s in watchdog_pool {
            let key = (s.epoch_id, s.epoch_t);
            if !recorded_wd.contains(&key)
                && wd_keys.insert(key)
                && self.validate_watchdog_signal(&chain.blocks, s)
            {
                watchdog_signals.push(s.clone());
            }
        }
        // Include rewind signals awaiting inclusion — one per (signer, cohort_epoch), re-validated
        // against the on-chain velocity spike, not already recorded (a cross-cluster quorum triggers
        // the Class-3 audit).
        let recorded_rw = self.recorded_rewind_keys(&chain.blocks);
        let mut rw_keys: HashSet<([u8; 32], u64)> = HashSet::new();
        let mut rewind_signals: Vec<RewindSignal> = Vec::new();
        for s in rewind_pool {
            let key = (s.epoch_id, s.cohort_epoch);
            if !recorded_rw.contains(&key)
                && rw_keys.insert(key)
                && self.validate_rewind_signal(&chain.blocks, s)
            {
                rewind_signals.push(s.clone());
            }
        }
        // Include arbitration handoff receipts awaiting inclusion — one per (member, subject),
        // re-validated against the subject's on-chain c_old + committee, not already recorded.
        let recorded_ho = self.recorded_handoff_keys(&chain.blocks);
        let mut ho_keys: HashSet<([u8; 32], u64)> = HashSet::new();
        let mut handoff_receipts: Vec<HandoffReceipt> = Vec::new();
        for r in handoff_pool {
            let key = (r.member, r.subject);
            if !recorded_ho.contains(&key)
                && ho_keys.insert(key)
                && self.validate_handoff_receipt(&chain.blocks, r)
            {
                handoff_receipts.push(r.clone());
            }
        }
        if alt {
            txs.clear(); // a conflicting variant of the same slot -> a different block id
            ops.clear();
            suspensions.clear();
            verdict_sigs.clear();
            audit_reports.clear();
            verdict_commits.clear();
            watchdog_signals.clear();
            rewind_signals.clear();
            handoff_receipts.clear();
        }
        let mut header = BlockHeader::create(
            &self.identity, r.height, r.view, r.beacon_t, prev, my_epoch_id, &r.my_vrf,
        );
        header.membership_ops = ops;
        header.suspensions = suspensions;
        header.verdict_sigs = verdict_sigs;
        header.audit_reports = audit_reports;
        header.verdict_commits = verdict_commits;
        header.watchdog_signals = watchdog_signals;
        header.rewind_signals = rewind_signals;
        header.handoff_receipts = handoff_receipts;
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
        // Every suspension the block carries must re-validate against public chain data under its
        // accompanying σ_VERDICT, carry no duplicate or already-recorded null_v, and the two parallel
        // vectors must align — so no proposer can inject an unauthorized dark-node extraction.
        if b.header.suspensions.len() != b.header.verdict_sigs.len() {
            return false;
        }
        {
            let on_chain = self.already_suspended(&chain.blocks);
            let mut seen: HashSet<u64> = HashSet::new();
            for (record, sigma) in b.header.suspensions.iter().zip(b.header.verdict_sigs.iter()) {
                let Ok(sig) = <[u8; 96]>::try_from(sigma.as_slice()) else { return false };
                if on_chain.contains(&record.null_v)
                    || !seen.insert(record.null_v)
                    || !self.validate_suspension(&chain.blocks, record, &sig)
                {
                    return false;
                }
            }
        }
        // Every audit report the block carries must re-validate against public chain data (real
        // subject, truthful admission epoch, VRF-selected registered observer), be unique within the
        // block, and not already be recorded — so no proposer injects unauthenticated attestations.
        {
            let recorded = self.recorded_audit_keys(&chain.blocks);
            let mut seen: HashSet<([u8; 32], u64)> = HashSet::new();
            for rep in &b.header.audit_reports {
                let key = (rep.observer, rep.subject_epoch_id);
                if recorded.contains(&key)
                    || !seen.insert(key)
                    || !self.validate_audit_report(&chain.blocks, rep)
                {
                    return false;
                }
            }
        }
        // Every verdict-commit the block carries must be signature-valid, unique within the block, and
        // not already recorded — public pre-commitments the watchdog counts; no proposer fabricates them.
        {
            let recorded = self.recorded_commit_keys(&chain.blocks);
            let mut seen: HashSet<([u8; 32], u64, [u8; 32])> = HashSet::new();
            for c in &b.header.verdict_commits {
                let key = (c.member, c.target_epoch_id, c.commit_hash);
                if recorded.contains(&key) || !seen.insert(key) || !c.verify() {
                    return false;
                }
            }
        }
        // Every watchdog signal must re-validate against the on-chain burst (true anomaly, registered
        // signer, canonical round), be unique within the block, and not already be recorded — so no
        // proposer injects a false oversight trigger.
        {
            let recorded = self.recorded_watchdog_keys(&chain.blocks);
            let mut seen: HashSet<([u8; 32], u64)> = HashSet::new();
            for s in &b.header.watchdog_signals {
                let key = (s.epoch_id, s.epoch_t);
                if recorded.contains(&key)
                    || !seen.insert(key)
                    || !self.validate_watchdog_signal(&chain.blocks, s)
                {
                    return false;
                }
            }
        }
        // Every rewind signal must re-validate against the on-chain velocity spike (canonical cohort
        // epoch, cross-niche signer), be unique within the block, and not already be recorded — so no
        // proposer injects a false Class-3 trigger.
        {
            let recorded = self.recorded_rewind_keys(&chain.blocks);
            let mut seen: HashSet<([u8; 32], u64)> = HashSet::new();
            for s in &b.header.rewind_signals {
                let key = (s.epoch_id, s.cohort_epoch);
                if recorded.contains(&key)
                    || !seen.insert(key)
                    || !self.validate_rewind_signal(&chain.blocks, s)
                {
                    return false;
                }
            }
        }
        // Every arbitration handoff receipt must re-validate against the subject's on-chain c_old +
        // committee, be unique within the block, and not already be recorded — so no proposer forges one.
        {
            let recorded = self.recorded_handoff_keys(&chain.blocks);
            let mut seen: HashSet<([u8; 32], u64)> = HashSet::new();
            for r in &b.header.handoff_receipts {
                let key = (r.member, r.subject);
                if recorded.contains(&key)
                    || !seen.insert(key)
                    || !self.validate_handoff_receipt(&chain.blocks, r)
                {
                    return false;
                }
            }
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
    #[allow(clippy::too_many_arguments)]
    fn on_tick(
        &self,
        r: &mut Round,
        chain: &mut Chain,
        pending: &HashMap<(u64, u64), EpochTransaction>,
        pending_membership: &[MembershipOp],
        pending_suspensions: &[(crate::verdict::SuspendRecord, [u8; 96])],
        audit_pool: &[FirstObservation],
        verdict_commit_pool: &[VerdictCommit],
        watchdog_pool: &[WatchdogSignal],
        rewind_pool: &[RewindSignal],
        handoff_pool: &[HandoffReceipt],
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
                    let a = self.assemble_block(chain, r, pending, pending_membership, pending_suspensions, audit_pool, verdict_commit_pool, watchdog_pool, rewind_pool, handoff_pool, false);
                    let b = self.assemble_block(chain, r, pending, pending_membership, pending_suspensions, audit_pool, verdict_commit_pool, watchdog_pool, rewind_pool, handoff_pool, true);
                    debug!(height = r.height, view = r.view, "EQUIVOCATING (double-signing the slot)");
                    mixer.publish(peers, r.beacon_t, Message::Proposal(a));
                    mixer.publish(peers, r.beacon_t, Message::Proposal(b));
                } else {
                    let block = self.assemble_block(chain, r, pending, pending_membership, pending_suspensions, audit_pool, verdict_commit_pool, watchdog_pool, rewind_pool, handoff_pool, false);
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
        pending_suspensions: &mut Vec<(crate::verdict::SuspendRecord, [u8; 96])>,
        verdict_partials: &mut HashMap<u64, HashMap<u64, [u8; 96]>>,
        audit_pool: &mut Vec<FirstObservation>,
        verdict_commit_pool: &mut Vec<VerdictCommit>,
        watchdog_pool: &mut Vec<WatchdogSignal>,
        rewind_pool: &mut Vec<RewindSignal>,
        handoff_pool: &mut Vec<HandoffReceipt>,
        custody_held: &mut HashMap<u64, ([u8; 32], [u8; 32])>,
        reshare_held: &mut HashMap<u64, Vec<(u64, [u8; 32], [u8; 32])>>,
        psi_initiated: &mut HashSet<[u8; 32]>,
        interest_peers: &mut HashSet<[u8; 32]>,
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
            Message::Suspension { target_epoch_id, sigma } => {
                // A verdict-backed dark-node extraction: rebuild the SuspendRecord from public chain
                // data, validate it under σ_VERDICT, pool it for the next leader (dedup by null_v), and
                // re-gossip the first time so it reaches the full mesh.
                let Ok(sig) = <[u8; 96]>::try_from(sigma.as_slice()) else { return };
                if let Some(record) = self.make_suspension(&chain.blocks, target_epoch_id, &sig) {
                    if self.validate_suspension(&chain.blocks, &record, &sig)
                        && !self.already_suspended(&chain.blocks).contains(&record.null_v)
                        && !pending_suspensions.iter().any(|(r, _)| r.null_v == record.null_v)
                    {
                        pending_suspensions.push((record, sig));
                        mixer.publish(peers, beacon_hint, Message::Suspension { target_epoch_id, sigma });
                    }
                }
            }
            Message::VerdictPartial { target_epoch_id, index, partial } => {
                // A peer's SUSPEND vote in the objective branch. Pool it only for a target whose
                // on-chain tx is genuinely malformed and not yet suspended (bounding the flood to real
                // targets); dedup by signer index; re-gossip the first sighting; then try to combine.
                if !self.verdict_authority {
                    return;
                }
                let Ok(p) = <[u8; 96]>::try_from(partial.as_slice()) else { return };
                if self.suspended_targets(&chain.blocks).contains(&target_epoch_id)
                    || !self.target_is_malformed(&chain.blocks, target_epoch_id)
                {
                    return;
                }
                let newly = verdict_partials
                    .entry(target_epoch_id)
                    .or_default()
                    .insert(index, p)
                    .is_none();
                if newly {
                    mixer.publish(peers, beacon_hint, Message::VerdictPartial { target_epoch_id, index, partial });
                    self.try_combine_verdict(chain, target_epoch_id, verdict_partials, pending_suspensions, peers, mixer, beacon_hint);
                }
            }
            Message::Audit(rep) => {
                // A first-observation attestation: pool it (for the next leader to record) only if it
                // re-validates against the subject's on-chain admission and is not already recorded or
                // pooled. Unlike the sparse verdict partials, audit reports are NOT re-gossiped: an
                // observer already broadcasts to all its peers, so the report reaches every node — and
                // thus the next leader — directly. Re-flooding would amplify the (per-observer ×
                // per-subject) report volume `N`-fold and starve the consensus votes sharing the inbox.
                let key = (rep.observer, rep.subject_epoch_id);
                if self.recorded_audit_keys(&chain.blocks).contains(&key)
                    || audit_pool.iter().any(|r| (r.observer, r.subject_epoch_id) == key)
                    || !self.validate_audit_report(&chain.blocks, &rep)
                {
                    return;
                }
                audit_pool.push(rep);
            }
            Message::VerdictCommit(c) => {
                // A public verdict-commit pre-commitment: pool it (for the next leader to record) if its
                // signature verifies and it is not already recorded or pooled, then re-gossip once so it
                // reaches the full mesh. Bounded (dedup by member/target/hash), so the relay is one hop
                // per node — the §4.9.6 ordering means this is visible before any decrypt.
                let key = (c.member, c.target_epoch_id, c.commit_hash);
                if self.recorded_commit_keys(&chain.blocks).contains(&key)
                    || verdict_commit_pool.iter().any(|x| (x.member, x.target_epoch_id, x.commit_hash) == key)
                    || !c.verify()
                {
                    return;
                }
                verdict_commit_pool.push(c.clone());
                mixer.publish(peers, beacon_hint, Message::VerdictCommit(c));
            }
            Message::Watchdog(s) => {
                // A watchdog alarm: pool it (dedup by signer/round) only if it re-validates against the
                // on-chain burst (a true anomaly, registered signer), then re-gossip once. Low volume
                // (one per watchdog node), so the single relay aids propagation without starving votes.
                let key = (s.epoch_id, s.epoch_t);
                if self.recorded_watchdog_keys(&chain.blocks).contains(&key)
                    || watchdog_pool.iter().any(|x| (x.epoch_id, x.epoch_t) == key)
                    || !self.validate_watchdog_signal(&chain.blocks, &s)
                {
                    return;
                }
                watchdog_pool.push(s.clone());
                mixer.publish(peers, beacon_hint, Message::Watchdog(s));
            }
            Message::Rewind(s) => {
                // A rewind / Class-3 signal: pool it (dedup by signer/cohort_epoch) only if it
                // re-validates against the on-chain velocity spike (canonical cohort, cross-niche signer),
                // then re-gossip once. Low volume (one per affected participant), so the single relay aids
                // propagation without starving votes.
                let key = (s.epoch_id, s.cohort_epoch);
                if self.recorded_rewind_keys(&chain.blocks).contains(&key)
                    || rewind_pool.iter().any(|x| (x.epoch_id, x.cohort_epoch) == key)
                    || !self.validate_rewind_signal(&chain.blocks, &s)
                {
                    return;
                }
                rewind_pool.push(s.clone());
                mixer.publish(peers, beacon_hint, Message::Rewind(s));
            }
            Message::CustodyDispatch(parcel) => {
                // A confidential arbitration custody parcel: if it is addressed to us and we serve on the
                // committee, open it and file our handoff receipt (consumed here, never re-gossiped or
                // recorded — it carries the subject's secret blinding, sealed to us alone).
                self.handle_custody_parcel(chain, &parcel, handoff_pool, custody_held, peers, mixer, beacon_hint);
            }
            Message::Reshare(parcel) => {
                // A confidential re-handoff sub-share addressed to a fresh-committee member: accumulate it
                // and, once the canonical dealer set is complete, file a round-1 handoff receipt. Consumed
                // here, never re-gossiped (it carries a custody sub-share sealed to us alone).
                self.handle_reshare_parcel(chain, &parcel, reshare_held, handoff_pool, peers, mixer, beacon_hint);
            }
            Message::PsiOffer { from, to, u } => {
                // §5.3/§5.4 PSI offer addressed to us: respond with our blinded set + the re-blinded offer.
                self.handle_psi_offer(from, to, &u, peers, mixer, beacon_hint);
            }
            Message::PsiResponse { from, to, v, w } => {
                // §5.3/§5.4 PSI response to an offer we sent: learn the overlap size, record an interest-peer.
                self.handle_psi_response(from, to, &v, &w, psi_initiated, interest_peers);
            }
            Message::Handoff(r) => {
                // A committee member's handoff receipt: pool it (dedup by member/subject) only if it
                // re-validates against the subject's on-chain c_old + committee, then re-gossip once.
                let key = (r.member, r.subject);
                if self.recorded_handoff_keys(&chain.blocks).contains(&key)
                    || handoff_pool.iter().any(|x| (x.member, x.subject) == key)
                    || !self.validate_handoff_receipt(&chain.blocks, &r)
                {
                    return;
                }
                handoff_pool.push(r.clone());
                mixer.publish(peers, beacon_hint, Message::Handoff(r));
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
        let mut pending_suspensions: Vec<(crate::verdict::SuspendRecord, [u8; 96])> = Vec::new();
        // Autonomous-verdict state: targets we have already emitted our own partial for (emit-once), and
        // the pool of received partials per target (signer-index -> partial) awaiting a threshold.
        let mut emitted_partials: HashSet<u64> = HashSet::new();
        let mut verdict_partials: HashMap<u64, HashMap<u64, [u8; 96]>> = HashMap::new();
        // Autonomous-audit state: subjects we have already considered for observation (observe-once),
        // and the pool of first-observation reports awaiting inclusion by the next leader.
        let mut audited: HashSet<u64> = HashSet::new();
        let mut audit_pool: Vec<FirstObservation> = Vec::new();
        // Autonomous oversight state: targets a rogue node has already committed against (emit-once), the
        // pool of public verdict-commits awaiting inclusion, whether this watchdog has raised its signal
        // (raise-once), and the pool of watchdog signals awaiting inclusion.
        let mut rogue_committed: HashSet<u64> = HashSet::new();
        let mut verdict_commit_pool: Vec<VerdictCommit> = Vec::new();
        let mut watchdog_raised = false;
        let mut watchdog_pool: Vec<WatchdogSignal> = Vec::new();
        let mut rewind_raised = false;
        let mut rewind_pool: Vec<RewindSignal> = Vec::new();
        let mut handoff_pool: Vec<HandoffReceipt> = Vec::new();
        let mut custody_dispatch_height: Option<u64> = None;
        // Custody this node took at round-0 handoff (orig subject → (r_old, our share)), so it can later
        // proactively re-share to a fresh committee; and the sub-shares it accumulates as a fresh-committee
        // member of a re-handoff (re-handoff nonce → [(old dealer index, r_old, sub-share)]).
        let mut custody_held: HashMap<u64, ([u8; 32], [u8; 32])> = HashMap::new();
        let mut reshare_held: HashMap<u64, Vec<(u64, [u8; 32], [u8; 32])>> = HashMap::new();
        let mut rehandoff_dispatch_height: Option<u64> = None;
        // §5.3/§5.4 PSI discovery: peers we have offered to (dedup), and the interest-peers we discovered.
        let mut psi_initiated: HashSet<[u8; 32]> = HashSet::new();
        let mut interest_peers: HashSet<[u8; 32]> = HashSet::new();
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
                    // Drop suspensions already recorded by a finalized block.
                    let suspended_now = self.already_suspended(&chain.blocks);
                    pending_suspensions.retain(|(r, _)| !suspended_now.contains(&r.null_v));
                    // Drop the partial pool for any target a finalized block has now suspended.
                    let suspended_targets_now = self.suspended_targets(&chain.blocks);
                    verdict_partials.retain(|t, _| !suspended_targets_now.contains(t));
                    // Drop audit reports a finalized block has now recorded (self-healing).
                    let recorded_audit = self.recorded_audit_keys(&chain.blocks);
                    audit_pool.retain(|r| !recorded_audit.contains(&(r.observer, r.subject_epoch_id)));
                    // Drop verdict-commits / watchdog signals a finalized block has now recorded.
                    let recorded_commits = self.recorded_commit_keys(&chain.blocks);
                    verdict_commit_pool
                        .retain(|c| !recorded_commits.contains(&(c.member, c.target_epoch_id, c.commit_hash)));
                    let recorded_wd = self.recorded_watchdog_keys(&chain.blocks);
                    watchdog_pool.retain(|s| !recorded_wd.contains(&(s.epoch_id, s.epoch_t)));
                    let recorded_rw = self.recorded_rewind_keys(&chain.blocks);
                    rewind_pool.retain(|s| !recorded_rw.contains(&(s.epoch_id, s.cohort_epoch)));
                    let recorded_ho = self.recorded_handoff_keys(&chain.blocks);
                    handoff_pool.retain(|r| !recorded_ho.contains(&(r.member, r.subject)));
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
                    // Autonomous objective-verdict driver: scan finalized txs and emit/combine partials
                    // (no-op unless this node is a verdict authority with a threshold key).
                    let beacon_hint = round.as_ref().map(|r| r.beacon_t).unwrap_or_else(|| chain.head().header.beacon_t);
                    self.drive_verdicts(&chain, &peers, &mixer, beacon_hint, &mut emitted_partials, &mut verdict_partials, &mut pending_suspensions);
                    // Autonomous audit-observer driver (no-op unless this node is an audit authority).
                    self.drive_audit(&chain, &peers, &mixer, beacon_hint, &mut audited, &mut audit_pool);
                    // Rogue-commit burst (no-op unless rogue) and watchdog driver (no-op unless authority).
                    self.drive_rogue_commits(&chain, &peers, &mixer, beacon_hint, &mut rogue_committed, &mut verdict_commit_pool);
                    self.drive_watchdog(&chain, &peers, &mixer, beacon_hint, &mut watchdog_raised, &mut watchdog_pool);
                    self.drive_rewind(&chain, &peers, &mixer, beacon_hint, &mut rewind_raised, &mut rewind_pool);
                    self.drive_custody_dispatch(&chain, &peers, &mixer, beacon_hint, &mut custody_dispatch_height);
                    // Re-handoff driver: a surviving custodian proactively re-shares to a fresh committee
                    // once an original custodian departs (no-op unless triggered + we are a canonical dealer).
                    self.drive_rehandoff(&chain, &custody_held, &mut reshare_held, &mut handoff_pool, &peers, &mixer, beacon_hint, &mut rehandoff_dispatch_height);
                    // §5.3/§5.4 PSI interest-peer discovery (no-op unless with_psi_discovery): additive,
                    // off-chain, one probe per tick — never affects consensus.
                    self.drive_psi(&chain, &peers, &mixer, beacon_hint, &mut psi_initiated);
                    // §6.4 slashing: a committee member that defaulted on a handoff (no valid receipt by
                    // the deadline) is excluded from leadership, exactly like an equivocator — derived
                    // identically from the finalized chain on every node, so no evidence message is needed.
                    for d in self.handoff_defaults(&chain.blocks) {
                        if slashed.insert(d) {
                            info!(slashed = %hex::encode(&d[..4]), "slashed committee member for handoff default");
                        }
                    }
                    if let Some(r) = round.as_mut() {
                        self.on_tick(r, &mut chain, &pending, &pending_membership, &pending_suspensions, &audit_pool, &verdict_commit_pool, &watchdog_pool, &rewind_pool, &handoff_pool, &peers, &mixer, &slashed);
                    }
                }
                Some(msg) = inbox_rx.recv() => {
                    self.on_msg(msg, round.as_mut(), &mut chain, &mut pending, &mut pending_membership, &mut pending_suspensions, &mut verdict_partials, &mut audit_pool, &mut verdict_commit_pool, &mut watchdog_pool, &mut rewind_pool, &mut handoff_pool, &mut custody_held, &mut reshare_held, &mut psi_initiated, &mut interest_peers, &peers, &mixer, &mut slashed);
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
        let mut suspended_targets: Vec<u64> = self.suspended_targets(&chain.blocks).into_iter().collect();
        suspended_targets.sort();
        let flagged_cohort = self.flagged_cohort(&chain.blocks);
        let audit_reports_recorded =
            chain.blocks.iter().map(|b| b.header.audit_reports.len()).sum::<usize>();
        let oversight_triggered = self.oversight_triggered(&chain.blocks);
        let watchdog_signals_recorded =
            chain.blocks.iter().map(|b| b.header.watchdog_signals.len()).sum::<usize>();
        let verdict_commits_recorded =
            chain.blocks.iter().map(|b| b.header.verdict_commits.len()).sum::<usize>();
        let class3_triggered = self.class3_triggered(&chain.blocks);
        let rewind_signals_recorded =
            chain.blocks.iter().map(|b| b.header.rewind_signals.len()).sum::<usize>();
        let handoff_receipts_recorded =
            chain.blocks.iter().map(|b| b.header.handoff_receipts.len()).sum::<usize>();
        let handoff_subjects = self.handoff_subjects(&chain.blocks);
        let handoff_complete = !handoff_subjects.is_empty()
            && handoff_subjects.iter().all(|&s| {
                self.handoff_completed_count(&chain.blocks, s) >= crate::arbitration::CUSTODY_THRESHOLD
            });
        let handoff_defaults = self.handoff_defaults(&chain.blocks);
        let rehandoff_complete = self.rehandoff_complete(&chain.blocks);
        let mut interest_peers: Vec<[u8; 32]> = interest_peers.into_iter().collect();
        interest_peers.sort_unstable();
        info!(peer = %hex::encode(&my_id[..4]), blocks = chain.blocks.len(), head = %hex::encode(&chain.head_hash()[..4]), all_qc_valid, max_view, slashed = slashed_vec.len(), active = final_active.len(), suspended = suspended_targets.len(), flagged = flagged_cohort.len(), audit_reports = audit_reports_recorded, oversight = oversight_triggered, wd_signals = watchdog_signals_recorded, commits = verdict_commits_recorded, class3 = class3_triggered, rewind_signals = rewind_signals_recorded, handoffs = handoff_receipts_recorded, handoff_complete, rehandoff_complete, "node done");
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
            suspended_targets,
            flagged_cohort,
            audit_reports_recorded,
            oversight_triggered,
            watchdog_signals_recorded,
            verdict_commits_recorded,
            class3_triggered,
            rewind_signals_recorded,
            handoff_receipts_recorded,
            handoff_complete,
            handoff_defaults,
            rehandoff_complete,
            interest_peers,
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
        assert!(Mixer::is_routable(&Message::Suspension { target_epoch_id: 0, sigma: Vec::new() }));
        assert!(Mixer::is_routable(&Message::VerdictPartial { target_epoch_id: 0, index: 1, partial: Vec::new() }));
        assert!(Mixer::is_routable(&Message::Audit(crate::audit::FirstObservation {
            observer: [0u8; 32],
            vrf_pk: [0u8; 32],
            subject_epoch_id: 0,
            first_seen_epoch: 0,
            preout: [0u8; 32],
            proof: Vec::new(),
            lottery: [0u8; 32],
            sig: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::VerdictCommit(crate::verdict::VerdictCommit {
            member: [0u8; 32],
            target_epoch_id: 0,
            commit_hash: [0u8; 32],
            sig: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::Watchdog(crate::watchdog::WatchdogSignal {
            epoch_id: [0u8; 32],
            epoch_t: 0,
            observed_commits: 0,
            expected_rate_milli: 0,
            sig: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::Rewind(crate::rewind::RewindSignal {
            epoch_id: [0u8; 32],
            current_t: 0,
            preferred_t: 0,
            cohort_epoch: 0,
            sig: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::CustodyDispatch(crate::arbitration::CustodyParcel {
            subject: 0,
            member: [0u8; 32],
            eph: [0u8; 32],
            ct: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::Reshare(crate::arbitration::ReshareParcel {
            subject: 0,
            round: 1,
            old_index: 1,
            member: [0u8; 32],
            eph: [0u8; 32],
            ct: Vec::new(),
        })));
        assert!(Mixer::is_routable(&Message::PsiOffer { from: [0u8; 32], to: [1u8; 32], u: Vec::new() }));
        assert!(!Mixer::is_routable(&Message::Hello {
            peer_id: [0u8; 32],
            listen_addr: String::new(),
            binding: Vec::new(),
        }));
    }

    /// The in-loop suspension path validates a real verdict-backed extraction from public chain data
    /// and rejects forgeries — the security core of `make_suspension`/`validate_suspension` that
    /// `assemble_block` and `structural_and_vrf_ok` rely on.
    #[test]
    fn verdict_backed_suspension_validates_and_forgeries_are_rejected() {
        use crate::bls::sign_dst;
        use crate::commit::{CommitT, NativeGroupVerEnc, VerEnc};
        use crate::dkg::combine_signatures;
        use crate::field::{from_u64, random_field, sub_mod, to_u64};
        use crate::verenc::VERENC_DST;

        // Genesis 3-of-4 threshold key; the target seals s₂ on-chain, then the committee threshold-signs
        // the verdict (mirrors the dark-node capstone, but here feeding the live block path).
        let validators: Vec<NodeIdentity> = (0..4).map(NodeIdentity::from_seed).collect();
        let ids: Vec<[u8; 32]> = validators.iter().map(|v| v.peer_id()).collect();
        let tks = genesis_threshold_keys(&validators, 3);
        let va_pub = tks[&ids[0]].va_pub;

        let target = &validators[0];
        let beacon = from_u64(0xFEED_BEEF);
        let epoch_id_fp = target.epoch_id(beacon);
        let epoch_id = to_u64(epoch_id_fp);
        let mut rng = rand::rngs::OsRng;
        let s2 = random_field(&mut rng);
        let s1 = sub_mod(target.null_v, s2);
        let d_t = NativeGroupVerEnc { va_pub }.encrypt(s2, epoch_id_fp);

        let id = crate::verdict::verdict_id(epoch_id);
        let partials: Vec<(u64, [u8; 96])> =
            ids.iter().skip(1).map(|p| (tks[p].index, sign_dst(&tks[p].share, &id, VERENC_DST))).collect();
        let sigma = combine_signatures(&partials).expect("σ_VERDICT");

        // A chain carrying the target's epoch tx (the public (s₁, d_T) any node extracts from).
        let mut chain = Chain::genesis();
        let mut blk = chain.blocks[0].clone();
        blk.header.height = 1;
        blk.txs = vec![EpochTransaction::create(target, 1, epoch_id, CommitT { s1: to_u64(s1), d_t })];
        chain.blocks.push(blk);

        let cfg = NodeConfig {
            listen_addr: "127.0.0.1:0".into(),
            genesis_validators: Vec::new(),
            window_ms: 100,
            max_height: 1,
            grace_ms: 0,
        };
        let node = Node::new(NodeIdentity::from_seed(9), cfg);

        // The honest extraction reproduces the target's null_v and validates.
        let rec = node.make_suspension(&chain.blocks, epoch_id, &sigma).expect("extraction succeeds");
        assert_eq!(rec.null_v, to_u64(target.null_v), "null_v recovered from public chain data");
        assert!(node.validate_suspension(&chain.blocks, &rec, &sigma), "a real suspension validates");

        // Forged σ: the verdict_hash no longer binds it, and it cannot decrypt to the claimed null_v.
        let mut forged = sigma;
        forged[0] ^= 0xff;
        assert!(!node.validate_suspension(&chain.blocks, &rec, &forged), "a forged σ is rejected");

        // Tampered null_v under the real σ: re-extraction mismatches.
        let mut lying = rec.clone();
        lying.null_v ^= 1;
        assert!(!node.validate_suspension(&chain.blocks, &lying, &sigma), "a tampered null_v is rejected");

        // No on-chain commitment for the target ⇒ nothing to extract.
        assert!(node.make_suspension(&chain.blocks, epoch_id ^ 0x9999, &sigma).is_none(), "absent target tx ⇒ no suspension");
    }
}
