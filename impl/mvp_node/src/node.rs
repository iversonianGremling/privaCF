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
use crate::chain::{
    block_id, proposal_sig_bytes, qc_valid, Block, BlockHeader, Chain, EquivocationProof,
    QuorumCert, Vote, VoteEquivocationProof,
};
use crate::commit::{CommitT, StubVerEnc, VerEnc};
use crate::consensus::{leader_for, quorum};
use crate::epoch::EpochTransaction;
use crate::field::{add_mod, from_u64, random_field, sub_mod, to_u64};
use crate::identity::{verify as verify_ed25519, NodeIdentity};
use crate::membership::{MembershipOp, ValidatorRecord, ValidatorSet};
use crate::message::Message;
use crate::transport::{noise_handshake, read_frame, write_frame};
use crate::vrf::VrfClaim;

type PeersMap = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

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

pub struct Node {
    identity: Arc<NodeIdentity>,
    config: NodeConfig,
    verenc: StubVerEnc,
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
}

impl Node {
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> Self {
        let mut genesis = config.genesis_validators.clone();
        genesis.sort_by_key(|r| r.peer_id);
        genesis.dedup_by_key(|r| r.peer_id);
        Self {
            identity: Arc::new(identity),
            config,
            verenc: StubVerEnc,
            genesis,
            withhold_proposals: false,
            equivocate: false,
            double_vote: false,
            leave_at: None,
            joining: false,
        }
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

    /// Begin a new height: submit our `commit_T` transaction and broadcast our VRF claim.
    #[allow(clippy::too_many_arguments)]
    fn start_round(
        &self,
        height: u64,
        chain: &Chain,
        peers: &PeersMap,
        pending: &mut HashMap<(u64, u64), EpochTransaction>,
        epoch_ids: &mut Vec<(u64, u64)>,
        beacons: &mut Vec<(u64, u64)>,
        split_ok: &mut bool,
        rng: &mut impl rand::RngCore,
    ) -> Round {
        let head = &chain.head().header;
        let beacon_t = next_beacon(head.beacon_t, &head.vrf_output, height);
        beacons.push((height, beacon_t));
        // Active validator set for this height — fixed by the finalized chain below it.
        let vset = self.active_set_at(&chain.blocks, height);
        // Dynamic membership: if configured to leave at this height (and still a member), gossip a
        // self-signed leave op for the current leader to record; it activates at the next height.
        if self.leave_at == Some(height) && vset.contains(&self.me()) {
            debug!(height, "broadcasting self-signed LEAVE op");
            Self::gossip(peers, Message::Membership(MembershipOp::remove(&self.identity)));
        }
        // A newcomer keeps gossiping its self-signed join op until it is admitted (self-healing: it
        // stops once it appears in the active set).
        if self.joining && !vset.contains(&self.me()) {
            debug!(height, "broadcasting self-signed JOIN op");
            let op = MembershipOp::add(&self.identity, self.config.listen_addr.clone());
            Self::gossip(peers, Message::Membership(op));
        }
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
            if !op.verify() || !subjects.insert(op.subject()) {
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
        let bid = block_id(&header, &txs);
        let proposer_sig =
            self.identity.sign(&proposal_sig_bytes(r.height, r.view, &bid)).to_bytes().to_vec();
        Block { header, txs, proposer_sig, qc: QuorumCert::default() }
    }

    fn cast_vote(&self, r: &mut Round, bid: [u8; 32], peers: &PeersMap) {
        if r.voted.is_some() || !r.vset.contains(&self.me()) {
            return; // only active validators vote (a departed validator no longer does)
        }
        let vote = Vote::create(&self.identity, r.height, r.view, bid);
        r.votes.entry(bid).or_default().insert(self.me(), vote.clone());
        r.voted = Some(bid);
        Self::gossip(peers, Message::Vote(vote));
        if self.double_vote {
            // Byzantine: sign a second, different block id at this same (height, view). The id need
            // not correspond to a real block — signing two ids in one slot is itself the offense.
            let mut alt = bid;
            alt[0] ^= 0xff;
            debug!(height = r.height, view = r.view, "DOUBLE-VOTING (signing a second block id)");
            Self::gossip(peers, Message::Vote(Vote::create(&self.identity, r.height, r.view, alt)));
        }
    }

    /// Structural validity + a verifiable VRF leadership proof (does not check WHICH view's leader).
    /// `vset` is the active validator set in effect at the block's height.
    fn structural_and_vrf_ok(&self, chain: &Chain, b: &Block, vset: &ValidatorSet) -> bool {
        let head = &chain.head().header;
        if b.header.height != head.height + 1 || b.header.prev_block_hash != chain.head_hash() {
            return false;
        }
        if b.header.beacon_t != next_beacon(head.beacon_t, &head.vrf_output, b.header.height) {
            return false;
        }
        // Every membership op the block carries must be self-authorized (the safety-critical check).
        if !b.header.membership_ops.iter().all(|op| op.verify()) {
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
                    Self::gossip(peers, Message::Proposal(a));
                    Self::gossip(peers, Message::Proposal(b));
                } else {
                    let block = self.assemble_block(chain, r, pending, pending_membership, false);
                    let bid = block_id(&block.header, &block.txs);
                    debug!(height = r.height, view = r.view, txs = block.txs.len(), "proposing as VRF leader");
                    r.blocks.insert(bid, block.clone());
                    Self::gossip(peers, Message::Proposal(block));
                    self.cast_vote(r, bid, peers);
                }
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
                Self::gossip(peers, Message::Finalized(fb));
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
        slashed: &mut HashSet<[u8; 32]>,
    ) {
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
                if op.verify() && !pending_membership.iter().any(|o| o.subject() == op.subject()) {
                    pending_membership.push(op.clone());
                    Self::gossip(peers, Message::Membership(op));
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
                                    Self::gossip(peers, Message::Slash(proof));
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
                            self.cast_vote(r, bid, peers);
                        }
                        self.try_finalize(r, chain, peers);
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
                                    Self::gossip(peers, Message::SlashVote(proof));
                                }
                                return; // never count an equivocator's vote
                            }
                        } else {
                            r.seen_votes.insert(key, (v.block_id, v.bls_sig.clone()));
                        }
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
                        need, &chain, &peers, &mut pending, &mut epoch_ids, &mut beacons,
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
                        self.on_tick(r, &mut chain, &pending, &pending_membership, &peers, &slashed);
                    }
                }
                Some(msg) = inbox_rx.recv() => {
                    self.on_msg(msg, round.as_mut(), &mut chain, &mut pending, &mut pending_membership, &peers, &mut slashed);
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
