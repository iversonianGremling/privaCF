//! The wire protocol. Length-prefixed bincode frames over the transport (see `transport.rs`).

use serde::{Deserialize, Serialize};

use crate::chain::{Block, EquivocationProof, Vote, VoteEquivocationProof};
use crate::epoch::EpochTransaction;
use crate::membership::MembershipOp;
use crate::sphinx::SphinxPacket;
use crate::vrf::VrfClaim;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Peer handshake — the first *encrypted* frame after the Noise XX handshake. `binding` is an
    /// ed25519 signature by `peer_id` over the Noise handshake hash (domain-separated), binding the
    /// long-term identity to this specific channel (see `transport.rs` and `run_conn`).
    Hello { peer_id: [u8; 32], listen_addr: String, binding: Vec<u8> },
    /// Gossip a pending per-epoch transaction.
    Tx(EpochTransaction),
    /// A validator's VRF leadership claim for a height.
    Vrf(VrfClaim),
    /// The elected leader's proposed block (no quorum certificate yet).
    Proposal(Block),
    /// A validator's vote for a proposed block.
    Vote(Vote),
    /// A block that reached a quorum certificate (finalized) — lets laggards adopt it directly.
    Finalized(Block),
    /// Proof that a proposer double-signed a slot — slashes the offender network-wide.
    Slash(EquivocationProof),
    /// Proof that a validator double-voted a slot — slashes the offender network-wide.
    SlashVote(VoteEquivocationProof),
    /// A self-signed validator-set change (join/leave) awaiting inclusion by the next leader.
    Membership(MembershipOp),
    /// A verdict-backed dark-node suspension awaiting inclusion: `sigma` is the `σ_VERDICT` (96-byte
    /// BLS) that authorizes extracting `null_v` from the target's on-chain `(s₁, d_T)` at
    /// `target_epoch_id`. Any node re-validates it from public chain data before pooling (see `node.rs`).
    Suspension { target_epoch_id: u64, sigma: Vec<u8> },
    /// A validator's threshold partial on `verdict_id(target_epoch_id)` — its SUSPEND vote in the
    /// *objective* verdict branch (`verdict_policy.rs`). `index` is the signer's 1-based DKG party
    /// index; `partial` is the 96-byte BLS partial. `⌊K/2⌋+1` of these combine
    /// (`dkg::combine_signatures`) into `σ_VERDICT`. A node only emits / pools one for a target whose
    /// on-chain transaction is objectively malformed, so the flood is bounded (see `node.rs`).
    VerdictPartial { target_epoch_id: u64, index: u64, partial: Vec<u8> },
    /// A Class-2 first-observation audit report (`audit.rs`) awaiting inclusion: a VRF-selected,
    /// signed attestation that the observer first saw the newly-admitted `subject_epoch_id` at
    /// `first_seen_epoch`. A node only pools / re-gossips one that validates against the subject's
    /// on-chain admission (so the flood is bounded to genuine newcomers); the next leader records it in
    /// `BlockHeader::audit_reports`, feeding the admission-time burst detector network-wide.
    Audit(crate::audit::FirstObservation),
    /// A public verdict-commit pre-commitment (§4.9.6/§4.9.8, `verdict.rs`). Any node pools / records
    /// one whose signature verifies; the next leader records it in `BlockHeader::verdict_commits`. An
    /// anomalous burst of these — against targets with no behavioral justification — is the
    /// mass-deanonymization signal the watchdog detects, *before* any identity is exposed.
    VerdictCommit(crate::verdict::VerdictCommit),
    /// A signed watchdog alarm (`watchdog.rs`) that an anomalous verdict-commit burst occurred at the
    /// named oversight round. A node pools / records one that re-derives true against the on-chain
    /// commit burst; a quorum of distinct signers triggers recursive oversight network-wide.
    Watchdog(crate::watchdog::WatchdogSignal),
    /// A signed §6.6 rewind / Class-3 signal (`rewind.rs`): the signer's recommendations were degraded
    /// by an on-chain gossip cohort that spiked a *foreign* item at `cohort_epoch`. A node pools / records
    /// one that re-derives true against the on-chain item-velocity spike; a quorum of distinct signers
    /// spanning ≥2 interest clusters, all naming the same cohort epoch, triggers a Class-3 audit.
    Rewind(crate::rewind::RewindSignal),
    /// A confidential §4.1/§6.4 arbitration custody parcel (`arbitration.rs`): a departing node seals its
    /// custody share + commitment blinding to one committee member's `mix_pk`. Routed to the mesh; only
    /// the addressed member can open it and act on it. Transient — consumed, not recorded on-chain.
    CustodyDispatch(crate::arbitration::CustodyParcel),
    /// A committee member's signed arbitration handoff receipt (`arbitration.rs`): the re-encrypted
    /// commitment it now custodies + the ZK proof binding it to the subject's on-chain `c_old`. A node
    /// pools / records one that verifies; the next leader records it in `BlockHeader::handoff_receipts`.
    Handoff(crate::arbitration::HandoffReceipt),
    /// A fixed-size Sphinx mix packet to peel and forward/deliver (the Loopix layer, `loopix.rs`).
    Sphinx(SphinxPacket),
    /// Request all finalized blocks at height ≥ `from_height`.
    GetChain { from_height: u64 },
    /// Response to `GetChain`.
    ChainRange(Vec<Block>),
}
