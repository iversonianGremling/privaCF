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
    /// A fixed-size Sphinx mix packet to peel and forward/deliver (the Loopix layer, `loopix.rs`).
    Sphinx(SphinxPacket),
    /// Request all finalized blocks at height ≥ `from_height`.
    GetChain { from_height: u64 },
    /// Response to `GetChain`.
    ChainRange(Vec<Block>),
}
