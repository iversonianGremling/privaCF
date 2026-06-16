//! The wire protocol. Length-prefixed bincode frames over the transport (see `transport.rs`).

use serde::{Deserialize, Serialize};

use crate::chain::{Block, EquivocationProof, Vote};
use crate::epoch::EpochTransaction;
use crate::vrf::VrfClaim;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Peer handshake (first frame on every connection). No Noise/encryption in the MVP.
    Hello { peer_id: [u8; 32], listen_addr: String },
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
    /// Request all finalized blocks at height ≥ `from_height`.
    GetChain { from_height: u64 },
    /// Response to `GetChain`.
    ChainRange(Vec<Block>),
}
