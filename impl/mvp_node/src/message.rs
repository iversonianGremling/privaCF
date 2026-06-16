//! The wire protocol. Length-prefixed bincode frames over the transport (see `transport.rs`).

use serde::{Deserialize, Serialize};

use crate::chain::Block;
use crate::epoch::EpochTransaction;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Peer handshake (first frame on every connection). No Noise/encryption in the MVP.
    Hello { peer_id: [u8; 32], listen_addr: String },
    /// Gossip a pending per-epoch transaction.
    Tx(EpochTransaction),
    /// Gossip a proposed block.
    Block(Block),
    /// Request all blocks at height ≥ `from_height`.
    GetChain { from_height: u64 },
    /// Response to `GetChain`.
    ChainRange(Vec<Block>),
}
