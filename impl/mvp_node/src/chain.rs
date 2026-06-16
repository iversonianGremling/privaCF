//! Minimal append-only public chain (SPEC §4.1, MVP subset). One block per epoch, produced by a
//! single round-robin proposer (the consensus seam). No BFT, no threshold-BLS finality: a block
//! carries ONE proposer ed25519 signature where the real header carries an aggregate validator
//! signature, and the SMT roots are zero stubs (no suspensions in the MVP).

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::beacon::GENESIS_BEACON;
use crate::epoch::EpochTransaction;
use crate::identity::{verify, NodeIdentity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub beacon_t: u64,
    pub prev_block_hash: [u8; 32],
    pub susp_smt_root: [u8; 32],       // zero stub — no suspensions in the MVP
    pub decryption_smt_root: [u8; 32], // zero stub
    pub proposer_id: u64,              // proposer's epoch_id (informational; selection is by peer)
    pub proposer_peer: [u8; 32],       // proposer's stable id — round-robin handle + sig key
    pub proposer_sig: Vec<u8>,         // ed25519 over the signing bytes (64 bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<EpochTransaction>,
}

/// Bytes the proposer signs / verifiers check: the header minus its own signature.
fn header_signing_bytes(h: &BlockHeader) -> Vec<u8> {
    bincode::serialize(&(
        h.height,
        h.beacon_t,
        h.prev_block_hash,
        h.susp_smt_root,
        h.decryption_smt_root,
        h.proposer_id,
        h.proposer_peer,
    ))
    .expect("header serialize")
}

/// blake3 over the full serialized header (block-plumbing hash; NOT circuit-constrained).
pub fn block_hash(h: &BlockHeader) -> [u8; 32] {
    let bytes = bincode::serialize(h).expect("header serialize");
    *blake3::hash(&bytes).as_bytes()
}

impl BlockHeader {
    /// Build and sign a proposer's header.
    pub fn create(
        proposer: &NodeIdentity,
        height: u64,
        beacon_t: u64,
        prev_block_hash: [u8; 32],
        proposer_epoch_id: u64,
    ) -> Self {
        let mut h = BlockHeader {
            height,
            beacon_t,
            prev_block_hash,
            susp_smt_root: [0u8; 32],
            decryption_smt_root: [0u8; 32],
            proposer_id: proposer_epoch_id,
            proposer_peer: proposer.peer_id(),
            proposer_sig: Vec::new(),
        };
        let sig = proposer.sign(&header_signing_bytes(&h)).to_bytes().to_vec();
        h.proposer_sig = sig;
        h
    }

    /// Verify the proposer's signature.
    pub fn verify_sig(&self) -> bool {
        match <[u8; 64]>::try_from(self.proposer_sig.as_slice()) {
            Ok(arr) => verify(&self.proposer_peer, &header_signing_bytes(self), &Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum ChainError {
    #[error("wrong height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },
    #[error("prev_block_hash does not match local head")]
    WrongPrev,
}

/// The append-only chain, including the deterministic genesis block at height 0.
#[derive(Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

impl Chain {
    /// The genesis block — identical for every node, so all chains share a common root.
    pub fn genesis() -> Self {
        let header = BlockHeader {
            height: 0,
            beacon_t: GENESIS_BEACON,
            prev_block_hash: [0u8; 32],
            susp_smt_root: [0u8; 32],
            decryption_smt_root: [0u8; 32],
            proposer_id: 0,
            proposer_peer: [0u8; 32],
            proposer_sig: Vec::new(),
        };
        Chain { blocks: vec![Block { header, txs: Vec::new() }] }
    }

    pub fn head(&self) -> &Block {
        self.blocks.last().expect("chain always has genesis")
    }

    /// Hash of the current head header — the convergence witness.
    pub fn head_hash(&self) -> [u8; 32] {
        block_hash(&self.head().header)
    }

    /// Structural append: enforces height and prev-hash linkage. Semantic checks (proposer
    /// round-robin, beacon, signatures) are the node's job (`valid_block`), since they need the
    /// validator set the chain itself does not hold.
    pub fn try_append(&mut self, b: Block) -> Result<(), ChainError> {
        let expected = self.head().header.height + 1;
        if b.header.height != expected {
            return Err(ChainError::WrongHeight { expected, got: b.header.height });
        }
        if b.header.prev_block_hash != self.head_hash() {
            return Err(ChainError::WrongPrev);
        }
        self.blocks.push(b);
        Ok(())
    }

    /// Blocks at height ≥ `from` (for serving sync requests).
    pub fn blocks_from(&self, from: u64) -> Vec<Block> {
        self.blocks.iter().filter(|b| b.header.height >= from).cloned().collect()
    }
}
