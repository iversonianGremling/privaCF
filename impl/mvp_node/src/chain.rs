//! Minimal append-only chain with VRF-elected proposers and quorum-certificate finality
//! (SPEC §4.1, MVP subset). Each block is produced by the VRF-elected leader (`vrf.rs`,
//! `consensus.rs`) and is only appendable once it carries a quorum certificate: ≥ ⌊2N/3⌋+1
//! distinct validator votes over its block id. The SMT roots remain zero stubs (no suspensions).

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::beacon::GENESIS_BEACON;
use crate::consensus::quorum;
use crate::epoch::EpochTransaction;
use crate::identity::{verify, NodeIdentity};
use crate::vrf::VrfClaim;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub view: u64,                     // view-change counter (0 = first leader; +1 per timeout)
    pub beacon_t: u64,
    pub prev_block_hash: [u8; 32],
    pub susp_smt_root: [u8; 32],       // zero stub — no suspensions in the MVP
    pub decryption_smt_root: [u8; 32], // zero stub
    pub proposer_id: u64,              // proposer's epoch_id (informational)
    pub proposer_peer: [u8; 32],       // proposer's stable id
    pub vrf_output: [u8; 32],          // proposer's VRF output (leadership lottery)
    pub vrf_proof: Vec<u8>,            // proof of that VRF output (verifiable leadership)
}

/// A validator's vote over a block id — the unit of the quorum certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub block_id: [u8; 32],
    pub voter: [u8; 32],
    pub sig: Vec<u8>, // ed25519 over vote_signing_bytes
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<EpochTransaction>,
    /// Quorum certificate: ≥ quorum distinct validator votes over `block_id(header, txs)`.
    pub qc: Vec<Vote>,
}

/// The block id is the convergence/linking identity. It EXCLUDES the quorum certificate so it is
/// stable before votes are gathered (votes are cast over this id).
pub fn block_id(header: &BlockHeader, txs: &[EpochTransaction]) -> [u8; 32] {
    let bytes = bincode::serialize(&(header, txs)).expect("block serialize");
    *blake3::hash(&bytes).as_bytes()
}

/// Canonical bytes a voter signs for `(height, block_id)`.
pub fn vote_signing_bytes(height: u64, block_id: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("vote", height, block_id)).expect("vote serialize")
}

impl Vote {
    pub fn create(voter: &NodeIdentity, height: u64, block_id: [u8; 32]) -> Self {
        let sig = voter.sign(&vote_signing_bytes(height, &block_id)).to_bytes().to_vec();
        Self { height, block_id, voter: voter.peer_id(), sig }
    }

    pub fn verify_sig(&self) -> bool {
        match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(arr) => verify(
                &self.voter,
                &vote_signing_bytes(self.height, &self.block_id),
                &Signature::from_bytes(&arr),
            ),
            Err(_) => false,
        }
    }
}

impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        proposer: &NodeIdentity,
        height: u64,
        view: u64,
        beacon_t: u64,
        prev_block_hash: [u8; 32],
        proposer_epoch_id: u64,
        vrf: &VrfClaim,
    ) -> Self {
        BlockHeader {
            height,
            view,
            beacon_t,
            prev_block_hash,
            susp_smt_root: [0u8; 32],
            decryption_smt_root: [0u8; 32],
            proposer_id: proposer_epoch_id,
            proposer_peer: proposer.peer_id(),
            vrf_output: vrf.output,
            vrf_proof: vrf.proof.clone(),
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

#[derive(Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

impl Chain {
    /// The genesis block — identical for every node.
    pub fn genesis() -> Self {
        let header = BlockHeader {
            height: 0,
            view: 0,
            beacon_t: GENESIS_BEACON,
            prev_block_hash: [0u8; 32],
            susp_smt_root: [0u8; 32],
            decryption_smt_root: [0u8; 32],
            proposer_id: 0,
            proposer_peer: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: Vec::new(),
        };
        Chain { blocks: vec![Block { header, txs: Vec::new(), qc: Vec::new() }] }
    }

    pub fn head(&self) -> &Block {
        self.blocks.last().expect("chain always has genesis")
    }

    /// Block id of the head — the convergence witness and the parent link for the next block.
    pub fn head_hash(&self) -> [u8; 32] {
        block_id(&self.head().header, &self.head().txs)
    }

    /// Structural append: enforces height and prev-hash linkage only. The quorum certificate, VRF
    /// leadership, and beacon checks are the node's job (`valid_block`), since they need the
    /// validator set the chain does not hold.
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

    pub fn blocks_from(&self, from: u64) -> Vec<Block> {
        self.blocks.iter().filter(|b| b.header.height >= from).cloned().collect()
    }
}

/// Verify a block's quorum certificate against the validator set: ≥ quorum distinct, valid votes
/// from validators, all over this block's id.
pub fn qc_valid(block: &Block, validators: &[[u8; 32]]) -> bool {
    let bid = block_id(&block.header, &block.txs);
    let mut seen = std::collections::HashSet::new();
    let mut count = 0usize;
    for v in &block.qc {
        if v.height != block.header.height || v.block_id != bid {
            return false;
        }
        if !validators.contains(&v.voter) || !seen.insert(v.voter) {
            return false;
        }
        if !v.verify_sig() {
            return false;
        }
        count += 1;
    }
    count >= quorum(validators.len())
}
