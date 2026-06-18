//! Minimal append-only chain with VRF-elected proposers and quorum-certificate finality
//! (SPEC §4.1, MVP subset). Each block is produced by the VRF-elected leader (`vrf.rs`,
//! `consensus.rs`) and is only appendable once it carries a quorum certificate: an aggregate
//! BLS signature (`bls.rs`) of ≥ ⌊2N/3⌋+1 distinct validator votes over its block id. The SMT
//! roots remain zero stubs (no suspensions).

use std::collections::{HashMap, HashSet};

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::beacon::GENESIS_BEACON;
use crate::bls;
use crate::consensus::quorum;
use crate::epoch::EpochTransaction;
use crate::identity::{verify, NodeIdentity};
use crate::membership::MembershipOp;
use crate::smt;
use crate::verdict::SuspendRecord;
use crate::vrf::VrfClaim;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub view: u64,                     // view-change counter (0 = first leader; +1 per timeout)
    pub beacon_t: u64,
    pub prev_block_hash: [u8; 32],
    /// SUSP_SMT root (suspended `null_v`s) and DECRYPTION_SMT root (`dec_nullifier` dedup), each a
    /// real Poseidon SMT root derived from the finalized chain (`smt.rs`). Empty until the first
    /// verdict, but a real empty-tree root, not a zero stub.
    pub susp_smt_root: [u8; 32],
    pub decryption_smt_root: [u8; 32],
    pub proposer_id: u64,              // proposer's epoch_id (informational)
    pub proposer_peer: [u8; 32],       // proposer's stable id
    pub vrf_output: [u8; 32],          // proposer's VRF output (leadership lottery)
    pub vrf_preout: [u8; 32],          // proposer's VRF pre-output (needed to verify the proof)
    pub vrf_proof: Vec<u8>,            // proof of that VRF output (verifiable leadership)
    /// Self-authorized validator-set changes carried by this block. They are part of the header, so
    /// `block_id` covers them (proposer-signed and voted-over); they take effect at the NEXT height,
    /// once this block is finalized and identical for every node (see `membership.rs`).
    pub membership_ops: Vec<MembershipOp>,
    /// Finalized dark-node suspensions carried by this block (extracted `null_v`s). Like
    /// `membership_ops` they are header-covered and fold into the SUSP_SMT / DECRYPTION_SMT at the
    /// next height (see `verdict.rs`, `node.rs::smt_roots_at`).
    pub suspensions: Vec<SuspendRecord>,
    /// The verdict threshold signature `σ_VERDICT` (96-byte BLS, as `Vec<u8>`) authorizing each
    /// `suspensions[i]` (same length). Carried in the header so any validator independently re-verifies
    /// the suspension against the target's on-chain `(s₁, d_T)` — the proposer cannot fabricate one.
    pub verdict_sigs: Vec<Vec<u8>>,
    /// Class-2 first-observation audit reports finalized by this block (`audit.rs`). Each is a
    /// VRF-selected, ed25519-signed attestation that an observer first saw a newly-admitted subject at
    /// a given epoch. Header-covered (so `block_id` binds them, voted-over) and re-validated by every
    /// validator against the subject's on-chain admission — accountable, rate-limited evidence from
    /// which any node derives the admission-time burst score (the Sybil-cohort signal, §4.9.7/§7).
    pub audit_reports: Vec<crate::audit::FirstObservation>,
    /// §4.9.8 recursive-oversight evidence. `verdict_commits` are public commit-reveal pre-commitments
    /// to verdicts (`verdict.rs`): a rogue committee mounting mass-deanonymization must post these
    /// BEFORE any `null_v` is decryptable, so an anomalous burst is visible on-chain *before* a single
    /// identity is exposed. `watchdog_signals` are the signed alarms watchers raise over that burst
    /// (`watchdog.rs`); a quorum of distinct signers triggers recursive oversight. Both header-covered
    /// (so `block_id` binds them, voted-over) and re-validated by every validator — accountable evidence
    /// from which any node deterministically derives the oversight trigger.
    pub verdict_commits: Vec<crate::verdict::VerdictCommit>,
    pub watchdog_signals: Vec<crate::watchdog::WatchdogSignal>,
}

/// A validator's BLS vote over a slot — the unit aggregated into the quorum certificate. The signed
/// message is `vote_sig_bytes(height, view, block_id)`, so every voter for the same block in the
/// same view signs identical bytes (required for same-message aggregation), while binding the vote
/// to a specific `(height, view)` makes it self-contained evidence: two votes from one voter for
/// different block ids at the same `(height, view)` are a non-repudiable double-vote.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub view: u64,
    pub block_id: [u8; 32],
    pub voter: [u8; 32],
    pub bls_sig: Vec<u8>, // BLS12-381 signature over vote_sig_bytes(height, view, block_id) (96 B)
}

/// A quorum certificate: the aggregate BLS signature of a quorum of votes plus the signer set.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct QuorumCert {
    pub signers: Vec<[u8; 32]>,
    pub agg_sig: Vec<u8>, // aggregate BLS signature over block_id (96 B)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<EpochTransaction>,
    /// Proposer's ed25519 signature over `proposal_sig_bytes(height, view, block_id)` — binds the
    /// proposer to THIS block (the VRF proof only proves leadership, not content) and is the
    /// non-repudiable evidence used to detect equivocation.
    pub proposer_sig: Vec<u8>,
    /// Quorum certificate over `block_id(header, txs)`.
    pub qc: QuorumCert,
}

/// The block id is the convergence/linking identity. It EXCLUDES the proposer signature and the
/// quorum certificate (both added after the id is fixed: votes are cast over this id).
pub fn block_id(header: &BlockHeader, txs: &[EpochTransaction]) -> [u8; 32] {
    let bytes = bincode::serialize(&(header, txs)).expect("block serialize");
    *blake3::hash(&bytes).as_bytes()
}

/// What a proposer signs to bind itself to a block at a given slot: `(height, view, block_id)`.
pub fn proposal_sig_bytes(height: u64, view: u64, block_id: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("proposal", height, view, block_id)).expect("proposal serialize")
}

/// What a validator signs to bind its vote to a slot: `(height, view, block_id)`. Distinct from the
/// proposal tag so a proposal signature can never be replayed as a vote (or vice versa).
pub fn vote_sig_bytes(height: u64, view: u64, block_id: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("vote", height, view, block_id)).expect("vote serialize")
}

impl Block {
    /// Verify the proposer's signature binds `proposer_peer` to this block.
    pub fn verify_proposer_sig(&self) -> bool {
        let bid = block_id(&self.header, &self.txs);
        let bytes = proposal_sig_bytes(self.header.height, self.header.view, &bid);
        match <[u8; 64]>::try_from(self.proposer_sig.as_slice()) {
            Ok(arr) => verify(&self.header.proposer_peer, &bytes, &Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}

/// Non-repudiable proof that `proposer` signed two different blocks at the same `(height, view)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub proposer: [u8; 32],
    pub height: u64,
    pub view: u64,
    pub id_a: [u8; 32],
    pub sig_a: Vec<u8>,
    pub id_b: [u8; 32],
    pub sig_b: Vec<u8>,
}

impl EquivocationProof {
    /// Valid iff the two ids differ and both signatures are the proposer's over their own
    /// `(height, view, id)` — i.e. the proposer provably double-signed the slot.
    pub fn verify(&self) -> bool {
        if self.id_a == self.id_b {
            return false;
        }
        let check = |id: &[u8; 32], sig: &[u8]| -> bool {
            let bytes = proposal_sig_bytes(self.height, self.view, id);
            match <[u8; 64]>::try_from(sig) {
                Ok(arr) => verify(&self.proposer, &bytes, &Signature::from_bytes(&arr)),
                Err(_) => false,
            }
        };
        check(&self.id_a, &self.sig_a) && check(&self.id_b, &self.sig_b)
    }
}

impl Vote {
    pub fn create(voter: &NodeIdentity, height: u64, view: u64, block_id: [u8; 32]) -> Self {
        let bls_sig = voter.bls_sign(&vote_sig_bytes(height, view, &block_id)).to_vec();
        Self { height, view, block_id, voter: voter.peer_id(), bls_sig }
    }

    /// Verify this vote's BLS signature over `(height, view, block_id)`, given the voter's BLS key.
    pub fn verify(&self, bls_pk: &[u8; 48]) -> bool {
        let msg = vote_sig_bytes(self.height, self.view, &self.block_id);
        match <[u8; 96]>::try_from(self.bls_sig.as_slice()) {
            Ok(sig) => bls::verify(bls_pk, &msg, &sig),
            Err(_) => false,
        }
    }
}

/// Non-repudiable proof that `voter` cast two votes for different block ids at the same
/// `(height, view)` — the vote-side analogue of `EquivocationProof`. Unlike proposer equivocation
/// (ed25519, key embedded in the block), votes are BLS-signed, so verification needs the voter's
/// BLS public key from the validator registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteEquivocationProof {
    pub voter: [u8; 32],
    pub height: u64,
    pub view: u64,
    pub id_a: [u8; 32],
    pub sig_a: Vec<u8>,
    pub id_b: [u8; 32],
    pub sig_b: Vec<u8>,
}

impl VoteEquivocationProof {
    /// Valid iff the two ids differ and both signatures are the voter's BLS signatures over their
    /// own `vote_sig_bytes(height, view, id)` — i.e. the voter provably double-voted the slot.
    pub fn verify(&self, bls_pk: &[u8; 48]) -> bool {
        if self.id_a == self.id_b {
            return false;
        }
        let check = |id: &[u8; 32], sig: &[u8]| -> bool {
            let msg = vote_sig_bytes(self.height, self.view, id);
            match <[u8; 96]>::try_from(sig) {
                Ok(s) => bls::verify(bls_pk, &msg, &s),
                Err(_) => false,
            }
        };
        check(&self.id_a, &self.sig_a) && check(&self.id_b, &self.sig_b)
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
            // Default to the empty-tree roots; the proposer overrides with chain-derived roots in
            // `assemble_block` (as it does for `membership_ops`) once suspensions/extractions exist.
            susp_smt_root: smt::empty_root(),
            decryption_smt_root: smt::empty_root(),
            proposer_id: proposer_epoch_id,
            proposer_peer: proposer.peer_id(),
            vrf_output: vrf.output,
            vrf_preout: vrf.preout,
            vrf_proof: vrf.proof.clone(),
            membership_ops: Vec::new(), // set by the proposer (assemble_block) before block_id is fixed
            suspensions: Vec::new(),
            verdict_sigs: Vec::new(),
            audit_reports: Vec::new(),
            verdict_commits: Vec::new(),
            watchdog_signals: Vec::new(),
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
            susp_smt_root: smt::empty_root(),
            decryption_smt_root: smt::empty_root(),
            proposer_id: 0,
            proposer_peer: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_preout: [0u8; 32],
            vrf_proof: Vec::new(),
            membership_ops: Vec::new(),
            suspensions: Vec::new(),
            verdict_sigs: Vec::new(),
            audit_reports: Vec::new(),
            verdict_commits: Vec::new(),
            watchdog_signals: Vec::new(),
        };
        Chain {
            blocks: vec![Block {
                header,
                txs: Vec::new(),
                proposer_sig: Vec::new(),
                qc: QuorumCert::default(),
            }],
        }
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

/// Verify a block's quorum certificate: ≥ quorum distinct validator signers, and their aggregate
/// BLS signature verifies over this block's id under the aggregated signer public keys.
pub fn qc_valid(block: &Block, validators: &[[u8; 32]], bls_pks: &HashMap<[u8; 32], [u8; 48]>) -> bool {
    let bid = block_id(&block.header, &block.txs);
    let signers = &block.qc.signers;
    if signers.len() < quorum(validators.len()) {
        return false;
    }
    let mut seen = HashSet::new();
    let mut pks = Vec::with_capacity(signers.len());
    for s in signers {
        if !validators.contains(s) || !seen.insert(*s) {
            return false;
        }
        match bls_pks.get(s) {
            Some(pk) => pks.push(*pk),
            None => return false,
        }
    }
    let agg: [u8; 96] = match <[u8; 96]>::try_from(block.qc.agg_sig.as_slice()) {
        Ok(a) => a,
        Err(_) => return false,
    };
    // Votes are over the slot tuple, so the aggregate verifies over the same bytes every quorum
    // voter signed: vote_sig_bytes(height, view, block_id) at this block's own (height, view).
    let msg = vote_sig_bytes(block.header.height, block.header.view, &bid);
    bls::verify_aggregate(&pks, &msg, &agg)
}
