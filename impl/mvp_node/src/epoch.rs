//! The per-epoch transaction a node publishes (SPEC §4.1, §6.4 handoff package, MVP subset).
//! Carries the pseudonym `epoch_id_T` and the `commit_T`. Signed by the submitter's long-term key.
//!
//! Note (unlinkability caveat): in the real protocol the transaction is signed by the *per-epoch*
//! key and the stable submitter id is NOT attached, preserving cross-epoch unlinkability. The MVP
//! attaches `submitter` and signs with the stable key for simple authenticity — acceptable because
//! the clearnet transport already links everything to a network observer (see README callouts).

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::commit::CommitT;
use crate::identity::{verify, NodeIdentity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochTransaction {
    pub height: u64,
    pub epoch_id: u64,
    pub commit: CommitT,
    /// Stable 32-byte id of the submitter (its ed25519 verifying key) — MVP authenticity handle.
    pub submitter: [u8; 32],
    /// ed25519 signature (64 bytes) over the canonical payload.
    pub sig: Vec<u8>,
}

/// Canonical bytes signed/verified for a transaction (everything but the signature).
fn tx_signing_bytes(height: u64, epoch_id: u64, commit: &CommitT, submitter: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&(height, epoch_id, commit, submitter)).expect("tx serialize")
}

impl EpochTransaction {
    pub fn create(identity: &NodeIdentity, height: u64, epoch_id: u64, commit: CommitT) -> Self {
        let submitter = identity.peer_id();
        let bytes = tx_signing_bytes(height, epoch_id, &commit, &submitter);
        let sig = identity.sign(&bytes).to_bytes().to_vec();
        Self { height, epoch_id, commit, submitter, sig }
    }

    /// Verify the submitter's signature over the transaction.
    pub fn verify_sig(&self) -> bool {
        let bytes = tx_signing_bytes(self.height, self.epoch_id, &self.commit, &self.submitter);
        match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(arr) => verify(&self.submitter, &bytes, &Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}
