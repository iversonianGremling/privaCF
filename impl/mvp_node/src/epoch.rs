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
use crate::history::{leaf_hash, leaf_salt, History, TAG_ANNOUNCE};
use crate::identity::{verify, NodeIdentity};
use crate::obfuscate::{laplace, LaplaceMethod};
use crate::pedersen::Pedersen;

/// The Layer-5 preference contribution a node attaches to its epoch transaction (SPEC §4.4–§4.6).
/// This is the on-chain substrate gossip the recommendation engine aggregates: the node never
/// publishes its clean preference vector — it publishes the **obfuscated** gossip plus a binding
/// **Pedersen commitment** to the clean vector and the **behavioral Merkle root** that logs the
/// announcement. Anyone reading the finalized chain can assemble the gossip matrix and recommend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreferencePayload {
    /// Obfuscated positive-preference gossip (§4.5) — the row recommendation aggregates over.
    pub gossip: Vec<f32>,
    /// Pedersen commitment `C_p(T)` to the node's CLEAN preference vector (§4.4) — binds the node to
    /// a fixed vector (the temporal/handoff ZK statements open against it) without revealing it.
    pub c_p: [u8; 32],
    /// Behavioral Merkle root `M_v(T)` (§4.6) — the tamper-evident log root for this epoch.
    pub m_v: [u8; 32],
}

/// Deterministic 32-byte per-epoch derivation from a node's secret handle (obfuscation seed, Pedersen
/// blinding, leaf-salt handle) — keeps the published payload reproducible and secret-bound.
fn derive32(sk_handle: &[u8; 32], epoch_id: u64, domain: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-pref-derive-v1");
    h.update(sk_handle);
    h.update(&epoch_id.to_le_bytes());
    h.update(domain);
    *h.finalize().as_bytes()
}

impl PreferencePayload {
    /// Build the payload from a node's clean preference row `prefs` (per-item integer weights),
    /// deterministically given the node's `sk_handle` and `epoch_id`: obfuscate the gossip with
    /// Laplace-DP at `epsilon` (§4.5), commit `C_p` (§4.4), and root `M_v` over an announce leaf that
    /// binds the obfuscated gossip into the behavioral log (§4.6).
    pub fn build(prefs: &[i64], sk_handle: &[u8; 32], epoch_id: u64, epsilon: f64) -> Self {
        // Obfuscated gossip: Laplace-DP over the clean positive row, seeded per-epoch from the secret.
        let seed = u64::from_le_bytes(derive32(sk_handle, epoch_id, b"obf-seed")[..8].try_into().unwrap());
        let pref_f: Vec<f64> = prefs.iter().map(|&v| v.max(0) as f64).collect();
        let row = laplace(&vec![pref_f], epsilon, seed, 2.0, 1.0, true, LaplaceMethod::Clamp)
            .pop()
            .unwrap_or_default();
        let gossip: Vec<f32> = row.iter().map(|&x| x as f32).collect();

        // Pedersen commitment to the CLEAN vector under a secret per-epoch blinding.
        let pc = Pedersen::new(prefs.len().max(1));
        let blinding = derive32(sk_handle, epoch_id, b"cp-blind");
        let c_p = pc.commit(prefs, &blinding);

        // Behavioral root: an announce leaf binding the obfuscated gossip, salted per-epoch.
        let salt = leaf_salt(sk_handle, epoch_id, 0);
        let gossip_bytes = bincode::serialize(&gossip).expect("gossip serialize");
        let leaf = leaf_hash(TAG_ANNOUNCE, epoch_id, &gossip_bytes, &salt);
        let m_v = History::from_leaves(&[leaf]).root();

        Self { gossip, c_p, m_v }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochTransaction {
    pub height: u64,
    pub epoch_id: u64,
    pub commit: CommitT,
    /// Optional Layer-5 preference contribution (§4.4–§4.6) — present when the node has preferences
    /// configured; the recommendation engine aggregates over the `pref.gossip` rows on-chain.
    pub pref: Option<PreferencePayload>,
    /// Stable 32-byte id of the submitter (its ed25519 verifying key) — MVP authenticity handle.
    pub submitter: [u8; 32],
    /// ed25519 signature (64 bytes) over the canonical payload.
    pub sig: Vec<u8>,
}

/// Canonical bytes signed/verified for a transaction (everything but the signature).
fn tx_signing_bytes(
    height: u64,
    epoch_id: u64,
    commit: &CommitT,
    pref: &Option<PreferencePayload>,
    submitter: &[u8; 32],
) -> Vec<u8> {
    bincode::serialize(&(height, epoch_id, commit, pref, submitter)).expect("tx serialize")
}

impl EpochTransaction {
    pub fn create(identity: &NodeIdentity, height: u64, epoch_id: u64, commit: CommitT) -> Self {
        Self::create_with_pref(identity, height, epoch_id, commit, None)
    }

    /// As [`create`](Self::create) but attaching a Layer-5 [`PreferencePayload`].
    pub fn create_with_pref(
        identity: &NodeIdentity,
        height: u64,
        epoch_id: u64,
        commit: CommitT,
        pref: Option<PreferencePayload>,
    ) -> Self {
        let submitter = identity.peer_id();
        let bytes = tx_signing_bytes(height, epoch_id, &commit, &pref, &submitter);
        let sig = identity.sign(&bytes).to_bytes().to_vec();
        Self { height, epoch_id, commit, pref, submitter, sig }
    }

    /// Verify the submitter's signature over the transaction.
    pub fn verify_sig(&self) -> bool {
        let bytes = tx_signing_bytes(self.height, self.epoch_id, &self.commit, &self.pref, &self.submitter);
        match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(arr) => verify(&self.submitter, &bytes, &Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}
