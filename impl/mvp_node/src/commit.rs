//! Per-epoch forward-secure nullifier commitment (SPEC §4.9.4, adopted publish-`s₁` form).
//! `commit_T = (s₁ public, d_T)` where `s₁ = null_v − s₂ (mod p)` and `d_T` encrypts `s₂` to the
//! standing validator key `VA_pub`. In the MVP there are no verdicts/decryption, so `d_T` is a
//! placeholder produced by the `VerEnc` seam below.

use serde::{Deserialize, Serialize};

use crate::field::{to_u64, Fp};

/// The published per-epoch commitment. `s1` is canonical-`u64` of the public share; `d_t` is the
/// (stubbed) verifiable encryption of `s2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitT {
    pub s1: u64,
    pub d_t: Vec<u8>,
}

/// Verifiable encryption of the secret share `s₂` to `VA_pub`.
///
/// Stub: `StubVerEnc` returns an opaque placeholder — it does NOT cryptographically seal `s₂`.
/// Real future impl: `NativeGroupVerEnc` — the limb verifiable encryption of
/// [DESIGN-f1-verifiable-encryption.md](../../DESIGN-f1-verifiable-encryption.md), decryptable only
/// by the post-verdict validator threshold signature (SPEC §4.9.4).
pub trait VerEnc: Send + Sync {
    fn encrypt(&self, s2: Fp, epoch_id: Fp) -> Vec<u8>;
}

/// Placeholder VerEnc. Emits a fixed tag plus the epoch id — NOT a sealing of `s₂`.
pub struct StubVerEnc;

impl VerEnc for StubVerEnc {
    fn encrypt(&self, _s2: Fp, epoch_id: Fp) -> Vec<u8> {
        // Deliberately does not encode s2: an MVP placeholder, not a ciphertext.
        let mut v = b"STUB-d_T".to_vec();
        v.extend_from_slice(&to_u64(epoch_id).to_le_bytes());
        v
    }
}
