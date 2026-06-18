//! Per-epoch forward-secure nullifier commitment (SPEC §4.9.4, adopted publish-`s₁` form).
//! `commit_T = (s₁ public, d_T)` where `s₁ = null_v − s₂ (mod p)` and `d_T` encrypts `s₂` to the
//! standing validator key `VA_pub`. `NativeGroupVerEnc` is the real sealing (`verenc.rs`); the
//! `StubVerEnc` placeholder remains for tests/networks without a validator threshold key.

use serde::{Deserialize, Serialize};

use crate::field::{to_u64, Fp};
use crate::verenc;

/// The published per-epoch commitment. `s1` is canonical-`u64` of the public share; `d_t` is the
/// (stubbed) verifiable encryption of `s2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitT {
    pub s1: u64,
    pub d_t: Vec<u8>,
}

/// Verifiable encryption of the secret share `s₂` to `VA_pub`.
///
/// `NativeGroupVerEnc` is the real sealing (`verenc.rs`): `d_T` is recoverable only by the
/// post-verdict validator threshold signature (SPEC §4.9.4). `StubVerEnc` remains a placeholder for
/// tests / networks without a validator threshold key — it does NOT seal `s₂`.
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

/// The real sealing: limb exponential-ElGamal of `s₂` to the validator threshold key `VA_pub`
/// (`verenc.rs`). Recoverable only by the verdict threshold signature on `verdict_id(epoch_id)`.
pub struct NativeGroupVerEnc {
    /// The standing validator threshold public key (`VA_pub = x·g₁`, compressed G₁).
    pub va_pub: [u8; 48],
}

impl VerEnc for NativeGroupVerEnc {
    fn encrypt(&self, s2: Fp, epoch_id: Fp) -> Vec<u8> {
        let id = verenc::verdict_id(to_u64(epoch_id));
        match verenc::encrypt(&self.va_pub, &id, to_u64(s2)) {
            Some(ct) => ct.to_bytes(),
            None => Vec::new(), // malformed VA_pub: empty d_T (a no-op seal; flagged upstream)
        }
    }
}

/// Recover `s₂` from a `d_T` ciphertext given the verdict threshold signature `σ` (the dark-node
/// extraction step). `None` if `d_T` is malformed or the signature is wrong.
pub fn open_commit(d_t: &[u8], sigma: &[u8; 96], epoch_id: Fp) -> Option<Fp> {
    let ct = verenc::VerEncCt::from_bytes(d_t)?;
    let id = verenc::verdict_id(to_u64(epoch_id));
    verenc::decrypt(&ct, sigma, &id).map(crate::field::from_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::from_u64;

    #[test]
    fn native_verenc_seals_s2_and_only_the_verdict_signature_opens_it() {
        let (x, va_pub) = verenc::group_keypair(b"validator-set");
        let sealer = NativeGroupVerEnc { va_pub };
        let epoch_id = from_u64(0x00C0_FFEE);
        let s2 = from_u64(0x1122_3344_5566_7788);

        // Seal s₂ into d_T; without the verdict signature it stays sealed.
        let d_t = sealer.encrypt(s2, epoch_id);
        assert!(!d_t.is_empty(), "real VerEnc produces a ciphertext");

        // The verdict threshold signature on verdict_id(epoch_id) opens it to exactly s₂.
        let sigma = verenc::verdict_signature(&x, &verenc::verdict_id(to_u64(epoch_id)));
        assert_eq!(open_commit(&d_t, &sigma, epoch_id), Some(s2), "verdict sig recovers s₂");

        // A signature for a different epoch does not.
        let wrong = verenc::verdict_signature(&x, &verenc::verdict_id(to_u64(epoch_id) ^ 1));
        assert_ne!(open_commit(&d_t, &wrong, epoch_id), Some(s2), "wrong verdict cannot open");
    }
}
