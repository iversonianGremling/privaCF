//! Admission seam (SPEC §4.3). Default: AcceptAll (Sybil-trivial). Real: `VdfAdmission` — a VDF
//! proof-of-work bound to the joining identity, rate-limiting identity creation.
//!
//! A joiner must evaluate the genesis VDF over its own `peer_id` for a prescribed delay before it can
//! be admitted: `proof = vdf::eval(N, input_from_bytes(N, peer_id), difficulty)`. Because the VDF is
//! inherently sequential, minting many identities in parallel costs real wall-clock time per
//! identity. The check is a pure function of the genesis parameters `(N, difficulty)` and the
//! `peer_id`, so every validator agrees on whether a join op is admissible (no split-brain) — the
//! parameters must therefore be genesis-consistent across the network.

use num_bigint::BigUint;

use crate::vdf::{self, VdfProof};

pub trait Admission: Send + Sync {
    fn admit(&self, peer_id: &[u8; 32]) -> bool;
}

/// AcceptAll: any key-holder may join (the MVP default).
pub struct AcceptAll;

impl Admission for AcceptAll {
    fn admit(&self, _peer_id: &[u8; 32]) -> bool {
        true
    }
}

/// The genesis VDF admission parameters, shared by every validator.
#[derive(Clone)]
pub struct VdfAdmission {
    /// The genesis RSA modulus (factors discarded — see `vdf`).
    pub modulus: BigUint,
    /// Required sequential squarings per admission.
    pub difficulty: u64,
}

impl VdfAdmission {
    /// Evaluate the admission VDF for `peer_id` (the joiner's side) and return the serialized proof.
    pub fn prove(&self, peer_id: &[u8; 32]) -> Vec<u8> {
        let x = vdf::input_from_bytes(&self.modulus, peer_id);
        vdf::eval(&self.modulus, &x, self.difficulty).to_bytes()
    }

    /// Verify a serialized admission proof for `peer_id` (every validator's side).
    pub fn admits(&self, peer_id: &[u8; 32], vdf_bytes: &[u8]) -> bool {
        let proof = match VdfProof::from_bytes(vdf_bytes) {
            Some(p) => p,
            None => return false,
        };
        let x = vdf::input_from_bytes(&self.modulus, peer_id);
        vdf::verify(&self.modulus, &x, self.difficulty, &proof)
    }
}
