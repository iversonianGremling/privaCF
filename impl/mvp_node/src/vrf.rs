//! VRF seam for leader election.
//!
//! STAND-IN: a deterministic ed25519 signature over the VRF input, with output = `blake3(sig)`.
//! ed25519 (RFC 8032) signatures are deterministic, so this is a verifiable per-key pseudo-random
//! value bound to `(height, beacon_T)` — good enough to drive verifiable, beacon-bound leader
//! election. It is NOT a true VRF (no formal uniqueness/pseudorandomness reduction).
//! Real future impl: sr25519 / EC-VRF (SPEC EC-VRF; CRYPTO.md). Note the MVP beacon is itself a
//! grindable hash chain, so leader selection is only as unpredictable as the beacon.

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::identity::{verify, NodeIdentity};

/// Canonical VRF input for a height (binds the claim to the epoch beacon).
pub fn vrf_input(height: u64, beacon_t: u64) -> Vec<u8> {
    bincode::serialize(&("vrf", height, beacon_t)).expect("vrf input")
}

/// A validator's VRF claim for a height — its leadership lottery ticket.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfClaim {
    pub height: u64,
    pub peer: [u8; 32],
    pub output: [u8; 32],
    pub proof: Vec<u8>, // ed25519 sig over vrf_input
}

impl VrfClaim {
    pub fn create(id: &NodeIdentity, height: u64, beacon_t: u64) -> Self {
        let proof = id.sign(&vrf_input(height, beacon_t)).to_bytes().to_vec();
        let output = *blake3::hash(&proof).as_bytes();
        Self { height, peer: id.peer_id(), output, proof }
    }

    /// Verify the proof signs `vrf_input(height, beacon_t)` under `peer`, and `output = blake3(proof)`.
    pub fn verify(&self, beacon_t: u64) -> bool {
        let arr = match <[u8; 64]>::try_from(self.proof.as_slice()) {
            Ok(a) => a,
            Err(_) => return false,
        };
        if !verify(&self.peer, &vrf_input(self.height, beacon_t), &Signature::from_bytes(&arr)) {
            return false;
        }
        *blake3::hash(&self.proof).as_bytes() == self.output
    }
}
