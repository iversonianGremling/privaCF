//! VRF seam for leader election — a real **EC-VRF** (schnorrkel / sr25519 over Ristretto255, the
//! VRF Polkadot's BABE uses). Unlike the previous ed25519-signature stand-in, the VRF *output* is
//! UNIQUE per `(key, input)`: a validator cannot grind its own leadership-lottery value by varying
//! a signing nonce, because exactly one output verifies. (ed25519 signatures are not unique — a
//! malicious signer could try many nonces, each a valid signature with a different `blake3(sig)`,
//! and keep the lowest, biasing election in its favor. A VRF closes that.)
//!
//! schnorrkel is isolated to this module (the same seam discipline as `blst` in `bls.rs`), so the
//! rest of the node handles only byte arrays.
//!
//! Remaining caveat: the MVP beacon is still a grindable hash chain, so leader selection is only as
//! unpredictable as the beacon (a drand/VDF beacon is the SPEC's real randomness source).

use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::{signing_context, Keypair, MiniSecretKey, PublicKey};
use serde::{Deserialize, Serialize};

use crate::identity::NodeIdentity;

/// VRF domain-separation context.
const VRF_CTX: &[u8] = b"PRIVACF_VRF_v1";
/// Label deriving the lottery value from the verified VRF in-out.
const LOTTERY: &[u8] = b"leader-lottery";

/// Canonical VRF input for a height (binds the claim to the epoch beacon).
pub fn vrf_input(height: u64, beacon_t: u64) -> Vec<u8> {
    bincode::serialize(&("vrf", height, beacon_t)).expect("vrf input")
}

/// Expand a 32-byte mini-secret seed into the sr25519 keypair (deterministic).
fn keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    MiniSecretKey::from_bytes(seed)
        .expect("32-byte seed")
        .expand_to_keypair(MiniSecretKey::UNIFORM_MODE)
}

/// The compressed Ristretto VRF public key (32 B) advertised in the validator set.
pub fn vrf_pk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    keypair_from_seed(seed).public.to_bytes()
}

/// Evaluate the VRF at `input`: returns `(pre-output, proof, lottery value)`. The lottery value is
/// uniquely determined by `(seed, input)`; the pre-output + proof let anyone verify it. (The proof
/// is randomized per call, but the pre-output and lottery value are not.)
pub fn vrf_prove(seed: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 64], [u8; 32]) {
    let kp = keypair_from_seed(seed);
    let ctx = signing_context(VRF_CTX);
    let (io, proof, _batchable) = kp.vrf_sign(ctx.bytes(input));
    (io.to_preout().to_bytes(), proof.to_bytes(), io.make_bytes(LOTTERY))
}

/// Verify a VRF `(pre-output, proof)` for `input` under `vrf_pk`; returns the lottery value iff the
/// proof is valid. A `Some` return is the authoritative, ungrindable lottery value.
pub fn vrf_verify(
    vrf_pk: &[u8; 32],
    input: &[u8],
    preout: &[u8; 32],
    proof: &[u8; 64],
) -> Option<[u8; 32]> {
    let pk = PublicKey::from_bytes(vrf_pk).ok()?;
    let preout = VRFPreOut::from_bytes(preout).ok()?;
    let proof = VRFProof::from_bytes(proof).ok()?;
    let ctx = signing_context(VRF_CTX);
    let (io, _batchable) = pk.vrf_verify(ctx.bytes(input), &preout, &proof).ok()?;
    Some(io.make_bytes(LOTTERY))
}

/// A validator's VRF claim for a height — its leadership lottery ticket.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfClaim {
    pub height: u64,
    /// Proposer's stable (ed25519) id — the addressing / leader-set handle.
    pub peer: [u8; 32],
    /// The lottery value (uniquely determined by the VRF; lowest wins the slot).
    pub output: [u8; 32],
    /// VRF pre-output (transmitted so the claim is verifiable).
    pub preout: [u8; 32],
    /// 64-byte VRF proof.
    pub proof: Vec<u8>,
}

impl VrfClaim {
    pub fn create(id: &NodeIdentity, height: u64, beacon_t: u64) -> Self {
        let (preout, proof, output) = id.vrf_prove(&vrf_input(height, beacon_t));
        Self { height, peer: id.peer_id(), output, preout, proof: proof.to_vec() }
    }

    /// Verify the VRF proof for `(height, beacon_t)` under the proposer's `vrf_pk`, and that the
    /// claimed `output` is exactly the unique verified lottery value (no self-grinding).
    pub fn verify(&self, beacon_t: u64, vrf_pk: &[u8; 32]) -> bool {
        let proof: [u8; 64] = match <[u8; 64]>::try_from(self.proof.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        match vrf_verify(vrf_pk, &vrf_input(self.height, beacon_t), &self.preout, &proof) {
            Some(rand) => rand == self.output,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn vrf_output_is_deterministic_verifiable_and_unforgeable() {
        let id = NodeIdentity::from_seed(0);
        let vrf_pk = id.vrf_pk();
        let c1 = VrfClaim::create(&id, 1, 42);
        let c2 = VrfClaim::create(&id, 1, 42);
        // Output (lottery value) is unique per (key, input) even though the proof is randomized.
        assert_eq!(c1.output, c2.output, "VRF output must be deterministic");
        assert!(c1.verify(42, &vrf_pk), "valid claim must verify");
        // Different input -> different output.
        let c3 = VrfClaim::create(&id, 2, 42);
        assert_ne!(c1.output, c3.output, "different height must change the output");
        // Wrong beacon, wrong key, and a tampered output are all rejected.
        assert!(!c1.verify(43, &vrf_pk), "wrong beacon must fail");
        assert!(!c1.verify(42, &NodeIdentity::from_seed(1).vrf_pk()), "wrong key must fail");
        let mut forged = c1.clone();
        forged.output[0] ^= 0xff;
        assert!(!forged.verify(42, &vrf_pk), "tampered output must fail");
    }
}
