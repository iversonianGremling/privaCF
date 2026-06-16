//! Node identity (SPEC §4.9.1, §4.2). A node holds a long-term ed25519 signing key and a
//! field-element secret `sk`. From `sk` it derives the permanent nullifier
//! `null_v = Poseidon(sk, "null_v")` and, each epoch, the pseudonym
//! `epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")` — unlinkable across epochs without `sk`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::field::{from_u64, random_field, Fp};
use crate::hash::{poseidon_scalar, DOM_EPOCH, DOM_NULL};

/// A node's long-term identity. The signing key and `sk` never leave the device.
pub struct NodeIdentity {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    /// Field-element secret feeding the Poseidon derivations.
    pub sk: Fp,
    /// Cached permanent nullifier `null_v = Poseidon(sk, "null_v")`.
    pub null_v: Fp,
}

impl NodeIdentity {
    /// Generate a fresh identity: new ed25519 keypair + fresh `sk` + derived `null_v`.
    pub fn generate(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        let sk = random_field(rng);
        let null_v = poseidon_scalar(&[sk, from_u64(DOM_NULL)]);
        Self { signing, verifying, sk, null_v }
    }

    /// Deterministic identity from a `u64` seed — so the demo/test can know every node's stable
    /// `peer_id` up front (the genesis validator set), and a node binary regenerates the same
    /// identity from `--seed`. (A real deployment generates from secure entropy via `generate`.)
    pub fn from_seed(seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        Self::generate(&mut rng)
    }

    /// Per-epoch pseudonym `epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")` (§4.2).
    pub fn epoch_id(&self, beacon: Fp) -> Fp {
        poseidon_scalar(&[self.sk, beacon, self.null_v, from_u64(DOM_EPOCH)])
    }

    /// 32-byte public node id (the ed25519 verifying key bytes) — stable across epochs, used for
    /// peer addressing and the round-robin proposer set. (The *pseudonym* `epoch_id` rotates;
    /// this stable id is the MVP's genesis-validator handle, a deliberate simplification.)
    pub fn peer_id(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Sign a message with the long-term key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

/// Verify an ed25519 signature against a 32-byte verifying-key.
pub fn verify(peer_id: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
    match VerifyingKey::from_bytes(peer_id) {
        Ok(vk) => vk.verify(msg, sig).is_ok(),
        Err(_) => false,
    }
}
