//! Node identity (SPEC §4.9.1, §4.2). A node holds a long-term ed25519 signing key and a
//! field-element secret `sk`. From `sk` it derives the permanent nullifier
//! `null_v = Poseidon(sk, "null_v")` and, each epoch, the pseudonym
//! `epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")` — unlinkable across epochs without `sk`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::bls::{keypair_from_ikm, sign as bls_sign_bytes};
use crate::field::{from_u64, random_field, Fp};
use crate::hash::{poseidon_scalar, DOM_EPOCH, DOM_NULL};
use crate::sphinx::derive_mix_keypair;
use crate::vrf::{vrf_pk_from_seed, vrf_prove};

/// A node's long-term identity. The signing key, `sk`, and BLS secret key never leave the device.
pub struct NodeIdentity {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    /// Field-element secret feeding the Poseidon derivations.
    pub sk: Fp,
    /// Cached permanent nullifier `null_v = Poseidon(sk, "null_v")`.
    pub null_v: Fp,
    /// BLS12-381 secret key bytes (for consensus vote signatures).
    bls_sk: [u8; 32],
    /// BLS12-381 compressed public key (advertised in the validator set).
    bls_pk: [u8; 48],
    /// sr25519 VRF mini-secret seed (for leader-election VRF proofs); never leaves the device.
    vrf_seed: [u8; 32],
    /// sr25519 VRF compressed public key (advertised in the validator set).
    vrf_pk: [u8; 32],
    /// Ristretto Sphinx mix secret-key bytes (for peeling mix packets); never leaves the device.
    mix_sk: [u8; 32],
    /// Ristretto Sphinx mix public key (advertised in the mix directory, `loopix.rs`).
    mix_pk: [u8; 32],
}

impl NodeIdentity {
    /// Generate a fresh identity: new ed25519 keypair + fresh `sk` + derived `null_v` + BLS keypair.
    pub fn generate(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        let sk = random_field(rng);
        let null_v = poseidon_scalar(&[sk, from_u64(DOM_NULL)]);
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        let (bls_sk, bls_pk) = keypair_from_ikm(&ikm);
        let mut vrf_seed = [0u8; 32];
        rng.fill_bytes(&mut vrf_seed);
        let vrf_pk = vrf_pk_from_seed(&vrf_seed);
        let mut mix_ikm = [0u8; 32];
        rng.fill_bytes(&mut mix_ikm);
        let (mix_sk, mix_pk) = derive_mix_keypair(&mix_ikm);
        Self { signing, verifying, sk, null_v, bls_sk, bls_pk, vrf_seed, vrf_pk, mix_sk, mix_pk }
    }

    /// The Ristretto Sphinx mix public key (advertised in the genesis mix directory).
    pub fn mix_pk(&self) -> [u8; 32] {
        self.mix_pk
    }

    /// The Ristretto Sphinx mix secret-key bytes (used to peel inbound mix packets).
    pub fn mix_sk(&self) -> [u8; 32] {
        self.mix_sk
    }

    /// The sr25519 VRF public key (advertised to peers in the validator set).
    pub fn vrf_pk(&self) -> [u8; 32] {
        self.vrf_pk
    }

    /// Produce a VRF proof at `input`: returns `(pre-output, proof, lottery value)` (see `vrf.rs`).
    pub fn vrf_prove(&self, input: &[u8]) -> ([u8; 32], [u8; 64], [u8; 32]) {
        vrf_prove(&self.vrf_seed, input)
    }

    /// Compressed BLS public key (advertised to peers in the validator set).
    pub fn bls_pk(&self) -> [u8; 48] {
        self.bls_pk
    }

    /// BLS-sign a message (consensus votes).
    pub fn bls_sign(&self, msg: &[u8]) -> [u8; 96] {
        bls_sign_bytes(&self.bls_sk, msg)
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
