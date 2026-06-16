//! The single Poseidon seam. This is the ONLY place plonky2 is touched, and it is
//! correctness-critical: `null_v` and `epoch_id` derived here must match what the eventual
//! Statement-5 ZK circuit constrains (SPEC §4.9.1/§4.2). We therefore reuse the *exact* native
//! Poseidon-over-Goldilocks the circuit uses — the same `hash_n_to_hash_no_pad` /
//! `PoseidonPermutation` pattern asserted equal to the in-circuit `PoseidonHash` in
//! `impl/spike_stmt5_proving/src/main.rs`.
//!
//! If plonky2's nightly requirement ever conflicts with the tokio/networking stack, this module
//! (≈10 lines) is the one place to swap to a standalone Goldilocks-Poseidon — provided it uses the
//! identical field, round constants, and MDS matrix, or every node's `epoch_id` silently diverges
//! from the circuit. Block-plumbing hashes use blake3 (see `chain.rs`), NOT this — Poseidon is
//! reserved for the circuit-equivalent identity derivations.

use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::poseidon::PoseidonPermutation;

use crate::field::Fp;

/// Domain-separation tags (cf. SPEC §4.2; mirror `DOM_NULL`/`DOM_EPOCH` in the proving spike).
pub const DOM_NULL: u64 = 0x6e_75_6c_6c; // "null"
pub const DOM_EPOCH: u64 = 0x65_70_6f_63; // "epoc"

/// Poseidon over a slice of field elements → the 4-element output.
pub fn poseidon(inputs: &[Fp]) -> [Fp; 4] {
    hash_n_to_hash_no_pad::<Fp, PoseidonPermutation<Fp>>(inputs).elements
}

/// Poseidon → the canonical scalar (first output element), as used for `null_v`/`epoch_id`.
pub fn poseidon_scalar(inputs: &[Fp]) -> Fp {
    poseidon(inputs)[0]
}
