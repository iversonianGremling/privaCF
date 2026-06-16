//! Field-element seam. PrivaCF derives `null_v`/`epoch_id` with Poseidon over the Goldilocks
//! field (SPEC §4.9.1/§4.2), and the publish-`s₁` split is `s₁ + s₂ = null_v (mod p)` (§4.9.4).
//! We reuse plonky2's `GoldilocksField` so node-produced values match the eventual ZK circuit.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};

/// The single field-element type used everywhere a scalar mod p is needed.
pub type Fp = GoldilocksField;

/// Goldilocks prime: p = 2^64 − 2^32 + 1.
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Canonical `u64` representation (for serialization / display). Always `< p`.
pub fn to_u64(x: Fp) -> u64 {
    x.to_canonical_u64()
}

/// From a canonical `u64`. Reduces mod p so deserialization of any `u64` is total.
pub fn from_u64(x: u64) -> Fp {
    Fp::from_canonical_u64(x % GOLDILOCKS_P)
}

/// Uniform field element in `[0, p)` by rejection sampling (reject rate ≈ 2^-32).
pub fn random_field(rng: &mut impl rand::RngCore) -> Fp {
    loop {
        let x = rng.next_u64();
        if x < GOLDILOCKS_P {
            return Fp::from_canonical_u64(x);
        }
    }
}

/// `a − b (mod p)` — the publish-`s₁` share computation `s₁ = null_v − s₂`.
pub fn sub_mod(a: Fp, b: Fp) -> Fp {
    a - b
}

/// `a + b (mod p)` — used to verify `s₁ + s₂ = null_v`.
pub fn add_mod(a: Fp, b: Fp) -> Fp {
    a + b
}
