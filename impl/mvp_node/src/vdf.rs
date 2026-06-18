//! Verifiable Delay Function (SPEC §4.1 beacon, §4.3 admission). A VDF is a function whose evaluation
//! requires a prescribed number of **inherently sequential** steps (no speed-up from parallelism),
//! yet whose result is **cheap to verify**. PrivaCF wants one in two places: to make the randomness
//! beacon **unbiasable** (a last-revealing leader cannot compute the next beacon fast enough to grind
//! it), and as the **admission** proof-of-work that rate-limits identity creation (Sybil cost).
//!
//! This is a **Wesolowski VDF over an RSA group** `Z_N`. The delay is `T` sequential modular
//! squarings: `y = x^(2^T) mod N`. Computing it fast requires knowing the group order `φ(N)` (i.e.
//! factoring `N`), so it is sequential for anyone who does not. The succinct proof `π = x^⌊2^T/ℓ⌋`
//! (with `ℓ` a prime derived by Fiat–Shamir from `x,y,T`) lets a verifier check `π^ℓ · x^(2^T mod ℓ)
//! = y` with two small exponentiations.
//!
//! **Trust model — this is exactly the "presuppose a good genesis" assumption.** Security needs `N`'s
//! factorisation to be unknown to everyone. We obtain that by generating `N = p·q` at genesis and
//! **discarding `p` and `q`** (`genesis_modulus`). That is a trusted-setup artifact — legitimate
//! under the project's good-genesis premise — and sidesteps the earlier blocker (no trustless
//! unknown-order group was available in-sandbox). A fully trustless variant would use a class group
//! of an imaginary quadratic field (no setup), which is a heavier, separate implementation.
//!
//! Big-integer arithmetic is isolated here (`num-bigint`), mirroring the per-module crypto discipline.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

/// A VDF proof: the claimed output and the Wesolowski succinct proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdfProof {
    pub y: BigUint,
    pub pi: BigUint,
}

impl VdfProof {
    /// Serialize as `len(y) ‖ y ‖ pi` (big-endian), for embedding in a wire message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let yb = self.y.to_bytes_be();
        let pb = self.pi.to_bytes_be();
        let mut out = Vec::with_capacity(4 + yb.len() + pb.len());
        out.extend_from_slice(&(yb.len() as u32).to_le_bytes());
        out.extend_from_slice(&yb);
        out.extend_from_slice(&pb);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let n = u32::from_le_bytes(b[..4].try_into().ok()?) as usize;
        if b.len() < 4 + n {
            return None;
        }
        let y = BigUint::from_bytes_be(&b[4..4 + n]);
        let pi = BigUint::from_bytes_be(&b[4 + n..]);
        Some(VdfProof { y, pi })
    }
}

/// Deterministic Miller–Rabin primality test. Bases are derived from the candidate itself, so the
/// verdict is a pure function of `n` — prover and verifier always agree on which `ℓ` is "prime".
fn is_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let bp = BigUint::from(p);
        if *n == bp {
            return true;
        }
        if (n % &bp).is_zero() {
            return false;
        }
    }
    let one = BigUint::one();
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }
    'witness: for i in 0..40u32 {
        let a = derive_base(n, i);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// A Miller–Rabin base in `[2, n-2]` derived deterministically from `n` and round index `i`.
fn derive_base(n: &BigUint, i: u32) -> BigUint {
    let nb = n.to_bytes_be();
    let mut buf = vec![0u8; nb.len() + 16];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-vdf-mr-base");
    h.update(&nb);
    h.update(&i.to_le_bytes());
    h.finalize_xof().fill(&mut buf);
    let a = BigUint::from_bytes_be(&buf);
    let range = n - BigUint::from(4u32); // map into [0, n-4], then shift to [2, n-2]
    (a % range) + BigUint::from(2u32)
}

/// Hash `data` to a ~128-bit prime (the Fiat–Shamir challenge `ℓ`), deterministically.
fn hash_to_prime(data: &[u8]) -> BigUint {
    let mut counter = 0u64;
    loop {
        let mut buf = [0u8; 16];
        let mut h = blake3::Hasher::new();
        h.update(b"privacf-vdf-prime");
        h.update(data);
        h.update(&counter.to_le_bytes());
        h.finalize_xof().fill(&mut buf);
        let mut cand = BigUint::from_bytes_be(&buf);
        cand |= BigUint::one(); // odd
        cand |= BigUint::one() << 127u32; // ~128-bit
        if is_prime(&cand) {
            return cand;
        }
        counter += 1;
    }
}

/// The Fiat–Shamir binding: derive `ℓ` from the statement `(x, y, T)`.
fn challenge(x: &BigUint, y: &BigUint, t: u64) -> BigUint {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-vdf-challenge");
    h.update(&x.to_bytes_be());
    h.update(&y.to_bytes_be());
    h.update(&t.to_le_bytes());
    hash_to_prime(h.finalize().as_bytes())
}

/// Generate an RSA modulus `N = p·q` from a seeded RNG and **discard the factors**. The returned `N`
/// has unknown factorisation to everyone (the good-genesis trusted-setup artifact). `prime_bits` is
/// the size of each factor (use ≥512 for security; small values are for fast tests only).
pub fn genesis_modulus(prime_bits: u64, rng: &mut impl RngCore) -> BigUint {
    let p = random_prime(prime_bits, rng);
    let q = random_prime(prime_bits, rng);
    p * q // p and q go out of scope here, never stored
}

fn random_prime(bits: u64, rng: &mut impl RngCore) -> BigUint {
    loop {
        let mut cand = rng.gen_biguint(bits);
        cand |= BigUint::one(); // odd
        cand |= BigUint::one() << (bits - 1); // full bit length
        if is_prime(&cand) {
            return cand;
        }
    }
}

/// Map arbitrary input bytes to a group element `x ∈ Z_N` (the VDF input).
pub fn input_from_bytes(n: &BigUint, data: &[u8]) -> BigUint {
    let mut buf = vec![0u8; n.to_bytes_be().len()];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-vdf-input");
    h.update(data);
    h.finalize_xof().fill(&mut buf);
    (BigUint::from_bytes_be(&buf) % n) + BigUint::one()
}

/// Evaluate the VDF: `y = x^(2^T) mod N` by `T` sequential squarings, with a Wesolowski proof.
/// This is the slow direction — intentionally `T` sequential steps.
pub fn eval(n: &BigUint, x: &BigUint, t: u64) -> VdfProof {
    let x = x % n;
    let mut y = x.clone();
    for _ in 0..t {
        y = (&y * &y) % n; // one squaring
    }
    // Wesolowski proof: ℓ = challenge(x,y,T); π = x^⌊2^T/ℓ⌋ mod N.
    let l = challenge(&x, &y, t);
    let two_t = BigUint::one() << t;
    let q = &two_t / &l;
    let pi = x.modpow(&q, n);
    VdfProof { y, pi }
}

/// Verify a VDF proof for the statement `x^(2^T) = y (mod N)` in two small exponentiations:
/// `π^ℓ · x^(2^T mod ℓ) == y`.
pub fn verify(n: &BigUint, x: &BigUint, t: u64, proof: &VdfProof) -> bool {
    if &proof.y >= n || &proof.pi >= n || proof.y.is_zero() {
        return false;
    }
    let x = x % n;
    let l = challenge(&x, &proof.y, t);
    let two_t = BigUint::one() << t;
    let r = &two_t % &l;
    let lhs = (proof.pi.modpow(&l, n) * x.modpow(&r, n)) % n;
    lhs == proof.y
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn small_modulus() -> BigUint {
        // 256-bit factors (512-bit N) — fast, enough to exercise correctness/soundness.
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        genesis_modulus(256, &mut rng)
    }

    #[test]
    fn eval_then_verify_accepts() {
        let n = small_modulus();
        let x = input_from_bytes(&n, b"some-identity");
        let t = 1000u64;
        let proof = eval(&n, &x, t);
        assert!(verify(&n, &x, t, &proof), "an honest proof must verify");
    }

    #[test]
    fn a_tampered_output_or_proof_is_rejected() {
        let n = small_modulus();
        let x = input_from_bytes(&n, b"id");
        let t = 500u64;
        let proof = eval(&n, &x, t);

        let mut bad_y = proof.clone();
        bad_y.y = (&bad_y.y + BigUint::one()) % &n;
        assert!(!verify(&n, &x, t, &bad_y), "a wrong output must be rejected");

        let mut bad_pi = proof.clone();
        bad_pi.pi = (&bad_pi.pi + BigUint::one()) % &n;
        assert!(!verify(&n, &x, t, &bad_pi), "a wrong proof must be rejected");

        // A proof for a different delay parameter must not verify (the challenge binds T).
        assert!(!verify(&n, &x, t + 1, &proof), "the delay parameter is bound into the proof");
        // A proof for a different input must not verify.
        let x2 = input_from_bytes(&n, b"other-id");
        assert!(!verify(&n, &x2, t, &proof), "the input is bound into the proof");
    }

    #[test]
    fn proof_round_trips_through_bytes() {
        let n = small_modulus();
        let x = input_from_bytes(&n, b"serde");
        let proof = eval(&n, &x, 300);
        let bytes = proof.to_bytes();
        let back = VdfProof::from_bytes(&bytes).expect("decode");
        assert_eq!(back, proof);
        assert!(verify(&n, &x, 300, &back));
    }

    #[test]
    fn sequential_squaring_matches_a_direct_exponentiation() {
        // y = x^(2^T) computed step-by-step must equal x^(2^T) computed via a single modpow.
        let n = small_modulus();
        let x = input_from_bytes(&n, b"check");
        let t = 64u64;
        let proof = eval(&n, &x, t);
        let direct = x.modpow(&(BigUint::one() << t), &n);
        assert_eq!(proof.y, direct, "the T squarings must equal x^(2^T)");
    }
}
