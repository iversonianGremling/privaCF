//! Pedersen vector commitments (SPEC §4.4) — `C_p(T) = Σᵢ pᵢ·Gᵢ + r·H` over Ristretto. A node
//! commits to its per-epoch preference vector `p_v` without revealing it: **perfectly hiding** (any
//! commitment opens to any vector under some blinding) and **computationally binding** (a vector is
//! pinned under the discrete-log assumption). The commitment is **additively homomorphic** in the
//! same generators, so `C_p(T) − C_p(T−1)` commits to the *difference* vector `p_v(T) − p_v(T−1)` —
//! the hook Statement 3 (temporal consistency, `‖Δ‖₁ ≤ Δ`) and the VerEnc bridge use.
//!
//! Generators are derived by hash-to-Ristretto (independent, nothing-up-my-sleeve), so no trusted
//! setup. Ristretto is reused from `sphinx.rs`/`dkg.rs`; the curve arithmetic stays isolated here.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// A vector Pedersen commitment scheme with `n` value generators plus a blinding generator `H`.
pub struct Pedersen {
    h: RistrettoPoint,
    gens: Vec<RistrettoPoint>,
}

/// A nothing-up-my-sleeve Ristretto generator from a domain + index (hash-to-curve).
fn generator(domain: &[u8], i: u64) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-pedersen-v1");
    h.update(domain);
    h.update(&i.to_le_bytes());
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// A signed integer preference as a scalar (`r − |v|` for negatives), so difference vectors commit.
fn scalar_i64(v: i64) -> Scalar {
    if v >= 0 {
        Scalar::from(v as u64)
    } else {
        -Scalar::from((-(v as i128)) as u64)
    }
}

impl Pedersen {
    /// A scheme for vectors of length ≤ `n`.
    pub fn new(n: usize) -> Self {
        let h = generator(b"H", 0);
        let gens = (0..n as u64).map(|i| generator(b"G", i)).collect();
        Self { h, gens }
    }

    fn commit_point(&self, values: &[i64], blinding: &Scalar) -> RistrettoPoint {
        let mut acc = self.h * blinding;
        for (v, g) in values.iter().zip(self.gens.iter()) {
            acc += g * scalar_i64(*v);
        }
        acc
    }

    /// Commit to `values` (length ≤ the scheme's `n`) with 32-byte `blinding`. Returns the compressed
    /// commitment.
    pub fn commit(&self, values: &[i64], blinding: &[u8; 32]) -> [u8; 32] {
        assert!(values.len() <= self.gens.len(), "vector longer than the scheme supports");
        self.commit_point(values, &Scalar::from_bytes_mod_order(*blinding)).compress().to_bytes()
    }

    /// Verify that `commitment` opens to `(values, blinding)` (binding check).
    pub fn open(&self, commitment: &[u8; 32], values: &[i64], blinding: &[u8; 32]) -> bool {
        self.commit(values, blinding) == *commitment
    }

    /// `c1 − c2` as commitments — commits to the difference vector under the difference blinding. The
    /// temporal-consistency hook: `difference(C(T), C(T−1))` opens to `(p(T)−p(T−1), r(T)−r(T−1))`.
    pub fn difference(&self, c1: &[u8; 32], c2: &[u8; 32]) -> Option<[u8; 32]> {
        let p1 = CompressedRistretto(*c1).decompress()?;
        let p2 = CompressedRistretto(*c2).decompress()?;
        Some((p1 - p2).compress().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_opens_and_binds() {
        let pc = Pedersen::new(8);
        let p = [3i64, -1, 0, 7, 2, -4, 5, 1];
        let r = [9u8; 32];
        let c = pc.commit(&p, &r);
        assert!(pc.open(&c, &p, &r), "the real opening verifies");

        // Binding: a different vector (same blinding) yields a different commitment.
        let mut p2 = p;
        p2[3] += 1;
        assert_ne!(pc.commit(&p2, &r), c, "a changed value changes the commitment");
        // A wrong blinding also fails to open.
        assert!(!pc.open(&c, &p, &[10u8; 32]), "the wrong blinding does not open");
    }

    #[test]
    fn hiding_two_blindings_give_different_commitments() {
        let pc = Pedersen::new(4);
        let p = [1i64, 2, 3, 4];
        assert_ne!(pc.commit(&p, &[1u8; 32]), pc.commit(&p, &[2u8; 32]), "blinding hides the vector");
    }

    #[test]
    fn difference_commits_to_the_difference_vector() {
        // The temporal property: C(T) − C(T−1) opens to (p(T)−p(T−1), r(T)−r(T−1)).
        let pc = Pedersen::new(4);
        let (pt, rt) = ([5i64, 3, 8, 1], 7u64);
        let (pt1, rt1) = ([2i64, 4, 1, 1], 3u64);
        let mut r_t = [0u8; 32];
        r_t[0] = rt as u8;
        let mut r_t1 = [0u8; 32];
        r_t1[0] = rt1 as u8;

        let ct = pc.commit(&pt, &r_t);
        let ct1 = pc.commit(&pt1, &r_t1);
        let diff = pc.difference(&ct, &ct1).expect("difference");

        let dp: Vec<i64> = pt.iter().zip(pt1.iter()).map(|(a, b)| a - b).collect();
        let mut dr = [0u8; 32];
        dr[0] = (rt - rt1) as u8;
        assert!(pc.open(&diff, &dp, &dr), "the difference opens to the difference vector + blinding");
    }
}
