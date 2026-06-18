//! Private set intersection for peer discovery (SPEC §5.3/§5.4). Two nodes decide whether they share
//! enough interest to be cluster peers **without revealing their item sets** — only the size of the
//! intersection leaks. This is a Diffie–Hellman PSI over Ristretto: each party hashes its items to
//! curve points and raises them to a private exponent; after a double exponentiation `H(z)^{ab}`
//! agrees exactly on shared items, so counting matches gives `|X ∩ Y|`. Non-shared items are
//! pseudorandom points that reveal nothing.
//!
//! Protocol (A holds `X` with secret `a`, B holds `Y` with secret `b`):
//!   1. A → B:  `U = {H(x)^a}` (shuffled)
//!   2. B → A:  `V = {H(y)^b}` (shuffled)  and  `W = {u^b} = {H(x)^{ab}}` (shuffled)
//!   3. A computes `Z = {v^a} = {H(y)^{ab}}`; `|W ∩ Z| = |X ∩ Y|`.
//! Shuffling `W`/`V` means A learns only the intersection **size**, not which items.
//!
//! The spec's deployment PSI is Pinkas et al. (OT-extension, faster at scale); DH-PSI is the
//! correct, dependency-light primitive used here. Ristretto reuses `curve25519-dalek`; the actual
//! networked handshake over the mixnet (gossip referral → PSI exchange → connect on overlap ≥ θ) is
//! the integration step on top of this primitive.

use std::collections::HashSet;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// A blinded item — a compressed Ristretto point, pseudorandom without the corresponding secret.
pub type Blinded = [u8; 32];

/// Derive a private PSI exponent (canonical scalar bytes) from a seed.
pub fn secret(seed: &[u8]) -> [u8; 32] {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-psi-secret-v1");
    h.update(seed);
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
}

fn hash_to_point(item: &[u8; 32]) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-psi-item-v1");
    h.update(item);
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// First blinding: `{H(item)^secret}`. The result hides the items (pseudorandom points).
pub fn blind(items: &[[u8; 32]], secret: &[u8; 32]) -> Vec<Blinded> {
    let s = Scalar::from_bytes_mod_order(*secret);
    items.iter().map(|it| (hash_to_point(it) * s).compress().to_bytes()).collect()
}

/// Re-blinding: raise already-blinded points to our secret (`{p^secret}`). Malformed points drop.
pub fn reblind(points: &[Blinded], secret: &[u8; 32]) -> Vec<Blinded> {
    let s = Scalar::from_bytes_mod_order(*secret);
    points
        .iter()
        .filter_map(|p| CompressedRistretto(*p).decompress().map(|pt| (pt * s).compress().to_bytes()))
        .collect()
}

/// `|A ∩ B|` over double-blinded point sets — the intersection size of the original item sets.
pub fn intersection_size(a: &[Blinded], b: &[Blinded]) -> usize {
    let set: HashSet<&Blinded> = a.iter().collect();
    b.iter().filter(|p| set.contains(p)).count()
}

/// Cluster-peer decision: connect iff the shared-interest overlap meets the threshold.
pub fn should_connect(intersection: usize, threshold: usize) -> bool {
    intersection >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(tag: &str) -> [u8; 32] {
        *blake3::hash(tag.as_bytes()).as_bytes()
    }

    /// Run the full DH-PSI between A and B and return the intersection size A learns.
    fn run_psi(x: &[[u8; 32]], y: &[[u8; 32]]) -> usize {
        let a = secret(b"node-A");
        let b = secret(b"node-B");
        let u = blind(x, &a); // A → B
        let v = blind(y, &b); // B → A
        let w = reblind(&u, &b); // B reblinds A's set → H(x)^{ab}
        let z = reblind(&v, &a); // A reblinds B's set → H(y)^{ab}
        intersection_size(&w, &z)
    }

    #[test]
    fn overlap_size_is_revealed_but_not_the_sets() {
        let x = [item("scifi"), item("noir"), item("jazz"), item("opera")];
        let y = [item("noir"), item("jazz"), item("techno"), item("folk")];
        assert_eq!(run_psi(&x, &y), 2, "the two shared items (noir, jazz) are counted");

        // Blinded items are pseudorandom: not the item, and they differ per secret.
        let a = secret(b"A");
        let bl = blind(&x, &a);
        assert_ne!(bl[0], x[0], "a blinded item is not the item");
        assert_ne!(blind(&x, &a)[0], blind(&x, &secret(b"other"))[0], "different secrets, different blinds");
    }

    #[test]
    fn disjoint_sets_intersect_to_zero() {
        let x = [item("a"), item("b"), item("c")];
        let y = [item("x"), item("y"), item("z")];
        assert_eq!(run_psi(&x, &y), 0, "disjoint interest sets reveal no overlap");
        assert!(!should_connect(0, 2), "no overlap → no cluster connection");
    }

    #[test]
    fn threshold_gates_the_connection() {
        let x = [item("a"), item("b"), item("c"), item("d")];
        let y = [item("a"), item("b"), item("c"), item("e")]; // overlap 3
        let n = run_psi(&x, &y);
        assert_eq!(n, 3);
        assert!(should_connect(n, 3) && !should_connect(n, 4), "threshold θ gates discovery");
    }
}
