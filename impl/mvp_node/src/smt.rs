//! Sparse Merkle Trees (SPEC §4.9.2–3) over the circuit-matching Goldilocks Poseidon. Two instances
//! drive the protocol: **SUSP_SMT** records suspended `null_v`s (a join proves *non-membership*), and
//! **DECRYPTION_SMT** dedups `null_v` extractions (insertion proves *membership*). Their roots live in
//! every block header.
//!
//! Layout matches `spike_stmt5_proving` EXACTLY so a node-produced non-membership proof is the one the
//! Statement-5 circuit verifies: a depth-`SMT_DEPTH` binary tree indexed by the key's bits (LSB at
//! level 0); the empty leaf is `[0;4]`; an internal node is `Poseidon(left[4] ‖ right[4]) -> [_;4]`;
//! at each level the current node is the right child iff the key bit is 1 (sibling on the left), else
//! the left child. The tree is **sparse**: only occupied paths are stored, and an absent subtree
//! defaults to the precomputed empty-subtree root for its level.
//!
//! Keys are 64-bit — a `null_v` Goldilocks element is `< p < 2^64`, so its canonical `u64` is its
//! position and distinct nullifiers occupy distinct leaves.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::field::{from_u64, to_u64, Fp};
use crate::hash::poseidon;

/// Tree depth (covers a full 64-bit key). Matches the circuit's per-level path-bit binding.
pub const SMT_DEPTH: usize = 64;

/// An internal node / leaf value: a 4-element Poseidon digest.
type Node = [Fp; 4];

fn empty_leaf() -> Node {
    [from_u64(0); 4]
}

/// The present-leaf marker for an occupied key. The position already encodes the key, so a fixed
/// non-empty constant suffices to distinguish "present" from the empty leaf.
fn present_leaf() -> Node {
    poseidon(&[from_u64(0x5355_5350)]) // "SUSP"
}

/// `Poseidon(left[4] ‖ right[4]) -> [_;4]` — the internal-node compression, identical to the circuit.
fn hash_pair(left: &Node, right: &Node) -> Node {
    let mut inp = Vec::with_capacity(8);
    inp.extend_from_slice(left);
    inp.extend_from_slice(right);
    poseidon(&inp)
}

/// Serialize a node to its 32-byte form (4 canonical-`u64` little-endian limbs) — the header root form.
fn node_bytes(n: &Node) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, e) in n.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&to_u64(*e).to_le_bytes());
    }
    out
}

fn bytes_node(b: &[u8; 32]) -> Node {
    let mut n = [from_u64(0); 4];
    for (i, e) in n.iter_mut().enumerate() {
        e.clone_from(&from_u64(u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"))));
    }
    n
}

/// Precomputed empty-subtree roots: `[0]` is the empty leaf, `[lvl]` the root of an all-empty subtree
/// of height `lvl`, `[SMT_DEPTH]` the empty-tree root.
fn empty_hashes() -> Vec<Node> {
    let mut v = vec![empty_leaf()];
    for lvl in 1..=SMT_DEPTH {
        let prev = v[lvl - 1];
        v.push(hash_pair(&prev, &prev));
    }
    v
}

/// A sparse Merkle tree. Built fresh from the set of occupied keys (a pure function of that set), so
/// every node that folds the same suspension/extraction events derives the identical root.
pub struct Smt {
    empties: Vec<Node>,
    /// Occupied nodes keyed by `(level, index)`; absent ⇒ `empties[level]`.
    nodes: HashMap<(u8, u64), Node>,
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

impl Smt {
    pub fn new() -> Self {
        Self { empties: empty_hashes(), nodes: HashMap::new() }
    }

    /// Build a tree holding exactly `keys` (order-independent).
    pub fn from_keys(keys: &[u64]) -> Self {
        let mut s = Self::new();
        for &k in keys {
            s.insert(k);
        }
        s
    }

    fn node_at(&self, level: u8, index: u64) -> Node {
        self.nodes.get(&(level, index)).copied().unwrap_or(self.empties[level as usize])
    }

    /// Insert `key` (set its leaf present) and recompute the path to the root. Idempotent.
    pub fn insert(&mut self, key: u64) {
        self.nodes.insert((0, key), present_leaf());
        let mut index = key;
        for level in 0..SMT_DEPTH as u8 {
            let sib = self.node_at(level, index ^ 1);
            let cur = self.node_at(level, index);
            let (l, r) = if index & 1 == 1 { (sib, cur) } else { (cur, sib) };
            let parent = hash_pair(&l, &r);
            index >>= 1;
            self.nodes.insert((level + 1, index), parent);
        }
    }

    pub fn contains(&self, key: u64) -> bool {
        self.nodes.contains_key(&(0, key))
    }

    /// The 32-byte root (block-header form).
    pub fn root(&self) -> [u8; 32] {
        node_bytes(&self.node_at(SMT_DEPTH as u8, 0))
    }

    /// A proof for `key`: the sibling path plus whether the leaf is present. `present == false` is a
    /// non-membership proof; `true` a membership proof. Either way it is sound only against the root.
    pub fn prove(&self, key: u64) -> SmtProof {
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        let mut index = key;
        for level in 0..SMT_DEPTH as u8 {
            siblings.push(node_bytes(&self.node_at(level, index ^ 1)));
            index >>= 1;
        }
        SmtProof { key, siblings, present: self.contains(key) }
    }
}

/// A membership / non-membership proof: the key, the `SMT_DEPTH` sibling hashes up the path, and the
/// claimed leaf state. Verification reconstructs the root from `(key bits, leaf, siblings)` and
/// compares — so the root binds the `present` claim (a false non-membership cannot reproduce it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtProof {
    pub key: u64,
    pub siblings: Vec<[u8; 32]>,
    pub present: bool,
}

/// Verify `proof` against `root`. Returns true iff the reconstructed root matches; the caller reads
/// `proof.present` for the membership verdict (sound because the root commits to it).
pub fn verify(root: &[u8; 32], proof: &SmtProof) -> bool {
    if proof.siblings.len() != SMT_DEPTH {
        return false;
    }
    let mut cur = if proof.present { present_leaf() } else { empty_leaf() };
    let mut index = proof.key;
    for sib_bytes in &proof.siblings {
        let sib = bytes_node(sib_bytes);
        let (l, r) = if index & 1 == 1 { (sib, cur) } else { (cur, sib) };
        cur = hash_pair(&l, &r);
        index >>= 1;
    }
    node_bytes(&cur) == *root
}

/// The empty-tree root — the header root for an SMT with no entries (the genesis / no-suspensions
/// state). A real, computed value (not a zero stub).
pub fn empty_root() -> [u8; 32] {
    Smt::new().root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_stable_and_nonzero() {
        assert_eq!(empty_root(), empty_root(), "empty root is deterministic");
        assert_ne!(empty_root(), [0u8; 32], "empty root is a real Poseidon value, not a zero stub");
    }

    #[test]
    fn membership_and_non_membership_verify() {
        let mut t = Smt::new();
        t.insert(42);
        t.insert(1_000_000);
        let root = t.root();
        assert_ne!(root, empty_root(), "inserting changed the root");

        // A present key proves membership; an absent key proves non-membership.
        let p_in = t.prove(42);
        assert!(p_in.present && verify(&root, &p_in), "membership proof verifies");
        let p_out = t.prove(43);
        assert!(!p_out.present && verify(&root, &p_out), "non-membership proof verifies");
    }

    #[test]
    fn a_forged_non_membership_for_a_present_key_is_rejected() {
        let mut t = Smt::new();
        t.insert(7);
        let root = t.root();
        let mut forged = t.prove(7); // real siblings around the present leaf
        forged.present = false; // lie: claim the suspended key is absent
        assert!(!verify(&root, &forged), "a false non-membership cannot reproduce the root");
        // And a forged membership for an absent key likewise fails.
        let mut forged2 = t.prove(8);
        forged2.present = true;
        assert!(!verify(&root, &forged2), "a false membership cannot reproduce the root");
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let a = Smt::from_keys(&[5, 99, 12345, 1]);
        let b = Smt::from_keys(&[1, 12345, 5, 99]);
        assert_eq!(a.root(), b.root(), "the root is a pure function of the key set");
        // Re-inserting a key is idempotent.
        let mut c = Smt::from_keys(&[5, 99]);
        c.insert(5);
        assert_eq!(c.root(), Smt::from_keys(&[5, 99]).root());
    }

    #[test]
    fn distinct_keys_high_bits_use_the_full_depth() {
        // A key with its top bit set occupies a different leaf than its low-bit twin.
        let mut t = Smt::new();
        t.insert(1u64 << 63);
        let root = t.root();
        assert!(verify(&root, &t.prove(1u64 << 63)));
        let p = t.prove(0);
        assert!(!p.present && verify(&root, &p), "a different high-bit key is non-member");
    }
}
