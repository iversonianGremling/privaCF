//! Behavioral Merkle history (SPEC §4.6) — a tamper-evident per-epoch log of a node's behavior
//! (announcements, pull receipts, audit responses, rate-limit tokens) committed as a Merkle root
//! `M_v(T)` published periodically. Leaves are **salted** with a per-epoch PRF value so a partial
//! reveal (showing one leaf + its inclusion path to an auditor) does NOT leak the contents of the
//! other leaves: a sibling is just an opaque hash, and a leaf's own preimage is unguessable without
//! its salt. Built from peer co-receipts (no single node controls a leaf), so it is not self-report.
//!
//! These hashes are NOT circuit-constrained (M_v is for audits, not the Statement-5 identity), so
//! they use blake3 like the rest of the block plumbing, not the circuit Poseidon.

use serde::{Deserialize, Serialize};

/// Behavioral-leaf kinds (§4.6).
pub const TAG_ANNOUNCE: u8 = 0;
pub const TAG_PULL: u8 = 1;
pub const TAG_AUDIT: u8 = 2;
pub const TAG_RATE_LIMIT: u8 = 3;

/// A per-epoch PRF salt for leaf `index`, derived from the node's secret material — the value that
/// makes a revealed leaf's preimage unguessable (`Poseidon(sk, epoch, "leaf_salt")` in the spec;
/// blake3 here, since `M_v` is not circuit-constrained).
pub fn leaf_salt(sk_bytes: &[u8; 32], epoch: u64, index: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-leaf-salt-v1");
    h.update(sk_bytes);
    h.update(&epoch.to_le_bytes());
    h.update(&index.to_le_bytes());
    *h.finalize().as_bytes()
}

/// `leaf = H(tag ‖ epoch ‖ data ‖ salt)`.
pub fn leaf_hash(tag: u8, epoch: u64, data: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-leaf-v1");
    h.update(&[tag]);
    h.update(&epoch.to_le_bytes());
    h.update(data);
    h.update(salt);
    *h.finalize().as_bytes()
}

fn empty_leaf() -> [u8; 32] {
    *blake3::hash(b"privacf-history-empty").as_bytes()
}

fn parent(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]); // domain-separate internal nodes from leaves
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

/// A node's behavioral history for one epoch — the (already salted) leaf hashes, padded to a power of
/// two with a fixed empty leaf, committed as the Merkle root `M_v(T)`.
pub struct History {
    levels: Vec<Vec<[u8; 32]>>, // levels[0] = padded leaves, last = [root]
}

impl History {
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
        let mut padded = leaves.to_vec();
        let n = padded.len().next_power_of_two().max(1);
        padded.resize(n, empty_leaf());
        let mut levels = vec![padded];
        while levels.last().unwrap().len() > 1 {
            let lvl = levels.last().unwrap();
            let next: Vec<[u8; 32]> = lvl.chunks(2).map(|p| parent(&p[0], &p[1])).collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// The published commitment `M_v(T)`.
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    /// An inclusion (partial-reveal) proof for leaf `index`: the sibling hash at each level.
    pub fn prove(&self, index: usize) -> MerkleProof {
        let mut siblings = Vec::new();
        let mut idx = index;
        for lvl in &self.levels[..self.levels.len() - 1] {
            siblings.push(lvl[idx ^ 1]);
            idx >>= 1;
        }
        MerkleProof { index, siblings }
    }
}

/// A partial-reveal proof — the sibling path. Reveals only opaque hashes of the unrevealed leaves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Verify that `leaf` is at `proof.index` under `root`.
pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut cur = *leaf;
    let mut idx = proof.index;
    for sib in &proof.siblings {
        cur = if idx & 1 == 0 { parent(&cur, sib) } else { parent(sib, &cur) };
        idx >>= 1;
    }
    cur == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(sk: &[u8; 32], epoch: u64) -> Vec<[u8; 32]> {
        vec![
            leaf_hash(TAG_ANNOUNCE, epoch, b"item-42 first-seen", &leaf_salt(sk, epoch, 0)),
            leaf_hash(TAG_PULL, epoch, b"receipt from peer-7", &leaf_salt(sk, epoch, 1)),
            leaf_hash(TAG_AUDIT, epoch, b"class2 obs ok", &leaf_salt(sk, epoch, 2)),
            leaf_hash(TAG_RATE_LIMIT, epoch, b"token-set card=3", &leaf_salt(sk, epoch, 3)),
        ]
    }

    #[test]
    fn inclusion_proof_verifies_and_tampering_fails() {
        let sk = [5u8; 32];
        let leaves = sample(&sk, 9);
        let h = History::from_leaves(&leaves);
        let root = h.root();
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(verify(&root, leaf, &h.prove(i)), "leaf {i} included");
        }
        // A wrong leaf at a valid index does not verify.
        assert!(!verify(&root, &[0u8; 32], &h.prove(1)), "a tampered leaf is rejected");
    }

    #[test]
    fn partial_reveal_keeps_siblings_opaque() {
        // Revealing leaf 0 (with its salt) exposes only opaque sibling hashes, never another leaf's
        // data — the proof for leaf 0 must not contain leaf 1's hash unless it is the direct sibling,
        // and even then it is just a hash (no preimage). Here we check the auditor cannot recompute a
        // hidden leaf: without its salt, guessing its small `data` does not reproduce the leaf hash.
        let sk = [7u8; 32];
        let leaves = sample(&sk, 3);
        let h = History::from_leaves(&leaves);

        // An auditor who knows the *data* of leaf 1 but not its salt cannot forge its hash.
        let guess = leaf_hash(TAG_PULL, 3, b"receipt from peer-7", &[0u8; 32]);
        assert_ne!(guess, leaves[1], "without the per-epoch salt a leaf preimage cannot be reproduced");
        // The revealed proof for leaf 0 verifies without exposing leaf 2/3 contents (only hashes).
        assert!(verify(&h.root(), &leaves[0], &h.prove(0)));
    }

    #[test]
    fn distinct_epochs_salt_differently() {
        let sk = [1u8; 32];
        assert_ne!(leaf_salt(&sk, 1, 0), leaf_salt(&sk, 2, 0), "salt rotates per epoch");
        assert_ne!(leaf_salt(&sk, 1, 0), leaf_salt(&sk, 1, 1), "salt differs per leaf index");
    }
}
