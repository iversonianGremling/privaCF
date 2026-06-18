//! Commit-reveal verdicts and dark-node extraction (SPEC §4.9.6). When a node is judged to
//! misbehave, a committee (the validator set in this MVP; a VRF subcommittee is the refinement) runs
//! a **commit-reveal** vote: each member first publishes `H(verdict ‖ nonce)`, then reveals
//! `(verdict, nonce)`. Locking the verdict *before* the decryption key exists is the load-bearing
//! ordering — the committee cannot be swayed by the `null_v` it is about to expose. If
//! `⌊K/2⌋+1` members reveal SUSPEND, the validators threshold-sign `verdict_id(epoch_id)` to produce
//! `σ_VERDICT` (`verenc::VERENC_DST`, combined by `dkg::combine_signatures`).
//!
//! **Dark-node extraction (P4.a):** with `σ_VERDICT` anyone decrypts the target's on-chain `d_T`
//! (`verenc`/`commit::open_commit`) to recover `s₂`, hence `null_v = s₁ + s₂` — from public chain
//! data alone, with NO cooperation from the (offline) node. The result is a `SuspendRecord` carried
//! on-chain, which folds `null_v` into the SUSP_SMT (permanent suspension) and its `dec_nullifier`
//! into the DECRYPTION_SMT (extraction dedup).
//!
//! Scope: the verdict **mechanism** (commit/reveal/tally/finalize/extract) and its on-chain state are
//! here and tested end-to-end with real crypto. Driving the multi-round flow autonomously inside the
//! live consensus loop (the *when*, vs the *what*) is a tracked refinement (P1.4b). Re-admission of
//! an *unlinkable* rejoining identity is enforced by the Statement-5 ZK non-membership proof
//! (Track Z); here a suspended `null_v` is listed and its SUSP_SMT non-membership provably fails.

use serde::{Deserialize, Serialize};

use crate::commit::open_commit;
use crate::field::{add_mod, from_u64, to_u64};
use crate::hash::poseidon_scalar;
use crate::identity::{verify as verify_ed25519, NodeIdentity};
use crate::verenc;

pub const SUSPEND: u8 = 1;
pub const PASS: u8 = 0;

fn commit_msg(target_epoch_id: u64, commit_hash: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("verdict-commit", target_epoch_id, commit_hash)).expect("commit msg")
}

fn reveal_msg(target_epoch_id: u64, verdict: u8, nonce: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("verdict-reveal", target_epoch_id, verdict, nonce)).expect("reveal msg")
}

/// `H(verdict ‖ nonce)` — the committed value, hiding the verdict until reveal.
fn commit_hash(verdict: u8, nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[verdict]);
    h.update(nonce);
    *h.finalize().as_bytes()
}

fn check_sig(peer: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    match <[u8; 64]>::try_from(sig) {
        Ok(arr) => verify_ed25519(peer, msg, &ed25519_dalek::Signature::from_bytes(&arr)),
        Err(_) => false,
    }
}

/// A committee member's commitment to a verdict on the identity that published `target_epoch_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerdictCommit {
    pub member: [u8; 32],
    pub target_epoch_id: u64,
    pub commit_hash: [u8; 32],
    pub sig: Vec<u8>,
}

/// The matching reveal — the verdict and nonce, checked against the commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerdictReveal {
    pub member: [u8; 32],
    pub target_epoch_id: u64,
    pub verdict: u8,
    pub nonce: [u8; 32],
    pub sig: Vec<u8>,
}

/// Produce a member's `(commit, reveal)` for `verdict` on `target_epoch_id` with the given `nonce`.
pub fn cast(identity: &NodeIdentity, target_epoch_id: u64, verdict: u8, nonce: [u8; 32]) -> (VerdictCommit, VerdictReveal) {
    let ch = commit_hash(verdict, &nonce);
    let commit = VerdictCommit {
        member: identity.peer_id(),
        target_epoch_id,
        commit_hash: ch,
        sig: identity.sign(&commit_msg(target_epoch_id, &ch)).to_bytes().to_vec(),
    };
    let reveal = VerdictReveal {
        member: identity.peer_id(),
        target_epoch_id,
        verdict,
        nonce,
        sig: identity.sign(&reveal_msg(target_epoch_id, verdict, &nonce)).to_bytes().to_vec(),
    };
    (commit, reveal)
}

impl VerdictCommit {
    pub fn verify(&self) -> bool {
        check_sig(&self.member, &commit_msg(self.target_epoch_id, &self.commit_hash), &self.sig)
    }
}

impl VerdictReveal {
    pub fn verify(&self) -> bool {
        check_sig(&self.member, &reveal_msg(self.target_epoch_id, self.verdict, &self.nonce), &self.sig)
    }

    /// The reveal opens its own commitment (commit-reveal binding).
    pub fn opens(&self, commit: &VerdictCommit) -> bool {
        commit.member == self.member
            && commit.target_epoch_id == self.target_epoch_id
            && commit.commit_hash == commit_hash(self.verdict, &self.nonce)
    }
}

/// Count distinct committee members who committed AND revealed SUSPEND for `target_epoch_id`, with a
/// valid commit-reveal pair (both signed, the reveal opening the commit). Tallying revealed verdicts
/// against their prior commitments enforces the commit-reveal ordering.
pub fn tally_suspend(commits: &[VerdictCommit], reveals: &[VerdictReveal], committee: &[[u8; 32]], target_epoch_id: u64) -> usize {
    let mut counted = std::collections::HashSet::new();
    for r in reveals {
        if r.target_epoch_id != target_epoch_id || r.verdict != SUSPEND || !committee.contains(&r.member) || !r.verify() {
            continue;
        }
        let has_matching_commit = commits.iter().any(|c| c.member == r.member && c.verify() && r.opens(c));
        if has_matching_commit {
            counted.insert(r.member);
        }
    }
    counted.len()
}

/// A finalized suspension carried on-chain: the extracted `null_v` for the suspended target, and a
/// `verdict_hash` binding the verdict. Folds into the SUSP_SMT (by `null_v`) and DECRYPTION_SMT (by
/// `dec_nullifier`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuspendRecord {
    pub target_epoch_id: u64,
    pub null_v: u64,
    pub verdict_hash: [u8; 32],
}

impl SuspendRecord {
    /// `dec_nullifier = Poseidon(null_v, fold(verdict_hash))` — the DECRYPTION_SMT key (one extraction
    /// per (verdict, null_v), preventing double-extraction).
    pub fn dec_nullifier(&self) -> u64 {
        let vh = u64::from_le_bytes(self.verdict_hash[..8].try_into().expect("8 bytes"));
        to_u64(poseidon_scalar(&[from_u64(self.null_v), from_u64(vh)]))
    }
}

/// Dark-node extraction: recover the target's `null_v` from its on-chain commitment `(s1, d_t)` for
/// `epoch_id` using the verdict threshold signature `σ_VERDICT`. Returns `null_v` (canonical u64), or
/// `None` if `d_t` is malformed or `σ_VERDICT` is wrong. NO cooperation from the target is needed.
pub fn extract_null_v(s1: u64, d_t: &[u8], sigma: &[u8; 96], epoch_id: u64) -> Option<u64> {
    let s2 = open_commit(d_t, sigma, from_u64(epoch_id))?;
    Some(to_u64(add_mod(from_u64(s1), s2)))
}

/// The verdict identity for an epoch (re-exported for the threshold signers).
pub fn verdict_id(epoch_id: u64) -> Vec<u8> {
    verenc::verdict_id(epoch_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn commit_reveal_binds_and_tallies() {
        let committee: Vec<NodeIdentity> = (0..5).map(NodeIdentity::from_seed).collect();
        let ids: Vec<[u8; 32]> = committee.iter().map(|i| i.peer_id()).collect();
        let target = 0xABCDu64;

        // Four members commit+reveal SUSPEND, one reveals PASS.
        let mut commits = Vec::new();
        let mut reveals = Vec::new();
        for (k, m) in committee.iter().enumerate() {
            let verdict = if k < 4 { SUSPEND } else { PASS };
            let (c, r) = cast(m, target, verdict, [k as u8; 32]);
            assert!(c.verify() && r.verify() && r.opens(&c));
            commits.push(c);
            reveals.push(r);
        }
        assert_eq!(tally_suspend(&commits, &reveals, &ids, target), 4, "4 SUSPEND votes counted");

        // A reveal whose verdict/nonce does not match its commitment is not counted.
        let (c, mut r) = cast(&committee[0], target, SUSPEND, [99u8; 32]);
        r.nonce = [1u8; 32]; // tamper: no longer opens the commit (and breaks the reveal sig too)
        assert!(!r.opens(&c) || !r.verify(), "a non-opening / re-signed reveal must not pass");
    }

    #[test]
    fn a_non_committee_member_vote_is_ignored() {
        let committee: Vec<NodeIdentity> = (0..3).map(NodeIdentity::from_seed).collect();
        let ids: Vec<[u8; 32]> = committee.iter().map(|i| i.peer_id()).collect();
        let outsider = NodeIdentity::from_seed(99);
        let target = 7u64;
        let (oc, or) = cast(&outsider, target, SUSPEND, [0u8; 32]);
        assert_eq!(tally_suspend(&[oc], &[or], &ids, target), 0, "an outsider's vote does not count");
    }
}
