//! Consensus seam — now a simplified single-round BFT: VRF leader election (`vrf.rs`) + a
//! quorum certificate (≥ ⌊2N/3⌋+1 validator votes) for finality. Honest validators vote only for
//! the lowest-VRF leader's block, so at most one block per height can gather a quorum certificate
//! under a <1/3 Byzantine assumption — that is the safety argument.
//!
//! Still stubbed / next: NO view-change (a dead leader stalls that height — liveness under failure),
//! and the quorum certificate is a list of individual ed25519 votes rather than an aggregated
//! threshold-BLS signature. Real future impl: BFT with view-change + threshold-BLS `validator_sigs`
//! (SPEC §4.1).

use std::collections::HashMap;

/// BFT quorum size for `n` validators: ⌊2n/3⌋ + 1 (tolerates ⌊(n-1)/3⌋ Byzantine).
pub fn quorum(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// The elected leader for `(round, view)`: candidates sorted by VRF output (peer id breaks ties);
/// view 0 is the lowest output, each view-change advances to the next candidate. `claims` maps
/// peer id → VRF output. Deterministic once every node has the same claim set, so a timed-out
/// (crashed) leader is skipped to the next-lowest VRF candidate without coordination.
pub fn leader_for(claims: &HashMap<[u8; 32], [u8; 32]>, view: u64) -> Option<[u8; 32]> {
    if claims.is_empty() {
        return None;
    }
    let mut candidates: Vec<(&[u8; 32], &[u8; 32])> = claims.iter().collect();
    candidates.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)));
    Some(*candidates[(view as usize) % candidates.len()].0)
}
