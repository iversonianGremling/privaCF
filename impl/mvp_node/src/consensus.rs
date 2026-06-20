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
/// peer id → VRF output. Deterministic ONLY once every node has the same claim set — which is the
/// problem: a node validates a proposal against whatever VRF claims it has collected so far, so two
/// nodes with different claim subsets elect different leaders and mutually reject each other's blocks.
/// In lock-step everyone collects all claims first and agrees, but a validator-set change (a
/// departure) desynchronizes claim collection and the disagreement livelocks consensus. Superseded by
/// [`leader_by_beacon`]; retained for reference / the VRF-election unit tests.
pub fn leader_for(claims: &HashMap<[u8; 32], [u8; 32]>, view: u64) -> Option<[u8; 32]> {
    if claims.is_empty() {
        return None;
    }
    let mut candidates: Vec<(&[u8; 32], &[u8; 32])> = claims.iter().collect();
    candidates.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)));
    Some(*candidates[(view as usize) % candidates.len()].0)
}

/// Deterministic, **claims-independent** leader for `(beacon, view)`: rank the active members by a
/// beacon-seeded per-peer key, then rotate by `view`. Every node computes this identically from
/// chain data alone — the active set and the (VRF-chained) round beacon — with NO dependency on which
/// VRF claims it happened to collect, so all validators always agree on the leader. Unpredictability
/// is preserved because `beacon` is itself unpredictable until the height is reached; fairness because
/// the per-beacon ranking permutes members pseudo-randomly each height. This eliminates the
/// claims-divergence livelock that `leader_for` suffers after a validator-set change (a node no longer
/// rejects a valid proposal merely because its in-flight claim set differs from the proposer's).
pub fn leader_by_beacon(members: &[[u8; 32]], beacon: u64, view: u64) -> Option<[u8; 32]> {
    if members.is_empty() {
        return None;
    }
    let mut ranked: Vec<([u8; 32], [u8; 32])> = members.iter().map(|p| (leader_key(beacon, p), *p)).collect();
    ranked.sort(); // by (key, peer_id) — total order, identical on every node
    Some(ranked[(view as usize) % ranked.len()].1)
}

/// A 32-byte beacon-seeded ranking key for a peer (domain-separated BLAKE3 of `beacon ‖ peer`).
fn leader_key(beacon: u64, peer: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-leader-by-beacon-v1");
    h.update(&beacon.to_le_bytes());
    h.update(peer);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_leader_is_deterministic_and_member_order_independent() {
        let members: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let mut shuffled = members.clone();
        shuffled.reverse();
        // Same (beacon, view) → same leader regardless of the order members are passed (the crux:
        // every node derives the identical leader from chain data, with NO dependency on which VRF
        // claims it collected — the claims-divergence livelock `leader_for` suffered).
        for view in 0..8 {
            assert_eq!(leader_by_beacon(&members, 42, view), leader_by_beacon(&shuffled, 42, view));
        }
    }

    #[test]
    fn beacon_leader_rotates_across_views_and_shifts_with_the_beacon() {
        let members: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        // Across n consecutive views the leader cycles through all n members (a fair rotation).
        let leaders: std::collections::HashSet<_> = (0..4).map(|v| leader_by_beacon(&members, 7, v).unwrap()).collect();
        assert_eq!(leaders.len(), 4, "every member leads exactly once over n views");
        // A different beacon generally permutes the ranking, so view-0 leadership is unpredictable
        // until the (VRF-chained) beacon is known.
        let differs = (0..50u64).any(|b| leader_by_beacon(&members, b, 0) != leader_by_beacon(&members, 0, 0));
        assert!(differs, "the beacon must influence the leader");
    }

    #[test]
    fn beacon_leader_empty_set_is_none() {
        assert_eq!(leader_by_beacon(&[], 1, 0), None);
    }
}
