//! Watchdog signals and recursive oversight (SPEC §4.9.8). The rogue-committee defense: a committee
//! that tries mass deanonymization must *publicly commit* to verdicts (commit-reveal ordering, §4.9.6)
//! before any `null_v` is decryptable — so an anomalous burst of `verdict_commit` transactions is
//! visible on the public chain *before* a single identity is exposed. Any node monitoring the chain
//! raises a [`WatchdogSignal`]; signals from multiple nodes trigger the **recursive oversight chain**:
//!
//!   * **Watchdog trigger** — `count(verdict_commit in epoch T)` exceeds `expected_rate(T)` by
//!     `threshold_watchdog` AND no corresponding behavioral signals justify the rate. Expected rate is
//!     near zero (legitimate suspensions are rare), so a deanonymization sweep stands out immediately.
//!   * **Recursive oversight** — a meta-committee surveys the original committee, running the *same*
//!     commit-reveal ordering; each level locks its decision before the next level's `null_v` becomes
//!     accessible. Levels are drawn **independently** (disjoint membership + interest-cluster diversity)
//!     with sizes growing linearly, `K_d = K₀ + d·ΔK`.
//!   * **Chernoff amplification** — given independence and committee-eligible adversarial fraction
//!     `q < ½`, `P(compromise at level d) ≤ exp(−K_d · D(½ ‖ q))` ([`compromise_bound`]) decays
//!     exponentially in `K_d` and hence in depth; the cumulative escape probability is a product of
//!     per-level terms each `< 1`, so a finite depth suffices for any target (closes OQ-49 structurally;
//!     `K₀`/`ΔK` calibration is Phase-5 empirical work).
//!
//! Scope: the watchdog/oversight **mechanism** (signal, escalation, independent committee draws, the
//! Chernoff bound) as a standalone, tested primitive. The per-level commit-reveal itself reuses
//! [`crate::verdict`]; wiring the trigger into the live block loop (the *when*) is the tracked
//! refinement, mirroring `verdict.rs`/`arbitration.rs`.

use serde::{Deserialize, Serialize};

use crate::arbitration::select_committee;
use crate::identity::{verify as verify_ed25519, NodeIdentity};

// ─────────────────────────────────── watchdog signals ───────────────────────────────────

/// Whether an epoch's verdict-commit activity is anomalous: the observed count exceeds the expected
/// rate by `threshold_watchdog` AND the behavioral signals fall short of matching the burst (a genuine
/// wave of misbehavior would be accompanied by behavioral signals at a comparable rate). Both
/// conditions are required, exactly as in §4.9.8.
pub fn anomalous(observed_commits: u64, expected_rate: f64, threshold_watchdog: f64, behavioral_signals: u64) -> bool {
    observed_commits as f64 > expected_rate + threshold_watchdog && behavioral_signals < observed_commits
}

fn signal_msg(epoch_t: u64, observed_commits: u64, expected_rate_milli: u64) -> Vec<u8> {
    bincode::serialize(&("watchdog-signal", epoch_t, observed_commits, expected_rate_milli)).expect("signal msg")
}

/// The expected rate carried in the signal is fixed-point (milli-units) so it is canonical on the wire
/// and the signature is well-defined.
fn rate_milli(expected_rate: f64) -> u64 {
    (expected_rate * 1000.0).round().max(0.0) as u64
}

/// A signed watchdog signal (§4.9.8): the observer's estimate that epoch `epoch_t` carried an anomalous
/// `verdict_commit` burst, broadcast to trigger recursive oversight.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchdogSignal {
    pub epoch_id: [u8; 32],
    pub epoch_t: u64,
    pub observed_commits: u64,
    pub expected_rate_milli: u64,
    pub sig: Vec<u8>,
}

impl WatchdogSignal {
    /// Raise a signal for `epoch_t` with the observed count and local rate estimate, signed by the node.
    pub fn raise(identity: &NodeIdentity, epoch_t: u64, observed_commits: u64, expected_rate: f64) -> Self {
        let rm = rate_milli(expected_rate);
        let sig = identity.sign(&signal_msg(epoch_t, observed_commits, rm)).to_bytes().to_vec();
        WatchdogSignal { epoch_id: identity.peer_id(), epoch_t, observed_commits, expected_rate_milli: rm, sig }
    }

    /// Verify the signal's signature against its claimed signer.
    pub fn verify(&self) -> bool {
        let msg = signal_msg(self.epoch_t, self.observed_commits, self.expected_rate_milli);
        match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(arr) => verify_ed25519(&self.epoch_id, &msg, &ed25519_dalek::Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}

/// Count distinct, valid signalers for `epoch_t`. Recursive oversight triggers once this reaches the
/// caller's quorum (signals "from multiple nodes", §4.9.8).
pub fn tally_signals(signals: &[WatchdogSignal], epoch_t: u64) -> usize {
    let mut seen = std::collections::HashSet::new();
    for s in signals {
        if s.epoch_t == epoch_t && s.verify() {
            seen.insert(s.epoch_id);
        }
    }
    seen.len()
}

// ─────────────────────────────── recursive oversight chain ───────────────────────────────

/// Committee size at oversight level `d`: `K_d = K₀ + d·ΔK` (grows linearly, so the Chernoff bound
/// tightens with depth — the doubly-exponential decay in §4.9.8).
pub fn committee_size(k0: usize, dk: usize, d: usize) -> usize {
    k0 + d * dk
}

/// Cluster of a peer in `clusters` (a peer→cluster map), or `None` if unknown.
fn cluster_of(clusters: &[([u8; 32], u64)], peer: &[u8; 32]) -> Option<u64> {
    clusters.iter().find(|(p, _)| p == peer).map(|(_, c)| *c)
}

/// Select the level-`d` oversight committee: an independent beacon-seeded draw of size `K_d` that is
/// **disjoint** from every lower-level committee in `lower` (the load-bearing independence the Chernoff
/// argument needs) and, where the pool allows, **interest-cluster diverse** — it first excludes peers
/// whose cluster already appears at a lower level, relaxing to plain member-disjointness only if too few
/// remain. `base_subject` is mixed with `d` so each level is an independent VRF draw. Re-derivable by
/// anyone from public chain data.
pub fn oversight_committee(
    eligible: &[[u8; 32]],
    beacon_t: u64,
    base_subject: u64,
    k0: usize,
    dk: usize,
    d: usize,
    lower: &[Vec<[u8; 32]>],
    clusters: &[([u8; 32], u64)],
) -> Vec<[u8; 32]> {
    let used_members: std::collections::HashSet<[u8; 32]> = lower.iter().flatten().copied().collect();
    let used_clusters: std::collections::HashSet<u64> =
        lower.iter().flatten().filter_map(|p| cluster_of(clusters, p)).collect();

    // Member-disjoint pool (always enforced).
    let disjoint: Vec<[u8; 32]> = eligible.iter().copied().filter(|p| !used_members.contains(p)).collect();
    let size = committee_size(k0, dk, d);

    // Prefer also cluster-disjoint; relax if that leaves fewer than a full committee.
    let cluster_diverse: Vec<[u8; 32]> =
        disjoint.iter().copied().filter(|p| cluster_of(clusters, p).map_or(true, |c| !used_clusters.contains(&c))).collect();
    let pool = if cluster_diverse.len() >= size { cluster_diverse } else { disjoint };

    // Independent draw per level: fold the depth into the subject.
    let subject = base_subject ^ (d as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    select_committee(&pool, beacon_t, subject, size)
}

/// Chernoff/KL upper bound on the probability that a size-`k` committee has an adversarial majority,
/// `P(Bin(k, q) ≥ ⌊k/2⌋+1) ≤ exp(−k · D(a ‖ q))` with `a = (⌊k/2⌋+1)/k` and KL divergence
/// `D(a‖q) = a·ln(a/q) + (1−a)·ln((1−a)/(1−q))`. Defined for `0 < q < a`; returns `1.0` if `q ≥ a`
/// (no amplification once the adversary holds a majority of the eligible pool — A2 has broken).
pub fn compromise_bound(k: usize, q: f64) -> f64 {
    if k == 0 || !(0.0..1.0).contains(&q) {
        return 1.0;
    }
    let a = ((k / 2 + 1) as f64) / k as f64;
    if q >= a {
        return 1.0;
    }
    let d_kl = a * (a / q).ln() + (1.0 - a) * ((1.0 - a) / (1.0 - q)).ln();
    (-(k as f64) * d_kl).exp()
}

/// The outcome of running the recursive oversight chain over per-level commit-reveal results
/// (`level_completed[d]` = did level `d`'s committee reach a majority reveal). Mirrors the §4.9.6
/// fallback: whichever level completes first resolves the oversight; exhausting all levels without
/// completion is a network-wide liveness incident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OversightOutcome {
    Resolved(usize),
    Exhausted,
}

/// Walk the oversight levels: the first completing level resolves; none completing is `Exhausted`.
pub fn resolve_oversight(level_completed: &[bool]) -> OversightOutcome {
    match level_completed.iter().position(|&c| c) {
        Some(d) => OversightOutcome::Resolved(d),
        None => OversightOutcome::Exhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_ids(n: u8) -> Vec<[u8; 32]> {
        (0..n as u64).map(|s| NodeIdentity::from_seed(s).peer_id()).collect()
    }

    #[test]
    fn anomaly_needs_both_a_burst_and_missing_behavioral_signals() {
        // A burst with no behavioral justification fires.
        assert!(anomalous(20, 1.0, 5.0, 0), "burst without behavioral signal is anomalous");
        // The same burst accompanied by matching behavioral signals does NOT (a real misbehavior wave).
        assert!(!anomalous(20, 1.0, 5.0, 20), "matched behavioral signals justify the rate");
        // Within the expected band: not anomalous.
        assert!(!anomalous(3, 1.0, 5.0, 0), "below threshold is normal");
    }

    #[test]
    fn signals_sign_verify_and_tally_distinct_signalers() {
        let nodes: Vec<NodeIdentity> = (0..4).map(NodeIdentity::from_seed).collect();
        let epoch_t = 99u64;
        let mut signals: Vec<WatchdogSignal> =
            nodes.iter().map(|n| WatchdogSignal::raise(n, epoch_t, 17, 0.5)).collect();
        assert!(signals.iter().all(|s| s.verify()));
        assert_eq!(tally_signals(&signals, epoch_t), 4, "four distinct signalers");
        // A tampered signal is rejected; a duplicate signaler is counted once.
        let mut forged = signals[0].clone();
        forged.observed_commits = 9999; // breaks the signature
        assert!(!forged.verify());
        signals.push(signals[0].clone());
        assert_eq!(tally_signals(&signals, epoch_t), 4, "a duplicate signaler still counts once");
        assert_eq!(tally_signals(&signals, epoch_t + 1), 0, "wrong epoch is ignored");
    }

    #[test]
    fn oversight_levels_are_disjoint_and_grow() {
        let eligible = peer_ids(40);
        // No cluster info: enforce member-disjointness and growth across three levels.
        let l0 = oversight_committee(&eligible, 7, 0xABCD, 4, 2, 0, &[], &[]);
        let l1 = oversight_committee(&eligible, 7, 0xABCD, 4, 2, 1, &[l0.clone()], &[]);
        let l2 = oversight_committee(&eligible, 7, 0xABCD, 4, 2, 2, &[l0.clone(), l1.clone()], &[]);
        assert_eq!((l0.len(), l1.len(), l2.len()), (4, 6, 8), "K_d = 4 + 2d");

        let all: Vec<[u8; 32]> = l0.iter().chain(&l1).chain(&l2).copied().collect();
        let distinct: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(distinct.len(), all.len(), "committees across levels are disjoint");
    }

    #[test]
    fn oversight_prefers_fresh_clusters_when_possible() {
        let eligible = peer_ids(20);
        // Assign clusters 0..4, four peers each. Level 0 will occupy some clusters; level 1 should avoid
        // them while the pool allows it.
        let clusters: Vec<([u8; 32], u64)> =
            eligible.iter().enumerate().map(|(i, p)| (*p, (i % 5) as u64)).collect();
        let l0 = oversight_committee(&eligible, 3, 1, 3, 0, 0, &[], &clusters);
        let l0_clusters: std::collections::HashSet<u64> =
            l0.iter().filter_map(|p| cluster_of(&clusters, p)).collect();
        let l1 = oversight_committee(&eligible, 3, 1, 3, 0, 1, &[l0.clone()], &clusters);
        // With 5 clusters and small committees, level 1 should land entirely in clusters level 0 missed.
        assert!(
            l1.iter().filter_map(|p| cluster_of(&clusters, p)).all(|c| !l0_clusters.contains(&c)),
            "level 1 draws from interest clusters distinct from level 0"
        );
    }

    #[test]
    fn compromise_probability_decays_with_depth() {
        // Honest-majority eligible pool (q < 1/2): the bound must strictly shrink as K_d grows.
        let q = 0.3;
        let (k0, dk) = (7usize, 4usize);
        let bounds: Vec<f64> = (0..5).map(|d| compromise_bound(committee_size(k0, dk, d), q)).collect();
        for w in bounds.windows(2) {
            assert!(w[1] < w[0], "compromise bound decreases with depth (Chernoff amplification)");
        }
        // Cumulative escape probability is a finite product of terms < 1 → tends toward 0.
        let cumulative: f64 = bounds.iter().product();
        assert!(cumulative < bounds[0], "cumulative escape shrinks across levels");
        // Once q reaches a committee majority, no amplification (A2 broken).
        assert_eq!(compromise_bound(9, 0.6), 1.0, "no amplification past honest-majority");
    }

    #[test]
    fn escalation_resolves_at_the_first_completing_level() {
        assert_eq!(resolve_oversight(&[false, false, true, false]), OversightOutcome::Resolved(2));
        assert_eq!(resolve_oversight(&[true]), OversightOutcome::Resolved(0));
        assert_eq!(resolve_oversight(&[false, false, false]), OversightOutcome::Exhausted);
    }
}
