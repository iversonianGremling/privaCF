//! Integration test for watchdog + recursive oversight (SPEC §4.9.8, escalating per §4.9.6). A rogue
//! committee floods the chain with `verdict_commit` transactions to mass-deanonymize; watchers detect
//! the anomalous burst and raise signals; a quorum of signals triggers the recursive oversight chain.
//! Level 0's oversight committee stalls (a minority refuses to reveal), so control passes to a
//! disjoint, larger level-1 committee that completes a real commit-reveal SUSPEND against the rogue
//! committee — exactly the "lock each level before the next becomes accessible" structure, run over the
//! real `verdict` machinery.

use mvp_node::identity::NodeIdentity;
use mvp_node::verdict::{self, SUSPEND, PASS};
use mvp_node::watchdog::{self, OversightOutcome};

/// Run a commit-reveal among a committee and return how many SUSPEND votes were tallied.
fn run_commit_reveal(members: &[NodeIdentity], target: u64, suspend_count: usize) -> usize {
    let ids: Vec<[u8; 32]> = members.iter().map(|m| m.peer_id()).collect();
    let mut commits = Vec::new();
    let mut reveals = Vec::new();
    for (k, m) in members.iter().enumerate() {
        let v = if k < suspend_count { SUSPEND } else { PASS };
        let (c, r) = verdict::cast(m, target, v, [k as u8; 32]);
        commits.push(c);
        reveals.push(r);
    }
    verdict::tally_suspend(&commits, &reveals, &ids, target)
}

#[test]
fn anomalous_burst_triggers_oversight_that_escalates_to_a_disjoint_level() {
    // ── 1. A rogue committee posts a burst of verdict commits with no behavioral justification.
    let observed_commits = 24u64;
    let expected_rate = 0.5; // near zero — legitimate suspensions are rare
    let threshold_watchdog = 4.0;
    let behavioral_signals = 0u64;
    assert!(
        watchdog::anomalous(observed_commits, expected_rate, threshold_watchdog, behavioral_signals),
        "a verdict burst with no behavioral signals is anomalous"
    );

    // ── 2. Multiple independent watchers raise signals; a quorum triggers oversight.
    let epoch_t = 0x4242u64;
    let watchers: Vec<NodeIdentity> = (100..105).map(NodeIdentity::from_seed).collect();
    let signals: Vec<watchdog::WatchdogSignal> = watchers
        .iter()
        .map(|w| watchdog::WatchdogSignal::raise(w, epoch_t, observed_commits, expected_rate))
        .collect();
    let quorum = 3;
    assert!(watchdog::tally_signals(&signals, epoch_t) >= quorum, "a quorum of watchers signalled");

    // ── 3. Recursive oversight: independent, disjoint committees of growing size drawn from the
    //       eligible validator pool. K_d = K0 + d·ΔK with K0=4, ΔK=2.
    let eligible: Vec<[u8; 32]> = (0..40u64).map(|s| NodeIdentity::from_seed(s).peer_id()).collect();
    let beacon_t = 0xBEAC0Au64;
    let base_subject = epoch_t;
    let (k0, dk) = (7usize, 4usize);

    let l0 = watchdog::oversight_committee(&eligible, beacon_t, base_subject, k0, dk, 0, &[], &[]);
    let l1 = watchdog::oversight_committee(&eligible, beacon_t, base_subject, k0, dk, 1, &[l0.clone()], &[]);
    assert_eq!((l0.len(), l1.len()), (7, 11));
    let l0set: std::collections::HashSet<_> = l0.iter().collect();
    assert!(l1.iter().all(|m| !l0set.contains(m)), "level 1 is disjoint from level 0 (independence)");

    // Map committee peers back to identities to actually run commit-reveal.
    let id_of = |peer: &[u8; 32]| (0..40u64).map(NodeIdentity::from_seed).find(|n| &n.peer_id() == peer).unwrap();
    let l0_members: Vec<NodeIdentity> = l0.iter().map(|p| id_of(p)).collect();
    let l1_members: Vec<NodeIdentity> = l1.iter().map(|p| id_of(p)).collect();

    // ── 4. Level 0 STALLS: only a minority (3 of 7) reveals SUSPEND — below ⌊7/2⌋+1 = 4.
    let l0_suspend = run_commit_reveal(&l0_members, epoch_t, 3);
    let l0_completed = l0_suspend >= l0.len() / 2 + 1;
    assert!(!l0_completed, "a stalling minority leaves level 0 short of a majority");

    // ── 5. Level 1 (disjoint, larger) COMPLETES: 6 of 11 reveal SUSPEND ≥ ⌊11/2⌋+1 = 6.
    let l1_suspend = run_commit_reveal(&l1_members, epoch_t, 6);
    let l1_completed = l1_suspend >= l1.len() / 2 + 1;
    assert!(l1_completed, "the fresh oversight committee reaches a SUSPEND majority");

    // ── 6. The chain resolves at the first completing level — the rogue committee is overseen.
    assert_eq!(
        watchdog::resolve_oversight(&[l0_completed, l1_completed]),
        OversightOutcome::Resolved(1),
        "oversight resolves at the disjoint escalation level"
    );

    // Chernoff: the escalation made compromise strictly less likely (larger K_d, honest-majority pool).
    let q = 0.3;
    assert!(
        watchdog::compromise_bound(l1.len(), q) < watchdog::compromise_bound(l0.len(), q),
        "escalating to the larger committee tightens the compromise bound"
    );
}
