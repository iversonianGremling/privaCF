//! Integration capstone for rewind + HNSW snapshots (SPEC §6.6): a coordinated gossip cohort poisons a
//! node's local index so its recommendation quality degrades; nodes across ≥2 interest clusters raise
//! rewind signals naming the same cohort epoch, which (a) triggers a Class-3 audit (the network
//! consequence) and (b) lets the node roll its local index back to the pre-poisoning snapshot, restoring
//! the honest recommendation. Ties `rewind.rs` to the real `recommend.rs` engine.

use mvp_node::identity::NodeIdentity;
use mvp_node::recommend::{top_k, CFConfig, ItemCF, Matrix};
use mvp_node::rewind::{class3_trigger, velocity_correlated, RewindSignal, SnapshotStore};

const T0: u64 = 10; // clean epoch (good snapshot)
const T1: u64 = 11; // the poisoning cohort enters here

/// 3 honest peers co-liking the {0,1} niche — item 1 is item 0's honest co-like.
fn clean_index() -> Matrix {
    vec![
        vec![1.0, 1.0, 0.0, 0.0, 0.0],
        vec![1.0, 1.0, 0.0, 0.0, 0.0],
        vec![1.0, 1.0, 0.0, 0.0, 0.0],
    ]
}

/// The poisoned index at T1: the clean rows plus a cohort that co-likes {0, 4}, making item 4 look
/// similar to item 0 (10 Sybils ≫ the 3-peer honest niche, so sim(0,4) overtakes sim(0,1)).
fn poisoned_index() -> Matrix {
    let mut g = clean_index();
    for _ in 0..10 {
        g.push(vec![1.0, 0.0, 0.0, 0.0, 5.0]);
    }
    g
}

/// Recommend one item for a user who interacted only with item 0. Similarity-driven (novelty/IDF off)
/// so the test isolates index poisoning vs. the separately-tested trust-cap/FoolsGold defences.
fn recommend_for_item0(index: &Matrix) -> usize {
    let cfg = CFConfig { kappa: 0.0, use_item_weight: false, dislike_penalty: 0.0, c: Some(100.0), ..Default::default() };
    let model = ItemCF::fit(cfg, index, None, None);
    let pref_pos = vec![vec![1.0, 0.0, 0.0, 0.0, 0.0]];
    let pref_neg = vec![vec![0.0; 5]];
    let seen = vec![vec![true, false, false, false, false]]; // item 0 already interacted with
    top_k(&model.score_all(&pref_pos, &pref_neg, &seen), 1)[0][0]
}

#[test]
fn a_poisoning_cohort_is_caught_by_rewind_signals_and_rolled_back() {
    // ── Snapshots: the node retains its index per epoch.
    let mut snaps: SnapshotStore<Matrix> = SnapshotStore::new(8);
    snaps.record(T0, clean_index());

    // At T0 the honest co-like (item 1) is recommended.
    assert_eq!(recommend_for_item0(snaps.get(T0).unwrap()), 1, "clean index recommends the honest co-like");

    // ── T1: the poisoning cohort enters; the node snapshots the now-degraded index.
    let poisoned = poisoned_index();
    snaps.record(T1, poisoned.clone());
    assert_eq!(recommend_for_item0(&poisoned), 4, "the poisoned index now recommends the Sybil-pushed item");

    // ── Rewind signals from nodes across TWO interest clusters, all naming cohort_epoch = T1.
    let signalers: Vec<NodeIdentity> = (200..204).map(NodeIdentity::from_seed).collect();
    let clusters: Vec<([u8; 32], u64)> = signalers
        .iter()
        .enumerate()
        .map(|(i, n)| (n.peer_id(), if i < 2 { 1u64 } else { 2u64 }))
        .collect();
    let signals: Vec<RewindSignal> =
        signalers.iter().map(|n| RewindSignal::raise(n, T1 + 1, T0, T1)).collect();
    assert!(signals.iter().all(|s| s.verify()));

    // ── Cohort detection → Class-3 trigger (≥3 signalers, ≥2 clusters, same cohort_epoch).
    let triggers = class3_trigger(&signals, &clusters, 3, 2);
    assert_eq!(triggers.len(), 1, "the correlated cohort triggers a Class-3 audit");
    assert_eq!(triggers[0].cohort_epoch, T1);
    assert_eq!(triggers[0].clusters, vec![1, 2], "the trigger spans both interest clusters");

    // The cohort coincides with item 4's anomalous trust velocity at T1 — the §7.1a T.8 L3 proxy.
    assert!(velocity_correlated(&triggers[0], T1), "the cohort correlates with the item's velocity epoch");

    // ── Local rollback to the pre-poisoning snapshot restores recommendation quality.
    let restored = snaps.rollback(T0).expect("T0 snapshot retained");
    assert_eq!(recommend_for_item0(&restored), 1, "after rollback the honest co-like is recommended again");
    assert_eq!(snaps.retained_epochs(), vec![T0], "the poisoned snapshot is discarded by the rollback");
}
