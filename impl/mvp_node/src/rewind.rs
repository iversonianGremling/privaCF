//! Rewind signals and HNSW snapshots (SPEC §6.6). A node periodically snapshots its local
//! recommendation index (the gossip-derived state `recommend.rs` fits over — the MVP's stand-in for the
//! §5.3 HNSW graph) so that, if a later gossip cohort degrades recommendation quality, it can **roll
//! back** to a prior, better snapshot. The rollback is *purely local*; the network consequence is a
//! **Class-3 audit** triggered when enough independent nodes raise correlated rewind signals.
//!
//!   * **Snapshot store** ([`SnapshotStore`]) — a bounded per-epoch ring of index snapshots;
//!     [`SnapshotStore::rollback`] restores the index to `preferred_T` and discards the poisoned tail.
//!   * **Rewind signal** ([`RewindSignal`]) — signed `{current_T, preferred_T, cohort_epoch}`, naming
//!     the epoch whose incoming gossip vectors are implicated (`cohort_epoch`).
//!   * **Cohort detection / Class-3 trigger** ([`class3_trigger`]) — the compound rule of §6.6 and the
//!     Class-3 flow box: `≥ q` rewind signals from `≥ 2` **distinct interest clusters** all naming the
//!     **same** `cohort_epoch` (the "correlated with the same gossip cohort" condition) surface a
//!     coordinated push that the trust cap alone wouldn't flag. A per-node **rate limit**
//!     ([`RewindRateLimiter`], `≤ 1` Class-3 contribution per `N_rewind` epochs) bounds griefing.
//!   * **Item-velocity proxy** ([`velocity_correlated`]) — a qualifying cohort whose `cohort_epoch`
//!     coincides with anomalous `trust_total` velocity for a specific item is the §7.1a T.8 compound
//!     L3 signal, with no extra machinery.
//!
//! Scope: the rewind **mechanism** (snapshot/rollback, signal, cohort correlation, rate limit) as a
//! standalone tested primitive, generic over the snapshot type so it composes with `recommend.rs`.
//! Driving the Class-3 audit it triggers inside the live loop (the *when*) is the tracked refinement,
//! mirroring `verdict.rs`/`arbitration.rs`/`watchdog.rs`.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::identity::{verify as verify_ed25519, NodeIdentity};

// ──────────────────────────────────── HNSW snapshots ────────────────────────────────────

/// A bounded ring of per-epoch index snapshots. `S` is the local index state (e.g. the gossip
/// `recommend::Matrix`). The newest `cap` epochs are retained; older snapshots are evicted.
pub struct SnapshotStore<S> {
    cap: usize,
    snaps: VecDeque<(u64, S)>,
}

impl<S: Clone> SnapshotStore<S> {
    /// A store retaining at most `cap` snapshots (`cap ≥ 1`).
    pub fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), snaps: VecDeque::new() }
    }

    /// Record the index snapshot for epoch `t`. Re-recording an epoch replaces it; recording a new
    /// epoch evicts the oldest once `cap` is exceeded. Epochs are kept in ascending order.
    pub fn record(&mut self, t: u64, snapshot: S) {
        if let Some(slot) = self.snaps.iter_mut().find(|(e, _)| *e == t) {
            slot.1 = snapshot;
            return;
        }
        self.snaps.push_back((t, snapshot));
        self.snaps.make_contiguous().sort_by_key(|(e, _)| *e);
        while self.snaps.len() > self.cap {
            self.snaps.pop_front();
        }
    }

    /// The retained snapshot for epoch `t`, if any.
    pub fn get(&self, t: u64) -> Option<&S> {
        self.snaps.iter().find(|(e, _)| *e == t).map(|(_, s)| s)
    }

    /// The epochs currently retained, ascending.
    pub fn retained_epochs(&self) -> Vec<u64> {
        self.snaps.iter().map(|(e, _)| *e).collect()
    }

    /// **Roll back** to `preferred_t`: return that snapshot (cloned) and discard every later snapshot,
    /// so the store reflects the rolled-back state. `None` if `preferred_t` is no longer retained.
    pub fn rollback(&mut self, preferred_t: u64) -> Option<S> {
        let snap = self.get(preferred_t).cloned()?;
        self.snaps.retain(|(e, _)| *e <= preferred_t);
        Some(snap)
    }
}

// ──────────────────────────────────── rewind signals ────────────────────────────────────

fn signal_msg(current_t: u64, preferred_t: u64, cohort_epoch: u64) -> Vec<u8> {
    bincode::serialize(&("rewind-signal", current_t, preferred_t, cohort_epoch)).expect("rewind msg")
}

/// A signed rewind signal (§6.6): the signer's recommendation quality degraded since `preferred_t`, and
/// the implicated gossip vectors entered the index at `cohort_epoch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewindSignal {
    pub epoch_id: [u8; 32],
    pub current_t: u64,
    pub preferred_t: u64,
    pub cohort_epoch: u64,
    pub sig: Vec<u8>,
}

impl RewindSignal {
    /// Raise (and sign) a rewind signal.
    pub fn raise(identity: &NodeIdentity, current_t: u64, preferred_t: u64, cohort_epoch: u64) -> Self {
        let sig = identity.sign(&signal_msg(current_t, preferred_t, cohort_epoch)).to_bytes().to_vec();
        RewindSignal { epoch_id: identity.peer_id(), current_t, preferred_t, cohort_epoch, sig }
    }

    /// Verify the signature and basic well-formedness (`preferred_t < current_t`).
    pub fn verify(&self) -> bool {
        if self.preferred_t >= self.current_t {
            return false;
        }
        let msg = signal_msg(self.current_t, self.preferred_t, self.cohort_epoch);
        match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(arr) => verify_ed25519(&self.epoch_id, &msg, &ed25519_dalek::Signature::from_bytes(&arr)),
            Err(_) => false,
        }
    }
}

// ──────────────────────────── cohort detection / Class-3 trigger ────────────────────────────

fn cluster_of(clusters: &[([u8; 32], u64)], peer: &[u8; 32]) -> Option<u64> {
    clusters.iter().find(|(p, _)| p == peer).map(|(_, c)| *c)
}

/// A cohort that meets the §6.6 Class-3 trigger: `cohort_epoch` named by `signalers` from `clusters`
/// distinct interest clusters (`≥ 2`). The trigger the Class-3 audit flow consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class3Trigger {
    pub cohort_epoch: u64,
    pub signalers: Vec<[u8; 32]>,
    pub clusters: Vec<u64>,
}

/// Detect Class-3 triggers: group **valid, distinct-signaler** rewind signals by `cohort_epoch` and
/// return each cohort named by `≥ q` signalers spanning `≥ min_clusters` distinct interest clusters
/// (`min_clusters` is `2` per §6.6). Signals from peers with no known cluster are counted toward `q`
/// but contribute no cluster. Deterministic (cohorts ascending), so every node detects identically.
pub fn class3_trigger(
    signals: &[RewindSignal],
    clusters: &[([u8; 32], u64)],
    q: usize,
    min_clusters: usize,
) -> Vec<Class3Trigger> {
    // cohort_epoch → distinct signalers
    let mut by_cohort: HashMap<u64, HashSet<[u8; 32]>> = HashMap::new();
    for s in signals {
        if s.verify() {
            by_cohort.entry(s.cohort_epoch).or_default().insert(s.epoch_id);
        }
    }
    let mut triggers: Vec<Class3Trigger> = by_cohort
        .into_iter()
        .filter_map(|(cohort_epoch, signers)| {
            if signers.len() < q {
                return None;
            }
            let mut cluster_set: Vec<u64> =
                signers.iter().filter_map(|p| cluster_of(clusters, p)).collect::<HashSet<_>>().into_iter().collect();
            cluster_set.sort_unstable();
            if cluster_set.len() < min_clusters {
                return None;
            }
            let mut signalers: Vec<[u8; 32]> = signers.into_iter().collect();
            signalers.sort_unstable();
            Some(Class3Trigger { cohort_epoch, signalers, clusters: cluster_set })
        })
        .collect();
    triggers.sort_by_key(|t| t.cohort_epoch);
    triggers
}

/// Item-velocity proxy (§6.6 / §7.1a T.8): true when a qualifying cohort's `cohort_epoch` coincides
/// with the epoch of anomalous `trust_total` velocity for a specific item — the correlated L3 signal.
pub fn velocity_correlated(trigger: &Class3Trigger, item_velocity_epoch: u64) -> bool {
    trigger.cohort_epoch == item_velocity_epoch
}

/// Per-node rate limit (§6.6): a node may contribute to triggering at most one Class-3 audit per
/// `n_rewind` epochs.
pub struct RewindRateLimiter {
    n_rewind: u64,
    last: HashMap<[u8; 32], u64>,
}

impl RewindRateLimiter {
    pub fn new(n_rewind: u64) -> Self {
        Self { n_rewind: n_rewind.max(1), last: HashMap::new() }
    }

    /// Whether `peer` may contribute a Class-3 trigger at epoch `t` (no contribution within the last
    /// `n_rewind` epochs). Pure query — does not record.
    pub fn allowed(&self, peer: &[u8; 32], t: u64) -> bool {
        self.last.get(peer).map_or(true, |&last| t >= last + self.n_rewind)
    }

    /// Record that `peer` contributed at epoch `t` (call only after `allowed` returned true).
    pub fn record(&mut self, peer: [u8; 32], t: u64) {
        self.last.insert(peer, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u8) -> Vec<NodeIdentity> {
        (0..n as u64).map(NodeIdentity::from_seed).collect()
    }

    #[test]
    fn snapshot_store_records_evicts_and_rolls_back() {
        let mut store: SnapshotStore<Vec<i32>> = SnapshotStore::new(3);
        store.record(1, vec![1]);
        store.record(2, vec![2]);
        store.record(3, vec![3]);
        store.record(4, vec![4]); // evicts epoch 1
        assert_eq!(store.retained_epochs(), vec![2, 3, 4]);
        assert!(store.get(1).is_none(), "the oldest snapshot was evicted");

        // Re-recording an epoch replaces in place (no growth).
        store.record(4, vec![40]);
        assert_eq!(store.get(4), Some(&vec![40]));
        assert_eq!(store.retained_epochs(), vec![2, 3, 4]);

        // Rollback to epoch 2 returns it and discards the poisoned tail (3, 4).
        let restored = store.rollback(2).expect("epoch 2 retained");
        assert_eq!(restored, vec![2]);
        assert_eq!(store.retained_epochs(), vec![2], "later snapshots discarded on rollback");
        assert!(store.rollback(99).is_none(), "rolling back to an unretained epoch fails");
    }

    #[test]
    fn rewind_signal_signs_verifies_and_checks_ordering() {
        let n = NodeIdentity::from_seed(7);
        let s = RewindSignal::raise(&n, 50, 42, 45);
        assert!(s.verify());
        // Tamper breaks the signature.
        let mut bad = s.clone();
        bad.cohort_epoch = 999;
        assert!(!bad.verify());
        // preferred_t must precede current_t.
        let mut backward = RewindSignal::raise(&n, 50, 42, 45);
        backward.current_t = 40;
        assert!(!backward.verify(), "preferred_t after current_t is malformed");
    }

    #[test]
    fn class3_triggers_only_on_multi_cluster_cohort_correlation() {
        let nodes = ids(6);
        // Clusters: nodes 0,1 → cluster 10; nodes 2,3 → cluster 20; nodes 4,5 → cluster 30.
        let clusters: Vec<([u8; 32], u64)> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.peer_id(), [10u64, 10, 20, 20, 30, 30][i]))
            .collect();

        // Four nodes from clusters 10 & 20 name the SAME cohort_epoch 77 → qualifies (q=3, ≥2 clusters).
        let mut signals: Vec<RewindSignal> =
            (0..4).map(|i| RewindSignal::raise(&nodes[i], 80, 60, 77)).collect();
        let triggers = class3_trigger(&signals, &clusters, 3, 2);
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].cohort_epoch, 77);
        assert_eq!(triggers[0].clusters, vec![10, 20]);

        // Same count but all from ONE cluster → no trigger (no cross-cluster correlation).
        let single: Vec<RewindSignal> = [0usize, 1]
            .iter()
            .flat_map(|_| (0..2).map(|i| RewindSignal::raise(&nodes[i], 80, 60, 88)))
            .collect();
        assert!(class3_trigger(&single, &clusters, 3, 2).is_empty(), "a single cluster cannot trigger");

        // Velocity proxy: the qualifying cohort coincides with an item's velocity epoch.
        assert!(velocity_correlated(&triggers[0], 77));
        assert!(!velocity_correlated(&triggers[0], 78));

        // Distinct signalers required: duplicates from the same node don't reach q.
        signals.push(signals[0].clone());
        let only_two_distinct: Vec<RewindSignal> =
            vec![signals[0].clone(), signals[0].clone(), signals[1].clone()];
        assert!(class3_trigger(&only_two_distinct, &clusters, 3, 2).is_empty(), "duplicates don't inflate the count");
    }

    #[test]
    fn rate_limiter_bounds_contributions_per_window() {
        let mut rl = RewindRateLimiter::new(10);
        let peer = NodeIdentity::from_seed(1).peer_id();
        assert!(rl.allowed(&peer, 100));
        rl.record(peer, 100);
        assert!(!rl.allowed(&peer, 105), "within the window, no second contribution");
        assert!(!rl.allowed(&peer, 109), "still within the window");
        assert!(rl.allowed(&peer, 110), "the window has elapsed");
    }
}
