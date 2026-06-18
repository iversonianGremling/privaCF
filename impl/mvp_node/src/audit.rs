//! Class-2 first-observation audit + burst-score detection (SPEC §4.9.7, §7). VRF-selected observers
//! report when they *first* see a newly-admitted node announce. Correlating those first-observation
//! times exposes **admission-time clustering**: a Sybil cohort that joins together is first-seen in a
//! tight window, giving every cohort member a high **burst score** — a structural signal no single
//! Sybil can avoid (it is about the cohort's joint timing, not any one node's behavior).
//!
//! Observers are VRF-selected (only a node whose VRF lottery for `(subject, beacon)` falls below a
//! threshold may report), so reports are rate-limited and unspoofable; each report is ed25519-signed.
//! The detector takes the consensus (median) first-seen epoch per subject and scores how many other
//! subjects were admitted within a window. This is the substrate signal Phase-2 detection consumes.

use serde::{Deserialize, Serialize};

use crate::identity::{verify as verify_ed25519, NodeIdentity};
use crate::vrf::vrf_verify;

/// The VRF input selecting observers for `subject_epoch_id` at `beacon`.
fn audit_input(subject_epoch_id: u64, beacon: u64) -> Vec<u8> {
    bincode::serialize(&("class2-observe", subject_epoch_id, beacon)).expect("audit input")
}

fn report_msg(observer: &[u8; 32], subject_epoch_id: u64, first_seen_epoch: u64) -> Vec<u8> {
    bincode::serialize(&("first-obs", observer, subject_epoch_id, first_seen_epoch)).expect("report msg")
}

/// A node is a selected observer iff its VRF lottery value is below `threshold` (first 8 bytes as a
/// big-endian u64). A smaller `threshold` ⇒ fewer observers.
pub fn selected(lottery: &[u8; 32], threshold: u64) -> bool {
    u64::from_be_bytes(lottery[..8].try_into().expect("8 bytes")) < threshold
}

/// A VRF-authenticated, signed first-observation report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirstObservation {
    pub observer: [u8; 32],
    pub vrf_pk: [u8; 32],
    pub subject_epoch_id: u64,
    pub first_seen_epoch: u64,
    pub preout: [u8; 32],
    pub proof: Vec<u8>,
    pub lottery: [u8; 32],
    pub sig: Vec<u8>,
}

impl FirstObservation {
    pub fn create(observer: &NodeIdentity, subject_epoch_id: u64, first_seen_epoch: u64, beacon: u64) -> Self {
        let (preout, proof, lottery) = observer.vrf_prove(&audit_input(subject_epoch_id, beacon));
        let sig = observer
            .sign(&report_msg(&observer.peer_id(), subject_epoch_id, first_seen_epoch))
            .to_bytes()
            .to_vec();
        Self {
            observer: observer.peer_id(),
            vrf_pk: observer.vrf_pk(),
            subject_epoch_id,
            first_seen_epoch,
            preout,
            proof: proof.to_vec(),
            lottery,
            sig,
        }
    }

    /// Valid iff the observer was VRF-selected for this subject (proof verifies, lottery < threshold)
    /// AND the report is ed25519-signed by it. (The `vrf_pk ↔ observer` binding is the registry's
    /// job; both are checked here.)
    pub fn verify(&self, beacon: u64, threshold: u64) -> bool {
        let proof: [u8; 64] = match self.proof.as_slice().try_into() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let lottery = match vrf_verify(&self.vrf_pk, &audit_input(self.subject_epoch_id, beacon), &self.preout, &proof) {
            Some(l) => l,
            None => return false,
        };
        if lottery != self.lottery || !selected(&lottery, threshold) {
            return false;
        }
        let sig = match <[u8; 64]>::try_from(self.sig.as_slice()) {
            Ok(s) => ed25519_dalek::Signature::from_bytes(&s),
            Err(_) => return false,
        };
        verify_ed25519(&self.observer, &report_msg(&self.observer, self.subject_epoch_id, self.first_seen_epoch), &sig)
    }
}

/// Consensus first-seen epoch for a subject from its observer reports: the median (robust to a
/// minority of lying observers).
pub fn consensus_first_seen(reports: &[FirstObservation], subject_epoch_id: u64) -> Option<u64> {
    let mut seen: Vec<u64> =
        reports.iter().filter(|r| r.subject_epoch_id == subject_epoch_id).map(|r| r.first_seen_epoch).collect();
    if seen.is_empty() {
        return None;
    }
    seen.sort_unstable();
    Some(seen[seen.len() / 2])
}

/// Burst score for `subject`: how many subjects (including itself) were first-seen within `window`
/// epochs — a measure of admission-time clustering. `first_seen` maps subject → consensus epoch.
pub fn burst_score(first_seen: &std::collections::BTreeMap<u64, u64>, subject: u64, window: u64) -> usize {
    let Some(&e) = first_seen.get(&subject) else { return 0 };
    first_seen.values().filter(|&&o| o.abs_diff(e) <= window).count()
}

/// A subject is flagged as part of a likely Sybil cohort if its burst score meets the threshold.
pub fn is_burst(score: usize, threshold: usize) -> bool {
    score >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn a_selected_observer_report_verifies_and_a_tamper_fails() {
        let observer = NodeIdentity::from_seed(1);
        let beacon = 0xABCD;
        // Use a permissive threshold so the report is "selected" for the test.
        let threshold = u64::MAX;
        let r = FirstObservation::create(&observer, 0xBEEF, 10, beacon);
        assert!(r.verify(beacon, threshold), "an honest selected report verifies");

        // Tampering with the claimed first-seen epoch breaks the signature.
        let mut t = r.clone();
        t.first_seen_epoch = 99;
        assert!(!t.verify(beacon, threshold), "a tampered report is rejected");
        // A different beacon (different selection input) breaks the VRF.
        assert!(!r.verify(beacon ^ 1, threshold), "the report is bound to its beacon");
    }

    #[test]
    fn an_admission_burst_scores_high() {
        // Five subjects admitted together (epoch 10) — a Sybil cohort — plus two isolated joins.
        let mut first_seen = BTreeMap::new();
        for s in 0..5u64 {
            first_seen.insert(1000 + s, 10);
        }
        first_seen.insert(2000, 3); // isolated
        first_seen.insert(2001, 40); // isolated

        for s in 0..5u64 {
            assert_eq!(burst_score(&first_seen, 1000 + s, 1), 5, "cohort member co-admitted with 5");
            assert!(is_burst(burst_score(&first_seen, 1000 + s, 1), 4), "cohort flagged");
        }
        assert_eq!(burst_score(&first_seen, 2000, 1), 1, "an isolated join scores 1");
        assert!(!is_burst(burst_score(&first_seen, 2000, 1), 4), "isolated join not flagged");
    }

    #[test]
    fn consensus_first_seen_is_the_median() {
        let obs: Vec<NodeIdentity> = (0..3).map(NodeIdentity::from_seed).collect();
        let reports: Vec<FirstObservation> = [9u64, 10, 11]
            .iter()
            .zip(&obs)
            .map(|(&e, o)| FirstObservation::create(o, 0xBEEF, e, 1))
            .collect();
        assert_eq!(consensus_first_seen(&reports, 0xBEEF), Some(10), "median first-seen");
        assert_eq!(consensus_first_seen(&reports, 0x1234), None, "no reports for an unknown subject");
    }
}
