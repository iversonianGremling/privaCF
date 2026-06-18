//! The deterministic, publicly-checkable verdict trigger — the *objective* branch of SPEC §4.9.6.
//!
//! [`verdict`](crate::verdict) gives the commit-reveal *mechanism* for SUBJECTIVE verdicts, where
//! committee members hold private judgements and must lock them *before* `null_v` is exposed so the
//! key they are about to reveal cannot sway the vote. This module is the complementary OBJECTIVE
//! branch: a verdict every honest validator derives identically from public, finalized chain data.
//!
//! For an objective verdict the commit-reveal is degenerate — there is nothing private to hide and no
//! committee to sway — so the threshold *partial signature* a validator emits over
//! `verdict_id(epoch_id)` IS its SUSPEND vote: a node signs only when its own copy of this
//! deterministic policy flags the on-chain transaction as malformed, and `⌊K/2⌋+1` such partials
//! combine ([`dkg::combine_signatures`](crate::dkg::combine_signatures)) into exactly the
//! `σ_VERDICT` the commit-reveal path would have produced (so dark-node extraction proceeds
//! unchanged, `verdict::extract_null_v`). The autonomous in-loop driver lives in `node.rs`.
//!
//! The objective tell used here is **protocol well-formedness of the published gossip row** (§4.5):
//! the honest pipeline ([`obfuscate::laplace`](crate::obfuscate::laplace), `Clamp`) emits a
//! non-negative row clamped to `[0, B]` and L1-renormalised to `≤ 1`. A row that is negative,
//! non-finite, over the per-entry bound, or not L1-bounded could only come from a node bypassing the
//! honest pipeline to inflate its weight in the CF aggregate (the gross-poisoning case the
//! recommendation capstone defends against downstream) — so it is objectively suspendable, and every
//! validator reading the same finalized transaction reaches the same verdict with no coordination.
//!
//! Scope: this catches *gross* malformedness — the cheap amplification attack. Subtler, in-bounds
//! poisoning (a well-formed row that still skews recommendations) is not a verdict matter; it is
//! bounded at the recommendation layer by FoolsGold + the DSybil cap ([`detection`](crate::detection),
//! [`recommend`](crate::recommend)).

use crate::epoch::PreferencePayload;

/// The public deployment clamp bound `B` for an obfuscated gossip entry. The honest pipeline
/// ([`epoch::PreferencePayload::build`](crate::epoch::PreferencePayload::build)) clamps to `[0, 1]`.
pub const GOSSIP_BOUND: f32 = 1.0;

/// Slack on the L1 bound, absorbing the `f64 → f32` rounding the honest renormalisation incurs. Kept
/// far tighter than any worthwhile amplification: a row inflated past `1 + L1_TOL` is suspendable.
pub const L1_TOL: f32 = 1e-2;

/// Is `gossip` a well-formed obfuscated row? Every entry must be finite, non-negative, and `≤ bound`,
/// and the L1-norm must be `≤ 1 + l1_tol` (the honest pipeline renormalises to `~1`, or to `0` when
/// every active dimension clamps out). Mirrors what `obfuscate::laplace(.., Clamp)` guarantees.
pub fn gossip_wellformed(gossip: &[f32], bound: f32, l1_tol: f32) -> bool {
    let mut l1 = 0.0f32;
    for &x in gossip {
        if !x.is_finite() || x < 0.0 || x > bound {
            return false;
        }
        l1 += x;
    }
    l1 <= 1.0 + l1_tol
}

/// SUSPEND iff the payload's gossip row is malformed under the public bound. A `None` payload (a node
/// that contributes no preference row) is never suspendable on this ground.
pub fn objective_suspend(pref: &Option<PreferencePayload>) -> bool {
    match pref {
        Some(p) => !gossip_wellformed(&p.gossip, GOSSIP_BOUND, L1_TOL),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::PreferencePayload;

    #[test]
    fn the_honest_pipeline_is_always_wellformed() {
        // Rows the real builder emits across a spread of preferences / budgets must all pass.
        for (prefs, eps) in [
            (vec![3i64, 0, 1, 0, 2], 5.0),
            (vec![1, 1, 1, 1, 1], 1.0),
            (vec![0, 0, 0, 0, 0], 5.0),
            (vec![100, 0, 0, 0, 0], 0.5),
        ] {
            let p = PreferencePayload::build(&prefs, &[7u8; 32], 42, eps);
            assert!(
                gossip_wellformed(&p.gossip, GOSSIP_BOUND, L1_TOL),
                "honest gossip {:?} must be well-formed",
                p.gossip
            );
            assert!(!objective_suspend(&Some(p)), "honest payload is not suspendable");
        }
    }

    #[test]
    fn gross_malformedness_is_caught() {
        // Over the per-entry bound (the cheap amplification attack).
        assert!(!gossip_wellformed(&[8.0, 0.0, 0.0], GOSSIP_BOUND, L1_TOL));
        // L1 mass inflation even with in-bound entries.
        assert!(!gossip_wellformed(&[0.9, 0.9, 0.9], GOSSIP_BOUND, L1_TOL));
        // Negative weight.
        assert!(!gossip_wellformed(&[-0.5, 0.5, 0.0], GOSSIP_BOUND, L1_TOL));
        // Non-finite.
        assert!(!gossip_wellformed(&[f32::NAN, 0.0], GOSSIP_BOUND, L1_TOL));
        assert!(!gossip_wellformed(&[f32::INFINITY], GOSSIP_BOUND, L1_TOL));

        // A hand-crafted over-bound payload is suspendable; the all-zero / single-strong rows are not.
        let bad = PreferencePayload { gossip: vec![5.0; 4], c_p: [0; 32], m_v: [0; 32] };
        assert!(objective_suspend(&Some(bad)));
        let strong = PreferencePayload { gossip: vec![1.0, 0.0, 0.0, 0.0], c_p: [0; 32], m_v: [0; 32] };
        assert!(!objective_suspend(&Some(strong)), "a single maxed-out item is well-formed, not malformed");
    }

    #[test]
    fn no_payload_is_never_suspendable_here() {
        assert!(!objective_suspend(&None));
    }
}
