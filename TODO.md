# TODO

Open items from the spec review of 2026-06-09 (v0.3.1, post-`0e8b4fa`). The mechanical
fixes from that review — publish-`s₁` staleness propagation, the §7.4/§8.1 DP
contradiction, the PSI/P2 carve-out (OQ-64) — are already applied. What remains is
judgment or analysis work, not bookkeeping.

> **Status (applied 2026-06-09):** all four items and all four smaller residuals below
> are now applied to `SPEC.md`. The analysis work is at "derived analytically, calibration
> deferred to Phase 5" level (new OQ-65; expanded OQ-12) — see per-item notes.

## 1. Quantify behavioral-cluster k-anonymity under Loopix

The Loopix fingerprint is two coarse features (`epoch_presence`, `audit_response_rate`,
§6.2), and the committee publishes per-node cluster labels every `n_cluster` epochs. A
node with a stable fingerprint carries the same label across epoch rotations — a
persistent identifier derived from public chain data. §8.1 acknowledges this
qualitatively, but there is no analysis of how identifying the label actually is:
with `k_cluster = O(10)` partitioning a coarse 2D space, the effective anonymity set
could be `O(N/k_cluster)` or much worse in niche communities.

- [x] Derive (or simulate) effective anonymity-set size as a function of `k_cluster`,
      population size, and honest-node fingerprint distribution — **done in new §6.2.1**:
      `A_eff = min(k_cluster occupancy, raw-fingerprint cell count)`, uniform vs. skewed
      regimes, tail-collapse to `O(1)–O(10)`, community-size dependence, intrinsic ceiling
      from the publicly-recomputable raw fingerprint. Per-config numeric simulation is the
      remaining Phase-5 residual.
- [x] State the result against P1 (epoch unlinkability) in §1.7 — **done**: added the
      `ε_cluster(v,T,k,Π)` term to the P1 advantage bound plus a scope carve-out paragraph
      paralleling the PSI/P2 one; updated the "does not yet bound" list and §8.1 bullet.
- [x] Candidate mitigations — **done in §6.2.1**: (1) `k_floor` publication, (2) coarser
      `k_cluster`, (3) drop per-node labels / ZK predicates, (4) source-side fingerprint
      coarsening (the only lever that raises the intrinsic ceiling). Tracked as **OQ-65**
      (added to the §10.1 table and the V1 calibration list).

## 2. Define the bootstrap transition criterion (OQ-12)

§1.7 is explicit that A2 is partly produced by the protocol it secures and that P1–P5
are conditional on the bootstrap mix consortium "until the published transition
criterion is met" — but no concrete criterion exists. The whole stack is conditional on
a threshold nobody can evaluate.

- [x] Define a measurable criterion — **done in §5.1.1** as the normative
      `TRANSITION_READY` predicate: (a) consortium-redundancy
      `W_cons/(W_org+W_cons) ≤ f_Loopix`, (b) AS-diversity floor, (c) pool-size floor,
      held over `W_transition` epochs, all publicly recomputable. Shape pinned; constants
      are the empirical residual of OQ-12.
- [x] Consolidate the conditionality — **done**: §5.1.1 is now the single normative home;
      §1.7 (already) and §2.1 (updated) reference it; the OQ-12 table row restates the
      defined predicate.

## 3. Fix CONFIG E "formal DSybil guarantee: 5/5" (Appendix F)

§7.3 itself says the DSybil rule transfers as "a well-motivated heuristic" — PrivaCF
lacks the persistent social graph and trust-propagation structure the DSybil theorem
requires, and binary ratings (CONFIG E) narrow but do not close the gap (OQ-10, §4.9.5
fallback note). The Appendix F scorecard overstates this as a formal guarantee.

- [x] Reword the CONFIG E cell — **done**: row renamed "DSybil non-overwhelm.¹"
      (heuristic, OQ-10), scores rescaled and **capped below "formal" (max 3)**: E 5→3,
      D 4→2; config-E header retitled "strongest DSybil transfer — heuristic, OQ-10";
      footnote added explaining the cap.
- [x] Audit other cells — **done**: "Formal DP guarantee" D=4 is genuinely formal
      (clean ε-DP post-clamp, §1.7 P2) and left as-is; "Suspension persistence" 5/5 is
      cryptographic (P3); remaining rows are qualitative preference scores, not guarantee
      claims. Only the DSybil row was inflated.

## 4. Move §14 (Decentralized Learning profile) to a Future Directions appendix

§14 is honest about being "stated, not specified," but it sits inside the normative
section range and adds speculative surface to the implementation-focused core.

- [x] Relocate — **done**: §14 became **Appendix J — Future Directions: Decentralized
      Learning Profile** (non-normative banner, subsections J.1–J.4), physically moved to
      after Appendix I; TOC updated. The FoolsGold-transfer argument (load-bearing for
      §7.4) is preserved verbatim in J.1.

## Smaller review residuals

- [x] **Label detection-contract "B" rows as unvalidated.** — **done**: the §7.9.1
      B-level definition now reads "intended, empirically unverified until Phase 5" and
      states the strength rests on the uncalibrated `p(flag_i | S)` of §7.1b; §7.9.5 adds
      that all B/H/PARTIAL rows are unvalidated until their Phase-5 experiments run (only
      C rows hold independently).
- [x] **Foreground the Statement-5 redesign gate in §9.2 Phase 1.** — **done**: added a
      "Pre-Phase-1 feasibility gate" callout at the top of Phase 1 (AMBER→RED as specified,
      restructured publish-`s₁` circuit is the build target, bad answer = design change)
      and tied the exit-criterion clause to it.
- [x] **Schedule T8 / VA_pub re-share calibration before Phase 5.** — **done**: §8.2 T8
      now requires a conservative window/threshold analysis pulled forward to the Phase-1
      build-parameter step (the `VA_pub` half of OQ-50), with Phase 5 only refining it.
- [x] **OQ-58 ↔ DKG-load interaction (2-of-2 profile only).** — **done**: OQ-58 table row
      now notes the deployment-conditional joint constraint — under 2-of-2, λ must satisfy
      both the anonymity lower bound and the DKG-throughput lower bound
      (ANALYSIS-dkg-load.md §8); does not arise in the default publish-`s₁` profile.
