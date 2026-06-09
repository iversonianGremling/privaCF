# TODO

Open items from the spec review of 2026-06-09 (v0.3.1, post-`0e8b4fa`). The mechanical
fixes from that review — publish-`s₁` staleness propagation, the §7.4/§8.1 DP
contradiction, the PSI/P2 carve-out (OQ-64) — are already applied. What remains is
judgment or analysis work, not bookkeeping.

## 1. Quantify behavioral-cluster k-anonymity under Loopix

The Loopix fingerprint is two coarse features (`epoch_presence`, `audit_response_rate`,
§6.2), and the committee publishes per-node cluster labels every `n_cluster` epochs. A
node with a stable fingerprint carries the same label across epoch rotations — a
persistent identifier derived from public chain data. §8.1 acknowledges this
qualitatively, but there is no analysis of how identifying the label actually is:
with `k_cluster = O(10)` partitioning a coarse 2D space, the effective anonymity set
could be `O(N/k_cluster)` or much worse in niche communities.

- [ ] Derive (or simulate) effective anonymity-set size as a function of `k_cluster`,
      population size, and honest-node fingerprint distribution
- [ ] State the result against P1 (epoch unlinkability) in §1.7 — either as a bound or
      as an explicit conditional carve-out like the PSI one
- [ ] Candidate mitigations if the number is bad: coarser label publication, label
      noising, or dropping per-node labels under Loopix (lifecycle already feeds only
      the compound flag system there, §6.2)

## 2. Define the bootstrap transition criterion (OQ-12)

§1.7 is explicit that A2 is partly produced by the protocol it secures and that P1–P5
are conditional on the bootstrap mix consortium "until the published transition
criterion is met" — but no concrete criterion exists. The whole stack is conditional on
a threshold nobody can evaluate.

- [ ] Define a measurable criterion (e.g., organic temporal-depth mass × AS-diversity
      floor in the mix-eligible pool) — even a conservative placeholder is better than
      none
- [ ] Consolidate the conditionality discussion, currently spread across §1.7, §2.1,
      and §5.1.1, into one normative location the others reference

## 3. Fix CONFIG E "formal DSybil guarantee: 5/5" (Appendix F)

§7.3 itself says the DSybil rule transfers as "a well-motivated heuristic" — PrivaCF
lacks the persistent social graph and trust-propagation structure the DSybil theorem
requires, and binary ratings (CONFIG E) narrow but do not close the gap (OQ-10, §4.9.5
fallback note). The Appendix F scorecard overstates this as a formal guarantee.

- [ ] Reword the CONFIG E cell to match §7.3's own caveat (e.g., "closest to formal —
      heuristic transfer, OQ-10")
- [ ] Audit the other Appendix F scorecard cells for the same inflation

## 4. Move §14 (Decentralized Learning profile) to a Future Directions appendix

§14 is honest about being "stated, not specified," but it sits inside the normative
section range and adds speculative surface to the implementation-focused core.

- [ ] Relocate to an appendix (or clearly-marked non-normative section); keep the
      FoolsGold-transfer argument, which is genuinely load-bearing for §7.4

## Smaller review residuals

- [ ] **Label detection-contract "B" rows as unvalidated.** The flag-compounding
      argument (§7.1b) rests entirely on unknown `p(flag_i)` constants; until Phase 5
      fills them in, the behavioral-probabilistic rows in §7.9.2 should read "intended,
      empirically unverified" rather than implying derived strength.
- [ ] **Foreground the Statement-5 redesign gate in §9.2 Phase 1.** The exit criterion
      still reads as if Statement 5 e2e verification is a Phase 1 deliverable; the
      P-feasibility benchmark (publish-`s₁` circuit + VerEnc bridge, 0.3–1 M constraint
      AMBER range) is a pre-Phase-1 gate whose bad outcome changes the design (§1.7,
      §10.1.1 V1).
- [ ] **Schedule T8 / VA_pub re-share calibration before Phase 5.** The re-share window
      is the highest-criticality single point of liveness (a failed re-share strands
      `s₂` for every pending `commit_T`, §8.2 T8) but ships in Phase 1 with
      calibration deferred to Phase 5 — pull at least a conservative window/threshold
      analysis forward.
- [ ] **OQ-58 ↔ DKG-load interaction (2-of-2 profile only).** Cover-traffic rate λ and
      committee DKG messages compete for the same mixnet bandwidth; λ needs a lower
      bound if the 2-of-2 profile is ever deployed (ANALYSIS-dkg-load.md §8).
