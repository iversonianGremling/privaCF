# Analysis — OQ-63: per-epoch committee-DKG load

### Second "bad answer = design change" item · run in parallel with the Statement-5 spike

> **Why this exists.** Audit committees are VRF-selected **per node** (`committee_T^{(i)} =
> VRF(… ‖ epoch_id_v ‖ i)`, §4.9.4) and `commit_T` is published **every epoch** by every active
> node, so each node's `N_fallback` committee threshold keys must be DKG'd every epoch for the
> `s₁` encryption to exist. The earlier framing ("O(N) DKGs per epoch") is true network-wide but
> misleading about where the pain is. This note does the analysis closed-form, locates the real
> bottleneck, and states the mitigation + its (now-cheap) security cost. Unlike the Statement-5
> spike this needs no code to reach a verdict — it's analytic, with a small sim only to confirm.

---

## 1. Counts (closed form)

Let `N` = active nodes, `E` = committee-eligible nodes (`E ≤ N`; eligibility = temporal-depth +
reputation + cluster-diversity floors, §4.1), `K = K_committee`, `F = N_fallback`.

```
committees per epoch (network)      = N · F
committee seats per epoch (network) = N · F · K
DKG instances per epoch (network)   = N · F                         ← the "O(N)" term
memberships per ELIGIBLE node       = (N · F · K) / E = (N/E) · F · K
```

With the v1 defaults `F = 3`, `K = 21`:

```
per-eligible-node committee memberships / epoch  = (N/E) · 63
per-eligible-node DKG messages / epoch           ≈ (N/E) · F · K²  ≈ (N/E) · 1323
   (each DKG: ~K messages per member — one share to each peer + a broadcast commitment)
```

---

## 2. The correction that reframes OQ-63

**Per-node load is `O(1)` in network size `N`, not `O(N)`.** If every node is eligible (`E = N`)
each node sits on `F·K = 63` committees per epoch *regardless of whether `N` is 10³ or 10⁶* — the
network total grows with `N`, but it's distributed, so the per-node constant is what matters and
it doesn't grow with scale. So this is **not** a scaling cliff in the usual sense.

The two things that *do* bite:

1. **Concentration on the eligible pool, factor `N/E`.** Committees draw only from eligible
   nodes, so the 63-per-node load is multiplied by `N/E`. If only 10 % of active nodes are
   eligible, eligible nodes carry `630` committee memberships/epoch — and those are exactly the
   valuable, long-lived, high-reputation nodes you least want to overload. **`N/E` is the real
   load knob, not `N`.**
2. **Latency/liveness of concurrent DKGs over the mixnet.** Each DKG is a multi-round protocol;
   over Loopix (Poisson per-hop delays, multi-hop, cover traffic) every round is a high-latency
   mixnet round-trip. Running `(N/E)·63` *concurrent* multi-round DKGs and having **all** of them
   complete before the `commit_T` submission deadline (the §4.1 "DKG timing constraint") is the
   binding constraint.

---

## 3. Where the cost actually lands

| Resource | Per-eligible-node, `F=3,K=21`, `E=N` | Verdict |
|---|---|---|
| **Compute** | 63 DKGs × ~O(K)–O(K²) EC ops ≈ 10³–10⁴ BLS12-381 ops ≈ **~1–6 s/epoch** | **Not the bottleneck** — trivial vs. a 2–3 h epoch. |
| **Raw bandwidth** | ~1323 messages × ~1 KB (Sphinx frame) ≈ **~1.3 MB/epoch** ≈ ~0.1–0.2 KB/s avg | Modest in bytes; non-trivial on metered/mobile when `N/E` is large. |
| **Message count** | **~1323 discrete mixnet sends/epoch** (× `N/E`) | Significant — cover-traffic budget (OQ-58) and provider buffering pressure. |
| **Latency / liveness** | ~63 concurrent multi-round DKGs, all due before the `commit_T` deadline | **The binding constraint.** A high-latency mixnet + a sub-epoch window is the failure mode. |

So OQ-63 is really a **liveness-under-latency** question concentrated on the **eligible pool by
factor `N/E`**, not a compute or raw-bandwidth blowup.

---

## 4. Mitigation spectrum (and why sharing is now security-cheap)

The dial is *how many nodes share a DKG'd committee key*. A single committee threshold key can be
the IBE master key for **many** nodes at once — the per-node IBE *identity* string
(`"SUSPEND epoch_id_v_T"`) differentiates them, so one DKG can serve a whole cohort.

| Option | DKG instances / epoch | Per-eligible-node load | Independence / blast radius |
|---|---|---|---|
| **A. Per-node committees** (as specified) | `N · F` | `(N/E)·F·K` | Max independence; a committee compromise touches 1 node. |
| **B. Per-cohort shared committees** (recommended) | `(#cohorts) · F` | `(#cohorts/E)·F·K` | Tunable; a committee compromise touches one cohort. |
| **C. Single network committee** | `F` (O(1) in N) | `F·K/E` | Min cost; one committee audits everyone — defeats per-node-independent auditing. |

**The 2-of-2 split (P4) makes B/C far more palatable than they would have been.** A committee
compromise now yields only the share `s₁`, which is **information-theoretically independent of
`null_v`** (SECURITY.md §P4.1) — recovering any node's `null_v` *still* requires the per-node,
per-verdict validator attestation `σ_T^VERDICT`. So sharing a committee across a cohort does
**not** create a cohort-wide deanonymization oracle; it creates at most a cohort-wide `s₁`-leak,
which is harmless without the validator half. The forward-secrecy fix and this cost-saving
mitigation are complementary: **the split is exactly what lets you amortize the DKG by sharing
committees without widening the privacy blast radius.**

Cohort size is then a clean dial: bigger cohorts → fewer DKGs → cheaper, at the cost of coarser
auditor independence (the §4.9.8 Chernoff/diversity argument still wants enough distinct
committees that an adversary can't sit astride all of a cohort's audits). The recommended path is
**B with cohort size chosen so per-eligible-node DKG count fits the window with margin**, keeping
per-node selection only where independence is most needed (e.g., elevated-alert nodes).

---

## 5. Verdict criteria (go / no-go for the per-node model)

The decision is which row of §4 to ship, gated on whether option **A** survives at the target
`(N/E)` and mixnet latency:

| Tier | Condition | Decision |
|---|---|---|
| **GREEN** | At target `N/E`, the `(N/E)·63` concurrent DKGs complete within the DKG window with comfortable margin (sim-confirmed). | Keep per-node committees (A). |
| **AMBER** | Fits only when `N/E` is small (most nodes eligible) / margin is thin. | Keep A but cap `N/E` via eligibility tuning, or pre-emptively move elevated load to B. |
| **RED** | Concurrent-DKG liveness over the mixnet can't be guaranteed in the window, or `N/E` concentration is prohibitive. | Switch to **B (per-cohort shared committees)**; tune cohort size. The 2-of-2 split keeps this security-cheap (§4). |

Given the latency analysis, **B is the likely landing spot** — but the verdict should come from
the §6 measurement, not assumption.

---

## 6. What to measure (analytic first, then a small sim)

1. **Analytic (now):** plug the deployment's expected `(N, E, K, F)` into §1 to get per-eligible
   load; compare DKG message-count and rounds against the per-node mixnet message budget (ties to
   OQ-58 cover rate `λ` and the §4.1 DKG window length).
2. **Small sim (confirm):** simulate `m` concurrent Pedersen/Feldman DKGs among `K`-node groups
   over a model Loopix latency distribution (Poisson per-hop × hop count); measure the
   completion-time distribution and the fraction of DKGs missing a window of length `W_dkg`.
   Sweep `m ∈ {21, 63, 315}` (i.e. `N/E ∈ {⅓,1,5}`) and `W_dkg` as a fraction of the epoch.
3. **Output:** a per-eligible-node load table + the completion-within-window curve, and a
   GREEN/AMBER/RED verdict with, if not GREEN, a recommended cohort size for option B.

**Effort:** the analytic pass is an afternoon; the sim a couple of days (no cryptography needed —
model DKG as `R` mixnet rounds among `K` parties; the EC work is confirmed negligible in §3).

---

## 7. Relationship to the rest

- This is the **second** "bad answer changes the design" item alongside the Statement-5 spike
  ([SPIKE-statement5.md](./SPIKE-statement5.md)); run both before committing to the Layer-1–4
  build. Neither needs the substrate to exist.
- It interacts with **OQ-58** (mixnet cover rate `λ` sets the per-message latency and the
  bandwidth budget the DKG traffic competes for) and with the **§4.1 DKG timing constraint** (the
  window `W_dkg`).
- A move to option B is a **localized** design change (committee-selection granularity), not a
  protocol redesign — the IBE/ForwardCommit machinery, Statement 5, and the 2-of-2 split are all
  unchanged; only "how many nodes share a committee key" moves.

---

## 8. Sim result (2026-06-06)

Ran `impl/spike_dkg_liveness.py` (`K=21, F=3, R=3, H=3` hops, `d_hop=5 s`, `W_dkg = 20%` of a
3 h epoch = 36 min). Verdict per cell = `max(throughput-time, latency-floor)` vs the window.

| N/E | λ_send | V_out | send-time | latency-floor | binding | vs W | verdict |
|---:|---:|---:|---:|---:|---:|---:|:--|
| 1 | 1/s | 3 969 | 66.2 m | 2.7 m | 66.2 m | 1.84× | **RED** |
| 1 | 2/s | 3 969 | 33.1 m | 2.7 m | 33.1 m | 0.92× | AMBER |
| 1 | 5/s | 3 969 | 13.2 m | 2.7 m | 13.2 m | 0.37× | GREEN |
| 3 | 5/s | 11 907 | 39.7 m | 2.7 m | 39.7 m | 1.10× | **RED** |
| 5 | 5/s | 19 845 | 66.2 m | 2.7 m | 66.2 m | 1.84× | **RED** |
| 10 | 5/s | 39 690 | 132 m | 2.7 m | 132 m | 3.67× | **RED** |

**Findings:**
1. **Latency is *not* the wall.** One DKG's `R` rounds finish in ~2.7 min — far inside a 36-min
   window even at a 5 s/hop mix delay. Mixnet *delay* is a non-issue.
2. **Throughput is the wall.** The binding term is *time to push `V_out = (N/E)·F·K²·R` messages
   through the fixed-rate Loopix sender*. Per-node out-volume is large (≈ 4 k messages/epoch even
   at `N/E = 1`), so the required sustained send rate (1.8 → 18 msg/s as `N/E` goes 1 → 10) quickly
   exceeds any plausible anonymity cover rate `λ_send`. This couples directly to **OQ-58** — you
   can't just crank `λ_send` to clear DKG without spending bandwidth/anonymity budget.
3. **Per-node committees (option A) are RED** at any realistic concentration (`N/E ≥ 3`) or modest
   send rate. Only the everyone-eligible + high-send-rate corner is GREEN.
4. **Per-cohort sharing (option B) fixes it cleanly.** Cohort size `g` divides `V_out` by ~`g`:
   at `N/E = 5`, `g = 5` → 1.8 msg/s, `g = 20` → 0.5 msg/s — comfortably GREEN. And the 2-of-2
   split (P4) makes sharing security-cheap (a shared-committee compromise yields only `s₁ ⟂ null_v`).

**Verdict: RED for the per-node committee model as specified → adopt option B (per-cohort shared
committees), cohort size `g ≈ 5–20` the dial.** This is the localized design change anticipated in
§4; nothing else in the IBE/ForwardCommit/Statement-5 machinery moves.

### 8.1 Privacy implications and drawbacks of option B

**Privacy — largely contained, one hard requirement.**
- The blast-radius worry (compromise one committee → expose `g` nodes, not 1) is **neutralized for
  *privacy* by the 2-of-2 split**: a committee compromise yields only `s₁ ⟂ null_v`, useless without
  each node's separate validator attestation `s₂`. You get `g` useless shares, not `g`
  deanonymizations. What rises is only the *yield of a combined* committee+validator break (a whole
  cohort at once) — but that already requires an A2-level validator-threshold break, so it's marginal.
- **Hard requirement:** cohort assignment MUST be derived from the **rotating `epoch_id`/beacon**,
  never from a stable per-node value and never from the interest/behavioral cluster. Otherwise cohort
  co-membership becomes a **cross-epoch linkage** signal (eroding P1) or a **cluster-membership leak**.
  Bucket on the rotating pseudonym and this is a non-issue.

**Non-privacy drawbacks (the real costs):**
- **Auditor independence drops by ~`g`.** Sharing means `g×` fewer *distinct* committees, weakening
  the §4.9.8 Chernoff/diversity argument — an adversary covers proportionally more of the (fewer)
  committees. Compensate by raising `K_committee` (ties to the `q_eff` scaffold, SECURITY.md). This
  is the genuine price: option B trades **DKG cost ↔ auditor-independence granularity**.
- **Correlated liveness failure.** A cohort's stalled committee blocks that slot for all `g` members
  at once (the `N_fallback` slots still cover it, but the failure is now correlated, not isolated).
- **Cohort-committee predictability.** A more stable cohort grouping could let a patient adversary
  pre-position within a cohort's committee; per-epoch VRF rotation mitigates but watch cohort churn.

Net: option B is sound and privacy-safe given the rotating-bucket requirement; the calibration
knob is `g` against `K_committee` (independence) and the correlated-liveness margin.

**Modeling caveats (honest).** `V_out` uses a conservative `K·R` messages per committee membership
(one share/broadcast round-set × `R` rounds); an optimistic count (dominant share round only, ≈`K`)
divides `V_out` by ~`R` and softens the numbers — but the conclusion holds across that range:
per-node committees strain a fixed-rate mixnet at concentration, and cohort-sharing is the fix. The
sim models send-throughput and round-latency; it does not model per-message queueing interactions,
which would only *worsen* option A. `λ_send` values and `d_hop` are placeholders pending OQ-58.
