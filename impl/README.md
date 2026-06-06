# PrivaCF — reference implementation

A runnable, test-backed implementation of pieces of the PrivaCF spec (`../SPEC.md`).
This is a **proof-of-concept**, built bottom-up alongside the PoC phases of §9.2.

## What's implemented

**Experiment E1 — "Does it recommend at all?" (§9.1).** The local, offline
collaborative-filtering core of §3, measured against a popularity baseline on
MovieLens. No crypto, mixnet, or blockchain — those are later phases.

E1 tests the core hypothesis: *item-based CF over accumulated gossip vectors
surfaces long-tail content that a popularity baseline misses.*

**Experiment E2 — "Content discovery under noise per segment" (§9.1).** The two
§4.5 preference-obfuscation modes — *chopping* and *Laplace DP* — applied to the
gossip a node broadcasts, swept across privacy levels, measured per head/long-tail
segment. Gate: long-tail precision ≥ popularity baseline at every operating point.

E2 tests: *how much recommendation quality does in-transit privacy cost, and which
obfuscation mode is gentler?*

**Experiment E3 — "Sybil damage by attack type and SSP scenario" (§9.1).** A Sybil
cohort push-attacks a cold target item (RobuRec shilling profiles: random / average
/ bandwagon / segment) under three placement scenarios (Dense / Distributed /
Sparse), against three defense levels. Gate: damage measurable and bounded.

E3 tests: *can coordinated fake accounts push a target into honest users' feeds, and
do the §7.3 passive damping and §7.4 FoolsGold defenses bound the damage?*

**Experiment E4 — "PSI peer selection and identity rotation" (§9.1).** Blends a
*cluster* trust_total restricted to a node's PSI peer neighbourhood (top-N taste-
overlapping users, §3.4 `β` blend) into discovery, then degrades that neighbourhood
to model unlinkable identity rotation + VRF jitter. Gate: PSI improves precision@K;
rotation degrades it by < 20%.

E4 tests: *does taste-based peer selection actually help recommendation quality, and
does making it privacy-preserving (rotation) stay cheap?*

**Frontier analysis — "do we keep decent recommendations?"** Sweeps the novelty
strength `κ` to trace the accuracy↔discovery tradeoff and locate a *decent*
operating point (overall precision competitive with plain CF / above popularity,
while still surfacing the long tail). This is the §9.2 Phase-4 CF-calibration
question and the §13 accuracy/discovery tension, measured.

**Temporal dynamics — the time-dependent claims the snapshots couldn't test.**
E1–E4 are all single-snapshot; this runs the protocol's *temporal* claims over
epochs: (A) `trust_total` convergence and non-amplification (§7.3 / OQ-15), and (B)
the on-off attack vs the `Δ_rise` reputation-recovery tension (§7.2, §8.2 T1) — which
*is* the deferred Phase-5 experiment 5.4. Faithful reputation update: absence snaps
to `BAND_1`, recovery climbs `+Δ_rise`/epoch, universal `−δ_decay`.

## Layout

```
privacf/
  data.py          MovieLens download/parse, preference mapping, train/test split, head/tail segments
  cf.py            §3 item-based CF: trust_contribution, trust_total, novelty, item_weight, dislikes
  baseline.py      popularity recommender (the thing to beat)
  obfuscate.py     §4.5 in-transit obfuscation: chopping (+cover) and Laplace DP
  attack.py        §7.4 Sybil push profiles (RobuRec) + SSP placement + FoolsGold defense
  metrics.py       Precision@K / Recall@K / NDCG@K / HitRate@K, overall and per segment
  experiment.py    E1 runner + gate check
  experiment_e2.py E2 runner (noise sweep) + gate check
  experiment_e3.py E3 runner (Sybil attack grid + boundedness sweep) + gate check
  experiment_e4.py E4 runner (PSI peer selection + identity rotation) + gate check
  experiment_frontier.py  accuracy<->discovery κ sweep ("is the feed decent?")
  temporal.py      per-epoch reputation dynamics (§7.2 penalty + §6.1 decay) + trust_total
  experiment_temporal.py  Test A: trust_total convergence (OQ-15); Test B: on-off / Δ_rise (first pass)
  experiment_damage.py    damage-coupled on-off attack — the honest exp 5.4 (reputation → E3 push)
  experiment_noveltykill.py  exp 5.47 novelty-kill saboteur (naive attack vs generic surge)
  experiment_killsep.py      exp 5.47 under evasion — attack taxonomy + the coherence fix
tests/
  test_core.py     unit tests: math + obfuscation + attack/defense + PSI peers + temporal (no pytest required)
```

## Run

```bash
cd impl
python3 -m tests.test_core                         # unit tests (no download)
python3 -m privacf.experiment --dataset ml-1m      # full E1 (downloads ~6 MB, cached in data/)
python3 -m privacf.experiment --dataset ml-100k    # fast smoke (~5 s)
python3 -m privacf.experiment_e2 --dataset ml-1m   # E2 noise sweep (chopping vs Laplace)
python3 -m privacf.experiment_e2 --dataset ml-100k --cover  # E2 smoke, chopping pads with cover
python3 -m privacf.experiment_e3 --dataset ml-100k # E3 Sybil attack grid (full 4×3, fast)
python3 -m privacf.experiment_e4 --dataset ml-1m   # E4 PSI peer selection + rotation
python3 -m privacf.experiment_frontier --dataset ml-1m  # accuracy<->discovery κ sweep
python3 -m privacf.experiment_temporal             # temporal: convergence + on-off/Δ_rise (no dataset)
python3 -m privacf.experiment_damage --dataset ml-100k  # damage-coupled on-off (honest exp 5.4)
python3 -m privacf.experiment_noveltykill --dataset ml-100k  # exp 5.47 novelty-kill + separator
```

Useful flags: `--k 10`, `--kappa` (novelty strength §3.7), `--beta` (global/cluster
blend §3.4), `--c-percentile` (DSybil cap), `--strategy temporal|random`,
`--head-frac 0.2`, `--dislike-penalty`. E2 adds `--cover` (chopping pads with cover
items). See `--help` on either runner.

## Spec → code map

| Spec | Quantity | Code |
|---|---|---|
| §3.2 | item-based CF, `sim`, `score = Σ sim·weight` | `cf.ItemCF.fit` / `score_all` |
| §3.4 | `trust_contribution`, `trust_total`, `effective_trust`, `item_weight` | `cf.ItemCF.fit` |
| §3.5 | dislike-aware scoring | `cf.ItemCF.score_all` |
| §3.7 | `novelty`, diversity bonus + passive Sybil damping | `cf.ItemCF.fit` / `score_all` |
| §4.5 | chopping (+cover) / Laplace DP obfuscation | `obfuscate.chop` / `obfuscate.laplace` |
| §7.3 | DSybil cap `c`; novelty as passive Sybil damping | `cf.ItemCF.fit` (`global_tt = min(raw, c)`) |
| §7.4 | FoolsGold-on-PSI-peers Sybil downweighting | `attack.foolsgold` |
| §3.4 / §5.4 | `cluster_trust_total`, `β` blend, PSI peer set | `experiment_e4` (`_user_peer_idx`, per-user boost) |
| §4.2 / §4.5 | identity rotation + VRF jitter (peer churn) | `experiment_e4._rotate` |
| §7.2 / §6.1 | asymmetric penalty, `Δ_rise` recovery, `δ_decay`, temporal depth | `temporal.simulate_reputation` / `trust_total_trajectory` |
| §7.3 / OQ-15 | `trust_total` convergence & non-amplification | `experiment_temporal.test_convergence` |
| §8.2 T1 / exp 5.4 | on-off vs `Δ_rise` (reputation-unit, first pass) | `experiment_temporal.test_onoff_tension` |
| §8.2 T1 / exp 5.4 | on-off vs `Δ_rise` (damage-coupled, honest) | `experiment_damage` (reputation → E3 push) |
| §7.3 / §7.9 row 9 / exp 5.47 | novelty-kill saboteur + FoolsGold separator | `experiment_noveltykill` |
| §9.1 / §9.3 | E1–E4 metrics + gates | `metrics`, `experiment`, `experiment_e2/e3/e4`, `experiment_frontier` |

Preference mapping: ratings are centred (`p = rating − 3`); positive part is the
gossiped "like" weight, negative part is the local dislike magnitude (§3.4/§3.5).

**Performance.** The MovieLens gossip matrices are ~95% sparse, so the heavy matmuls
(item-item similarity, scoring, FoolsGold cosine, PSI user-cosine) use `scipy.sparse`
when available — a ~20× speedup on ml-1m (E1 ~7 s vs ~145 s dense) with numerically
identical results. scipy is optional; without it the code falls back to dense NumPy.

## What E1 shows

- **Popularity** scores **0** on long-tail recall by construction — it can never
  surface tail items.
- **CF (plain item-cosine)** beats popularity overall *and* on the tail.
- **CF (novelty + IDF, the full §3 machinery)** multiplies long-tail discovery
  several-fold over plain CF, at a measured cost to head-item precision — the
  accuracy-vs-discovery tradeoff the novelty bonus (§3.7) exists to make.

The gate (CF beats popularity on long-tail discovery) passes.

## What E2 shows

- **Chopping degrades gracefully.** Dropping transmitted preferences destroys item
  *support* (which items co-occur), so long-tail precision falls roughly linearly
  with the keep fraction — about half the tail precision is lost at 25 % retention.
- **Sign-preserving Laplace is far gentler and flat in ε.** Because the §4.5
  sign-preservation constraint caps noise at `|p_v[i]|` and is zero on inactive
  dimensions, Laplace perturbs only the *magnitudes* of already-active items — item
  support is fully preserved — so CF quality is nearly **independent of ε**: tail
  precision is essentially the same at ε = 0.5 as at ε = 4. Most of Laplace's cost
  is the L1 renormalisation, not the noise (the ε = ∞ "normalise-only" row isolates
  this), and that renormalisation actually *raises* head/overall precision while
  shifting a little weight off the tail.
- The gate (long-tail precision ≥ popularity) holds at **every** tested operating
  point of both modes — privacy does not eliminate long-tail discovery.

The practical reading: **the formal-DP mode is cheap and ε-insensitive for CF
quality (you can crank ε down for a strong guarantee almost for free), while the
niche-friendly chopping mode pays a steady, predictable price that scales with how
much you drop** — a real deployment tradeoff between formal guarantees (Laplace)
and small-anonymity-set friendliness (chopping), now quantified rather than assumed.

## What E3 shows

A Sybil cohort pushing a cold target item into honest feeds, measured as the
target's hit-rate@K among honest users (≈ 0 with no attack):

- **The push is real and measurable, and orders the way theory predicts.**
  *Bandwagon* and *segment* attacks do the most damage (they link the target to
  popular / co-liked items, so it rides into many feeds); *random* does the least.
  Coordination concentration matters: Dense > Distributed > Sparse.
- **Novelty/item_weight is genuine passive Sybil damping (§7.3).** With the full CF
  machinery and *no* explicit Sybil detection, almost every attack collapses to ~0:
  pushing a *cold* item raises its trust, which strips its long-tail boost — the
  push defeats itself. This is the spec's "novelty term as passive Sybil damping"
  claim, demonstrated empirically rather than asserted.
- **FoolsGold (§7.4) is the active backstop.** Coordinated Sybils have near-identical
  contribution vectors and are downweighted to ≈ 0 (ᾱ_sybil ≪ ᾱ_honest), driving
  residual damage to 0 with negligible honest collateral (active-defense P@K ≈ clean).
- **There is no stealthy-and-effective regime.** Where FoolsGold *fails* to flag the
  Sybils (independent random filler → low mutual similarity → ᾱ_sybil ≈ 1), the
  attack already did ~0 damage by construction. To be effective a push must be
  coordinated; to be coordinated is to be detectable.
- **Damage is bounded.** The Sybil-count sweep shows no-defense damage growing
  *sub-linearly* (it saturates), and the defenses hold it near 0 even at 40 % Sybils.

This is the §9.1 E3 gate — *damage measurable and bounded* — met, and it
cross-validates two separate spec mechanisms at once.

## What E4 shows

PSI peer selection (the `β` cluster blend, §3.4) and identity rotation:

- **Taste-based peer selection genuinely improves precision.** Blending in a
  cluster trust_total restricted to a node's top-N taste-overlapping peers lifts
  overall P@K over the global-only baseline (clause 1 of the gate). Personalising
  *which items count as locally novel* is worth real accuracy.
- **Making it privacy-preserving is cheap.** Modelling unlinkable identity rotation
  + VRF jitter as peer-set churn (keep a fraction of true peers, fill the rest with
  random draws) costs **< 20%** precision vs the ideal neighbourhood — clause 2 met.
  The CF degrades gracefully because it leans on the *aggregate* taste of a
  neighbourhood, not on any single irreplaceable peer link.
- **Finding: `β` is a second discovery↔accuracy dial.** Like `κ`, the cluster blend
  trades long-tail recall for precision (locally-popular items lose their novelty
  boost), just via a different route — local-vs-global popularity rather than
  novelty strength. The two knobs navigate the same frontier and should be
  calibrated together (§9.2 Phase 4).

## Do we keep decent recommendations? (frontier)

The synthesis question, answered by sweeping `κ` (ml-100k, popularity floor P@10
0.079 / tail R@10 0.000):

| config | overall P@10 | tail R@10 | read |
|---|---:|---:|---|
| plain CF | 0.118 | 0.019 | best accuracy, weak discovery |
| IDF only (κ=0) | 0.115 | 0.042 | ~2× discovery, nearly free |
| **κ=0.25** | **0.101** | 0.068 | **3.5× discovery, −14% precision, still beats popularity** |
| κ=0.5 | 0.074 | 0.083 | dips below popularity |
| κ=1 (E1/E2 headline) | 0.049 | 0.092 | discovery-maxed, accuracy sacrificed |
| κ=2 | 0.045 | 0.092 | strictly worse — tail plateaus, precision keeps falling |

**Yes — at a sane κ the feed is decent *and* discovers.** The IDF damping is nearly
free; κ≈0.25 keeps ~86% of plain-CF precision (above the popularity floor) for ~3.5×
the long-tail discovery; κ≥1 is the wrong default (the E1/E2 headline reported the
extreme end to *prove the capability*, not a recommended setting). Crucially, tuning
κ down does **not** weaken the Sybil resistance — E3's passive damping is the same
novelty/IDF mechanism and FoolsGold is independent of κ — so the "decent feed" point
and the "Sybil-resistant" point coincide.

**Confirmed at ml-1m scale** (the table above is ml-100k): the κ=0.25 point holds
*cleaner* on the 1M dataset — overall P@10 0.098 (91% of plain CF's 0.107, above the
popularity floor 0.087) with tail R@10 0.024 vs popularity's structural 0.000. E3
(full 4×3 grid) and E4 (PSI +15.3%, rotation no-cost) also pass on ml-1m with the
same shape as ml-100k.

## What the temporal sim shows

Everything above is a single snapshot; these run over epochs.

- **`trust_total` converges and cannot be amplified (§7.3 / OQ-15).** For fixed
  inputs it climbs monotonically to a fixed point at the cap `c` (settled variance
  ~0, no overshoot). Driven by an on-off announcer, it *tracks* the exogenous cycle
  with a peak ratio of 1.00 vs always-on (never exceeds the always-on ceiling) and a
  non-growing oscillation envelope — the empirical counterpart of the spec's
  structural "tracks but cannot amplify" argument.
- **The on-off / `Δ_rise` tension — first pass found a knife-edge, the proper
  experiment showed it was an artifact (exp 5.4).** A first cut measured the on-off
  attack in *reputation* units against an arbitrary "fair line" and found only
  `Δ_rise ≈ 0.5` workable — a knife-edge. That was an artifact of two choices:
  snapping reputation to `BAND_1` on *every* absent epoch (over-punishing honest
  absence) and an arbitrary fairness baseline. The **damage-coupled** version
  (`experiment_damage.py`) fixes both — absence costs only the §6.1 slow decay (the
  `BAND_1` snap is reserved for actual violations), and the adversary's payoff is
  *real recommendation damage* via the E3 push (reputation gates an announcer's
  gossip weight, §3.4). Its findings:
  - **Reputation amplifies the *undefended* push** (target hit-rate 0 → 0.022 as the
    Sybil cohort's score band rises 0.25× → 1.0×), but the §7.3/§7.4 defenses crush
    it to **exactly 0 at every reputation level**.
  - Under faithful slow decay the on-off adversary **keeps near-full reputation and
    push weight down to ~15% activity** (going dark is cheap; only at ~5% does the
    dark gap outrun `Δ_rise` and collapse its reputation). `Δ_rise` thus barely
    constrains it — but it doesn't matter, because the defended damage is **0 at every
    stealth level**.
  - **Conclusion (revises the first pass):** for *recommendation* damage, `Δ_rise`
    calibration is **non-critical** — the defenses bound the push downstream of
    reputation, so the on-off adversary can win the reputation game and still poison
    nothing. `Δ_rise` matters only for what reputation *else* gates (committee /
    validator eligibility), which is outside this PoC. The honest-recovery cost of
    `Δ_rise` shows up only after *long* outages (60-epoch absence: 9 vs 2 epochs at
    `Δ_rise` 0.25 vs 1.0) and never touches the bounded recommendation damage.

  *(This is a worked example of why the damage-coupled version mattered: the cheap
  reputation-unit experiment would have shipped a wrong "calibrate `Δ_rise` to 0.5"
  conclusion.)*

## What 5.47 shows — the novelty-kill separator

The converse of E3: instead of *inflating* a target, the adversary pushes a *niche*
item's trust past its threshold to **kill its novelty bonus** (§3.7), suppressing the
long-tail discovery that would have surfaced it. §7.9.4 flags this (T4, row 9) as the
recommendation contract's weakest point — *"no mechanism distinguishes a coordinated
novelty-suppression push from an organic early-popularity surge ... should become H
once Phase 5 produces a separator."* This experiment **produces that separator**:

- **The attack is real and cheap.** A coordinated cohort of ~20–30 Sybils (≈2–3% of
  users) fully suppresses a niche victim — reach drops to **0** for every victim
  tested (likers 20→67, baseline reach 9→125). With no defense the kill always works.
- **FoolsGold (§7.4) is the separator.** The coordinated kill cohort has near-identical
  contribution vectors → flagged (ᾱ ≈ 0.00); the diverse organic surge is not (ᾱ ≈
  1.00). The gap is structural and held across every victim. So a coordinated kill *is*
  distinguishable from organic popularity by the content-similarity signal — exactly
  what §7.9.4 row 9 asked for. FoolsGold also restores most of the suppressed reach on
  the coordinated push (0 → 16 of 22 for the headline victim).
- **No false intervention on genuine popularity.** FoolsGold leaves the organic surge
  at full weight (ᾱ ≈ 1), so it never "defends" against real popularity.

Two honest caveats: (1) a *one-shot* push that completes before a FoolsGold epoch
evades the content flag — the §7.1a burst/velocity signals cover the timing axis, so
the two are complementary, not redundant; (2) the organic surge *also* drops the
victim's reach in this cosine CF, but that is a separate cosine-normalization artifact
(a newly-popular item's column norm inflates and lowers its similarity), not part of
the separator — FoolsGold correctly does not touch the organic case, which is all the
separator question requires.

**Upshot (first pass — later corrected, see below):** the naive shared-filler kill
*is* flagged by FoolsGold. But this was tested against a generic-diverse "organic
surge", which is not how a real niche surge looks — and the naive attack is not the
attack a real adversary would run. See the evasion analysis next.

## 5.47 under evasion — FoolsGold isn't the fix; coherence is (`experiment_killsep.py`)

Stress-testing the separator against an *evading* adversary and a *realistic* niche
surge overturns the clean "O → H via FoolsGold" claim above. Attack taxonomy (all
announce the victim to kill its novelty; they differ only in the filler disguise):
**A0 naive** (shared filler), **A1 diverse** (independent random filler), **A2 mimic**
(filler drawn from the victim's real neighbourhood N(X)). Two signals: FoolsGold ᾱ
(mutual similarity) and **coherence** (does the cohort share the victim's *pre-existing*
cluster N(X), or only the victim?).

| cohort | victim reach | ᾱ (FoolsGold) | coherence |
|---|---:|---:|---:|
| ORGANIC (realistic niche surge) | 1 | **0.00** | 1.00 |
| A0 naive | 0 | 0.00 | 0.00 |
| A1 diverse | 0 | **1.00** | 0.09 |
| A2 mimic | 1 | 0.00 | 1.00 |

What the data says:
- **FoolsGold is the wrong tool here.** A genuine niche surge *is* a tight cluster, so
  FoolsGold flags it (**false positive**, ᾱ=0.00) — and the diversified kill (A1)
  *evades* it (false negative, ᾱ=1.00). This is precisely why §7.9.4 row 9 was left open.
- **The discriminating property is neighbourhood coherence.** The naive (A0) and
  diverse (A1) kills are "stars" — assembled only to push X, coherence ≈ 0 — and are
  cleanly separated from a genuine surge (coherence ≈ 1). *That* is the fix, and it's a
  new signal, not the existing §7.4 mechanism.
- **Irreducible residual.** An adversary that reconstructs N(X) and emits diverse-yet-
  coherent fans (A2) is, statistically, a genuine niche surge — **no content signal can
  split them**. The defence is non-content: the *cost* of reconstructing the audience +
  per-Sybil admission, and the orthogonal §7.1a admission-burst / trust-velocity
  *timing* signals (a fabricated surge arrives in a tighter window than word-of-mouth).

**Corrected upshot:** T4 (row 9) moves **O → partial**, not a clean H. A coherence
signal handles the realistic naive+diverse novelty-kill; the mimic residual needs the
timing/cost axes. The first-pass "defended by existing §7.4" claim was wrong — testing
the evasion caught it. *(Lesson: the naive-attack-vs-generic-surge test flattered the
defense; the real comparison is evading-attack vs realistic-niche-surge.)*

## Implementation findings worth flagging back to the spec

1. **`item_weight` singularity (§3.4).** `item_weight = 1/log(1 + effective_trust/c)`
   diverges to +∞ as `effective_trust → 0` (cold items), producing `inf·0 → NaN`
   scores. The code regularises the denominator to `log(2 + effective_trust/c)`
   (bounded, still monotone-decreasing). §3.4 should either bound the formula or
   note it is only applied to items with positive trust.
2. **Novelty bonus is a no-op under cosine similarity.** Putting `(1 + κ·novelty)`
   *inside* the gossip matrix `P` has zero effect, because cosine normalises each
   item column independently and cancels the per-column scale. The novelty bonus
   must enter at **ranking time** (as a candidate-item multiplier), not in the
   similarity construction. The spec text is ambiguous about where novelty applies;
   this should be pinned down.

> Both findings above are now reflected in `../SPEC.md` (§3.4 singularity note,
> §3.7 novelty-placement note).

## Not yet implemented

All four §9.1 recommendation-layer experiments (E1–E4) are now built and passing.
What remains is the substrate — the identity / network / blockchain / crypto layers
of §9.2 Phases 1–3 (Poseidon/VDF identity, Loopix transport, BFT chain, ZK proofs,
PSI as actual MPC rather than the in-the-clear quality model used here). Those are a
different class of work (systems + cryptography, not NumPy), out of scope for this
recommendation-quality PoC.
