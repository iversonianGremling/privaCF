"""Experiment E3 — "Sybil damage by attack type and SSP scenario" (SPEC.md §9.1).

    All RobuRec types × Dense/Distributed/Sparse SSP.
    Gate: damage measurable and bounded.

A Sybil cohort push-attacks a cold long-tail target item; we measure how often the
target lands in honest users' top-K (the push's payoff) under three defense levels:

  no defense        plain item-cosine CF (kappa=0, no item_weight) — the raw push
  passive (§7.3)    full CF machinery: the novelty/item_weight "passive Sybil
                    damping" — a pushed cold item accrues trust and loses its
                    long-tail boost, so the push partly defeats itself
  active (§7.4)      passive + FoolsGold-on-PSI-peers: coordinated Sybil rows have
                    near-identical contribution vectors and are downweighted to ~0,
                    cutting the co-occurrence inflation at its source

Damage = target hit-rate@K among honest users who have not already seen the target
(baseline ~0 for a cold item). "Bounded" is shown two ways: (a) the defenses drive
realized damage down, hardest on the coordinated Dense scenario; (b) a Sybil-count
sweep shows damage *saturates* rather than growing without limit. Collateral — the
honest recommendation precision — is reported so FoolsGold's false-positive cost on
genuinely similar honest users is visible.

    python -m privacf.experiment_e3 --dataset ml-1m --k 10
"""

from __future__ import annotations

import argparse
import time

import numpy as np

from . import attack
from . import data as data_mod
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate

ATTACKS = ("random", "average", "bandwagon", "segment")
SSPS = ("dense", "distributed", "sparse")


def _measure(gossip, cfg, split, target, k, fg=False):
    """Fit CF on the (optionally FoolsGold-weighted) gossip, return
    (target hit-rate among eligible honest users, honest P@K, sybil/honest alpha)."""
    g = gossip
    alpha = None
    if fg:
        alpha = attack.foolsgold(gossip)
        g = gossip * alpha[:, None]
    cf = ItemCF(cfg).fit(g)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    tk = top_k(scores, k)
    elig = ~split.seen[:, target]
    in_topk = (tk == target).any(axis=1)
    thr = float(in_topk[elig].mean()) if elig.any() else 0.0
    pk = evaluate(tk, split.test_pos, k).precision
    return thr, pk, alpha


def run(dataset="ml-1m", k=10, like_threshold=4.0, test_frac=0.2,
        strategy="temporal", head_frac=0.2, sybil_frac=0.10, n_filler=30,
        target_kind="tail", attacks=ATTACKS, ssps=SSPS,
        sweep_fracs=(0.02, 0.05, 0.10, 0.20, 0.40), data_dir="data", seed=0):
    t0 = time.time()
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, like_threshold=like_threshold,
                                test_frac=test_frac, strategy=strategy, seed=seed)

    plain = CFConfig(kappa=0.0, use_item_weight=False)          # no defense
    full = CFConfig(kappa=1.0, use_item_weight=True)            # passive damping (§7.3)

    target = attack.pick_target(split.pref_pos, split.seen, kind=target_kind,
                                head_frac=head_frac, seed=seed)
    pop = int(split.seen[:, target].sum())
    print(f"[target] item {target} ({target_kind}, {pop} honest likers in train)")

    # --- clean baselines (no injection) ---
    base_thr_plain, base_pk_plain, _ = _measure(split.pref_pos, plain, split, target, k)
    base_thr_full, base_pk_full, _ = _measure(split.pref_pos, full, split, target, k)
    print(f"[clean]  no-injection target hit-rate: plain={base_thr_plain:.4f} "
          f"full={base_thr_full:.4f}  (honest P@{k}: plain={base_pk_plain:.4f} "
          f"full={base_pk_full:.4f})")

    # --- the grid: attack × ssp × defense ---
    print("\n" + "=" * 86)
    print(f"E3 — target hit-rate@{k} among honest users (push payoff; lower = better defense)")
    print(f"     sybil_frac={sybil_frac}  n_filler={n_filler}  target=item {target}")
    print("=" * 86)
    hdr = (f"  {'attack':<10} {'ssp':<12} {'no-def':>8} {'passive':>8} {'active':>8} "
           f"{'P@K act':>8} {'ᾱ sybil':>8} {'ᾱ honest':>9}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    grid = []
    for atk in attacks:
        for ssp in ssps:
            inj = attack.inject(split.pref_pos, split.seen, target, attack=atk,
                                ssp=ssp, sybil_frac=sybil_frac, n_filler=n_filler,
                                seed=seed)
            d0, _, _ = _measure(inj.gossip, plain, split, target, k)
            d1, _, _ = _measure(inj.gossip, full, split, target, k)
            d2, pk2, alpha = _measure(inj.gossip, full, split, target, k, fg=True)
            a_syb = float(alpha[inj.is_sybil].mean())
            a_hon = float(alpha[~inj.is_sybil].mean())
            grid.append((atk, ssp, d0, d1, d2, pk2, a_syb, a_hon))
            print(f"  {atk:<10} {ssp:<12} {d0:>8.4f} {d1:>8.4f} {d2:>8.4f} "
                  f"{pk2:>8.4f} {a_syb:>8.3f} {a_hon:>9.3f}")

    # --- boundedness: damage vs Sybil count (dense bandwagon — the strongest push) ---
    print("\n" + "-" * 86)
    print(f"  Boundedness sweep — dense bandwagon, target hit-rate@{k} vs sybil fraction:")
    print(f"  {'sybil_frac':>10} {'no-def':>8} {'passive':>8} {'active':>8}")
    sweep = []
    for f in sweep_fracs:
        inj = attack.inject(split.pref_pos, split.seen, target, attack="bandwagon",
                            ssp="dense", sybil_frac=f, n_filler=n_filler, seed=seed)
        s0, _, _ = _measure(inj.gossip, plain, split, target, k)
        s1, _, _ = _measure(inj.gossip, full, split, target, k)
        s2, _, _ = _measure(inj.gossip, full, split, target, k, fg=True)
        sweep.append((f, s0, s1, s2))
        print(f"  {f:>10.2f} {s0:>8.4f} {s1:>8.4f} {s2:>8.4f}")

    # --- gate ---
    measurable = any(d0 > base_thr_full + 1e-9 for _, _, d0, _, _, _, _, _ in grid)
    # bounded: active defense reduces damage vs no-defense on average, and the
    # strongest (dense) push saturates — damage at 40% Sybils is not wildly above 10%.
    no_def = np.array([g[2] for g in grid])    # no-defense damage column
    act = np.array([g[4] for g in grid])       # active-defense damage column
    reduced = act.mean() < no_def.mean()
    s_lo = next(s for s in sweep if s[0] == 0.10)
    s_hi = sweep[-1]
    saturates = s_hi[1] <= max(3.0 * s_lo[1], s_lo[1] + 0.05) + 1e-9  # no-def grows sub-linearly
    fg_detects = np.mean([g[6] for g in grid]) < np.mean([g[7] for g in grid])  # ᾱ_sybil < ᾱ_honest

    passed = measurable and reduced and saturates
    print("\n" + "=" * 86)
    print(f"  damage measurable (push beats clean baseline)        : {measurable}")
    print(f"  active defense reduces mean damage vs no-defense     : {reduced}  "
          f"(no-def {no_def.mean():.4f} -> active {act.mean():.4f})")
    print(f"  dense push saturates with Sybil count (bounded)      : {saturates}  "
          f"(frac .10 -> .40 no-def: {s_lo[1]:.4f} -> {s_hi[1]:.4f})")
    print(f"  FoolsGold separates Sybils (ᾱ_sybil < ᾱ_honest)       : {fg_detects}  "
          f"({np.mean([g[6] for g in grid]):.3f} < {np.mean([g[7] for g in grid]):.3f})")
    print(f"  RESULT = {'PASS ✅' if passed else 'FAIL ❌'}  (damage measurable and bounded)")
    print("=" * 86)
    print(f"[done] {time.time() - t0:.1f}s")
    return passed, grid, sweep


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF Experiment E3 (Sybil damage)")
    ap.add_argument("--dataset", default="ml-1m", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--sybil-frac", type=float, default=0.10)
    ap.add_argument("--n-filler", type=int, default=30)
    ap.add_argument("--target-kind", default="tail", choices=["tail", "head"])
    ap.add_argument("--strategy", default="temporal", choices=["temporal", "random"])
    ap.add_argument("--head-frac", type=float, default=0.2)
    ap.add_argument("--attacks", nargs="+", default=list(ATTACKS), choices=list(ATTACKS))
    ap.add_argument("--ssps", nargs="+", default=list(SSPS), choices=list(SSPS))
    ap.add_argument("--sweep-fracs", nargs="+", type=float,
                    default=[0.02, 0.05, 0.10, 0.20, 0.40])
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    passed, _, _ = run(dataset=a.dataset, k=a.k, sybil_frac=a.sybil_frac,
                       n_filler=a.n_filler, target_kind=a.target_kind,
                       strategy=a.strategy, head_frac=a.head_frac,
                       attacks=tuple(a.attacks), ssps=tuple(a.ssps),
                       sweep_fracs=tuple(a.sweep_fracs),
                       data_dir=a.data_dir, seed=a.seed)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
