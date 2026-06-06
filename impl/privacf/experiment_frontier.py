"""Accuracy <-> discovery frontier — "do we keep decent recommendations?"

E1/E2/E3 each measured one slice. This sweeps the novelty strength kappa (§3.7)
and the IDF item_weight (§3.4) to trace the tradeoff the full PrivaCF machinery
makes: head/overall precision vs long-tail discovery. It answers the synthesis
question — is there an operating point that keeps a *decent* feed (overall
precision competitive with plain CF / above popularity) while still surfacing the
long tail that popularity structurally cannot?

This is the §9.2 Phase-4 "CF and Noise Calibration" question, and the practical
choice §13 frames as the accuracy/discovery tension.

    python -m privacf.experiment_frontier --dataset ml-1m --k 10
"""

from __future__ import annotations

import argparse
import time

import numpy as np

from . import data as data_mod
from .baseline import Popularity
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate


def _row(split, cfg, k, is_head, is_tail):
    cf = ItemCF(cfg).fit(split.pref_pos)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    tk = top_k(scores, k)
    ov = evaluate(tk, split.test_pos, k)
    hd = evaluate(tk, split.test_pos, k, item_subset=is_head)
    tl = evaluate(tk, split.test_pos, k, item_subset=is_tail)
    return ov, hd, tl


def run(dataset="ml-1m", k=10, like_threshold=4.0, test_frac=0.2,
        strategy="temporal", head_frac=0.2,
        kappas=(0.0, 0.25, 0.5, 1.0, 2.0), data_dir="data", seed=0):
    t0 = time.time()
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, like_threshold=like_threshold,
                                test_frac=test_frac, strategy=strategy, seed=seed)
    is_head, is_tail, _ = data_mod.popularity_segments(split.seen, head_frac)

    # popularity reference floor
    pop_tk = top_k(Popularity().fit(split.seen).score_all(split.seen), k)
    pop_ov = evaluate(pop_tk, split.test_pos, k)
    pop_tl = evaluate(pop_tk, split.test_pos, k, item_subset=is_tail)
    pop_p = pop_ov.precision

    print("\n" + "=" * 80)
    print(f"Accuracy <-> discovery frontier (k={k})")
    print("  'decent' = overall P@K not far below plain CF, AND tail R@K > 0 "
          "(popularity can't)")
    print("=" * 80)
    print(f"  reference  popularity        : overall P@{k}={pop_p:.4f}  "
          f"tail R@{k}={pop_tl.recall:.4f}")
    hdr = (f"  {'config':<22} {'overall P':>10} {'head P':>8} {'tail R':>8} "
           f"{'tail HR':>8}  {'vs pop':>7}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    rows = []
    # plain CF (kappa irrelevant, no item_weight) — the head-accuracy ceiling
    ov, hd, tl = _row(split, CFConfig(kappa=0.0, use_item_weight=False), k, is_head, is_tail)
    rows.append(("plain CF (no novelty/IDF)", ov, hd, tl, 0.0, False))

    # the frontier: novelty strength kappa, with IDF on (the discovery machinery)
    for kp in kappas:
        ov, hd, tl = _row(split, CFConfig(kappa=kp, use_item_weight=True),
                          k, is_head, is_tail)
        rows.append((f"novelty+IDF  κ={kp:g}", ov, hd, tl, kp, True))

    for label, ov, hd, tl, kp, idf in rows:
        rel = ov.precision / pop_p if pop_p > 0 else float("inf")
        mark = "≥pop" if ov.precision >= pop_p else f"{rel:.2f}×"
        print(f"  {label:<22} {ov.precision:>10.4f} {hd.precision:>8.4f} "
              f"{tl.recall:>8.4f} {tl.hit_rate:>8.4f}  {mark:>7}")

    # pick a "decent" operating point: highest tail recall among configs whose
    # overall precision is within 'decent_band' of plain CF AND beats popularity.
    plain_p = rows[0][1].precision
    decent_band = 0.80   # keep at least 80% of plain-CF overall precision
    candidates = [r for r in rows[1:]
                  if r[1].precision >= max(decent_band * plain_p, pop_p)]
    print("  " + "-" * (len(hdr) - 2))
    if candidates:
        best = max(candidates, key=lambda r: r[3].recall)
        tail_cmp = ("∞ — popularity surfaces no tail" if pop_tl.recall <= 0
                    else f"{best[3].recall / pop_tl.recall:.0f}× popularity's tail")
        print(f"  DECENT operating point: {best[0]}  — overall P@{k}={best[1].precision:.4f} "
              f"(≥{decent_band:.0%} of plain {plain_p:.4f} and ≥pop {pop_p:.4f}), "
              f"tail R@{k}={best[3].recall:.4f} ({tail_cmp})")
        verdict = True
    else:
        print(f"  No config keeps ≥{decent_band:.0%} of plain-CF precision while beating "
              f"popularity — accuracy/discovery tension is hard here; tune κ to taste.")
        verdict = False
    print(f"  (κ=0 with IDF on isolates the IDF damping; κ raises long-tail weight at "
          f"a head-precision cost.)")
    print("=" * 80)
    print(f"[done] {time.time() - t0:.1f}s")
    return verdict, rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF accuracy/discovery frontier")
    ap.add_argument("--dataset", default="ml-1m", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--strategy", default="temporal", choices=["temporal", "random"])
    ap.add_argument("--head-frac", type=float, default=0.2)
    ap.add_argument("--kappas", nargs="+", type=float, default=[0.0, 0.25, 0.5, 1.0, 2.0])
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    run(dataset=a.dataset, k=a.k, strategy=a.strategy, head_frac=a.head_frac,
        kappas=tuple(a.kappas), data_dir=a.data_dir, seed=a.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
