"""Experiment E2 — "Content discovery under noise per segment" (SPEC.md §9.1).

    Chopping vs. Laplace across head / long-tail.
    Gate: long-tail precision >= popularity baseline.

Faithful split (§4.5): obfuscation applies to the *gossip* matrix a node
broadcasts (which builds the item-item similarity and trust totals), while each
node scores from its own *clean local* preference vector. So we fit() on the
obfuscated matrix and score_all() on the clean one.

Sweeps the privacy parameter for each mode and reports per-segment Precision@K /
Recall@K, the degradation vs the clean E1 ceiling, and the §9.1 gate at every
operating point. Popularity scores 0 on the long-tail by construction, so the
gate reduces to: does CF still surface *any* correct long-tail item under noise?

    python -m privacf.experiment_e2 --dataset ml-1m --k 10
"""

from __future__ import annotations

import argparse
import time

import numpy as np

from . import data as data_mod
from . import obfuscate
from .baseline import Popularity
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate


def _eval_cf(gossip, split, cfg, k, is_head, is_tail):
    """Fit CF on an (obfuscated) gossip matrix, score from clean local vectors."""
    cf = ItemCF(cfg).fit(gossip)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    tk = top_k(scores, k)
    return (evaluate(tk, split.test_pos, k),
            evaluate(tk, split.test_pos, k, item_subset=is_head),
            evaluate(tk, split.test_pos, k, item_subset=is_tail))


def run(dataset="ml-1m", k=10, like_threshold=4.0, test_frac=0.2,
        strategy="temporal", head_frac=0.2, kappa=1.0, beta=1.0,
        c_percentile=90.0, dislike_penalty=1.0, cover=False,
        chop_fracs=(1.0, 0.75, 0.5, 0.25),
        epsilons=(float("inf"), 4.0, 1.0, 0.5),
        data_dir="data", seed=0):
    t0 = time.time()
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, like_threshold=like_threshold,
                                test_frac=test_frac, strategy=strategy, seed=seed)
    is_head, is_tail, pop = data_mod.popularity_segments(split.seen, head_frac)
    print(f"[segments] head={int(is_head.sum())} items, "
          f"tail={int(is_tail.sum())} items (head_frac={head_frac})")

    cfg = CFConfig(kappa=kappa, beta=beta, c_percentile=c_percentile,
                   use_item_weight=True, dislike_penalty=dislike_penalty)

    # --- reference floor: popularity ---
    pop_model = Popularity().fit(split.seen)
    pop_tk = top_k(pop_model.score_all(split.seen), k)
    pop_all = evaluate(pop_tk, split.test_pos, k)
    pop_tail = evaluate(pop_tk, split.test_pos, k, item_subset=is_tail)

    # --- reference ceiling: clean CF (= E1) ---
    clean = _eval_cf(split.pref_pos, split, cfg, k, is_head, is_tail)
    cf_clean = ItemCF(cfg).fit(split.pref_pos)   # for cover padding's trust_total
    trust_total = cf_clean.effective_trust

    rows = []  # (label, overall, head, tail, passed)

    def _record(label, res):
        ov, hd, tl = res
        passed = tl.precision >= pop_tail.precision and tl.precision > 0
        rows.append((label, ov, hd, tl, passed))

    rows.append(("popularity", pop_all, evaluate(pop_tk, split.test_pos, k, item_subset=is_head),
                 pop_tail, pop_tail.precision > 0))
    _record("clean CF (E1)", clean)

    # --- chopping sweep ---
    for f in chop_fracs:
        g = obfuscate.chop(split.pref_pos, keep_frac=f, seed=seed, cover=cover,
                           trust_total=trust_total, c=cf_clean.c)
        tag = f"chop keep={f:.2f}" + (" +cover" if cover else "")
        _record(tag, _eval_cf(g, split, cfg, k, is_head, is_tail))

    # --- laplace sweep (correct clamp-based ε-DP) ---
    for eps in epsilons:
        g = obfuscate.laplace(split.pref_pos, epsilon=eps, seed=seed, method="clamp")
        etag = "ε=∞ (norm only)" if not np.isfinite(eps) else f"ε={eps:g}"
        _record(f"laplace[clamp] {etag}", _eval_cf(g, split, cfg, k, is_head, is_tail))

    # --- legacy clip method (DP-voiding) shown for contrast: how much of the old
    #     "ε-insensitive" result was the data-dependent-clip artifact ---
    for eps in (e for e in epsilons if np.isfinite(e)):
        g = obfuscate.laplace(split.pref_pos, epsilon=eps, seed=seed, method="clip_legacy")
        _record(f"laplace[legacy] ε={eps:g}", _eval_cf(g, split, cfg, k, is_head, is_tail))

    # --- report ---
    print("\n" + "=" * 78)
    print(f"E2 — content discovery under noise (k={k}), per segment")
    print("=" * 78)
    hdr = f"  {'config':<26} {'P@K all':>8} {'P@K head':>9} {'P@K tail':>9} {'R@K tail':>9}  gate"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for label, ov, hd, tl, passed in rows:
        if label == "popularity":
            gate = ""
        elif "legacy" in label:
            gate = "  (contrast)"          # DP-voiding; shown for comparison, not gated
        else:
            gate = "  ✅" if passed else "  ❌"
        print(f"  {label:<26} {ov.precision:>8.4f} {hd.precision:>9.4f} "
              f"{tl.precision:>9.4f} {tl.recall:>9.4f}{gate}")

    # E2 passes if CF beats popularity on long-tail precision at *every* tested
    # operating point (popularity tail precision = 0, so this means tail P > 0).
    # The legacy clip rows are excluded — they are not a valid DP deployment, shown
    # only to expose the artifact in the old "ε-insensitive" claim.
    cf_rows = [r for r in rows if r[0] != "popularity" and "legacy" not in r[0]]
    e2_pass = all(r[4] for r in cf_rows)
    worst = min(cf_rows, key=lambda r: r[3].precision)
    print("  " + "-" * (len(hdr) - 2))
    print(f"  popularity long-tail precision : {pop_tail.precision:.4f} (structural floor)")
    print(f"  worst CF operating point       : {worst[0]} (tail P@{k}={worst[3].precision:.4f})")
    print(f"  RESULT = {'PASS ✅' if e2_pass else 'FAIL ❌'}  "
          f"(CF {'beats' if e2_pass else 'fails to beat'} popularity on long-tail at all noise levels)")
    print("=" * 78)
    print(f"[done] {time.time() - t0:.1f}s")
    return e2_pass, rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF Experiment E2 (noise)")
    ap.add_argument("--dataset", default="ml-1m", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--like-threshold", type=float, default=4.0)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--strategy", default="temporal", choices=["temporal", "random"])
    ap.add_argument("--head-frac", type=float, default=0.2)
    ap.add_argument("--kappa", type=float, default=1.0)
    ap.add_argument("--beta", type=float, default=1.0)
    ap.add_argument("--c-percentile", type=float, default=90.0)
    ap.add_argument("--dislike-penalty", type=float, default=1.0)
    ap.add_argument("--cover", action="store_true", help="chopping pads with cover items (§4.5)")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    e2_pass, _ = run(dataset=a.dataset, k=a.k, like_threshold=a.like_threshold,
                     test_frac=a.test_frac, strategy=a.strategy, head_frac=a.head_frac,
                     kappa=a.kappa, beta=a.beta, c_percentile=a.c_percentile,
                     dislike_penalty=a.dislike_penalty, cover=a.cover,
                     data_dir=a.data_dir, seed=a.seed)
    return 0 if e2_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
