"""Experiment E1 — "Does it recommend at all?" (SPEC.md §9.1).

Runs the §3 item-based CF against a popularity baseline on MovieLens and reports
Precision@K / Recall@K / NDCG@K / HitRate@K overall and split into head / long-tail
segments. Gate: CF beats the popularity baseline on long-tail discovery (tail R@K).

Also runs an ablation (CF without the novelty bonus and IDF item_weight) to show
those §3.4/§3.7 mechanisms are what drive the long-tail lift.

    python -m privacf.experiment --dataset ml-1m --k 10
"""

from __future__ import annotations

import argparse
import time

import numpy as np

from . import data as data_mod
from .baseline import Popularity
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate


def _report(name, topk, split, k, is_head, is_tail):
    overall = evaluate(topk, split.test_pos, k)
    head = evaluate(topk, split.test_pos, k, item_subset=is_head)
    tail = evaluate(topk, split.test_pos, k, item_subset=is_tail)
    print("  " + overall.row(name + " [all]"))
    print("  " + head.row(name + " [head]"))
    print("  " + tail.row(name + " [tail]"))
    return overall, head, tail


def run(dataset="ml-1m", k=10, like_threshold=4.0, test_frac=0.2,
        strategy="temporal", head_frac=0.2, kappa=1.0, beta=1.0,
        c_percentile=90.0, dislike_penalty=1.0, sim_topk=None,
        data_dir="data", seed=0):
    t0 = time.time()
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, like_threshold=like_threshold,
                                test_frac=test_frac, strategy=strategy, seed=seed)
    is_head, is_tail, pop = data_mod.popularity_segments(split.seen, head_frac)
    print(f"[segments] head={int(is_head.sum())} items, "
          f"tail={int(is_tail.sum())} items (head_frac={head_frac})")

    results = {}

    # --- Popularity baseline ---
    print("\n[popularity baseline]")
    pop_model = Popularity().fit(split.seen)
    pop_scores = pop_model.score_all(split.seen)
    pop_topk = top_k(pop_scores, k)
    results["pop"] = _report("popularity", pop_topk, split, k, is_head, is_tail)

    # --- CF (full: novelty + IDF item_weight) ---
    print("\n[PrivaCF item-based CF — novelty + item_weight]")
    cfg = CFConfig(kappa=kappa, beta=beta, c_percentile=c_percentile,
                   use_item_weight=True, dislike_penalty=dislike_penalty,
                   sim_topk=sim_topk)
    cf = ItemCF(cfg).fit(split.pref_pos)
    cf_scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    cf_topk = top_k(cf_scores, k)
    results["cf"] = _report("CF(full)", cf_topk, split, k, is_head, is_tail)
    print(f"    (DSybil cap c={cf.c:.3f}, mean novelty={cf.novelty.mean():.3f})")

    # --- CF ablation: no novelty bonus, no IDF damping (plain item-cosine CF) ---
    print("\n[ablation — CF without novelty/item_weight]")
    cfg_abl = CFConfig(kappa=0.0, beta=beta, use_item_weight=False,
                       dislike_penalty=dislike_penalty, sim_topk=sim_topk)
    cf_abl = ItemCF(cfg_abl).fit(split.pref_pos)
    abl_scores = cf_abl.score_all(split.pref_pos, split.pref_neg, split.seen)
    abl_topk = top_k(abl_scores, k)
    results["abl"] = _report("CF(plain)", abl_topk, split, k, is_head, is_tail)

    # --- Gate check (§9.1 E1): CF beats popularity on long-tail discovery ---
    pop_tail, cf_tail, pln_tail = results["pop"][2], results["cf"][2], results["abl"][2]
    pop_all, cf_all, pln_all = results["pop"][0], results["cf"][0], results["abl"][0]

    def _lift(a, b):
        return f"{a / b:.2f}x" if b > 0 else "∞ (baseline surfaces no tail)"

    passed = cf_tail.recall > pop_tail.recall and cf_tail.recall > 0
    print("\n" + "=" * 68)
    print(f"E1 GATE — long-tail discovery, tail Recall@{k} (higher = better):")
    print(f"    popularity baseline : {pop_tail.recall:.4f}   (HR@{k}={pop_tail.hit_rate:.4f})")
    print(f"    CF, plain           : {pln_tail.recall:.4f}   (HR@{k}={pln_tail.hit_rate:.4f})")
    print(f"    CF, novelty+IDF     : {cf_tail.recall:.4f}   (HR@{k}={cf_tail.hit_rate:.4f})")
    print(f"    lift CF(full) vs popularity : {_lift(cf_tail.recall, pop_tail.recall)}")
    print(f"    lift CF(full) vs CF(plain)  : {_lift(cf_tail.recall, pln_tail.recall)}")
    print(f"  sanity — overall P@{k}: popularity={pop_all.precision:.4f}  "
          f"CF(plain)={pln_all.precision:.4f}  CF(full)={cf_all.precision:.4f}")
    print(f"  (CF(full) trades head accuracy for long-tail discovery — the §3.7 "
          f"novelty/§3.4 IDF tradeoff)")
    print(f"  RESULT = {'PASS ✅' if passed else 'FAIL ❌'}  "
          f"(CF {'beats' if passed else 'does not beat'} popularity on long-tail discovery)")
    print("=" * 68)
    print(f"[done] {time.time() - t0:.1f}s")
    return passed, results


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF Experiment E1")
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
    ap.add_argument("--sim-topk", type=int, default=None)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    passed, _ = run(dataset=a.dataset, k=a.k, like_threshold=a.like_threshold,
                    test_frac=a.test_frac, strategy=a.strategy, head_frac=a.head_frac,
                    kappa=a.kappa, beta=a.beta, c_percentile=a.c_percentile,
                    dislike_penalty=a.dislike_penalty, sim_topk=a.sim_topk,
                    data_dir=a.data_dir, seed=a.seed)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
