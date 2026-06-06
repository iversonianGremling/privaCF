"""Top-N ranking metrics, overall and per popularity segment (§9.3).

Given per-user top-K recommendation lists and per-user held-out positive test
items, compute Precision@K, Recall@K, NDCG@K, HitRate@K. The same metrics
restricted to long-tail test items give the "long-tail discovery rate" that is
E1's gate (§9.1).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Result:
    k: int
    n_users: int
    precision: float
    recall: float
    ndcg: float
    hit_rate: float

    def row(self, label: str) -> str:
        return (f"{label:<22} P@{self.k}={self.precision:.4f}  R@{self.k}={self.recall:.4f}  "
                f"NDCG@{self.k}={self.ndcg:.4f}  HR@{self.k}={self.hit_rate:.4f}  "
                f"(n={self.n_users})")


def _dcg(hits: np.ndarray) -> float:
    # hits: 1/0 array in ranked order
    discounts = 1.0 / np.log2(np.arange(2, hits.size + 2))
    return float((hits * discounts).sum())


def evaluate(topk: np.ndarray, test_pos: list[np.ndarray], k: int,
             item_subset: np.ndarray | None = None) -> Result:
    """Evaluate ranked lists against held-out positives.

    item_subset: optional bool[n_items] mask. When given, both the recommendation
    list and the test targets are restricted to that subset before scoring — this
    yields per-segment (head / long-tail) metrics. A user with no test positives
    inside the subset is skipped.
    """
    n_eval = 0
    p_sum = r_sum = ndcg_sum = hr_sum = 0.0
    for u, pos in enumerate(test_pos):
        if pos.size == 0:
            continue
        # The recommendation list is always the user's full top-K. For per-segment
        # metrics we restrict only the *targets* to the segment and ask how many
        # segment items the top-K captured — keeping the denominator model-independent
        # (popularity simply scores ~0 on long-tail targets rather than being skipped).
        target = pos
        if item_subset is not None:
            target = pos[item_subset[pos]]
            if target.size == 0:
                continue
        rec_k = topk[u][:k]
        target_set = set(target.tolist())
        hits = np.fromiter((1.0 if it in target_set else 0.0 for it in rec_k),
                           dtype=np.float64, count=rec_k.size)
        n_hit = hits.sum()

        p_sum += n_hit / k
        r_sum += n_hit / target.size
        # ideal DCG: min(#targets, k) ones at the top
        ideal = _dcg(np.ones(min(target.size, k)))
        ndcg_sum += (_dcg(hits) / ideal) if ideal > 0 else 0.0
        hr_sum += 1.0 if n_hit > 0 else 0.0
        n_eval += 1

    if n_eval == 0:
        return Result(k, 0, 0.0, 0.0, 0.0, 0.0)
    return Result(k, n_eval, p_sum / n_eval, r_sum / n_eval,
                  ndcg_sum / n_eval, hr_sum / n_eval)
