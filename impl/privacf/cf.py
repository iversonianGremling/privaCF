"""Item-based collaborative filtering — the §3 core of PrivaCF.

Faithful to SPEC.md §3.2, §3.4, §3.5, §3.7. E1 runs with noise=0 and all peers
honest (band 4 -> full weight); the noise term (§4.5) is plumbed but left at 0,
so E2 (chopping vs Laplace) is a one-line extension.

Notation matches the spec:
  Δ_base (delta_base)  base trust increment per announcement                §3.4
  c                    DSybil global trust cap per item                      §7.3
  κ (kappa)            novelty bonus coefficient                            §3.4/§3.7
  β (beta)             blend of global vs cluster trust_total               §3.4
  novelty(X) = clamp(1 - effective_trust(X)/c, 0, 1)                        §3.7
  item_weight(X) = 1 / log(1 + effective_trust(X)/c)   (IDF-like damping)   §3.4
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

try:                                   # optional: ~20-60x faster matmuls on the
    import scipy.sparse as _sp         # large, ~95%-sparse MovieLens gossip matrices
except Exception:                      # pragma: no cover - scipy is optional
    _sp = None

_EPS = 1e-8
# Below this density a dense [n,m] matrix is worth converting to CSR for the
# heavy matmuls (sim build and scoring); above it the dense path is fine.
_SPARSE_DENSITY = 0.25


def _maybe_csr(x: np.ndarray):
    """Return a CSR view of x if scipy is present and x is sparse enough, else x."""
    if _sp is None or _sp.issparse(x):
        return x
    if x.size == 0 or (np.count_nonzero(x) / x.size) > _SPARSE_DENSITY:
        return x
    return _sp.csr_matrix(x)


def _gram(Pn: np.ndarray) -> np.ndarray:
    """Dense Gram matrix Pnᵀ·Pn, via sparse matmul when Pn is sparse enough."""
    s = _maybe_csr(Pn)
    if _sp is not None and _sp.issparse(s):
        return np.asarray((s.T @ s).todense(), dtype=np.float32)
    return (Pn.T @ Pn).astype(np.float32)


def _mul(X: np.ndarray, sim: np.ndarray) -> np.ndarray:
    """Dense product X·sim, via sparse matmul when X is sparse enough."""
    s = _maybe_csr(X)
    if _sp is not None and _sp.issparse(s):
        return np.asarray(s @ sim, dtype=np.float32)
    return (X @ sim).astype(np.float32)


@dataclass
class CFConfig:
    delta_base: float = 1.0
    kappa: float = 1.0          # novelty bonus strength (§3.7); 0 disables novelty
    beta: float = 1.0           # 1.0 = pure global trust_total (E1 default)
    c: float | None = None      # DSybil cap; None -> data-driven (percentile below)
    c_percentile: float = 90.0  # percentile of raw global trust used when c is None
    use_item_weight: bool = True   # apply the §3.4 IDF damping to candidate scores
    dislike_penalty: float = 1.0   # §3.5 penalty coefficient (0 disables)
    sim_topk: int | None = None    # keep only top-k item neighbours (None = all)


class ItemCF:
    """Local item-based CF recommender built from received gossip vectors.

    fit() consumes the network's positive preference matrix (rows = peer nodes,
    cols = items) and builds the item-item similarity, novelty, and item_weight
    structures. score_all() then scores candidate items for every user from that
    user's own train interactions (§3.2: score(i) = Σ_{j∈interacted} sim(i,j)·w(j)).
    """

    def __init__(self, cfg: CFConfig | None = None):
        self.cfg = cfg or CFConfig()
        self.sim: np.ndarray | None = None
        self.item_weight: np.ndarray | None = None
        self.novelty: np.ndarray | None = None
        self.effective_trust: np.ndarray | None = None
        self.c: float | None = None

    def fit(self, gossip_pos: np.ndarray, cluster_mask: np.ndarray | None = None,
            noise: np.ndarray | None = None) -> "ItemCF":
        cfg = self.cfg
        # trust_contribution base term: max(0, p + noise) · Δ_base   (§3.4)
        p = gossip_pos
        if noise is not None:
            p = np.maximum(0.0, p + noise)
        base_contrib = (p * cfg.delta_base).astype(np.float32)

        # global_trust_total(X) with the DSybil cap c (§7.3: contributions halt at c)
        global_tt_raw = base_contrib.sum(axis=0)
        if cfg.c is None:
            pos = global_tt_raw[global_tt_raw > 0]
            c = float(np.percentile(pos, cfg.c_percentile)) if pos.size else 1.0
        else:
            c = float(cfg.c)
        c = max(c, _EPS)
        self.c = c
        global_tt = np.minimum(global_tt_raw, c)

        # cluster_trust_total(X) restricted to the receiving node's PSI peers.
        # E1 default beta=1 -> clusters unused; supported for E4.
        if cfg.beta < 1.0 and cluster_mask is not None:
            cluster_tt = np.minimum((base_contrib * cluster_mask[:, None]).sum(0), c)
        else:
            cluster_tt = global_tt
        effective_tt = cfg.beta * global_tt + (1.0 - cfg.beta) * cluster_tt
        self.effective_trust = effective_tt

        # novelty (§3.7) and IDF item_weight (§3.4)
        novelty = np.clip(1.0 - effective_tt / c, 0.0, 1.0).astype(np.float32)
        self.novelty = novelty
        # NOTE (impl finding): the spec form item_weight = 1/log(1 + eff/c) diverges
        # to +inf as eff -> 0 (cold items), producing inf*0 -> NaN scores. We regularise
        # the denominator to log(2 + eff/c): bounded in (1/log3, 1/log2] ≈ [0.91, 1.44],
        # still monotone-decreasing in trust. Worth flagging back to §3.4.
        self.item_weight = (1.0 / np.log(2.0 + effective_tt / c)).astype(np.float32)

        # Similarity is computed from the un-novelty-scaled contributions. Cosine
        # normalises each column independently, so a per-column novelty factor would
        # cancel out and have *zero* effect on sim (impl finding). The novelty bonus
        # therefore enters at ranking time in score_all(), not in P.
        P = base_contrib

        # item-item cosine similarity over columns of P  (§3.2)
        norms = np.sqrt((P * P).sum(axis=0)) + _EPS
        Pn = P / norms[None, :]
        sim = _gram(Pn)
        np.fill_diagonal(sim, 0.0)  # an item is not its own neighbour for scoring
        if cfg.sim_topk is not None and cfg.sim_topk < sim.shape[1]:
            sim = _keep_topk_rows(sim, cfg.sim_topk)
        self.sim = sim
        return self

    def score_all(self, pref_pos: np.ndarray, pref_neg: np.ndarray,
                  seen: np.ndarray) -> np.ndarray:
        """Score every (user, item). Returns float32 [n_users, n_items] with seen
        items set to -inf. Vectorised form of §3.2 + §3.5:

            raw(i)  = Σ_{j∈interacted} sim(i,j)·p_v[j]          = (pref_pos @ sim)
            final(i)= item_weight(i)·raw(i)
                      − penalty·max(0, Σ_{j∈dislikes} sim(i,j)·|p_v[j]|)
        """
        assert self.sim is not None and self.item_weight is not None
        cfg = self.cfg
        scores = _mul(pref_pos, self.sim)
        # discovery boost on the candidate item i: novelty bonus (§3.7) and IDF
        # damping (§3.4), both decreasing in item popularity -> lifts long-tail
        # candidates. Ablation (kappa=0, use_item_weight=False) -> boost=1 -> plain CF.
        boost = np.ones(scores.shape[1], dtype=np.float32)
        if cfg.kappa > 0:
            boost = boost * (1.0 + cfg.kappa * self.novelty)
        if cfg.use_item_weight:
            boost = boost * self.item_weight
        scores *= boost[None, :]
        if cfg.dislike_penalty > 0:
            dislike = _mul(pref_neg, self.sim)
            scores -= cfg.dislike_penalty * np.maximum(0.0, dislike)
        scores[seen] = -np.inf
        return scores


def _keep_topk_rows(sim: np.ndarray, k: int) -> np.ndarray:
    """Zero all but the top-k entries of each row (sparsify neighbourhoods)."""
    out = np.zeros_like(sim)
    idx = np.argpartition(-sim, k, axis=1)[:, :k]
    rows = np.arange(sim.shape[0])[:, None]
    out[rows, idx] = sim[rows, idx]
    return out


def top_k(scores: np.ndarray, k: int) -> np.ndarray:
    """Return int32 [n_users, k] item indices ranked by score (desc) per user."""
    n_items = scores.shape[1]
    k = min(k, n_items)
    part = np.argpartition(-scores, k - 1, axis=1)[:, :k]
    rows = np.arange(scores.shape[0])[:, None]
    order = np.argsort(-scores[rows, part], axis=1)
    return part[rows, order].astype(np.int32)
