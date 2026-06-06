"""Experiment E4 — "PSI peer selection and identity rotation" (SPEC.md §9.1).

    Gate: PSI improves precision@K; VRF degrades by < 20%.

Two mechanisms, measured on recommendation precision:

  PSI peer selection (§3.4, §5.4)  Instead of weighting discovery by *global*
      trust_total, blend in a *cluster* trust_total restricted to the node's PSI
      peer neighbourhood — the users whose tastes overlap yours (top-N by
      preference cosine, the in-the-clear analogue of Jaccard PSI ≥ θ_cluster).
      effective_trust = β·global + (1−β)·cluster; β<1 personalises which items
      count as "novel/undersurfaced" for *you*, softening globally-popular-but-
      locally-rare items (§3.4). Gate clause 1: PSI (β<1) beats global (β=1) on P@K.

  Identity rotation + VRF jitter (§4.2, §4.5)  Client identities rotate every
      epoch and are unlinkable, so a node cannot perfectly re-find its peers each
      epoch — the working neighbourhood is a churned, partly-random subset of the
      ideal one (keep a fraction φ of true peers; the rest are replaced by
      VRF-random draws). Gate clause 2: this privacy-preserving version costs < 20%
      of the ideal PSI precision.

So E4 answers: does taste-based peer selection actually help, and does the price of
making it privacy-preserving (rotation) stay small?

    python -m privacf.experiment_e4 --dataset ml-1m --k 10
"""

from __future__ import annotations

import argparse
import time

import numpy as np

try:
    import scipy.sparse as _sp
except Exception:                      # pragma: no cover
    _sp = None

from . import data as data_mod
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate

_EPS = 1e-8


def _sparse(x):
    if _sp is not None and not _sp.issparse(x) and x.size and \
            np.count_nonzero(x) / x.size < 0.25:
        return _sp.csr_matrix(x)
    return x


def _user_peer_idx(pref, n_peers):
    """Top-n_peers PSI peers per user by preference-vector cosine (excl. self)."""
    norm = np.sqrt((pref * pref).sum(1)) + _EPS
    un = (pref / norm[:, None]).astype(np.float32)
    un_s = _sparse(un)
    usim = (np.asarray((un_s @ un_s.T).todense(), dtype=np.float32)
            if _sp is not None and _sp.issparse(un_s) else un @ un.T)  # [U,U] taste overlap
    np.fill_diagonal(usim, -np.inf)       # never your own peer
    n = min(n_peers, usim.shape[1] - 1)
    idx = np.argpartition(-usim, n, axis=1)[:, :n]
    return idx                            # [U, n]


def _rotate(peer_idx, keep_frac, n_users, rng):
    """Identity-rotation churn: keep keep_frac of each user's true peers, replace
    the rest with VRF-random draws (unlinkable rotation loses peer continuity)."""
    U, n = peer_idx.shape
    n_keep = max(1, int(round(keep_frac * n)))
    out = peer_idx.copy()
    # randomise which kept-columns survive, and fill the rest with random users
    for j_block in range(0, U, 4096):                       # chunk to bound memory
        sl = slice(j_block, min(j_block + 4096, U))
        m = out[sl].shape[0]
        # shuffle columns per row, keep first n_keep, random-fill the tail
        perm = np.argsort(rng.random((m, n)), axis=1)
        kept = np.take_along_axis(peer_idx[sl], perm[:, :n_keep], axis=1)
        rand = rng.integers(0, n_users, size=(m, n - n_keep))
        out[sl] = np.concatenate([kept, rand], axis=1)
    return out


def _peer_mask(peer_idx, n_users):
    """Indicator of each user's peer set. Returns CSR when scipy is present (the
    mask is ~1% dense), else a dense [U, n_users] array."""
    U, n = peer_idx.shape
    if _sp is not None:
        rows = np.repeat(np.arange(U), n)
        data = np.ones(U * n, dtype=np.float32)
        return _sp.csr_matrix((data, (rows, peer_idx.ravel())), shape=(U, n_users))
    mask = np.zeros((U, n_users), dtype=np.float32)
    mask[np.arange(U)[:, None], peer_idx] = 1.0
    return mask


def _precision(pref, seen, sim, c, global_tt, cluster_tt, beta, kappa, k,
               test_pos, is_head, is_tail):
    """Per-user blended boost (cluster-aware novelty/IDF) applied at ranking time."""
    eff = beta * global_tt[None, :] + (1.0 - beta) * cluster_tt        # [U, I]
    novelty = np.clip(1.0 - eff / c, 0.0, 1.0).astype(np.float32)
    item_w = (1.0 / np.log(2.0 + eff / c)).astype(np.float32)
    boost = (1.0 + kappa * novelty) * item_w
    pref_s = _sparse(pref)
    raw = np.asarray(pref_s @ sim, dtype=np.float32)
    scores = raw * boost
    scores[seen] = -np.inf
    tk = top_k(scores, k)
    ov = evaluate(tk, test_pos, k)
    tl = evaluate(tk, test_pos, k, item_subset=is_tail)
    return ov, tl


def run(dataset="ml-1m", k=10, like_threshold=4.0, test_frac=0.2,
        strategy="temporal", head_frac=0.2, kappa=0.5, beta=0.5,
        n_peers=50, keep_frac=0.5, c_percentile=90.0, data_dir="data", seed=0):
    t0 = time.time()
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, like_threshold=like_threshold,
                                test_frac=test_frac, strategy=strategy, seed=seed)
    is_head, is_tail, _ = data_mod.popularity_segments(split.seen, head_frac)
    pref, seen = split.pref_pos, split.seen
    U, I = pref.shape
    rng = np.random.default_rng(seed)

    cf = ItemCF(CFConfig(kappa=kappa, use_item_weight=True,
                         c_percentile=c_percentile)).fit(pref)
    sim, c = cf.sim, cf.c
    global_tt = np.minimum(pref.sum(0), c).astype(np.float32)

    print(f"[psi] n_peers={n_peers}  β={beta}  κ={kappa}  keep_frac(rotation)={keep_frac}")
    peer_idx = _user_peer_idx(pref, n_peers)

    # global (β=1): cluster term unused -> boost is per-item (= E1 full machinery)
    g_ov, g_tl = _precision(pref, seen, sim, c, global_tt, global_tt, 1.0,
                            kappa, k, split.test_pos, is_head, is_tail)

    # PSI peer selection (ideal peers)
    cluster_tt = np.minimum(_peer_mask(peer_idx, U) @ pref, c).astype(np.float32)
    p_ov, p_tl = _precision(pref, seen, sim, c, global_tt, cluster_tt, beta,
                            kappa, k, split.test_pos, is_head, is_tail)

    # PSI under identity rotation + VRF jitter (churned/partly-random peers)
    rot_idx = _rotate(peer_idx, keep_frac, U, rng)
    rot_tt = np.minimum(_peer_mask(rot_idx, U) @ pref, c).astype(np.float32)
    r_ov, r_tl = _precision(pref, seen, sim, c, global_tt, rot_tt, beta,
                            kappa, k, split.test_pos, is_head, is_tail)

    # --- report ---
    print("\n" + "=" * 76)
    print(f"E4 — PSI peer selection and identity rotation (k={k})")
    print("=" * 76)
    hdr = f"  {'config':<28} {'overall P':>10} {'tail R':>9}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    print(f"  {'global (β=1, no PSI)':<28} {g_ov.precision:>10.4f} {g_tl.recall:>9.4f}")
    print(f"  {'PSI peers (β=%.2f, ideal)' % beta:<28} {p_ov.precision:>10.4f} {p_tl.recall:>9.4f}")
    print(f"  {'PSI + rotation/VRF':<28} {r_ov.precision:>10.4f} {r_tl.recall:>9.4f}")

    psi_helps = p_ov.precision > g_ov.precision
    psi_lift = (p_ov.precision / g_ov.precision - 1.0) * 100 if g_ov.precision else 0.0
    rot_delta = (r_ov.precision / p_ov.precision - 1.0) * 100 if p_ov.precision else -100.0
    degrade = max(0.0, -rot_delta)        # only a *drop* counts as degradation
    rotation_ok = degrade < 20.0
    rot_note = f"{rot_delta:+.1f}% (no degradation)" if rot_delta >= 0 else f"−{degrade:.1f}%"

    print("  " + "-" * (len(hdr) - 2))
    print(f"  clause 1 — PSI improves P@{k} over global : {psi_helps}  "
          f"({g_ov.precision:.4f} -> {p_ov.precision:.4f}, {psi_lift:+.1f}%)")
    print(f"  clause 2 — rotation/VRF degrades < 20%    : {rotation_ok}  "
          f"(ideal {p_ov.precision:.4f} -> rotated {r_ov.precision:.4f}, {rot_note})")
    passed = psi_helps and rotation_ok
    print(f"  RESULT = {'PASS ✅' if passed else 'FAIL ❌'}  "
          f"(PSI helps and rotation cost is bounded)")
    print("=" * 76)
    print(f"[done] {time.time() - t0:.1f}s")
    return passed, (g_ov, p_ov, r_ov)


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF Experiment E4 (PSI + rotation)")
    ap.add_argument("--dataset", default="ml-1m", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--strategy", default="temporal", choices=["temporal", "random"])
    ap.add_argument("--head-frac", type=float, default=0.2)
    ap.add_argument("--kappa", type=float, default=0.5)
    ap.add_argument("--beta", type=float, default=0.5, help="global/cluster blend; <1 = use PSI peers")
    ap.add_argument("--n-peers", type=int, default=50)
    ap.add_argument("--keep-frac", type=float, default=0.5, help="peers retained under rotation")
    ap.add_argument("--c-percentile", type=float, default=90.0)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    passed, _ = run(dataset=a.dataset, k=a.k, strategy=a.strategy, head_frac=a.head_frac,
                    kappa=a.kappa, beta=a.beta, n_peers=a.n_peers, keep_frac=a.keep_frac,
                    c_percentile=a.c_percentile, data_dir=a.data_dir, seed=a.seed)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
