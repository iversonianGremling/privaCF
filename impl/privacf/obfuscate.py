"""Preference obfuscation in transit — SPEC.md §4.5.

Two mutually-exclusive deployment modes transform the *gossip* a node broadcasts
(the positive-preference matrix), while the node's own local vector — used as the
query in score_all() — stays clean (negative weights and the un-obfuscated history
never leave the device). E2 measures what each mode costs recommendation quality
per head/long-tail segment.

  chopping (niche-friendly)  transmit exactly n_v(T) positive elements, the rest
                             dropped; optionally pad back up with cover items drawn
                             toward low-trust (novel) items.  §4.5 "Variable chopping"
  laplace  (formal DP)       L1-normalise the row, add Laplace(0, S/ε) (S=2), then
                             enforce sign preservation |noise_i| < |p_v[i]|.  §4.5

Key faithful detail: under sign preservation, Laplace perturbs only the *magnitude*
of already-active dimensions (cap = 0 on inactive dims), so it preserves item support
(which items co-occur) while jittering weights. Chopping, by contrast, destroys
support. This asymmetry is the headline of E2.
"""

from __future__ import annotations

import numpy as np

_EPS = 1e-8


def chop(pref_pos: np.ndarray, keep_frac: float, seed: int = 0,
         cover: bool = False, cover_scale: float = 1.0,
         trust_total: np.ndarray | None = None, c: float | None = None,
         pad_to_original: bool = True) -> np.ndarray:
    """Variable chopping (§4.5).

    Each node transmits a subset of its positive preferences: keep_frac of each
    row's nonzero entries (at least 1), chosen by a per-node random draw. With
    cover=True the dropped slots are padded back with cover items so the
    transmitted count is uninformative about the true preference count; cover
    items are sampled toward low-trust (novel) items per the §4.5 cover_weight.
    """
    rng = np.random.default_rng(seed)
    pos = pref_pos > 0
    n_pos = pos.sum(axis=1)
    n_keep = np.minimum(n_pos, np.maximum(1, np.round(keep_frac * n_pos)).astype(np.int64))
    n_keep[n_pos == 0] = 0

    # per-row random ranking of the positive entries; keep the n_keep smallest-rank
    rand = rng.random(pref_pos.shape).astype(np.float32)
    rand[~pos] = 2.0                                   # push non-positive entries last
    rank = np.argsort(np.argsort(rand, axis=1), axis=1)  # 0 = smallest rand in row
    keep_mask = pos & (rank < n_keep[:, None])
    out = np.where(keep_mask, pref_pos, 0.0).astype(np.float32)

    if cover and pad_to_original:
        out = _add_cover(out, pos, n_pos - n_keep, rng, cover_scale, trust_total, c)
    return out


def _add_cover(out, real_pos, n_cover, rng, cover_scale, trust_total, c):
    """Pad each row with n_cover[u] cover items drawn ∝ 1/log(1 + trust_total/c)
    (favouring low-trust / novel items), at a small cover_weight (§4.5)."""
    n_items = out.shape[1]
    if trust_total is None:
        base_w = np.ones(n_items, dtype=np.float64)
    else:
        cc = c if c else float(np.percentile(trust_total[trust_total > 0], 90)) or 1.0
        base_w = 1.0 / np.log(1.0 + np.maximum(trust_total, 0.0) / max(cc, _EPS) + 1.0)
    for u in np.nonzero(n_cover > 0)[0]:
        k = int(n_cover[u])
        w = base_w.copy()
        w[real_pos[u]] = 0.0                            # don't cover an item already real
        s = w.sum()
        if s <= 0:
            continue
        pick = rng.choice(n_items, size=min(k, int((w > 0).sum())), replace=False, p=w / s)
        out[u, pick] = (rng.uniform(0.0, cover_scale, size=pick.shape)).astype(np.float32)
    return out


def laplace(pref_pos: np.ndarray, epsilon: float, seed: int = 0,
            sensitivity: float = 2.0, sign_preserve: bool = True,
            normalize: bool = True) -> np.ndarray:
    """Laplace DP obfuscation (§4.5).

    L1-normalise each row (so ‖p_v‖₁ = 1, making S = 2 meaningful), add
    Laplace(0, S/ε), and enforce the sign-preservation constraint
    |noise_i| < |p_v[i]| by per-dimension truncation. Only positive weights are
    transmitted, so the result is clamped at 0. epsilon = inf gives the
    normalize-only reference point (isolates the cost of noise from the cost of
    the L1 renormalisation).
    """
    rng = np.random.default_rng(seed)
    out = pref_pos.astype(np.float32).copy()
    if normalize:
        l1 = np.abs(out).sum(axis=1, keepdims=True)
        l1[l1 == 0] = 1.0
        out = out / l1

    if not np.isfinite(epsilon):
        return np.maximum(0.0, out)

    scale = sensitivity / epsilon
    noise = rng.laplace(0.0, scale, size=out.shape).astype(np.float32)
    if sign_preserve:
        cap = np.abs(out)                # cap = 0 on inactive dims -> they stay 0
        noise = np.clip(noise, -cap, cap)
    return np.maximum(0.0, out + noise)
