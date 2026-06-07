"""Preference obfuscation in transit — SPEC.md §4.5.

Two mutually-exclusive deployment modes transform the *gossip* a node broadcasts
(the positive-preference matrix), while the node's own local vector — used as the
query in score_all() — stays clean (negative weights and the un-obfuscated history
never leave the device). E2 measures what each mode costs recommendation quality
per head/long-tail segment.

  chopping (niche-friendly)  transmit exactly n_v(T) positive elements, the rest
                             dropped; optionally pad back up with cover items drawn
                             toward low-trust (novel) items.  §4.5 "Variable chopping"
  laplace  (formal DP)       L1-normalise the row, add Laplace(0, S/ε) (S=2) on the
                             active dimensions, then **clamp the output to [0, B]**
                             (B public) and renormalise.  §4.5

Faithful detail (corrected 2026-06-06 to match SPEC §4.5 / SECURITY.md §P2): the DP
mode now achieves sign preservation by a **data-independent output clamp** to [0, B],
not by the old data-dependent noise-truncation |noise_i| < |p_v[i]|. The latter
conditioned the output on a data-dependent event and therefore **voided nominal
ε-DP** (neighbouring vectors got outputs with different supports). The clamp +
renormalise are post-processing of the noised vector, so by DP's post-processing
immunity the mechanism is **clean ε-DP (δ=0)**.

Consequence for E2: the old "ε-insensitive, nearly free" Laplace result was partly an
*artifact* of that DP-voiding clip — clipping noise to ±|p_v[i]| made the effective
perturbation proportional to each weight (hence ε-independent) and never dropped an
active item. Under the correct clamp, a small active weight whose draw goes negative
clamps to 0 (mild support loss that grows as ε shrinks), so the corrected Laplace is
genuinely ε-*sensitive*. The `method="clip_legacy"` path is retained so E2 can show
the contrast directly. Which-items privacy remains chopping/permutation's job (§4.5),
so noise is applied to active dimensions only — inactive dims stay 0.
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
            sensitivity: float = 2.0, bound: float = 1.0,
            normalize: bool = True, method: str = "clamp") -> np.ndarray:
    """Laplace DP obfuscation (§4.5, corrected to clean ε-DP).

    L1-normalise each row (so ‖p_v‖₁ = 1, making S = 2 meaningful), add
    Laplace(0, S/ε) on the active dimensions, then post-process. Two methods:

      method="clamp"  (default, **correct — clean ε-DP, δ=0**):
          gossip = renormalise(clamp(p_v + noise·active, 0, B))
          The clamp to [0, B] and the renormalise are data-independent functions of
          the noised vector, so by post-processing immunity the mechanism stays ε-DP.
          Sign preservation falls out of the non-negativity clamp (a sign-flipping
          draw projects to 0 = "not endorsed"). B is a public deployment constant.

      method="clip_legacy"  (**old — voids ε-DP; kept only for the E2 contrast**):
          gossip = max(0, p_v + clip(noise, -|p_v|, |p_v|))
          Truncating the noise to ±|p_v[i]| conditions on a data-dependent event,
          which destroys nominal ε-DP. Retained so E2 can show how much of the old
          "ε-insensitive" result was this artifact.

    Noise is applied to active dims only — which-items privacy is chopping/
    permutation's job (§4.5), so inactive dims stay exactly 0 in both methods.
    epsilon = inf gives the normalise-only reference point (isolates the cost of
    noise from the cost of the L1 renormalisation).
    """
    rng = np.random.default_rng(seed)
    out = pref_pos.astype(np.float32).copy()
    if normalize:
        l1 = np.abs(out).sum(axis=1, keepdims=True)
        l1[l1 == 0] = 1.0
        out = out / l1

    if not np.isfinite(epsilon):
        return np.maximum(0.0, out)

    active = out > 0
    scale = sensitivity / epsilon
    noise = (rng.laplace(0.0, scale, size=out.shape).astype(np.float32)) * active

    if method == "clamp":
        out = np.clip(out + noise, 0.0, bound)         # data-independent → ε-DP preserved
        if normalize:
            l1 = out.sum(axis=1, keepdims=True)         # renormalise (post-processing)
            l1[l1 == 0] = 1.0
            out = out / l1
        return out
    elif method == "clip_legacy":
        cap = np.abs(out)                               # data-dependent cap (DP-voiding)
        return np.maximum(0.0, out + np.clip(noise, -cap, cap))
    raise ValueError(f"unknown laplace method: {method!r}")
