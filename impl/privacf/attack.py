"""Sybil attacks and the §7.4 FoolsGold-on-PSI-peers defense — for E3.

RobuRec / shilling attack profiles (push attacks — gossip is positive-only, so a
Sybil's lever is to inject positive endorsement of a target item plus a filler
pattern that links it into honest users' recommendations):

  random     filler = random items at a base weight; cheap, no catalog knowledge
  average    filler = items at their popularity-proportional weight; mimics a
             typical user, harder to flag on profile statistics
  bandwagon  filler = the most-popular items at max weight; links the target to
             the head so it rides into many users' lists — the strongest push
  segment    filler = the target's own honest item-neighbourhood; a targeted push
             into exactly the users predisposed to the co-liked items

SSP scenarios (Werthenbach & Pouwelse 2023) — how the Sybils are placed:

  dense        many Sybils sharing one identical profile — maximal co-occurrence
               concentration, but maximal mutual similarity (easy to detect)
  distributed  many Sybils each with an independent filler draw — lower mutual
               similarity (harder to detect), weaker per-filler co-occurrence
  sparse       few Sybils, independent fillers — small footprint

Defense — FoolsGold (Fung et al., RAID 2020), applied over PSI-peer contribution
vectors per §7.4: nodes whose contribution vectors are anomalously similar to one
another are downweighted toward zero. A coordinated Sybil group has near-identical
vectors and is crushed; diverse honest users keep full weight. Implemented as the
soft per-node weight (the spec uses the same signal as a flag → committee
escalation; the soft downweight is the CF-integrated approximation).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

try:
    import scipy.sparse as _sp
except Exception:                      # pragma: no cover
    _sp = None

_EPS = 1e-8


@dataclass
class Injection:
    gossip: np.ndarray          # [n_honest + n_sybil, n_items] combined gossip matrix
    n_honest: int
    n_sybil: int
    target: int                 # the pushed item index
    is_sybil: np.ndarray        # bool [n_nodes]


def pick_target(honest_pos: np.ndarray, seen: np.ndarray, kind: str = "tail",
                head_frac: float = 0.2, seed: int = 0) -> int:
    """Choose a push target. 'tail' picks a cold long-tail item (the realistic
    target — pushing an already-popular item is pointless); 'head' picks popular."""
    pop = seen.sum(axis=0).astype(np.int64)
    rng = np.random.default_rng(seed)
    order = np.argsort(-pop, kind="stable")
    n_head = max(1, int(round(head_frac * pop.size)))
    pool = order[:n_head] if kind == "head" else order[n_head:]
    # among the chosen band, take items with a little signal but not zero
    pool = pool[(pop[pool] > 0)]
    if kind == "tail":
        # lower-mid of the tail: cold but not a total isolate
        pool = pool[len(pool) // 2:]
    return int(rng.choice(pool))


def inject(honest_pos: np.ndarray, seen: np.ndarray, target: int,
           attack: str = "bandwagon", ssp: str = "dense",
           sybil_frac: float = 0.10, n_filler: int = 30,
           target_weight: float = 2.0, base_weight: float = 1.0,
           seed: int = 0) -> Injection:
    """Build the combined honest+Sybil gossip matrix for one (attack, ssp) cell."""
    rng = np.random.default_rng(seed)
    n_honest, n_items = honest_pos.shape
    counts = {"dense": sybil_frac, "distributed": sybil_frac, "sparse": sybil_frac / 3.0}
    m = max(1, int(round(counts[ssp] * n_honest)))

    pop = seen.sum(axis=0).astype(np.float64)
    pop_order = np.argsort(-pop, kind="stable")
    # mean positive weight per item among honest likers (for the 'average' attack)
    with np.errstate(invalid="ignore"):
        item_mean = honest_pos.sum(0) / np.maximum(1.0, (honest_pos > 0).sum(0))

    def _filler_items(r):
        if attack == "random":
            return r.choice(n_items, size=min(n_filler, n_items), replace=False)
        if attack == "average":
            w = pop / pop.sum()
            return r.choice(n_items, size=min(n_filler, int((w > 0).sum())),
                            replace=False, p=w)
        if attack == "bandwagon":
            pop_items = pop_order[:max(1, n_filler // 2)]
            rest = r.choice(n_items, size=min(n_filler - len(pop_items), n_items),
                            replace=False)
            return np.unique(np.concatenate([pop_items, rest]))
        if attack == "segment":
            # target's honest item-neighbourhood: items co-liked by users who like target
            likers = honest_pos[:, target] > 0
            if likers.sum() == 0:
                likers = (honest_pos[:, pop_order[:50]] > 0).any(1)  # fallback
            coliked = honest_pos[likers].sum(0)
            coliked[target] = 0
            seg = np.argsort(-coliked)[:n_filler]
            return seg[coliked[seg] > 0]
        raise ValueError(f"unknown attack {attack!r}")

    def _filler_weights(items, r):
        if attack == "average":
            return np.maximum(base_weight, item_mean[items]).astype(np.float32)
        return np.full(len(items), base_weight, dtype=np.float32)

    sybil = np.zeros((m, n_items), dtype=np.float32)
    if ssp == "dense":
        items = _filler_items(rng)                 # one shared profile
        w = _filler_weights(items, rng)
        sybil[:, items] = w
    else:                                          # distributed / sparse: independent draws
        for s in range(m):
            items = _filler_items(rng)
            sybil[s, items] = _filler_weights(items, rng)
    sybil[:, target] = target_weight               # every Sybil pushes the target

    gossip = np.vstack([honest_pos, sybil]).astype(np.float32)
    is_sybil = np.zeros(n_honest + m, dtype=bool)
    is_sybil[n_honest:] = True
    return Injection(gossip, n_honest, m, target, is_sybil)


def foolsgold(contrib: np.ndarray, confidence: float = 1.0) -> np.ndarray:
    """FoolsGold per-node weights (Fung et al., RAID 2020), §7.4.

    Returns alpha in [0, 1] per node: ~1 for nodes with diverse contribution
    vectors, ~0 for a tightly-coordinated (mutually-similar) group. Includes the
    pardoning step (don't over-penalise an honest node that merely resembles a
    Sybil) and the logit confidence rescaling.
    """
    n = contrib.shape[0]
    norm = np.sqrt((contrib * contrib).sum(1)) + _EPS
    cn = (contrib / norm[:, None]).astype(np.float32)
    if _sp is not None and cn.size and np.count_nonzero(cn) / cn.size < 0.25:
        cs_sp = _sp.csr_matrix(cn)
        cs = np.asarray((cs_sp @ cs_sp.T).todense(), dtype=np.float64)
    else:
        cs = (cn @ cn.T).astype(np.float64)
    np.fill_diagonal(cs, 0.0)

    v = cs.max(1)                                  # max similarity per node
    # pardoning: scale cs[i,j] down when j is more suspicious than i (v[j] > v[i])
    ratio = np.where(v[None, :] > _EPS, v[:, None] / (v[None, :] + _EPS), 1.0)
    pardon = (v[None, :] > v[:, None])
    cs = np.where(pardon, cs * np.minimum(1.0, ratio), cs)

    alpha = 1.0 - cs.max(1)
    alpha = np.clip(alpha, 0.0, 1.0)
    mx = alpha.max()
    if mx > 0:
        alpha = alpha / mx                         # rescale so the most-trusted -> 1
    alpha = np.clip(alpha, _EPS, 1.0 - _EPS)
    # logit rescaling: sharpen the separation between honest (~1) and Sybil (~0)
    alpha = confidence * (np.log(alpha / (1.0 - alpha)) + 0.5)
    return np.clip(alpha, 0.0, 1.0).astype(np.float32)
