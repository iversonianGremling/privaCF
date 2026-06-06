"""Temporal dynamics — reputation over epochs and trust_total accumulation.

Everything in E1-E4 was a single snapshot. The protocol's load-bearing temporal
claims were argued only structurally:

  * the asymmetric reputation penalty and its on-off tension (§7.2, §8.2 T1,
    Phase-5 experiment 5.4)
  * trust_total has no autonomous oscillation and only passively tracks an
    exogenous reputation cycle (§7.3 / OQ-15)

This module implements the faithful per-epoch update so those claims can be run.

Reputation update (per epoch T), from §7.2 asymmetric penalty + §6.1 slow decay:

    active(T):   r_T = min(r_{T-1} + Δ_rise, BAND_MAX)     # climb / maintain
    absent(T):   r_T = min(r_{T-1}, BAND_1)                # snap to BAND_1 (the cliff)
    always:      r_T = clamp(r_T − δ_decay, 0, BAND_MAX)   # universal slow decay

The asymmetry is the whole point: one absence drops you to BAND_1 instantly, but
recovery is linear at Δ_rise/epoch. Δ_rise too small punishes honest absence; too
large lets an on-off adversary regain reputation cheaply (§8.2 T1).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class RepConfig:
    delta_rise: float = 0.5     # Δ_rise: reputation gained per active epoch (§7.2)
    delta_decay: float = 0.05   # δ_decay: universal slow decay per epoch (§6.1)
    band_1: float = 1.0         # BAND_1: the floor an absence snaps you to
    band_max: float = 4.0       # BAND_MAX: top score band (§6.1 bands 1-4)


def simulate_reputation(active: np.ndarray, cfg: RepConfig,
                        r0: float | None = None,
                        snap_on_absence: bool = True) -> np.ndarray:
    """Reputation trajectory for a per-epoch activity schedule (bool array).

    Two distinct spec mechanisms erode reputation, and which one absence triggers
    is the crux of the on-off analysis:

      * §6.1 universal slow decay  − δ_decay every epoch (always applied)
      * §7.2 asymmetric penalty    r ← min(r, BAND_1)   (a hard cliff)

    `snap_on_absence=True` treats every absent epoch as a §7.2 cliff (the harshest
    reading — what the first temporal pass used). `snap_on_absence=False` is the
    faithful reading for the on-off adversary: merely going *quiet* is not a
    violation, so absence costs only the slow δ_decay, and the BAND_1 snap is
    reserved for an actual detected violation. The on-off attack should be analysed
    under the faithful (decay) model; the snap model over-punishes honest absence
    and manufactures a spurious knife-edge.
    """
    r = cfg.band_max if r0 is None else r0
    out = np.empty(active.shape[0], dtype=np.float64)
    for t, on in enumerate(active):
        if on:
            r = min(r + cfg.delta_rise, cfg.band_max)
        elif snap_on_absence:
            r = min(r, cfg.band_1)                       # §7.2 cliff (violation reading)
        r = min(max(r - cfg.delta_decay, 0.0), cfg.band_max)
        out[t] = r
    return out


def recovery_after_absence(cfg: RepConfig, absence_len: int, target: float,
                           settle: int = 500) -> float:
    """Epochs to climb back to `target` band after an *extended* absence of
    `absence_len` epochs (the realistic honest concern under the faithful decay
    model — a single missed epoch is nearly free, but a long downtime is not)."""
    sched = np.ones(absence_len + settle, dtype=bool)
    sched[:absence_len] = False
    r = simulate_reputation(sched, cfg, r0=cfg.band_max, snap_on_absence=False)
    after = np.where(r[absence_len:] >= target)[0]
    return float(after[0]) if after.size else float("inf")


def recovery_epochs(cfg: RepConfig, target: float, settle: int = 200) -> float:
    """Epochs for a fully-reputable node to climb back to `target` band after a
    single absence (the honest-UX cost of the asymmetric penalty)."""
    sched = np.ones(settle + 2, dtype=bool)
    sched[0] = False                                     # one legitimate absence at t=0
    r = simulate_reputation(sched, cfg, r0=cfg.band_max)
    hit = np.where(r[1:] >= target)[0]
    return float(hit[0] + 1) if hit.size else float("inf")


def onoff_schedule(n_epochs: int, k_on: int, k_off: int) -> np.ndarray:
    """Repeating on-off duty cycle: k_on active epochs then k_off absent."""
    period = max(1, k_on + k_off)
    phase = np.arange(n_epochs) % period
    return phase < k_on


def random_active(n_epochs: int, frac: float, rng) -> np.ndarray:
    """Legitimately-intermittent node: `frac` of epochs active at random positions."""
    k = int(round(frac * n_epochs))
    sched = np.zeros(n_epochs, dtype=bool)
    sched[rng.choice(n_epochs, size=k, replace=False)] = True
    return sched


def best_onoff_avg_rep(cfg: RepConfig, activity_frac: float, n_epochs: int = 400,
                       warmup: int = 100):
    """Best average reputation an on-off adversary can sustain at a target activity
    fraction, optimising the duty cycle (k_on, k_off). Returns (avg_rep, (k_on,k_off))."""
    best, best_kk = -1.0, (1, 1)
    for total in range(2, 21):                           # search cycle lengths 2..20
        k_on = max(1, int(round(activity_frac * total)))
        k_off = total - k_on
        if k_off < 1 or abs(k_on / total - activity_frac) > 0.08:
            continue
        sched = onoff_schedule(n_epochs, k_on, k_off)
        r = simulate_reputation(sched, cfg)
        avg = float(r[warmup:].mean())                   # steady-state average
        if avg > best:
            best, best_kk = avg, (k_on, k_off)
    return best, best_kk


def trust_total_trajectory(announcer_active: np.ndarray, reputation: np.ndarray,
                           base_contrib: np.ndarray, c: float, lam: float = 0.6,
                           cap: bool = True) -> np.ndarray:
    """trust_total(X) over epochs with §7.2 temporal-depth λ-decay and reputation
    weighting. announcer_active/reputation are [n_announcers, n_epochs];
    base_contrib is the per-announcer base weight for the item.

    tt(T) = λ·tt(T−1) + Σ_v active(v,T)·reputation(v,T)·base_contrib(v),  capped at c.

    The λ-decay makes tt a *responsive* readout (not a pure monotone accumulator),
    so an on-off announcer genuinely perturbs it — which is exactly the setting in
    which §7.3 claims tt tracks but cannot amplify the exogenous cycle.
    """
    n_v, T = announcer_active.shape
    tt = 0.0
    out = np.empty(T, dtype=np.float64)
    for t in range(T):
        inflow = float((announcer_active[:, t] * reputation[:, t] * base_contrib).sum())
        tt = lam * tt + inflow
        if cap:
            tt = min(tt, c)
        out[t] = tt
    return out
