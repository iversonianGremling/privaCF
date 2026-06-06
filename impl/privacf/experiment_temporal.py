"""Temporal experiments — the time-dependent claims the static PoC couldn't test.

Test A — trust_total convergence and non-amplification (§7.3 / OQ-15).
    Run trust_total(X) over epochs. Show (i) for fixed inputs it converges to a
    fixed point with no oscillation, and (ii) when driven by an on-off announcer it
    *tracks* the exogenous reputation cycle but never amplifies it (peak under
    on-off ≤ peak under always-on; no growing oscillation). This is the empirical
    counterpart of the structural argument in §7.3.

Test B — on-off attack and the Δ_rise tension (§7.2, §8.2 T1, Phase-5 exp 5.4).
    Sweep Δ_rise. Report the honest-UX cost (epochs to recover reputation after a
    single legitimate absence) against the adversary's gain (extra average
    reputation an on-off gamer extracts over an equally-active honest node). These
    move in opposite directions, so this *is* the tradeoff curve experiment 5.4
    asks governance to choose a point on.

    python -m privacf.experiment_temporal
"""

from __future__ import annotations

import argparse

import numpy as np

from . import temporal as tp


def test_convergence(n_epochs=120, n_announcers=40, c=50.0, lam=0.6, seed=0):
    rng = np.random.default_rng(seed)
    base = rng.uniform(0.5, 1.5, size=n_announcers)
    print("=" * 74)
    print("Test A — trust_total convergence & non-amplification (§7.3 / OQ-15)")
    print("=" * 74)

    # (i) fixed inputs: all announcers always active, fixed reputation -> fixed point
    active = np.ones((n_announcers, n_epochs), dtype=bool)
    rep = np.full((n_announcers, n_epochs), 3.0)
    tt_fixed = tp.trust_total_trajectory(active, rep, base, c, lam)
    tail = tt_fixed[-20:]
    converged = tail.std() < 1e-6
    # monotone non-decreasing on the way up (no overshoot/oscillation)
    monotone = np.all(np.diff(tt_fixed) >= -1e-9)
    print(f"  (i) fixed inputs  -> fixed point {tt_fixed[-1]:.4f} "
          f"(cap c={c}), settled std={tail.std():.2e}, monotone-up={monotone}")

    # (ii) one announcer driven by an on-off reputation cycle (the exogenous driver)
    rep_on = np.full((n_announcers, n_epochs), 3.0)
    cyc = tp.onoff_schedule(n_epochs, k_on=3, k_off=3)          # 50% duty, period 6
    rep_on[0] = np.where(cyc, 3.0, 0.0)                          # announcer 0 cycles
    act_on = np.ones((n_announcers, n_epochs), dtype=bool)
    act_on[0] = cyc
    tt_onoff = tp.trust_total_trajectory(act_on, rep_on, base, c, lam)

    # amplification check: does the on-off case ever exceed the always-on ceiling?
    peak_ratio = tt_onoff.max() / tt_fixed.max()
    # oscillation envelope is bounded & non-growing (compare first half-cycles to last)
    osc = tt_onoff[-40:]
    amp_late = osc.max() - osc.min()
    amp_early = (tt_onoff[40:80].max() - tt_onoff[40:80].min())
    non_growing = amp_late <= amp_early + 1e-6
    print(f"  (ii) on-off driver -> tt tracks the cycle, peak ratio vs always-on "
          f"= {peak_ratio:.3f} (≤1 ⇒ no amplification)")
    print(f"       oscillation envelope non-growing: {non_growing} "
          f"(amp early {amp_early:.3f} -> late {amp_late:.3f})")
    passed = converged and monotone and peak_ratio <= 1.0 + 1e-6 and non_growing
    print(f"  RESULT = {'PASS ✅' if passed else 'FAIL ❌'}  "
          f"(converges, no oscillation, tracks-but-cannot-amplify)")
    print()
    return passed


def test_onoff_tension(deltas=(0.25, 0.5, 1.0, 1.5, 2.0, 3.0), adv_frac=0.30,
                       n_epochs=400, max_recovery=6, seed=0):
    print("=" * 74)
    print("Test B — on-off attack & Δ_rise tension (§8.2 T1 / Phase-5 exp 5.4)")
    print(f"        on-off adversary active {adv_frac:.0%} of epochs; an honest")
    print(f"        always-on node earns BAND_MAX per unit activity (the fair line)")
    print("=" * 74)
    print(f"  {'Δ_rise':>7} {'honest recovery':>16} {'adv rep':>8} "
          f"{'adv rep/activity':>17} {'exploit×fair':>13}")
    print("  " + "-" * 66)

    rows = []
    for d in deltas:
        cfg = tp.RepConfig(delta_rise=d)
        rec = tp.recovery_epochs(cfg, target=3.0)              # honest UX: epochs to BAND_3
        adv_avg, kk = tp.best_onoff_avg_rep(cfg, adv_frac, n_epochs)
        efficiency = adv_avg / adv_frac                        # reputation per unit work
        exploit = efficiency / cfg.band_max                    # vs an honest always-on node
        rows.append((d, rec, adv_avg, efficiency, exploit))
        rec_s = "∞" if rec == float("inf") else f"{rec:.0f} epochs"
        flag = "  ← exploit" if exploit > 1.0 else ""
        print(f"  {d:>7.2f} {rec_s:>16} {adv_avg:>8.3f} {efficiency:>17.3f} "
              f"{exploit:>12.2f}×{flag}")

    print("  " + "-" * 66)
    recs = np.array([r[1] if np.isfinite(r[1]) else 1e9 for r in rows])
    exploits = np.array([r[4] for r in rows])
    # the tension: as Δ_rise rises, honest recovery improves (↓) but the adversary's
    # reputation-per-unit-work rises (↑) and eventually exceeds the honest fair line.
    tension = recs[0] > recs[-1] and exploits[-1] > exploits[0]
    viable = [r for r in rows if r[1] <= max_recovery and r[4] <= 1.0]
    print(f"  tension confirmed (recovery↓ while exploit×fair↑ as Δ_rise↑): {tension}")
    if viable:
        lo = min(v[0] for v in viable)
        hi = max(v[0] for v in viable)
        v0 = viable[0]
        print(f"  viable band: Δ_rise∈[{lo:.2f},{hi:.2f}] — recovery ≤ {max_recovery} "
              f"epochs AND adversary stays ≤ fair line")
        print(f"  exp-5.4 result: a single Δ_rise CAN satisfy both, but the band is "
              f"{'narrow' if lo == hi else 'bounded'} (≈{v0[0]:.2f}: recovery {v0[1]:.0f} "
              f"epochs, exploit {v0[4]:.2f}×) — calibrate carefully")
    else:
        print(f"  NO Δ_rise meets recovery ≤ {max_recovery} AND exploit ≤ fair line")
        print(f"  exp-5.4 result: governance must pick a point on the tradeoff (§8.2 T1)")
    print()
    return tension


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF temporal experiments")
    ap.add_argument("--adv-frac", type=float, default=0.30)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    a_ok = test_convergence(seed=a.seed)
    b_ok = test_onoff_tension(adv_frac=a.adv_frac, seed=a.seed)
    print("=" * 74)
    print(f"  Test A (OQ-15 convergence)     : {'PASS ✅' if a_ok else 'FAIL ❌'}")
    print(f"  Test B (exp 5.4 tension shown) : {'PASS ✅' if b_ok else 'FAIL ❌'}")
    print("=" * 74)
    return 0 if (a_ok and b_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
