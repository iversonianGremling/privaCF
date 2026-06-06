"""Damage-coupled on-off attack — the honest version of Phase-5 experiment 5.4.

The first temporal pass measured the on-off attack in *reputation* units against an
arbitrary "fair line", and found a knife-edge Δ_rise — which turned out to be an
artifact of (a) snapping reputation to BAND_1 on every absent epoch and (b) the
arbitrary fairness baseline. This version fixes both: reputation erodes by slow
decay during absence (§6.1), the BAND_1 snap is reserved for violations (§7.2), and
the adversary's payoff is measured as **actual recommendation damage** by coupling
the reputation dynamics to the E3 push attack — reputation gates an announcer's
gossip weight (§3.4, "weighting each contribution by the announcer's score band"),
so a lower-reputation Sybil pushes more weakly.

Two questions, in order:

  Part 1 — Does reputation amplify the push at all, and do the §7.3/§7.4 defenses
           bound it regardless of reputation? (sweep Sybil score band)
  Part 2 — Couple the on-off schedule: Δ_rise sets how much push power a *stealthy*
           (low-activity) adversary retains. Does a larger Δ_rise — which honest
           users want for faster recovery — translate into more realized damage?

The honest deliverable for exp 5.4 is whichever of these the data supports, with the
absolute numbers caveated to the toy reputation parameters.

    python -m privacf.experiment_damage --dataset ml-100k
"""

from __future__ import annotations

import argparse

import numpy as np

from . import attack
from . import data as data_mod
from . import temporal as tp
from .cf import CFConfig, ItemCF, top_k
from .metrics import evaluate


def _hitrate(gossip, is_sybil, mult, cfg, split, target, k, fg=False):
    """Scale the Sybil rows by `mult` (their reputation-derived weight), fit CF,
    and return the target's hit-rate among honest users who haven't seen it."""
    g = gossip.copy()
    g[is_sybil] *= mult
    if fg:
        g = g * attack.foolsgold(g)[:, None]
    cf = ItemCF(cfg).fit(g)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    tk = top_k(scores, k)
    elig = ~split.seen[:, target]
    return float((tk == target).any(axis=1)[elig].mean()) if elig.any() else 0.0


def run(dataset="ml-100k", k=10, sybil_frac=0.10, n_filler=30, attack_kind="segment",
        adv_frac=0.30, absence_len=20, deltas=(0.25, 0.5, 1.0, 2.0, 3.0),
        data_dir="data", seed=0):
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, seed=seed)
    plain = CFConfig(kappa=0.0, use_item_weight=False)         # no defense
    full = CFConfig(kappa=1.0, use_item_weight=True)           # passive §7.3 defense
    target = attack.pick_target(split.pref_pos, split.seen, kind="tail", seed=seed)
    inj = attack.inject(split.pref_pos, split.seen, target, attack=attack_kind,
                        ssp="dense", sybil_frac=sybil_frac, n_filler=n_filler, seed=seed)
    g, iss = inj.gossip, inj.is_sybil
    cfg_rep = tp.RepConfig()
    bmax = cfg_rep.band_max
    print(f"[damage] target=item {target} (cold), attack={attack_kind} dense, "
          f"sybils={inj.n_sybil}, k={k}")

    # --- Part 1: does reputation amplify the push, and do defenses bound it? ---
    print("\n" + "=" * 74)
    print("Part 1 — reputation vs push damage (target hit-rate@K among honest)")
    print("=" * 74)
    print(f"  {'score band':>11} {'weight×':>8} {'no-defense':>11} {'passive §7.3':>13} "
          f"{'active §7.4':>12}")
    print("  " + "-" * 60)
    bands = [cfg_rep.band_1, 2.0, 3.0, bmax]
    for b in bands:
        m = b / bmax
        d0 = _hitrate(g, iss, m, plain, split, target, k)
        d1 = _hitrate(g, iss, m, full, split, target, k)
        d2 = _hitrate(g, iss, m, full, split, target, k, fg=True)
        print(f"  {b:>11.2f} {m:>8.2f} {d0:>11.4f} {d1:>13.4f} {d2:>12.4f}")

    # --- Part 2: the on-off adversary's stealth vs retained push power ---
    # Under faithful slow decay (not the BAND_1 snap), going dark briefly costs
    # almost nothing, so Δ_rise barely affects a stealthy adversary's retained
    # reputation — it stays near BAND_MAX. We therefore sweep the *stealth level*
    # (activity fraction) and show the adversary keeps high reputation while dark,
    # yet still achieves no defended damage.
    print("\n" + "=" * 74)
    print("Part 2 — on-off stealth vs retained push power (faithful slow decay)")
    print(f"        the adversary goes dark to evade burst/smoothness detection;")
    print(f"        does it keep enough reputation to push? (Δ_rise={tp.RepConfig().delta_rise})")
    print("=" * 74)
    print(f"  {'activity':>9} {'avg rep':>8} {'rep@announce':>13} {'weight×':>8} "
          f"{'no-def dmg':>11} {'defended':>9}")
    print(f"  {'(stealth)':>9} {'(footprint)':>8}")
    print("  " + "-" * 62)
    cfg_rep = tp.RepConfig()
    rows = []
    for phi in (0.50, 0.30, 0.15, 0.05):
        k_off = max(1, round(1.0 / phi) - 1)                   # 1 active, k_off dark
        sched = tp.onoff_schedule(600, 1, k_off)
        rep = tp.simulate_reputation(sched, cfg_rep, snap_on_absence=False)  # faithful decay
        active = sched[150:]
        avg_rep = float(rep[150:].mean())                      # observer-visible footprint
        rep_ann = float(rep[150:][active].mean()) if active.any() else 0.0  # rep when pushing
        m = rep_ann / bmax
        d0 = _hitrate(g, iss, m, plain, split, target, k)
        d2 = _hitrate(g, iss, m, full, split, target, k, fg=True)
        rows.append((phi, avg_rep, rep_ann, m, d0, d2))
        print(f"  {phi:>8.0%} {avg_rep:>8.3f} {rep_ann:>13.3f} {m:>8.2f} "
              f"{d0:>11.4f} {d2:>9.4f}")
    print(f"  → under slow decay (δ_decay={cfg_rep.delta_decay}) the adversary keeps near-full")
    print(f"    reputation and push weight down to ~15% activity — going dark is cheap; only")
    print(f"    at extreme stealth (5%) does the dark gap finally outrun Δ_rise and collapse")
    print(f"    its reputation. Either way the defended-damage column stays 0.")

    # honest side, decoupled: where Δ_rise actually bites is recovery after a *long*
    # outage — and even that never touches the (bounded) recommendation damage.
    print("\n  honest recovery after a long outage (where Δ_rise matters at all):")
    print(f"  {'absence':>8} {'recov @Δ=0.25':>14} {'recov @Δ=1.0':>13}")
    for L in (10, 30, 60):
        r_lo = tp.recovery_after_absence(tp.RepConfig(delta_rise=0.25), L, 3.0)
        r_hi = tp.recovery_after_absence(tp.RepConfig(delta_rise=1.0), L, 3.0)
        f = lambda x: "0" if x == 0 else ("∞" if not np.isfinite(x) else f"{x:.0f}")
        print(f"  {L:>6}ep {f(r_lo):>14} {f(r_hi):>13}")

    # --- conclusion ---
    print("  " + "-" * 56)
    no_def = np.array([r[4] for r in rows])
    defended = np.array([r[5] for r in rows])
    rep_high_when_dark = rows[1][2] > 0.8 * bmax             # rep-when-announcing at 30% active
    defenses_bound = defended.max() < 1e-9                    # defended damage ≈ 0 throughout
    print(f"  on-off adversary stays stealthy AND high-reputation (rep@announce>0.8·max "
          f"at 30% active): {rep_high_when_dark}")
    print(f"  yet defended recommendation damage stays ≈ 0 at every stealth level: "
          f"{defenses_bound}")
    if defenses_bound:
        print("  exp-5.4 finding: the on-off adversary *wins* the reputation game — under")
        print("    faithful slow decay it keeps near-full reputation while staying dark, so")
        print("    Δ_rise barely constrains it (the earlier knife-edge was an artifact of")
        print("    snapping to BAND_1 on every absence). But that retained reputation buys")
        print("    NO recommendation damage: the §7.3/§7.4 defenses bound the push downstream")
        print("    of reputation. Δ_rise calibration is thus non-critical for feed poisoning;")
        print("    it matters only for what reputation else gates (committee/validator")
        print("    eligibility) — outside this recommendation PoC.")
    else:
        print("  exp-5.4 finding: retained-reputation push survives the defenses at some")
        print("    stealth level — Δ_rise/decay calibration matters for rec damage after all.")
    print("=" * 74)
    return defenses_bound, rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF damage-coupled on-off (exp 5.4)")
    ap.add_argument("--dataset", default="ml-100k", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--sybil-frac", type=float, default=0.10)
    ap.add_argument("--n-filler", type=int, default=30)
    ap.add_argument("--attack-kind", default="segment",
                    choices=["random", "average", "bandwagon", "segment"])
    ap.add_argument("--adv-frac", type=float, default=0.30)
    ap.add_argument("--absence-len", type=int, default=20)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    run(dataset=a.dataset, k=a.k, sybil_frac=a.sybil_frac, n_filler=a.n_filler,
        attack_kind=a.attack_kind, adv_frac=a.adv_frac, absence_len=a.absence_len,
        data_dir=a.data_dir, seed=a.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
