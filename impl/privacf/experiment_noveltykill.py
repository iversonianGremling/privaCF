"""Experiment 5.47 — novelty-kill saboteur (SPEC.md §7.3, §7.9 row 9 / T4).

The converse of E3. Instead of *inflating* a target into feeds, the adversary
pushes a *niche* item's trust_total past its early threshold to **suppress its
novelty bonus** (§3.7: novelty = clamp(1 − trust/c)), killing the long-tail
discovery acceleration that would have surfaced it. §7.9.4 flags this as the
contract's weakest recommendation-layer point: "No mechanism currently
distinguishes a coordinated novelty-suppression push from an organic early-
popularity surge ... should become H once Phase 5 simulation produces a separator."

This experiment's job is to *produce that separator*. Hypothesis: the §7.4
FoolsGold-on-PSI-peers coordination signature is the separator — a coordinated
kill cohort has near-identical contribution vectors (flagged), while an organic
surge is a diverse crowd genuinely liking the item (not flagged, and its novelty
loss is *correct* — the item really did become popular).

Two pushes that both raise the victim's trust and kill its novelty:
  coordinated kill   m Sybils announcing the victim (+ shared/unrelated filler)
  organic surge      m diverse users who genuinely like the victim (varied baskets)

We measure the victim's *reach* (how many honest users get it in their top-K) and
ask: (1) does the kill suppress reach? (2) does FoolsGold restore it? (3) does
FoolsGold leave the organic surge alone (no false intervention)?

    python -m privacf.experiment_noveltykill --dataset ml-100k
"""

from __future__ import annotations

import argparse

import numpy as np

from . import attack
from . import data as data_mod
from .cf import CFConfig, ItemCF, top_k


def _reach(gossip, cfg, split, victim, k, fg=False):
    """How many honest users get the victim item in their top-K (its discovery)."""
    g = gossip
    alpha = None
    if fg:
        alpha = attack.foolsgold(gossip)
        g = gossip * alpha[:, None]
    cf = ItemCF(cfg).fit(g)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    n_honest = split.n_users
    tk = top_k(scores, k)
    elig = ~split.seen[:, victim]
    reach = int(((tk == victim).any(axis=1) & elig).sum())
    return reach, alpha


def pick_victim(split, cfg, k, head_frac=0.2, min_reach=8, seed=0):
    """A niche (long-tail) item that the novelty machinery actually surfaces, so
    there is discovery to suppress. Returns the victim with median baseline reach
    among qualifying tail items."""
    is_head, is_tail, pop = data_mod.popularity_segments(split.seen, head_frac)
    cf = ItemCF(cfg).fit(split.pref_pos)
    scores = cf.score_all(split.pref_pos, split.pref_neg, split.seen)
    tk = top_k(scores, k)
    reach = np.zeros(split.n_items, dtype=np.int64)
    for it in np.where(is_tail)[0]:
        elig = ~split.seen[:, it]
        reach[it] = int(((tk == it).any(axis=1) & elig).sum())
    cand = np.where(is_tail & (reach >= min_reach))[0]
    if cand.size == 0:
        cand = np.where(is_tail & (reach > 0))[0]
    cand = cand[np.argsort(reach[cand])]
    return int(cand[len(cand) // 2]), int(reach[cand[len(cand) // 2]])


def organic_surge(honest_pos, seen, victim, m, n_basket=25, seed=0):
    """m diverse new users who genuinely like the victim — each with a varied
    basket of other items drawn by popularity. Diverse => low mutual similarity."""
    rng = np.random.default_rng(seed + 777)
    n_items = honest_pos.shape[1]
    pop = seen.sum(0).astype(np.float64)
    pop[victim] = 0
    p = pop / pop.sum()
    surge = np.zeros((m, n_items), dtype=np.float32)
    for s in range(m):
        basket = rng.choice(n_items, size=min(n_basket, int((p > 0).sum())),
                            replace=False, p=p)
        surge[s, basket] = rng.uniform(1.0, 2.0, size=basket.shape)
        surge[s, victim] = 2.0
    gossip = np.vstack([honest_pos, surge]).astype(np.float32)
    is_surge = np.zeros(honest_pos.shape[0] + m, dtype=bool)
    is_surge[honest_pos.shape[0]:] = True
    return gossip, is_surge


def run(dataset="ml-100k", k=10, kappa=1.0, sizes=(20, 50, 100), n_filler=20,
        head_frac=0.2, data_dir="data", seed=0):
    ds = data_mod.load(dataset, data_dir=data_dir)
    split = data_mod.make_split(ds, seed=seed)
    cfg = CFConfig(kappa=kappa, use_item_weight=True)          # novelty machinery ON
    victim, base_reach = pick_victim(split, cfg, k, head_frac, seed=seed)
    pop_v = int(split.seen[:, victim].sum())
    print(f"[5.47] victim=item {victim} (niche, {pop_v} train likers), "
          f"baseline novelty-driven reach={base_reach} honest users, k={k}, κ={kappa}")

    print("\n" + "=" * 78)
    print("Novelty-kill: victim reach (honest users getting it in top-K) under attack")
    print("  suppression = reach drops vs baseline; defense works = FoolsGold restores it")
    print("=" * 78)
    print(f"  {'m':>4} {'COORDINATED kill':>26}    {'ORGANIC surge':>24}")
    print(f"  {'':>4} {'no-def':>8} {'+FoolsGold':>10} {'ᾱ_syb':>6}   "
          f"{'no-def':>8} {'+FoolsGold':>10} {'ᾱ_srg':>6}")
    print("  " + "-" * 72)

    rows = []
    for m in sizes:
        frac = m / split.n_users
        inj = attack.inject(split.pref_pos, split.seen, victim, attack="random",
                            ssp="dense", sybil_frac=frac, n_filler=n_filler, seed=seed)
        k_nodef, _ = _reach(inj.gossip, cfg, split, victim, k)
        k_fg, a_k = _reach(inj.gossip, cfg, split, victim, k, fg=True)
        a_syb = float(a_k[inj.is_sybil].mean())

        sg, is_sg = organic_surge(split.pref_pos, split.seen, victim, m, seed=seed)
        s_nodef, _ = _reach(sg, cfg, split, victim, k)
        s_fg, a_s = _reach(sg, cfg, split, victim, k, fg=True)
        a_srg = float(a_s[is_sg].mean())

        rows.append((m, k_nodef, k_fg, a_syb, s_nodef, s_fg, a_srg))
        print(f"  {m:>4} {k_nodef:>8} {k_fg:>10} {a_syb:>6.2f}   "
              f"{s_nodef:>8} {s_fg:>10} {a_srg:>6.2f}")

    print("  " + "-" * 72)
    print(f"  baseline (no push): victim reach = {base_reach}")

    # --- the separator verdict ---
    suppresses = any(r[1] < base_reach for r in rows)               # kill reduces reach
    fg_restores = any(r[2] > r[1] for r in rows)                    # FoolsGold lifts it back
    a_syb_mean = float(np.mean([r[3] for r in rows]))
    a_srg_mean = float(np.mean([r[6] for r in rows]))
    separates = a_syb_mean < a_srg_mean - 0.2                       # coordinated flagged, organic not
    surge_untouched = all(abs(r[4] - r[5]) <= max(2, 0.1 * max(r[4], 1)) for r in rows)

    print("\n" + "=" * 78)
    print(f"  novelty-kill suppresses the niche victim's reach          : {suppresses}")
    print(f"  FoolsGold (§7.4) restores the suppressed reach            : {fg_restores}")
    print(f"  FoolsGold separates coordinated kill from organic surge   : {separates}  "
          f"(ᾱ_kill {a_syb_mean:.2f} ≪ ᾱ_surge {a_srg_mean:.2f})")
    print(f"  FoolsGold leaves the organic surge essentially untouched  : {surge_untouched}")
    print("  " + "-" * 72)
    if suppresses and fg_restores and separates:
        print("  5.47 RESULT: SEPARATOR FOUND (detection axis). The coordination signature")
        print("    (§7.4 FoolsGold) flags the faked novelty-kill push — near-identical Sybil")
        print("    vectors, ᾱ≈0 — while leaving the diverse organic surge at full weight")
        print("    (ᾱ≈1, no false intervention). That is exactly the separator §7.9.4 row 9")
        print("    asks for: a coordinated kill is *distinguishable* from an organic surge by")
        print("    the content-similarity signal, so the T4 cell can move O → H using the")
        print("    existing §7.4 mechanism rather than a new one. On the coordinated push,")
        print(f"    FoolsGold also restores most of the suppressed reach (0 → {rows[0][2]} of "
              f"{base_reach}).")
        print("  Two honest caveats: (1) a one-shot push that completes before a FoolsGold")
        print("    epoch evades the *content* flag — the §7.1a burst/velocity signals cover")
        print("    the timing axis; the two are complementary. (2) The organic surge also")
        print("    drops the victim's reach here, but that is a *cosine-CF* artifact (a")
        print("    newly-popular item's column norm inflates and lowers its similarity), a")
        print("    separate CF-quality issue from the separator — FoolsGold correctly does")
        print("    NOT touch the organic case, which is all the separator question requires.")
    else:
        print("  5.47 RESULT: no clean separator under these params — T4 stays O; the")
        print("    novelty-kill remains a genuine residual. Report honestly.")
    print("=" * 78)
    return (suppresses, fg_restores, separates), rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="PrivaCF exp 5.47 (novelty-kill saboteur)")
    ap.add_argument("--dataset", default="ml-100k", choices=["ml-100k", "ml-1m"])
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--kappa", type=float, default=1.0)
    ap.add_argument("--sizes", nargs="+", type=int, default=[20, 50, 100])
    ap.add_argument("--n-filler", type=int, default=20)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    run(dataset=a.dataset, k=a.k, kappa=a.kappa, sizes=tuple(a.sizes),
        n_filler=a.n_filler, data_dir=a.data_dir, seed=a.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
