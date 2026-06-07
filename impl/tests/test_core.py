"""Unit tests for the PrivaCF E1 core — runnable without pytest.

    python -m tests.test_core      # from impl/
    pytest impl/tests              # if pytest is available
"""

from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from privacf.baseline import Popularity  # noqa: E402
from privacf.cf import CFConfig, ItemCF, top_k  # noqa: E402
from privacf.metrics import _dcg, evaluate  # noqa: E402


def test_cosine_similarity_matches_definition():
    # two users, three items; item0 and item1 perfectly co-occur, item2 differs
    gossip = np.array([[1.0, 1.0, 0.0],
                       [2.0, 2.0, 3.0]], dtype=np.float32)
    cf = ItemCF(CFConfig(kappa=0.0, use_item_weight=False)).fit(gossip)
    s = cf.sim
    assert s.shape == (3, 3)
    assert np.allclose(np.diag(s), 0.0)               # zeroed diagonal
    assert s[0, 1] > 0.999                            # identical columns -> ~1
    assert s[0, 1] >= s[0, 2]                         # co-occurring more similar
    assert np.allclose(s, s.T, atol=1e-6)             # symmetric


def test_novelty_clamped_and_inversely_tracks_trust():
    # popular item (col 0) should have low novelty, rare item (col 1) high novelty
    gossip = np.zeros((50, 2), dtype=np.float32)
    gossip[:, 0] = 1.0      # everyone likes item 0  -> high trust_total
    gossip[:3, 1] = 1.0     # few like item 1         -> low trust_total
    cf = ItemCF(CFConfig(c_percentile=50.0)).fit(gossip)
    assert (cf.novelty >= 0).all() and (cf.novelty <= 1).all()
    assert cf.novelty[1] > cf.novelty[0]


def test_dsybil_cap_bounds_trust_total():
    gossip = np.ones((100, 1), dtype=np.float32)      # raw trust_total = 100
    cf = ItemCF(CFConfig(c=10.0)).fit(gossip)
    assert cf.effective_trust[0] <= 10.0 + 1e-6       # capped at c


def test_item_weight_is_idf_like_monotone():
    # higher effective trust -> smaller item_weight (IDF damping, §3.4)
    gossip = np.zeros((100, 2), dtype=np.float32)
    gossip[:, 0] = 1.0
    gossip[:10, 1] = 1.0
    cf = ItemCF(CFConfig(c=100.0)).fit(gossip)
    assert cf.item_weight[0] < cf.item_weight[1]


def test_dislike_penalty_lowers_score():
    gossip = np.array([[1.0, 1.0, 0.0],
                       [1.0, 1.0, 1.0]], dtype=np.float32)
    cf = ItemCF(CFConfig(kappa=0.0, use_item_weight=False,
                         dislike_penalty=5.0)).fit(gossip)
    pos = np.array([[1.0, 0.0, 0.0]], dtype=np.float32)   # user liked item 0
    neg = np.zeros((1, 3), dtype=np.float32)
    seen = np.array([[True, False, False]])
    s_no = cf.score_all(pos, neg, seen)
    neg2 = np.array([[0.0, 0.0, 1.0]], dtype=np.float32)  # user dislikes item 2
    s_yes = cf.score_all(pos, neg2, seen)
    # item 1 is similar to disliked item 2 via user-2 co-occurrence -> penalised
    assert s_yes[0, 1] <= s_no[0, 1] + 1e-6


def test_top_k_orders_by_score_and_excludes_seen():
    scores = np.array([[0.5, -np.inf, 0.9, 0.1]], dtype=np.float32)
    tk = top_k(scores, 2)
    assert tk.tolist() == [[2, 0]]                    # 0.9 then 0.5, seen excluded


def test_dcg_and_ndcg_perfect_and_zero():
    assert _dcg(np.array([1.0, 1.0])) > _dcg(np.array([0.0, 1.0]))
    topk = np.array([[0, 1, 2]])                      # recommended items
    test_pos = [np.array([0, 1])]                     # both correct, top-ranked
    r = evaluate(topk, test_pos, k=2)
    assert abs(r.ndcg - 1.0) < 1e-9                   # perfect ranking
    assert abs(r.precision - 1.0) < 1e-9
    assert abs(r.recall - 1.0) < 1e-9
    r0 = evaluate(np.array([[5, 6, 7]]), [np.array([0, 1])], k=2)
    assert r0.precision == 0.0 and r0.hit_rate == 0.0


def test_segment_evaluation_restricts_targets():
    topk = np.array([[0, 1]])
    test_pos = [np.array([0, 1])]
    is_tail = np.array([False, True, False])          # only item 1 is tail
    r = evaluate(topk, test_pos, k=2, item_subset=is_tail)
    assert r.n_users == 1 and r.recall == 1.0         # the one tail target was hit


def test_popularity_prefers_frequent_items():
    seen = np.array([[True, False, True],
                     [True, False, False],
                     [True, True, False]])
    pop = Popularity().fit(seen)
    s = pop.score_all(np.zeros_like(seen, dtype=bool))
    assert s[0, 0] > s[0, 1]                           # item 0 most popular


def test_chop_keeps_fraction_and_only_positives():
    from privacf import obfuscate  # noqa: E402
    pref = np.zeros((1, 20), dtype=np.float32)
    pref[0, :10] = 1.0                                 # 10 positive entries
    g = obfuscate.chop(pref, keep_frac=0.5, seed=1)
    kept = np.nonzero(g[0] > 0)[0]
    assert len(kept) == 5                              # exactly half kept
    assert set(kept).issubset(set(range(10)))          # only ever real positives
    # keep_frac=1.0 is the identity (no chopping)
    assert np.array_equal(obfuscate.chop(pref, keep_frac=1.0, seed=1), pref)


def test_chop_cover_pads_back_to_original_count():
    from privacf import obfuscate  # noqa: E402
    pref = np.zeros((1, 50), dtype=np.float32)
    pref[0, :10] = 1.0
    tt = np.linspace(0, 100, 50)                       # trust totals for cover weighting
    g = obfuscate.chop(pref, keep_frac=0.5, seed=2, cover=True,
                       trust_total=tt, c=50.0)
    assert int((g[0] > 0).sum()) == 10                 # padded back to original size


def test_laplace_clamp_keeps_inactive_zero_and_nonneg():
    from privacf import obfuscate  # noqa: E402
    pref = np.zeros((1, 8), dtype=np.float32)
    pref[0, [1, 3, 5]] = np.array([1.0, 2.0, 1.0])
    g = obfuscate.laplace(pref, epsilon=0.5, seed=3)   # heavy noise, default method="clamp"
    # noise applied to active dims only -> inactive dims stay exactly 0 (which-items
    # privacy is chopping's job, §4.5); clamp to [0,B] keeps everything non-negative
    assert np.all(g[0, [0, 2, 4, 6, 7]] == 0.0)
    assert np.all(g[0, [1, 3, 5]] >= 0.0)              # non-negative (positive-only gossip)
    assert not np.any(np.isnan(g))


def test_laplace_clamp_is_data_independent_dp_post_processing():
    from privacf import obfuscate  # noqa: E402
    # clamp method bounds the output to [0, B] (data-independent) and renormalises;
    # the legacy clip method (data-dependent, DP-voiding) is retained for the E2 contrast.
    pref = np.zeros((1, 6), dtype=np.float32)
    pref[0, [0, 2, 4]] = np.array([1.0, 1.0, 1.0])
    clamp = obfuscate.laplace(pref, epsilon=1.0, seed=1, bound=0.5, normalize=False, method="clamp")
    assert clamp.max() <= 0.5 + 1e-6                   # respects the public bound B
    legacy = obfuscate.laplace(pref, epsilon=1.0, seed=1, method="clip_legacy")
    assert not np.any(np.isnan(legacy)) and np.all(legacy >= 0.0)


def test_laplace_inf_is_normalize_only():
    from privacf import obfuscate  # noqa: E402
    pref = np.array([[3.0, 1.0, 0.0]], dtype=np.float32)
    g = obfuscate.laplace(pref, epsilon=float("inf"), seed=0)
    assert abs(g.sum() - 1.0) < 1e-5                   # L1-normalised, no noise
    assert np.allclose(g[0], [0.75, 0.25, 0.0])


def test_inject_pushes_target_for_every_sybil():
    from privacf import attack  # noqa: E402
    honest = np.zeros((40, 60), dtype=np.float32)
    honest[:, :10] = 1.0                               # honest like the first 10 items
    seen = honest > 0
    inj = attack.inject(honest, seen, target=55, attack="bandwagon",
                        ssp="dense", sybil_frac=0.25, n_filler=8, seed=1)
    assert inj.n_sybil == 10                            # 25% of 40
    assert np.all(inj.gossip[inj.is_sybil, 55] > 0)     # every Sybil pushes the target
    assert np.all(~inj.is_sybil[:40]) and np.all(inj.is_sybil[40:])


def test_foolsgold_downweights_coordinated_group():
    from privacf import attack  # noqa: E402
    # 8 diverse honest rows + 4 near-identical Sybil rows
    rng = np.random.default_rng(0)
    honest = (rng.random((8, 30)) > 0.7).astype(np.float32)
    sybil = np.zeros((4, 30), dtype=np.float32)
    sybil[:, [0, 1, 2, 29]] = 1.0                       # identical coordinated profile
    contrib = np.vstack([honest, sybil])
    alpha = attack.foolsgold(contrib)
    assert alpha.shape == (12,)
    assert alpha[8:].mean() < alpha[:8].mean()          # Sybils downweighted vs honest
    assert alpha[8:].max() < 0.5                        # tightly-coordinated -> near 0


def test_foolsgold_spares_diverse_nodes():
    from privacf import attack  # noqa: E402
    rng = np.random.default_rng(1)
    contrib = (rng.random((20, 50)) > 0.6).astype(np.float32)  # all diverse, no Sybils
    alpha = attack.foolsgold(contrib)
    assert alpha.mean() > 0.5                           # diverse nodes keep substantial weight


def test_psi_peer_idx_picks_taste_similar_users():
    from privacf import experiment_e4 as e4  # noqa: E402
    # users 0,1 share taste (items 0-3); users 2,3 share a different taste (items 6-9)
    pref = np.zeros((4, 10), dtype=np.float32)
    pref[0, [0, 1, 2, 3]] = 1.0
    pref[1, [0, 1, 2]] = 1.0
    pref[2, [6, 7, 8, 9]] = 1.0
    pref[3, [7, 8, 9]] = 1.0
    idx = e4._user_peer_idx(pref, n_peers=1)
    assert idx[0, 0] == 1 and idx[1, 0] == 0       # taste twins pick each other
    assert idx[2, 0] == 3 and idx[3, 0] == 2


def test_rotation_keeps_fraction_of_true_peers():
    from privacf import experiment_e4 as e4  # noqa: E402
    rng = np.random.default_rng(0)
    peer_idx = np.tile(np.arange(10, 18), (5, 1))   # 5 users, 8 known peers each
    rot = e4._rotate(peer_idx, keep_frac=0.5, n_users=100, rng=rng)
    assert rot.shape == peer_idx.shape
    # each row should retain ~half of its true peers (4 of 8)
    kept = [len(set(rot[u]) & set(peer_idx[u])) for u in range(5)]
    assert all(3 <= k_ <= 8 for k_ in kept)         # at least the kept fraction survives


def test_peer_mask_is_indicator():
    from privacf import experiment_e4 as e4  # noqa: E402
    peer_idx = np.array([[1, 2], [0, 3]])
    mask = e4._peer_mask(peer_idx, n_users=4)
    assert mask[0, 1] == 1 and mask[0, 2] == 1 and mask[0, 0] == 0
    assert mask.sum() == 4                          # 2 users x 2 peers


def test_reputation_asymmetric_penalty():
    from privacf import temporal as tp  # noqa: E402
    cfg = tp.RepConfig(delta_rise=0.5, delta_decay=0.0, band_1=1.0, band_max=4.0)
    # active node sits at band_max; a single absence snaps it to band_1
    sched = np.array([True, True, True, False, True, True], dtype=bool)
    r = tp.simulate_reputation(sched, cfg)
    assert abs(r[2] - 4.0) < 1e-9                       # maintained at max
    assert abs(r[3] - 1.0) < 1e-9                       # absence -> snap to band_1
    assert r[4] > r[3] and r[5] > r[4]                  # then climbs back by Δ_rise


def test_recovery_is_slower_for_smaller_delta_rise():
    from privacf import temporal as tp  # noqa: E402
    fast = tp.recovery_epochs(tp.RepConfig(delta_rise=1.0, delta_decay=0.0), target=3.0)
    slow = tp.recovery_epochs(tp.RepConfig(delta_rise=0.25, delta_decay=0.0), target=3.0)
    assert slow > fast                                  # smaller Δ_rise -> slower recovery


def test_faithful_decay_does_not_snap_on_absence():
    from privacf import temporal as tp  # noqa: E402
    cfg = tp.RepConfig(delta_rise=0.5, delta_decay=0.05, band_1=1.0, band_max=4.0)
    sched = np.array([True, True, False, True], dtype=bool)
    snap = tp.simulate_reputation(sched, cfg, snap_on_absence=True)
    decay = tp.simulate_reputation(sched, cfg, snap_on_absence=False)
    assert snap[2] < 1.5                                # snap reading -> BAND_1 cliff (≈0.95 after decay)
    assert decay[2] > 3.0                               # faithful reading -> only slow decay


def test_recovery_after_long_absence_scales_with_outage():
    from privacf import temporal as tp  # noqa: E402
    cfg = tp.RepConfig(delta_rise=0.5, delta_decay=0.05)
    short = tp.recovery_after_absence(cfg, absence_len=10, target=3.0)
    long = tp.recovery_after_absence(cfg, absence_len=60, target=3.0)
    assert long > short                                 # longer outage -> slower recovery


def test_trust_total_fixed_point_and_no_amplification():
    from privacf import temporal as tp  # noqa: E402
    base = np.ones(5)
    rep = np.full((5, 60), 2.0)
    # fixed inputs -> converges to a fixed point, monotone up, capped
    act = np.ones((5, 60), dtype=bool)
    tt = tp.trust_total_trajectory(act, rep, base, c=20.0, lam=0.6)
    assert tt[-1] <= 20.0 + 1e-9                         # capped at c
    assert tt[-1] == max(tt) and tt[-5:].std() < 1e-6   # settled fixed point
    # on-off announcer never pushes tt above the always-on ceiling (no amplification)
    cyc = tp.onoff_schedule(60, 2, 2)
    act2 = act.copy(); act2[0] = cyc
    tt2 = tp.trust_total_trajectory(act2, rep, base, c=20.0, lam=0.6)
    assert tt2.max() <= tt.max() + 1e-9


def test_noveltykill_separator_coordinated_vs_organic():
    from privacf import attack  # noqa: E402
    from privacf.experiment_noveltykill import organic_surge  # noqa: E402
    honest = np.zeros((60, 80), dtype=np.float32)
    rng = np.random.default_rng(0)
    for u in range(60):                                 # diverse honest population
        honest[u, rng.choice(80, 12, replace=False)] = 1.0
    seen = honest > 0
    victim = 77
    # coordinated novelty-kill cohort: near-identical -> FoolsGold flags (low ᾱ)
    inj = attack.inject(honest, seen, victim, attack="random", ssp="dense",
                        sybil_frac=0.25, n_filler=10, seed=1)
    a_kill = attack.foolsgold(inj.gossip)[inj.is_sybil].mean()
    # organic surge: diverse crowd genuinely liking the victim -> not flagged (high ᾱ)
    sg, is_sg = organic_surge(honest, seen, victim, m=15, seed=1)
    a_surge = attack.foolsgold(sg)[is_sg].mean()
    assert a_kill < 0.4                                  # coordinated push is flagged
    assert a_surge > 0.7                                 # organic surge is not
    assert a_surge - a_kill > 0.3                        # the separator gap


def test_coherence_separates_star_from_cluster():
    from privacf import experiment_killsep as ks  # noqa: E402
    n_items = 60
    pref = np.zeros((40, n_items), dtype=np.float32)
    rng = np.random.default_rng(0)
    victim = 59
    cluster = np.arange(10, 25)                          # the victim's taste neighbourhood
    for u in range(40):                                  # honest fans co-like the cluster
        pref[u, rng.choice(cluster, 6, replace=False)] = 1.0
        if u % 2 == 0:
            pref[u, victim] = 1.0
    seen = pref > 0
    neigh = ks.neighborhood(pref, seen, victim, n_neigh=15)
    # a "star" cohort: shares only the victim, random unrelated filler
    star = np.zeros((8, n_items), dtype=np.float32)
    for s in range(8):
        star[s, rng.choice(np.arange(30, 59), 6, replace=False)] = 1.0
        star[s, victim] = 2.0
    # a "cluster" cohort: genuine fans, filler from the neighbourhood
    clus = np.zeros((8, n_items), dtype=np.float32)
    for s in range(8):
        clus[s, rng.choice(np.where(neigh)[0], 6, replace=False)] = 1.0
        clus[s, victim] = 2.0
    coh_star = ks.coherence(list(star), neigh, victim)
    coh_clus = ks.coherence(list(clus), neigh, victim)
    assert coh_star < 0.3                                # assembled-to-push star: incoherent
    assert coh_clus > 0.7                                # genuine cluster: coherent
    assert coh_clus - coh_star > 0.4                     # the separating gap


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if _run_all() else 0)
