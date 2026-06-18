//! Whole-protocol capstone: a real Layer-5 recommendation in which a Sybil cohort's influence is
//! bounded by the stack the substrate exists to provide. Honest peers gossip a genuine niche; a Sybil
//! cohort hammers one item and is (a) damped by FoolsGold (detection, §7.4), (b) capped by the DSybil
//! trust cap (§7.3), and (c) excluded outright once suspended (the dark-node machinery, P1.5). The
//! recommendation surfaces the honest co-liked item, not the Sybil's.

use mvp_node::detection::foolsgold;
use mvp_node::obfuscate::{laplace, LaplaceMethod};
use mvp_node::recommend::{top_k, CFConfig, ItemCF, Matrix};

/// 6 peers × 5 items. Peers 0–2 honestly co-like the {0,1} niche; peers 3–5 are a Sybil cohort all
/// hammering item 4 (and nothing else).
fn scenario() -> Matrix {
    vec![
        vec![1.0, 1.0, 0.0, 0.0, 0.0], // honest
        vec![1.0, 1.0, 0.0, 0.0, 0.0], // honest
        vec![1.0, 1.0, 0.0, 0.0, 0.0], // honest
        vec![0.0, 0.0, 0.0, 0.0, 50.0], // sybil
        vec![0.0, 0.0, 0.0, 0.0, 50.0], // sybil
        vec![0.0, 0.0, 0.0, 0.0, 50.0], // sybil
    ]
}

/// Weight each peer's gossip row by its FoolsGold trust (the operational Sybil defence).
fn foolsgold_weighted(gossip: &Matrix) -> Matrix {
    let alpha = foolsgold(gossip, 1.0);
    gossip
        .iter()
        .zip(alpha.iter())
        .map(|(row, &a)| row.iter().map(|x| x * a).collect())
        .collect()
}

#[test]
fn foolsgold_and_the_dsybil_cap_bound_a_sybil_cohorts_influence() {
    let gossip = scenario();
    let cfg = CFConfig { c: Some(3.0), ..Default::default() };

    // Undefended: the Sybil item still cannot exceed the DSybil cap c.
    let raw = ItemCF::fit(cfg.clone(), &gossip, None, None);
    assert!(raw.effective_trust[4] <= raw.c + 1e-9, "even undefended, item 4 is capped at c");

    // Defended: FoolsGold damps the (mutually-identical) Sybil cohort, so item 4 gathers far less
    // trust than the honest niche items do.
    let defended = ItemCF::fit(cfg.clone(), &foolsgold_weighted(&gossip), None, None);
    assert!(
        defended.effective_trust[4] < defended.effective_trust[0],
        "FoolsGold leaves the Sybil-pushed item below the honest niche items"
    );

    // A user who interacted with item 0 is recommended its honest co-like (item 1), not the Sybil's.
    let pref_pos = vec![vec![1.0, 0.0, 0.0, 0.0, 0.0]];
    let pref_neg = vec![vec![0.0; 5]];
    let seen = vec![vec![true, false, false, false, false]];
    let rec = top_k(&defended.score_all(&pref_pos, &pref_neg, &seen), 1);
    assert_eq!(rec[0][0], 1, "the honest co-liked item is the top recommendation, not the Sybil's");
}

#[test]
fn a_suspended_sybil_is_excluded_from_the_aggregation() {
    // The substrate link: once a peer is suspended (dark-node extraction listed its null_v in
    // SUSP_SMT), its gossip row is dropped before CF — so it contributes nothing at all.
    let gossip = scenario();
    let suspended_peers = [3usize, 4, 5]; // the Sybil cohort, suspended by verdict

    let filtered: Matrix = gossip
        .iter()
        .enumerate()
        .map(|(i, row)| if suspended_peers.contains(&i) { vec![0.0; row.len()] } else { row.clone() })
        .collect();

    let cf = ItemCF::fit(CFConfig { c: Some(3.0), ..Default::default() }, &filtered, None, None);
    assert!(cf.effective_trust[4] <= 1e-9, "a suspended cohort's pushed item gathers no trust");
    // The honest niche is untouched.
    assert!(cf.effective_trust[0] > 0.0 && cf.effective_trust[1] > 0.0, "honest items keep their trust");
}

#[test]
fn dp_obfuscated_gossip_still_recommends_the_honest_co_like() {
    // The §4.5 link: peers broadcast Laplace-DP-obfuscated gossip (the protocol never sees the clean
    // rows), yet the recommendation over that noised substrate still surfaces the honest co-like.
    // We use a co-like niche broad enough that the per-row noise can't destroy the {0,1} signal.
    let honest: Matrix = (0..12).map(|_| vec![1.0, 1.0, 0.0, 0.0, 0.0]).collect();
    let sybil: Matrix = (0..6).map(|_| vec![0.0, 0.0, 0.0, 0.0, 50.0]).collect();
    let gossip: Matrix = honest.into_iter().chain(sybil).collect();

    // Each peer obfuscates its OWN row before broadcast (clean rows never leave the device).
    let obf = laplace(&gossip, 5.0, 2026, 2.0, 1.0, true, LaplaceMethod::Clamp);

    let cfg = CFConfig { c: Some(3.0), ..Default::default() };
    let cf = ItemCF::fit(cfg, &obf, None, None);

    // Even over noised gossip, the DSybil cap still bounds the Sybil-pushed item.
    assert!(cf.effective_trust[4] <= cf.c + 1e-9, "the cap holds over obfuscated gossip too");

    // A user who liked item 0 is still recommended item 1 (its honest co-like), not the Sybil's item 4.
    let pref_pos = vec![vec![1.0, 0.0, 0.0, 0.0, 0.0]];
    let pref_neg = vec![vec![0.0; 5]];
    let seen = vec![vec![true, false, false, false, false]];
    let rec = top_k(&cf.score_all(&pref_pos, &pref_neg, &seen), 1);
    assert_eq!(rec[0][0], 1, "obfuscated gossip still yields the honest co-liked recommendation");
}
