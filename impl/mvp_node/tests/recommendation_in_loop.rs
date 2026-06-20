//! Integration capstone: the Layer-5 recommendation PRODUCT computed BY THE NODE, in-loop.
//!
//! Earlier work proved the CF/FoolsGold/cap stack over a hand-built or test-assembled matrix; here the
//! *running node* does it: each height it reads its own on-chain gossip, weights every contributor by
//! reputation (presence over epochs) and FoolsGold (Sybil down-weighting), drops suspended contributors,
//! fits the §3 item-CF, and ranks the items it has not itself interacted with — surfaced in
//! `NodeOutcome.recommendations`. This turns the substrate into the actual product: no test harness
//! assembles the matrix or runs the CF; the node does, from the finalized chain, with no effect on
//! consensus.
//!
//! Scenario: the recommender likes only item 0. Two honest peers co-like the {0,1} niche; a three-node
//! Sybil cohort (outnumbering the honest co-likers) hammers item 4. The node still recommends item 1 —
//! the honest co-like — because item 4 shares no co-occurrence with item 0, FoolsGold crushes the mutually
//! identical Sybil rows, and the DSybil cap bounds item 4's trust.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_computes_a_sybil_bounded_recommendation_in_loop() {
    let total_n = 6u64;
    let recommender = 0u64;
    let epochs = 10u64;
    let base_port = 9400u16;
    let window_ms = 700u64;
    let epsilon = 6.0;

    // seed 0 likes only item 0 (the recommendation query); seeds 1,2 honestly co-like {0,1}; seeds 3,4,5
    // are a Sybil cohort hammering item 4.
    let prefs = |seed: u64| -> Vec<i64> {
        match seed {
            0 => vec![3, 0, 0, 0, 0],
            1 | 2 => vec![3, 3, 0, 0, 0],
            _ => vec![0, 0, 0, 0, 5],
        }
    };

    let validators = genesis_validator_set(total_n, base_port);
    let mut handles = Vec::new();
    for seed in 0..total_n {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + seed as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 16,
        };
        let mut node = Node::new(NodeIdentity::from_seed(seed), cfg).with_preferences(prefs(seed), epsilon);
        if seed == recommender {
            node = node.with_recommendations();
        }
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus is unperturbed by the in-loop recommendation computation.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The recommender actually produced a recommendation in-loop.
    let r = &outs[recommender as usize];
    assert!(!r.recommendations.is_empty(), "the node must compute a recommendation from its on-chain gossip");

    // 3. It surfaces the honest co-like (item 1), NOT the Sybil-pushed item 4 — even though the Sybil
    //    cohort (3) outnumbers the honest co-likers (2).
    assert_eq!(r.recommendations[0], 1, "the top recommendation is the honest co-like (item 1), got {:?}", r.recommendations);
    assert_ne!(r.recommendations[0], 4, "the Sybil-pushed item must not be the top recommendation");

    // 4. The DSybil cap + FoolsGold kept the Sybil item's trust at or below the honest niche's.
    assert!(r.reco_item_trust.len() >= 5, "per-item trust is reported");
    assert!(
        r.reco_item_trust[4] <= r.reco_item_trust[0] + 1e-9,
        "the Sybil-pushed item's trust stays at or below the honest niche item's (item4={}, item0={})",
        r.reco_item_trust[4],
        r.reco_item_trust[0]
    );
}
