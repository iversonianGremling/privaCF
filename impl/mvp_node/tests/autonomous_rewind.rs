//! Integration capstone: the *autonomous* §6.6 rewind / Class-3 trigger, driven entirely in-loop.
//!
//! The in-bounds poisoning defense. A coordinated cohort can skew recommendations without ever posting
//! a malformed gossip row — each row is individually within the public `[0, B]` bound, so the objective
//! verdict path (`verdict_policy`) cannot suspend it. What it *cannot* hide is the correlation: the
//! cohort's combined weight makes one item's total on-chain gossip **velocity** spike at the epoch it
//! activates. Here three validators, honest at the consensus layer, switch at a chosen epoch to push a
//! single foreign item. No off-chain coordinator: each honest recommendation participant is an in-loop
//! rewind watcher that, reading the same chain, sees the foreign item's velocity spike, raises a signed
//! `RewindSignal` naming that cohort epoch, and the next leader records it in `BlockHeader::rewind_signals`.
//! Because the victims span two distinct interest niches, the on-chain signals satisfy the §6.6 Class-3
//! rule (≥ q signers across ≥ 2 clusters, same cohort epoch) — a trigger every node derives identically
//! from the finalized chain, catching the coordinated push the per-row verdict check is blind to.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};
use mvp_node::rewind;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_coordinated_push_cohort_autonomously_triggers_a_class3_rewind_in_loop() {
    // 4 honest in-loop rewind watchers split across two interest niches (items 0 and 2) + 3 pushers that
    // co-activate on a foreign item (item 4). A generous round window keeps consensus from spurious
    // view-changes on a loaded host. Every node is a correct BFT validator — only the pushers' gossip
    // is adversarial, and even that stays individually within the public bound.
    let epsilon = 8.0; // strong-dominant prefs → a stable on-chain argmax (cluster) under DP noise
    let push_from = 4u64; // the cohort activates here; epochs 1..push_from-1 are the clean baseline
    let push_item = 4usize;
    let push_weight = 1.0f32; // within [0, B] and L1 ≤ 1 — the row stays objectively well-formed

    // (seed, clean-preference row). Honest niches: items 0 and 2. Pushers' honest niche is item 3, which
    // they abandon for item 4 at `push_from`.
    let cluster_a = vec![10i64, 0, 0, 0, 0]; // honest niche, dominant item 0
    let cluster_b = vec![0i64, 0, 10, 0, 0]; // honest niche, dominant item 2
    let pusher_base = vec![0i64, 0, 0, 10, 0]; // pushers' pre-activation niche, dominant item 3
    let honest: Vec<(u64, Vec<i64>)> =
        vec![(0, cluster_a.clone()), (1, cluster_a), (2, cluster_b.clone()), (3, cluster_b)];
    let pusher_seeds = [4u64, 5, 6];

    let total_n = (honest.len() + pusher_seeds.len()) as u64; // 7
    let epochs = 12u64;
    let base_port = 9180u16;
    let window_ms = 700u64;

    let validators = genesis_validator_set(total_n, base_port);
    let cfg = |i: u64| NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        grace_ms: window_ms * 16,
    };

    let mut handles = Vec::new();
    for (seed, prefs) in honest {
        handles.push(tokio::spawn(
            Node::new(NodeIdentity::from_seed(seed), cfg(seed))
                .with_preferences(prefs, epsilon)
                .with_rewind_authority()
                .run(),
        ));
    }
    for &seed in &pusher_seeds {
        handles.push(tokio::spawn(
            Node::new(NodeIdentity::from_seed(seed), cfg(seed))
                .with_preferences(pusher_base.clone(), epsilon)
                .byzantine_push_item(push_item, push_weight, push_from)
                .run(),
        ));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The network still converges on one finalized chain with full BFT finality — the rewind
    //    machinery rides on top of consensus without breaking it.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The push is individually valid — each pushed gossip row is within the public bound, so the
    //    objective verdict path never suspends a pusher. This is exactly the gap Class-3 closes.
    assert!(
        outs[0].suspended_targets.is_empty(),
        "an in-bounds coordinated push must NOT be caught by the per-row verdict path, got {:?}",
        outs[0].suspended_targets
    );

    // 3. Honest watchers actually attested: a quorum of signed rewind signals was recorded on-chain.
    assert!(
        outs[0].rewind_signals_recorded >= rewind::REWIND_Q,
        "at least a signal quorum of rewind signals must be recorded, got {}",
        outs[0].rewind_signals_recorded
    );

    // 4. The cohort autonomously triggered a Class-3 audit — and every node agrees (the trigger is a
    //    pure function of the on-chain rewind signals + the velocity spike + each signer's cluster).
    for o in &outs {
        assert!(
            o.class3_triggered,
            "node {} must derive the Class-3 trigger from the on-chain cross-cluster rewind quorum",
            hex::encode(&o.peer_id[..4])
        );
    }
}
