//! Integration capstone: the *autonomous* dark-node verdict — the in-loop *when*, not just the *what*.
//!
//! A live BFT network runs with one node publishing an objectively-malformed preference row each
//! epoch (an over-bound gossip vector — the cheap CF-amplification attack). No off-chain coordinator,
//! no scripted committee: each verdict-authority validator, reading the same finalized chain, applies
//! the deterministic `verdict_policy`, emits its `σ_VERDICT` partial, and `⌊K/2⌋+1` partials combine
//! into a real threshold signature that dark-node-extracts the offender's `null_v` and lands a
//! suspension on-chain — entirely inside the consensus loop. Honest, well-formed contributors are
//! never suspended, and every node converges on the same finalized chain and the same suspended set.

use std::collections::HashSet;

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_threshold_keys, genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_contributor_is_autonomously_suspended_in_loop() {
    let nodes = 5u64;
    let epochs = 9u64;
    let base_port = 9020u16;
    let window_ms = 250u64;
    let threshold = 3usize; // ⌊5/2⌋+1 — a verdict quorum is exactly a signing quorum.

    let validators = genesis_validator_set(nodes, base_port);
    let idents: Vec<NodeIdentity> = (0..nodes).map(NodeIdentity::from_seed).collect();
    let tks = genesis_threshold_keys(&idents, threshold);

    // Node 0 is the offender: it has preferences (so it publishes a pref payload) but corrupts the
    // gossip row to an over-bound vector every epoch. It is NOT a verdict authority. All other nodes
    // carry well-formed preferences AND act as verdict authorities. Every node holds a threshold-key
    // share (so the offender's d_T is sealed to VA_pub and therefore extractable).
    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 14,
        };
        let id = NodeIdentity::from_seed(i);
        let tk = tks[&id.peer_id()].clone();
        let node = if i == 0 {
            Node::new(id, cfg)
                .with_threshold_key(tk)
                .with_preferences(vec![3, 0, 1, 0, 2], 5.0)
                .byzantine_malformed_pref()
        } else {
            Node::new(id, cfg)
                .with_threshold_key(tk)
                .with_preferences(vec![1, 1, 0, 0, 0], 5.0)
                .with_verdict_authority()
        };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The network still converges on one finalized chain with full BFT finality — the autonomous
    //    verdict machinery rides on top of consensus without breaking it.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. A suspension was reached autonomously — entirely in-loop, no scripted verdict.
    let suspended = &outs[0].suspended_targets;
    assert!(!suspended.is_empty(), "the malformed contributor must be autonomously suspended");

    // 3. Every node converged on the SAME suspended set (it lives in the finalized chain).
    for o in &outs {
        assert_eq!(&o.suspended_targets, suspended, "all honest nodes must agree on the suspended set");
    }

    // 4. The suspended targets are exactly the offender's pseudonyms — at least one of node 0's
    //    epoch_ids was suspended, and NONE of the honest nodes' epoch_ids ever were (no false
    //    positives against well-formed contributors).
    let offender_ids: HashSet<u64> = outs[0].epoch_ids.iter().map(|(_, e)| *e).collect();
    let suspended_set: HashSet<u64> = suspended.iter().copied().collect();
    assert!(
        suspended_set.is_subset(&offender_ids),
        "only the malformed offender's pseudonyms may be suspended, got {suspended:?}"
    );
    assert!(
        !suspended_set.is_disjoint(&offender_ids),
        "at least one offender pseudonym must be suspended"
    );
    for o in outs.iter().skip(1) {
        for (_, e) in &o.epoch_ids {
            assert!(!suspended_set.contains(e), "an honest contributor's epoch_id was suspended");
        }
    }
}
