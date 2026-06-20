//! Integration capstone: §5.3/§5.4 PSI interest-peer discovery, driven entirely in-loop.
//!
//! Discovery rides as an ADDITIVE logical overlay over the live validator mesh: each node privately probes
//! the others with a Diffie–Hellman PSI of its liked-item set (`psi.rs`), learns only the intersection SIZE,
//! and records a peer as an interest-peer when the shared-interest overlap meets the threshold. It is fully
//! decoupled from consensus — nothing goes on-chain, and it does NOT gate validator dialing (which would
//! partition the BFT mesh); the validators stay fully connected for consensus while each independently
//! discovers its own interest cluster.
//!
//! Four validators with crafted clean preferences: nodes 0 and 2 like the SAME three items (one interest
//! cluster), while nodes 1 and 3 like disjoint/near-disjoint items. With threshold 2, the only discovered
//! link is 0 ↔ 2 — and each side learns only the OTHER's overlap size, never its items.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_privately_discover_their_shared_interest_cluster_in_loop() {
    let total_n = 4u64;
    let epochs = 8u64;
    let base_port = 9380u16;
    let window_ms = 600u64;
    let epsilon = 6.0;

    // Liked items = preference dimensions with a positive clean weight. Nodes 0 and 2 share {0,1,2}; node 1
    // likes {3,4}; node 3 likes {4,5}. Overlaps vs node 0: node2=3 (≥2 → peer), node1=0, node3=0. Node 1 vs
    // node 3 overlap = {4} = 1 (< 2 → not peers).
    let prefs = |seed: u64| -> Vec<i64> {
        match seed {
            0 => vec![5, 5, 5, 0, 0, 0],
            1 => vec![0, 0, 0, 5, 5, 0],
            2 => vec![5, 5, 5, 0, 0, 0],
            _ => vec![0, 0, 0, 0, 5, 5],
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
        handles.push(tokio::spawn(
            Node::new(NodeIdentity::from_seed(seed), cfg).with_preferences(prefs(seed), epsilon).with_psi_discovery().run(),
        ));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus is unperturbed by the discovery overlay: one finalized chain, full BFT finality.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    let peer = |seed: u64| NodeIdentity::from_seed(seed).peer_id();

    // 2. The shared-interest cluster {0,2} discovered each other — and ONLY each other.
    assert_eq!(outs[0].interest_peers, vec![peer(2)], "node 0 must discover exactly node 2 as an interest-peer");
    assert_eq!(outs[2].interest_peers, vec![peer(0)], "node 2 must discover exactly node 0 as an interest-peer");

    // 3. The off-cluster nodes form no link (their pairwise overlaps are below the threshold).
    assert!(outs[1].interest_peers.is_empty(), "node 1 shares too few items to discover any interest-peer");
    assert!(outs[3].interest_peers.is_empty(), "node 3 shares too few items to discover any interest-peer");

    // 4. Sanity: the cluster nodes did NOT spuriously link to the off-cluster nodes.
    for off in [peer(1), peer(3)] {
        assert!(!outs[0].interest_peers.contains(&off), "node 0 must not link to an off-cluster node");
        assert!(!outs[2].interest_peers.contains(&off), "node 2 must not link to an off-cluster node");
    }
}
