//! Integration test: N in-process nodes over loopback TCP cycle K epochs and must converge on one
//! chain head, with each node rotating distinct per-epoch `epoch_id`s and a correct publish-`s₁`
//! split every epoch.

use std::collections::HashSet;

use mvp_node::beacon::{next_beacon, GENESIS_BEACON};
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};
use mvp_node::vrf::VrfClaim;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_converge_and_rotate_epoch_ids() {
    let nodes = 4u64;
    let epochs = 5u64;
    let base_port = 9300u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(nodes, base_port);
    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 10,
        };
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(i), cfg).run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Convergence: all nodes share one head hash and the same chain length (genesis + K blocks).
    let head0 = outs[0].head_hash;
    let len0 = outs[0].blocks_len;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head hash diverged", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len, len0, "chain length mismatch");
    }
    assert_eq!(len0 as u64, epochs + 1, "expected genesis + {epochs} blocks");

    // 2. Each node rotated distinct epoch_ids across the K epochs, the split held, and every
    //    finalized block carries a valid quorum certificate (BFT finality).
    for o in &outs {
        let ids: HashSet<u64> = o.epoch_ids.iter().map(|(_, e)| *e).collect();
        assert_eq!(ids.len(), o.epoch_ids.len(), "epoch_ids must be distinct across epochs");
        assert_eq!(o.epoch_ids.len() as u64, epochs, "one epoch_id per epoch");
        assert!(o.split_ok, "publish-s1 split s1+s2=null_v must hold every epoch");
        assert!(o.all_qc_valid, "every block must carry a valid quorum certificate");
    }

    // 3. At a fixed height, distinct nodes (distinct sk) produce distinct epoch_ids.
    let at_h1: Vec<u64> = outs
        .iter()
        .map(|o| o.epoch_ids.iter().find(|(h, _)| *h == 1).expect("height-1 epoch_id").1)
        .collect();
    let set: HashSet<u64> = at_h1.iter().copied().collect();
    assert_eq!(set.len(), at_h1.len(), "distinct nodes must have distinct epoch_ids at one height");
}

/// View-change: make the height-1 VRF leader a Byzantine node that withholds its proposal. The
/// other validators must time out and view-change to the next-lowest-VRF leader, still finalizing
/// every height with a quorum certificate and converging.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn view_change_recovers_from_a_withholding_leader() {
    let nodes = 4u64;
    let epochs = 6u64;
    let base_port = 9400u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(nodes, base_port);

    // Deterministically pick the height-1 view-0 leader (lowest VRF output) as the faulty node,
    // guaranteeing at least one view-change.
    let beacon1 = next_beacon(GENESIS_BEACON, 1);
    let faulty = (0..nodes)
        .min_by_key(|&i| VrfClaim::create(&NodeIdentity::from_seed(i), 1, beacon1).output)
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 12,
        };
        let node = Node::new(NodeIdentity::from_seed(i), cfg);
        let node = if i == faulty { node.byzantine_withhold() } else { node };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // All nodes (the 3 honest + the faulty one, which still tracks the chain) converge.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} diverged", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "every height still finalized");
        assert!(o.all_qc_valid, "every block must carry a valid quorum certificate");
    }
    // View-change actually fired: at least one block was finalized in a view > 0.
    let max_view = outs.iter().map(|o| o.max_view).max().unwrap();
    assert!(max_view >= 1, "view-change should have advanced past the withholding leader (got {max_view})");
}
