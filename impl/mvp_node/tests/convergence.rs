//! Integration test: N in-process nodes over loopback TCP cycle K epochs and must converge on one
//! chain head, with each node rotating distinct per-epoch `epoch_id`s and a correct publish-`s₁`
//! split every epoch.

use std::collections::HashSet;

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

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

    // 2. Each node rotated distinct epoch_ids across the K epochs, and the publish-s1 split held.
    for o in &outs {
        let ids: HashSet<u64> = o.epoch_ids.iter().map(|(_, e)| *e).collect();
        assert_eq!(ids.len(), o.epoch_ids.len(), "epoch_ids must be distinct across epochs");
        assert_eq!(o.epoch_ids.len() as u64, epochs, "one epoch_id per epoch");
        assert!(o.split_ok, "publish-s1 split s1+s2=null_v must hold every epoch");
    }

    // 3. At a fixed height, distinct nodes (distinct sk) produce distinct epoch_ids.
    let at_h1: Vec<u64> = outs
        .iter()
        .map(|o| o.epoch_ids.iter().find(|(h, _)| *h == 1).expect("height-1 epoch_id").1)
        .collect();
    let set: HashSet<u64> = at_h1.iter().copied().collect();
    assert_eq!(set.len(), at_h1.len(), "distinct nodes must have distinct epoch_ids at one height");
}
