//! Integration test: a node that falls behind recovers via chain-sync (`GetChain`/`ChainRange`).
//!
//! A finalized block only appends at exactly `head + 1`, so a node that misses even one `Finalized`
//! gossip would be stranded forever — nothing else used to request the missing range (`GetChain` was
//! handled but never sent). Here one genesis validator starts LATE: by the time it comes up the others
//! have already finalized several blocks, so its very next `Finalized` is far past its head. It must
//! detect the gap (or proactively poll), pull the missing range, catch up, and converge with the rest.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_node_recovers_via_chain_sync_and_converges() {
    let nodes = 4u64;
    let epochs = 8u64;
    let base_port = 9820u16;
    let window_ms = 300u64;

    let validators = genesis_validator_set(nodes, base_port);
    let cfg = |i: u64| NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        // Generous grace so the early nodes linger at max_height and still answer the latecomer's
        // sync requests while it catches up.
        grace_ms: window_ms * 24,
    };

    let mut handles = Vec::new();
    // Quorum for n=4 is 3, so the three early nodes can finalize on their own while node 3 is down.
    for i in 0..(nodes - 1) {
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(i), cfg(i)).run()));
    }

    // Bring the last validator up only after the network has made real progress, forcing it to rely
    // on chain-sync rather than following blocks in order from genesis.
    let late = nodes - 1;
    let late_cfg = cfg(late);
    let late_handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        Node::new(NodeIdentity::from_seed(late), late_cfg).run().await
    });
    handles.push(late_handle);

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The latecomer reached the same head as everyone else — it could only have obtained the blocks
    //    finalized before it started by syncing them (it cannot append out of order, nor finalize alone).
    let head0 = outs[0].head_hash;
    let len0 = outs[0].blocks_len;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head hash diverged", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len, len0, "node {} chain length mismatch", hex::encode(&o.peer_id[..4]));
    }
    assert_eq!(len0 as u64, epochs + 1, "expected genesis + {epochs} blocks");

    // 2. Every finalized block still carries a valid quorum certificate — the latecomer accepted only
    //    properly-certified blocks through the sync path, it did not weaken finality.
    for o in &outs {
        assert!(o.all_qc_valid, "node {} accepted a block without a valid QC", hex::encode(&o.peer_id[..4]));
    }
}
