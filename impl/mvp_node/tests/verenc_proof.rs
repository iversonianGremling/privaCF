//! Integration capstone: the **VerEnc `d_T` well-formedness gate**, driven in-loop.
//!
//! `with_verenc_proof()` makes every validator require each epoch transaction's `d_T` to carry a
//! `verenc` well-formedness proof — a real, BLS12-381-native zero-knowledge proof (DESIGN-f1 §R1–R3)
//! that the published ciphertext is a genuine, openable, in-range encryption of `s₂`, verifiable at
//! publish time *without* the verdict signature. This closes the openability hole: today a node could
//! publish an un-openable / out-of-range `d_T`, and only at verdict time would dark-node extraction
//! silently fail, letting the node escape suspension.
//!
//! Here a genesis set all hold a threshold-key share (so their `d_T` is sealed to `VA_pub`) and all
//! run the gate. The proof: consensus converges with full BFT finality across many epochs — i.e.
//! every node, each epoch, built a well-formedness proof for its own `d_T`, gossiped it, and every
//! validator independently re-verified it at pooling and block validation before finalizing. (The
//! negative direction — a tampered, out-of-range, or non-transferable `d_T` proof is rejected — is
//! exhaustively covered by the `verenc` unit tests.)

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_threshold_keys, genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn epoch_transactions_carry_a_verified_verenc_proof_in_loop() {
    let nodes = 4u64;
    let epochs = 9u64;
    let base_port = 9560u16;
    let window_ms = 250u64;
    let threshold = 3usize; // ⌊4/2⌋+1

    let validators = genesis_validator_set(nodes, base_port);
    let idents: Vec<NodeIdentity> = (0..nodes).map(NodeIdentity::from_seed).collect();
    let tks = genesis_threshold_keys(&idents, threshold);

    // Every node seals its s₂ to VA_pub (with_threshold_key) AND enforces the well-formedness gate
    // (with_verenc_proof). Each also carries preferences so its epoch tx is a full, realistic payload.
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
        let node = Node::new(id, cfg)
            .with_threshold_key(tk)
            .with_verenc_proof()
            .with_preferences(vec![1, 1, 0, 0, 0], 5.0);
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // The network converges on one finalized chain with full BFT finality: every epoch tx that was
    // finalized carried a d_T whose well-formedness proof every validator independently accepted.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
        assert!(o.split_ok, "s₁ + s₂ = null_v must hold every epoch");
    }

    // The chain made real progress (so the gate did not stall block production by rejecting honest txs).
    assert!(outs[0].blocks_len >= (epochs - 2) as usize, "the gated network must finalize blocks, not stall");
}
