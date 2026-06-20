//! Integration capstone: the §6.4 handoff-package ZK proof (Statements 1-3), driven in-loop.
//!
//! When a node departs, the §6.4 handoff package must include a composite zero-knowledge proof that the
//! profile being handed off is well-formed — norm-bounded (S1), sign-consistent (S2) and slow-moving (S3)
//! — WITHOUT revealing it. Only the profile owner can produce it (it alone knows the vector and the
//! per-epoch blindings), so here the departing node generates the proof over its own two latest on-chain
//! `C_p`, publishes it, and every validator independently re-verifies it against the on-chain commitments
//! before recording it in `BlockHeader::handoff_proofs`. No node ever sees the preference vector.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departing_nodes_handoff_carries_a_verified_zk_proof_in_loop() {
    let total_n = 6u64;
    let leaver_seed = 5u64;
    let leave_height = 3u64;
    let epochs = 12u64;
    let base_port = 9440u16;
    let window_ms = 700u64;
    let epsilon = 6.0;

    // Distinct, within-bound (|p_i| <= 16) preference vectors, so each node commits a real C_p on-chain.
    let prefs = |seed: u64| -> Vec<i64> {
        let mut v = vec![0i64; 5];
        v[(seed as usize) % 5] = 4 + (seed as i64);
        v
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
        node = if seed == leaver_seed {
            node.leaves_at(leave_height)
        } else {
            node.with_arbitration_authority()
        };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus converges with full BFT finality across the departure.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The leaver actually departed.
    let leaver = NodeIdentity::from_seed(leaver_seed).peer_id();
    assert!(!outs[0].final_active.contains(&leaver), "the rotated-out node must be gone from the active set");

    // 3. The departing node's composite handoff-package ZK proof was recorded on-chain — and since a proof
    //    is only recorded after re-verifying against the on-chain C_p (in assemble_block AND in every
    //    validator's structural check), its presence on the agreed chain IS the verification.
    assert!(
        outs[0].handoff_proofs_recorded >= 1,
        "the departing node's §6.4 handoff ZK proof must be recorded, got {}",
        outs[0].handoff_proofs_recorded
    );

    // 4. Every node agrees on the recorded proof set (it rides the finalized chain).
    for o in &outs {
        assert_eq!(
            o.handoff_proofs_recorded, outs[0].handoff_proofs_recorded,
            "node {} disagrees on recorded handoff proofs",
            hex::encode(&o.peer_id[..4])
        );
    }
}
