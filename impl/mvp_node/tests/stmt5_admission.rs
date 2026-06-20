//! Integration capstone: the **Statement-5 forward-secrecy rejoin gate**, driven in-loop.
//!
//! `with_stmt5_admission()` makes every validator require a joining node to attach a `zkstmt5`
//! rejoin proof — a real ZK proof that the joiner's `null_v` is NOT in the on-chain SUSP set —
//! before admitting it. This is the privacy-preserving half of the suspension machinery: a
//! suspended (dark) node, whose `null_v` was extracted and folded into the SUSP_SMT, cannot produce
//! the proof and so cannot re-admit, while an honest node proves non-membership and joins normally.
//!
//! Here an honest never-suspended newcomer joins a genesis set that all run the gate. The proof:
//! consensus converges with full BFT finality across the join, and the newcomer ends in the active
//! set — i.e. its in-loop-generated rejoin proof was rebuilt against the live SUSP root, gossiped,
//! and independently re-verified by every validator at pooling / assembly / block validation. (The
//! negative direction — a suspended `null_v` cannot build or pass the proof, and a proof cannot be
//! replayed under another identity — is exhaustively covered by the `zkstmt5` unit tests.)

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_newcomer_passes_the_statement5_rejoin_gate_and_is_admitted() {
    let genesis_n = 4u64;
    let epochs = 11u64;
    let base_port = 9520u16;
    let window_ms = 650u64;

    let validators = genesis_validator_set(genesis_n, base_port);

    // A late joiner whose peer id is below every genesis id, so it dials the full set and meshes.
    let genesis_min = (0..genesis_n).map(|i| NodeIdentity::from_seed(i).peer_id()).min().unwrap();
    let joiner_seed = {
        let mut s = 1000u64;
        while !(NodeIdentity::from_seed(s).peer_id() < genesis_min) {
            s += 1;
        }
        s
    };

    let cfg = |i: u16| NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + i),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        grace_ms: window_ms * 18,
    };

    let mut handles = Vec::new();
    // Genesis validators all enforce the Statement-5 admission gate.
    for seed in 0..genesis_n {
        let id = NodeIdentity::from_seed(seed);
        handles.push(tokio::spawn(Node::new(id, cfg(seed as u16)).with_stmt5_admission().run()));
    }
    // The honest newcomer: it must build + attach a rejoin proof every height until admitted.
    handles.push(tokio::spawn(
        Node::new(NodeIdentity::from_seed(joiner_seed), cfg(genesis_n as u16))
            .joining()
            .with_stmt5_admission()
            .run(),
    ));

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus converges with full BFT finality across the gated join.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The honest newcomer cleared the gate — its in-loop ZK rejoin proof was accepted network-wide.
    let joiner = NodeIdentity::from_seed(joiner_seed).peer_id();
    assert!(
        outs[0].final_active.contains(&joiner),
        "the honest newcomer must pass the Statement-5 gate and be admitted"
    );
}
