//! Integration capstone: the §6.4 arbitration **slashing** path, driven entirely in-loop.
//!
//! A selected committee member that takes custody but never files a handoff receipt cannot stall the
//! handoff — the custody is `CUSTODY_THRESHOLD`-of-committee, so the honest majority still completes it —
//! and it does not escape accountability: once the deadline passes, every node, reading the same chain
//! (the beacon-selected committee, the recorded receipts, the elapsed deadline), independently settles
//! the round, finds the withholder defaulted, and slashes it from leadership. No extra evidence message:
//! the absence of a receipt by the deadline IS the on-chain evidence, recomputable by anyone.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withholding_committee_member_is_defaulted_and_slashed_while_the_handoff_still_completes() {
    // 5 validators: 1 rotates out at height 3; the other four ARE its committee (committee size 4 over
    // exactly four candidates), so the chosen withholder is guaranteed to be on it. The custody threshold
    // is 3, so the three honest members still complete the handoff; the withholder defaults.
    let total_n = 5u64;
    let leaver_seed = 4u64;
    let withholder_seed = 0u64;
    let leave_height = 3u64;
    let epochs = 16u64;
    let base_port = 9260u16;
    let window_ms = 700u64;
    let epsilon = 6.0;

    let prefs = |seed: u64| -> Vec<i64> {
        let mut v = vec![0i64; 5];
        v[(seed as usize) % 5] = 4 + (seed as i64);
        v
    };

    let validators = genesis_validator_set(total_n, base_port);
    let cfg = |i: u64| NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        grace_ms: window_ms * 16,
    };

    let mut handles = Vec::new();
    for seed in 0..total_n {
        let mut node = Node::new(NodeIdentity::from_seed(seed), cfg(seed)).with_preferences(prefs(seed), epsilon);
        node = if seed == leaver_seed {
            node.leaves_at(leave_height)
        } else if seed == withholder_seed {
            node.byzantine_withhold_handoff() // takes custody, files nothing
        } else {
            node.with_arbitration_authority()
        };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Convergence + finality survive the departure AND the withholder's leadership exclusion.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The handoff STILL completes: the three honest custodians meet the custody threshold even though
    //    one member withheld (custody is threshold-of-committee, robust to a single non-filer).
    for o in &outs {
        assert!(o.handoff_complete, "node {} must see the handoff complete via the custody threshold", hex::encode(&o.peer_id[..4]));
    }

    // 3. The withholder is defaulted and slashed — on EVERY node, derived purely from the chain.
    let withholder = NodeIdentity::from_seed(withholder_seed).peer_id();
    for o in &outs {
        assert!(
            o.handoff_defaults.contains(&withholder),
            "node {} must default the withholding committee member",
            hex::encode(&o.peer_id[..4])
        );
        assert!(
            o.slashed.contains(&withholder),
            "node {} must slash the withholder from leadership",
            hex::encode(&o.peer_id[..4])
        );
    }

    // 4. No honest custodian is spuriously defaulted (the deadline is past the self-healing window).
    for seed in [1u64, 2, 3] {
        let honest = NodeIdentity::from_seed(seed).peer_id();
        assert!(!outs[0].handoff_defaults.contains(&honest), "an honest custodian must not be defaulted");
    }
}
