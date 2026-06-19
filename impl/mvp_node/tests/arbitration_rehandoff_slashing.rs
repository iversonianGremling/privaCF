//! Integration capstone: the §6.4 **re-handoff slashing** path, driven entirely in-loop.
//!
//! A re-handoff (the proactive custody rotation triggered when an original custodian departs) defaults and
//! slashes a fresh-committee member exactly as the original handoff does: once the re-handoff deadline
//! passes, every node — reading the same chain (the trigger, the fresh beacon-selected committee, the
//! recorded round-1 receipts, the elapsed deadline) — independently settles the round, finds the
//! non-filing fresh custodian defaulted, and slashes it from leadership. No extra evidence message: the
//! absence of a round-1 receipt by the deadline IS the on-chain evidence, recomputable by anyone.
//!
//! Setup. Five genesis validators: seed4 is the round-0 subject (leaves at h2); the other four are its
//! committee (committee size 4 == candidate count 4, so membership is guaranteed). seed0, one of those
//! custodians, leaves at h7 — the re-handoff trigger. The three survivors re-share to the fresh committee.
//! A SIXTH node `W` joins late (after the round-0 committee has already formed, so it is never an original
//! custodian) and lands on the fresh committee, but withholds its round-1 receipt: the three honest
//! survivors still complete the re-handoff (custody threshold 3), and `W` is defaulted and slashed.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withholding_fresh_committee_member_is_defaulted_and_slashed_in_the_re_handoff() {
    let genesis_n = 5u64;
    let subject_seed = 4u64; // round-0 subject
    let custodian_leaver_seed = 0u64; // an original custodian that departs → re-handoff trigger
    let subject_leave = 2u64;
    let custodian_leave = 7u64;
    let join_at = 3u64; // W joins only after the round-0 committee has formed
    let epochs = 16u64;
    let base_port = 9340u16;
    let window_ms = 800u64;
    let epsilon = 6.0;

    let prefs = |seed: u64| -> Vec<i64> {
        let mut v = vec![0i64; 5];
        v[(seed as usize) % 5] = 4 + (seed as i64);
        v
    };

    let validators = genesis_validator_set(genesis_n, base_port);
    // A late joiner whose peer id is below every genesis id, so it dials the whole bootstrap set and meshes
    // deterministically (mirrors the join convergence/audit tests).
    let genesis_min = (0..genesis_n).map(|i| NodeIdentity::from_seed(i).peer_id()).min().unwrap();
    let withholder_seed = {
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
    for seed in 0..genesis_n {
        let mut node = Node::new(NodeIdentity::from_seed(seed), cfg(seed as u16)).with_preferences(prefs(seed), epsilon);
        node = if seed == subject_seed {
            node.leaves_at(subject_leave)
        } else if seed == custodian_leaver_seed {
            node.with_arbitration_authority().leaves_at(custodian_leave)
        } else {
            node.with_arbitration_authority()
        };
        handles.push(tokio::spawn(node.run()));
    }
    // The late joiner: lands on the fresh committee but withholds its round-1 receipt.
    handles.push(tokio::spawn(
        Node::new(NodeIdentity::from_seed(withholder_seed), cfg(genesis_n as u16))
            .joins_at(join_at)
            .byzantine_withhold_handoff()
            .run(),
    ));

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus survives the two departures and the late join with full BFT finality.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The subject and the departing custodian rotated out; the late joiner is now an active validator.
    let subject = NodeIdentity::from_seed(subject_seed).peer_id();
    let custodian = NodeIdentity::from_seed(custodian_leaver_seed).peer_id();
    let w = NodeIdentity::from_seed(withholder_seed).peer_id();
    assert!(!outs[0].final_active.contains(&subject), "the round-0 subject must have rotated out");
    assert!(!outs[0].final_active.contains(&custodian), "the departing custodian must have rotated out");
    assert!(outs[0].final_active.contains(&w), "the late joiner must have been admitted");

    // 3. Both rounds completed: round 0 (original committee) and round 1 (re-handoff under the fresh
    //    committee) each reached custody threshold — the withholder did NOT stall the re-handoff.
    for o in &outs {
        assert!(o.handoff_complete, "node {} must see the round-0 handoff complete", hex::encode(&o.peer_id[..4]));
        assert!(o.rehandoff_complete, "node {} must see the re-handoff complete via the custody threshold", hex::encode(&o.peer_id[..4]));
    }

    // 4. The withholder is defaulted AND slashed — on every node, derived purely from the chain.
    for o in &outs {
        assert!(
            o.handoff_defaults.contains(&w),
            "node {} must default the withholding fresh-committee member",
            hex::encode(&o.peer_id[..4])
        );
        assert!(
            o.slashed.contains(&w),
            "node {} must slash the re-handoff withholder from leadership",
            hex::encode(&o.peer_id[..4])
        );
    }

    // 5. The honest surviving custodians are NOT spuriously defaulted.
    for seed in [1u64, 2, 3] {
        let honest = NodeIdentity::from_seed(seed).peer_id();
        assert!(!outs[0].handoff_defaults.contains(&honest), "an honest survivor must not be defaulted");
    }
}
