//! Integration capstone: the §4.1/§6.4 arbitration **re-handoff**, driven entirely in-loop.
//!
//! Round 0 is the ordinary handoff: a node departs and a beacon-selected committee takes custody of its
//! on-chain commitment, Shamir-holding the departed node's recovery secret `sk_handle` `t`-of-`K`. The new
//! risk this test exercises is **committee churn**: when one of those original custodians ITSELF leaves the
//! validator set, custody must be re-established under a FRESH committee — without the original (gone) node,
//! and crucially WITHOUT any party ever reconstructing `sk_handle`.
//!
//! Each surviving custodian proactively re-shares only its OWN Shamir share to the fresh committee
//! (`dkg::reshare_subdeal`), sealed confidentially per new member (`arbitration::seal_reshare`); a new
//! member combines the sub-shares (`dkg::reshare_combine`) into a fresh share of the SAME `sk_handle`,
//! homomorphically re-blinds the subject's on-chain `c_old`, proves the re-encryption, and files a round-1
//! handoff receipt under the fresh committee. The trigger (an original custodian's `Remove`), the fresh
//! committee, and the canonical dealer set are all re-derived identically by every node from public chain
//! data — no off-chain coordinator — so every node agrees the re-handoff completed.

use mvp_node::arbitration;
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departing_custodian_triggers_a_re_handoff_to_a_fresh_committee_in_loop() {
    // 5 genesis validators. seed4 is the round-0 SUBJECT (leaves at h2). The other four are the only
    // committee candidates, and the committee size is 4 — so they ARE the round-0 committee, guaranteed.
    // seed0, one of those custodians, then leaves at h6: that departure is the re-handoff trigger. The three
    // survivors (seeds 1,2,3) re-share the custody to the fresh committee (which, in this minimal set, is the
    // survivors themselves — each acts as both dealer and fresh custodian, self-delivering its own sub-share).
    let total_n = 5u64;
    let subject_seed = 4u64; // round-0 subject
    let custodian_leaver_seed = 0u64; // an original custodian that departs → re-handoff trigger
    let subject_leave = 2u64;
    let custodian_leave = 6u64;
    let epochs = 13u64;
    let base_port = 9300u16;
    let window_ms = 800u64;
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
        node = if seed == subject_seed {
            node.leaves_at(subject_leave) // the round-0 subject
        } else if seed == custodian_leaver_seed {
            node.with_arbitration_authority().leaves_at(custodian_leave) // custodian that later departs
        } else {
            node.with_arbitration_authority() // a surviving custodian / re-handoff dealer
        };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus survives BOTH departures (the subject's and a custodian's) with full BFT finality.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. Both the subject and the departing custodian are gone from the active set.
    let subject = NodeIdentity::from_seed(subject_seed).peer_id();
    let custodian = NodeIdentity::from_seed(custodian_leaver_seed).peer_id();
    assert!(!outs[0].final_active.contains(&subject), "the round-0 subject must have rotated out");
    assert!(!outs[0].final_active.contains(&custodian), "the departing custodian must have rotated out");

    // 3. Round 0 completed (the original committee took custody) — the precondition for a re-handoff.
    for o in &outs {
        assert!(o.handoff_complete, "node {} must see the round-0 handoff reach custody threshold", hex::encode(&o.peer_id[..4]));
    }

    // 4. The re-handoff completed under the fresh committee — every node agrees, derived from the chain.
    for o in &outs {
        assert!(
            o.rehandoff_complete,
            "node {} must see the departed custodian's re-handoff reach custody threshold under the fresh committee",
            hex::encode(&o.peer_id[..4])
        );
    }

    // 5. Both rounds left a custody threshold of receipts on-chain (round 0 + round 1, distinct subjects).
    assert!(
        outs[0].handoff_receipts_recorded >= 2 * arbitration::CUSTODY_THRESHOLD,
        "both handoff rounds must record at least a custody threshold of receipts each, got {}",
        outs[0].handoff_receipts_recorded
    );
}
