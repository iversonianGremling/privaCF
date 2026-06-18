//! Integration capstone: the *autonomous* Class-2 audit — admission-time Sybil-cohort detection
//! driven entirely in-loop (SPEC §4.9.7 / §7).
//!
//! A live BFT network grows by admitting a *cohort* of newcomers that all ask to join at once — the
//! classic Sybil pattern (organic growth trickles in; a Sybil operator spins up many identities
//! together). No off-chain coordinator: each genesis validator is an in-loop audit observer that,
//! reading the same finalized chain, VRF-selects itself per newly-admitted subject and emits a
//! signed `FirstObservation` report; the next leader records it in `BlockHeader::audit_reports`. From
//! those on-chain attestations every node deterministically derives the admission-time burst score
//! (`audit.rs`) and flags exactly the co-admitted cohort — while the genesis bootstrap set, never an
//! audit subject, is spared. Every node converges on the same chain and the same flagged set.

use std::collections::HashSet;

use mvp_node::audit;
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mass_join_cohort_is_autonomously_flagged_in_loop() {
    // A modest 4 + 3 network with a deliberately *large* round window: the per-round slack keeps
    // consensus from spurious view-changes even on a loaded host, so the test is timing-robust rather
    // than fast. (The newcomers dial the whole genesis set, so they mesh and vote in time; the genesis
    // set plus connected cohort comfortably clears quorum each round.)
    let genesis_n = 4u64;
    let cohort_n = 3usize; // == audit::BURST_THRESHOLD — a co-admitted burst of this size trips it.
    let epochs = 9u64;
    let base_port = 9120u16;
    let window_ms = 600u64;

    let validators = genesis_validator_set(genesis_n, base_port);
    // Pick cohort newcomers whose peer ids are all below every genesis id, so they dial the whole
    // bootstrap set and form a full mesh deterministically (mirrors the join convergence test).
    let genesis_min = (0..genesis_n).map(|i| NodeIdentity::from_seed(i).peer_id()).min().unwrap();
    let mut join_seeds: Vec<u64> = Vec::new();
    let mut s = 1000u64;
    while join_seeds.len() < cohort_n {
        if NodeIdentity::from_seed(s).peer_id() < genesis_min {
            join_seeds.push(s);
        }
        s += 1;
    }
    let cohort_subjects: HashSet<u64> =
        join_seeds.iter().map(|&s| audit::subject_id(&NodeIdentity::from_seed(s).peer_id())).collect();
    let mut expected_flagged: Vec<u64> = cohort_subjects.iter().copied().collect();
    expected_flagged.sort_unstable();

    let mut handles = Vec::new();
    // Genesis validators: each is an in-loop audit observer.
    for i in 0..genesis_n {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 18,
        };
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(i), cfg).with_audit_authority().run()));
    }
    // The Sybil cohort: newcomers that all ask to join from boot (admitted in a tight window). They
    // are subjects of audit, not observers.
    for (k, &seed) in join_seeds.iter().enumerate() {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + genesis_n as u16 + k as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 18,
        };
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(seed), cfg).joining().run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The network still converges on one finalized chain with full BFT finality — the audit
    //    machinery rides on top of consensus (and the grown validator set) without breaking it.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The whole cohort was admitted — the active set grew by exactly the newcomers.
    assert_eq!(
        outs[0].final_active.len() as u64,
        genesis_n + cohort_n as u64,
        "every cohort member must have joined the active set"
    );

    // 3. Observers actually attested: first-observation reports were recorded on-chain.
    assert!(
        outs[0].audit_reports_recorded >= cohort_n,
        "at least one report per subject must be recorded, got {}",
        outs[0].audit_reports_recorded
    );

    // 4. The cohort was autonomously flagged as an admission-time burst — and every node agrees (the
    //    flag lives in the finalized chain).
    assert!(!outs[0].flagged_cohort.is_empty(), "the mass-join cohort must be flagged");
    for o in &outs {
        assert_eq!(o.flagged_cohort, head_flagged(&outs), "all nodes must agree on the flagged cohort");
    }

    // 5. The flagged set is exactly the co-admitted newcomers — the genesis bootstrap set is never an
    //    audit subject and is never flagged (no false positives).
    assert_eq!(
        outs[0].flagged_cohort, expected_flagged,
        "exactly the co-admitted cohort is flagged, not the genesis bootstrap"
    );
    let genesis_subjects: HashSet<u64> =
        (0..genesis_n).map(|i| audit::subject_id(&NodeIdentity::from_seed(i).peer_id())).collect();
    for sid in &outs[0].flagged_cohort {
        assert!(!genesis_subjects.contains(sid), "a genesis member was wrongly flagged");
        assert!(cohort_subjects.contains(sid), "a non-cohort subject was flagged");
    }
}

/// The flagged cohort agreed by node 0 (used as the reference all nodes must match).
fn head_flagged(outs: &[mvp_node::node::NodeOutcome]) -> Vec<u64> {
    outs[0].flagged_cohort.clone()
}
