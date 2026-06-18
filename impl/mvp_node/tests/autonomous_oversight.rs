//! Integration capstone: the *autonomous* §4.9.8 watchdog / recursive-oversight trigger, driven
//! entirely in-loop.
//!
//! The rogue-committee defense. A committee mounting mass-deanonymization cannot decrypt a single
//! `null_v` without first *publicly committing* to its verdicts (the §4.9.6 commit-reveal ordering) —
//! so an anomalous burst of public `verdict_commit` transactions is visible on the finalized chain
//! *before* any identity is exposed. Here one rogue validator posts a burst of verdict-commits against
//! *innocent* pseudonyms (no behavioral justification). No off-chain coordinator: each honest validator
//! is an in-loop watchdog that, reading the same chain, sees the burst outrun the behavioral signals,
//! raises a signed `WatchdogSignal`, and the next leader records it in `BlockHeader::watchdog_signals`.
//! From those on-chain signals every node deterministically derives the recursive-oversight trigger —
//! caught at the commit stage, before a single identity is deanonymized. Every node converges on the
//! same chain and the same trigger.

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};
use mvp_node::watchdog;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rogue_verdict_commit_burst_autonomously_triggers_oversight_in_loop() {
    // A 4 + 1 network: four honest in-loop watchdogs and one rogue committee. A deliberately large
    // round window keeps consensus from spurious view-changes even on a loaded host (timing-robust, not
    // fast). The rogue is a correct BFT validator — only its verdict-commit emission is adversarial.
    let honest_n = 4u64; // each an in-loop watchdog; honest_n >= watchdog::SIGNAL_QUORUM
    let total_n = honest_n + 1; // + the rogue
    let epochs = 10u64;
    let base_port = 9140u16;
    let window_ms = 600u64;

    // The rogue's innocent targets: a burst comfortably beyond THRESHOLD_WATCHDOG, none of which carries
    // an objectively-malformed on-chain tx, so the behavioral signals stay at zero (a true anomaly).
    let n_targets = (watchdog::THRESHOLD_WATCHDOG as u64) + 4; // 8
    let rogue_targets: Vec<u64> = (0..n_targets).map(|i| 0xDEAD_BEEF_0000_0000 ^ (i + 1)).collect();

    let validators = genesis_validator_set(total_n, base_port);
    let cfg = |i: u64| NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        grace_ms: window_ms * 18,
    };

    let mut handles = Vec::new();
    // Seeds 0..honest_n are honest watchdogs; the last seed is the rogue committee.
    for i in 0..honest_n {
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(i), cfg(i)).with_watchdog_authority().run()));
    }
    let rogue_seed = honest_n;
    handles.push(tokio::spawn(
        Node::new(NodeIdentity::from_seed(rogue_seed), cfg(rogue_seed))
            .byzantine_rogue_verdict_commits(rogue_targets.clone())
            .run(),
    ));

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The network still converges on one finalized chain with full BFT finality — the oversight
    //    machinery rides on top of consensus without breaking it.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The rogue's public verdict-commit burst was recorded on-chain — a burst beyond the watchdog
    //    threshold (the deanonymization sweep is visible BEFORE any null_v is decryptable).
    assert!(
        outs[0].verdict_commits_recorded as f64 > watchdog::THRESHOLD_WATCHDOG,
        "the verdict-commit burst must exceed the watchdog threshold, got {}",
        outs[0].verdict_commits_recorded
    );

    // 3. Honest watchdogs actually attested: a quorum of signed signals was recorded on-chain.
    assert!(
        outs[0].watchdog_signals_recorded >= watchdog::SIGNAL_QUORUM,
        "at least a signal quorum must be recorded, got {}",
        outs[0].watchdog_signals_recorded
    );

    // 4. The burst autonomously triggered recursive oversight — and every node agrees (the trigger
    //    lives in the finalized chain, a pure function of the on-chain signals + burst).
    for o in &outs {
        assert!(
            o.oversight_triggered,
            "node {} must derive the oversight trigger from the on-chain watchdog quorum",
            hex::encode(&o.peer_id[..4])
        );
    }
}
