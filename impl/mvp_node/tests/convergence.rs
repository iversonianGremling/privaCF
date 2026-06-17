//! Integration test: N in-process nodes over loopback TCP cycle K epochs and must converge on one
//! chain head, with each node rotating distinct per-epoch `epoch_id`s and a correct publish-`s₁`
//! split every epoch.

use std::collections::HashSet;

use mvp_node::beacon::{next_beacon, GENESIS_BEACON, GENESIS_VRF_OUTPUT};
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};
use mvp_node::vrf::VrfClaim;

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

    // 2. Each node rotated distinct epoch_ids across the K epochs, the split held, and every
    //    finalized block carries a valid quorum certificate (BFT finality).
    for o in &outs {
        let ids: HashSet<u64> = o.epoch_ids.iter().map(|(_, e)| *e).collect();
        assert_eq!(ids.len(), o.epoch_ids.len(), "epoch_ids must be distinct across epochs");
        assert_eq!(o.epoch_ids.len() as u64, epochs, "one epoch_id per epoch");
        assert!(o.split_ok, "publish-s1 split s1+s2=null_v must hold every epoch");
        assert!(o.all_qc_valid, "every block must carry a valid quorum certificate");
    }

    // 3. At a fixed height, distinct nodes (distinct sk) produce distinct epoch_ids.
    let at_h1: Vec<u64> = outs
        .iter()
        .map(|o| o.epoch_ids.iter().find(|(h, _)| *h == 1).expect("height-1 epoch_id").1)
        .collect();
    let set: HashSet<u64> = at_h1.iter().copied().collect();
    assert_eq!(set.len(), at_h1.len(), "distinct nodes must have distinct epoch_ids at one height");
}

/// View-change: make the height-1 VRF leader a Byzantine node that withholds its proposal. The
/// other validators must time out and view-change to the next-lowest-VRF leader, still finalizing
/// every height with a quorum certificate and converging.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn view_change_recovers_from_a_withholding_leader() {
    let nodes = 4u64;
    let epochs = 6u64;
    let base_port = 9400u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(nodes, base_port);

    // Deterministically pick the height-1 view-0 leader (lowest VRF output) as the faulty node,
    // guaranteeing at least one view-change.
    let beacon1 = next_beacon(GENESIS_BEACON, &GENESIS_VRF_OUTPUT, 1);
    let faulty = (0..nodes)
        .min_by_key(|&i| VrfClaim::create(&NodeIdentity::from_seed(i), 1, beacon1).output)
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 12,
        };
        let node = Node::new(NodeIdentity::from_seed(i), cfg);
        let node = if i == faulty { node.byzantine_withhold() } else { node };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // All nodes (the 3 honest + the faulty one, which still tracks the chain) converge.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} diverged", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "every height still finalized");
        assert!(o.all_qc_valid, "every block must carry a valid quorum certificate");
    }
    // View-change actually fired: at least one block was finalized in a view > 0.
    let max_view = outs.iter().map(|o| o.max_view).max().unwrap();
    assert!(max_view >= 1, "view-change should have advanced past the withholding leader (got {max_view})");
}

/// Equivocation slashing: make the height-1 VRF leader a Byzantine node that double-signs its slot
/// (proposes two conflicting blocks). The honest validators must detect the equivocation from the
/// two signed proposals, slash the offender network-wide, and still converge on one chain with no
/// fork. (Whether the offender's first block finalizes or it is skipped depends on gossip order —
/// both are safe; the invariants asserted here hold either way.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slashing_detects_and_punishes_an_equivocating_leader() {
    let nodes = 4u64;
    let epochs = 6u64;
    let base_port = 9500u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(nodes, base_port);
    let beacon1 = next_beacon(GENESIS_BEACON, &GENESIS_VRF_OUTPUT, 1);
    let faulty = (0..nodes)
        .min_by_key(|&i| VrfClaim::create(&NodeIdentity::from_seed(i), 1, beacon1).output)
        .unwrap();
    let faulty_peer = NodeIdentity::from_seed(faulty).peer_id();

    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 12,
        };
        let node = Node::new(NodeIdentity::from_seed(i), cfg);
        let node = if i == faulty { node.byzantine_equivocate() } else { node };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // No fork: every node converges to one head and chain length, each block a valid quorum cert.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} forked", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "chain still progressed every height");
        assert!(o.all_qc_valid, "every finalized block carries a valid quorum certificate");
    }
    // Every honest node detected the equivocation and slashed the offender.
    for o in outs.iter().filter(|o| o.peer_id != faulty_peer) {
        assert!(
            o.slashed.contains(&faulty_peer),
            "honest node {} did not slash the equivocator",
            hex::encode(&o.peer_id[..4])
        );
    }
}

/// Vote-equivocation slashing: make a (non-leader) validator double-vote — sign two different block
/// ids in the same slot. Every honest validator must detect the double-vote from the two BLS-signed
/// votes, slash the offender network-wide, and still finalize every height with a quorum certificate
/// (the offender's vote is never needed: the remaining honest validators are a quorum on their own).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slashing_detects_and_punishes_a_double_voting_validator() {
    let nodes = 4u64;
    let epochs = 6u64;
    let base_port = 9600u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(nodes, base_port);
    let beacon1 = next_beacon(GENESIS_BEACON, &GENESIS_VRF_OUTPUT, 1);
    // Pick the HIGHEST-VRF node at height 1 as the offender, so it is not the view-0 leader — the
    // double-vote is exercised on the vote path, independent of proposing.
    let faulty = (0..nodes)
        .max_by_key(|&i| VrfClaim::create(&NodeIdentity::from_seed(i), 1, beacon1).output)
        .unwrap();
    let faulty_peer = NodeIdentity::from_seed(faulty).peer_id();

    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 12,
        };
        let node = Node::new(NodeIdentity::from_seed(i), cfg);
        let node = if i == faulty { node.byzantine_double_vote() } else { node };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // No fork: every node converges to one head and length, each block a valid quorum certificate.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} forked", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "chain still progressed every height");
        assert!(o.all_qc_valid, "every finalized block carries a valid quorum certificate");
    }
    // Every honest node detected the double-vote and slashed the offender.
    for o in outs.iter().filter(|o| o.peer_id != faulty_peer) {
        assert!(
            o.slashed.contains(&faulty_peer),
            "honest node {} did not slash the double-voter",
            hex::encode(&o.peer_id[..4])
        );
    }
}

/// The randomness beacon is VRF-chained: every node derives the identical beacon sequence from the
/// finalized chain (so consensus still converges), yet that sequence is NOT predictable from the
/// genesis seed alone — from height 2 on it folds in the real, ungrindable VRF output of the prior
/// block, so it diverges from the genesis-time-computable "zero-VRF" projection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beacon_is_vrf_chained_and_unpredictable_from_genesis() {
    let nodes = 4u64;
    let epochs = 5u64;
    let base_port = 9700u16;
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

    // 1. Every node derived the identical beacon sequence (randomness convergence).
    let beacons0 = &outs[0].beacons;
    for o in &outs {
        assert_eq!(&o.beacons, beacons0, "node {} beacon chain diverged", hex::encode(&o.peer_id[..4]));
    }
    assert_eq!(beacons0.len() as u64, epochs, "one beacon per height");

    // 2. The genesis-time projection (every block assumed a zero VRF output) diverges from the
    //    realized beacon by height 2 — proving real VRF entropy entered the chain, i.e. an attacker
    //    cannot compute the height-2+ leader schedule from the genesis seed.
    let mut projected = Vec::new();
    let mut prev = GENESIS_BEACON;
    for h in 1..=epochs {
        let b = next_beacon(prev, &GENESIS_VRF_OUTPUT, h);
        projected.push((h, b));
        prev = b;
    }
    assert_eq!(beacons0[0], projected[0], "height-1 beacon depends only on genesis, must match");
    assert_ne!(
        beacons0[1], projected[1],
        "height-2 beacon must fold in block-1's real VRF output (not predictable from genesis)"
    );
}

/// Dynamic membership + quorum reconfiguration: a validator gracefully leaves mid-run by gossiping a
/// self-signed leave op. The current leader records it on-chain; once that block finalizes, every
/// node derives the same reduced active set (5 → 4) — so the BFT quorum shrinks from 4 to 3 — and
/// the network keeps finalizing blocks whose quorum certificates are now validated under the smaller
/// set. All nodes (including the leaver, which stays connected and follows the chain) agree on the
/// final membership: the safety crux is that the active set is a pure function of the finalized chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_membership_lets_a_validator_leave_and_reconfigures_quorum() {
    let nodes = 5u64;
    let epochs = 6u64;
    let base_port = 9800u16;
    let window_ms = 200u64;
    let leave_height = 2u64; // leave op recorded at height 2 → active from height 3

    let validators = genesis_validator_set(nodes, base_port);
    let leaver = nodes - 1;
    let leaver_peer = NodeIdentity::from_seed(leaver).peer_id();

    let mut handles = Vec::new();
    for i in 0..nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 14,
        };
        let node = Node::new(NodeIdentity::from_seed(i), cfg);
        let node = if i == leaver { node.leaves_at(leave_height) } else { node };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // The expected post-leave membership: the genesis set minus the leaver.
    let mut expected_active: Vec<[u8; 32]> =
        (0..nodes).filter(|&i| i != leaver).map(|i| NodeIdentity::from_seed(i).peer_id()).collect();
    expected_active.sort();

    let head0 = outs[0].head_hash;
    for o in &outs {
        // 1. Convergence held through the reconfiguration: one head, full length, valid QCs at every
        //    height (each validated under the active set in effect at that height).
        assert_eq!(o.head_hash, head0, "node {} forked", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "chain progressed every height post-leave");
        assert!(o.all_qc_valid, "every block's QC valid under its height's active set");
        // 2. Every node — the leaver included — agrees the active set is now the genesis set minus
        //    the leaver, i.e. the quorum shrank from 4 to 3.
        assert_eq!(
            o.final_active, expected_active,
            "node {} disagrees on final membership",
            hex::encode(&o.peer_id[..4])
        );
        assert!(!o.final_active.contains(&leaver_peer), "leaver must be out of the active set");
        assert_eq!(o.final_active.len() as u64, nodes - 1, "active set must be one smaller");
    }
}

/// The join side of dynamic membership: a brand-new node — NOT in the genesis set — boots with the
/// genesis set as its bootstrap peers, gossips a self-signed join op until admitted, and becomes a
/// full validator. The dial layer reaches the newcomer once its address is known, and every node
/// (genesis and newcomer alike) converges on the grown 4 → 5 validator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_membership_lets_a_new_validator_join() {
    let genesis_n = 4u64;
    let epochs = 8u64;
    let base_port = 9900u16;
    let window_ms = 200u64;

    let validators = genesis_validator_set(genesis_n, base_port);
    // Choose a newcomer whose peer id is below every genesis id, so it dials the whole bootstrap set
    // and forms a full mesh deterministically (a larger-id newcomer relies on reverse-dialing, which
    // is also implemented but timing-sensitive to assert on).
    let genesis_min =
        (0..genesis_n).map(|i| NodeIdentity::from_seed(i).peer_id()).min().unwrap();
    let join_seed =
        (1000u64..).find(|&s| NodeIdentity::from_seed(s).peer_id() < genesis_min).unwrap();
    let joiner_peer = NodeIdentity::from_seed(join_seed).peer_id();

    let mut handles = Vec::new();
    for i in 0..genesis_n {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms,
            max_height: epochs,
            grace_ms: window_ms * 16,
        };
        handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(i), cfg).run()));
    }
    // The newcomer: not in genesis, uses the genesis set purely as bootstrap, and asks to join.
    let joiner_cfg = NodeConfig {
        listen_addr: format!("127.0.0.1:{}", base_port + genesis_n as u16),
        genesis_validators: validators.clone(),
        window_ms,
        max_height: epochs,
        grace_ms: window_ms * 16,
    };
    handles.push(tokio::spawn(Node::new(NodeIdentity::from_seed(join_seed), joiner_cfg).joining().run()));

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // Expected final membership: the genesis set plus the newcomer.
    let mut expected_active: Vec<[u8; 32]> =
        (0..genesis_n).map(|i| NodeIdentity::from_seed(i).peer_id()).collect();
    expected_active.push(joiner_peer);
    expected_active.sort();

    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} forked", hex::encode(&o.peer_id[..4]));
        assert_eq!(o.blocks_len as u64, epochs + 1, "chain progressed every height");
        assert!(o.all_qc_valid, "every block's QC valid under its height's active set");
        assert_eq!(
            o.final_active, expected_active,
            "node {} disagrees on final membership",
            hex::encode(&o.peer_id[..4])
        );
        assert!(o.final_active.contains(&joiner_peer), "newcomer must have joined the active set");
        assert_eq!(o.final_active.len() as u64, genesis_n + 1, "active set grew by the newcomer");
    }
}
