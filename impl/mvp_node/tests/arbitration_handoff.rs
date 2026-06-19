//! Integration capstone: the *autonomous* §4.1/§6.4 arbitration handoff, driven entirely in-loop.
//!
//! When a node departs custody (here a graceful rotation out of the validator set), an **arbitration
//! committee** must assume responsibility for its preference profile without ever learning it. No
//! off-chain coordinator: the departing node Shamir-splits its custody secret and seals each share —
//! plus the on-chain commitment's blinding `r_old` — to a committee member's `mix_pk` (confidential,
//! one parcel per member). The committee is beacon-selected, so every node re-derives it from public
//! chain data. Each selected member opens its parcel, *homomorphically* re-blinds the subject's on-chain
//! `C_p` to a fresh blinding it controls (never seeing the vector), proves in zero knowledge that the new
//! commitment re-encrypts the SAME vector, and files a signed `HandoffReceipt`. The next leader records
//! the receipts in `BlockHeader::handoff_receipts`; every node settles them identically and sees the
//! handoff reach a custody threshold — the departed node's profile preserved under new custody, its
//! blinding never exposed.

use mvp_node::arbitration;
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departing_nodes_profile_is_handed_off_to_its_committee_in_loop() {
    // 6 validators, each with a Layer-5 preference profile. One rotates out at height 3; the other five
    // serve on arbitration committees. After the departure, the beacon-selected committee (4 of the 5
    // remaining) takes custody of the departed node's commitment. A generous window keeps consensus
    // stable on a loaded host; quorum survives the departure (5 left, quorum 4).
    let total_n = 6u64;
    let leaver_seed = 5u64;
    let leave_height = 3u64;
    let epochs = 12u64;
    let base_port = 9220u16;
    let window_ms = 700u64;
    let epsilon = 6.0;

    // Distinct small preference profiles so each node has its own on-chain C_p to (potentially) hand off.
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
        if seed == leaver_seed {
            node = node.leaves_at(leave_height); // the departing subject
        } else {
            node = node.with_arbitration_authority(); // a potential committee member
        }
        handles.push(tokio::spawn(node.run()));
    }

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. The network converges on one finalized chain with full BFT finality — the handoff machinery
    //    rides on top of consensus (and the departure) without breaking it.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The departure actually took effect: the leaver is no longer in the active validator set.
    let leaver = NodeIdentity::from_seed(leaver_seed).peer_id();
    assert!(
        !outs[0].final_active.contains(&leaver),
        "the rotated-out node must be gone from the active set"
    );

    // 3. The committee filed receipts: at least a custody threshold of valid handoff receipts is recorded
    //    on-chain (the departed node's profile is now redundantly custodied).
    assert!(
        outs[0].handoff_receipts_recorded >= arbitration::CUSTODY_THRESHOLD,
        "at least a custody threshold of handoff receipts must be recorded, got {}",
        outs[0].handoff_receipts_recorded
    );

    // 4. Every node agrees the handoff completed — the trigger is a pure function of the on-chain receipts
    //    settled against the beacon-selected committee + the subject's on-chain c_old.
    for o in &outs {
        assert!(
            o.handoff_complete,
            "node {} must see the departed node's handoff reach custody threshold",
            hex::encode(&o.peer_id[..4])
        );
    }
}
