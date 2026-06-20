//! Integration capstone: §4.1 proactive re-share of the standing `VA_pub` threshold key, driven in-loop.
//!
//! `VA_pub` is the validator-attestation key that seals `s₂` and threshold-signs verdicts. Its shares are
//! held by the validators — so when the validator set ROTATES, custody of the shares must follow, WITHOUT
//! changing `VA_pub` (already-published `d_T` must stay decryptable) and WITHOUT any party reconstructing
//! the secret. Here a newcomer joins; the current shareholders proactively re-share `VA_pub` to the new
//! set (`dkg::reshare_subdeal`/`reshare_combine`, each sub-share sealed to a member's `mix_pk`), and the
//! whole new set — INCLUDING the joiner — ends holding fresh shares of the SAME `VA_pub`.
//!
//! The proof: every post-rotation node signs a canonical tag with its fresh share; a threshold subset of
//! the new set combines into a signature that verifies under the UNCHANGED `VA_pub`, and a sub-threshold
//! subset does not. So the joiner genuinely gained a usable share of the same group key, in-loop.

use mvp_node::bls;
use mvp_node::dkg::combine_signatures;
use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_threshold_keys, genesis_validator_set, Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn va_pub_is_re_shared_to_the_rotated_validator_set_preserving_the_group_key() {
    let genesis_n = 4u64;
    let threshold = 3usize;
    let epochs = 11u64;
    let base_port = 9480u16;
    let window_ms = 650u64;

    let validators = genesis_validator_set(genesis_n, base_port);
    let idents: Vec<NodeIdentity> = (0..genesis_n).map(NodeIdentity::from_seed).collect();
    let tks = genesis_threshold_keys(&idents, threshold);
    let va_pub = tks[&idents[0].peer_id()].va_pub;

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
    // Genesis validators: each holds a VA_pub share and is a canonical re-share dealer.
    for seed in 0..genesis_n {
        let id = NodeIdentity::from_seed(seed);
        let tk = tks[&id.peer_id()].clone();
        handles.push(tokio::spawn(Node::new(id, cfg(seed as u16)).with_threshold_key(tk).run()));
    }
    // The joiner: no genesis share, but participates in the re-share (knows the threshold).
    handles.push(tokio::spawn(
        Node::new(NodeIdentity::from_seed(joiner_seed), cfg(genesis_n as u16))
            .joining()
            .with_va_reshare(threshold)
            .run(),
    ));

    let mut outs = Vec::new();
    for h in handles {
        outs.push(h.await.expect("node task panicked"));
    }

    // 1. Consensus converges with full BFT finality across the join.
    let head0 = outs[0].head_hash;
    for o in &outs {
        assert_eq!(o.head_hash, head0, "node {} head diverged", hex::encode(&o.peer_id[..4]));
        assert!(o.all_qc_valid, "every finalized block must carry a valid quorum certificate");
    }

    // 2. The joiner was admitted.
    let joiner = NodeIdentity::from_seed(joiner_seed).peer_id();
    assert!(outs[0].final_active.contains(&joiner), "the joiner must be in the active set");

    // 3. Every node in the rotated set — INCLUDING the joiner — holds a fresh VA_pub share.
    for o in &outs {
        assert!(
            o.va_share_index.is_some() && o.va_proof_partial.is_some(),
            "node {} must hold a re-shared VA_pub share",
            hex::encode(&o.peer_id[..4])
        );
    }

    // 4. A threshold subset of the NEW set reconstructs a signature verifiable under the UNCHANGED VA_pub.
    let mut partials: Vec<(u64, [u8; 96])> = outs
        .iter()
        .filter_map(|o| {
            let idx = o.va_share_index?;
            let sig: [u8; 96] = o.va_proof_partial.as_ref()?.as_slice().try_into().ok()?;
            Some((idx, sig))
        })
        .collect();
    partials.sort_by_key(|(i, _)| *i);
    partials.dedup_by_key(|(i, _)| *i);
    assert!(partials.len() >= threshold, "at least a threshold of fresh shares must exist, got {}", partials.len());

    let sigma = combine_signatures(&partials[..threshold]).expect("combine threshold partials");
    assert!(
        bls::verify(&va_pub, Node::VA_PROOF_TAG, &sigma),
        "the re-shared new set signs under the UNCHANGED VA_pub"
    );

    // 5. A sub-threshold subset does NOT verify — the shares are genuine t-of-n shares of the group key.
    if partials.len() > threshold {
        let bad = combine_signatures(&partials[..threshold - 1]).expect("combine");
        assert!(!bls::verify(&va_pub, Node::VA_PROOF_TAG, &bad), "fewer than threshold cannot sign under VA_pub");
    }
}
