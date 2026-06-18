//! ZK handoff statements (SPEC §6.4 Statements 1–3) proven against the *on-chain* `C_p`. A node
//! publishes a `PreferencePayload` each epoch carrying `c_p = Pedersen.commit(clean_prefs, blinding)`;
//! here we recompute that exact commitment + blinding and prove, in zero knowledge, that the committed
//! vector is norm-bounded, that its per-epoch change is small (temporal), and sign-consistent
//! (directional) — all binding to the published `c_p`, with no Goldilocks↔Ristretto bridge.

use mvp_node::epoch::{pref_blinding, PreferencePayload};
use mvp_node::pedersen::Pedersen;
use mvp_node::zkstmt::{
    prove_directional, prove_norm, prove_temporal, verify_directional, verify_norm, verify_temporal,
};

/// A node's secret handle (mirrors `Node::pref_sk_handle`) — any 32 bytes work for the test.
fn sk_handle(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[test]
fn statements_bind_to_the_published_c_p() {
    let sk = sk_handle(0xAB);
    let n_items = 6;
    let pc = Pedersen::new(n_items);

    // Two consecutive epochs of clean preferences (the node never publishes these).
    let prev = vec![3i64, 1, 0, 2, 4, 0];
    let curr = vec![3i64, 2, 1, 2, 3, 0]; // Δ = [0,+1,+1,0,-1,0], small & sign-consistent
    let (e_prev, e_curr) = (40u64, 41u64);

    // The payloads carry exactly c_p = commit(prefs, pref_blinding(sk, epoch)).
    let pay_prev = PreferencePayload::build(&prev, &sk, e_prev, 6.0);
    let pay_curr = PreferencePayload::build(&curr, &sk, e_curr, 6.0);
    let r_prev = pref_blinding(&sk, e_prev);
    let r_curr = pref_blinding(&sk, e_curr);

    // Sanity: the recomputed commitment matches the on-chain c_p.
    assert_eq!(pc.commit(&curr, &r_curr), pay_curr.c_p, "recomputed C_p matches the published payload");
    assert_eq!(pc.commit(&prev, &r_prev), pay_prev.c_p, "recomputed C_p matches the published payload");

    // Statement 1 — preference norm ‖p‖∞ ≤ 4, bound to the published c_p.
    let norm = prove_norm(&pc, &curr, &r_curr, 4, &sk_handle(1));
    assert!(verify_norm(&pc, &pay_curr.c_p, &norm), "norm statement verifies against on-chain C_p");

    // Statement 3 — temporal ‖Δp‖∞ ≤ 1, bound to C(T) − C(T−1) of the two published commitments.
    let temporal = prove_temporal(&pc, &prev, &r_prev, &curr, &r_curr, 1, &sk_handle(2));
    assert!(
        verify_temporal(&pc, &pay_prev.c_p, &pay_curr.c_p, &temporal),
        "temporal statement verifies against the on-chain difference"
    );

    // Statement 2 — directional: declared up/down/free signs all consistent with the actual change.
    let dirs = [0i8, 1, 1, 0, -1, 0];
    let directional = prove_directional(&pc, &prev, &r_prev, &curr, &r_curr, &dirs, 4, &sk_handle(3));
    assert!(
        verify_directional(&pc, &pay_prev.c_p, &pay_curr.c_p, &directional),
        "directional statement verifies against the on-chain difference"
    );
}

#[test]
fn a_norm_proof_does_not_transfer_to_another_nodes_c_p() {
    // The proof is bound to one node's commitment; another node's c_p (different secret) rejects it.
    let pc = Pedersen::new(4);
    let prefs = vec![2i64, 1, 0, 3];
    let (sk_a, sk_b) = (sk_handle(1), sk_handle(2));
    let epoch = 9u64;

    let pay_a = PreferencePayload::build(&prefs, &sk_a, epoch, 6.0);
    let pay_b = PreferencePayload::build(&prefs, &sk_b, epoch, 6.0);
    let r_a = pref_blinding(&sk_a, epoch);

    let proof = prove_norm(&pc, &prefs, &r_a, 3, &sk_handle(9));
    assert!(verify_norm(&pc, &pay_a.c_p, &proof), "verifies against A's own c_p");
    assert!(!verify_norm(&pc, &pay_b.c_p, &proof), "does not transfer to B's c_p");
}
