//! Integration test for the arbitration committee handoff (SPEC §4.1 / §6.4): a departing node's
//! state is taken over by a beacon-selected committee that (1) holds the node's custody secret under
//! Shamir sharing, (2) re-encrypts the node's on-chain preference commitment under a fresh blinding and
//! proves — in zero knowledge — both that the re-encryption is faithful AND that the re-committed
//! profile still satisfies the §6.4 handoff statements (norm + temporal), and (3) slashes any selected
//! member that fails to complete. The filing quorum then reconstructs the custody secret and rotates
//! the threshold `VA_pub` to the new custodians via the companion `dkg::reshare` — the full Phase-2
//! "multi-auditor handoff" wired together over real crypto.

use mvp_node::{arbitration, dkg, pedersen::Pedersen, zkstmt};
use mvp_node::identity::NodeIdentity;

fn peer_ids(ids: &[NodeIdentity]) -> Vec<[u8; 32]> {
    ids.iter().map(|i| i.peer_id()).collect()
}

#[test]
fn departing_node_is_handed_off_faithfully_with_a_defaulter_slashed() {
    // A validator set of 7; one node (the "subject") is suspended and must hand off its state.
    let validators: Vec<NodeIdentity> = (0..7u64).map(NodeIdentity::from_seed).collect();
    let vset = peer_ids(&validators);
    let beacon_t = 0xBEAC04u64;
    let subject_epoch_id = 0x5151u64;

    // ── 1. Beacon-seeded committee of 4, re-derivable by anyone from public chain data.
    let committee = arbitration::select_committee(&vset, beacon_t, subject_epoch_id, 4);
    assert_eq!(committee.len(), 4);
    // The same inputs select the same committee on every node.
    assert_eq!(committee, arbitration::select_committee(&vset, beacon_t, subject_epoch_id, 4));

    // ── 2. The departing node's preference commitment is on-chain (clean values known only to it).
    let pc = Pedersen::new(8);
    let prefs = [4i64, -2, 0, 3, 1, -1, 2, 0];
    let r_old = [17u8; 32];
    let c_old = pc.commit(&prefs, &r_old);

    // Its custody secret (here: the commitment blinding that lets a custodian re-open the profile) is
    // Shamir-split to the committee — any 3 of 4 reconstruct it, no single arbiter can.
    let custody = dkg::shamir_split(&r_old, 3, committee.len(), b"subject-custody");

    // ── 3. The committee re-commits the SAME profile under a fresh blinding it controls and proves it.
    let r_new = [29u8; 32];
    let c_new = pc.commit(&prefs, &r_new);

    // Map each committee peer back to its NodeIdentity (to sign receipts) and its custody share.
    let member_idx = |peer: &[u8; 32]| validators.iter().position(|v| &v.peer_id() == peer).unwrap();

    // Three members file valid handoff receipts; the fourth defaults (goes offline).
    let mut receipts = Vec::new();
    for (k, peer) in committee.iter().take(3).enumerate() {
        let id = &validators[member_idx(peer)];
        let reenc = arbitration::prove_reencryption(&pc, &c_old, &c_new, &r_old, &r_new, &[k as u8; 32]);
        receipts.push(arbitration::HandoffReceipt::create(id, subject_epoch_id, c_new, reenc, &custody[k].1));
    }

    // ── 4. Settle: the three filers are credited, the absentee is slashable.
    let (completed, defaulted) = arbitration::settle(&pc, &c_old, &committee, subject_epoch_id, &receipts);
    assert_eq!(completed.len(), 3, "three faithful handoffs accepted");
    assert_eq!(defaulted.len(), 1, "the non-completing member is slashed");
    assert_eq!(defaulted[0].member, committee[3]);

    // ── 5. The re-committed profile also satisfies the §6.4 handoff statements over c_new (a committee
    //       cannot quietly inflate the profile it took over): Statement 1 norm bound...
    let norm = zkstmt::prove_norm(&pc, &prefs, &r_new, 8, &[7u8; 32]);
    assert!(zkstmt::verify_norm(&pc, &c_new, &norm), "the handed-off profile is still norm-bounded");

    // ...and Statement 3 temporal: the handoff did not lurch the profile vs the prior epoch.
    let prev = [3i64, -2, 0, 2, 1, 0, 2, 0];
    let r_prev = [11u8; 32];
    let c_prev = pc.commit(&prev, &r_prev);
    let temporal = zkstmt::prove_temporal(&pc, &prev, &r_prev, &prefs, &r_new, 3, &[8u8; 32]);
    assert!(zkstmt::verify_temporal(&pc, &c_prev, &c_new, &temporal), "the handoff change stays within δ");

    // ── 6. The filing quorum recovers the custody secret with NO cooperation from the departed node,
    //       and rotates the threshold VA_pub to the new custodians (companion dkg::reshare).
    let quorum: Vec<(u64, [u8; 32])> = (0..3).map(|i| custody[i]).collect();
    assert_eq!(dkg::shamir_recover(&quorum), r_old, "the quorum reconstructs the departed node's custody secret");

    // Genesis threshold key over the old validators, re-shared to the committee preserving VA_pub.
    let old_parties: Vec<([u8; 32], Vec<u8>)> = {
        let mut v: Vec<([u8; 32], Vec<u8>)> =
            vset.iter().map(|p| (*p, format!("genesis-{}", hex::encode(&p[..4])).into_bytes())).collect();
        v.sort_by_key(|(p, _)| *p);
        v
    };
    let (va_pub, old_shares) = dkg::genesis_keys(5, &old_parties);
    let qualified: Vec<(u64, [u8; 32])> =
        old_parties.iter().enumerate().take(5).map(|(i, (p, _))| (i as u64 + 1, old_shares[p])).collect();
    let mut new_parties: Vec<([u8; 32], Vec<u8>)> =
        committee.iter().map(|p| (*p, format!("handoff-{}", hex::encode(&p[..4])).into_bytes())).collect();
    new_parties.sort_by_key(|(p, _)| *p);
    let new_shares = dkg::reshare(5.min(new_parties.len()), &qualified, &new_parties);

    // The new custodians threshold-sign under the UNCHANGED VA_pub.
    let t = 5.min(new_parties.len());
    let msg = b"post-handoff verdict authority";
    let partials: Vec<(u64, [u8; 96])> = new_parties
        .iter()
        .take(t)
        .enumerate()
        .map(|(i, (p, _))| (i as u64 + 1, dkg::sign_share(&new_shares[p], msg)))
        .collect();
    let sigma = dkg::combine_signatures(&partials).expect("threshold signature");
    assert!(mvp_node::bls::verify(&va_pub, msg, &sigma), "the rotated committee signs under the same VA_pub");
}
