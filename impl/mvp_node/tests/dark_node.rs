//! Dark-node extraction capstone (SPEC §4.9.6, P4.a). End-to-end with the real cryptography: a node
//! seals `s₂` each epoch under the genesis DKG threshold key (`NativeGroupVerEnc`); a committee runs
//! a commit-reveal SUSPEND verdict; the validators threshold-sign the verdict; and — from public data
//! alone, with NO cooperation from the (offline) target — anyone recovers its `null_v = s₁ + s₂` and
//! lists it in the SUSP_SMT so its non-membership provably fails (re-admission listing). This ties
//! together SMT (P1.1), VerEnc (P1.2), the live threshold key (P1.3), and the verdict flow (P1.4).

use mvp_node::bls::sign_dst;
use mvp_node::commit::{NativeGroupVerEnc, VerEnc};
use mvp_node::dkg::combine_signatures;
use mvp_node::field::{from_u64, random_field, sub_mod, to_u64};
use mvp_node::identity::NodeIdentity;
use mvp_node::node::genesis_threshold_keys;
use mvp_node::smt::{self, Smt};
use mvp_node::verdict::{self, cast, extract_null_v, tally_suspend, SUSPEND};
use mvp_node::verenc::VERENC_DST;

#[test]
fn a_suspended_node_has_its_null_v_extracted_without_cooperation_and_listed() {
    // Trusted genesis: a 3-of-4 DKG threshold key over the four validators.
    let validators: Vec<NodeIdentity> = (0..4).map(NodeIdentity::from_seed).collect();
    let committee_ids: Vec<[u8; 32]> = validators.iter().map(|v| v.peer_id()).collect();
    let tks = genesis_threshold_keys(&validators, 3);
    let va_pub = tks[&committee_ids[0]].va_pub;

    // The TARGET (validator 0) seals s₂ for one epoch, exactly as it would on-chain, then "goes
    // offline" — we never touch its secret key again.
    let target = &validators[0];
    let beacon = from_u64(0xFEED_BEEF);
    let epoch_id_fp = target.epoch_id(beacon);
    let epoch_id = to_u64(epoch_id_fp);
    let null_v = target.null_v; // what the network must recover without the target's help
    let mut rng = rand::rngs::OsRng;
    let s2 = random_field(&mut rng);
    let s1 = sub_mod(null_v, s2);
    let d_t = NativeGroupVerEnc { va_pub }.encrypt(s2, epoch_id_fp);
    assert!(!d_t.is_empty(), "the target sealed a real ciphertext");

    // The committee (validators 1,2,3 — a majority that excludes the accused) commit-reveal SUSPEND.
    let mut commits = Vec::new();
    let mut reveals = Vec::new();
    for (k, m) in validators.iter().enumerate().skip(1) {
        let (c, r) = cast(m, epoch_id, SUSPEND, [k as u8; 32]);
        commits.push(c);
        reveals.push(r);
    }
    assert!(
        tally_suspend(&commits, &reveals, &committee_ids, epoch_id) >= 3,
        "a majority committed-and-revealed SUSPEND"
    );

    // Finalization: those three validators threshold-sign verdict_id(epoch_id); combine → σ_VERDICT.
    let id = verdict::verdict_id(epoch_id);
    let partials: Vec<(u64, [u8; 96])> = committee_ids
        .iter()
        .skip(1)
        .map(|pid| {
            let tk = &tks[pid];
            (tk.index, sign_dst(&tk.share, &id, VERENC_DST))
        })
        .collect();
    let sigma = combine_signatures(&partials).expect("combine verdict signature");

    // Dark-node extraction: recover null_v from public (s1, d_T) + σ_VERDICT alone.
    let recovered = extract_null_v(to_u64(s1), &d_t, &sigma, epoch_id).expect("extraction");
    assert_eq!(recovered, to_u64(null_v), "the offline node's null_v is recovered from public data");

    // List it in the SUSP_SMT: it is now suspended, and a non-membership proof for it must fail
    // (the SMT-level re-admission rejection; unlinkable enforcement is the Statement-5 ZK proof).
    let mut susp = Smt::new();
    susp.insert(recovered);
    let root = susp.root();
    let mut claim_absent = susp.prove(recovered);
    claim_absent.present = false;
    assert!(!smt::verify(&root, &claim_absent), "a suspended null_v cannot prove non-membership");
    // A different, un-suspended null_v still proves non-membership.
    let other = recovered ^ 0x1;
    let other_proof = susp.prove(other);
    assert!(!other_proof.present && smt::verify(&root, &other_proof), "an unrelated id is still admissible");
}

#[test]
fn a_wrong_verdict_signature_cannot_extract() {
    let validators: Vec<NodeIdentity> = (0..4).map(NodeIdentity::from_seed).collect();
    let ids: Vec<[u8; 32]> = validators.iter().map(|v| v.peer_id()).collect();
    let tks = genesis_threshold_keys(&validators, 3);
    let va_pub = tks[&ids[0]].va_pub;

    let target = &validators[0];
    let epoch_id = to_u64(target.epoch_id(from_u64(1)));
    let mut rng = rand::rngs::OsRng;
    let s2 = random_field(&mut rng);
    let s1 = sub_mod(target.null_v, s2);
    let d_t = NativeGroupVerEnc { va_pub }.encrypt(s2, target.epoch_id(from_u64(1)));

    // A σ for a DIFFERENT epoch's verdict cannot extract this epoch's null_v.
    let wrong_id = verdict::verdict_id(epoch_id ^ 1);
    let partials: Vec<(u64, [u8; 96])> = ids
        .iter()
        .skip(1)
        .map(|pid| (tks[pid].index, sign_dst(&tks[pid].share, &wrong_id, VERENC_DST)))
        .collect();
    let wrong_sigma = combine_signatures(&partials).expect("combine");
    assert_ne!(
        extract_null_v(to_u64(s1), &d_t, &wrong_sigma, epoch_id),
        Some(to_u64(target.null_v)),
        "a wrong-epoch verdict signature must not recover null_v"
    );
}
