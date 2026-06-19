//! Arbitration committee orchestration (SPEC §4.1 / §6.4). When a node departs custody — suspended by
//! a verdict, or rotated out of the validator set — an **arbitration committee** assumes responsibility
//! for its state under three guarantees:
//!
//!   * **Beacon-seeded committee selection** — the committee is the `size` validators with the smallest
//!     `H(beacon_t ‖ subject ‖ peer)`. Seeded by the unpredictable chain beacon (the VRF/VDF output),
//!     so it is a *verifiable-random* subcommittee anyone re-derives from public chain data — no extra
//!     interaction, the same derive-from-chain discipline the validator set uses.
//!   * **Shamir custody of node state** — the departing node's secret recovery state is `(t, K)`
//!     Shamir-split across the committee (`dkg::shamir_split`); any `t` members reconstruct it, `t−1`
//!     learn nothing. No single arbiter ever holds the node's secret.
//!   * **ZK handoff / re-encryption proof** — the committee re-commits the departing node's preference
//!     vector under a fresh blinding it controls (`c_new`) and proves, in zero knowledge, that `c_new`
//!     commits the SAME vector as the on-chain `c_old` (i.e. `c_new − c_old = Δr·H`, a Schnorr PoK of
//!     the blinding difference over `H`). Composed with the `zkstmt` Statements 1–3
//!     (norm/directional/temporal) over `c_new`, the handoff is provably faithful WITHOUT revealing the
//!     preferences: a committee cannot substitute an arbitrary profile for the node it took over.
//!
//! **Slashing for non-completion** — a selected member that publishes no valid handoff receipt by the
//! close defaults; [`settle`] emits a [`HandoffDefault`] for it, recomputable by anyone from the public
//! committee + receipts and fed to the same `slashed`-set machinery the consensus equivocation path
//! uses. This re-share of *custody* on rotation is the companion to [`crate::dkg::reshare`], which
//! rotates the threshold `VA_pub` shares preserving the group key.
//!
//! Scope: the arbitration **mechanism** (selection / custody / re-encryption proof / receipts / default
//! evidence) and its crypto, tested standalone end-to-end. Driving it inside the live consensus loop
//! (the *when* — triggering on a verdict/rotation and carrying receipts in blocks) is the tracked
//! refinement, mirroring `verdict.rs`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::identity::{verify as verify_ed25519, NodeIdentity};
use crate::pedersen::Pedersen;

/// Arbitration committee size — the `size` of [`select_committee`] for an in-loop handoff.
pub const COMMITTEE_SIZE: usize = 4;
/// Shamir custody threshold — any `CUSTODY_THRESHOLD` committee members reconstruct the custody secret
/// (`dkg::shamir_recover`); fewer learn nothing.
pub const CUSTODY_THRESHOLD: usize = 3;
/// Epochs after a subject's departure by which every selected committee member must have filed a valid
/// handoff receipt; one that has not by the close has defaulted (`settle`) and is slashable. Set well
/// above the leaver's self-healing re-dispatch window so an honest member is never spuriously defaulted.
pub const HANDOFF_DEADLINE: u64 = 5;

// ───────────────────────────────── committee selection ─────────────────────────────────

/// Sortition key `H(beacon_t ‖ subject ‖ peer)` — smaller wins. Beacon-seeded so it is unpredictable
/// before the beacon is fixed yet deterministic and verifiable afterward.
fn sortition_key(beacon_t: u64, subject: u64, peer: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-sortition-v1");
    h.update(&beacon_t.to_le_bytes());
    h.update(&subject.to_le_bytes());
    h.update(peer);
    *h.finalize().as_bytes()
}

/// Select the arbitration committee for `subject` (e.g. the suspended node's `epoch_id`, or a rotation
/// nonce): the `size` validators with the smallest sortition key. Deterministic and publicly
/// re-derivable from `(validators, beacon_t, subject)`. Ties (equal keys) break by `peer_id`, so the
/// result is total-ordered and identical on every node. Returns at most `validators.len()` members.
pub fn select_committee(validators: &[[u8; 32]], beacon_t: u64, subject: u64, size: usize) -> Vec<[u8; 32]> {
    let mut ranked: Vec<[u8; 32]> = validators.to_vec();
    ranked.sort_by(|a, b| {
        sortition_key(beacon_t, subject, a)
            .cmp(&sortition_key(beacon_t, subject, b))
            .then_with(|| a.cmp(b))
    });
    ranked.truncate(size);
    ranked
}

// ───────────────────────────── ZK re-encryption (handoff) proof ─────────────────────────────

/// A zero-knowledge proof that `c_new` re-commits the SAME preference vector as `c_old` under a fresh
/// blinding — a Schnorr proof of knowledge of `Δr` with `c_new − c_old = Δr·H`. Reveals nothing about
/// the vector. If `c_new` committed a *different* vector, the difference would carry a non-`H` component
/// (the `Gᵢ` and `H` are independent NUMS generators), so no `Δr` satisfies the relation and the proof
/// cannot be forged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReEncryptionProof {
    t: [u8; 32],   // commitment k·H
    z: [u8; 32],   // response k + e·Δr
}

fn dec(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*b).decompress()
}

/// Fiat-Shamir challenge binding the statement `(c_old, c_new)` and the prover's commitment `t`.
fn reenc_challenge(c_old: &RistrettoPoint, c_new: &RistrettoPoint, t: &RistrettoPoint) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-reenc-fs-v1");
    h.update(c_old.compress().as_bytes());
    h.update(c_new.compress().as_bytes());
    h.update(t.compress().as_bytes());
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn reenc_nonce(seed: &[u8; 32], c_old: &[u8; 32], c_new: &[u8; 32]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-reenc-nonce-v1");
    h.update(seed);
    h.update(c_old);
    h.update(c_new);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Prove that `c_new` re-blinds `c_old` to the same preference vector, where `r_old`/`r_new` are the old
/// and new blindings the prover knows (the departing node hands them off, or the committee reconstructs
/// `r_old` from custody and chooses `r_new`). `seed` makes the proof deterministic.
pub fn prove_reencryption(pc: &Pedersen, c_old: &[u8; 32], c_new: &[u8; 32], r_old: &[u8; 32], r_new: &[u8; 32], seed: &[u8; 32]) -> ReEncryptionProof {
    let (cold, cnew) = (dec(c_old).expect("valid c_old"), dec(c_new).expect("valid c_new"));
    let dr = Scalar::from_bytes_mod_order(*r_new) - Scalar::from_bytes_mod_order(*r_old);
    let k = reenc_nonce(seed, c_old, c_new);
    let t = pc.h() * k;
    let e = reenc_challenge(&cold, &cnew, &t);
    let z = k + e * dr;
    ReEncryptionProof { t: t.compress().to_bytes(), z: z.to_bytes() }
}

/// Verify a [`prove_reencryption`] proof: `z·H == t + e·(c_new − c_old)`.
pub fn verify_reencryption(pc: &Pedersen, c_old: &[u8; 32], c_new: &[u8; 32], proof: &ReEncryptionProof) -> bool {
    let (Some(cold), Some(cnew), Some(t)) = (dec(c_old), dec(c_new), dec(&proof.t)) else { return false };
    let Some(z) = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.z)) else { return false };
    let e = reenc_challenge(&cold, &cnew, &t);
    pc.h() * z == t + (cnew - cold) * e
}

/// Homomorphically re-blind `c_old` from `r_old` to `r_new` WITHOUT the preference vector:
/// `c_new = c_old + (r_new − r_old)·H`. A committee member computes the freshly-blinded commitment it
/// will custody knowing only the public `c_old` and the two blindings — never the underlying vector.
pub fn reencrypt(pc: &Pedersen, c_old: &[u8; 32], r_old: &[u8; 32], r_new: &[u8; 32]) -> Option<[u8; 32]> {
    let cold = dec(c_old)?;
    let dr = Scalar::from_bytes_mod_order(*r_new) - Scalar::from_bytes_mod_order(*r_old);
    Some((cold + pc.h() * dr).compress().to_bytes())
}

// ──────────────────────────────── confidential custody delivery ────────────────────────────────

/// A confidential custody parcel a departing node sends to one committee member: the member's Shamir
/// custody share **and** the on-chain commitment's blinding `r_old` (needed to compute the re-blinded
/// `c_new = c_old + Δr·H`), sealed to the member's Ristretto `mix_pk` by a one-shot ECIES so only that
/// member can open it. `r_old` is confidential — revealing it would strip the Pedersen commitment's
/// hiding — so it never travels in the clear.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyParcel {
    pub subject: u64,
    pub member: [u8; 32],
    pub eph: [u8; 32], // ephemeral Ristretto public key
    pub ct: Vec<u8>,   // (r_old ‖ share), XORed with the ECIES keystream
}

/// ECIES keystream over the DH shared point, domain-separated and bound to `(subject, member)`.
fn custody_keystream(shared: &RistrettoPoint, subject: u64, member: &[u8; 32], len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-custody-ecies-v1");
    h.update(shared.compress().as_bytes());
    h.update(&subject.to_le_bytes());
    h.update(member);
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn eph_scalar(eph_seed: &[u8; 32], subject: u64, member: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-custody-eph-v1");
    h.update(eph_seed);
    h.update(&subject.to_le_bytes());
    h.update(member);
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Seal `(r_old ‖ share)` to committee `member`'s `member_mix_pk`. `eph_seed` makes the ephemeral key
/// deterministic (no RNG). Returns `None` if `member_mix_pk` is not a valid point.
pub fn seal_custody(
    member_mix_pk: &[u8; 32],
    subject: u64,
    member: &[u8; 32],
    r_old: &[u8; 32],
    share: &[u8; 32],
    eph_seed: &[u8; 32],
) -> Option<CustodyParcel> {
    let pk = dec(member_mix_pk)?;
    let e = eph_scalar(eph_seed, subject, member);
    let eph = RISTRETTO_BASEPOINT_POINT * e;
    let shared = pk * e;
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(r_old);
    payload[32..].copy_from_slice(share);
    let ks = custody_keystream(&shared, subject, member, 64);
    let ct: Vec<u8> = payload.iter().zip(ks).map(|(a, b)| a ^ b).collect();
    Some(CustodyParcel { subject, member: *member, eph: eph.compress().to_bytes(), ct })
}

/// Open a parcel addressed to this member, recovering `(r_old, share)`. `None` if malformed or not
/// actually sealed to `my_mix_sk`.
pub fn open_custody(my_mix_sk: &[u8; 32], parcel: &CustodyParcel) -> Option<([u8; 32], [u8; 32])> {
    if parcel.ct.len() != 64 {
        return None;
    }
    let e_pub = dec(&parcel.eph)?;
    let sk = Scalar::from_bytes_mod_order(*my_mix_sk);
    let shared = e_pub * sk;
    let ks = custody_keystream(&shared, parcel.subject, &parcel.member, 64);
    let pt: Vec<u8> = parcel.ct.iter().zip(ks).map(|(a, b)| a ^ b).collect();
    let mut r_old = [0u8; 32];
    let mut share = [0u8; 32];
    r_old.copy_from_slice(&pt[..32]);
    share.copy_from_slice(&pt[32..]);
    Some((r_old, share))
}

// ──────────────────────────────── handoff receipts + slashing ────────────────────────────────

fn receipt_msg(subject: u64, c_new: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("arbitration-receipt", subject, c_new)).expect("receipt msg")
}

fn check_sig(peer: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    match <[u8; 64]>::try_from(sig) {
        Ok(arr) => verify_ed25519(peer, msg, &ed25519_dalek::Signature::from_bytes(&arr)),
        Err(_) => false,
    }
}

/// A committee member's completed handoff: the re-encrypted commitment it now custodies, the ZK proof
/// binding it to the departing node's on-chain `c_old`, and a commitment to its Shamir custody share
/// (so a later reconstruction can detect a withheld/substituted share). Signed by the member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandoffReceipt {
    pub member: [u8; 32],
    pub subject: u64,
    pub c_new: [u8; 32],
    pub reenc: ReEncryptionProof,
    pub share_commitment: [u8; 32],
    pub sig: Vec<u8>,
}

/// A binding commitment to a custody share — `H(share)`, published in the receipt so the share a member
/// later contributes to reconstruction can be checked against what it attested to holding.
pub fn share_commitment(share: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-arbitration-share-v1");
    h.update(share);
    *h.finalize().as_bytes()
}

impl HandoffReceipt {
    /// Build and sign a member's receipt for `subject`, attesting custody of `share` and the
    /// re-encrypted commitment `c_new` with its proof.
    pub fn create(identity: &NodeIdentity, subject: u64, c_new: [u8; 32], reenc: ReEncryptionProof, share: &[u8; 32]) -> Self {
        let sig = identity.sign(&receipt_msg(subject, &c_new)).to_bytes().to_vec();
        HandoffReceipt { member: identity.peer_id(), subject, c_new, reenc, share_commitment: share_commitment(share), sig }
    }

    /// Validate the receipt against the on-chain `c_old`: the member is in `committee`, the signature is
    /// good, and the re-encryption proof binds `c_new` to `c_old`.
    pub fn verify(&self, pc: &Pedersen, c_old: &[u8; 32], committee: &[[u8; 32]]) -> bool {
        committee.contains(&self.member)
            && check_sig(&self.member, &receipt_msg(self.subject, &self.c_new), &self.sig)
            && verify_reencryption(pc, c_old, &self.c_new, &self.reenc)
    }
}

/// Slashing evidence that a selected committee member defaulted — it filed no valid handoff receipt for
/// `subject` by the close. Recomputable by anyone: re-derive the committee, check no valid receipt from
/// `member` exists. The trigger the consensus `slashed` set consumes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffDefault {
    pub member: [u8; 32],
    pub subject: u64,
}

/// Settle a handoff round: partition the committee into members who filed a valid receipt and members
/// who defaulted (no valid receipt). Each input receipt is checked against `c_old`; a member is credited
/// at most once. Pure function of public inputs, so every node settles identically.
pub fn settle(
    pc: &Pedersen,
    c_old: &[u8; 32],
    committee: &[[u8; 32]],
    subject: u64,
    receipts: &[HandoffReceipt],
) -> (Vec<[u8; 32]>, Vec<HandoffDefault>) {
    let mut completed = Vec::new();
    for member in committee {
        let ok = receipts
            .iter()
            .any(|r| &r.member == member && r.subject == subject && r.verify(pc, c_old, committee));
        if ok {
            completed.push(*member);
        }
    }
    let defaulted = committee
        .iter()
        .filter(|m| !completed.contains(m))
        .map(|m| HandoffDefault { member: *m, subject })
        .collect();
    (completed, defaulted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;

    fn peers(n: u8) -> Vec<NodeIdentity> {
        (0..n as u64).map(NodeIdentity::from_seed).collect()
    }

    #[test]
    fn committee_is_deterministic_size_bounded_and_beacon_dependent() {
        let ids: Vec<[u8; 32]> = peers(10).iter().map(|i| i.peer_id()).collect();
        let c1 = select_committee(&ids, 42, 7, 4);
        let c2 = select_committee(&ids, 42, 7, 4);
        assert_eq!(c1, c2, "selection is deterministic");
        assert_eq!(c1.len(), 4, "committee has the requested size");
        assert!(c1.iter().all(|m| ids.contains(m)), "members are validators");
        // A different beacon (or subject) reshuffles the committee.
        assert_ne!(c1, select_committee(&ids, 43, 7, 4), "a new beacon changes the committee");
        // Size larger than the set is clamped, not padded.
        assert_eq!(select_committee(&ids, 42, 7, 50).len(), 10);
    }

    #[test]
    fn reencryption_proves_same_vector_under_fresh_blinding() {
        let pc = Pedersen::new(8);
        let p = [3i64, -1, 0, 5, 2, -4, 1, 0];
        let (r_old, r_new) = ([9u8; 32], [21u8; 32]);
        let c_old = pc.commit(&p, &r_old);
        let c_new = pc.commit(&p, &r_new); // same vector, the committee's fresh blinding
        let proof = prove_reencryption(&pc, &c_old, &c_new, &r_old, &r_new, &[1u8; 32]);
        assert!(verify_reencryption(&pc, &c_old, &c_new, &proof), "a faithful re-encryption verifies");
    }

    #[test]
    fn reencryption_rejects_a_substituted_profile() {
        let pc = Pedersen::new(8);
        let p = [3i64, -1, 0, 5, 2, -4, 1, 0];
        let mut tampered = p;
        tampered[2] += 6; // the committee tries to swap in a different preference vector
        let (r_old, r_new) = ([9u8; 32], [21u8; 32]);
        let c_old = pc.commit(&p, &r_old);
        let c_bad = pc.commit(&tampered, &r_new);
        // No Δr links c_bad to c_old, so an honestly-built proof can't validate...
        let forged = prove_reencryption(&pc, &c_old, &c_bad, &r_old, &r_new, &[1u8; 32]);
        assert!(!verify_reencryption(&pc, &c_old, &c_bad, &forged), "a substituted vector cannot be proven a re-encryption");
    }

    #[test]
    fn settle_credits_filers_and_defaults_the_rest() {
        let pc = Pedersen::new(8);
        let p = [1i64, 2, -3, 4, 0, 1, -1, 2];
        let (r_old, r_new) = ([5u8; 32], [12u8; 32]);
        let c_old = pc.commit(&p, &r_old);
        let c_new = pc.commit(&p, &r_new);
        let subject = 0xC0FFEEu64;

        let members = peers(4);
        let committee: Vec<[u8; 32]> = members.iter().map(|m| m.peer_id()).collect();
        // The custody secret is Shamir-split to the committee (any 3 reconstruct it).
        let custody = dkg::shamir_split(&r_old, 3, 4, b"handoff-custody");

        // Three of four members file valid receipts; the fourth defaults.
        let receipts: Vec<HandoffReceipt> = members
            .iter()
            .take(3)
            .enumerate()
            .map(|(i, m)| {
                let reenc = prove_reencryption(&pc, &c_old, &c_new, &r_old, &r_new, &[i as u8; 32]);
                HandoffReceipt::create(m, subject, c_new, reenc, &custody[i].1)
            })
            .collect();

        let (completed, defaulted) = settle(&pc, &c_old, &committee, subject, &receipts);
        assert_eq!(completed.len(), 3, "three valid receipts credited");
        assert_eq!(defaulted, vec![HandoffDefault { member: committee[3], subject }], "the non-filer is slashable");

        // The quorum that filed can reconstruct the custody secret (Shamir t-of-K), so the handoff is
        // recoverable without the departed node.
        let quorum: Vec<(u64, [u8; 32])> = (0..3).map(|i| custody[i]).collect();
        assert_eq!(dkg::shamir_recover(&quorum), r_old, "the filing quorum recovers the custody secret");
    }

    #[test]
    fn custody_parcel_seals_to_one_member_and_reencrypt_is_homomorphic() {
        let pc = Pedersen::new(8);
        let p = [4i64, 0, -2, 7, 1, 0, 3, -1];
        let r_old = [9u8; 32];
        let c_old = pc.commit(&p, &r_old);

        // The departing node Shamir-splits its custody secret and seals (r_old ‖ share) to a member.
        let member = NodeIdentity::from_seed(3);
        let interloper = NodeIdentity::from_seed(99);
        let custody = dkg::shamir_split(&r_old, 3, 4, b"handoff-custody");
        let parcel = seal_custody(
            &member.mix_pk(),
            0xC0FFEE,
            &member.peer_id(),
            &r_old,
            &custody[0].1,
            &[7u8; 32],
        )
        .expect("valid member key");

        // Only the addressed member opens it; a different key recovers garbage, not r_old.
        let (got_r_old, got_share) = open_custody(&member.mix_sk(), &parcel).expect("opens");
        assert_eq!(got_r_old, r_old, "the member recovers the true blinding");
        assert_eq!(got_share, custody[0].1, "the member recovers its custody share");
        let (bad_r_old, _) = open_custody(&interloper.mix_sk(), &parcel).expect("decodes bytes");
        assert_ne!(bad_r_old, r_old, "a non-addressed key cannot recover the custody secret");

        // The member re-blinds c_old to a fresh r_new homomorphically — never seeing the vector — and
        // the result equals a direct commitment of the SAME vector under r_new, and the proof binds it.
        let r_new = [21u8; 32];
        let c_new = reencrypt(&pc, &c_old, &got_r_old, &r_new).expect("reencrypt");
        assert_eq!(c_new, pc.commit(&p, &r_new), "homomorphic re-blinding matches a direct re-commit");
        let proof = prove_reencryption(&pc, &c_old, &c_new, &got_r_old, &r_new, &[1u8; 32]);
        assert!(verify_reencryption(&pc, &c_old, &c_new, &proof), "the re-encryption proof verifies");
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_commitment() {
        let pc = Pedersen::new(8);
        let p = [2i64, 2, 2, 2, 2, 2, 2, 2];
        let (r_old, r_new) = ([3u8; 32], [8u8; 32]);
        let c_old = pc.commit(&p, &r_old);
        let c_new = pc.commit(&p, &r_new);
        let proof = prove_reencryption(&pc, &c_old, &c_new, &r_old, &r_new, &[1u8; 32]);
        // Re-using the proof against an unrelated c_old' must fail (the challenge binds both points).
        let other_old = pc.commit(&p, &[99u8; 32]);
        assert!(!verify_reencryption(&pc, &other_old, &c_new, &proof), "the proof is bound to its statement");
    }
}
