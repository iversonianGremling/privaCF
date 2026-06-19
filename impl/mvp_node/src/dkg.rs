//! Distributed Key Generation → a BLS threshold key `VA_pub` (SPEC §4.1/§4.3). This is the construct
//! the spec separates from the aggregatable multisig: instead of recording *which* validators signed
//! and aggregating their distinct keys, a `(t, n)` **threshold** key lets any `t` validators produce
//! ONE signature verifiable against a single fixed public key `VA_pub` — and crucially **no party
//! ever knows the group secret**.
//!
//! Protocol — synchronous **Feldman VSS** DKG (every participant deals):
//!   1. Each participant `i` picks a degree-`t-1` polynomial `f_i`, broadcasts Feldman commitments
//!      `C_{i,k} = a_{i,k}·G1`, and sends share `s_{i,j} = f_i(j)` privately to participant `j`.
//!   2. Each `j` **verifies** every received share against its dealer's commitments
//!      (`s_{i,j}·G1 == Σ_k j^k·C_{i,k}`) — a cheating dealer is caught.
//!   3. `j`'s secret share is `x_j = Σ_i s_{i,j}`; the group key is `VA_pub = Σ_i C_{i,0} =
//!      (Σ_i a_{i,0})·G1`, which no one can open.
//!
//! Threshold signing is non-interactive (the reason BLS is the right primitive for a quorum
//! certificate): each signer signs with its share exactly as an ordinary vote, and any `t` partial
//! signatures combine by Lagrange interpolation in the exponent into `σ = group_secret·H(m)` — a
//! plain BLS signature that **`bls::verify(VA_pub, m, σ)` accepts** (same `min_pk` encoding and DST).
//!
//! All `blst` low-level field/group arithmetic is isolated here (and in `bls.rs`).
//!
//! Scope: this is the DKG + threshold-signing primitive, tested standalone. Wiring it as the live
//! quorum certificate would also need a **re-share on every membership change** (a fixed threshold
//! key and a *changing* validator set are in tension — which is exactly why the running consensus
//! uses the aggregatable multisig, that needs no re-DKG). The two coexist deliberately.

use std::collections::BTreeMap;

use blst::*;

use crate::bls;

// --- scalar-field (Fr) helpers --------------------------------------------------------------------

fn fr_from_u64(v: u64) -> blst_fr {
    unsafe {
        let limbs = [v, 0u64, 0, 0];
        let mut s = blst_scalar::default();
        blst_scalar_from_uint64(&mut s, limbs.as_ptr());
        let mut fr = blst_fr::default();
        blst_fr_from_scalar(&mut fr, &s);
        fr
    }
}

fn fr_from_be(b: &[u8; 32]) -> blst_fr {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_bendian(&mut s, b.as_ptr());
        let mut fr = blst_fr::default();
        blst_fr_from_scalar(&mut fr, &s);
        fr
    }
}

fn fr_to_be(fr: &blst_fr) -> [u8; 32] {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_fr(&mut s, fr);
        let mut out = [0u8; 32];
        blst_bendian_from_scalar(out.as_mut_ptr(), &s);
        out
    }
}

fn fr_to_scalar_le(fr: &blst_fr) -> [u8; 32] {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_fr(&mut s, fr);
        let mut out = [0u8; 32];
        blst_lendian_from_scalar(out.as_mut_ptr(), &s);
        out
    }
}

fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    unsafe {
        let mut o = blst_fr::default();
        blst_fr_add(&mut o, a, b);
        o
    }
}

fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
    unsafe {
        let mut o = blst_fr::default();
        blst_fr_sub(&mut o, a, b);
        o
    }
}

fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    unsafe {
        let mut o = blst_fr::default();
        blst_fr_mul(&mut o, a, b);
        o
    }
}

fn fr_inverse(a: &blst_fr) -> blst_fr {
    unsafe {
        let mut o = blst_fr::default();
        blst_fr_inverse(&mut o, a);
        o
    }
}

/// A random non-zero scalar derived from key material (via BLS key-gen, which reduces mod r).
fn fr_random(ikm: &[u8]) -> blst_fr {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(blake3::hash(ikm).as_bytes());
    let sk = min_pk::SecretKey::key_gen(&seed, &[]).expect("key_gen");
    fr_from_be(&sk.to_bytes())
}

// --- G1 helpers (commitments + VA_pub live in G1, the min_pk public-key group) ---------------------

fn g1_generator() -> blst_p1 {
    unsafe { *blst_p1_generator() }
}

fn g1_mul(p: &blst_p1, k: &blst_fr) -> blst_p1 {
    unsafe {
        let le = fr_to_scalar_le(k);
        let mut o = blst_p1::default();
        blst_p1_mult(&mut o, p, le.as_ptr(), 255);
        o
    }
}

fn g1_add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    unsafe {
        let mut o = blst_p1::default();
        blst_p1_add_or_double(&mut o, a, b);
        o
    }
}

fn g1_compress(p: &blst_p1) -> [u8; 48] {
    unsafe {
        let mut out = [0u8; 48];
        blst_p1_compress(out.as_mut_ptr(), p);
        out
    }
}

fn g1_uncompress(b: &[u8; 48]) -> Option<blst_p1> {
    unsafe {
        let mut aff = blst_p1_affine::default();
        if blst_p1_uncompress(&mut aff, b.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        let mut p = blst_p1::default();
        blst_p1_from_affine(&mut p, &aff);
        Some(p)
    }
}

fn g1_eq(a: &blst_p1, b: &blst_p1) -> bool {
    unsafe { blst_p1_is_equal(a, b) }
}

// --- G2 helpers (signatures live in G2; used only to Lagrange-combine partials) --------------------

fn g2_uncompress(b: &[u8; 96]) -> Option<blst_p2> {
    unsafe {
        let mut aff = blst_p2_affine::default();
        if blst_p2_uncompress(&mut aff, b.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        let mut p = blst_p2::default();
        blst_p2_from_affine(&mut p, &aff);
        Some(p)
    }
}

fn g2_mul(p: &blst_p2, k: &blst_fr) -> blst_p2 {
    unsafe {
        let le = fr_to_scalar_le(k);
        let mut o = blst_p2::default();
        blst_p2_mult(&mut o, p, le.as_ptr(), 255);
        o
    }
}

fn g2_add(a: &blst_p2, b: &blst_p2) -> blst_p2 {
    unsafe {
        let mut o = blst_p2::default();
        blst_p2_add_or_double(&mut o, a, b);
        o
    }
}

fn g2_compress(p: &blst_p2) -> [u8; 96] {
    unsafe {
        let mut out = [0u8; 96];
        blst_p2_compress(out.as_mut_ptr(), p);
        out
    }
}

// --- polynomial + Lagrange ------------------------------------------------------------------------

/// Evaluate `f(x) = Σ coeffs[k]·x^k` by Horner's rule.
fn poly_eval(coeffs: &[blst_fr], x: &blst_fr) -> blst_fr {
    let mut acc = blst_fr::default(); // 0
    for c in coeffs.iter().rev() {
        acc = fr_add(&fr_mul(&acc, x), c);
    }
    acc
}

/// Lagrange basis coefficient `λ_j(0)` for the signer set `s` (1-based indices): `Π_{l≠j} l/(l-j)`.
fn lagrange_at_zero(j: u64, s: &[u64]) -> blst_fr {
    let fj = fr_from_u64(j);
    let mut num = fr_from_u64(1);
    let mut den = fr_from_u64(1);
    for &l in s {
        if l == j {
            continue;
        }
        let fl = fr_from_u64(l);
        num = fr_mul(&num, &fl); // Π l
        den = fr_mul(&den, &fr_sub(&fl, &fj)); // Π (l - j)
    }
    fr_mul(&num, &fr_inverse(&den))
}

// --- public API -----------------------------------------------------------------------------------

/// One participant's Feldman dealing: commitments to its polynomial coefficients, and the per-party
/// shares `shares[j-1] = f(j)` for parties `j = 1..=n`.
#[derive(Clone, Debug)]
pub struct Dealing {
    pub commitments: Vec<[u8; 48]>,
    pub shares: Vec<[u8; 32]>,
}

/// Build a dealing (commitments + per-party shares) from explicit polynomial coefficients.
fn deal_coeffs(coeffs: &[blst_fr], n: usize) -> Dealing {
    let g = g1_generator();
    let commitments = coeffs.iter().map(|a| g1_compress(&g1_mul(&g, a))).collect();
    let shares = (1..=n as u64).map(|j| fr_to_be(&poly_eval(coeffs, &fr_from_u64(j)))).collect();
    Dealing { commitments, shares }
}

fn random_coeffs(threshold: usize, ikm: &[u8]) -> Vec<blst_fr> {
    (0..threshold)
        .map(|k| {
            let mut m = ikm.to_vec();
            m.extend_from_slice(b"dkg-coeff");
            m.extend_from_slice(&(k as u64).to_le_bytes());
            fr_random(&m)
        })
        .collect()
}

/// Deal a degree-`threshold-1` polynomial for an `n`-party group from key material `ikm`.
pub fn deal(threshold: usize, n: usize, ikm: &[u8]) -> Dealing {
    assert!(threshold >= 1 && threshold <= n, "need 1 <= threshold <= n");
    deal_coeffs(&random_coeffs(threshold, ikm), n)
}

/// Deal a polynomial whose constant term is a FIXED `secret` (the rest random). Used by proactive
/// re-sharing, where each old shareholder re-shares its own share `x_i = f(0)`.
fn deal_with_secret(threshold: usize, n: usize, secret: &[u8; 32], ikm: &[u8]) -> Dealing {
    let mut coeffs = random_coeffs(threshold, ikm);
    coeffs[0] = fr_from_be(secret); // constant term = the secret to re-share
    deal_coeffs(&coeffs, n)
}

/// Verify a received share `s = f_i(j)` against dealer `i`'s commitments: `s·G1 == Σ_k j^k·C_{i,k}`.
pub fn verify_share(party_index: u64, share: &[u8; 32], commitments: &[[u8; 48]]) -> bool {
    let lhs = g1_mul(&g1_generator(), &fr_from_be(share));
    let mut rhs = blst_p1::default(); // infinity
    let mut jpow = fr_from_u64(1);
    let j = fr_from_u64(party_index);
    for c in commitments {
        let point = match g1_uncompress(c) {
            Some(p) => p,
            None => return false,
        };
        rhs = g1_add(&rhs, &g1_mul(&point, &jpow));
        jpow = fr_mul(&jpow, &j);
    }
    g1_eq(&lhs, &rhs)
}

/// Combine a party's received shares (one per dealer) into its secret-key share `x_j = Σ_i s_{i,j}`.
pub fn combine_shares(received: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = blst_fr::default(); // 0
    for s in received {
        acc = fr_add(&acc, &fr_from_be(s));
    }
    fr_to_be(&acc)
}

/// The group public key `VA_pub = Σ_i C_{i,0}` from every dealer's constant-term commitment.
pub fn group_public_key(constant_commitments: &[[u8; 48]]) -> Option<[u8; 48]> {
    let mut acc = blst_p1::default(); // infinity
    for c in constant_commitments {
        acc = g1_add(&acc, &g1_uncompress(c)?);
    }
    Some(g1_compress(&acc))
}

/// **Shamir-split** a 32-byte `secret` into `n` shares (1-based party index), any `threshold` of which
/// reconstruct it while `threshold − 1` learn nothing. Reuses the Feldman dealing machinery (a
/// degree-`threshold−1` polynomial whose constant term is the secret). This is the custody primitive
/// the arbitration committee (`arbitration.rs`) uses to hold a departing node's recovery state.
pub fn shamir_split(secret: &[u8; 32], threshold: usize, n: usize, ikm: &[u8]) -> Vec<(u64, [u8; 32])> {
    assert!(threshold >= 1 && threshold <= n, "need 1 <= threshold <= n");
    let dealing = deal_with_secret(threshold, n, secret, ikm);
    (1..=n as u64).zip(dealing.shares).collect() // shares[j-1] = f(j)
}

/// Reconstruct a Shamir secret from `threshold` (index, share) pairs by Lagrange interpolation at 0:
/// `secret = Σ_j λ_j(0)·share_j`. Fewer than `threshold` distinct shares yield an unrelated value.
pub fn shamir_recover(shares: &[(u64, [u8; 32])]) -> [u8; 32] {
    let indices: Vec<u64> = shares.iter().map(|(i, _)| *i).collect();
    let mut acc = blst_fr::default(); // 0
    for (i, s) in shares {
        let lambda = lagrange_at_zero(*i, &indices);
        acc = fr_add(&acc, &fr_mul(&lambda, &fr_from_be(s)));
    }
    fr_to_be(&acc)
}

/// A partial signature: sign `msg` with a secret-key share (identical to an ordinary BLS vote).
pub fn sign_share(share: &[u8; 32], msg: &[u8]) -> [u8; 96] {
    bls::sign(share, msg)
}

/// Combine `t` partial signatures (each tagged with its 1-based party index) into the threshold
/// signature `σ = group_secret·H(msg)`, verifiable via `bls::verify(VA_pub, msg, σ)`.
pub fn combine_signatures(partials: &[(u64, [u8; 96])]) -> Option<[u8; 96]> {
    if partials.is_empty() {
        return None;
    }
    let indices: Vec<u64> = partials.iter().map(|(i, _)| *i).collect();
    let mut acc = blst_p2::default(); // infinity
    for (j, sig) in partials {
        let point = g2_uncompress(sig)?;
        let lambda = lagrange_at_zero(*j, &indices);
        acc = g2_add(&acc, &g2_mul(&point, &lambda));
    }
    Some(g2_compress(&acc))
}

/// Run the genesis DKG among `parties` (each `(peer_id, ikm)`, **sorted by peer_id** so the 1-based
/// party index is consistent network-wide) and return `(VA_pub, peer_id → secret-key share)`. Every
/// party deals, shares are verified and summed, and `VA_pub` is the sum of constant-term commitments.
/// This is the trusted genesis ceremony's output — a presupposed-good-genesis artifact distributed to
/// the validators (`VA_pub` public for sealing, each share private for verdict threshold-signing).
pub fn genesis_keys(threshold: usize, parties: &[([u8; 32], Vec<u8>)]) -> ([u8; 48], BTreeMap<[u8; 32], [u8; 32]>) {
    let n = parties.len();
    let dealings: Vec<Dealing> = parties.iter().map(|(_, ikm)| deal(threshold, n, ikm)).collect();
    let mut shares = BTreeMap::new();
    for (j, (pid, _)) in parties.iter().enumerate() {
        let mine: Vec<[u8; 32]> = dealings.iter().map(|d| d.shares[j]).collect();
        shares.insert(*pid, combine_shares(&mine));
    }
    let constants: Vec<[u8; 48]> = dealings.iter().map(|d| d.commitments[0]).collect();
    let va_pub = group_public_key(&constants).expect("group key");
    (va_pub, shares)
}

/// **Proactive re-share** (PSS) — refresh the threshold shares to a NEW validator set while keeping
/// the SAME secret (so `VA_pub` is unchanged): a quorum of old shareholders `qualified`
/// (`(old_index, share)`, ≥ `threshold` of them) each re-shares its own share `x_i = f(0)` to the
/// new parties; new party `k` (1-based by sorted order) gets `x'_k = Σ_i λ_i·g_i(k)`, where `λ_i` is
/// the Lagrange coefficient reconstructing the secret from the qualified set, so
/// `x'(0) = Σ_i λ_i·x_i = x`. This is the rotation step P1.3 deferred — the threshold key survives a
/// changing validator set without a fresh genesis DKG (`VA_pub` constant).
pub fn reshare(
    threshold: usize,
    qualified: &[(u64, [u8; 32])],
    new_parties: &[([u8; 32], Vec<u8>)],
) -> BTreeMap<[u8; 32], [u8; 32]> {
    let n_new = new_parties.len();
    let old_indices: Vec<u64> = qualified.iter().map(|(i, _)| *i).collect();
    // Each qualified old member re-shares its share to the new set (constant term = its share).
    let subdeals: Vec<(u64, Dealing)> = qualified
        .iter()
        .map(|(idx, share)| {
            let mut ikm = b"privacf-reshare".to_vec();
            ikm.extend_from_slice(&idx.to_le_bytes());
            for (pid, _) in new_parties {
                ikm.extend_from_slice(pid);
            }
            (*idx, deal_with_secret(threshold, n_new, share, &ikm))
        })
        .collect();
    let mut out = BTreeMap::new();
    for (k, (pid, _)) in new_parties.iter().enumerate() {
        let mut acc = blst_fr::default(); // 0
        for (idx, dealing) in &subdeals {
            let lambda = lagrange_at_zero(*idx, &old_indices);
            acc = fr_add(&acc, &fr_mul(&lambda, &fr_from_be(&dealing.shares[k])));
        }
        out.insert(*pid, fr_to_be(&acc));
    }
    out
}

/// One qualified old shareholder's **independent** re-share contribution to a new committee — the
/// distributed counterpart of [`reshare`], which a single caller runs over *all* qualified shares.
/// Here a holder of `my_share` (its own Shamir share, constant term of a fresh degree-`threshold−1`
/// polynomial) deals only its share to `n_new` new parties, learning nothing about the others' shares
/// and never reconstructing the secret. Returns `[(new_index, subshare)]` (1-based new index); the
/// holder seals `subshare_k` to new party `k` confidentially and discards the rest.
pub fn reshare_subdeal(threshold: usize, n_new: usize, my_share: &[u8; 32], ikm: &[u8]) -> Vec<(u64, [u8; 32])> {
    shamir_split(my_share, threshold, n_new, ikm)
}

/// A new committee member's side of the distributed re-share: combine the sub-shares it received, one
/// per qualified old holder, into its fresh Shamir share `x'_k = Σ_i λ_i(0)·subshare_{i,k}`. The Lagrange
/// coefficients are taken over **exactly** the contributing `old_index` set, so every new member MUST
/// combine over the identical qualified set for the new shares to lie on one consistent polynomial whose
/// constant term is the unchanged secret (`Σ_i λ_i·x_i = x`). With ≥ `threshold` honest contributors the
/// fresh shares reconstruct the SAME secret; no party ever holds it. Mirrors the inner sum of [`reshare`].
pub fn reshare_combine(contributions: &[(u64, [u8; 32])]) -> [u8; 32] {
    let old_indices: Vec<u64> = contributions.iter().map(|(i, _)| *i).collect();
    let mut acc = blst_fr::default(); // 0
    for (idx, subshare) in contributions {
        let lambda = lagrange_at_zero(*idx, &old_indices);
        acc = fr_add(&acc, &fr_mul(&lambda, &fr_from_be(subshare)));
    }
    fr_to_be(&acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the full DKG among `n` parties and return (VA_pub, secret-key share per party).
    fn run_dkg(threshold: usize, n: usize) -> ([u8; 48], Vec<[u8; 32]>) {
        // Every party deals.
        let dealings: Vec<Dealing> =
            (0..n).map(|i| deal(threshold, n, format!("party-{i}").as_bytes())).collect();

        // Every party verifies every share addressed to it.
        for d in &dealings {
            for (j, share) in d.shares.iter().enumerate() {
                assert!(verify_share(j as u64 + 1, share, &d.commitments), "honest share verifies");
            }
        }

        // Party j's secret share = Σ over dealers of the share addressed to j.
        let shares: Vec<[u8; 32]> = (0..n)
            .map(|j| {
                let mine: Vec<[u8; 32]> = dealings.iter().map(|d| d.shares[j]).collect();
                combine_shares(&mine)
            })
            .collect();

        let constants: Vec<[u8; 48]> = dealings.iter().map(|d| d.commitments[0]).collect();
        let va_pub = group_public_key(&constants).expect("group key");
        (va_pub, shares)
    }

    #[test]
    fn any_threshold_subset_produces_a_signature_under_va_pub() {
        let (t, n) = (3usize, 5usize);
        let (va_pub, shares) = run_dkg(t, n);
        let msg = b"finalize-block-id";

        // Parties 1,3,5 (a t-of-n subset) sign and combine.
        let subset = [1u64, 3, 5];
        let partials: Vec<(u64, [u8; 96])> =
            subset.iter().map(|&j| (j, sign_share(&shares[j as usize - 1], msg))).collect();
        let sig = combine_signatures(&partials).expect("combine");
        assert!(bls::verify(&va_pub, msg, &sig), "the threshold signature must verify under VA_pub");

        // A DIFFERENT t-subset (2,3,4) must reconstruct the SAME group signature key.
        let subset2 = [2u64, 3, 4];
        let partials2: Vec<(u64, [u8; 96])> =
            subset2.iter().map(|&j| (j, sign_share(&shares[j as usize - 1], msg))).collect();
        let sig2 = combine_signatures(&partials2).expect("combine");
        assert!(bls::verify(&va_pub, msg, &sig2), "another subset also verifies under VA_pub");
        assert_eq!(sig, sig2, "threshold BLS is unique: any t-subset yields the identical signature");
    }

    #[test]
    fn fewer_than_threshold_signers_do_not_verify() {
        let (t, n) = (3usize, 5usize);
        let (va_pub, shares) = run_dkg(t, n);
        let msg = b"too-few";
        // Only 2 of the required 3 sign: the Lagrange combine is for the wrong-degree interpolation,
        // so the result is not group_secret·H(m) and does not verify.
        let partials: Vec<(u64, [u8; 96])> =
            [1u64, 2].iter().map(|&j| (j, sign_share(&shares[j as usize - 1], msg))).collect();
        let sig = combine_signatures(&partials).expect("combine");
        assert!(!bls::verify(&va_pub, msg, &sig), "t-1 signers must NOT forge a VA_pub signature");
    }

    #[test]
    fn a_corrupt_share_is_caught_by_feldman_verification() {
        let d = deal(3, 5, b"dealer");
        assert!(verify_share(2, &d.shares[1], &d.commitments), "the real share verifies");
        let mut tampered = d.shares[1];
        tampered[0] ^= 0x01;
        assert!(!verify_share(2, &tampered, &d.commitments), "a tampered share is rejected");
    }

    #[test]
    fn reshare_rotates_the_committee_preserving_va_pub() {
        use crate::bls;
        // Old set: a 3-of-4 genesis key.
        let mut old: Vec<([u8; 32], Vec<u8>)> =
            (0..4u8).map(|i| ([i; 32], format!("old-{i}").into_bytes())).collect();
        old.sort_by_key(|(p, _)| *p);
        let (va_pub, old_shares) = genesis_keys(3, &old);

        // A quorum of 3 old shareholders re-shares (1-based index = sorted position).
        let qualified: Vec<(u64, [u8; 32])> =
            old.iter().enumerate().take(3).map(|(i, (pid, _))| (i as u64 + 1, old_shares[pid])).collect();

        // New set: 5 DIFFERENT validators. The secret/VA_pub must survive the rotation.
        let mut newp: Vec<([u8; 32], Vec<u8>)> =
            (10..15u8).map(|i| ([i; 32], format!("new-{i}").into_bytes())).collect();
        newp.sort_by_key(|(p, _)| *p);
        let new_shares = reshare(3, &qualified, &newp);

        let msg = b"after-rotation";
        let sign_subset = |range: std::ops::Range<usize>| -> [u8; 96] {
            let partials: Vec<(u64, [u8; 96])> = newp[range.clone()]
                .iter()
                .enumerate()
                .map(|(off, (pid, _))| (range.start as u64 + off as u64 + 1, sign_share(&new_shares[pid], msg)))
                .collect();
            combine_signatures(&partials).expect("combine")
        };
        // The re-shared NEW committee signs under the UNCHANGED VA_pub — two different 3-subsets.
        assert!(bls::verify(&va_pub, msg, &sign_subset(0..3)), "new committee signs under the same VA_pub");
        assert!(bls::verify(&va_pub, msg, &sign_subset(2..5)), "a different new 3-subset also verifies");
    }

    #[test]
    fn shamir_custody_reconstructs_from_a_quorum_only() {
        let secret = [7u8; 32];
        let shares = shamir_split(&secret, 3, 5, b"custody-ikm");
        assert_eq!(shares.len(), 5);

        // Any 3 distinct shares reconstruct the secret exactly.
        assert_eq!(shamir_recover(&shares[0..3]), secret, "a 3-of-5 quorum recovers the secret");
        let scattered = [shares[0], shares[2], shares[4]];
        assert_eq!(shamir_recover(&scattered), secret, "a different 3-subset recovers the same secret");

        // Fewer than the threshold cannot: 2 shares interpolate to an unrelated value.
        assert_ne!(shamir_recover(&shares[0..2]), secret, "below threshold learns nothing");
    }

    #[test]
    fn distributed_reshare_rotates_custody_without_reconstructing_the_secret() {
        // The arbitration re-handoff: a secret held 3-of-4 by an original committee must be re-shared to
        // a FRESH committee when an original custodian departs — preserving the threshold split, with NO
        // single party ever holding the secret. Each survivor sub-deals its OWN share independently.
        let secret = [0x5Au8; 32];
        let (t, k_old, k_new) = (3usize, 4usize, 4usize);
        let old = shamir_split(&secret, t, k_old, b"orig-custody");

        // Three of the four original custodians survive (indices 1,2,3); each independently re-shares its
        // share to the new committee. None of them — nor anyone — reconstructs `secret`.
        let survivors: Vec<(u64, [u8; 32])> = old[0..3].to_vec();
        let subdeals: Vec<(u64, Vec<(u64, [u8; 32])>)> = survivors
            .iter()
            .map(|(idx, share)| {
                let mut ikm = b"rehandoff".to_vec();
                ikm.extend_from_slice(&idx.to_le_bytes());
                (*idx, reshare_subdeal(t, k_new, share, &ikm))
            })
            .collect();

        // Each NEW member m (1-based) combines the sub-share addressed to it from every survivor.
        let new_shares: Vec<(u64, [u8; 32])> = (1..=k_new as u64)
            .map(|m| {
                let contributions: Vec<(u64, [u8; 32])> =
                    subdeals.iter().map(|(idx, sd)| (*idx, sd[m as usize - 1].1)).collect();
                (m, reshare_combine(&contributions))
            })
            .collect();

        // The fresh committee holds the SAME secret 3-of-4: any 3 new shares reconstruct it...
        assert_eq!(shamir_recover(&new_shares[0..3]), secret, "the re-shared committee recovers the original secret");
        let scattered = [new_shares[0], new_shares[2], new_shares[3]];
        assert_eq!(shamir_recover(&scattered), secret, "a different new 3-subset recovers the same secret");
        // ...while fewer than the threshold of the NEW shares learn nothing.
        assert_ne!(shamir_recover(&new_shares[0..2]), secret, "below threshold on the new committee learns nothing");

        // Only `threshold` survivors re-sharing is required: with just 2 survivors the Lagrange set is the
        // wrong degree, so the new shares do NOT reconstruct the secret (the re-handoff would stall/slash).
        let too_few: Vec<(u64, Vec<(u64, [u8; 32])>)> = subdeals[0..2].to_vec();
        let bad_new: Vec<(u64, [u8; 32])> = (1..=k_new as u64)
            .map(|m| {
                let c: Vec<(u64, [u8; 32])> = too_few.iter().map(|(idx, sd)| (*idx, sd[m as usize - 1].1)).collect();
                (m, reshare_combine(&c))
            })
            .collect();
        assert_ne!(shamir_recover(&bad_new[0..3]), secret, "fewer than threshold survivors cannot re-share the secret");
    }
}
