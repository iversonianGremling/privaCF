//! Native-group verifiable encryption (SPEC §4.9.4, DESIGN-f1 §3–4) — the real sealing of the
//! forward-secure share `s₂`. `s₂` is published *encrypted* (`d_T`) so that it can be recovered
//! **only after a SUSPEND verdict**, by the verdict's threshold signature, with NO cooperation from
//! the (possibly offline) node — the dark-node-closure property (P4.a). No committee holds any
//! decryption material; the verdict threshold signature *is* the decryption key.
//!
//! Scheme — exponential-ElGamal over BLS12-381, decrypted by a pairing (no in-circuit pairing; the
//! pairing is native, done by whoever extracts `null_v`). `min_pk` groups: `VA_pub = x·g₁ ∈ G₁` is
//! the validator threshold key (`x` the group secret, shared by DKG — `dkg.rs`); the verdict identity
//! is `id = "VERDICT_FINALIZED ‖ epoch_id"`, `Q_id = HashToG2(id) ∈ G₂`, and the verdict threshold
//! signature is `σ = x·Q_id ∈ G₂` (an ordinary BLS signature on `id`).
//!
//!   * `g_T = e(g₁, Q_id) ∈ G_T`,  `K_pub = e(VA_pub, Q_id) = g_T^x` — both computable from public data.
//!   * Split `s₂` (a 64-bit Goldilocks value) into four 16-bit limbs `mⱼ`. Per limb pick `ρⱼ ∈ Z_r`:
//!       `Uⱼ = ρⱼ·g₁ ∈ G₁`,   `Wⱼ = g_T^{mⱼ} · K_pub^{ρⱼ} ∈ G_T`.
//!   * Decrypt with `σ`:  `e(Uⱼ, σ) = e(ρⱼ·g₁, x·Q_id) = g_T^{ρⱼ x} = K_pub^{ρⱼ}`, so
//!       `g_T^{mⱼ} = Wⱼ · e(Uⱼ, σ)^{-1}`, and `mⱼ ∈ [0,2^16)` is found by baby-step/giant-step.
//!
//! Confidentiality (no `σ` ⇒ no `s₂`) reduces to co-DBDH per limb (DESIGN Thm 1). The full
//! well-formedness sigma+range proof a validator checks before accepting `d_T` (DESIGN R1–R3) is a
//! tracked follow-on (P1.2b); honest encrypt → correct decrypt is delivered and tested here. blst
//! Fp12/pairing FFI is isolated to this module (alongside `bls.rs`/`dkg.rs`).

use blst::*;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Domain-separation tag for the verdict identity hash-to-G2 — the verdict threshold signature MUST
/// sign with this same DST so `σ = x·HashToG2(id, VERENC_DST)`.
pub const VERENC_DST: &[u8] = b"PRIVACF_VERENC_VERDICT_v1";

const LIMB_BITS: usize = 16;
const N_LIMBS: usize = 4; // 4 × 16 = 64 bits covers a Goldilocks element

/// The verdict identity bytes for an epoch: `"VERDICT_FINALIZED" ‖ epoch_id` (little-endian).
pub fn verdict_id(epoch_id: u64) -> Vec<u8> {
    let mut v = b"VERDICT_FINALIZED".to_vec();
    v.extend_from_slice(&epoch_id.to_le_bytes());
    v
}

// --- group helpers (G1 / G2 / scalar) -------------------------------------------------------------

fn scalar_le_from_be(be: &[u8; 32]) -> [u8; 32] {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_bendian(&mut s, be.as_ptr());
        let mut le = [0u8; 32];
        blst_lendian_from_scalar(le.as_mut_ptr(), &s);
        le
    }
}

/// A uniform scalar (big-endian, `< r`) from key material, via BLS key-gen (which reduces mod r).
fn random_scalar_be(ikm: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(blake3::hash(ikm).as_bytes());
    min_pk::SecretKey::key_gen(&seed, &[]).expect("key_gen").to_bytes()
}

fn g1_generator() -> blst_p1 {
    unsafe {
        let mut p = blst_p1::default();
        blst_p1_from_affine(&mut p, blst_p1_affine_generator());
        p
    }
}

fn g1_mul(p: &blst_p1, scalar_le: &[u8; 32]) -> blst_p1 {
    unsafe {
        let mut o = blst_p1::default();
        blst_p1_mult(&mut o, p, scalar_le.as_ptr(), 255);
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

fn g1_affine_uncompress(b: &[u8; 48]) -> Option<blst_p1_affine> {
    unsafe {
        let mut aff = blst_p1_affine::default();
        (blst_p1_uncompress(&mut aff, b.as_ptr()) == BLST_ERROR::BLST_SUCCESS).then_some(aff)
    }
}

fn g2_hash(id: &[u8]) -> blst_p2 {
    unsafe {
        let mut q = blst_p2::default();
        blst_hash_to_g2(&mut q, id.as_ptr(), id.len(), VERENC_DST.as_ptr(), VERENC_DST.len(), std::ptr::null(), 0);
        q
    }
}

fn g2_mul(p: &blst_p2, scalar_le: &[u8; 32]) -> blst_p2 {
    unsafe {
        let mut o = blst_p2::default();
        blst_p2_mult(&mut o, p, scalar_le.as_ptr(), 255);
        o
    }
}

fn g2_to_affine(p: &blst_p2) -> blst_p2_affine {
    unsafe {
        let mut a = blst_p2_affine::default();
        blst_p2_to_affine(&mut a, p);
        a
    }
}

fn g2_compress(p: &blst_p2) -> [u8; 96] {
    unsafe {
        let mut out = [0u8; 96];
        blst_p2_compress(out.as_mut_ptr(), p);
        out
    }
}

fn g2_affine_uncompress(b: &[u8; 96]) -> Option<blst_p2_affine> {
    unsafe {
        let mut aff = blst_p2_affine::default();
        (blst_p2_uncompress(&mut aff, b.as_ptr()) == BLST_ERROR::BLST_SUCCESS).then_some(aff)
    }
}

// --- G_T (Fp12) helpers ---------------------------------------------------------------------------

const FP12_BYTES: usize = std::mem::size_of::<blst_fp12>(); // 576

fn fp12_one() -> blst_fp12 {
    unsafe { *blst_fp12_one() }
}

fn fp12_mul(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 {
    unsafe {
        let mut o = blst_fp12::default();
        blst_fp12_mul(&mut o, a, b);
        o
    }
}

fn fp12_sqr(a: &blst_fp12) -> blst_fp12 {
    unsafe {
        let mut o = blst_fp12::default();
        blst_fp12_sqr(&mut o, a);
        o
    }
}

fn fp12_inverse(a: &blst_fp12) -> blst_fp12 {
    unsafe {
        let mut o = blst_fp12::default();
        blst_fp12_inverse(&mut o, a);
        o
    }
}

/// The pairing `e(P_{G1}, Q_{G2}) = final_exp(miller_loop(Q, P)) ∈ G_T`.
fn pairing(p1: &blst_p1_affine, q2: &blst_p2_affine) -> blst_fp12 {
    unsafe {
        let mut ml = blst_fp12::default();
        blst_miller_loop(&mut ml, q2, p1);
        let mut out = blst_fp12::default();
        blst_final_exp(&mut out, &ml);
        out
    }
}

/// `base^exp` for a small `u64` exponent (the 16-bit limb encoding `g_T^{mⱼ}`).
fn fp12_pow_u64(base: &blst_fp12, mut exp: u64) -> blst_fp12 {
    let mut result = fp12_one();
    let mut b = *base;
    while exp > 0 {
        if exp & 1 == 1 {
            result = fp12_mul(&result, &b);
        }
        b = fp12_sqr(&b);
        exp >>= 1;
    }
    result
}

/// `base^scalar` for a 255-bit scalar given big-endian (`K_pub^{ρ}`), square-and-multiply MSB-first.
fn fp12_pow_be(base: &blst_fp12, exp_be: &[u8; 32]) -> blst_fp12 {
    let mut result = fp12_one();
    for &byte in exp_be.iter() {
        for bit in (0..8).rev() {
            result = fp12_sqr(&result);
            if (byte >> bit) & 1 == 1 {
                result = fp12_mul(&result, base);
            }
        }
    }
    result
}

fn fp12_to_bytes(a: &blst_fp12) -> Vec<u8> {
    // POD struct (only u64 limbs, no padding); raw little-endian limb bytes, same-arch canonical.
    let mut out = vec![0u8; FP12_BYTES];
    unsafe {
        std::ptr::copy_nonoverlapping(a as *const blst_fp12 as *const u8, out.as_mut_ptr(), FP12_BYTES);
    }
    out
}

fn fp12_from_bytes(b: &[u8]) -> Option<blst_fp12> {
    if b.len() != FP12_BYTES {
        return None;
    }
    let mut a = blst_fp12::default();
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr(), &mut a as *mut blst_fp12 as *mut u8, FP12_BYTES);
    }
    Some(a)
}

// --- public API -----------------------------------------------------------------------------------

/// One encrypted limb: `Uⱼ ∈ G₁` (compressed) and `Wⱼ ∈ G_T` (raw).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Limb {
    #[serde(with = "BigArray")]
    u: [u8; 48],
    w: Vec<u8>,
}

/// `d_T` — the verifiable-encryption ciphertext of `s₂` for one epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerEncCt {
    limbs: Vec<Limb>,
}

impl VerEncCt {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("verenc serialize")
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        bincode::deserialize(b).ok()
    }
}

/// Encrypt `s2` (a 64-bit value) to `va_pub` under verdict identity `id`.
pub fn encrypt(va_pub: &[u8; 48], id: &[u8], s2: u64) -> Option<VerEncCt> {
    let vapub_aff = g1_affine_uncompress(va_pub)?;
    let q_id_aff = g2_to_affine(&g2_hash(id));
    let g1_gen_aff = unsafe { *blst_p1_affine_generator() };
    let g_t = pairing(&g1_gen_aff, &q_id_aff); // e(g1, Q_id)
    let k_pub = pairing(&vapub_aff, &q_id_aff); // e(VA_pub, Q_id) = g_t^x
    let g1 = g1_generator();

    let mut limbs = Vec::with_capacity(N_LIMBS);
    for j in 0..N_LIMBS {
        let m = (s2 >> (LIMB_BITS * j)) & 0xFFFF;
        let rho_be = random_scalar_be(&[id, b"rho", &(j as u64).to_le_bytes(), &s2.to_le_bytes()].concat());
        let rho_le = scalar_le_from_be(&rho_be);
        let u = g1_compress(&g1_mul(&g1, &rho_le)); // U = ρ·g1
        let w = fp12_mul(&fp12_pow_u64(&g_t, m), &fp12_pow_be(&k_pub, &rho_be)); // g_t^m · K_pub^ρ
        limbs.push(Limb { u, w: fp12_to_bytes(&w) });
    }
    Some(VerEncCt { limbs })
}

/// Decrypt `ct` with the verdict threshold signature `σ` and the public verdict identity `id`.
/// Returns the recovered 64-bit `s2`, or `None` on malformed input / out-of-range limb.
pub fn decrypt(ct: &VerEncCt, sigma: &[u8; 96], id: &[u8]) -> Option<u64> {
    if ct.limbs.len() != N_LIMBS {
        return None;
    }
    let sigma_aff = g2_affine_uncompress(sigma)?;
    let g1_gen_aff = unsafe { *blst_p1_affine_generator() };
    let q_id_aff = g2_to_affine(&g2_hash(id));
    let g_t = pairing(&g1_gen_aff, &q_id_aff);
    let table = bsgs_table(&g_t);

    let mut s2 = 0u64;
    for (j, limb) in ct.limbs.iter().enumerate() {
        let u_aff = g1_affine_uncompress(&limb.u)?;
        let w = fp12_from_bytes(&limb.w)?;
        let mask = pairing(&u_aff, &sigma_aff); // e(U, σ) = K_pub^ρ
        let g_t_m = fp12_mul(&w, &fp12_inverse(&mask)); // = g_t^m
        let m = bsgs_solve(&g_t, &table, &g_t_m)?;
        s2 |= (m as u64) << (LIMB_BITS * j);
    }
    Some(s2)
}

// --- baby-step / giant-step discrete log over a 16-bit range in G_T -------------------------------

const BSGS_M: u64 = 256; // ceil(sqrt(2^16))

/// Baby-step table: `g_T^i ↦ i` for `i ∈ [0, 256)`.
fn bsgs_table(g_t: &blst_fp12) -> std::collections::HashMap<Vec<u8>, u64> {
    let mut table = std::collections::HashMap::new();
    let mut cur = fp12_one();
    for i in 0..BSGS_M {
        table.insert(fp12_to_bytes(&cur), i);
        cur = fp12_mul(&cur, g_t);
    }
    table
}

/// Solve `g_T^m == target` for `m ∈ [0, 2^16)` via baby-step/giant-step.
fn bsgs_solve(g_t: &blst_fp12, table: &std::collections::HashMap<Vec<u8>, u64>, target: &blst_fp12) -> Option<u16> {
    // factor = g_T^{-256}
    let factor = fp12_inverse(&fp12_pow_u64(g_t, BSGS_M));
    let mut gamma = *target;
    for i in 0..BSGS_M {
        if let Some(&j) = table.get(&fp12_to_bytes(&gamma)) {
            let m = i * BSGS_M + j;
            return u16::try_from(m).ok();
        }
        gamma = fp12_mul(&gamma, &factor);
    }
    None
}

// --- test / integration helpers: the validator group key and verdict signature --------------------
//
// In production `VA_pub` and `σ_VERDICT` come from the DKG threshold key and the verdict threshold
// signature (`dkg.rs`). These helpers produce the identical values from a single secret `x`, for
// unit tests and for the (static-key) wiring before the live DKG path lands (P1.3).

/// A group keypair `(x_be, VA_pub)` with `VA_pub = x·g₁`, from key material.
pub fn group_keypair(ikm: &[u8]) -> ([u8; 32], [u8; 48]) {
    let x_be = random_scalar_be(ikm);
    let va_pub = g1_compress(&g1_mul(&g1_generator(), &scalar_le_from_be(&x_be)));
    (x_be, va_pub)
}

/// The verdict signature `σ = x·HashToG2(id, VERENC_DST)` for group secret `x`.
pub fn verdict_signature(x_be: &[u8; 32], id: &[u8]) -> [u8; 96] {
    g2_compress(&g2_mul(&g2_hash(id), &scalar_le_from_be(x_be)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp12_size_is_576() {
        assert_eq!(FP12_BYTES, 576);
    }

    #[test]
    fn seal_then_unlock_with_the_verdict_signature() {
        let (x, va_pub) = group_keypair(b"validators");
        let epoch_id = 0xDEAD_BEEF_CAFEu64;
        let id = verdict_id(epoch_id);
        let s2 = 0x1234_5678_9abc_def0u64;

        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");
        // Before any verdict there is no σ; with it, s2 is recovered exactly.
        let sigma = verdict_signature(&x, &id);
        assert_eq!(decrypt(&ct, &sigma, &id), Some(s2), "verdict signature unlocks s2 exactly");
    }

    #[test]
    fn the_wrong_signature_does_not_recover_s2() {
        let (x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(7);
        let s2 = 0x00FF_00FF_00FF_0042u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");

        // A signature for a DIFFERENT id (different verdict / epoch) cannot decrypt.
        let wrong = verdict_signature(&x, &verdict_id(8));
        assert_ne!(decrypt(&ct, &wrong, &id), Some(s2), "a wrong-identity signature must not unlock");
        // A signature from a different group key likewise fails.
        let (x2, _) = group_keypair(b"other-validators");
        let wrong2 = verdict_signature(&x2, &id);
        assert_ne!(decrypt(&ct, &wrong2, &id), Some(s2), "a wrong-key signature must not unlock");
    }

    #[test]
    fn the_dkg_threshold_signature_unlocks_a_sealed_share() {
        use crate::{bls, dkg};
        // Genesis DKG among 5 validators (threshold 3); VA_pub seals, t shares unlock.
        let (t, n) = (3usize, 5usize);
        let parties: Vec<([u8; 32], Vec<u8>)> = (0..n as u8)
            .map(|i| ([i; 32], format!("validator-{i}").into_bytes()))
            .collect();
        let (va_pub, shares) = dkg::genesis_keys(t, &parties);

        let id = verdict_id(0xABCD_1234);
        let s2 = 0x0102_0304_0506_0708u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt under VA_pub");

        // Any t validators threshold-sign verdict_id (with VERENC_DST); combine → σ_VERDICT.
        let partials: Vec<(u64, [u8; 96])> = parties
            .iter()
            .enumerate()
            .take(t)
            .map(|(idx, (pid, _))| (idx as u64 + 1, bls::sign_dst(&shares[pid], &id, VERENC_DST)))
            .collect();
        let sigma = dkg::combine_signatures(&partials).expect("combine verdict signature");

        assert_eq!(decrypt(&ct, &sigma, &id), Some(s2), "the DKG threshold verdict sig unlocks s₂");
    }

    #[test]
    fn ciphertext_round_trips_through_bytes() {
        let (x, va_pub) = group_keypair(b"v");
        let id = verdict_id(123);
        let s2 = 0xFFFF_FFFF_FFFF_FFFFu64 % crate::field::GOLDILOCKS_P;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");
        let bytes = ct.to_bytes();
        let back = VerEncCt::from_bytes(&bytes).expect("decode");
        let sigma = verdict_signature(&x, &id);
        assert_eq!(decrypt(&back, &sigma, &id), Some(s2));
    }
}
