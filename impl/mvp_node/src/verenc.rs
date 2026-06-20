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

// ============================ d_T well-formedness proof (DESIGN-f1 §R1–R3, P1.2b) =================
//
// A node publishes `d_T = Enc(s₂)` so that a SUSPEND verdict can recover `s₂` (hence `null_v`) with
// no cooperation from the node. But nothing above forces `d_T` to be a *well-formed* ciphertext of a
// recoverable value: a malicious node could publish garbage, a ciphertext it cannot open, or one
// whose limbs lie outside `[0,2¹⁶)` (so `decrypt`'s baby-step/giant-step search silently fails). The
// breakage is only discovered at verdict time — too late: extraction fails and the node escapes
// suspension. This module lets **every validator verify, at publish time and without `σ`**, that
// `d_T` is a real exponential-ElGamal encryption of a 64-bit value whose opening the publisher knows.
//
// Per limb `j` the public statement (over the group params `g₁`, `g_T = e(g₁,Q_id)`,
// `K_pub = e(VA_pub,Q_id)`, all derivable from public `VA_pub`/`id`) is, for `Uⱼ ∈ G₁`, `Wⱼ ∈ G_T`:
//
//     ∃ (mⱼ ∈ [0,2¹⁶), ρⱼ ∈ Z_r):  Uⱼ = ρⱼ·g₁   ∧   Wⱼ = g_T^{mⱼ} · K_pub^{ρⱼ}
//
// proven in zero knowledge by two standard, **fully BLS12-381-native** Fiat–Shamir sigma protocols
// (no non-native field emulation — the AMBER part of Statement-5 is *only* the cross-field binding of
// `s₂` to the Goldilocks `null_v`, which is NOT attempted here and stays a documented residual):
//
//   * a **16-bit OR-decomposition range proof** (mirroring `zkstmt.rs`, in `G₁` with a NUMS second
//     generator `h₁`): the prover publishes hiding bit commitments `Pᵢ = bᵢ·g₁ + tᵢ·h₁` and a
//     Chaum–Pedersen OR-proof `bᵢ ∈ {0,1}` for each; their `2ⁱ`-weighted sum is the value commitment
//     `C_m = mⱼ·g₁ + t·h₁` with `mⱼ ∈ [0,2¹⁶)`;
//   * a **generalized Schnorr** over `(mⱼ, t, ρⱼ)` linking `C_m`, `Uⱼ` and `Wⱼ` through the shared
//     `mⱼ`/`ρⱼ`, proving the encryption is consistent and the prover knows the plaintext.
//
// What this CLOSES: a `d_T` that survives the check is a genuine encryption of a definite, in-range,
// known `s₂` — extraction is guaranteed to succeed, so a node can no longer escape suspension by
// publishing an un-openable ciphertext. What it does NOT close: that the recovered `s₂` satisfies
// `s₁ + s₂ = null_v` for the node's *real* nullifier (a hidden value living in Goldilocks/Poseidon).
// Binding the BLS-side `s₂` to the Goldilocks `null_v` inside one proof is the irreducible non-native
// step (`spike_bridge_cost` ~2²¹ rows) and remains the AMBER Phase-1b residual.

/// NUMS second `G₁` generator `h₁` for the Pedersen bit commitments — hash-to-curve of a fixed label,
/// so nobody knows its discrete log w.r.t. `g₁` (the binding property of the commitments).
fn h1_generator() -> blst_p1 {
    const H1_MSG: &[u8] = b"PRIVACF_VERENC_PROOF_H1_v1";
    const H1_DST: &[u8] = b"PRIVACF_VERENC_PROOF_H1_NUMS_v1";
    unsafe {
        let mut p = blst_p1::default();
        blst_hash_to_g1(&mut p, H1_MSG.as_ptr(), H1_MSG.len(), H1_DST.as_ptr(), H1_DST.len(), std::ptr::null(), 0);
        p
    }
}

// --- scalar (Fr) arithmetic for the sigma responses -----------------------------------------------

fn fr_from_be(be: &[u8; 32]) -> blst_fr {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_bendian(&mut s, be.as_ptr());
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

fn fr_to_le(fr: &blst_fr) -> [u8; 32] {
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_fr(&mut s, fr);
        let mut out = [0u8; 32];
        blst_lendian_from_scalar(out.as_mut_ptr(), &s);
        out
    }
}

fn fr_from_u64(v: u64) -> blst_fr {
    let mut be = [0u8; 32];
    be[24..].copy_from_slice(&v.to_be_bytes());
    fr_from_be(&be)
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

/// A Fiat–Shamir scalar from a transcript: BLAKE3 → 32-byte seed → BLS key-gen (which reduces `< r`),
/// so the result is a uniform `Fr` element deterministically derived from `parts`.
fn fr_from_hash(parts: &[&[u8]]) -> blst_fr {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-verenc-proof-fs-v1");
    for p in parts {
        h.update(p);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(h.finalize().as_bytes());
    fr_from_be(&min_pk::SecretKey::key_gen(&seed, &[]).expect("key_gen").to_bytes())
}

// --- G₁ point arithmetic --------------------------------------------------------------------------

fn p1_from_affine(a: &blst_p1_affine) -> blst_p1 {
    unsafe {
        let mut p = blst_p1::default();
        blst_p1_from_affine(&mut p, a);
        p
    }
}

fn g1_mul_fr(p: &blst_p1, k: &blst_fr) -> blst_p1 {
    g1_mul(p, &fr_to_le(k))
}

fn g1_add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    unsafe {
        let mut o = blst_p1::default();
        blst_p1_add_or_double(&mut o, a, b);
        o
    }
}

fn g1_neg(p: &blst_p1) -> blst_p1 {
    let mut o = *p;
    unsafe { blst_p1_cneg(&mut o, true) };
    o
}

fn g1_sub(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    g1_add(a, &g1_neg(b))
}

fn g1_eq(a: &blst_p1, b: &blst_p1) -> bool {
    g1_compress(a) == g1_compress(b)
}

fn g1_uncompress(b: &[u8; 48]) -> Option<blst_p1> {
    g1_affine_uncompress(b).map(|a| p1_from_affine(&a))
}

// --- G_T (Fp12) helpers for the sigma --------------------------------------------------------------

fn fp12_pow_fr(base: &blst_fp12, k: &blst_fr) -> blst_fp12 {
    fp12_pow_be(base, &fr_to_be(k))
}

fn fp12_eq(a: &blst_fp12, b: &blst_fp12) -> bool {
    unsafe { blst_fp12_is_equal(a, b) }
}

// --- proof wire types ------------------------------------------------------------------------------

/// A Chaum–Pedersen OR-proof that a `G₁` commitment `P = b·g₁ + t·h₁` opens to a bit (`P = t·h₁` OR
/// `P − g₁ = t·h₁`), in the discrete-log base `h₁`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BitOr {
    #[serde(with = "BigArray")]
    a0: [u8; 48],
    #[serde(with = "BigArray")]
    a1: [u8; 48],
    e0: [u8; 32], // e1 = challenge − e0 recomputed
    z0: [u8; 32],
    z1: [u8; 32],
}

/// The well-formedness proof for one encrypted limb: hiding bit commitments + per-bit OR-proofs
/// (`mⱼ ∈ [0,2¹⁶)`) and the linking generalized-Schnorr `(R_a, R_b, R_c, z_m, z_t, z_ρ)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LimbProof {
    bits: Vec<Vec<u8>>, // Pᵢ (each a 48-byte compressed G₁ point)
    ors: Vec<BitOr>,
    #[serde(with = "BigArray")]
    r_a: [u8; 48],
    #[serde(with = "BigArray")]
    r_b: [u8; 48],
    r_c: Vec<u8>, // R_c ∈ G_T (raw fp12)
    z_m: [u8; 32],
    z_t: [u8; 32],
    z_rho: [u8; 32],
}

/// A proof that `d_T` is a well-formed encryption of a known, in-range 64-bit `s₂` — one `LimbProof`
/// per 16-bit limb. Verified by any validator from public `VA_pub`/`id`/`d_T` alone (no `σ`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WellFormedProof {
    limbs: Vec<LimbProof>,
}

impl WellFormedProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("verenc proof serialize")
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        bincode::deserialize(b).ok()
    }
}

/// Deterministic nonce stream for the prover (seeded; never revealed). Each draw is a uniform `Fr`.
struct FrStream(blake3::OutputReader);

impl FrStream {
    fn new(seed: &[u8; 32], domain: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"privacf-verenc-proof-nonce-v1");
        h.update(seed);
        h.update(domain);
        Self(h.finalize_xof())
    }
    fn next(&mut self) -> blst_fr {
        let mut b = [0u8; 32];
        self.0.fill(&mut b);
        fr_from_be(&min_pk::SecretKey::key_gen(&b, &[]).expect("key_gen").to_bytes())
    }
}

/// The shared group parameters of a `d_T`, derived from public `VA_pub` and verdict `id`.
struct Params {
    g1: blst_p1,
    h1: blst_p1,
    g_t: blst_fp12,
    k_pub: blst_fp12,
}

fn params(va_pub: &[u8; 48], id: &[u8]) -> Option<Params> {
    let vapub_aff = g1_affine_uncompress(va_pub)?;
    let q_id_aff = g2_to_affine(&g2_hash(id));
    let g1_gen_aff = unsafe { *blst_p1_affine_generator() };
    Some(Params {
        g1: g1_generator(),
        h1: h1_generator(),
        g_t: pairing(&g1_gen_aff, &q_id_aff),
        k_pub: pairing(&vapub_aff, &q_id_aff),
    })
}

/// Fiat–Shamir challenge for the per-limb generalized Schnorr (binds the context, limb index, both
/// group points and the three sigma commitments).
#[allow(clippy::too_many_arguments)]
fn sigma_challenge(va_pub: &[u8; 48], id: &[u8], j: usize, u: &blst_p1, w: &blst_fp12, c_m: &blst_p1, r_a: &blst_p1, r_b: &blst_p1, r_c: &blst_fp12) -> blst_fr {
    fr_from_hash(&[
        b"sigma",
        va_pub,
        id,
        &(j as u64).to_le_bytes(),
        &g1_compress(u),
        &fp12_to_bytes(w),
        &g1_compress(c_m),
        &g1_compress(r_a),
        &g1_compress(r_b),
        &fp12_to_bytes(r_c),
    ])
}

/// Fiat–Shamir challenge for the per-bit OR-proof.
fn bit_challenge(va_pub: &[u8; 48], id: &[u8], j: usize, i: usize, p0: &blst_p1, p1: &blst_p1, a0: &blst_p1, a1: &blst_p1) -> blst_fr {
    fr_from_hash(&[
        b"bit",
        va_pub,
        id,
        &(j as u64).to_le_bytes(),
        &(i as u64).to_le_bytes(),
        &g1_compress(p0),
        &g1_compress(p1),
        &g1_compress(a0),
        &g1_compress(a1),
    ])
}

/// Prove `d_T` (=`ct`, encrypting `s2` under `va_pub`/`id`) is well-formed. `seed` drives the prover's
/// nonces (kept secret). Returns `None` if `ct` is malformed or its limbs do not decode.
pub fn prove_wellformed(va_pub: &[u8; 48], id: &[u8], ct: &VerEncCt, s2: u64, seed: &[u8; 32]) -> Option<WellFormedProof> {
    if ct.limbs.len() != N_LIMBS {
        return None;
    }
    let pr = params(va_pub, id)?;
    let mut stream = FrStream::new(seed, id);
    let mut out = Vec::with_capacity(N_LIMBS);
    for (j, limb) in ct.limbs.iter().enumerate() {
        let u = g1_uncompress(&limb.u)?;
        let w = fp12_from_bytes(&limb.w)?;
        let m = (s2 >> (LIMB_BITS * j)) & 0xFFFF;
        // Re-derive the per-limb randomness ρⱼ exactly as `encrypt` did (deterministic in id/j/s2).
        let rho_be = random_scalar_be(&[id, b"rho", &(j as u64).to_le_bytes(), &s2.to_le_bytes()].concat());
        let rho = fr_from_be(&rho_be);
        out.push(prove_limb(&pr, va_pub, id, j, &u, &w, m, &rho, &mut stream));
    }
    Some(WellFormedProof { limbs: out })
}

#[allow(clippy::too_many_arguments)]
fn prove_limb(pr: &Params, va_pub: &[u8; 48], id: &[u8], j: usize, u: &blst_p1, w: &blst_fp12, m: u64, rho: &blst_fr, stream: &mut FrStream) -> LimbProof {
    // ---- bit commitments Pᵢ = bᵢ·g₁ + tᵢ·h₁, with OR-proofs bᵢ∈{0,1}; t = Σ 2ⁱ tᵢ, C_m = Σ 2ⁱ Pᵢ ----
    let mut bits = Vec::with_capacity(LIMB_BITS);
    let mut ors = Vec::with_capacity(LIMB_BITS);
    let mut t = fr_from_u64(0);
    let mut c_m: Option<blst_p1> = None;
    for i in 0..LIMB_BITS {
        let b = (m >> i) & 1;
        let ti = stream.next();
        let p_i = g1_add(&g1_mul_fr(&pr.g1, &fr_from_u64(b)), &g1_mul_fr(&pr.h1, &ti));
        bits.push(g1_compress(&p_i).to_vec());

        // accumulate t and C_m by their 2ⁱ weights.
        let w_i = fr_from_u64(1u64 << i);
        t = fr_add(&t, &fr_mul(&w_i, &ti));
        let term = g1_mul_fr(&p_i, &w_i);
        c_m = Some(match c_m {
            Some(acc) => g1_add(&acc, &term),
            None => term,
        });

        // OR-proof that P_i opens to a bit, in base h₁ (witness tᵢ on the true branch).
        let p0 = p_i;
        let p1 = g1_sub(&p_i, &pr.g1);
        let d = b as usize; // true branch
        let e_fake = stream.next();
        let z_fake = stream.next();
        let p_fake = if d == 0 { &p1 } else { &p0 };
        let a_fake = g1_sub(&g1_mul_fr(&pr.h1, &z_fake), &g1_mul_fr(p_fake, &e_fake));
        let k = stream.next();
        let a_real = g1_mul_fr(&pr.h1, &k);
        let (a0, a1) = if d == 0 { (a_real, a_fake) } else { (a_fake, a_real) };
        let ch = bit_challenge(va_pub, id, j, i, &p0, &p1, &a0, &a1);
        let e_real = fr_sub(&ch, &e_fake);
        let z_real = fr_add(&k, &fr_mul(&e_real, &ti));
        let (e0, z0, z1) = if d == 0 { (e_real, z_real, z_fake) } else { (e_fake, z_fake, z_real) };
        ors.push(BitOr { a0: g1_compress(&a0), a1: g1_compress(&a1), e0: fr_to_be(&e0), z0: fr_to_be(&z0), z1: fr_to_be(&z1) });
    }
    let c_m = c_m.expect("LIMB_BITS ≥ 1");

    // ---- linking generalized Schnorr over (m, t, ρ): C_m, U, W share m/ρ ----
    let alpha = stream.next();
    let beta = stream.next();
    let gamma = stream.next();
    let r_a = g1_add(&g1_mul_fr(&pr.g1, &alpha), &g1_mul_fr(&pr.h1, &beta));
    let r_b = g1_mul_fr(&pr.g1, &gamma);
    let r_c = fp12_mul(&fp12_pow_fr(&pr.g_t, &alpha), &fp12_pow_fr(&pr.k_pub, &gamma));
    let ch = sigma_challenge(va_pub, id, j, u, w, &c_m, &r_a, &r_b, &r_c);
    let z_m = fr_add(&alpha, &fr_mul(&ch, &fr_from_u64(m)));
    let z_t = fr_add(&beta, &fr_mul(&ch, &t));
    let z_rho = fr_add(&gamma, &fr_mul(&ch, rho));

    LimbProof {
        bits,
        ors,
        r_a: g1_compress(&r_a),
        r_b: g1_compress(&r_b),
        r_c: fp12_to_bytes(&r_c),
        z_m: fr_to_be(&z_m),
        z_t: fr_to_be(&z_t),
        z_rho: fr_to_be(&z_rho),
    }
}

/// Verify a `WellFormedProof` for `ct` under public `va_pub`/`id`. `true` ⇒ `d_T` is a genuine
/// encryption of a known 64-bit value with every 16-bit limb in `[0,2¹⁶)` (so extraction will
/// succeed). Reveals nothing about `s₂`.
pub fn verify_wellformed(va_pub: &[u8; 48], id: &[u8], ct: &VerEncCt, proof: &WellFormedProof) -> bool {
    if ct.limbs.len() != N_LIMBS || proof.limbs.len() != N_LIMBS {
        return false;
    }
    let Some(pr) = params(va_pub, id) else { return false };
    for (j, (limb, lp)) in ct.limbs.iter().zip(proof.limbs.iter()).enumerate() {
        let (Some(u), Some(w)) = (g1_uncompress(&limb.u), fp12_from_bytes(&limb.w)) else { return false };
        if !verify_limb(&pr, va_pub, id, j, &u, &w, lp) {
            return false;
        }
    }
    true
}

fn verify_limb(pr: &Params, va_pub: &[u8; 48], id: &[u8], j: usize, u: &blst_p1, w: &blst_fp12, lp: &LimbProof) -> bool {
    if lp.bits.len() != LIMB_BITS || lp.ors.len() != LIMB_BITS {
        return false;
    }
    // Recompute C_m = Σ 2ⁱ Pᵢ and check each bit-commitment opens to a bit.
    let mut c_m: Option<blst_p1> = None;
    for (i, (pb, or)) in lp.bits.iter().zip(lp.ors.iter()).enumerate() {
        let Ok(pb): Result<[u8; 48], _> = pb.as_slice().try_into() else { return false };
        let Some(p_i) = g1_uncompress(&pb) else { return false };
        let term = g1_mul_fr(&p_i, &fr_from_u64(1u64 << i));
        c_m = Some(match c_m {
            Some(acc) => g1_add(&acc, &term),
            None => term,
        });
        let p0 = p_i;
        let p1 = g1_sub(&p_i, &pr.g1);
        let (Some(a0), Some(a1)) = (g1_uncompress(&or.a0), g1_uncompress(&or.a1)) else { return false };
        let e0 = fr_from_be(&or.e0);
        let z0 = fr_from_be(&or.z0);
        let z1 = fr_from_be(&or.z1);
        let ch = bit_challenge(va_pub, id, j, i, &p0, &p1, &a0, &a1);
        let e1 = fr_sub(&ch, &e0);
        // h₁·z0 == a0 + P0·e0   and   h₁·z1 == a1 + P1·e1
        if !g1_eq(&g1_mul_fr(&pr.h1, &z0), &g1_add(&a0, &g1_mul_fr(&p0, &e0))) {
            return false;
        }
        if !g1_eq(&g1_mul_fr(&pr.h1, &z1), &g1_add(&a1, &g1_mul_fr(&p1, &e1))) {
            return false;
        }
    }
    let c_m = c_m.expect("LIMB_BITS ≥ 1");

    // Linking generalized Schnorr.
    let (Some(r_a), Some(r_b), Some(r_c)) = (g1_uncompress(&lp.r_a), g1_uncompress(&lp.r_b), fp12_from_bytes(&lp.r_c)) else {
        return false;
    };
    let z_m = fr_from_be(&lp.z_m);
    let z_t = fr_from_be(&lp.z_t);
    let z_rho = fr_from_be(&lp.z_rho);
    let ch = sigma_challenge(va_pub, id, j, u, w, &c_m, &r_a, &r_b, &r_c);
    // (a) z_m·g₁ + z_t·h₁ == R_a + c·C_m
    let lhs_a = g1_add(&g1_mul_fr(&pr.g1, &z_m), &g1_mul_fr(&pr.h1, &z_t));
    let rhs_a = g1_add(&r_a, &g1_mul_fr(&c_m, &ch));
    // (b) z_ρ·g₁ == R_b + c·U
    let lhs_b = g1_mul_fr(&pr.g1, &z_rho);
    let rhs_b = g1_add(&r_b, &g1_mul_fr(u, &ch));
    // (c) g_T^{z_m}·K_pub^{z_ρ} == R_c · W^c
    let lhs_c = fp12_mul(&fp12_pow_fr(&pr.g_t, &z_m), &fp12_pow_fr(&pr.k_pub, &z_rho));
    let rhs_c = fp12_mul(&r_c, &fp12_pow_fr(w, &ch));
    g1_eq(&lhs_a, &rhs_a) && g1_eq(&lhs_b, &rhs_b) && fp12_eq(&lhs_c, &rhs_c)
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

    // ---- d_T well-formedness proof (P1.2b) ----

    #[test]
    fn an_honest_d_t_proves_well_formed_and_verifies() {
        let (_x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(0xAB_CDEF);
        let s2 = 0x1234_5678_9ABC_DEF0u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");

        let proof = prove_wellformed(&va_pub, &id, &ct, s2, b"seed-well-formed-proof-32bytes!!").expect("prove");
        assert!(verify_wellformed(&va_pub, &id, &ct, &proof), "an honest d_T verifies as well-formed");
    }

    #[test]
    fn the_well_formed_proof_round_trips_through_bytes() {
        let (_x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(42);
        let s2 = 0x00FF_1200_3400_5600u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");
        let proof = prove_wellformed(&va_pub, &id, &ct, s2, &[7u8; 32]).expect("prove");
        let back = WellFormedProof::from_bytes(&proof.to_bytes()).expect("decode");
        assert!(verify_wellformed(&va_pub, &id, &ct, &back), "a round-tripped proof still verifies");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_ciphertext() {
        // A proof is bound (via Fiat–Shamir) to the exact U/W of its own d_T: it must not transfer to
        // a different ciphertext, even one under the same key/identity.
        let (_x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(9);
        let ct_a = encrypt(&va_pub, &id, 0x0101_0101_0101_0101).expect("encrypt a");
        let ct_b = encrypt(&va_pub, &id, 0x0202_0202_0202_0202).expect("encrypt b");
        let proof_a = prove_wellformed(&va_pub, &id, &ct_a, 0x0101_0101_0101_0101, &[1u8; 32]).expect("prove a");
        assert!(verify_wellformed(&va_pub, &id, &ct_a, &proof_a));
        assert!(!verify_wellformed(&va_pub, &id, &ct_b, &proof_a), "A's proof must not verify against B's d_T");
    }

    #[test]
    fn a_proof_does_not_verify_under_a_different_key_or_identity() {
        let (_x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(123);
        let s2 = 0x0033_0044_0055_0066u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");
        let proof = prove_wellformed(&va_pub, &id, &ct, s2, &[3u8; 32]).expect("prove");

        // A different VA_pub changes K_pub, so the linking equation fails.
        let (_x2, va_pub2) = group_keypair(b"other-validators");
        assert!(!verify_wellformed(&va_pub2, &id, &ct, &proof), "a wrong VA_pub must reject");
        // A different verdict identity changes g_T/K_pub likewise.
        let id2 = verdict_id(124);
        assert!(!verify_wellformed(&va_pub, &id2, &ct, &proof), "a wrong verdict id must reject");
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let (_x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(77);
        let s2 = 0x0AA0_0BB0_0CC0_0DD0u64;
        let ct = encrypt(&va_pub, &id, s2).expect("encrypt");
        let proof = prove_wellformed(&va_pub, &id, &ct, s2, &[9u8; 32]).expect("prove");

        // Flip a response scalar in the first limb's linking proof: the sigma equations no longer hold.
        let mut bad = proof.clone();
        bad.limbs[0].z_m[0] ^= 0x01;
        assert!(!verify_wellformed(&va_pub, &id, &ct, &bad), "a tampered response must reject");

        // Corrupt a bit commitment: Σ 2ⁱ Pᵢ no longer matches the committed m, OR-proof breaks.
        let mut bad2 = proof.clone();
        bad2.limbs[0].bits[0][0] ^= 0x01;
        assert!(!verify_wellformed(&va_pub, &id, &ct, &bad2), "a tampered bit commitment must reject");
    }

    #[test]
    fn an_out_of_range_limb_is_unopenable_and_cannot_be_proven_well_formed() {
        // The exact threat the well-formedness proof closes: a ciphertext whose limb encodes a value
        // ≥ 2¹⁶ is *un-openable* — `decrypt`'s baby-step/giant-step search (range [0,2¹⁶)) silently
        // fails, so at verdict time extraction yields nothing and the node would escape suspension.
        let (x, va_pub) = group_keypair(b"validators");
        let id = verdict_id(0xDEAD);
        let s2 = 0x0000_0000_0000_1111u64; // limb 0 = 0x1111, the rest 0
        let mut ct = encrypt(&va_pub, &id, s2).expect("encrypt");

        // Push limb 0 out of range: W₀ ← W₀ · g_T^{2¹⁶}, i.e. m₀ becomes 0x1111 + 2¹⁶ ∉ [0,2¹⁶).
        let q_id_aff = g2_to_affine(&g2_hash(&id));
        let g1_gen_aff = unsafe { *blst_p1_affine_generator() };
        let g_t = pairing(&g1_gen_aff, &q_id_aff);
        let w0 = fp12_from_bytes(&ct.limbs[0].w).expect("decode W0");
        ct.limbs[0].w = fp12_to_bytes(&fp12_mul(&w0, &fp12_pow_u64(&g_t, 1u64 << LIMB_BITS)));

        // It is now un-openable even with the genuine verdict signature.
        let sigma = verdict_signature(&x, &id);
        assert_eq!(decrypt(&ct, &sigma, &id), None, "an out-of-range limb cannot be opened");

        // And no well-formedness proof verifies for it: an honest-looking attempt (proving the masked
        // 16-bit m₀) fails the linking equation, which uses the genuine out-of-range W₀.
        let proof = prove_wellformed(&va_pub, &id, &ct, s2, &[2u8; 32]).expect("prove attempt");
        assert!(
            !verify_wellformed(&va_pub, &id, &ct, &proof),
            "an out-of-range ciphertext must NOT pass the well-formedness check"
        );
    }
}
