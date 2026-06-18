//! Zero-knowledge handoff statements over the on-chain preference commitment `C_p` (SPEC §6.4
//! Statements 1–3). The publisher of an epoch transaction commits to its CLEAN preference vector with
//! the Ristretto vector Pedersen commitment in [`crate::pedersen`]; these proofs let it convince any
//! verifier — *in zero knowledge, without a Goldilocks ↔ Ristretto bridge* — that the committed
//! vector (and its change since last epoch) is well-formed:
//!
//!   * **Statement 1 (preference norm, §6.4):** every component is bounded, `|p_i| ≤ M`. Bounds
//!     `‖p‖∞ ≤ M` (hence `‖p‖₁ ≤ n·M`) so no single item can carry unbounded weight.
//!   * **Statement 2 (directional, §6.4):** the per-epoch change is sign-consistent — declared "up"
//!     items only rose (`Δp_i ≥ 0`), declared "down" items only fell (`Δp_i ≤ 0`).
//!   * **Statement 3 (temporal consistency, §6.4):** the change is small, `|Δp_i| ≤ δ` per item, so a
//!     node cannot lurch its profile between epochs (bounds `‖Δp‖∞ ≤ δ`, hence `‖Δp‖₁ ≤ n·δ`). The
//!     difference is read straight off the homomorphic `C_p(T) − C_p(T−1)` (`Pedersen::difference`).
//!
//! All three reduce to two primitives, both standard Fiat-Shamir sigma protocols in the SAME
//! Ristretto group the commitment lives in (so no non-native EC arithmetic — this side-steps the
//! AMBER Track-Z bridge entirely):
//!
//!   * a **proof of knowledge of the vector opening** ([`OpeningProof`]) — Schnorr over the vector
//!     commitment, binding the publisher to a vector it actually knows;
//!   * a **per-component bounded-range proof** ([`RangeProof`]) — bit-decomposition with a
//!     Chaum-Pedersen OR-proof per bit (`b ∈ {0,1}`), giving `v ∈ [0, 2ⁿ)`, composed into `v ∈ [0,B]`.
//!
//! To range-prove individual components of an *aggregated* vector commitment, the prover also publishes
//! per-component commitments `C_i = p_i·G_i + r_i·H` with `Σ r_i = r`; the verifier checks `Σ C_i = C_p`
//! (binding to the on-chain commitment) and that each `C_i` satisfies its bound. The `C_i` are
//! perfectly hiding, so this leaks nothing about `p`.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::pedersen::Pedersen;

/// A deterministic stream of scalars for the prover's nonces — seeded by a caller-supplied 32-byte
/// seed so proofs are reproducible (and unpredictable to the verifier, who never sees the seed).
struct ScalarStream(blake3::OutputReader);

impl ScalarStream {
    fn new(seed: &[u8; 32], domain: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"privacf-zkstmt-nonce-v1");
        h.update(seed);
        h.update(domain);
        Self(h.finalize_xof())
    }
    fn next(&mut self) -> Scalar {
        let mut wide = [0u8; 64];
        self.0.fill(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

/// Fiat-Shamir challenge over a transcript label and a list of points.
fn challenge(label: &[u8], points: &[&RistrettoPoint]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-zkstmt-fs-v1");
    h.update(label);
    for p in points {
        h.update(p.compress().as_bytes());
    }
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn enc(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}
fn dec(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*b).decompress()
}
fn enc_s(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}
fn dec_s(b: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*b))
}

// ─────────────────────────── proof of knowledge of vector opening ───────────────────────────

/// Schnorr proof of knowledge of an opening `(values, r)` of a vector commitment `C = Σ vᵢ·Gᵢ + r·H`.
/// Zero-knowledge: reveals nothing about `values`/`r`. Binds the publisher to a vector it knows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpeningProof {
    t: [u8; 32],
    z: Vec<[u8; 32]>,
    z_r: [u8; 32],
}

/// Prove knowledge of the opening of `commitment = pc.commit(values, blinding)`.
pub fn prove_opening(pc: &Pedersen, commitment: &[u8; 32], values: &[i64], blinding: &[u8; 32], seed: &[u8; 32]) -> OpeningProof {
    let c = dec(commitment).expect("valid commitment");
    let r = Scalar::from_bytes_mod_order(*blinding);
    let mut stream = ScalarStream::new(seed, b"opening");

    let a: Vec<Scalar> = (0..values.len()).map(|_| stream.next()).collect();
    let s = stream.next();
    let mut t = pc.h() * s;
    for (i, ai) in a.iter().enumerate() {
        t += pc.g(i) * ai;
    }

    let ch = challenge(b"opening", &[&c, &t]);
    let z: Vec<[u8; 32]> =
        a.iter().zip(values.iter()).map(|(ai, &v)| enc_s(&(ai + ch * Pedersen::value_scalar(v)))).collect();
    let z_r = enc_s(&(s + ch * r));
    OpeningProof { t: enc(&t), z, z_r }
}

/// Verify a [`prove_opening`] proof against `commitment`.
pub fn verify_opening(pc: &Pedersen, commitment: &[u8; 32], proof: &OpeningProof) -> bool {
    let (Some(c), Some(t)) = (dec(commitment), dec(&proof.t)) else { return false };
    if proof.z.len() > pc.width() {
        return false;
    }
    let ch = challenge(b"opening", &[&c, &t]);
    let Some(z_r) = dec_s(&proof.z_r) else { return false };
    let mut lhs = pc.h() * z_r;
    for (i, zi) in proof.z.iter().enumerate() {
        let Some(zi) = dec_s(zi) else { return false };
        lhs += pc.g(i) * zi;
    }
    lhs == t + c * ch
}

// ─────────────────────────────── range proof (bit decomposition) ───────────────────────────────

/// A Chaum-Pedersen OR-proof that a commitment `B` opens to a bit: `B = b·G + s·H` with `b ∈ {0,1}`
/// (equivalently `B = s·H` OR `B − G = s·H`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BitOr {
    a0: [u8; 32],
    a1: [u8; 32],
    e0: [u8; 32], // e1 = challenge − e0 is recomputed
    z0: [u8; 32],
    z1: [u8; 32],
}

/// A proof that a Pedersen commitment `V = v·G + r·H` (value base `G`, blinding base `H`) opens to
/// `v ∈ [0, 2^n)`: `n` bit-commitments whose `2ʲ`-weighted sum is `V`, each proven to be a bit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    bits: Vec<[u8; 32]>, // Bⱼ
    ors: Vec<BitOr>,
}

fn two_pow(j: usize) -> Scalar {
    let mut acc = Scalar::ONE;
    let two = Scalar::from(2u64);
    for _ in 0..j {
        acc *= two;
    }
    acc
}

/// Prove `v ∈ [0, 2^n)` for the commitment `V = v·g + r·h` (the caller holds `V`; `g` is the value
/// base, `h` the blinding base). `r` is the blinding scalar.
fn prove_range_pow2(g: RistrettoPoint, h: RistrettoPoint, v: u64, r: Scalar, n: usize, stream: &mut ScalarStream) -> RangeProof {
    debug_assert!(n >= 1 && n <= 64);
    // Per-bit blindings sₘ with Σ 2ʲ·sⱼ = r: choose the first n−1 freely, solve the last.
    let mut s: Vec<Scalar> = (0..n - 1).map(|_| stream.next()).collect();
    let mut weighted = Scalar::ZERO;
    for (j, sj) in s.iter().enumerate() {
        weighted += two_pow(j) * sj;
    }
    let last = (r - weighted) * two_pow(n - 1).invert();
    s.push(last);

    let mut bits = Vec::with_capacity(n);
    let mut ors = Vec::with_capacity(n);
    for j in 0..n {
        let bj = (v >> j) & 1;
        let bj_s = Scalar::from(bj);
        let bcom = g * bj_s + h * s[j];
        bits.push(enc(&bcom));

        // OR proof: P0 = B (dlog s w.r.t H if b=0); P1 = B − G (dlog s w.r.t H if b=1).
        let p0 = bcom;
        let p1 = bcom - g;
        let x = s[j]; // the real witness on the true branch
        let d = bj as usize; // true branch index

        // Simulate the false branch (1−d): random challenge + response, back out its commitment.
        let e_fake = stream.next();
        let z_fake = stream.next();
        let p_fake = if d == 0 { p1 } else { p0 };
        let a_fake = h * z_fake - p_fake * e_fake;
        // Real branch nonce.
        let k = stream.next();
        let a_real = h * k;

        let (a0, a1) = if d == 0 { (a_real, a_fake) } else { (a_fake, a_real) };
        let ch = challenge(b"bit", &[&p0, &p1, &a0, &a1]);
        let e_real = ch - e_fake;
        let z_real = k + e_real * x;

        let (e0, z0, z1) = if d == 0 { (e_real, z_real, z_fake) } else { (e_fake, z_fake, z_real) };
        ors.push(BitOr { a0: enc(&a0), a1: enc(&a1), e0: enc_s(&e0), z0: enc_s(&z0), z1: enc_s(&z1) });
    }
    RangeProof { bits, ors }
}

/// Verify a `v ∈ [0, 2^n)` proof for commitment `vcom = V` under value base `g`, blinding base `h`.
fn verify_range_pow2(g: RistrettoPoint, h: RistrettoPoint, vcom: RistrettoPoint, proof: &RangeProof, n: usize) -> bool {
    if proof.bits.len() != n || proof.ors.len() != n {
        return false;
    }
    // Σ 2ʲ·Bⱼ must equal V (binds the bits to the committed value+blinding).
    let mut acc = RistrettoPoint::default();
    for (j, b) in proof.bits.iter().enumerate() {
        let Some(bj) = dec(b) else { return false };
        acc += bj * two_pow(j);
    }
    if acc != vcom {
        return false;
    }
    // Each bit is 0 or 1.
    for (b, or) in proof.bits.iter().zip(proof.ors.iter()) {
        let Some(bcom) = dec(b) else { return false };
        let p0 = bcom;
        let p1 = bcom - g;
        let (Some(a0), Some(a1)) = (dec(&or.a0), dec(&or.a1)) else { return false };
        let (Some(e0), Some(z0), Some(z1)) = (dec_s(&or.e0), dec_s(&or.z0), dec_s(&or.z1)) else { return false };
        let ch = challenge(b"bit", &[&p0, &p1, &a0, &a1]);
        let e1 = ch - e0;
        if h * z0 != a0 + p0 * e0 || h * z1 != a1 + p1 * e1 {
            return false;
        }
    }
    true
}

/// A proof that a Pedersen commitment opens to `v ∈ [0, B]`: range proofs of both `v` and `B − v` in
/// `[0, 2^n)` with `2^n > B` (so `v ≥ 0` and `B − v ≥ 0` ⇒ `0 ≤ v ≤ B`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundedProof {
    lo: RangeProof, // v ∈ [0, 2ⁿ)
    hi: RangeProof, // B − v ∈ [0, 2ⁿ)
    n: u32,
    bound: u64,
}

fn bits_for(bound: u64) -> usize {
    (64 - (bound.max(1)).leading_zeros()) as usize
}

/// Prove the commitment `vcom = v·g + r·h` opens to `v ∈ [0, bound]`.
fn prove_bounded(g: RistrettoPoint, h: RistrettoPoint, v: u64, r: Scalar, bound: u64, stream: &mut ScalarStream) -> BoundedProof {
    let n = bits_for(bound) + 1; // headroom so 2ⁿ > bound
    let lo = prove_range_pow2(g, h, v, r, n, stream);
    // (B − v) under blinding −r; its commitment is B·g − vcom.
    let hi = prove_range_pow2(g, h, bound - v, -r, n, stream);
    BoundedProof { lo, hi, n: n as u32, bound }
}

/// Verify `v ∈ [0, proof.bound]` for `vcom` under value base `g`, blinding base `h`.
fn verify_bounded(g: RistrettoPoint, h: RistrettoPoint, vcom: RistrettoPoint, proof: &BoundedProof) -> bool {
    let n = proof.n as usize;
    if n == 0 || n > 64 {
        return false;
    }
    let hi_com = g * Scalar::from(proof.bound) - vcom;
    verify_range_pow2(g, h, vcom, &proof.lo, n) && verify_range_pow2(g, h, hi_com, &proof.hi, n)
}

// ───────────────────────────────── the three handoff statements ─────────────────────────────────

/// Per-component commitments `C_i = p_i·G_i + r_i·H` with `Σ r_i = r`, published alongside the proofs
/// so the verifier can bind them to the aggregate `C_p` (checks `Σ C_i = C_p`) and range-prove each.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentCommits {
    coms: Vec<[u8; 32]>,
}

impl ComponentCommits {
    fn points(&self) -> Option<Vec<RistrettoPoint>> {
        self.coms.iter().map(dec).collect()
    }
}

/// Build per-component commitments for `values` whose blindings sum to `blinding` (so they aggregate
/// to the original `C_p`). Returns the commitments and the per-component blindings (kept by the prover).
fn component_commits(pc: &Pedersen, values: &[i64], blinding: &[u8; 32], stream: &mut ScalarStream) -> (ComponentCommits, Vec<Scalar>) {
    let n = values.len();
    let r = Scalar::from_bytes_mod_order(*blinding);
    let mut rs: Vec<Scalar> = (0..n.saturating_sub(1)).map(|_| stream.next()).collect();
    let used: Scalar = rs.iter().sum();
    rs.push(r - used); // last blinding makes the sum equal r
    let coms: Vec<[u8; 32]> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| enc(&(pc.g(i) * Pedersen::value_scalar(v) + pc.h() * rs[i])))
        .collect();
    (ComponentCommits { coms }, rs)
}

/// Statement 1 (preference norm): every `|p_i| ≤ m`. Proof = component commitments + a per-component
/// bounded proof of `p_i + m ∈ [0, 2m]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormProof {
    components: ComponentCommits,
    bounds: Vec<BoundedProof>,
    m: u64,
}

/// Prove `‖p‖∞ ≤ m` for the on-chain `commitment = pc.commit(values, blinding)`.
pub fn prove_norm(pc: &Pedersen, values: &[i64], blinding: &[u8; 32], m: u64, seed: &[u8; 32]) -> NormProof {
    let mut stream = ScalarStream::new(seed, b"norm");
    let (components, rs) = component_commits(pc, values, blinding, &mut stream);
    let bounds = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            // shifted value p_i + m ∈ [0, 2m], same blinding r_i, value base G_i.
            let shifted = (v + m as i64).max(0) as u64;
            prove_bounded(pc.g(i), pc.h(), shifted, rs[i], 2 * m, &mut stream)
        })
        .collect();
    NormProof { components, bounds, m }
}

/// Verify a [`prove_norm`] proof binds to `commitment` and bounds every component.
pub fn verify_norm(pc: &Pedersen, commitment: &[u8; 32], proof: &NormProof) -> bool {
    let (Some(c), Some(parts)) = (dec(commitment), proof.components.points()) else { return false };
    if parts.len() != proof.bounds.len() {
        return false;
    }
    // Bind to the aggregate.
    if parts.iter().sum::<RistrettoPoint>() != c {
        return false;
    }
    // Each component p_i + m ∈ [0, 2m].
    let m = proof.m;
    parts.iter().zip(proof.bounds.iter()).enumerate().all(|(i, (ci, bp))| {
        bp.bound == 2 * m && {
            let shifted = ci + pc.g(i) * Scalar::from(m);
            verify_bounded(pc.g(i), pc.h(), shifted, bp)
        }
    })
}

/// Statement 3 (temporal consistency): `|Δp_i| ≤ δ` between epochs `T−1` and `T`. Reads the difference
/// straight off the homomorphic `C_p(T) − C_p(T−1)` and bounds each component.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TemporalProof {
    components: ComponentCommits, // per-component commitments to Δp, aggregating to C(T) − C(T−1)
    bounds: Vec<BoundedProof>,
    delta: u64,
}

/// Prove `‖Δp‖∞ ≤ delta` where `prev`/`curr` are the clean vectors and `r_prev`/`r_curr` their
/// blindings. The proof binds to `C(T) − C(T−1)` (the verifier supplies the two on-chain commitments).
pub fn prove_temporal(
    pc: &Pedersen,
    prev: &[i64],
    r_prev: &[u8; 32],
    curr: &[i64],
    r_curr: &[u8; 32],
    delta: u64,
    seed: &[u8; 32],
) -> TemporalProof {
    let mut stream = ScalarStream::new(seed, b"temporal");
    let diff: Vec<i64> = curr.iter().zip(prev.iter()).map(|(a, b)| a - b).collect();
    // Δr = r_curr − r_prev so component commitments aggregate to C(T) − C(T−1).
    let dr = Scalar::from_bytes_mod_order(*r_curr) - Scalar::from_bytes_mod_order(*r_prev);
    let dr_bytes = dr.to_bytes();
    let (components, rs) = component_commits(pc, &diff, &dr_bytes, &mut stream);
    let bounds = diff
        .iter()
        .enumerate()
        .map(|(i, &dv)| {
            let shifted = (dv + delta as i64).max(0) as u64; // Δp_i + δ ∈ [0, 2δ]
            prove_bounded(pc.g(i), pc.h(), shifted, rs[i], 2 * delta, &mut stream)
        })
        .collect();
    TemporalProof { components, bounds, delta }
}

/// Verify a [`prove_temporal`] proof binds to `C(T) − C(T−1)` and bounds every component change.
pub fn verify_temporal(pc: &Pedersen, commit_prev: &[u8; 32], commit_curr: &[u8; 32], proof: &TemporalProof) -> bool {
    let (Some(cp), Some(cc)) = (dec(commit_prev), dec(commit_curr)) else { return false };
    let Some(parts) = proof.components.points() else { return false };
    if parts.len() != proof.bounds.len() {
        return false;
    }
    // Bind: the component commitments must aggregate to the homomorphic difference.
    if parts.iter().sum::<RistrettoPoint>() != cc - cp {
        return false;
    }
    let delta = proof.delta;
    parts.iter().zip(proof.bounds.iter()).enumerate().all(|(i, (ci, bp))| {
        bp.bound == 2 * delta && {
            let shifted = ci + pc.g(i) * Scalar::from(delta);
            verify_bounded(pc.g(i), pc.h(), shifted, bp)
        }
    })
}

/// Statement 2 (directional): declared "up" items only rose (`Δp_i ≥ 0`), "down" items only fell
/// (`Δp_i ≤ 0`). `dirs[i]`: `+1` up, `−1` down, `0` unconstrained.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectionalProof {
    components: ComponentCommits,
    dirs: Vec<i8>,
    bound: u64,
    // a non-negativity range proof on (dir·Δp_i) for each constrained component
    ranges: Vec<Option<RangeProof>>,
    n: u32,
}

/// Prove the per-epoch change respects `dirs` (sign per item), with `|Δp_i| ≤ bound` providing the
/// range. Binds to `C(T) − C(T−1)`.
pub fn prove_directional(
    pc: &Pedersen,
    prev: &[i64],
    r_prev: &[u8; 32],
    curr: &[i64],
    r_curr: &[u8; 32],
    dirs: &[i8],
    bound: u64,
    seed: &[u8; 32],
) -> DirectionalProof {
    let mut stream = ScalarStream::new(seed, b"directional");
    let diff: Vec<i64> = curr.iter().zip(prev.iter()).map(|(a, b)| a - b).collect();
    let dr = Scalar::from_bytes_mod_order(*r_curr) - Scalar::from_bytes_mod_order(*r_prev);
    let dr_bytes = dr.to_bytes();
    let (components, rs) = component_commits(pc, &diff, &dr_bytes, &mut stream);
    let n = bits_for(bound) + 1;
    let ranges = diff
        .iter()
        .enumerate()
        .map(|(i, &dv)| {
            let d = dirs.get(i).copied().unwrap_or(0);
            if d == 0 {
                None
            } else {
                // The value dir·Δp_i ≥ 0 is committed by dir·C_i = G_i·(dir·Δp_i) + H·(dir·r_i): keep
                // the value base G_i, take blinding dir·r_i; the commitment scales by dir at verify.
                let signed = (d as i64 * dv).max(0) as u64;
                let r = Pedersen::value_scalar(d as i64) * rs[i];
                Some(prove_range_pow2(pc.g(i), pc.h(), signed, r, n, &mut stream))
            }
        })
        .collect();
    DirectionalProof { components, dirs: dirs.to_vec(), bound, ranges, n: n as u32 }
}

/// Verify a [`prove_directional`] proof.
pub fn verify_directional(pc: &Pedersen, commit_prev: &[u8; 32], commit_curr: &[u8; 32], proof: &DirectionalProof) -> bool {
    let (Some(cp), Some(cc)) = (dec(commit_prev), dec(commit_curr)) else { return false };
    let Some(parts) = proof.components.points() else { return false };
    if parts.len() != proof.ranges.len() || parts.len() != proof.dirs.len() {
        return false;
    }
    if parts.iter().sum::<RistrettoPoint>() != cc - cp {
        return false;
    }
    let n = proof.n as usize;
    parts.iter().zip(proof.ranges.iter()).enumerate().all(|(i, (ci, rng))| {
        let d = proof.dirs[i];
        match (d, rng) {
            (0, None) => true,
            (0, Some(_)) | (_, None) => d == 0, // a constrained item must carry a proof
            (_, Some(rp)) => {
                let signed_com = *ci * Pedersen::value_scalar(d as i64); // dir·C_i commits dir·Δp_i ≥ 0
                verify_range_pow2(pc.g(i), pc.h(), signed_com, rp, n)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn opening_proof_round_trips_and_rejects_tampering() {
        let pc = Pedersen::new(6);
        let v = [3i64, -1, 0, 5, 2, -4];
        let r = [9u8; 32];
        let c = pc.commit(&v, &r);
        let proof = prove_opening(&pc, &c, &v, &r, &seed(1));
        assert!(verify_opening(&pc, &c, &proof), "honest opening proof verifies");

        // A proof does not verify against a different commitment.
        let c2 = pc.commit(&[3, -1, 0, 5, 2, -3], &r);
        assert!(!verify_opening(&pc, &c2, &proof), "proof is bound to its commitment");
    }

    #[test]
    fn range_proof_accepts_in_range_and_binds_value() {
        let pc = Pedersen::new(1);
        let (g, h) = (pc.g(0), pc.h());
        let mut st = ScalarStream::new(&seed(2), b"t");
        let r = st.next();
        let v = 42u64;
        let vcom = g * Scalar::from(v) + h * r;
        let proof = prove_range_pow2(g, h, v, r, 8, &mut st);
        assert!(verify_range_pow2(g, h, vcom, &proof, 8), "42 ∈ [0,256) verifies");
        // Wrong committed value (same proof) fails the Σ2ʲBⱼ == V binding.
        let wrong = g * Scalar::from(43u64) + h * r;
        assert!(!verify_range_pow2(g, h, wrong, &proof, 8), "proof binds to the value");
    }

    #[test]
    fn bounded_proof_accepts_within_and_the_commitment_binds() {
        let pc = Pedersen::new(1);
        let (g, h) = (pc.g(0), pc.h());
        let mut st = ScalarStream::new(&seed(3), b"t");
        let r = st.next();
        let v = 7u64;
        let vcom = g * Scalar::from(v) + h * r;
        let proof = prove_bounded(g, h, v, r, 10, &mut st);
        assert!(verify_bounded(g, h, vcom, &proof), "7 ∈ [0,10] verifies");
    }

    #[test]
    fn norm_statement_bounds_every_component_and_binds_to_c_p() {
        let pc = Pedersen::new(5);
        let p = [3i64, -2, 1, 0, 3];
        let r = [11u8; 32];
        let c = pc.commit(&p, &r);
        let proof = prove_norm(&pc, &p, &r, 3, &seed(4));
        assert!(verify_norm(&pc, &c, &proof), "‖p‖∞ ≤ 3 verifies against C_p");
        // Tampered aggregate commitment is rejected (binding).
        let c_bad = pc.commit(&[3, -2, 1, 0, 4], &r);
        assert!(!verify_norm(&pc, &c_bad, &proof), "proof is bound to the real C_p");
    }

    #[test]
    fn temporal_statement_bounds_change_against_the_homomorphic_difference() {
        let pc = Pedersen::new(5);
        let prev = [5i64, 3, 0, 2, 4];
        let curr = [6i64, 2, 1, 2, 3]; // Δ = [+1,-1,+1,0,-1], all within δ=2
        let rp = [3u8; 32];
        let rc = [8u8; 32];
        let c_prev = pc.commit(&prev, &rp);
        let c_curr = pc.commit(&curr, &rc);
        let proof = prove_temporal(&pc, &prev, &rp, &curr, &rc, 2, &seed(5));
        assert!(verify_temporal(&pc, &c_prev, &c_curr, &proof), "‖Δp‖∞ ≤ 2 verifies");
        // Bind: swapping in a different current commitment breaks the difference check.
        let c_other = pc.commit(&[9, 9, 9, 9, 9], &rc);
        assert!(!verify_temporal(&pc, &c_prev, &c_other, &proof), "bound to C(T) − C(T−1)");
    }

    #[test]
    fn directional_statement_enforces_per_item_signs() {
        let pc = Pedersen::new(4);
        let prev = [2i64, 5, 1, 3];
        let curr = [4i64, 3, 1, 4]; // Δ = [+2,-2,0,+1]
        let dirs = [1i8, -1, 0, 1]; // up, down, free, up — all consistent
        let rp = [2u8; 32];
        let rc = [7u8; 32];
        let c_prev = pc.commit(&prev, &rp);
        let c_curr = pc.commit(&curr, &rc);
        let proof = prove_directional(&pc, &prev, &rp, &curr, &rc, &dirs, 8, &seed(6));
        assert!(verify_directional(&pc, &c_prev, &c_curr, &proof), "consistent directions verify");
    }

    #[test]
    fn out_of_bound_component_cannot_be_proven() {
        // Soundness: a vector with a component exceeding the norm bound cannot yield a verifying proof
        // (the B−v side of the bounded proof underflows and breaks the Σ2ʲBⱼ == V binding).
        let pc = Pedersen::new(3);
        let p = [4i64, 0, 0]; // 4 > m = 3
        let r = [5u8; 32];
        let c = pc.commit(&p, &r);
        let proof = prove_norm(&pc, &p, &r, 3, &seed(7));
        assert!(!verify_norm(&pc, &c, &proof), "an over-bound component fails verification");
    }

    #[test]
    fn temporal_rejects_a_lurch_beyond_delta() {
        // Soundness for Statement 3: a change exceeding δ cannot be proven.
        let pc = Pedersen::new(3);
        let prev = [0i64, 0, 0];
        let curr = [5i64, 0, 0]; // Δ = +5 > δ = 2
        let rp = [1u8; 32];
        let rc = [4u8; 32];
        let c_prev = pc.commit(&prev, &rp);
        let c_curr = pc.commit(&curr, &rc);
        let proof = prove_temporal(&pc, &prev, &rp, &curr, &rc, 2, &seed(8));
        assert!(!verify_temporal(&pc, &c_prev, &c_curr, &proof), "a lurch beyond δ fails verification");
    }
}
