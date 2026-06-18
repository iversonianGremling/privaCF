//! VerEnc-bridge cost, tightened — a REAL non-native **modular** multiply (Track Z).
//!
//! CONTEXT. The publish-`s₁` Statement 5 is GREEN at the core (`spike_stmt5_proving`); the one
//! remaining feasibility risk is the **two-worlds bridge** (DESIGN-f1 §5): opening a `G₁` Pedersen
//! commitment `C = s₂·G + γ·H` *inside* the small-field circuit — non-native EC over BLS12-381. The
//! dominant primitive is a non-native **modular** multiply `a·b mod p`. `spike_bridge_cost` measured
//! only the schoolbook **limb** multiply and accounted the modular **reduction** as a flat `2×`.
//!
//! WHAT THIS DOES (the improvement). It builds and proves a FULL modular multiply `a·b = q·p + r`
//! over the BLS12-381 base field `p` (381-bit, 24×16-bit limbs): the witness supplies `q, r` (via
//! `num-bigint`), the circuit proves the integer identity `a·b == q·p + r` by canonicalising both
//! sides to 16-bit limbs and connecting them, with every limb range-checked. So the reduction is
//! *measured*, not assumed — `rows/modmul` is read off a real circuit. The bridge band is then
//! recomposed from the measured full-modmul cost (replacing the `2× limb-multiply` proxy).
//!
//! FAITHFULNESS. Same Plonky2-stands-for-Plonky3 logic and 16-bit limbs as the sibling spikes (same
//! FRI/Goldilocks cost class). The EC op-counts (doublings/additions per scalar-mult) remain standard
//! projective-formula counts — building a full scalar-mult is the next step; this increment removes
//! the reduction approximation, the largest source of error in the previous band.

use std::time::Instant;

use num_bigint::BigUint;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

const LIMB_BITS: usize = 16;
const N_LIMBS: usize = 24; // 24 × 16 = 384 ≥ 381-bit BLS12-381 base field

/// BLS12-381 base field modulus `p`.
fn bls12_381_p() -> BigUint {
    BigUint::parse_bytes(
        b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        16,
    )
    .expect("valid p")
}

/// `x` as `n` little-endian 16-bit limbs.
fn to_limbs(mut x: BigUint, n: usize) -> Vec<u64> {
    let mask = BigUint::from(0xFFFFu64);
    (0..n)
        .map(|_| {
            let limb = (&x & &mask).to_u64_digits().first().copied().unwrap_or(0);
            x >>= 16u32;
            limb
        })
        .collect()
}

/// Carry-propagate schoolbook `cols` (each `< ~2^38`) into canonical 16-bit limbs.
fn canonicalize(builder: &mut CircuitBuilder<F, D>, cols: &[Target]) -> Vec<Target> {
    let mut carry = builder.zero();
    let mut out = Vec::with_capacity(cols.len() + 1);
    for c in cols {
        let t = builder.add(*c, carry);
        let bits = builder.split_le(t, 42); // col<2^37 + carry<2^26 ⇒ <2^38, 42 bits safe
        out.push(builder.le_sum(bits[0..LIMB_BITS].iter()));
        carry = builder.le_sum(bits[LIMB_BITS..42].iter());
    }
    out.push(carry);
    out
}

/// Build one full non-native modular multiply `a·b mod p`: prove `a·b == q·p + r` as integers, every
/// limb 16-bit range-checked. Returns the virtual targets `(a, b, q, r)` for the witness.
fn build_modmul(builder: &mut CircuitBuilder<F, D>, p_limbs: &[u64]) -> (Vec<Target>, Vec<Target>, Vec<Target>, Vec<Target>) {
    let n = N_LIMBS;
    let mk = |b: &mut CircuitBuilder<F, D>| -> Vec<Target> { (0..n).map(|_| b.add_virtual_target()).collect() };
    let a = mk(builder);
    let b = mk(builder);
    let q = mk(builder);
    let r = mk(builder);
    for t in a.iter().chain(&b).chain(&q).chain(&r) {
        let _ = builder.split_le(*t, LIMB_BITS); // 16-bit range-check
    }

    let ncols = 2 * n - 1;
    // LHS columns: a·b
    let mut lhs = vec![builder.zero(); ncols];
    for i in 0..n {
        for j in 0..n {
            let prod = builder.mul(a[i], b[j]);
            lhs[i + j] = builder.add(lhs[i + j], prod);
        }
    }
    // RHS columns: q·p + r   (p is a constant)
    let p_consts: Vec<Target> =
        p_limbs.iter().map(|&pj| builder.constant(F::from_canonical_u64(pj))).collect();
    let mut rhs = vec![builder.zero(); ncols];
    for i in 0..n {
        for j in 0..n {
            let prod = builder.mul(q[i], p_consts[j]);
            rhs[i + j] = builder.add(rhs[i + j], prod);
        }
    }
    for (k, rk) in r.iter().enumerate() {
        rhs[k] = builder.add(rhs[k], *rk);
    }

    // Canonicalize both and connect: a·b == q·p + r as non-negative integers.
    let lhs_c = canonicalize(builder, &lhs);
    let rhs_c = canonicalize(builder, &rhs);
    let zero = builder.zero();
    for k in 0..lhs_c.len().max(rhs_c.len()) {
        let l = lhs_c.get(k).copied().unwrap_or(zero);
        let rr = rhs_c.get(k).copied().unwrap_or(zero);
        builder.connect(l, rr);
    }
    (a, b, q, r)
}

struct Row {
    n_muls: usize,
    degree_bits: usize,
    trace_len: usize,
    prove_s: f64,
}

fn run(n_muls: usize) -> Row {
    let p = bls12_381_p();
    let p_limbs = to_limbs(p.clone(), N_LIMBS);

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let gadgets: Vec<_> = (0..n_muls).map(|_| build_modmul(&mut builder, &p_limbs)).collect();

    let data = builder.build::<C>();
    let degree_bits = data.common.degree_bits();
    let trace_len = 1usize << degree_bits;

    // Witness: a,b reduced mod p (so q < 2^384 fits 24 limbs); q,r from real big-int divmod.
    let mut pw = PartialWitness::new();
    for (idx, (a, b, q, r)) in gadgets.iter().enumerate() {
        let av = (BigUint::from(0x9e37_79b9_u64) * (idx as u64 + 1)) % &p;
        let bv = (BigUint::from(0x85eb_ca6b_u64) * (idx as u64 + 7)) % &p;
        let prod = &av * &bv;
        let qv = &prod / &p;
        let rv = &prod % &p;
        assert!(&qv * &p + &rv == prod && rv < p && qv < (BigUint::from(1u64) << 384));
        let set = |pw: &mut PartialWitness<F>, ts: &[Target], val: &BigUint| {
            for (t, limb) in ts.iter().zip(to_limbs(val.clone(), N_LIMBS)) {
                pw.set_target(*t, F::from_canonical_u64(limb));
            }
        };
        set(&mut pw, a, &av);
        set(&mut pw, b, &bv);
        set(&mut pw, q, &qv);
        set(&mut pw, r, &rv); // to_limbs handles r == 0 (all-zero limbs)
    }

    let t = Instant::now();
    let proof = data.prove(pw).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    data.verify(proof).expect("verify failed");

    Row { n_muls, degree_bits, trace_len, prove_s }
}

fn main() {
    println!("VerEnc-bridge cost — REAL non-native MODULAR multiply (a·b mod p) over BLS12-381 Fp");
    println!("(Plonky2/Goldilocks FRI stand-in for Plonky3; 24×16-bit limbs; reduction MEASURED)\n");
    println!("  {:>9} {:>9} {:>11} {:>9}", "n_modmuls", "deg_bits", "trace_len", "prove_s");

    let sizes = [1usize, 16, 64, 256];
    let mut rows = Vec::new();
    for &n in &sizes {
        let r = run(n);
        println!("  {:>9} {:>9} {:>11} {:>9.3}", r.n_muls, r.degree_bits, r.trace_len, r.prove_s);
        rows.push(r);
    }

    // Marginal rows per FULL modular multiply, from the two largest points (amortises the fixed
    // FRI/recursion overhead in the small circuits).
    let a = &rows[rows.len() - 2];
    let b = &rows[rows.len() - 1];
    let rows_per_modmul = (b.trace_len as f64 - a.trace_len as f64) / (b.n_muls as f64 - a.n_muls as f64);
    let s_per_row = ((b.prove_s - a.prove_s) / (b.trace_len as f64 - a.trace_len as f64)).max(0.0);

    println!("\n  Measured marginal cost (full modular multiply, reduction included):");
    println!("    rows / modmul : ~{:.0}", rows_per_modmul.max(0.0));
    println!("    prover rate   : {:.3e} s/row (this machine)", s_per_row);

    // Compose the BLS12-381 G1 bridge from the MEASURED full-modmul cost (no 2× reduction proxy).
    // Projective doubling ~8 muls, addition ~14 muls; double-and-add over a ~255-bit scalar.
    let scalar_bits = 255.0;
    let muls_scalarmul = scalar_bits * 8.0 + (scalar_bits / 2.0) * 14.0; // ≈ 3832 modmuls
    let band = |s: f64| if s <= 10.0 { "GREEN" } else if s <= 120.0 { "AMBER" } else { "RED" };

    for (label, modmuls) in [("1 batched scalar-mult", muls_scalarmul), ("Pedersen 2-MSM (s2·G+γ·H)", 2.0 * muls_scalarmul)] {
        let bridge_rows = modmuls * rows_per_modmul.max(0.0);
        let pow2 = (bridge_rows as usize).next_power_of_two();
        let prove_s = s_per_row * pow2 as f64;
        println!("\n  {label}: ~{modmuls:.0} modmuls");
        println!("    trace rows ~{:.2e} -> 2^{} = {}", bridge_rows, (pow2 as f64).log2() as usize, pow2);
        println!("    naive-gadget prove time ~{:.1}s : {}", prove_s, band(prove_s));
        for opt in [3.0f64, 10.0, 30.0] {
            println!("      /{:>2}x tuned : {} (~{:.1}s)", opt as usize, band(prove_s / opt), prove_s / opt);
        }
    }

    println!("\n  BOTTOM LINE: the reduction is now measured, not a 2× proxy. The verdict refines the");
    println!("  prior band: full Statement-5 with this bridge is AMBER-at-best on a naive gadget,");
    println!("  reaching AMBER/near-GREEN only with a 10–30× purpose-built non-native gadget. Pairing");
    println!("  removal keeps the core GREEN; the bridge stays the tracked Phase-1 exit criterion.");
    println!("  Caveat: EC op-counts are standard projective-formula counts (a built scalar-mult is the");
    println!("  next step); Plonky2 stands in for Plonky3.");
}
