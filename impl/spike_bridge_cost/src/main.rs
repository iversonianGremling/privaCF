//! VerEnc "bridge" cost measurement — the one unresolved P-feasibility term.
//!
//! CONTEXT. The adopted publish-`s₁` Statement 5 (SPEC §4.9.5, DESIGN-f1 §7) removes the
//! in-circuit pairing. `spike_stmt5_proving` measured the Poseidon/SMT core (GREEN, ~30 ms) and
//! pinned the prover's at-scale RATE, but left the **two-worlds bridge** (DESIGN-f1 §5) as an
//! estimate: opening a `G₁` Pedersen commitment `C = s₂·G + γ·H` *inside* the small-field circuit
//! is non-native EC over BLS12-381 — DESIGN §5 puts it at ~0.2–0.4 M constraints (the AMBER term).
//! The previous spike could only band it across a *guessed* gate-packing factor (RED at 1×,
//! GREEN at ≥10×). This binary is the whole remaining feasibility risk.
//!
//! WHAT THIS DOES. It MEASURES the dominant primitive the bridge is built from — a non-native
//! modular **field multiplication** — as a real, provable Plonky2/Goldilocks circuit, reading its
//! true `degree_bits`/row count instead of guessing a packing factor. Then it composes the G₁
//! scalar-mult / Pedersen-MSM gate count on top of the measured per-mul cost, and multiplies by
//! the prover rate to give a desktop prove-time band for the bridge. This converts the bridge from
//! "estimate ÷ unknown packing" to "measured-mul × known-EC-op-count".
//!
//! FAITHFULNESS. Same Plonky2-stands-for-Plonky3 logic as the sibling spike (same FRI/Goldilocks
//! cost class; see its header). A non-native field is represented in 16-bit limbs (the largest that
//! keeps a limb*limb product + column accumulation safely below Goldilocks' ~2^64 modulus). The
//! measured unit is a range-checked schoolbook limb multiply; a full modular multiply is ~2 such
//! products (the `a*b` and the `q*p` of the reduction), stated explicitly where it enters the
//! composition rather than hidden in a constant.

use std::time::Instant;

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

/// Build one range-checked schoolbook limb multiply of two `n`-limb (16-bit/limb) integers.
/// Inputs are range-checked to 16 bits; the product is carry-propagated into 16-bit output limbs
/// (each range-checked by `split_le`). Returns the input limb targets so the witness can set them.
/// This is the provable, dominant core of a non-native multiply (the modular reduction adds a
/// second product of the same shape — accounted for in the composition, not here).
fn build_limb_mul(builder: &mut CircuitBuilder<F, D>, n: usize) -> (Vec<Target>, Vec<Target>) {
    let a: Vec<Target> = (0..n).map(|_| builder.add_virtual_target()).collect();
    let b: Vec<Target> = (0..n).map(|_| builder.add_virtual_target()).collect();

    // range-check every input limb to 16 bits
    for t in a.iter().chain(b.iter()) {
        let _ = builder.split_le(*t, LIMB_BITS);
    }

    // schoolbook columns: col[i+j] += a[i]*b[j]   (each product < 2^32, native Goldilocks mul)
    let ncols = 2 * n - 1;
    let mut col = vec![builder.zero(); ncols];
    for i in 0..n {
        for j in 0..n {
            let p = builder.mul(a[i], b[j]);
            col[i + j] = builder.add(col[i + j], p);
        }
    }

    // carry-propagate: t = col[k] + carry; out[k] = low 16 bits, carry = the rest.
    // col[k] <= n*2^32 <= 2^36 (n<=24); + carry (<2^24) => t < 2^37, split to 40 bits is safe.
    let mut carry = builder.zero();
    let mut out: Vec<Target> = Vec::with_capacity(ncols + 1);
    for k in 0..ncols {
        let t = builder.add(col[k], carry);
        let bits = builder.split_le(t, 40);
        let lo = builder.le_sum(bits[0..LIMB_BITS].iter());
        let hi = builder.le_sum(bits[LIMB_BITS..40].iter());
        out.push(lo);
        carry = hi;
    }
    out.push(carry);
    for o in &out {
        builder.register_public_input(*o);
    }
    (a, b)
}

struct Row {
    label: String,
    n_muls: usize,
    limbs: usize,
    degree_bits: usize,
    trace_len: usize,
    prove_s: f64,
}

/// Build `n_muls` independent `limbs`-limb multiplies, prove once, return timings.
fn run(label: &str, n_muls: usize, limbs: usize) -> Row {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut inputs = Vec::with_capacity(n_muls);
    for _ in 0..n_muls {
        inputs.push(build_limb_mul(&mut builder, limbs));
    }

    let data = builder.build::<C>();
    let degree_bits = data.common.degree_bits();
    let trace_len = 1usize << degree_bits;

    let mut pw = PartialWitness::new();
    // fixed-but-nontrivial 16-bit limb values
    for (a, b) in &inputs {
        for (idx, t) in a.iter().enumerate() {
            pw.set_target(*t, F::from_canonical_u64(((0x9e37 * (idx as u64 + 1)) & 0xffff) as u64));
        }
        for (idx, t) in b.iter().enumerate() {
            pw.set_target(*t, F::from_canonical_u64(((0x85eb * (idx as u64 + 3)) & 0xffff) as u64));
        }
    }

    let t = Instant::now();
    let proof = data.prove(pw).expect("prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    data.verify(proof).expect("verify failed");

    Row { label: label.to_string(), n_muls, limbs, degree_bits, trace_len, prove_s }
}

fn main() {
    println!("VerEnc-bridge cost — non-native field multiply, measured in Plonky2/Goldilocks FRI");
    println!("(stand-in for the Plonky3 cost class; 16-bit limbs; see file header)\n");
    println!(
        "  {:>14} {:>7} {:>7} {:>9} {:>10} {:>9}",
        "config", "n_muls", "limbs", "deg_bits", "trace_len", "prove_s"
    );

    // 256-bit modulus (secp256k1 / BLS12-381 Fr scale) = 16 limbs; sweep sizes for marginal rate.
    let mut rows = Vec::new();
    for &(lbl, n) in &[("256b x1", 1usize), ("256b x64", 64), ("256b x256", 256), ("256b x1024", 1024)] {
        let r = run(lbl, n, 16);
        println!(
            "  {:>14} {:>7} {:>7} {:>9} {:>10} {:>9.3}",
            r.label, r.n_muls, r.limbs, r.degree_bits, r.trace_len, r.prove_s
        );
        rows.push(r);
    }
    // 384-bit (BLS12-381 Fp / G1 coordinate field) = 24 limbs — measure at TWO sizes so the
    // 256->384 scaling is a real marginal, not a power-of-2-rounded single point.
    let mut rows384 = Vec::new();
    for &(lbl, n) in &[("384b x256", 256usize), ("384b x1024", 1024)] {
        let r = run(lbl, n, 24);
        println!(
            "  {:>14} {:>7} {:>7} {:>9} {:>10} {:>9.3}",
            r.label, r.n_muls, r.limbs, r.degree_bits, r.trace_len, r.prove_s
        );
        rows384.push(r);
    }

    // ---- marginal rows per multiply, from the two largest 256-bit points ----
    let a = &rows[rows.len() - 2];
    let b = &rows[rows.len() - 1];
    let rows_per_mul_256 = (b.trace_len as f64 - a.trace_len as f64) / (b.n_muls as f64 - a.n_muls as f64);
    let rows_per_mul_384 = (rows384[1].trace_len as f64 - rows384[0].trace_len as f64)
        / (rows384[1].n_muls as f64 - rows384[0].n_muls as f64);
    let s_per_row = (b.prove_s - a.prove_s) / (b.trace_len as f64 - a.trace_len as f64);

    println!("\n  Measured marginal cost:");
    println!("    256-bit limb-multiply : ~{:.0} trace rows/mul", rows_per_mul_256.max(0.0));
    println!("    384-bit limb-multiply : ~{:.0} trace rows/mul (marginal, two sizes)", rows_per_mul_384);
    println!("    prover rate           : {:.3e} s/row (this machine)", s_per_row.max(0.0));
    let scale_256_384 = rows_per_mul_384 / rows_per_mul_256.max(1.0);
    println!("    measured 256->384 scaling: {:.2}x  (schoolbook ~(24/16)^2 = 2.25x expected)", scale_256_384);

    // ---- compose: G1 scalar-mult and Pedersen 2-MSM gate count ----
    // Jacobian/projective EC ops (no per-step inversion):
    //   doubling   ~  8 field muls,   addition ~ 14 field muls   (standard formula counts)
    // Double-and-add over a ~255-bit scalar: 255 doublings + ~128 additions (avg Hamming wt).
    // A non-native MODULAR multiply ~= 2 schoolbook products (a*b and q*p) -> 2x the measured unit.
    let muls_per_double = 8.0;
    let muls_per_add = 14.0;
    let scalar_bits = 255.0;
    let avg_adds = scalar_bits / 2.0;
    let field_muls_scalarmul = scalar_bits * muls_per_double + avg_adds * muls_per_add;
    let modmul_factor = 2.0; // a*b and q*p
    // Pedersen C = s2*G + gamma*H : two scalar-mults (Strauss/Shamir would share doublings ~ -255 muls;
    // we keep the conservative independent-MSM count and note the optimization).
    let field_muls_pedersen = 2.0 * field_muls_scalarmul;

    let rows_per_modmul_384 = rows_per_mul_384 * modmul_factor;
    let bridge_rows = field_muls_pedersen * rows_per_modmul_384;
    let bridge_rows_pow2 = (bridge_rows as usize).next_power_of_two();
    let bridge_prove_s = s_per_row.max(0.0) * bridge_rows_pow2 as f64;

    // single-scalar-mult variant (if one batched Pedersen opening, DESIGN §5 optimization note)
    let bridge_rows_1sm = field_muls_scalarmul * rows_per_modmul_384;
    let bridge_rows_1sm_pow2 = (bridge_rows_1sm as usize).next_power_of_two();
    let bridge_prove_s_1sm = s_per_row.max(0.0) * bridge_rows_1sm_pow2 as f64;

    println!("\n  Composed BLS12-381 G1 bridge (384-bit field, modmul = 2x measured multiply):");
    println!("    field muls / scalar-mult      : ~{:.0}", field_muls_scalarmul);
    println!("    --- Pedersen 2-MSM (s2*G + gamma*H, conservative independent) ---");
    println!("    field muls                    : ~{:.0}", field_muls_pedersen);
    println!("    bridge trace rows             : ~{:.2e}  (-> 2^{} = {})",
             bridge_rows, (bridge_rows_pow2 as f64).log2() as usize, bridge_rows_pow2);
    println!("    bridge prove time             : ~{:.2} s", bridge_prove_s);
    println!("    --- single batched scalar-mult (DESIGN §5 optimization) ---");
    println!("    bridge trace rows             : ~{:.2e}  (-> 2^{} = {})",
             bridge_rows_1sm, (bridge_rows_1sm_pow2 as f64).log2() as usize, bridge_rows_1sm_pow2);
    println!("    bridge prove time             : ~{:.2} s", bridge_prove_s_1sm);

    let band = |s: f64| if s <= 10.0 { "GREEN" } else if s <= 120.0 { "AMBER" } else { "RED" };
    println!("\n  VERDICT (desktop, this machine):");
    println!("    Pedersen 2-MSM bridge (naive gadget) : {} (~{:.1}s)", band(bridge_prove_s), bridge_prove_s);
    println!("    1 batched scalar-mult (naive gadget) : {} (~{:.1}s)", band(bridge_prove_s_1sm), bridge_prove_s_1sm);

    // The measured gadget is deliberately NAIVE: a split_le range-check per carry column, on the
    // recursion-tuned standard config. A dedicated non-native gadget (u32 range-check gates,
    // Karatsuba, CRT reduction, arithmetic-tuned config) packs materially better. Show the band
    // an X-fold tuned gadget would reach, so the verdict spans naive -> well-optimized.
    println!("\n  Tuned-gadget projection (1 batched scalar-mult, optimism factor):");
    for opt in [3.0f64, 10.0, 30.0] {
        let s = bridge_prove_s_1sm / opt;
        println!("    /{:>2}x : {} (~{:.1}s)", opt as usize, band(s), s);
    }

    println!("\n  HONEST BOTTOM LINE:");
    println!("  The bridge is the WHOLE remaining feasibility risk, and it is heavier than DESIGN-f1 §5's");
    println!("  'AMBER, sub-second to a few seconds' estimate. A MEASURED non-native multiply is ~{:.0} rows;",
             rows_per_mul_256.max(0.0));
    println!("  the in-circuit BLS12-381 scalar-mult the bridge needs is ~{:.0} modular muls -> ~2^21 rows",
             field_muls_scalarmul);
    println!("  -> RED (~2 min) with this naive gadget. A 10-30x tuned gadget brings it to AMBER (~5-40s);");
    println!("  only an implausible >30x reaches GREEN. So: pairing-removal buys back the CORE (GREEN, other");
    println!("  spike), but the publish-s1 BRIDGE is AMBER-at-best and needs a purpose-built non-native");
    println!("  gadget in Phase 1 — it is NOT the near-free term the design doc currently implies.");
    println!("\n  Caveats: limb-multiply measured (modmul = 2x, stated); EC op-counts are standard");
    println!("  Jacobian formula counts, not a fully built scalar-mult; Plonky2 stands in for Plonky3.");
}
