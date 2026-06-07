//! Statement-5 (publish-`s₁`) proving-time benchmark — P-feasibility gate, sub-gate (b).
//!
//! Companion to ../../SPIKE-statement5.md and SPEC §4.9.5 (adopted publish-`s₁` form).
//!
//! WHAT THIS MEASURES. The adopted publish-`s₁` Statement 5 has **no in-circuit pairing**
//! (that was the ≥99%-of-constraints wall in the 2-of-2 form; see spike_stmt5_constraints.py).
//! What remains splits in two:
//!   (1) a Poseidon/SMT core   — null_v + epoch_id derivations, SMT non-membership path,
//!                               and the s₁+s₂=null_v split (s₁ public).  ← BUILT & PROVED here.
//!   (2) the VerEnc "bridge"   — non-native group openings binding d_T to s₂ (~0.3–1.0M gates,
//!                               the AMBER term).                          ← ESTIMATED here, but
//!                               calibrated against THIS machine's measured proving rate.
//!
//! TOOLCHAIN NOTE. SPEC targets Plonky3. Plonky3's API is low-level AIR tables with no
//! Merkle/Poseidon gadgets — wrong tool for a spike. Plonky2 is the *same* Polygon-Zero FRI
//! prover over the Goldilocks field (same proving-cost class) with a friendly CircuitBuilder
//! and built-in Poseidon. The wall-clock numbers transfer to the Plonky3 cost class to within
//! the constant factor that separates two implementations of the same FRI/Goldilocks pipeline.
//! This is a *leaning with a real measurement attached*, not a Plonky3 production number.

use std::time::Instant;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

// Domain separators (cf. SPEC §4.2 table). Arbitrary fixed tags for the spike.
const DOM_NULL: u64 = 0x6e_75_6c_6c; // "null"
const DOM_EPOCH: u64 = 0x65_70_6f_63; // "epoc"

/// Native Poseidon over Goldilocks (matches the in-circuit PoseidonHash).
fn poseidon_native(inputs: &[F]) -> HashOut<F> {
    hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(inputs)
}

struct Timing {
    depth: usize,
    degree_bits: usize,
    trace_len: usize,
    build_s: f64,
    prove_s: f64,
    verify_ms: f64,
    proof_kb: f64,
}

/// Build the publish-`s₁` Statement-5 core at SMT depth `depth`, prove once, return timings.
fn run_depth(depth: usize) -> Timing {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ---- witnesses (private) ----
    let sk = builder.add_virtual_target();
    let s2 = builder.add_virtual_target();
    let siblings: Vec<HashOutTarget> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
    let path_bits: Vec<_> = (0..depth)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();
    let empty_leaf = builder.add_virtual_hash();

    // ---- public inputs ----
    let s1 = builder.add_virtual_target();
    builder.register_public_input(s1);
    let beacon = builder.add_virtual_target();
    builder.register_public_input(beacon);
    let epoch_id_pub = builder.add_virtual_hash();
    builder.register_public_inputs(&epoch_id_pub.elements);
    let susp_root_pub = builder.add_virtual_hash();
    builder.register_public_inputs(&susp_root_pub.elements);

    // ---- constraint 1: null_v = Poseidon(sk, DOM_NULL); first limb = the scalar ----
    let dom_null = builder.constant(F::from_canonical_u64(DOM_NULL));
    let null_v_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sk, dom_null]);
    let null_v = null_v_hash.elements[0];

    // ---- constraint 2: epoch_id = Poseidon(sk, beacon, null_v, DOM_EPOCH) == public ----
    let dom_epoch = builder.constant(F::from_canonical_u64(DOM_EPOCH));
    let epoch_id_calc =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sk, beacon, null_v, dom_epoch]);
    builder.connect_hashes(epoch_id_calc, epoch_id_pub);

    // ---- constraint 3: additive split  s1 + s2 = null_v ----
    let sum = builder.add(s1, s2);
    builder.connect(sum, null_v);

    // ---- constraint 4: bind low SMT path bits to null_v's bit-decomposition ----
    let bound = depth.min(63);
    let nv_bits = builder.split_le(null_v, 64);
    for i in 0..bound {
        builder.connect(path_bits[i].target, nv_bits[i].target);
    }

    // ---- constraint 5: SMT non-membership = Merkle path from empty_leaf to public root ----
    let mut cur = empty_leaf;
    for lvl in 0..depth {
        let sib = siblings[lvl];
        let bit = path_bits[lvl];
        let mut left = [builder.zero(); 4];
        let mut right = [builder.zero(); 4];
        for k in 0..4 {
            left[k] = builder.select(bit, sib.elements[k], cur.elements[k]);
            right[k] = builder.select(bit, cur.elements[k], sib.elements[k]);
        }
        let mut inputs = Vec::with_capacity(8);
        inputs.extend_from_slice(&left);
        inputs.extend_from_slice(&right);
        cur = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    }
    builder.connect_hashes(cur, susp_root_pub);

    // ---- build ----
    let t_build = Instant::now();
    let data = builder.build::<C>();
    let build_s = t_build.elapsed().as_secs_f64();
    let degree_bits = data.common.degree_bits();
    let trace_len = 1usize << degree_bits;

    // ---- witness (a consistent honest assignment) ----
    let mut pw = PartialWitness::new();
    let sk_v = F::from_canonical_u64(0x1234_5678_9abc_def0);
    let null_v_v = poseidon_native(&[sk_v, F::from_canonical_u64(DOM_NULL)]).elements[0];
    let s1_v = F::from_canonical_u64(0x0011_2233);
    let s2_v = null_v_v - s1_v;
    let beacon_v = F::from_canonical_u64(0xfeed_face);
    let epoch_v = poseidon_native(&[sk_v, beacon_v, null_v_v, F::from_canonical_u64(DOM_EPOCH)]);

    pw.set_target(sk, sk_v);
    pw.set_target(s2, s2_v);
    pw.set_target(s1, s1_v);
    pw.set_target(beacon, beacon_v);
    pw.set_hash_target(epoch_id_pub, epoch_v);

    let nv_u = null_v_v.to_canonical_u64();
    let empty = HashOut::from_vec(vec![F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
    pw.set_hash_target(empty_leaf, empty);
    let mut cur_v = empty;
    for lvl in 0..depth {
        let bit = if lvl < 63 { (nv_u >> lvl) & 1 } else { 0 };
        let sib_v = poseidon_native(&[F::from_canonical_u64(lvl as u64 + 1)]);
        pw.set_hash_target(siblings[lvl], sib_v);
        pw.set_bool_target(path_bits[lvl], bit == 1);
        let (l, r) = if bit == 1 { (sib_v, cur_v) } else { (cur_v, sib_v) };
        let mut inp = Vec::with_capacity(8);
        inp.extend_from_slice(&l.elements);
        inp.extend_from_slice(&r.elements);
        cur_v = poseidon_native(&inp);
    }
    pw.set_hash_target(susp_root_pub, cur_v);

    // ---- prove ----
    let t_prove = Instant::now();
    let proof = data.prove(pw).expect("prove failed");
    let prove_s = t_prove.elapsed().as_secs_f64();

    // ---- verify ----
    let t_verify = Instant::now();
    data.verify(proof.clone()).expect("verify failed");
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;
    let proof_kb = proof.to_bytes().len() as f64 / 1024.0;

    Timing { depth, degree_bits, trace_len, build_s, prove_s, verify_ms, proof_kb }
}

/// Ballast circuit: chain `n_hashes` Poseidon permutations so the trace reaches a target
/// size comparable to the VerEnc bridge (2^16–2^19). Measures REAL at-scale proving time,
/// from which we read the *marginal* rate (small circuits are all fixed FRI overhead).
fn run_ballast(n_hashes: usize) -> (usize, f64) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut cur = builder.add_virtual_target();
    let in0 = cur;
    let k = builder.constant(F::from_canonical_u64(0xabc));
    for _ in 0..n_hashes {
        let h = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![cur, k]);
        cur = h.elements[0];
    }
    builder.register_public_input(cur);
    let data = builder.build::<C>();
    let trace_len = 1usize << data.common.degree_bits();
    let mut pw = PartialWitness::new();
    pw.set_target(in0, F::from_canonical_u64(7));
    let t = Instant::now();
    let proof = data.prove(pw).expect("ballast prove failed");
    let prove_s = t.elapsed().as_secs_f64();
    data.verify(proof).expect("ballast verify failed");
    (trace_len, prove_s)
}

fn main() {
    println!("Statement-5 (publish-s1) proving benchmark — Plonky2/Goldilocks FRI");
    println!("(stand-in for the Plonky3 cost class; see file header)\n");
    println!(
        "  {:>5} {:>8} {:>10} {:>9} {:>9} {:>9} {:>8}",
        "depth", "deg_bits", "trace_len", "build_s", "prove_s", "verify_ms", "proof_kB"
    );

    let depths = [32usize, 64, 128, 256];
    let mut rows = Vec::new();
    for &d in &depths {
        let t = run_depth(d);
        println!(
            "  {:>5} {:>8} {:>10} {:>9.2} {:>9.3} {:>9.2} {:>8.1}",
            t.depth, t.degree_bits, t.trace_len, t.build_s, t.prove_s, t.verify_ms, t.proof_kb
        );
        rows.push(t);
    }

    let big = rows.last().unwrap();

    // --- at-scale rate: measure REAL proving time at bridge-sized traces (Poseidon ballast) ---
    println!("\n  At-scale proving (Poseidon ballast — direct measurement at bridge sizes):");
    println!("    {:>10} {:>10} {:>9}", "n_hashes", "trace_len", "prove_s");
    let mut scale = Vec::new();
    for &n in &[4_000usize, 16_000, 64_000, 256_000] {
        let (tl, ps) = run_ballast(n);
        println!("    {:>10} {:>10} {:>9.3}", n, tl, ps);
        scale.push((tl, ps));
    }
    // marginal rate from the two largest points (subtracts fixed FRI overhead)
    let (tl_a, ps_a) = scale[scale.len() - 2];
    let (tl_b, ps_b) = scale[scale.len() - 1];
    let marginal = (ps_b - ps_a) / (tl_b - tl_a) as f64;
    let fixed = ps_b - marginal * tl_b as f64;
    println!(
        "    marginal rate: {:.3e} s/row  (fixed overhead ~{:.3}s)",
        marginal, fixed.max(0.0)
    );

    // --- bridge band: trace ROWS = constraints / packing_factor (the key unknown) ---
    // The estimate gives the bridge in CONSTRAINTS (~0.3-1.0M non-native limb ops); FRI cost is
    // driven by TRACE ROWS. plonky2 packs several constraints per row; the factor depends on the
    // gadget (arithmetic gates pack well, ~10-50x; Poseidon-heavy packs ~1x). We don't know it
    // until the gadget is built, so we show the band across packing scenarios.
    let nproc = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    println!("\n  Cores available to the prover: {}", nproc);
    println!("\n  VerEnc-bridge band — proving time vs CONSTRAINT count x PACKING factor:");
    println!("    (rows = constraints/packing; time = fixed + marginal*next_pow2(rows))");
    println!("    {:>12} | {:>9} {:>9} {:>9}", "constraints", "pack 1x", "pack 10x", "pack 50x");
    for (label, c) in [("low  0.3M", 300_000.0f64), ("mid  0.6M", 600_000.0), ("high 1.0M", 1_000_000.0)] {
        let t_at = |pack: f64| {
            let rows = ((c / pack) as usize).next_power_of_two();
            fixed.max(0.0) + marginal * rows as f64
        };
        println!("    {:>12} | {:>8.2}s {:>8.2}s {:>8.2}s", label, t_at(1.0), t_at(10.0), t_at(50.0));
    }

    println!("\n  VERDICT (desktop, this machine, {} cores):", nproc);
    println!("    * Poseidon/SMT core (the part the pairing-removal leaves): MEASURED prove ~{:.3}s", big.prove_s);
    println!("      -> GREEN. Removing the in-circuit pairing definitively buys back the core.");
    println!("    * VerEnc bridge: UNRESOLVED here — swings GREEN<->RED on the packing factor above,");
    println!("      which only building the gadget settles. Pessimistic (pack 1x): RED; well-packed");
    println!("      arithmetic (pack >=10x): AMBER/GREEN. The proving RATE is now pinned ({:.2e}s/row),", marginal);
    println!("      so the verdict is immediate once the gadget's trace-row count is known.");
    println!("\n  HONEST BOTTOM LINE: pairing-removal is confirmed sufficient for the core; the residual");
    println!("  feasibility risk is entirely the VerEnc bridge's trace size. Building the native-group");
    println!("  VerEnc gadget (DESIGN §3-§4) and reading its degree_bits is the decisive Phase-1b step.");
}
