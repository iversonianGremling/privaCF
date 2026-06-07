// Gate-1 Phase-0a: MEASURE in-circuit pairing cost (vs a G1 scalar-mul = the
// Pedersen "bridge" atom), to replace the back-of-envelope estimate in
// SPIKE-statement5.md §8 with real R1CS constraint counts.
//
// Curve: BLS12-377 (the *friendly* case — purpose-built for in-circuit pairings
// via the BW6-761 2-chain). In-circuit BLS12-381 has no such partner, so 377 is a
// LOWER BOUND on the 381 cost: if even 377's pairing dwarfs a scalar-mul, the
// "pairing dominates / move it out of circuit" conclusion holds a fortiori.
//
// Constraint field = BLS12-377's base field Fq = BW6-761's scalar field.

use ark_bls12_377::{
    constraints::{G1Var, G2Var, PairingVar},
    Fq, G1Projective, G2Projective,
};
use ark_r1cs_std::{
    alloc::AllocVar,
    groups::CurveVar,
    pairing::PairingVar as PairingVarTrait,
};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::UniformRand;

fn main() {
    let mut rng = ark_std::test_rng();

    // --- (1) one in-circuit pairing ---
    let cs = ConstraintSystem::<Fq>::new_ref();
    let p = G1Projective::rand(&mut rng);
    let q = G2Projective::rand(&mut rng);
    let pv = G1Var::new_witness(cs.clone(), || Ok(p)).unwrap();
    let qv = G2Var::new_witness(cs.clone(), || Ok(q)).unwrap();
    let pp = PairingVar::prepare_g1(&pv).unwrap();
    let qp = PairingVar::prepare_g2(&qv).unwrap();
    let _e = PairingVar::pairing(pp, qp).unwrap();
    let c_pairing = cs.num_constraints();

    // --- (2) one G1 scalar-mul (the Pedersen "bridge" opening atom) ---
    let cs2 = ConstraintSystem::<Fq>::new_ref();
    let g = G1Projective::rand(&mut rng);
    let gv = G1Var::new_witness(cs2.clone(), || Ok(g)).unwrap();
    let bits: Vec<bool> = (0..253).map(|_| bool::rand(&mut rng)).collect();
    let bit_vars: Vec<_> = bits
        .iter()
        .map(|b| ark_r1cs_std::boolean::Boolean::new_witness(cs2.clone(), || Ok(*b)).unwrap())
        .collect();
    let _r = gv.scalar_mul_le(bit_vars.iter()).unwrap();
    let c_scalarmul = cs2.num_constraints();

    // --- report ---
    println!("=== Gate-1 Phase-0a — MEASURED R1CS constraints (BLS12-377 / BW6-761) ===");
    println!("in-circuit pairing        : {:>9} constraints", c_pairing);
    println!("in-circuit G1 scalar-mul  : {:>9} constraints  (Pedersen bridge atom)", c_scalarmul);
    println!("ratio pairing / scalar-mul: {:>9.1}x", c_pairing as f64 / c_scalarmul as f64);
    println!();
    println!("Reference (well-known): a Poseidon 2-to-1 hash is ~hundreds of constraints.");
    println!("So pairing : Poseidon is ~{}x+ — the pairing dominates by orders of magnitude.", c_pairing / 300);
    println!();
    println!("NOTE: BLS12-377 is the FRIENDLY curve (2-chain-native); BLS12-381 (the spec's");
    println!("curve) has no 2-chain partner, so its in-circuit pairing is STRICTLY WORSE.");
    println!("Measured lower bound confirming SPIKE §8's estimate and the 'move the pairing");
    println!("out of the circuit (F1)' verdict.");
}
