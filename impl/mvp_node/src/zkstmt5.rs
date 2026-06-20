//! **Statement 5 (SPEC §4.9.5) — the forward-secrecy rejoin keystone**, in real ZK.
//!
//! When a node re-admits under a fresh epoch identity it must prove, *without revealing which node
//! it is*, that its permanent nullifier `null_v` is **not** in the SUSP_SMT (the suspended set). A
//! suspended dark node cannot produce this proof; an honest one can. This is the privacy-preserving
//! half of the suspension machinery — the public half (verdict → threshold-decrypt → extract `null_v`
//! → fold into SUSP_SMT) is already live in `verdict.rs`/`smt.rs`; this closes the loop.
//!
//! ## The adopted *publish-`s₁`* form (no in-circuit pairing)
//!
//! The circuit proves, over Goldilocks Poseidon (the field `smt.rs` already commits in):
//!   1. `null_v = Poseidon(sk, "null_v")[0]`            — binds the secret to the nullifier (§4.2)
//!   2. `epoch_id = Poseidon(sk, beacon, null_v, "epoch")[0]` == the published pseudonym (§4.2)
//!   3. `s₁ + s₂ = null_v` with **`s₁` a public input** — the additive split the dark-node
//!      extraction (`verdict::extract_null_v`) inverts; publishing `s₁` removes the 2-of-2 pairing
//!      that was ≥99% of the old circuit (see `impl/spike_stmt5_proving`).
//!   4. SMT **non-membership**: a Poseidon Merkle path from the empty leaf `[0;4]` to the public
//!      SUSP root, with the path direction at each level bound to `null_v`'s bits — the exact layout
//!      `smt.rs` builds, so a node's native `Smt::prove(null_v)` siblings are the circuit witness.
//!
//! `sk`, `s₂` and `null_v` stay private; only `s₁`, `beacon`, `epoch_id` and the on-chain SUSP root
//! are public. So the proof reveals nothing linking the rejoiner to its suspended-or-not status
//! beyond "not suspended".
//!
//! ## What this module is and is NOT
//!
//! This is the **GREEN core** the `spike_stmt5_proving` benchmark measured (~30 ms prove at depth
//! 256; here depth 64). The one remaining term — the **VerEnc bridge** that would additionally bind
//! the on-chain ciphertext `d_T` to `s₂` *inside* the circuit — is the AMBER-at-best non-native
//! gadget (`spike_bridge_cost`: ~2²¹ rows, purpose-built ~5–40 s). Per the plan's decision gate it
//! stays a **validator-side check** for now (the committee verifies `d_T ↔ s₂` natively when it
//! extracts), not an in-circuit constraint. So this proof is sound for the *nullifier/non-membership*
//! statement; the `d_T` binding remains the documented Phase-1b residual.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};

use crate::field::{from_u64, to_u64, Fp};
use crate::hash::{DOM_EPOCH, DOM_NULL};
use crate::smt::SMT_DEPTH;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

/// The public statement a rejoin proof attests to: the published `s₁`, the round `beacon`, the
/// claimed pseudonym `epoch_id`, the on-chain `susp_root` against which non-membership holds, and the
/// joiner's `peer_id`. The `peer_id` is **committed as a circuit public input** so the proof is
/// non-transferable: a suspended node cannot replay an honest node's proof, because the gate checks
/// the committed `peer_id` equals the joining op's `peer_id`, and a committed proof's public inputs
/// cannot be swapped after the fact (FRI binds them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejoinPublic {
    pub s1: Fp,
    pub beacon: Fp,
    pub epoch_id: Fp,
    /// SUSP_SMT root in block-header form (4 canonical-`u64` LE limbs), exactly `Smt::root()`.
    pub susp_root: [u8; 32],
    /// The joining validator's stable id, bound into the proof (4 LE-`u64` limbs as public inputs).
    pub peer_id: [u8; 32],
}

/// The private witness: the node's secret `sk`, the additive share `s₂` (so `s₁ + s₂ = null_v`), and
/// the `SMT_DEPTH` sibling hashes of `null_v`'s empty-leaf path — i.e. `Smt::prove(null_v).siblings`.
pub struct RejoinWitness {
    pub sk: Fp,
    pub s2: Fp,
    pub siblings: Vec<[u8; 32]>,
}

/// A serialized Statement-5 proof (plonky2 `ProofWithPublicInputs` bytes). Self-describing; verified
/// against a freshly-rebuilt (deterministic) circuit.
pub type RejoinProof = Vec<u8>;

/// The wire form a joining node attaches to its `MembershipOp::Add` under the Statement-5 admission
/// gate. It carries only the scalars the gate cannot derive on its own — the reference height `h_ref`
/// (whose finalized SUSP root and beacon the gate looks up), the published split `s1`, the round
/// `beacon`, the claimed `epoch_id`, and the proof. The gate supplies `susp_root` (from block
/// `h_ref`) and `peer_id` (from the op) itself, so the joiner cannot lie about either: the proof must
/// verify against the *chain-derived* root and the *op's* identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejoinPackage {
    pub h_ref: u64,
    pub s1: u64,
    pub beacon: u64,
    pub epoch_id: u64,
    pub proof: RejoinProof,
}

impl RejoinPackage {
    /// Build a rejoin package for `sk`/`null_v` against the SUSP tree at reference height `h_ref`.
    /// `siblings` are the node's native `Smt::prove(null_v).siblings` for that tree; `susp_root` is
    /// that tree's root; `peer_id` is the joining identity. Returns `None` if the node is suspended
    /// (its `null_v` is in the tree, so non-membership cannot be proven).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        sk: Fp,
        s2: Fp,
        s1: Fp,
        beacon: Fp,
        epoch_id: Fp,
        susp_root: [u8; 32],
        peer_id: [u8; 32],
        h_ref: u64,
        siblings: Vec<[u8; 32]>,
    ) -> Option<Self> {
        let publ = RejoinPublic { s1, beacon, epoch_id, susp_root, peer_id };
        let wit = RejoinWitness { sk, s2, siblings };
        let proof = prove_rejoin(&wit, &publ)?;
        Some(Self { h_ref, s1: to_u64(s1), beacon: to_u64(beacon), epoch_id: to_u64(epoch_id), proof })
    }

    /// Verify this package against the chain-supplied `susp_root` (from block `h_ref`) and the op's
    /// `peer_id`. The caller separately enforces freshness (`h_ref` finalized, within the staleness
    /// window) and that `beacon` matches block `h_ref`'s beacon.
    pub fn verify(&self, susp_root: [u8; 32], peer_id: [u8; 32]) -> bool {
        let publ = RejoinPublic {
            s1: from_u64(self.s1),
            beacon: from_u64(self.beacon),
            epoch_id: from_u64(self.epoch_id),
            susp_root,
            peer_id,
        };
        verify_rejoin(&self.proof, &publ)
    }
}

/// 32-byte header root → the 4 Goldilocks limbs the circuit's public root target carries.
fn root_to_fields(root: &[u8; 32]) -> [F; 4] {
    let mut out = [F::ZERO; 4];
    for (i, e) in out.iter_mut().enumerate() {
        *e = from_u64(u64::from_le_bytes(root[i * 8..i * 8 + 8].try_into().expect("8 bytes")));
    }
    out
}

/// Handles into a built circuit, kept so the prover can assign the witness targets.
struct Circuit {
    data: CircuitData<F, C, D>,
    sk: Target,
    s2: Target,
    s1: Target,
    beacon: Target,
    epoch_id: Target,
    susp_root: HashOutTarget,
    peer_id: [Target; 4],
    siblings: Vec<HashOutTarget>,
}

/// Build the publish-`s₁` Statement-5 core circuit. Deterministic — prover and verifier rebuild the
/// identical circuit, so a proof is self-contained (no shared proving/verifying key to ship).
fn build() -> Circuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ---- private witnesses ----
    let sk = builder.add_virtual_target();
    let s2 = builder.add_virtual_target();
    let siblings: Vec<HashOutTarget> = (0..SMT_DEPTH).map(|_| builder.add_virtual_hash()).collect();

    // ---- public inputs: s₁, beacon, epoch_id, susp_root[4] ----
    let s1 = builder.add_virtual_target();
    builder.register_public_input(s1);
    let beacon = builder.add_virtual_target();
    builder.register_public_input(beacon);
    let epoch_id = builder.add_virtual_target();
    builder.register_public_input(epoch_id);
    let susp_root = builder.add_virtual_hash();
    builder.register_public_inputs(&susp_root.elements);
    // peer_id as 4 committed public limbs — binds the proof to the joining identity (anti-replay).
    let peer_id: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
    builder.register_public_inputs(&peer_id);

    // ---- (1) null_v = Poseidon(sk, DOM_NULL)[0] ----
    let dom_null = builder.constant(F::from_canonical_u64(DOM_NULL));
    let null_v = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sk, dom_null]).elements[0];

    // ---- (2) epoch_id = Poseidon(sk, beacon, null_v, DOM_EPOCH)[0] == public ----
    let dom_epoch = builder.constant(F::from_canonical_u64(DOM_EPOCH));
    let epoch_calc =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![sk, beacon, null_v, dom_epoch]).elements[0];
    builder.connect(epoch_calc, epoch_id);

    // ---- (3) additive split s₁ + s₂ = null_v ----
    let sum = builder.add(s1, s2);
    builder.connect(sum, null_v);

    // ---- (4) path bits = null_v's bit-decomposition (LSB at level 0, matching smt.rs) ----
    let nv_bits = builder.split_le(null_v, 64);

    // ---- (5) SMT non-membership: empty leaf [0;4] folded up to the public root ----
    let zero = builder.zero();
    let mut cur = HashOutTarget { elements: [zero; 4] };
    for lvl in 0..SMT_DEPTH {
        let sib = siblings[lvl];
        let bit = nv_bits[lvl];
        // smt.rs: current node is the RIGHT child iff bit==1 (sibling on the left).
        let mut left = [zero; 4];
        let mut right = [zero; 4];
        for k in 0..4 {
            left[k] = builder.select(bit, sib.elements[k], cur.elements[k]);
            right[k] = builder.select(bit, cur.elements[k], sib.elements[k]);
        }
        let mut inputs = Vec::with_capacity(8);
        inputs.extend_from_slice(&left);
        inputs.extend_from_slice(&right);
        cur = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    }
    builder.connect_hashes(cur, susp_root);

    let data = builder.build::<C>();
    Circuit { data, sk, s2, s1, beacon, epoch_id, susp_root, peer_id, siblings }
}

/// Prove Statement 5: the holder of `w.sk` — whose published `(s₁, epoch_id)` corresponds to
/// `null_v` — is NOT in the SUSP_SMT rooted at `p.susp_root`. Returns `None` if the witness is
/// inconsistent (wrong siblings, a present leaf, `s₁ + s₂ ≠ null_v`) so the circuit cannot be
/// satisfied. Reveals nothing about `sk`, `s₂` or `null_v`.
pub fn prove_rejoin(w: &RejoinWitness, p: &RejoinPublic) -> Option<RejoinProof> {
    if w.siblings.len() != SMT_DEPTH {
        return None;
    }
    let null_v = crate::hash::poseidon_scalar(&[w.sk, from_u64(DOM_NULL)]);
    let nv_u = to_u64(null_v);

    // Native pre-checks so a non-satisfiable witness returns `None` rather than panicking inside
    // plonky2's witness generation: (a) `s₁ + s₂ = null_v`, and (b) the siblings genuinely prove
    // `null_v`'s NON-membership against `susp_root` (an empty-leaf path reaching the root). A
    // suspended node only has a *present*-leaf path, so (b) fails and it cannot prove — exactly the
    // forward-secrecy guarantee.
    if crate::field::add_mod(p.s1, w.s2) != null_v {
        return None;
    }
    let non_member = crate::smt::SmtProof { key: nv_u, siblings: w.siblings.clone(), present: false };
    if !crate::smt::verify(&p.susp_root, &non_member) {
        return None;
    }

    let c = build();
    let mut pw = PartialWitness::new();

    pw.set_target(c.sk, w.sk);
    pw.set_target(c.s2, w.s2);
    pw.set_target(c.s1, p.s1);
    pw.set_target(c.beacon, p.beacon);
    pw.set_target(c.epoch_id, p.epoch_id);
    pw.set_hash_target(c.susp_root, HashOut { elements: root_to_fields(&p.susp_root) });
    let pid = root_to_fields(&p.peer_id);
    for (t, v) in c.peer_id.iter().zip(pid.iter()) {
        pw.set_target(*t, *v);
    }

    for (lvl, sib_t) in c.siblings.iter().enumerate() {
        let sib = root_to_fields(&w.siblings[lvl]);
        pw.set_hash_target(*sib_t, HashOut { elements: sib });
    }
    c.data.prove(pw).ok().map(|proof| proof.to_bytes())
}

/// Verify a Statement-5 proof against the public statement. Rebuilds the deterministic circuit,
/// checks the proof's public inputs equal `(s₁, beacon, epoch_id, susp_root)`, then verifies. A
/// suspended node's `null_v` IS in the tree, so no empty-leaf path reaches the root — its proof
/// cannot exist; a forged-public-input proof is rejected by the public-input equality check.
pub fn verify_rejoin(proof: &RejoinProof, p: &RejoinPublic) -> bool {
    let c = build();
    let pi = match ProofWithPublicInputs::<F, C, D>::from_bytes(proof.clone(), &c.data.common) {
        Ok(pi) => pi,
        Err(_) => return false,
    };
    // Public-input layout: [s1, beacon, epoch_id, susp_root[4], peer_id[4]].
    let mut expected = vec![p.s1, p.beacon, p.epoch_id];
    expected.extend_from_slice(&root_to_fields(&p.susp_root));
    expected.extend_from_slice(&root_to_fields(&p.peer_id));
    if pi.public_inputs != expected {
        return false;
    }
    c.data.verify(pi).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{add_mod, sub_mod};
    use crate::hash::poseidon_scalar;
    use crate::identity::NodeIdentity;
    use crate::smt::Smt;

    /// Build the public statement + witness for `id` rejoining against the suspension tree `susp`.
    fn statement(id: &NodeIdentity, beacon: Fp, susp: &Smt) -> (RejoinPublic, RejoinWitness) {
        let null_v = id.null_v;
        let nv_u = to_u64(null_v);
        // An honest additive split: pick s₁ public, s₂ = null_v − s₁ (the protocol publishes s₁ and
        // seals s₂; here we just need a consistent pair).
        let s1 = from_u64(0x0011_2233_4455_6677);
        let s2 = sub_mod(null_v, s1);
        let epoch_id = id.epoch_id(beacon);
        let proof = susp.prove(nv_u);
        let publ =
            RejoinPublic { s1, beacon, epoch_id, susp_root: susp.root(), peer_id: id.peer_id() };
        let wit = RejoinWitness { sk: id.sk, s2, siblings: proof.siblings };
        (publ, wit)
    }

    #[test]
    fn an_unsuspended_node_proves_non_membership_in_zk() {
        let id = NodeIdentity::from_seed(7);
        let beacon = from_u64(0xfeed_face);
        // A suspension tree holding some OTHER nullifiers — not this node's.
        let mut susp = Smt::new();
        susp.insert(0x1111);
        susp.insert(to_u64(NodeIdentity::from_seed(99).null_v));
        let (publ, wit) = statement(&id, beacon, &susp);

        let proof = prove_rejoin(&wit, &publ).expect("honest non-membership must prove");
        assert!(verify_rejoin(&proof, &publ), "the proof verifies against the on-chain SUSP root");
    }

    #[test]
    fn the_in_circuit_root_equals_the_native_smt_root() {
        // The circuit's public root must be exactly Smt::root() — otherwise a node's native
        // non-membership siblings would not satisfy the circuit.
        let id = NodeIdentity::from_seed(3);
        let beacon = from_u64(123);
        let susp = Smt::from_keys(&[5, 9, 4242]);
        let (publ, wit) = statement(&id, beacon, &susp);
        let proof = prove_rejoin(&wit, &publ).expect("prove");
        // Verifying with the genuine native root succeeds; with any other root it must fail.
        assert!(verify_rejoin(&proof, &publ));
        let mut wrong = publ.clone();
        wrong.susp_root = Smt::from_keys(&[5, 9]).root();
        assert!(!verify_rejoin(&proof, &wrong), "a proof does not verify against a different root");
    }

    #[test]
    fn a_suspended_node_cannot_prove_non_membership() {
        // The node's own null_v is folded into the suspension tree → no empty-leaf path reaches the
        // root, so the circuit is unsatisfiable and proving fails.
        let id = NodeIdentity::from_seed(11);
        let beacon = from_u64(77);
        let mut susp = Smt::new();
        susp.insert(to_u64(id.null_v)); // SUSPEND this node
        let (publ, wit) = statement(&id, beacon, &susp);
        assert!(prove_rejoin(&wit, &publ).is_none(), "a suspended null_v cannot prove non-membership");
    }

    #[test]
    fn an_inconsistent_split_is_rejected() {
        let id = NodeIdentity::from_seed(5);
        let beacon = from_u64(1);
        let susp = Smt::from_keys(&[1, 2, 3]);
        let (publ, mut wit) = statement(&id, beacon, &susp);
        // Break s₁ + s₂ = null_v.
        wit.s2 = add_mod(wit.s2, from_u64(1));
        assert!(prove_rejoin(&wit, &publ).is_none(), "s₁ + s₂ ≠ null_v must not prove");
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_nodes_statement() {
        // Node A's proof must not verify under node B's public statement (different epoch_id/s1).
        let beacon = from_u64(555);
        let susp = Smt::from_keys(&[10, 20, 30]);
        let a = NodeIdentity::from_seed(1);
        let b = NodeIdentity::from_seed(2);
        let (pub_a, wit_a) = statement(&a, beacon, &susp);
        let (pub_b, _wit_b) = statement(&b, beacon, &susp);
        let proof = prove_rejoin(&wit_a, &pub_a).expect("prove");
        assert!(verify_rejoin(&proof, &pub_a));
        assert!(!verify_rejoin(&proof, &pub_b), "A's proof must not satisfy B's public statement");
        // Sanity: the epoch_ids genuinely differ (so the statements are distinct).
        assert_ne!(pub_a.epoch_id, pub_b.epoch_id);
        let _ = poseidon_scalar(&[a.sk, from_u64(DOM_NULL)]);
    }

    #[test]
    fn a_proof_is_bound_to_its_peer_id_and_cannot_be_replayed() {
        // Anti-replay: an honest node A proves non-membership; a (would-be) suspended node B grabs
        // A's package and presents it under B's own peer_id. The committed peer_id is A's, so the
        // gate's check against B's peer_id fails — B gains nothing from the replay.
        let beacon = from_u64(99);
        let susp = Smt::from_keys(&[100, 200]);
        let a = NodeIdentity::from_seed(8);
        let (pub_a, wit_a) = statement(&a, beacon, &susp);
        let pkg = RejoinPackage::build(
            wit_a.sk,
            wit_a.s2,
            pub_a.s1,
            beacon,
            pub_a.epoch_id,
            pub_a.susp_root,
            a.peer_id(),
            5,
            wit_a.siblings.clone(),
        )
        .expect("honest package builds");
        // Verifying against A's own peer_id succeeds; against any other peer_id it fails.
        assert!(pkg.verify(pub_a.susp_root, a.peer_id()), "A's package verifies under A's peer_id");
        let b = NodeIdentity::from_seed(9);
        assert!(
            !pkg.verify(pub_a.susp_root, b.peer_id()),
            "A's package must NOT verify under B's peer_id — the proof is identity-bound"
        );
    }
}
