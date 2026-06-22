# VerEnc bridge gadget — scope

Status of the one remaining cross-field term of Statement 5: **NOT DONE (Phase-1b residual,
AMBER-at-best by measurement).** Companion to
[`DESIGN-f1-verifiable-encryption.md`](./DESIGN-f1-verifiable-encryption.md) §5,
[`SPIKE-statement5.md`](./SPIKE-statement5.md) §10, and the measured cost crate
[`impl/spike_bridge_cost/`](./impl/spike_bridge_cost/). Source of truth for what's built:
[`impl/mvp_node/src/verenc.rs`](./impl/mvp_node/src/verenc.rs) and
[`impl/mvp_node/src/zkstmt5.rs`](./impl/mvp_node/src/zkstmt5.rs).

---

## 1. What the bridge is (one sentence)

A single zero-knowledge proof that the **`s₂` encrypted in the node's on-chain ciphertext `d_T`**
(BLS12-381 world) is the **same `s₂`** used inside the Statement-5 rejoin circuit
(Goldilocks/Poseidon world) to prove `s₁ + s₂ = null_v ∉ SUSP_SMT`. Concretely: **open a G₁
Pedersen commitment `C = s₂·G + γ·H` *inside* the small-field circuit** — a non-native BLS12-381 EC
scalar-mult. That cross-field link is the one piece that cheap native arithmetic can't do.

The Pedersen commitment `C` is the clean two-worlds link: the BLS-side sigma proves the encrypted
limbs reconstruct `C`'s value (a linear Schnorr relation), and the circuit **opens `C`** — so both
proofs reference the same `C` and therefore the same `s₂`.

---

## 2. What is already DONE ✅

The bridge does not start from zero — both endpoints it must connect already exist and are wired.

- ✅ **VerEnc** — `verenc.rs::{encrypt, decrypt}`. Real exponential-ElGamal `d_T` over BLS12-381,
  decryptable by the verdict threshold signature `σ_VERDICT`. Wired + tested (`dark_node.rs`).
- ✅ **BLS-native well-formedness proof** — `verenc.rs::{prove_wellformed, verify_wellformed}`,
  DESIGN R1–R3. Per-16-bit-limb Chaum–Pedersen OR-range proof + a generalized Schnorr linking
  `(mⱼ, t, ρⱼ)`, proving `d_T` is a genuine encryption of a **known, in-range** `s₂`. Fully
  BLS12-381-native (no field emulation). Validators verify it from public `VA_pub`/`id`/`d_T` alone.
  ~52 ms prove / ~44 ms verify / ~19 KB. 6 unit tests + `tests/verenc_proof.rs` in-loop
  (`Node::with_verenc_proof()`).
  - **Closes:** the openability hole — an un-openable or out-of-range `d_T` can no longer escape
    suspension.
  - **Does NOT close:** that the recovered `s₂` is the one satisfying `s₁ + s₂ = null_v` for the
    node's *real* nullifier (a hidden value in the Goldilocks/Poseidon world). ← **the bridge.**
- ✅ **Statement-5 core circuit** — `zkstmt5.rs`, plonky2/Goldilocks. Proves, with `sk`, `s₂`,
  `null_v` private and `s₁`, `beacon`, `epoch_id`, SUSP-root public:
  1. `null_v = Poseidon(sk, "null_v")`
  2. `epoch_id = Poseidon(sk, beacon, null_v, "epoch")` matches the published pseudonym
  3. `s₁ + s₂ = null_v`, **`s₁` a public input** (this is what removed the in-circuit pairing)
  4. SMT **non-membership** of `null_v` vs the on-chain SUSP root (depth-64, the exact `smt.rs`
     layout, so a node's native `Smt::prove(null_v).siblings` are the witness)

  ~tens of ms (GREEN). `peer_id` committed as a public input (FRI-bound anti-replay), wired in-loop
  as the rejoin admission gate (`Node::with_stmt5_admission()`, `tests/stmt5_admission.rs`).

So: the encryption, the well-formedness proof, the nullifier/non-membership circuit, and the `C`
that links them are all in place. The bridge is the missing constraint that ties `C` into the
circuit.

---

## 3. What is NOT DONE yet ❌

Everything in this section is unbuilt. This is the actual gadget project.

- ❌ **(a) The non-native EC gadget — the hard core.** An in-circuit BLS12-381 G₁ scalar-mult /
  2-MSM (`s₂·G + γ·H`) over Goldilocks. Sub-pieces, none assembled:
  - Non-native BLS12-381 `Fp` (~381-bit) arithmetic on 16-bit limbs: multiply (the spike
    **measured** one at ~256 rows), add, and **modular reduction** (CRT / Barrett / Montgomery —
    the spike accounted reduction as a flat 2× factor and did **not** build it).
  - EC point ops (Jacobian doubling ≈8 muls, addition ≈14 muls) — only op-counted, not assembled.
  - Full **double-and-add scalar-mult** over a ~255-bit scalar — not assembled.
- ❌ **(b) Circuit integration.** Wire the gadget into `zkstmt5`'s circuit so the opening constraint
  binds the circuit's private `s₂` (Goldilocks) to the `s₂` committed in `C` (BLS), preserving the
  deterministic prover==verifier circuit rebuild (no shared proving/verifying key to ship).
- ❌ **(c) The gadget optimization pass.** Naive cost is **RED**; reaching AMBER needs a
  purpose-built gadget — dedicated range-check gates, Karatsuba multiply, CRT reduction, an
  arithmetic-tuned (non-recursion) plonky2 config. **This is where the feasibility risk lives.**
- ❌ **(d) Tooling.** `plonky2_ecdsa` / `plonky2_u32` (the off-the-shelf non-native libs) are pinned
  to **abandoned plonky2 0.1.1 and do not compile** against any consistent toolchain
  (`itertools`/`hashbrown`/`WitnessGenerator` API skew). So the gadget must be **hand-built on
  plonky2 0.2** (as the spike's multiply was) or the stack migrated to plonky3. Real infra work, not
  a library call.
- ❌ **(e) Live-path integration + decision gate.** Per the plan: add a `zk_proof` field to
  `epoch.rs::EpochTransaction`, gate it GREEN/AMBER/RED, ship the larger/slower proof on the rejoin
  path, and decide whether to **remove** the current validator-side native `d_T↔s₂` check or keep it
  as defense-in-depth.

---

## 4. Measured reality — why it's "AMBER-at-best", not free

From [`impl/spike_bridge_cost/`](./impl/spike_bridge_cost/) (20-core desktop, 2026-06-16, real
provable plonky2 circuits with `degree_bits` read off — not modelled):

| Gadget | Rows | Time | Band |
|---|---|---|---|
| non-native field multiply (256/384-bit) | ~256 rows/mul (measured marginal) | — | primitive |
| BLS12-381 G₁ scalar-mult (~3,825 modmuls) | ~1.96 M → 2²¹ | **~130 s** | **RED** |
| Pedersen 2-MSM `s₂·G + γ·H` | ~3.9 M → 2²² | **~260 s** | **RED** |
| tuned gadget ÷10× | — | ~13 s | **AMBER** |
| tuned gadget ÷30× | — | ~4 s | GREEN (implausible) |

Removing the in-circuit pairing (the publish-`s₁` design) already bought back the **core
(GREEN, ~30 ms)**. The bridge is the **irreducible residual** — realistically a **~5–40 s prover**
after a purpose-built gadget. Sub-second/GREEN is not on the table; this updates DESIGN-f1 §5's
original "AMBER, sub-second to a few seconds" estimate, which was optimistic (it omitted the bridge,
then under-counted it).

Spike caveats (honest, none flip the conclusion): the limb *multiply* is measured but modular
reduction is a 2× accounting; EC op-counts are standard Jacobian formula counts, not a fully
assembled in-circuit scalar-mult; the gadget is deliberately naive (so the number is an **upper
bound**); plonky2 stands in for plonky3 (same FRI/Goldilocks cost class).

---

## 5. The security delta — what the bridge actually buys

- **Today (without the bridge):** the `d_T ↔ s₂` link is enforced by **validators checking
  natively** at verdict time — the committee decrypts `d_T`, extracts `null_v = s₁ + s₂`, and
  inserts it into SUSP_SMT. The rejoin S5 proof then shows `null_v ∉ SUSP`. The residual is a
  **trust assumption**: you trust that native validator check rather than a self-contained
  cryptographic artifact. (Openability — the more dangerous hole — is already closed in-circuit-free
  by the §2 well-formedness proof.)
- **With the bridge:** the rejoin proof becomes **fully untrusted-verifiable end-to-end** — one
  artifact binds "the ciphertext the suspension machinery decrypts" to "the nullifier I'm proving is
  unsuspended," with no validator-side native step in the trust path.

---

## 6. Effort, risk, recommendation

- **Effort:** a **multi-week ZK-engineering project**, not an increment. Dominated by (a) hand-building
  a non-native EC gadget on plonky2 0.2 and (c) the optimization pass to drag it RED→AMBER, with an
  uncertain landing. The surrounding plumbing (Pedersen commitment, circuit wiring, `zk_proof`
  field, decision gate) is comparatively small.
- **Risk:** the optimization is the gamble — the measurement says AMBER is *plausible* with a tuned
  gadget but not guaranteed; GREEN is implausible; there's a real chance it lands heavier than hoped.
- **Recommendation:** correctly parked as **Phase-1b**. The MVP is sound without it — the
  validator-side native check is a reasonable MVP trust assumption, and the dangerous hole
  (un-openable `d_T` escaping suspension) is already closed. **Do not start** unless a fully
  trustless rejoin path is a hard requirement.

### First concrete step if pursued (de-risk before committing)

A **focused gadget prototype**, ~1–2 days, before any integration:

1. On plonky2 0.2, hand-build the non-native BLS12-381 `Fp` **modular reduction** (the piece the
   spike accounted as 2× rather than building) and **one EC addition**.
2. Read off real `degree_bits` and compose the scalar-mult row count from measured (not modelled)
   primitives.
3. Confirm whether the ÷10× tuning band is reachable. **Only if it is** proceed to the full
   scalar-mult, circuit integration, and live-path wiring.

This converts the AMBER estimate from "plausible by extrapolation" to "measured" before sinking the
multi-week build cost.
