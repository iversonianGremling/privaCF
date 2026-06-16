# Spike Plan — Statement 5 ZK Feasibility (the P-feasibility gate)

### First feasibility spike · go/no-go for the substrate build

> **Why this spike exists.** Every P1–P5 guarantee is contingent on the substrate being
> buildable (SECURITY.md "P-feasibility"). The single highest-risk unknown is whether the
> per-epoch handoff ZK proof — dominated by **Statement 5** (§4.9.5) — can be generated within a
> node's per-epoch compute budget. A bad answer here does **not** mean "tune a parameter"; it
> means **restructure the design** (the ForwardCommit certification, `N_fallback`, the SMT, or
> the proof system). So this is sequenced *before* any Layer-1–4 build, and it is a narrow spike
> — build only the circuit, measure, decide. It is the desktop half of OQ-3 / OQ-33.

---

## 1. The circuit under test

Statement 5 (§4.9.5), proven each epoch at handoff with `null_v`, `sk`, `s₁`, `s₂`, and the
SMT path as **private** witnesses:

```
(a) null_v      = Poseidon(sk, "null_v")
(b) epoch_id_T  = Poseidon(sk, beacon_T, null_v, "epoch_id")
(c) null_v ∉ SUSP_SMT_root_T                                   ← SMT non-membership, null_v private
(d) s₁ + s₂ = null_v   (mod p)
(e) ∀ i ∈ {0..N_fallback−1}:
        c_T^{(i)} = ForwardCommit(s₁, "SUSPEND epoch_id_T",  threshold_BLS_pk_T^{(i)}; r_i)
(f) d_T          = ForwardCommit(s₂, "VERDICT_FINALIZED epoch_id_T", VA_pub;        r_d)
```

Cost annotation (what actually drives proving time):

| Sub-component | Count | Cost class | Risk |
|---|---|---|---|
| (a),(b) Poseidon evals | 2 | ~hundreds of constraints each | low |
| (c) SMT non-membership path | tree-depth `D` Poseidon hashes | `D ×` 2-to-1 Poseidon | **medium** (scales with `D`) |
| (d) field addition | 1 | trivial | none |
| (e),(f) ForwardCommit certification | `N_fallback + 1` | **in-circuit BLS12-381 pairing each** | **HIGH — prime suspect** |

The spec already concedes (e)/(f) is "a pairing check per committee slot" (§4.9.5). **In-circuit
pairings over BLS12-381 inside a Plonky3 circuit (small field: Goldilocks/BabyBear) are
non-native field arithmetic and blow up the constraint count.** That is the single thing most
likely to fail this gate. Benchmark it *first and in isolation* (Phase 0 below) — don't build
the whole circuit only to discover the pairing was the wall.

---

## 2. Two prime suspects — isolate them before assembling

**Suspect 1 — in-circuit ForwardCommit pairing (e/f).** BF-IBE `Encrypt` computes
`e(H(id), pk)^r`; certifying the ciphertext was formed correctly with the committed plaintext
means evaluating that pairing inside the proof. Pairings are not native in any SNARK; over a
mismatched field they are catastrophic. **If one in-circuit pairing is on the order of millions
of constraints, then `(N_fallback+1) ×` that is the design-breaker.**

**Suspect 2 — SMT non-membership depth (c).** A sparse Merkle tree keyed on `null_v` has a path
of length = key bit-length (~256 for a naïve SMT). Each level is a Poseidon hash. 256 Poseidon
hashes is heavy but bounded; a compacted/Jellyfish SMT shortens the *effective* path to ~the log
of the number of *occupied* leaves, which is tiny early on but grows with suspensions (this is
OQ-47, SUSP_SMT proof latency vs. tree population).

---

## 3. Build phases (minimal — circuit only, no networking, no chain)

**Phase 0 — isolate the cost drivers (do this first; it can end the spike early).**
- **0a.** Benchmark *one* in-circuit ForwardCommit/BF-IBE encryption-formation check. Measure
  constraints, proof-gen time, RAM. **This is the make-or-break number.** If it's already
  intractable here, stop and go to §5 RED before building anything else.
- **0b.** Benchmark SMT non-membership at depths `D ∈ {16, 32, 64, 128, 256}` (and, if using a
  compacted SMT, at occupied-leaf counts `{10³, 10⁴, 10⁵, 10⁶}`). Get the depth/latency curve.

**Phase 1 — assemble full Statement 5** at `N_fallback = 3` (the v1 default): (a)+(b)+(c)+(d)
+(e×3)+(f). Measure end-to-end. Re-run at `N_fallback ∈ {1, 3, 5}` to confirm the linear-in-N
claim and locate where N pushes past the budget.

**Phase 2 — full handoff proof** (the honest per-epoch cost): Statements 1+2+3+5 together.
Statement 2 (directional consistency, inner-product over preference dimension `d`) is the *other*
unbenchmarked piece (OQ-3b) — measure at `d ∈ {128, 256}`. Statements 1 and 3 are range/vector
proofs and should be cheap; confirm.

---

## 4. What to measure (every run)

- **Constraint / trace count** (leading indicator — predicts mobile feasibility before you even
  time it).
- **Proof-generation wall-clock**: single desktop core *and* all-cores (Plonky3 parallelizes).
- **Peak prover RAM** (the other mobile-killer; record even though mobile is out of scope here).
- **Proof size** and **verification time** (expected cheap; confirm).
- Report each as a table across the swept parameter (`D`, `N_fallback`, `d`).

Hardware: a defined modern desktop (record exact CPU/RAM). This is the *desktop* gate; mobile
numbers are **collected as data only, not gated** (§9.1 Mobile policy).

---

## 5. Pass/fail — the go/no-go decision

The binding real-world constraint is generous (epoch = 2–3 h, §4.1), so the proof has hours of
headroom; the gate is really about leaving room for everything else and keeping a path to mobile.
Thresholds on the **full handoff proof, desktop all-cores**:

| Tier | Full-handoff proof-gen | Statement-5 constraints | Decision |
|---|---|---|---|
| **GREEN** | ≤ 10 s | ≤ ~few M | Proceed to substrate build; mobile plausible (run OQ-3 mobile next). |
| **AMBER** | 10 s – 2 min | few M – ~20 M | Proceed on **desktop-first** deployment; defer mobile; open a circuit-optimization task. |
| **RED** | > 2 min, **or** Phase-0a pairing alone > ~tens of M constraints / minutes | — | **Design change before building.** See decision tree. |

**RED decision tree (what to change, in order of preference):**
1. **Move the pairing out of the circuit.** Restructure (e)/(f) so the ZK proof binds `s₁`/`s₂`
   to `null_v` and to the *committed* ciphertext via a hash/commitment, and check
   encryption-correctness with a separate non-ZK consistency mechanism (validators already run
   `ForwardCommit.Verify` at reveal time, §4.9.6). This removes the in-circuit pairing entirely
   and is the most likely fix.
2. **Cut `N_fallback`** (3 → 1–2): fewer pairing checks, at the cost of the liveness margin the
   fallback slots buy (§4.9.6). A calibration retreat, not a redesign.
3. **Swap proof system for the pairing part** — a hybrid (Plonky3 for Poseidon/SMT over its
   small field; a pairing-friendly SNARK, e.g. a Groth16/PLONK recursion, for the BF-IBE
   binding). Heavier engineering; only if (1) and (2) are insufficient.
4. **Shorten the SMT** (compacted/Jellyfish SMT, or a bounded-depth accumulator) if Phase-0b
   shows (c) — not the pairing — is the dominant term.

The key output is not a single pass/fail bit but **which term dominates** — that's what tells you
whether the design as specified survives or which of the four changes above to make.

---

## 6. Stack and the load-bearing assumption to test

- **Proof system:** Plonky3 (spec mandate, Appendix E). Poseidon over its native field is the
  cheap, intended case. **The assumption this spike actually tests is that Statement 5 *as
  specified* — with in-circuit ForwardCommit certification — is provable in Plonky3 at a
  tolerable cost.** Phase 0a is the direct test of that assumption; treat a negative there as the
  most valuable result the spike can produce (it saves the whole build from a wrong foundation).
- **For the pairing sub-benchmark**, also try `arkworks`/`gnark` pairing-in-circuit gadgets as a
  cross-check on the constraint count — if every toolchain blows up, that confirms the redesign
  (RED path 1) rather than a Plonky3-specific limitation.
- No networking, no chain, no DKG, no real keys — use fixed test vectors for `pk_i`, `VA_pub`,
  `beacon_T`, and a synthetic SUSP_SMT. This stays a pure circuit/prover benchmark.

---

## 7. Effort and deliverable

- **Effort:** Phase 0a is the highest-value day or two (the pairing number). Phase 0b another
  day. Phases 1–2 a few days once the gadgets exist. Low total — this is a spike, not a build.
- **Deliverable:** a benchmark table (constraints / proof-gen / RAM / proof-size / verify across
  `D`, `N_fallback`, `d`), a GREEN/AMBER/RED verdict, and — if not GREEN — a one-paragraph
  recommendation naming which §5 change to make and why. That verdict is the gate that releases
  (or redirects) the Layer-1–4 build.

**Sequencing note.** Run the OQ-63 DKG-load analysis (analytic, cheap) in parallel — it's the
other "bad answer = design change" item. Together these two clear the design before committing to
the substrate. Everything after is build-then-calibrate (Phases 1–5, §9.2).

---

## 8. Phase-0a result — constraint estimate (2026-06-06)

Ran `impl/spike_stmt5_constraints.py` — a constraint-count model from published gadget costs
(an *estimate*, not a Plonky3 run; the Phase-1 build confirms absolute timing). The decisive
question — *is the in-circuit ForwardCommit pairing the wall?* — is answered: **yes, decisively.**

| scenario (N_fallback=3 ⇒ 4 pairings) | poseidon | pairing | total | pairing share | rough proof-gen |
|---|---:|---:|---:|---:|---:|
| optimistic (fp_mul=50) | 5k | 1.60M | 1.61M | 99.7% | ~2–8 s |
| midpoint (fp_mul=120) | 5k | 5.76M | 5.77M | 99.9% | ~6–29 s |
| pessimistic (fp_mul=200) | 5k | 12.8M | 12.81M | 100.0% | ~13–64 s |
| + naive SMT depth 256 | 52k | 5.76M | 5.81M | 99.1% | ~6–29 s |
| **no in-circuit pairing** | 7k | 0 | **7k** | 0.0% | **~7–35 ms** |

**Findings:**
1. **The in-circuit BLS12-381 pairing dominates — ≥99% of constraints in every case.** Poseidon
   and the SMT path (even a naive 256-deep one) are rounding error beside `(N_fallback+1)`
   pairings emulated over Plonky3's small field. The spike's prime suspect is confirmed.
2. **Statement 5 *as literally specified* is AMBER→RED on desktop** (~2–13 M constraints) and
   **RED on mobile** (OQ-3). The dominant cost is a *design choice* (in-circuit pairing), not a
   fundamental requirement of the statement.
3. **Removing the in-circuit pairing collapses it to ~7 k constraints (sub-second, mobile-trivial,
   deep GREEN)** — a ~3-orders-of-magnitude drop.

**But "move the pairing out" is not free — this is the genuine design work the spike surfaces.**
The pairing is in-circuit to guarantee, *at handoff time*, that `commit_T` is decryptable
post-verdict **without the node's cooperation** (the dark-node-closure property, detection-contract
row 14 / P4.a). If encryption-correctness is only checked at reveal, a node could publish a
`commit_T` that passes handoff but decrypts to garbage at verdict — widening the dark-node
residual. So the RED-fixes carry a security dimension and must be chosen with care:

| Fix | Idea | Cost it trades |
|---|---|---|
| **F1. Native-group verifiable encryption** | Don't prove encryption-correctness inside the Plonky3 (small-field) circuit. The ZK circuit does only the cheap part (`null_v` derivation, SMT, `s₁+s₂=null_v` bound to Poseidon commitments `C₁,C₂`). A **companion native-BLS12-381 sigma proof** (verified by validators directly, no SNARK) proves the ciphertext **encrypts the value committed in `C₁`** — i.e. *verifiable encryption*. | **Likely forces a verifiable-encryption-friendly scheme** (vanilla BF-IBE's hash-masked ciphertext isn't sigma-friendly) → a changed/new encryption primitive with its own maturity cost, plus per-node-per-epoch **validator-side** public verification load. Leading path, but it is real crypto design — see the warning below. |
| **F2. Hybrid prover** | Keep the encryption-correctness proof but discharge it on a 2-chain / pairing-friendly prover (BLS12-377/BW6) and recurse into Plonky3. | Heavier engineering; a second proof system in the stack. |
| **F3. Verify-at-reveal + penalty** | Check encryption only at reveal; a node whose `commit_T` won't decrypt is already suspended, so treat it as the (widened) dark-node residual. | Weakens P4.a / row 14 — a knowing adversary mints undecryptable `commit_T`. Probably unacceptable. |
| **F4. Cut N_fallback** | Fewer pairings (linear). 3→1 is ~2× off the constraint count. | Liveness margin (§4.9.6); doesn't change the order of magnitude — palliative, not a fix. |

> **⚠ The F1 correctness trap (why "just move it out" is wrong).** A naïve F1 — validators check
> only ciphertext *well-formedness* + ZK binds `s₁` to a commitment — **silently breaks the
> dark-node guarantee.** Well-formed (decryptable to *something*) plus "I know `s₁` matching `C₁`"
> does **not** force the ciphertext's plaintext to *equal* `s₁`: a malicious node can publish a
> well-formed ciphertext of **garbage** with an honest-looking commitment proof, so at verdict
> decryption yields garbage ≠ `null_v` and extraction fails (P4.a / row 14 lost). The binding that
> closes this — "ciphertext encrypts the committed value" — *is* verifiable encryption, which is
> exactly the expensive relation unless discharged by a cheap native-group sigma proof (the F1
> above). **Privacy is unaffected** by F1 (the public check runs on the already-published, already-
> presence-leaking `commit_T`; no new plaintext or identity is revealed), but **correctness is
> delicate** — this is the real content of Gate 1's residual risk and the thing Phase-1 must prove,
> not just benchmark.

> **MEASURED (2026-06-07, `impl/spike_pairing_cost/`, arkworks R1CS).** Built a real
> constraint-counter. In-circuit **BLS12-377 pairing = 26,228 constraints**; G1 scalar-mul =
> 4,116; ratio 6.4×; pairing : Poseidon ≈ 87×. **This corrects the estimate below in one
> important way:** an in-circuit pairing is *not* intrinsically millions of constraints — that
> figure is specific to emulating **BLS12-381 over Plonky3's small field (non-native, no 2-chain
> partner)**. On a pairing-friendly **2-chain (BLS12-377 / BW6-761)** the pairing is ~26k —
> trivially affordable (×(N_fallback+1) ≈ 105k). So the Gate-1 "wall" is the *stack choice*
> (small-field Plonky3 + BLS12-381), not in-circuit pairings per se. Two clean escapes, now both
> credible: **(b) prove the pairing on a 2-chain** (measured-cheap, but requires migrating the
> curve 381→377, touching the whole BLS/IBE stack, + recursion); **(c) publish-`s₁` / F1
> verifiable encryption** (keeps BLS12-381, no in-circuit pairing, and *also* dissolves OQ-63).
> The adopted choice stays **(c) publish-`s₁`** — it keeps the curve and kills OQ-63 too — but
> the measurement shows (b) is a real fallback and that the pairing expense was stack-specific,
> not fundamental. The small-field non-native ~10⁶–10⁷ figure below remains an *estimate* (that
> emulation wasn't measured); only the 2-chain end is measured.

> **Update — F1 designed concretely; "~7k without pairing" was over-optimistic.** The full F1
> construction is now worked out in [DESIGN-f1-verifiable-encryption.md](./DESIGN-f1-verifiable-encryption.md):
> exponential-ElGamal *limb* verifiable encryption (decryptable by the verdict signature,
> proven correct by a native sigma + range proof — no in-circuit pairing, and it provably closes
> the correctness trap). The "~7k constraints without the pairing" figure in the table above
> **omitted the two-worlds bridge** — linking the group-world ciphertext to the arithmetic-world
> `s₁+s₂=null_v` needs **one or two in-circuit non-native `G₁` Pedersen openings (~0.2–0.4 M
> each)**. Corrected estimate: **~0.3–1 M constraints (AMBER, sub-second to a few seconds desktop,
> mobile-marginal)** — still ~10× better than the in-circuit pairings, but not deep-GREEN. The
> design doc also gives a sharper alternative (**publish `s₁`**) that dissolves both this gate and
> OQ-63, at the cost of dropping the decryption lock from 2-of-2 to validator-only (A2-bounded).

**Phase-0a verdict: AMBER/RED for Statement 5 as specified; the ForwardCommit certification must
be restructured (F1 — native-group verifiable encryption — the leading path, see
[DESIGN-f1-verifiable-encryption.md](./DESIGN-f1-verifiable-encryption.md)), which is real
cryptographic design with a correctness trap (see warning above), not a free optimization.** This
is a "go, but redesign this one component first" — *not* a dead end (the recommendation layer and
the rest of the substrate are unaffected, and privacy is unaffected by the fix). Phase-1 of this
spike must do two things, in order: (1) **prove** that the chosen verifiable-encryption construction
binds the ciphertext to the committed plaintext (i.e. preserves handoff-time extractability,
P4.a / row 14) — a correctness argument, not a benchmark; then (2) **measure** that the resulting
circuit + companion sigma proof hits ~10⁴ ZK constraints and acceptable validator-side verify cost.
Step (1) is the residual risk; step (2) is near-certain once (1) holds.

## 9. Phase-1 proving result — the publish-`s₁` core, measured (2026-06-07)

A real proving benchmark now exists: [`impl/spike_stmt5_proving/`](./impl/spike_stmt5_proving/)
(Plonky2/Goldilocks FRI — the same Polygon-Zero prover family and cost class as Plonky3, with a
friendly circuit API; see that crate's README for the toolchain caveat). It builds the **adopted
publish-`s₁` Statement-5 core** — `null_v`/`epoch_id` Poseidon derivations, the `s₁+s₂=null_v`
split with **public `s₁`**, and a depth-256 Poseidon SMT non-membership path, **no in-circuit
pairing** — proves it, and calibrates the prover's at-scale rate to band the VerEnc bridge.

**Measured (20-core desktop):**

| Piece | Status | Number |
|---|---|---|
| Poseidon/SMT **core** (depth 256) | ✅ **measured — GREEN** | prove **~0.03 s**, verify ~3–6 ms, proof ~101 kB |
| prover rate at scale | ✅ measured | **~6×10⁻⁵ s / trace-row** (linear to 2¹⁸: 64k→3.8 s, 256k→15.6 s) |
| VerEnc **bridge** | ⚠️ **OPEN — packing-dependent** | pack 1×: 31–63 s (RED); **pack ≥10×: 0.5–8 s (AMBER/GREEN)** |

**What this settles and what it doesn't.**

1. **Pairing removal is confirmed sufficient for the core.** The non-bridge part of Statement 5
   proves in ~30 ms — the ~10⁴-constraint / mobile-trivial Phase-0a claim is now a measurement,
   not an estimate. The original in-circuit-pairing wall is genuinely gone.

2. **The residual feasibility risk is *entirely* the VerEnc bridge's trace size.** The proving
   *rate* is pinned, so the desktop verdict reduces to one unknown: the bridge's trace-row count
   = (bridge constraints, est. 0.3–1.0M) ÷ (plonky2 gate-packing factor). At 1× it is RED; at the
   ≥10× typical of well-laid-out arithmetic it is AMBER/GREEN. The ballast uses Poseidon gates
   (heavier than the bridge's arithmetic gates), so the measured rate is a **conservative** proxy,
   biasing the true answer toward AMBER/GREEN.

**This sharpens — and slightly corrects — the prior leaning.** §8 and the spec called the bridge a
flat "AMBER." The measurement shows the bridge verdict genuinely swings RED↔GREEN on packing, so
it is **not** safe to assume AMBER without building the gadget. **Decisive Phase-1b step:** build
the native-group VE gadget (DESIGN §3–§4) in-circuit, read its `degree_bits`, and plug the row
count into the rate measured here — that collapses the band to a single verdict. Until then:
**core GREEN, bridge open, rate known.** *(Now done — see §10.)*

## 10. Phase-1b result — the bridge measured, packing factor collapsed (2026-06-16)

The §9 "decisive Phase-1b step" is now executed: [`impl/spike_bridge_cost/`](./impl/spike_bridge_cost/)
**measures** the bridge's dominant primitive — a non-native modular field multiplication — as a
real, provable Plonky2/Goldilocks circuit, instead of guessing a packing factor. It reads the true
trace-row cost of a range-checked limb multiply, then composes the BLS12-381 `G₁` scalar-mult /
Pedersen-MSM gate count on top of it. This converts the bridge from "estimate ÷ unknown packing"
into "measured-multiply × standard-EC-op-count".

**Why this route (not the published EC gadget):** `plonky2_ecdsa`/`plonky2_u32` (the would-be
off-the-shelf non-native EC gadgets) are pinned to the abandoned plonky2 0.1.1 era and no longer
compile against any consistent toolchain (internal `itertools`/`hashbrown`/`WitnessGenerator` API
skew that does not converge under version pinning). So the gadget was built directly on the working
plonky2 0.2 stack: 16-bit limbs (the largest that keeps a limb·limb product + column accumulation
safely below Goldilocks' ~2⁶⁴ modulus), schoolbook product, `split_le` carry propagation, all
range-checked — a genuine provable circuit whose `degree_bits` is read off, not modelled.

**Measured (20-core desktop):**

| Quantity | Result |
|---|---|
| non-native field multiply (256-bit / 16-limb, **and** 384-bit / 24-limb) | **~256 trace rows/mul**, measured marginal (limb count packs into row slack at this granularity) |
| prover rate | ~6×10⁻⁵ s/row (consistent with §9) |
| BLS12-381 `G₁` scalar-mult (~3 825 modular muls, modmul = 2× measured multiply) | **~1.96 M rows → 2²¹ → ~130 s — RED** |
| Pedersen 2-MSM `s₂·G + γ·H` (conservative independent, ~7 650 muls) | **~3.9 M rows → 2²² → ~260 s — RED** |
| same, tuned gadget ÷10× | ~13 s — **AMBER** |
| same, tuned gadget ÷30× | ~4 s — GREEN (implausible packing gain) |

**The correction — the bridge is heavier than DESIGN-f1 §5 estimated.** DESIGN §5 put one scalar-mult
at ~0.2–0.4 M constraints and the whole bridge at "AMBER — sub-second to a few seconds." The
*measured* composition puts a single scalar-mult at ~2²¹ trace rows ≈ **~2 minutes** with this
(naive) gadget. A purpose-built non-native gadget (dedicated u32 range-check gates, Karatsuba,
CRT reduction, an arithmetic-tuned config rather than the recursion config) plausibly buys 10–30×,
landing the bridge at **AMBER (~5–40 s)**; only an implausible >30× reaches GREEN. This is
consistent with the known reality that non-native EC over a small FRI field is expensive (plonky2
ECDSA verification is minutes-class).

**Verdict — bridge band collapsed to AMBER-at-best (not the near-free term the design implied).**
The two spikes together now read: pairing-removal buys back the **core (GREEN, §9)**, but the
publish-`s₁` **bridge is AMBER at best and RED if built naively** — it is the real desktop cost and
**requires a purpose-built non-native gadget as a Phase-1 deliverable**, not an afterthought. The
P-feasibility gate is therefore *passable but conditional on bridge-gadget engineering*: green-light
the substrate build, but treat the optimized bridge gadget (target ≤ ~2²⁰ rows / ≤ ~30 s desktop)
as a tracked Phase-1 exit criterion, and re-measure the real gadget's `degree_bits` before
committing the rest of Layer-1.

**Caveats (honest):** the limb-*multiply* is measured; the modular reduction is accounted as 2×
(the `a·b` and `q·p` products) rather than separately built; the EC op-counts are standard Jacobian
doubling/addition formula counts, not a fully assembled in-circuit scalar-mult; Plonky2 stands in
for Plonky3 (same FRI/Goldilocks cost class, constant-factor caveat per §9). All three biases are
named in the crate output; none flips the AMBER-at-best conclusion.
