# VerEnc "bridge" cost — the last open P-feasibility term, measured

Companion to [`../../SPIKE-statement5.md`](../../SPIKE-statement5.md) §10,
[`../../DESIGN-f1-verifiable-encryption.md`](../../DESIGN-f1-verifiable-encryption.md) §5, and
[`../spike_stmt5_proving/`](../spike_stmt5_proving/) (which measured the Poseidon/SMT *core* and
left the bridge open).

## What this settles

The adopted publish-`s₁` Statement 5 removes the in-circuit pairing. The sibling spike showed the
**core** proves in ~30 ms (GREEN) and pinned the prover's rate, but the **two-worlds bridge** —
opening a `G₁` Pedersen commitment `C = s₂·G + γ·H` *inside* the small-field circuit, a non-native
BLS12-381 EC scalar-mult — was left as an estimate banded across a *guessed* gate-packing factor
(RED at 1×, GREEN at ≥10×). That binary was the **whole** remaining feasibility risk.

This crate **measures** the dominant primitive (a non-native modular field multiply) as a real,
provable circuit, reads its true trace-row cost, and composes the scalar-mult / MSM gate count on
top — replacing the guessed packing factor with a measured one.

## How to run

```bash
cargo +nightly run --release      # plonky2 0.2 needs the nightly toolchain
```

Built on **plonky2 0.2** (the working stack), *not* `plonky2_ecdsa` — that and `plonky2_u32` are
pinned to the abandoned plonky2 0.1.1 era and no longer compile against any consistent toolchain
(`itertools`/`hashbrown`/`WitnessGenerator` API skew that does not converge under version pinning).
So the non-native multiply is hand-built: 16-bit limbs (largest that keeps limb·limb products + a
column sum under Goldilocks' ~2⁶⁴ modulus), schoolbook product, `split_le` carry propagation, all
range-checked — a genuine provable circuit whose `degree_bits` is read off, not modelled.

## Result (20-core desktop, 2026-06-16)

| Quantity | Result |
|---|---|
| non-native field multiply (256-bit and 384-bit) | **~256 trace rows/mul** (measured marginal) |
| BLS12-381 `G₁` scalar-mult (~3 825 modmuls) | ~1.96 M rows → 2²¹ → **~130 s — RED** |
| Pedersen 2-MSM `s₂·G + γ·H` | ~3.9 M rows → 2²² → **~260 s — RED** |
| tuned gadget ÷10× | ~13 s — **AMBER** |
| tuned gadget ÷30× | ~4 s — GREEN (implausible) |

**Bottom line.** The bridge is **heavier than DESIGN-f1 §5's "AMBER, sub-second to a few seconds."**
A measured non-native multiply is ~256 rows; the in-circuit scalar-mult the bridge needs is ~2²¹
rows ≈ ~2 min naively. A purpose-built gadget (dedicated range-check gates, Karatsuba, CRT
reduction, arithmetic-tuned config) plausibly reaches **AMBER (~5–40 s)**; >30× to hit GREEN is
implausible. So pairing-removal buys back the **core (GREEN)**, but the publish-`s₁` **bridge is
AMBER-at-best** and is a **purpose-built-gadget Phase-1 deliverable**, not a near-free term.

## Caveats (honest)

- The limb-*multiply* is measured; the modular reduction is accounted as 2× (the `a·b` and `q·p`
  products), not separately built.
- EC op-counts are standard Jacobian doubling/addition formula counts (≈8 / ≈14 field muls), not a
  fully assembled in-circuit scalar-mult.
- The gadget is deliberately naive (a `split_le` per carry on the recursion-tuned config) → the
  measured number is an **upper bound**; the tuned-gadget band brackets the realistic target.
- Plonky2 stands in for Plonky3 — same FRI/Goldilocks cost class, constant-factor caveat.

None of these flips the AMBER-at-best conclusion.
