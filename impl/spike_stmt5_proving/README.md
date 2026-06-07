# Statement-5 (publish-`s₁`) proving-time spike — P-feasibility gate, sub-gate (b)

Companion to [`../../SPIKE-statement5.md`](../../SPIKE-statement5.md) and SPEC §4.9.5.
This is the **proving benchmark** that `spike_stmt5_constraints.py` (a constraint *estimate*)
and `../spike_pairing_cost/` (an in-circuit-pairing *measurement*) pointed to but did not run.

## What it does

Builds the **adopted publish-`s₁` Statement 5 core** as a real circuit and proves it:

- `null_v = Poseidon(sk, "null")`, `epoch_id = Poseidon(sk, beacon, null_v, "epoch")`
- additive split `s₁ + s₂ = null_v` with **`s₁` a public input** (the publish-`s₁` design)
- SMT non-membership = a Poseidon Merkle path (depth 32–256) to a public root, with the path
  direction bound to `null_v`'s bits
- **no in-circuit pairing** — the whole point of publish-`s₁`

Then it measures the prover's **at-scale rate** with a Poseidon ballast sweep (traces up to
2¹⁸) and uses that rate to band the **VerEnc bridge** (the one remaining cost, estimated at
0.3–1.0M constraints in DESIGN §3–§4) across plausible gate-packing factors.

## How to run

```bash
cargo +nightly run --release      # plonky2 0.2 needs the nightly toolchain
```

(If nightly is missing: `rustup toolchain install nightly --profile minimal`.)

## Toolchain caveat — why Plonky2, not Plonky3

SPEC targets **Plonky3**, but Plonky3's public API is low-level AIR tables with no Poseidon/
Merkle gadgets — the wrong tool for a quick spike. **Plonky2** is the *same* Polygon-Zero FRI
prover over the Goldilocks field (same proving-cost class) with a friendly `CircuitBuilder` and
a native Poseidon. The wall-clock numbers transfer to the Plonky3 cost class up to the constant
factor between two implementations of the same FRI/Goldilocks pipeline. **This is a leaning with
a real measurement attached, not a Plonky3 production number.**

## Result (run on a 20-core desktop, 2026-06-07)

| Piece | Status | Number |
|---|---|---|
| **Poseidon/SMT core** (depth 256) | ✅ **measured, GREEN** | prove **~0.03s**, verify ~3–6ms, proof ~101 kB |
| at-scale prover rate | ✅ measured | **~6×10⁻⁵ s / trace-row** (linear: 4k→0.25s, 64k→3.8s, 256k→15.6s) |
| **VerEnc bridge** | ⚠️ **UNRESOLVED** | RED at pack 1× (31–63s); **AMBER/GREEN at pack ≥10× (0.5–8s)** |

**Conclusions:**

1. **Removing the in-circuit pairing definitively buys back the core.** The Poseidon/SMT core
   proves in ~30 ms — confirming the Phase-0a claim that publish-`s₁` makes the non-bridge part
   mobile-trivial. The original 2-of-2 pairing wall is genuinely gone.

2. **The residual feasibility risk is *entirely* the VerEnc bridge's trace size.** The proving
   *rate* is now pinned, so the desktop verdict reduces to a single unknown: how many trace rows
   the native-group VE gadget compiles to (= bridge constraints ÷ plonky2's gate-packing factor).
   At 1× packing it is RED; at the ≥10× packing typical of well-laid-out arithmetic it is
   AMBER/GREEN. This is more cautious than the docs' prior flat "AMBER" leaning — the bridge can
   be RED if it packs poorly, so it must be built to know.

3. The ballast uses **Poseidon** gates, which are *heavier* than the arithmetic gates the bridge
   would mostly compile to — so the measured per-row rate is a **conservative (pessimistic)**
   proxy for bridge rows. This biases the true answer toward the AMBER/GREEN end.

## The decisive remaining step (Phase-1b)

Build the native-group **VerEnc gadget** (DESIGN §3–§4: the exponential-ElGamal limb encryption
+ sigma/range binding linking `d_T` to `s₂`) in-circuit, read its `degree_bits`, and plug the
trace-row count into the rate measured here. That collapses the band above to a single verdict.
Until then: **core GREEN, bridge open, rate known.**
