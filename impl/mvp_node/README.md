# `mvp_node` — PrivaCF substrate thin-skeleton MVP

The first runnable piece of the PrivaCF **substrate** (Layers 1–2 + a minimal chain) — distinct
from the Python Layer-5 recommendation PoC in `../privacf/`. It demonstrates **creating nodes on a
network**: N nodes join over TCP, each generates an identity, and they cycle through staggered
epochs publishing per-epoch commitments to a shared minimal chain, converging on one head.

Companion to `SPEC.md` §4.1 (chain/epochs), §4.2/§4.9.1 (identity derivation), §4.9.4 (publish-`s₁`
`commit_T`), §5.1.1 (clearnet dev transport), §9.2 Phase 1.

## What it does (REAL)

- **Identity** (§4.9.1, §4.2): ed25519 signing key + a field-element `sk`; `null_v = Poseidon(sk,
  "null_v")`; per epoch `epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")` — unlinkable
  across epochs without `sk`. Poseidon is the **same Goldilocks Poseidon the ZK circuit uses**
  (reused from `../spike_stmt5_proving/`, isolated in `src/hash.rs`) so node values match the
  circuit.
- **Publish-`s₁` commitment** (§4.9.4): each epoch sample `s₂`, publish `s₁ = null_v − s₂ (mod p)`,
  with `d_T` a stub (no verdicts in the MVP). The `s₁ + s₂ = null_v` split is checked every epoch.
- **Per-epoch node loop**: derive `epoch_id`, build + sign an `epoch_transaction`, gossip it, and
  participate in consensus on the next block.
- **Consensus — simplified single-round BFT with view-change**: each height the validators
  broadcast a VRF claim (`vrf.rs`), deterministically elect the lowest-output leader, vote on its
  block with a **BLS12-381 signature** (`bls.rs`), and **finalize once a quorum certificate forms —
  an aggregate BLS signature of ≥ ⌊2N/3⌋+1 distinct validator votes over the block id** (one 96-byte
  signature, verified against the aggregated signer public keys; the spec's `validator_sigs`
  mechanism, §4.1). Honest validators vote only for the elected leader, so at most one block per
  height can finalize under a <1/3 Byzantine assumption (safety). If the elected leader fails to
  produce a quorum in time, validators **view-change** to the next-lowest-VRF candidate, so a dead
  or withholding leader no longer stalls the height (liveness under leader failure).
- **Minimal chain**: append-only, deterministic genesis, one finalized block per epoch; structural
  validation (height + prev-hash) plus semantic checks (beacon, VRF leadership, quorum certificate).
- **Networking**: tokio TCP, length-prefixed bincode frames, full-mesh gossip (one connection per
  pair), sync-on-timeout.

## Run

```bash
# nightly is required (plonky2 0.2, used for the Poseidon in hash.rs); rust-toolchain.toml pins it.
cargo +nightly build --release

# live demo — N nodes in-process over loopback TCP, prints a convergence summary
cargo +nightly run  --release --bin demo -- --nodes 4 --epochs 6 --window-ms 250

# the convergence integration test (4 nodes, 5 epochs)
cargo +nightly test --release --test convergence -- --nocapture

# a single real node (run several in separate terminals for a multi-process network)
cargo +nightly run  --release --bin node -- --index 0 --nodes 3
```

The demo prints, per node, the shared head hash, `split_ok`, and the distinct per-epoch
`epoch_ids`, then `CONVERGED: true`. The test additionally asserts cross-node `epoch_id`
distinctness and the publish-`s₁` split.

## What it does NOT do (the stubbed seams)

| Seam (trait → stub / real future impl) | MVP behavior | Deferred to |
|---|---|---|
| `Transport` → `TcpTransport` / `LoopixTransport` | **clearnet, plaintext** — no Noise, no mixing; fully linkable to a network observer | SPEC §5.1 |
| consensus — VRF election + aggregate-BLS quorum cert + view-change (real) → +slashing/+DKG | **safety + leader-failure liveness + aggregate-BLS finality done** (≥2/3 BLS quorum cert, view-change skips dead leaders); remaining: no equivocation/slashing detection, and the QC is an aggregatable MULTISIG (signer set recorded), not a DKG threshold key (`VA_pub` is the separate DKG construct) | SPEC §4.1 |
| `vrf` → ed25519-sig stand-in / EC-VRF | leader lottery works + is verifiable, but it is an ed25519-deterministic-sig stand-in, not a true VRF; and the beacon it binds to is grindable | SPEC EC-VRF |
| `Admission` → `AcceptAll` / `VdfAdmission` | declared seam; membership is the static genesis set (Sybil-trivial) | SPEC §4.3 |
| `Discovery` → `ConnectKnown` / `PsiDiscovery` | declared seam; peers come from the static genesis validator set | SPEC §5.3/§5.4 |
| `VerEnc` → `StubVerEnc` / `NativeGroupVerEnc` | `d_T` is a placeholder; `s₂` is **not** sealed | DESIGN-f1, SPEC §4.9.4 |
| beacon | `Poseidon(prev, height)` — no drand/VDF, grindable | SPEC §4.1 |
| SMT roots | zero stubs — no suspensions, no non-membership proofs | SPEC §4.9.2 |
| ZK proof in the loop | omitted entirely | SPEC §4.9.5 |

So the MVP demonstrates node creation, network formation, epoch cycling, `epoch_id` **rotation**,
and **BFT-style consensus** (VRF leader election + aggregate-BLS ≥2/3 quorum-certificate finality +
view-change past failed leaders) — but NOT the *unlinkability* rotation exists for (plaintext
transport), Sybil cost, or any sealing/verdict/ZK property.

## What to make real next

Inside the consensus seam: **equivocation/slashing detection** (punish a leader that double-signs or
a validator that votes for conflicting blocks) and a true **EC-VRF** in place of the ed25519-sig
stand-in. Then the **`Transport` seam** (Noise → Loopix) to actually exercise unlinkability.
*(Globally, separate from this node roadmap, the optimized non-native ZK **bridge gadget** — see
`../spike_bridge_cost/` and `SPIKE-statement5.md` §10 — remains the standing P-feasibility item.)*

## Toolchain caveat

plonky2 0.2 requires **nightly**, so this crate does too (same as the sibling proving spikes). It is
used *only* for the Goldilocks Poseidon in `src/hash.rs` (≈10 lines) — the one circuit-equivalence-
critical hash. If nightly ever conflicts with the tokio stack, swap `hash.rs` to a standalone
Goldilocks-Poseidon using the identical field/round-constants/MDS, or every node's `epoch_id`
silently diverges from the circuit. Block-plumbing hashes use blake3, NOT Poseidon.
