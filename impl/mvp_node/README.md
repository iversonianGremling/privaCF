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
  broadcast a real **EC-VRF** claim (`vrf.rs`; sr25519/Ristretto, the VRF Polkadot's BABE uses —
  the lottery value is *unique* per key+input, so a validator cannot grind its own output),
  deterministically elect the lowest-output leader, vote on its
  block with a **BLS12-381 signature** (`bls.rs`), and **finalize once a quorum certificate forms —
  an aggregate BLS signature of ≥ ⌊2N/3⌋+1 distinct validator votes over the block id** (one 96-byte
  signature, verified against the aggregated signer public keys; the spec's `validator_sigs`
  mechanism, §4.1). Honest validators vote only for the elected leader, so at most one block per
  height can finalize under a <1/3 Byzantine assumption (safety). If the elected leader fails to
  produce a quorum in time, validators **view-change** to the next-lowest-VRF candidate, so a dead
  or withholding leader no longer stalls the height (liveness under leader failure).
- **Proposer signatures + equivocation slashing**: every block carries the proposer's signature
  over its id (the VRF proof only proves *leadership*, not *content*), so blocks are bound to their
  proposer. If a leader double-signs a slot — two conflicting blocks for the same `(height, view)` —
  any validator turns the two signatures into a non-repudiable `EquivocationProof`, **slashes** the
  offender (excluding it from future leader election), and gossips the evidence so the whole network
  slashes it. No fork results (an equivocator can get at most one block finalized, never two).
- **Validator double-vote slashing**: votes are BLS-signed over the slot tuple `(height, view,
  block_id)`, so a vote is self-contained evidence. If a validator signs two different block ids in
  the same slot, any node turns the two votes into a `VoteEquivocationProof`, **slashes** the
  offender, ignores its votes, and gossips the proof network-wide. (Both fault sides — proposer
  equivocation and voter double-vote — are now caught.)
- **Dynamic validator-set membership + quorum reconfiguration**: the validator set is no longer
  frozen at genesis. A validator **joins** or **leaves** by gossiping a **self-signed** membership op
  (`membership.rs`); the next leader records it in its block header (so `block_id` covers it,
  proposer-signs it, and it is voted over). The op activates at the **next** height, by which point
  the carrying block is finalized and identical for everyone. The **active set — and therefore the
  BFT quorum `⌊2N/3⌋+1` — at any height is a pure function of the finalized chain below it**, so
  every node derives the identical set with no extra coordination (the reconfiguration-safety crux:
  no split-brain). Leader election, vote counting, and quorum-certificate verification all use the
  height's active set; a departed validator can no longer lead, vote, or count toward quorum.
  Authorization is **AcceptAll** beyond proving key-control — anyone proving they hold the keys may
  join (Sybil-trivial; the real gate is the deferred `Admission`/`VdfAdmission` seam), but nobody can
  inject or evict a validator that did not sign the change. This rides on the existing aggregatable
  multisig (no DKG needed for a *changing* set; a fixed DKG threshold key stays the deferred
  `VA_pub` construct).
- **Minimal chain**: append-only, deterministic genesis, one finalized block per epoch; structural
  validation (height + prev-hash) plus semantic checks (beacon, VRF leadership, quorum certificate).
- **Networking — Noise-encrypted channels**: every peer connection runs a real **Noise XX**
  handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, via `snow`, isolated in `transport.rs`) before any
  application traffic — giving confidentiality, integrity, and **forward secrecy** on the wire (no
  more plaintext bincode). The anonymous-static XX exchange is upgraded to mutual **identity
  authentication** by an ed25519 **channel binding**: each side signs the Noise handshake hash with
  its long-term identity key inside the first encrypted `Hello`, so a man-in-the-middle — who would
  see two *different* handshake hashes — cannot relay the signature. Frames are AEAD-encrypted and
  chunked under Noise's 64 KiB message cap (so large sync responses still fit), over tokio TCP with
  full-mesh gossip (one connection per pair) and sync-on-timeout.

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
| `Transport` — Noise XX + ed25519 channel binding (real) → `LoopixTransport` | **confidential, authenticated, forward-secret** channels done (no plaintext wire); still **linkable** — a network observer sees who-talks-to-whom (no mixing/cover traffic) | SPEC §5.1 |
| consensus — VRF election + aggregate-BLS quorum cert + view-change + proposer-equivocation + double-vote slashing + dynamic membership (real) → +DKG threshold key | **safety + leader-failure liveness + aggregate-BLS finality + both equivocation-slashing paths + dynamic validator-set membership with chain-derived quorum reconfiguration done**; remaining: the QC is an aggregatable MULTISIG (signer set recorded) not a DKG threshold key (`VA_pub` is the separate DKG construct); join admission is AcceptAll (the Sybil gate is the `Admission` seam) | SPEC §4.1, §4.3 |
| `vrf` — real EC-VRF (sr25519, `schnorrkel`) | **real VRF done** (unique, ungrindable lottery value per key+input); the beacon it binds to is now VRF-chained too (see the beacon row), leaving only the residual last-revealer bias → VDF/drand | SPEC EC-VRF, §4.1 |
| `Admission` — AcceptAll (real) → `VdfAdmission` | membership is now **dynamic** (join/leave, §4.1 row), but admission is **AcceptAll**: proving key-control suffices to join (Sybil-trivial). The real gate — a VDF proof-of-work cost per admission — is deferred | SPEC §4.3 |
| `Discovery` → `ConnectKnown` / `PsiDiscovery` | declared seam; peers come from the static genesis validator set | SPEC §5.3/§5.4 |
| `VerEnc` → `StubVerEnc` / `NativeGroupVerEnc` | `d_T` is a placeholder; `s₂` is **not** sealed | DESIGN-f1, SPEC §4.9.4 |
| beacon — VRF-chained (real) → +VDF/drand | `beacon_T = Poseidon(beacon_{T-1}, T, fold(vrf_output_{T-1}))` — folds in the prior block's *ungrindable* VRF output, so the leader schedule is no longer computable from genesis; residual last-revealer (withhold-to-regrind) bias remains → VDF/drand for full unbiasability | SPEC §4.1 |
| SMT roots | zero stubs — no suspensions, no non-membership proofs | SPEC §4.9.2 |
| ZK proof in the loop | omitted entirely | SPEC §4.9.5 |

So the MVP demonstrates node creation, network formation over **Noise-encrypted authenticated
channels**, epoch cycling, `epoch_id` **rotation**, and **BFT-style consensus** (VRF leader election
+ aggregate-BLS ≥2/3 quorum-certificate finality + view-change past failed leaders +
proposer-equivocation + validator-double-vote slashing + dynamic membership with chain-derived quorum
reconfiguration) — but NOT the *unlinkability* rotation exists
for (Noise authenticates and conceals *content*, but a network observer still sees the
who-talks-to-whom traffic pattern — that needs Loopix mixing), Sybil cost, or any sealing/verdict/ZK
property.

## What to make real next

Consensus now has a real EC-VRF, a VRF-chained beacon, catches both equivocation faults, and supports
**dynamic membership** with chain-derived quorum reconfiguration — a coherent BFT-ish core — and the
wire is a real **Noise XX** channel (confidential, authenticated, forward-secret). The remaining steps
each open a larger, decision-laden subsystem: **Loopix mixing** on the `Transport` seam (the actual
*unlinkability* the epoch_id rotation exists to provide — Noise hides content but not the
who-talks-to-whom pattern; research-grade: Sphinx packets, Poisson per-hop delay, cover traffic,
SURBs), a **VDF/drand beacon** (to remove the residual last-revealer bias — needs a VDF artifact or an
external drand network), a **VDF `Admission` gate** (the real Sybil cost replacing AcceptAll joins),
and a **DKG threshold key** (`VA_pub`) in place of the aggregatable multisig. *(Globally, separate
from this node roadmap, the optimized non-native ZK **bridge gadget** — see `../spike_bridge_cost/`
and `SPIKE-statement5.md` §10 — remains the standing P-feasibility item.)*

## Toolchain caveat

plonky2 0.2 requires **nightly**, so this crate does too (same as the sibling proving spikes). It is
used *only* for the Goldilocks Poseidon in `src/hash.rs` (≈10 lines) — the one circuit-equivalence-
critical hash. If nightly ever conflicts with the tokio stack, swap `hash.rs` to a standalone
Goldilocks-Poseidon using the identical field/round-constants/MDS, or every node's `epoch_id`
silently diverges from the circuit. Block-plumbing hashes use blake3, NOT Poseidon.
