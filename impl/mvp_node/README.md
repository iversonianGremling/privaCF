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
  `VA_pub` construct). A **newcomer** boots with the genesis set as bootstrap peers and gossips its
  join op until admitted; peer **dialing is dynamic** (a shared address book grown from the chain and
  from peers' `Hello`s), so the network reaches a validator that joined after genesis. (Gossip is
  single-hop, so a newcomer meshes fully; a newcomer whose id exceeds every existing one's still
  needs reverse-dialing — implemented — but the demo/test newcomer dials the whole bootstrap set.)
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
- **Loopix mixnet — real Sphinx packets + chain-seeded mixing** (`sphinx.rs`, `loopix.rs`): the
  *unlinkability* layer the `epoch_id` rotation exists for. A **Sphinx** packet (Ristretto
  key-blinding, fixed `285`-byte MAC'd routing header + fixed `1024`-byte onion payload) is a
  fixed-size onion each mix peels by one layer, learning *only* the next hop and a per-hop delay —
  never the origin, destination, payload, or its own position. Entering and leaving a mix the packet
  is **bitwise unlinkable** (every field changes), so a passive observer cannot correlate it. Per the
  project directive the mixnet **presupposes a trusted genesis** (the `MixDirectory` of mix keys is
  published at genesis) and **draws all its entropy from the blockchain**: the mix **path**, the
  per-hop **Poisson delays**, and the **cover-traffic** schedule are seeded from the VRF-chained
  `beacon_T` (`beacon.rs`) — unpredictable before the prior block finalizes, yet recomputable from
  public chain data — rather than an external VDF/drand. The payload is onion-wrapped with a
  **LIONESS wide-block SPRP** (one keyed layer per hop), so any mid-path bit-flip avalanches across
  the whole 1024-byte block — closing the payload **tagging channel** (an active mix cannot stamp a
  recognisable mark for a downstream colluder to trace). A `MixNode` engine runs the
  peel→delay→forward / deliver loop over the existing Noise channels and emits two kinds of
  indistinguishable **cover traffic**: **loop** packets (routed back to self, counted on return) and
  **drop** packets (routed to a random other mix, silently discarded) — so an observer cannot tell
  when a node genuinely transmits. **SURBs** (single-use reply blocks) let an anonymous sender hand a
  recipient a pre-built return header so it can reply without ever learning the sender's identity:
  the recipient encrypts its reply under a SURB key, the mixes LIONESS-decrypt it like any packet,
  and only the creator (which kept the per-hop secrets) inverts the chain to read it. This is **wired
  into the live `MixNode`** — `mint_surb` builds a chain-selected return block and stores its keys,
  `reply` sends through one, recovered replies surface on a dedicated stream — tested end-to-end over
  real Noise. (Honest scope: statistical anonymity-set guarantees are a deployment-scale property and
  out of scope.)
- **Consensus routed through the mixnet, blocks included** (`Node::with_mixnet`, `--mix`): the whole
  BFT exchange no longer broadcasts in the clear. With mixing on, every **VRF claim, vote, tx,
  membership/slash, proposal, and finalized block** is wrapped in Sphinx packets and unicast to each
  validator along chain-beacon-selected mix paths (the validators *are* the mixes), so a network
  observer no longer sees who-claims / who-votes / who-proposes / who-changes-set. A block exceeds one
  fixed Sphinx payload, so each message is **fragmented** (`msg_id ‖ index ‖ count ‖ chunk`) across
  packets — each fragment routed independently — and reassembled at the destination by a bounded
  `Reassembler` (single-fragment messages are just `count = 1`). The BFT round timers absorb the
  per-hop Poisson delay — the network still converges with valid quorum certificates (integration-
  tested at N=4 routing real blocks; the standalone mixnet reassembles a 6 KB payload end-to-end; the
  demo's `--mix` flag shows it live). Only the **catch-up/sync** path (`GetChain`/`ChainRange`, a
  point-to-point bulk response) stays direct. Mixing is **off by default** (the original direct-gossip
  path is preserved byte-for-byte), opt-in per node.

## Run

```bash
# nightly is required (plonky2 0.2, used for the Poseidon in hash.rs); rust-toolchain.toml pins it.
cargo +nightly build --release

# live demo — N nodes in-process over loopback TCP, prints a convergence summary
cargo +nightly run  --release --bin demo -- --nodes 4 --epochs 6 --window-ms 250

# same demo, but route the consensus control plane through the Loopix mixnet (unlinkable gossip)
cargo +nightly run  --release --bin demo -- --nodes 4 --epochs 5 --window-ms 350 --mix

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
| `Transport` — Noise XX + ed25519 channel binding **and** a real Loopix/Sphinx mixnet carrying the **whole BFT exchange** (VRF/vote/tx/membership/slash **+ fragmented blocks**) (real) → mixnet hardening | **confidential, authenticated, forward-secret** Noise channels **plus** a chain-seeded Sphinx mixnet (per-hop bitwise unlinkability, Poisson delays, loop cover) that **routes all consensus gossip incl. proposals/finalized blocks via fragmentation+reassembly** — consensus converges over it; **every message except the two transport frames (`Hello`/`Sphinx`) routes through the mixnet** (the chain-sync seam is closed — it's a dormant path, laggards catch up via the mixnet-routed `Finalized`); payload is a LIONESS wide-block SPRP (anti-tagging) with loop+drop cover and live SURB anonymous replies; remaining: deployment-scale anonymity-set tuning | SPEC §5.1 |
| consensus — VRF election + aggregate-BLS quorum cert + view-change + proposer-equivocation + double-vote slashing + dynamic membership (real); **DKG threshold key as a tested primitive** (`dkg.rs`) | **safety + leader-failure liveness + aggregate-BLS finality + both equivocation-slashing paths + dynamic validator-set membership with chain-derived quorum reconfiguration done**. The live QC is an aggregatable MULTISIG (no re-DKG on membership change); the spec's **`VA_pub` DKG threshold key** is implemented standalone — a Feldman-VSS DKG + non-interactive threshold BLS where any `t`-of-`n` shares combine into one signature under a single `VA_pub`. Wiring it live would require a re-share each membership change, which is why the running set uses the multisig | SPEC §4.1, §4.3 |
| `vrf` — real EC-VRF (sr25519, `schnorrkel`) | **real VRF done** (unique, ungrindable lottery value per key+input); the beacon it binds to is now VRF-chained too (see the beacon row), leaving only the residual last-revealer bias → VDF/drand | SPEC EC-VRF, §4.1 |
| `Admission` — AcceptAll **and** a real `VdfAdmission` (real, opt-in) | AcceptAll by default; opt **`VdfAdmission`** in (`Node::with_vdf_admission`, genesis-consistent) and a join must carry a valid **Wesolowski VDF** proof-of-work over its `peer_id` (`vdf.rs`) — a prover is admitted, a proofless freeloader is rejected, enforced at pooling/assembly/block-validation. The VDF runs over a genesis RSA modulus with **factors discarded** (the good-genesis trusted setup); a fully trustless class-group VDF is the heavier alternative | SPEC §4.3 |
| `Discovery` — bootstrap + chain-driven address book (partial) → `PsiDiscovery` | peers come from the genesis bootstrap set plus a dynamic address book grown from on-chain joins and peers' `Hello`s; the private set-intersection discovery is deferred | SPEC §5.3/§5.4 |
| `VerEnc` — `NativeGroupVerEnc` (real, `verenc.rs`) / `StubVerEnc` | **`s₂` is really sealed**: limb exponential-ElGamal over BLS12-381 to `VA_pub`, recoverable ONLY by the verdict threshold signature on `verdict_id(epoch_id)` (pairing decrypt + BSGS) — the dark-node-closure seal. `open_commit` recovers `s₂` exactly with the right `σ`, nothing without it. Remaining: the well-formedness sigma+range proof validators check before accepting `d_T` (P1.2b), and wiring `VA_pub` into the node from the genesis DKG (P1.3) | DESIGN-f1, SPEC §4.9.4 |
| beacon — VRF-chained **and** optionally VDF-folded (real) | `beacon_T = Poseidon(beacon_{T-1}, T, fold(vrf_output_{T-1}))` folds in the prior block's *ungrindable* VRF output (no genesis-predictable schedule); with `Node::with_vdf_beacon` (genesis-consistent) it **also folds a Wesolowski VDF output over the previous beacon** (`next_beacon_vdf`), so the next beacon is uncomputable until the VDF's sequential delay elapses — removing the residual last-revealer (withhold-to-regrind) bias. Convergence-tested with the VDF beacon on; the security margin scales with the chosen delay | SPEC §4.1 |
| SMT roots — real Poseidon SMT (`smt.rs`), **folded from on-chain suspensions** | block headers carry real circuit-matching Poseidon SMT roots (SUSP_SMT + DECRYPTION_SMT), derived from the finalized chain and validated; `SuspendRecord`s in blocks fold extracted `null_v`s into the SUSP_SMT (and `dec_nullifier`s into the DECRYPTION_SMT) | SPEC §4.9.2 |
| **verdicts + dark-node extraction** — real mechanism (`verdict.rs`) → autonomous in-loop trigger | **commit-reveal SUSPEND verdicts** (commit `H(verdict‖nonce)` → reveal/tally `⌊K/2⌋+1`), validator **threshold finalization** → `σ_VERDICT`, then **dark-node extraction**: `null_v = s₁+s₂` recovered from public `(s₁, d_T)` + `σ_VERDICT` with no node cooperation, listed in SUSP_SMT (non-membership then provably fails). Tested end-to-end with real crypto. Remaining: driving the multi-round flow autonomously in the live consensus loop (the *when*, P1.4b); unlinkable re-admission enforcement is the Statement-5 ZK proof (Track Z) | SPEC §4.9.6 |
| ZK proof in the loop | omitted entirely | SPEC §4.9.5 |

So the MVP demonstrates node creation, network formation over **Noise-encrypted authenticated
channels**, epoch cycling, `epoch_id` **rotation**, and **BFT-style consensus** (VRF leader election
+ aggregate-BLS ≥2/3 quorum-certificate finality + view-change past failed leaders +
proposer-equivocation + validator-double-vote slashing + dynamic membership with chain-derived quorum
reconfiguration) — **and** a working Loopix/Sphinx mixnet giving per-hop **unlinkability** with
chain-seeded paths/delays and cover traffic (the who-talks-to-whom hiding the rotation exists for),
**now carrying the entire BFT exchange itself** (VRF claims, votes, txs, membership/slash, **and
fragmented proposals/finalized blocks** route through the mixnet and the network still converges). It
still does NOT demonstrate Sybil cost, or any sealing/verdict/ZK property.

## What to make real next

Consensus now has a real EC-VRF, a VRF-chained beacon, catches both equivocation faults, and supports
**dynamic membership** with chain-derived quorum reconfiguration — a coherent BFT-ish core; the wire
is a real **Noise XX** channel (confidential, authenticated, forward-secret); and there is now a real
**Loopix/Sphinx mixnet** (`sphinx.rs`/`loopix.rs`) with chain-seeded paths/delays and cover traffic
that **already carries the entire BFT exchange** (consensus converges over mix-routed
VRF/vote/tx/slash messages **and fragmented proposals/finalized blocks**), with a **LIONESS**
anti-tagging payload, **loop + drop cover traffic**, and live **SURB** anonymous replies — and every
message except the transport frames now routes through it. A real **Wesolowski VDF** (`vdf.rs`,
over a genesis RSA modulus with factors discarded) now backs both an opt-in **VDF admission gate**
and an opt-in **VDF-folded beacon**, and a **Feldman-VSS DKG with non-interactive threshold BLS**
(`dkg.rs`) realises the spec's **`VA_pub`** threshold key. Every research-grade node subsystem the MVP
set out to skeletonise now has a real, tested implementation; the open frontier is *integration depth*
(e.g. re-DKG on membership change to make `VA_pub` the live QC) and deployment-scale tuning, plus —
globally, separate from this node roadmap — the optimized non-native ZK **bridge gadget** (see
`../spike_bridge_cost/` and `SPIKE-statement5.md` §10), the standing P-feasibility item.

## Toolchain caveat

plonky2 0.2 requires **nightly**, so this crate does too (same as the sibling proving spikes). It is
used *only* for the Goldilocks Poseidon in `src/hash.rs` (≈10 lines) — the one circuit-equivalence-
critical hash. If nightly ever conflicts with the tokio stack, swap `hash.rs` to a standalone
Goldilocks-Poseidon using the identical field/round-constants/MDS, or every node's `epoch_id`
silently diverges from the circuit. Block-plumbing hashes use blake3, NOT Poseidon.
