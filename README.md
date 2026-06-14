# PrivaCF

**A privacy-preserving, decentralized recommendation protocol.**
No server owns your data, no one can read what you like, and fake accounts can't cheaply
drown out real taste.

*License: [AGPL-3.0-or-later](./LICENSE) · Spec: v0.3.1 · Status: research + PoC*

> **Status — research project, not production.** This repository is a detailed design
> specification, a runnable proof-of-concept for the recommendation layer, machine-checked
> proofs for the cryptographic core, and feasibility spikes for the parts that needed
> measuring before building. The full decentralized substrate is **not** built yet. See
> [Status](#status) for an honest breakdown. Spec version: **v0.3.1**.

---

## The problem

Every major recommendation system learns what you like by collecting your identity, history,
and behavior on a server you don't control. PrivaCF asks whether that has to be true.

The hard part is a three-way tension:

- **Personalization** needs preference data.
- **Privacy** needs that data to be unreadable by anyone else.
- **Integrity** needs recommendations to reflect real human taste, not signals manufactured
  by fake accounts.

Prior work resolves at most two of the three at once. PrivaCF attempts all three, with no
trusted operator in the middle:

- Each participant holds a **pseudonymous rotating identity** tied to a sequential
  computational **admission cost** that makes fake-account flooding expensive.
- Preferences are **never transmitted in recoverable form** — only shuffled, partially
  transmitted, noised approximations that let similar users find each other without revealing
  what they actually like.
- Behavioral history is committed to a **tamper-evident structure**, checked by a rotating
  committee of independent auditors via **zero-knowledge proof**, without access to the
  underlying data.
- Suspension is **permanent and survives identity rotation**: a banned key's *nullifier* lands
  in a public set, and every future identity from that key carries the same nullifier by
  construction — the membership check fails by arithmetic, not by policy.

If the cryptography and the network model sound unfamiliar, start with the plain-language
[EXPLAINER.md](./EXPLAINER.md) — it walks through the whole thing with no math.

---

## Status

PrivaCF is built in layers (L1 identity · L2 network · L3 Sybil resistance · L4 reputation/audit
· L5 recommendation), over a public BFT/VDF chain. Where each part stands today:

| Part | State |
|---|---|
| **L5 recommendation** | ✅ **proof-of-concept built & passing** — `impl/`, experiments E1–E4 + temporal + novelty-kill on MovieLens |
| **Forward-secure nullifier** (the "banned-means-banned" crypto) | ✅ **design adopted** (publish-`s₁`); algebraic core **machine-checked in EasyCrypt** (`impl/easycrypt/`) |
| **Feasibility gates** (can it be built?) | ✅ both resolved on paper; Statement-5 proving core **measured GREEN**, one residual term open (see below) |
| **Security properties P1–P5** | ◐ reduction-level **proof sketches** + key pieces machine-checked; two open questions closed analytically |
| **L1–L4 substrate** | ❌ **not built** — spec-only. This is the main gate to a real deployment. |

**The honest one-liner:** the design is validated and internally coherent, the recommendation
idea works in code, and the trickiest cryptography is partly machine-checked — but the
decentralized substrate (identity / mixnet / chain / audit) is still a specification, not a
running system.

Claims in the docs are tagged by how much they're backed:

- **Proven / machine-checked** — a computer (EasyCrypt) verified it.
- **Proof sketch** — the reduction is written and the assumption it bottoms out in is named,
  but it isn't fully formalized.
- **Assumed** — taken as given (e.g. honest-majority-by-weight); standard and stated explicitly.

---

## Repository layout

```
SPEC.md          The full specification (authoritative). Notation, ZK statements, network
                 layer, reputation & audit, Sybil resistance, limitations, open questions.
SECURITY.md      Security companion — reduction-level proof sketches for P1–P5, the
                 feasibility gate, and the analytic closures (OQ-15, OQ-57).
DESIGN-f1-verifiable-encryption.md
                 The forward-secrecy construction in full: native-group verifiable
                 encryption, the publish-`s₁` design, security analysis, threat-model sign-off.
EXPLAINER.md     Plain-language tour of "the proof stuff" — no math required.
SPIKE-statement5.md   Feasibility spike for the handoff ZK proof (the P-feasibility gate).
ANALYSIS-dkg-load.md  Feasibility analysis for per-epoch committee load.
CRYPTO.md        Reference for the cryptographic primitives used.
GRAPHS.md        Original design intuitions (historical; spec is authoritative on conflicts).

impl/            Reference implementation (proof-of-concept).
  privacf/       The recommendation layer in Python: CF core, obfuscation, attacks/defenses.
  tests/         Unit tests (no external test framework required).
  easycrypt/     Machine-checked proofs of the verifiable-encryption core (EasyCrypt).
  spike_stmt5_proving/    Plonky2 proving-time benchmark for the handoff ZK proof.
  spike_stmt5_constraints.py / spike_dkg_liveness.py / spike_pairing_cost/
                 The feasibility spikes behind the gate analyses above.
```

---

## How it works, briefly

A behavioral sketch; primitives are named here and defined precisely in
[SPEC.md §4](./SPEC.md#4-identity-and-privacy).

**Getting recommendations.** Your node keeps a preference vector entirely local. Each epoch it
exchanges a *shuffled, partially transmitted* version of it with a few peers whose tastes
overlap with yours — peers discovered without revealing what those tastes are. Exactly `n_v(T)`
elements are sent (a VRF-jittered mix of real preferences and cover items), so even the vector
*size* leaks nothing. Filtering and ranking run **on your device**; nothing is requested from
any server.

**Participating.** When you interact positively with an item, your node announces it after a
random delay with a little noise on the rating; negative interactions never leave the device.
Your behavioral history is summarized into a per-epoch commitment that an on-demand arbitration
committee can check for consistency via ZK proof, holding only Shamir shares of the encrypted
state — reconstructable only on a threshold quorum, and only when an arbitration is actually
invoked.

**When something goes wrong.** If recommendations degrade, nodes signal it; enough independent
signals assemble a rotating audit committee whose traffic is indistinguishable from normal
protocol activity. A suspension runs as a public **commit-reveal**: committee members lock in
their verdict on-chain *before* anything is decryptable. On a finalized SUSPEND verdict, the
validator set publishes a verdict attestation that unseals the encrypted half of the offender's
forward-secure nullifier commitment; combined with the public half, anyone can recover `null_v`.
No committee member needs to be online, and **absent a real verdict, nothing decrypts** —
forward secrecy holds by construction, not by a deletion policy.

**Banned means banned.** The recovered `null_v` is inserted into a public Sparse Merkle Tree.
Every future epoch ID derived from the same key carries the same `null_v`, so the
non-membership proof required at each handoff fails for that key forever. A genuinely new key
must pay the full admission cost again and faces behavioral-fingerprint matching on arrival.

---

## The proof-of-concept (`impl/`)

The recommendation layer (L5) is implemented and test-backed in Python — crypto, mixnet, and
chain are modeled in the clear, since this PoC is about *recommendation quality*, not the
substrate. It runs the §9.1 experiments against a popularity baseline on MovieLens:

```bash
cd impl
python3 -m tests.test_core                          # unit tests (no download)
python3 -m privacf.experiment        --dataset ml-1m    # E1: does it recommend at all?
python3 -m privacf.experiment_e2     --dataset ml-1m    # E2: quality under in-transit noise
python3 -m privacf.experiment_e3     --dataset ml-100k  # E3: Sybil damage by attack type
python3 -m privacf.experiment_e4     --dataset ml-1m    # E4: PSI peer selection + rotation
python3 -m privacf.experiment_frontier --dataset ml-1m  # accuracy <-> discovery sweep
python3 -m privacf.experiment_temporal                  # temporal: convergence + on-off attack
```

What it shows, in short: item-based CF over accumulated gossip vectors **beats a popularity
baseline on long-tail discovery**; in-transit privacy (chopping or clamp-Laplace DP) costs
bounded quality without ever breaching the long-tail floor; the novelty term is **genuine
passive Sybil damping** (a cold-item push defeats itself) with FoolsGold as the active backstop;
and PSI peer selection helps while privacy-preserving identity rotation costs < 20%. See
[`impl/README.md`](./impl/README.md) for the full findings and the spec→code map.

**Crypto core, machine-checked.** `impl/easycrypt/` contains EasyCrypt proofs of the
verifiable-encryption core behind the forward-secrecy mechanism — confidentiality (IND-CPA →
DDH), decryption correctness, binding, and sigma-protocol extraction — five lemmas, no `admit`s.

**Feasibility, measured.** `impl/spike_stmt5_proving/` benchmarks the handoff ZK proof: the
Poseidon/SMT core of the adopted publish-`s₁` design proves in ~30 ms on desktop (the original
in-circuit-pairing wall is gone), with one residual term (the verifiable-encryption "bridge")
whose verdict depends on its circuit size — the next thing to build. See
[SPIKE-statement5.md §9](./SPIKE-statement5.md).

---

## Threat model & assumptions

PrivaCF defends against opportunists, sustained commercial promoters, coordinated campaigns,
and — most subtly — identity cyclers who try to escape a ban (defeated by the nullifier and
the admission cost) or to deanonymize users (defeated by commit-reveal ordering and a
validator-only, slashable decryption lock). Full taxonomy in
[SPEC.md §7](./SPEC.md#7-sybil-resistance).

The whole thing rests on four explicit assumptions:

- **A1 — Honest neighbor.** Every node has ≥ 1 honest gossip peer per epoch.
- **A2 — Honest majority by weight.** > ½ of accumulated reputation weight is honest.
- **A3 — Resource-bounded adversary.** Can't outrun the VDF, break standard primitives, or
  predict the randomness beacon.
- **A4 — Time-bounded genesis.** The bootstrap set is trusted for a finite period only — the
  standard BFT bootstrap axiom.

Out of scope: nation-state adversaries, compromise of the external randomness beacon, eclipse
attacks. Use Tor or I2P if your threat model needs it.

---

## Documentation map

- **Start here (no math):** [EXPLAINER.md](./EXPLAINER.md)
- **The whole design:** [SPEC.md](./SPEC.md) — and quick links:
  [§2 architecture](./SPEC.md#2-system-overview) ·
  [§4 identity & privacy](./SPEC.md#4-identity-and-privacy) ·
  [§7 Sybil resistance](./SPEC.md#7-sybil-resistance) ·
  [§9 implementation plan](./SPEC.md#9-implementation-plan) ·
  [§10 open questions](./SPEC.md#10-open-questions-and-status) ·
  [§11 comparative analysis](./SPEC.md#11-comparative-analysis)
- **Why it's secure:** [SECURITY.md](./SECURITY.md) (proof sketches for P1–P5 + the gate)
- **The forward-secrecy construction:** [DESIGN-f1-verifiable-encryption.md](./DESIGN-f1-verifiable-encryption.md)
- **Can it be built?** [SPIKE-statement5.md](./SPIKE-statement5.md) · [ANALYSIS-dkg-load.md](./ANALYSIS-dkg-load.md)
- **The code:** [impl/README.md](./impl/README.md)

---

## Status of this repository

This is active research. The specification and proofs are evolving; the recommendation-layer
PoC is stable and passing its gates; the substrate is the next major build. Issues and
discussion are welcome — the [open questions](./SPEC.md#10-open-questions-and-status) are a good
place to see what's genuinely undecided versus what's calibration work for later phases.

## License

Copyright (C) 2026 the PrivaCF authors.

PrivaCF is free software, licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later) — see [LICENSE](./LICENSE). AGPL is deliberate: because PrivaCF is meant to
run as a decentralized network service, the AGPL's §13 ensures that anyone who operates a
modified version **over a network** must offer their users the corresponding source. Plain GPL
would not reach network operators; AGPL does. Strong copyleft, all the way down.
