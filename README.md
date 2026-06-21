# PrivaCF

**A privacy-preserving, decentralized recommendation protocol — with a working substrate.**
No server owns your data, no one can read what you like, and fake accounts can't cheaply drown
out real taste.

*License: [AGPL-3.0-or-later](./LICENSE) · Spec: v0.3.1 · Status: research prototype (not production)*

---

## The one hard problem

Every major recommender learns what you like by collecting your identity and history on a server
you don't control. PrivaCF asks whether that's avoidable, against a **three-way tension** prior
work only ever resolves two-at-a-time:

- **Personalization** needs preference data.
- **Privacy** needs that data unreadable by anyone else.
- **Integrity** needs recommendations to reflect real human taste, not signals manufactured by
  fake accounts.

PrivaCF attempts all three with **no trusted operator in the middle** — and the substrate below
demonstrates the integration actually composes. The plain-language tour is
[EXPLAINER.md](./EXPLAINER.md) (no math).

---

## Status — what runs vs. what's designed

The honest map. Claims throughout the docs are tagged **proven / machine-checked**, **proof
sketch**, or **assumed** — and this table is the same discipline applied to the code.

| Layer | State |
|---|---|
| **Rust substrate** (`impl/mvp_node/`) — identity · Noise network · BFT consensus · Loopix mixnet · VDF · DKG/threshold-BLS · ZK · recommendation | ✅ **working prototype** — 37 modules, ~14k lines, 138 tests across 23 integration suites |
| **End-to-end private recommendation** | ✅ **runs in-loop** — a Sybil cohort is bounded and the honest co-liked item surfaces, over real on-chain epoch transactions (`tests/recommendation*.rs`) |
| **Forward-secure suspension** ("banned means banned") | ✅ **runs** — dark-node nullifier extraction from public chain data (`tests/dark_node.rs`); ZK rejoin-gate in-loop (`tests/stmt5_admission.rs`) |
| **Recommendation quality** | ✅ **PoC validated** — Python experiments E1–E4 + temporal on MovieLens, beats a popularity baseline on long-tail discovery |
| **Crypto core** | ✅ **machine-checked** — verifiable-encryption confidentiality/binding/extraction in EasyCrypt (`impl/easycrypt/`, 5 lemmas, no `admit`s) |
| **Security properties P1–P5** | ◐ reduction-level **proof sketches** + key pieces machine-checked |
| **The `d_T↔s₂` VerEnc bridge** | ⚠️ **AMBER** — the one cross-field ZK gadget is a native validator-side check, not yet in-circuit (measured, deliberately deferred) |
| **Decentralized social layer** (sibling design corpus) | 📐 **design only** — see [Design vision](#design-vision-separate-not-built) |

**Deliberate simplifications** (named, not hidden): single-round consensus, hash-chain beacon
(vs. drand+VDF), DH-PSI (vs. Pinkas-OT), and a **presupposed honest genesis / proof-of-personhood**
— the standard bootstrap axioms, called out where they're load-bearing.

---

## See it run

```bash
git clone https://github.com/iversonianGremling/privaCF.git
cd privaCF
```

**The cryptography** — Rust substrate (consensus, mixnet, threshold crypto, ZK):

```bash
cd impl/mvp_node
cargo test                        # full suite: 138 tests, 23 integration suites
cargo test --test recommendation  # Sybil cohort bounded → honest recommendation surfaces
cargo test --test dark_node       # recover a banned key's nullifier from public chain data alone
cargo test --test stmt5_admission # a suspended identity blocked from rejoining, in ZK
```

**The recommendation** — Python, on MovieLens:

```bash
cd impl
pip install -r requirements.txt
python3 -m privacf.experiment    --dataset ml-1m    # does it recommend at all?
python3 -m privacf.experiment_e3 --dataset ml-100k  # Sybil damage by attack type
```

---

## How it works, briefly

A behavioral sketch; primitives are defined precisely in [SPEC.md](./SPEC.md).

- **Getting recommendations.** Your node keeps a preference vector entirely local. Each epoch it
  exchanges a *shuffled, partially-transmitted, noised* version with a few peers whose tastes
  overlap — peers found via PSI *without* revealing what those tastes are. Ranking runs on your
  device; nothing is requested from any server.
- **Sybil resistance.** A sequential **VDF admission cost** makes fake-account flooding expensive;
  a **DSybil contribution cap** + **FoolsGold** coordination detection bound what a cohort can do
  even after it pays in.
- **Banned means banned.** On a finalized commit-reveal **SUSPEND** verdict, a validator
  attestation unseals the encrypted half of the offender's forward-secure nullifier; combined with
  the public half, anyone recovers `null_v` and folds it into a public Sparse Merkle Tree. Every
  future identity from that key fails the non-membership proof required to rejoin — *by arithmetic,
  not policy.* Absent a real verdict, **nothing decrypts**.

---

## Repository map

```
Working prototype ───────────────────────────────────────────────
impl/mvp_node/   The Rust substrate (37 modules). Consensus, mixnet, VDF, DKG/threshold-BLS,
                 SMT, verifiable encryption, verdict/dark-node, reputation, FoolsGold,
                 item-CF recommendation, DP, PSI, arbitration, zkstmt (S1-3) + zkstmt5 (rejoin).
impl/privacf/    The recommendation layer in Python (PoC): CF core, obfuscation, attacks/defenses.
impl/easycrypt/  Machine-checked proofs of the verifiable-encryption core.
impl/spike_*     Feasibility benchmarks (Statement-5 proving, modmul/bridge cost, DKG, pairing).

Specification & proofs ──────────────────────────────────────────
SPEC.md          The full specification (authoritative).
SECURITY.md      Reduction-level proof sketches for P1–P5 + the feasibility gate.
DESIGN-f1-verifiable-encryption.md   The forward-secrecy construction in full.
EXPLAINER.md     Plain-language tour, no math.
CRYPTO.md · SPIKE-statement5.md · ANALYSIS-dkg-load.md   Primitives + feasibility analyses.
```

---

## Design vision (not built)

A companion design corpus explores PrivaCF as the substrate for a **decentralized social network**
— posts, per-community karma, moderation-without-deanonymization, and a **bounded-identity model**
(one proof-of-personhood anchor → a capped budget of mutually-unlinkable accounts). This is
**design exploration, explicitly not implemented** — it reuses the substrate's existing ZK
machinery on paper. It lives as its own document set (`DESIGN-karma-communities`,
`DESIGN-identity-model`, `IMPLEMENTATION-DELTA`, `SLICE-1-SCOPE`) and is fenced off here on
purpose: the working claims above do not depend on it.

---

## Threat model & assumptions

Defends against opportunists, sustained commercial promoters, coordinated campaigns, and identity
cyclers escaping a ban (defeated by the nullifier + admission cost) or trying to deanonymize users
(defeated by commit-reveal ordering + a validator-only, slashable decryption lock). Full taxonomy
in [SPEC.md §7](./SPEC.md#7-sybil-resistance). Four explicit assumptions:

- **A1 — Honest neighbor:** every node has ≥1 honest gossip peer per epoch.
- **A2 — Honest majority by weight:** >½ of accumulated reputation weight is honest.
- **A3 — Resource-bounded adversary:** can't outrun the VDF, break standard primitives, or predict
  the beacon.
- **A4 — Time-bounded genesis:** the bootstrap set is trusted for a finite period only.

Out of scope: nation-state adversaries, beacon compromise, eclipse attacks. Use Tor/I2P if your
threat model needs it.

---

## License

Copyright (C) 2026 the PrivaCF authors. Free software under the **GNU Affero General Public License
v3.0 or later** ([LICENSE](./LICENSE)). AGPL is deliberate: because PrivaCF is meant to run as a
decentralized network service, §13 ensures anyone operating a modified version *over a network*
must offer their users the corresponding source. Strong copyleft, all the way down.
