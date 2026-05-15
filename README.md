# PrivaCF

## A Privacy-Preserving Decentralized Recommendation Protocol

### Design Document v0.2.9

> **Status:** Research specification. Full spec lives in [SPEC.md](./SPEC.md). This README is a behavioral orientation only.

---

## Abstract

Every major recommendation system learns what users like by collecting identity, history, and behavior on a server those users don't control. PrivaCF asks whether that has to be true.

The core challenge is a three-way tension: personalization requires preference data, privacy requires that data not be readable by others, and integrity requires that it reflects real human taste rather than manufactured signals from fake accounts. Prior work resolves at most two simultaneously. PrivaCF attempts all three.

Each participant holds a pseudonymous rotating identity tied to a computational admission cost that makes fake-account flooding expensive. Preferences are never transmitted in recoverable form — only shuffled, partially transmitted approximations that let similar users find each other without revealing what they actually like. Behavioral history is committed to a tamper-evident structure verified by a rotating committee of independent auditors via ZK proof, without access to the underlying data.

Suspension verdicts are permanent and survive identity rotation. A suspended node's nullifier — derived from their secret key — is inserted into a public Sparse Merkle Tree. Every future identity from the same key carries the same nullifier by construction; the membership proof fails by arithmetic, not by rule.

A remaining gap — a node going dark before nullifier extraction — is closed by a forward-secure commitment scheme. Every epoch, each node publishes a commitment to their nullifier encrypted under their committee's threshold BLS key. A suspension verdict serves as the decryption key, making nullifier extraction possible without node cooperation. Critically, the committee must publicly commit to their verdict before decryption is possible, so any extraction attempt is visible to the entire network before a single nullifier is recovered.

---

## 1. How It Works

This section describes the system behaviorally. Cryptographic primitives are named here but defined precisely in [SPEC.md §4](./SPEC.md#4-identity-and-privacy); a reader encountering an unfamiliar term can defer to that section without losing the thread.

### 1.1 Getting Recommendations

Alice's node holds a preference vector — a signed list of how much she likes various items — kept entirely local. Periodically, her node exchanges a shuffled, partially transmitted version of this vector with a small set of peers whose tastes overlap with hers, discovered without revealing what those tastes are. Each epoch, exactly n_v(T) elements are transmitted — a VRF-jittered count combining real preferences and cover items — so even the transmitted vector size reveals nothing about how many genuine preferences Alice holds.

Alice's node accumulates received vectors over time. Filtering and ranking happens entirely on her device. No recommendations are requested from any server — computation runs locally against data that has already arrived passively through the gossip protocol.

### 1.2 Being Part of the Network

When Alice interacts positively with an item, her node announces it to the network after a random delay, with a small amount of added noise on the rating. Negative interactions stay private. For rare items with small anonymity sets, announcement is further delayed by a VRF-derived number of epochs to prevent timing correlation.

Alice's behavioral history is summarized into a tamper-evident commitment each epoch. A rotating committee of auditors from independent clusters holds an encrypted chain of her prior commitments and can verify consistency of successive commitments via ZK proof alone, without access to the underlying data. Public verdicts and anonymized reputation attestations are written to the public blockchain. Fine-grained behavioral data, continuity proofs, and handoff history are held on the committee chain, readable only by threshold committee members.

### 1.3 When Something Goes Wrong

If Alice's recommendations start degrading, her node signals this to the network. If enough independent nodes signal the same thing, a rotating committee of auditors is assembled to investigate. Audits are indistinguishable from normal protocol traffic.

If a node is found to be manipulating the network, the committee initiates a commit-reveal verdict process. Each committee member first publishes a commitment to their verdict on the public chain — locking in their decision before decryption is possible — then publishes their BLS share alongside the verdict. Once a threshold of shares is revealed, anyone can aggregate them to decrypt the node's forward-secure nullifier commitment and recover `null_v`.

The suspended node's nullifier is inserted into the suspended nullifier tree (SUSP_SMT). Creating a new identity from the same key is impossible: every future epoch ID derived from that key carries the same nullifier by construction, and the non-membership proof fails at the first handoff. Creating a new identity with a genuinely different key requires completing the full admission proof chain again, and new identities matching the behavioral fingerprint of a suspended one are flagged on arrival.

Any node can monitor the public chain for anomalous commit-reveal activity — an unexpected burst of verdict commitments with no corresponding behavioral signals triggers watchdog broadcasts and recursive oversight.

### 1.4 Joining the Network

Creating an identity requires completing a chain of sequential computational proofs over n epochs, interspersed with mandatory protocol interactions with existing nodes. Once all n proofs are complete and all interaction checkpoints have been passed, the identity is admitted and begins accumulating reputation. There are no partial admissions — the proof chain must be completed in full.

### 1.5 The Adversary Model

**The opportunist** creates a handful of fake accounts to boost their own content. Defended by admission cost, temporal depth, rate limits, and behavioral fingerprinting.

**The commercial promoter** operates a sustained campaign of fake accounts with enough patience to build reputation before exploiting it. Defended by the non-overwhelming trust rule, smoothness detection, and within-cluster coordination detection across both interest and behavioral cluster dimensions.

**The coordinated campaign** involves many accounts pushing a narrative across many items simultaneously. The system surfaces behavioral anomaly patterns for operator review. Intent classification requires human judgment.

**The epoch rotator** earns a SUSPENDED verdict then attempts to re-enter under a new identity derived from the same key. Defended by the nullifier mechanism: the same key always produces the same nullifier, which is permanently in the suspended set. Re-entry from the same key is cryptographically impossible.

**The dark node rotator** earns a SUSPENDED verdict and goes offline before their nullifier is extracted, then attempts to re-admit from the same key. Defended by forward-secure commitment: the committee decrypts `commit_T` using the verdict as a key, without requiring node cooperation. The residual gap — nodes that go dark during the admission window before publishing any `commit_T` — is bounded by zero reputation and behavioral fingerprinting.

**The rogue committee** attempts mass deanonymization by extracting `null_v` from many nodes without legitimate verdicts. Defended by the commit-reveal ordering: the committee must publicly commit to verdicts before decryption is possible. Anomalous commit rates are visible on the public chain before any `null_v` is recovered, triggering watchdog signals and recursive oversight.

Nation-state adversaries, compromise of the external randomness beacon, and eclipse attacks are out of scope. Use Tor or I2P if the threat model requires it.

### 1.6 Assumptions

**A1 — Honest neighbor.** Every node has at least one honest gossip peer per epoch.

**A2 — Honest majority by weight.** More than half of total accumulated reputation weight belongs to honest nodes.

**A3 — Resource-bounded adversary.** Cannot solve VDFs faster than specified delay, cannot break standard cryptographic primitives, cannot predict the drand beacon before publication, cannot find Poseidon collisions, cannot break BLS signature unforgeability.

**A4 — Time-bounded genesis.** The initial bootstrap set is trusted for a finite period only. This is the standard bootstrap assumption for Byzantine-fault-tolerant systems and is treated as an axiom rather than a derived property. A network that cannot trust its genesis set generates a regress that no purely cryptographic mechanism resolves.

---

## Where to go next

The full specification — notation, formal definitions, ZK proof system, network layer, reputation and audit, Sybil resistance, known limitations, implementation plan, open questions, comparative analysis, and appendices — is in **[SPEC.md](./SPEC.md)**.

Quick links into the spec:

- [§2 System Overview](./SPEC.md#2-system-overview) — five-layer architecture diagram
- [§4 Identity and Privacy](./SPEC.md#4-identity-and-privacy) — Poseidon PRF, EC-VRF, VDF, Pedersen, nullifier, ForwardCommit, commit-reveal verdicts
- [§7 Sybil Resistance](./SPEC.md#7-sybil-resistance) — attack taxonomy, temporal depth, DSybil rule, FoolsGold, compound flag system, [detection contract (§7.9)](./SPEC.md#79-detection-contract)
- [§9 Implementation Plan](./SPEC.md#9-implementation-plan) — minimal viable PrivaCF, PoC phases, evaluation metrics
- [§10 Open Questions and Status](./SPEC.md#10-open-questions-and-status) — open vs. resolved prerequisites
- [§11 Comparative Analysis](./SPEC.md#11-comparative-analysis) — vs. EigenTrust, DSybil, GOSSPLE, Web3Recommend/MeritRank, Hegedűs gossip MF, McSherry & Mironov, Cyffers et al.
