# PrivaCF

## A Privacy-Preserving Decentralized Recommendation Protocol

### Design Document v0.3.0

> **Status:** Research specification. §10.1 lists open questions. §10.2 lists resolved prerequisites.

---

## Notation

| Symbol              | Meaning                                             | First defined |
| ------------------- | --------------------------------------------------- | ------------- |
| `sk`                | Long-term secret key                                | §4.2          |
| `null_v`            | Nullifier: `Poseidon(sk, "null_v")`                 | §4.9.1        |
| `epoch_id_T`        | Pseudonymous identity for epoch T                   | §4.2          |
| `beacon_T`          | Public randomness beacon for epoch T                | §4.1          |
| `C_p(T)`            | Pedersen commitment to preference vector            | §4.4          |
| `p_v`               | Signed preference vector (local only)               | §4.4          |
| `r_p`               | Pedersen blinding factor                            | §4.4          |
| `M_v(T)`            | Merkle root of behavioral history                   | §4.6          |
| `π_v(T)`            | Per-epoch permutation of preference vector          | §4.5          |
| `n_v(T)`            | VRF-jittered gossip vector element count            | §4.5          |
| `commit_T`          | Forward-secure nullifier commitment                 | §4.9.4        |
| `null_v_decryption` | On-chain transaction recovering null_v post-verdict | §4.9.6        |
| `dec_nullifier`     | `Poseidon(verdict_hash, null_v)`                    | §4.9.3        |
| `D_v(T)`            | Temporal depth of node v at epoch T                 | §7.2          |
| `SUSP_SMT`          | Sparse Merkle Tree of suspended nullifiers          | §4.9.2        |
| `DECRYPTION_SMT`    | Sparse Merkle Tree of executed decryptions          | §4.9.3        |
| `θ_cluster`         | Jaccard similarity threshold for peer selection     | §5.4          |
| `θ_behavioral`      | Behavioral fingerprint similarity threshold         | §6.3          |
| `c`                 | Trust cap (DSybil non-overwhelming parameter)       | §7.3          |
| `n`                 | Admission window length in epochs                   | §4.3          |
| `K_committee`       | Auditor committee size                              | §6.4          |
| `K_validators`      | Validator set size                                  | §4.1          |
| `n_commit`          | Epochs between public chain commits                 | §4.1          |
| `δ_decay`           | Per-epoch reputation decay                          | §6.1          |
| `μ`                 | Hop-distance trust attenuation factor               | §5.7          |
| `λ`                 | Temporal depth decay factor                         | §7.2          |
| `β`                 | Global/cluster trust blending factor                | §3.4          |
| `κ`                 | Novelty bonus scaling factor                        | §3.7          |

---

## Abstract

Every major recommendation system learns what users like by collecting identity, history, and behavior on a server those users don't control. PrivaCF asks whether that has to be true.

The core challenge is a three-way tension: personalization requires preference data, privacy requires that data not be readable by others, and integrity requires that it reflects real human taste rather than manufactured signals from fake accounts. Prior work resolves at most two simultaneously. PrivaCF attempts all three.

Each participant holds a pseudonymous rotating identity tied to a computational admission cost that makes fake-account flooding expensive. Preferences are never transmitted in recoverable form — only shuffled, partially transmitted approximations that let similar users find each other without revealing what they actually like. Behavioral history is committed to a tamper-evident structure verified by a rotating committee of independent auditors via ZK proof, without access to the underlying data.

Suspension verdicts are permanent and survive identity rotation. A suspended node's nullifier — derived from their secret key — is inserted into a public Sparse Merkle Tree. Every future identity from the same key carries the same nullifier by construction; the membership proof fails by arithmetic, not by rule.

---

## Table of Contents

- [1. How It Works](#1-how-it-works)
  - [1.1 Getting Recommendations](#11-getting-recommendations)
  - [1.2 Being Part of the Network](#12-being-part-of-the-network)
  - [1.3 When Something Goes Wrong](#13-when-something-goes-wrong)
  - [1.4 Joining the Network](#14-joining-the-network)
  - [1.5 The Adversary Model](#15-the-adversary-model)
  - [1.6 Assumptions](#16-assumptions)
- [2. System Overview](#2-system-overview)
  - [2.1 Node Relationships](#21-node-relationships)
- [3. Collaborative Filtering](#3-collaborative-filtering)
  - [3.1 Goal](#31-goal)
  - [3.2 Computing Recommendations](#32-computing-recommendations)
  - [3.3 Clusters](#33-clusters)
  - [3.4 Trust Weight and Local trust_total](#34-trust-weight-and-local-trust_total)
  - [3.5 Dislike-Aware Scoring](#35-dislike-aware-scoring)
  - [3.6 User-Configurable Reputation Floor](#36-user-configurable-reputation-floor)
  - [3.7 Diversity and Novelty](#37-diversity-and-novelty)
- [4. Identity and Privacy](#4-identity-and-privacy)
  - [4.1 The Dual-Chain Architecture](#41-the-dual-chain-architecture)
  - [4.2 Rotating Pseudonymous Identity](#42-rotating-pseudonymous-identity)
  - [4.3 Identity Admission Cost](#43-identity-admission-cost)
  - [4.4 Preference Privacy](#44-preference-privacy)
  - [4.5 Preference Obfuscation in Transit](#45-preference-obfuscation-in-transit)
  - [4.6 Tamper-Evident Behavioral History](#46-tamper-evident-behavioral-history)
  - [4.7 Cross-Epoch Identity Continuity](#47-cross-epoch-identity-continuity)
  - [4.8 PSI Cache Decay](#48-psi-cache-decay)
  - [4.9 Nullifier, Suspension Persistence, and Dark Node Closure](#49-nullifier-suspension-persistence-and-dark-node-closure)
- [5. Network](#5-network)
  - [5.1 Transport](#51-transport)
  - [5.2 Uniform Message Frames](#52-uniform-message-frames)
  - [5.3 Node Discovery and Cluster Re-Discovery](#53-node-discovery-and-cluster-re-discovery)
  - [5.4 Interest Cluster Peer Selection — Asymmetric PSI](#54-interest-cluster-peer-selection--asymmetric-psi)
  - [5.5 Relay Submission](#55-relay-submission)
  - [5.6 Staggered Epochs](#56-staggered-epochs)
  - [5.7 Two-Tier Peer Selection](#57-two-tier-peer-selection)
  - [5.8 Communication Rhythm](#58-communication-rhythm)
- [6. Reputation and Audit](#6-reputation-and-audit)
  - [6.1 Per-Epoch Score](#61-per-epoch-score)
  - [6.2 Behavioral Cluster Computation](#62-behavioral-cluster-computation)
  - [6.3 Admission and First-Observation Interrogation](#63-admission-and-first-observation-interrogation)
  - [6.4 Multi-Auditor Encrypted State Handoff](#64-multi-auditor-encrypted-state-handoff)
  - [6.5 Audit Classes](#65-audit-classes)
  - [6.6 Rewind Signals and HNSW Snapshots](#66-rewind-signals-and-hnsw-snapshots)
  - [6.7 Health Tiers](#67-health-tiers)
- [7. Sybil Resistance](#7-sybil-resistance)
  - [7.1 Attack Taxonomy](#71-attack-taxonomy)
  - [7.2 Temporal Depth](#72-temporal-depth)
  - [7.3 DSybil Non-Overwhelming Rule](#73-dsybil-non-overwhelming-rule)
  - [7.4 Within-Cluster FoolsGold](#74-within-cluster-foolsgold)
  - [7.5 Smoothness Detection](#75-smoothness-detection)
  - [7.6 Weight Caps and Gini Monitoring](#76-weight-caps-and-gini-monitoring)
  - [7.7 Tamper Analysis](#77-tamper-analysis)
  - [7.8 Compound Flag System and Alert Levels](#78-compound-flag-system-and-alert-levels)
  - [7.9 Detection Contract](#79-detection-contract)
- [8. Known Limitations](#8-known-limitations)
  - [8.1 What Is Not Protected](#81-what-is-not-protected)
  - [8.2 Unresolved Design Tensions](#82-unresolved-design-tensions)
- [9. Implementation Plan](#9-implementation-plan)
  - [9.1 Minimal Viable PrivaCF](#91-minimal-viable-privacf)
  - [9.2 PoC Phases](#92-poc-phases)
  - [9.3 Evaluation Metrics](#93-evaluation-metrics)
- [10. Open Questions and Status](#10-open-questions-and-status)
  - [10.1 Open Questions](#101-open-questions)
  - [10.2 Resolved Prerequisites](#102-resolved-prerequisites)
  - [10.3 Proposed Experiments](#103-proposed-experiments)
- [11. Comparative Analysis](#11-comparative-analysis)
  - [11.1 Identity and Privacy Properties](#111-identity-and-privacy-properties)
  - [11.2 Sybil Resistance and Audit Properties](#112-sybil-resistance-and-audit-properties)
  - [11.3 Narrative Analysis](#113-narrative-analysis)
- [12. Related Work](#12-related-work)
- [13. Recommendation Layer: Open Problems for Deployment](#13-recommendation-layer-open-problems-for-deployment)
- [Appendix A — Full Message Schemas](#appendix-a--full-message-schemas)
- [Appendix B — What Each Node Holds](#appendix-b--what-each-node-holds)
- [Appendix C — Reputation Decision Tree](#appendix-c--reputation-decision-tree)
- [Appendix D — Node Lifecycle](#appendix-d--node-lifecycle)
- [Appendix E — Implementation Readiness](#appendix-e--implementation-readiness)
- [Appendix F — Configuration Reference](#appendix-f--configuration-reference)
- [Appendix G — Node Relationship Diagram](#appendix-g--node-relationship-diagram)
- [Appendix H — Identity and Privacy Relationship Diagram](#appendix-h--identity-and-privacy-relationship-diagram)
- [Appendix I — PSI Peer Selection Flow](#appendix-i--psi-peer-selection-flow)

---

## 1. How It Works

This section describes the system behaviorally. Cryptographic primitives are named here but defined precisely in §4; a reader encountering an unfamiliar term can defer to that section without losing the thread.

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

## 2. System Overview

PrivaCF is organized into five layers plus a dual-chain structure that underpins the entire system's state.

```
┌─────────────────────────────────────────────────┐
│  LAYER 5 · Collaborative Filtering               │
│  Computed locally · Never transmitted            │
├─────────────────────────────────────────────────┤
│  LAYER 4 · Reputation & Audit                    │
│  Behavioral commitments · Multi-auditor handoff  │
│  On-chain verdicts · Permanent health state      │
│  Commit-reveal verdict flow                      │
├─────────────────────────────────────────────────┤
│  LAYER 3 · Sybil Resistance                      │
│  Weight caps · Temporal cost · Anomaly detection │
│  Interest clusters · Behavioral clusters         │
│  Watchdog signals · Recursive oversight          │
├─────────────────────────────────────────────────┤
│  LAYER 2 · Network                               │
│  Loopix/Sphinx · Dandelion++ · PSI peer sel.     │
│  Relay submission · Niche item delay             │
├─────────────────────────────────────────────────┤
│  LAYER 1 · Identity & Privacy                    │
│  Poseidon PRF · EC-VRF · VDF · Pedersen · Perm   │
│  Merkle · Nullifier · SUSP_SMT                   │
│  ForwardCommit · DECRYPTION_SMT                  │
├─────────────────────────────────────────────────┤
│  PUBLIC CHAIN · Verdicts & Attestations          │
│  VDF-chained · BFT consensus · Deterministic     │
│  finality · Permanent verdicts · SUSP_SMT root   │
│  DECRYPTION_SMT root · commit_T per node/epoch   │
│  Light clients                                   │
├─────────────────────────────────────────────────┤
│  COMMITTEE CHAIN · Sensitive State               │
│  Threshold-held · Encrypted · Continuity proofs  │
│  Fine-grained behavioral data · Handoff history  │
└─────────────────────────────────────────────────┘
```

### 2.1 Node Relationships

See Appendix G for the full node relationship diagram. In brief: each node maintains peers in two tiers — an interest cluster tier (2–3 nodes confirmed by PSI) and a bridge tier (1 random DHT peer refreshed each epoch). Auditor committees and validator sets are VRF-selected each epoch with dual cluster diversity constraints; neither is predictable before the beacon is published.

**On validator and committee discoverability:** VRF selection means any node can verify who was selected for a given epoch after the beacon is published, but cannot predict it in advance. The cluster diversity constraints are checked deterministically against each candidate's attested cluster membership on the public chain.

**Bootstrapping beyond genesis:** The genesis validator set covers the period before enough nodes have accumulated sufficient temporal depth and cluster diversity. When cluster diversity constraints cannot yet be fully satisfied, the behavioral cluster constraint is relaxed during the transition period, falling back to interest cluster diversity only. The transition threshold requires empirical calibration (OQ-12).

---

## 3. Collaborative Filtering

### 3.1 Goal

Given a node's interaction history and a set of gossip vectors received from peers over many epochs, produce a ranked list of items the node has not interacted with that it is likely to enjoy. The filtering and ranking computation happens entirely on the local device. The network's role is to deliver gossip vectors — it does not participate in the recommendation computation itself.

The CF algorithm is not fixed by the protocol. Item-based collaborative filtering is the default and is specified below, but any algorithm that operates on a matrix of received gossip vectors can be substituted.

### 3.2 Computing Recommendations

PrivaCF uses item-based collaborative filtering as its primary method. If items A and B tend to appear together in peer preference vectors, and Alice likes item A, she probably likes item B.

Each node maintains a local HNSW index built from gossip vectors received from peers over many epochs. Item similarity is computed from this index:

```
sim(item_i, item_j) = cosine_similarity(column_i(P), column_j(P))
score(item_i)       = Σ_{j ∈ interacted} sim(item_i, j) × weight(j)
```

where P is the matrix of received gossip vectors. Fully offline. Each node sends one gossip vector push per epoch and receives one per peer per epoch. Recommendation quality improves as the local index grows over many epochs.

User-based CF is applied as a within-epoch supplement. Item-based CF is preferred because it is stable across epoch rotation.

Two data structures serve different roles:

- **LSH** (Indyk & Motwani, 1998): fast approximate bucketing at the network layer for PSI candidate identification.
- **HNSW** (Malkov & Yashunin, 2018): high-quality approximate nearest-neighbor search for recommendation computation.

### 3.3 Clusters

PrivaCF organizes nodes into two independent cluster types, both derived from public data without any central coordinator.

**Interest clusters** group nodes whose item interaction sets overlap significantly, as measured by Jaccard similarity via PSI. Two nodes end up in the same interest cluster because they have interacted with many of the same items — not because they were assigned to one. Interest clusters drive peer selection and CF quality.

**Behavioral clusters** group nodes with similar participation patterns — when they are active within an epoch, how they space out announcements, when they submit on-chain transactions. These are derived entirely from public timing data on the blockchain. Behavioral clusters are used for Sybil detection and to ensure auditor committee independence. They are never used directly for reputation — they feed the compound flag system described in §7.

Cluster membership is not fixed. It is recomputed each epoch from current data and evolves as a node's interaction history grows.

**Privacy implications:** Interest cluster membership is partially inferable by an external observer who watches PSI handshake patterns over time. Behavioral cluster membership is fully reconstructable by any observer from public chain timing data by design. The dual-chain model, per-n-epoch commits, relay submission, and transaction timing jitter collectively degrade the precision of behavioral fingerprints but do not eliminate them.

### 3.4 Trust Weight and Local trust_total

```
trust_contribution(v, X) = max(0, r_v(X) + noise) × Δ × (1 + κ × novelty(X))
```

`trust_total(item)` is not stored on the blockchain. Each node maintains a local estimate updated from received announcements weighted by announcer reputation band. Divergence across nodes is acceptable — CF requires only local consistency.

Items globally popular but not popular within a node's interest cluster are softened:

```
effective_trust(X) = β × global_trust_total(X) + (1−β) × cluster_trust_total(X)
item_weight(X)     = 1 / log(1 + effective_trust(X) / c)
```

### 3.5 Dislike-Aware Scoring

Negative preference weights are never transmitted. Dislikes are applied locally as a post-processing filter only:

```
final_score(item_i) = raw_cf_score(item_i)
    − penalty × max(0, Σ_{j ∈ dislike_set} sim(item_i, j) × |p_v[j]|)
```

### 3.6 User-Configurable Reputation Floor

Each node sets a minimum reputation band for gossip vectors incorporated into its local HNSW index. Default: Band 2.

### 3.7 Diversity and Novelty

```
novelty(item)  = 1 − effective_trust(item) / c
Δ_trust(v, X) = Δ_base × (1 + κ × novelty(X))
```

Novel items accumulate trust weight faster. Nodes in sparse interest clusters receive additional CF aggregation weight.

> The protocol does not prescribe a recommendation algorithm. For a full discussion of the deployment-level tensions this creates — sparsity, feedback loops, reputation interaction, epoch length, positive-only signal, niche privacy tradeoffs, and the boundary between organic popularity and coordinated pushing — see §13.

---

## 4. Identity and Privacy

Each cryptographic primitive solves one specific problem. To orient the reader before the formal definitions: a node's long-term key `sk` never leaves the device. From it, the node derives a per-epoch pseudonym (`epoch_id_T`) that is unlinkable across epochs, a permanent nullifier (`null_v`) that ties all epoch IDs together without revealing the link, and a forward-secure commitment (`commit_T`) that lets the committee extract `null_v` after a verdict without any cooperation from the node. The ZK proof system lets auditors verify properties of preference and behavior data they cannot read. The diagram below shows how these relate before each is introduced individually.

See Appendix H for the full identity/privacy relationship diagram.

### 4.1 The Dual-Chain Architecture

PrivaCF's public state is split across two purpose-built chains with different trust and visibility properties.

**The public blockchain** is the authoritative record for verdicts, anonymized reputation attestations, epoch_id registrations, `commit_T` values, and the SUSP_SMT and DECRYPTION_SMT roots. It is a VDF-chained ledger with Byzantine fault-tolerant consensus. Every node can read and verify it.

**The committee chain** is a threshold-held encrypted ledger maintained by rotating auditor committees. It stores continuity proofs, fine-grained behavioral data, handoff history, and first-observation reports. Only a threshold of committee members can read any entry.

**Public blockchain block structure:**

```
block_T = {
    height:                T,
    vdf_output_T:          VDF_eval(vdf_output_{T-1}, δ_block),
    prev_block_hash:       H(block_{T-1}),
    primary_entries:       [high-priority transactions for epoch T],
    beacon_T:              H(drand_T ‖ vdf_output_{T-1}),
    proposer_id:           <VRF-selected proposer epoch_id>,
    validator_sigs:        <threshold BLS aggregate signature>,
    susp_smt_root_T:       <root of SUSP_SMT>,
    decryption_smt_root_T: <root of DECRYPTION_SMT>
}
```

**Two-level transaction pool:**

```
PRIMARY POOL (packed into blocks immediately):
    committee_verdict
    verdict_commit          ← per-member verdict commitment
    verdict_reveal          ← per-member BLS share + verdict
    null_v_decryption       ← recovered null_v + DECRYPTION_SMT insertion
    double_signing_evidence
    Class 3 audit results
    epoch_transaction       ← includes commit_T and commit_T_zk_proof every epoch
    admission_summary
    watchdog_signal

SECONDARY POOL (accumulated, merged at epoch end):
    announcement_observation
    pull_receipt
    audit_nonce_record
    rate_limit_event
```

**commit_T and n_commit batching:** `commit_T` and its ZK proof are included in the `epoch_transaction` and submitted every epoch. `M_v(T)`, `C_p(T)`, score band, and health tier batch per `n_commit`. The rationale: `commit_T` must be tied to the current epoch's committee threshold BLS key, which rotates every epoch; batching would create key staleness. `commit_T` is opaque without a verdict signature and reveals only node presence, which is already inferrable from `epoch_id` registration.

**DKG timing constraint:** Committee DKG must complete before a node constructs and submits `commit_T`. DKG for K≈21 nodes is fast in practice. The `epoch_transaction` submission deadline is set after DKG completion.

At epoch end, all secondary pool entries are aggregated into a single `epoch_transaction`. The secondary pool entries are discarded.

**Legitimacy verification:** An `epoch_transaction` carries two independent authenticity guarantees. First, it is signed by the submitting node's `epoch_id` key. Second, each field is either cryptographically committed or committee-attested before the transaction is assembled. Validators verify the node's signature, the committee's threshold BLS signature on the score band, and the ZK proof certifying correct `commit_T` formation.

**Block production:**

```
validator_set_T = EC-VRF(sk_proposer, beacon_T ‖ "validators",
                      k = K_validators,
                      constraints = [
                          temporal_depth ≥ D_validator,
                          reputation ≥ rep_validator,
                          different_interest_clusters,
                          different_behavioral_clusters
                      ])

proposer_T = EC-VRF(sk_proposer, beacon_T ‖ "proposer", pool = validator_set_T)
```

The proposer assembles the block from pending transactions and broadcasts it. Validators verify and sign with BLS. Once ⌊K_validators / 3⌋ × 2 + 1 signatures are collected, the block is final. Deterministic finality. K_validators ≈ 21 is a reasonable default.

**Validator incentives:**

```
score_v(T) += w_validator × validator_service_indicator(T)
```

**Liveness — proposer timeout:** If the proposer does not produce a block within a timeout window (default: 20% of epoch duration), the next VRF-ranked validator in the set takes over.

**Double-signing detection:** Two BLS signatures from the same `epoch_id` on competing blocks at the same height are both on-chain and publicly verifiable. Consequence: immediate permanent SUSPENDED verdict.

**Light clients:** Mobile nodes store block headers only and use Merkle inclusion proofs to verify specific entries.

**Per-n-epoch public chain commits:** The `epoch_transaction` merge fires every `n_commit` epochs for `M_v`, `C_p`, score band, and health tier, reducing on-chain timing resolution available for behavioral fingerprinting. `commit_T` is exempt. n_commit = 2 or 3 is a reasonable starting range.

### 4.2 Rotating Pseudonymous Identity

**Problem:** The same identity across epochs makes a node's activity linkable over time.

**Tool:** Poseidon as a keyed PRF for local per-epoch derivations, and EC-VRF (RFC 9381) for on-chain verifiable selection. Given a secret key, a nullifier, and the current beacon, the PRF produces a pseudonym for this epoch. Epoch IDs are unlinkable across epochs without knowing `sk`.

```
null_v     = Poseidon(sk, "null_v")
epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")
```

**Primitive split — Poseidon PRF for local derivations, EC-VRF for on-chain selection:** Local per-epoch derivations (epoch ID, permutation, chop count, offset, niche delay, leaf salt) require only pseudorandomness under a secret key — a PRF, not a full VRF. Poseidon as a keyed hash satisfies this under the same assumptions used throughout the protocol, and evaluates in a few hundred Plonky3 constraints. On-chain verifiable selection (validator set, committee, relay) requires unpredictability plus publicly verifiable proof of correct evaluation — a true VRF. EC-VRF (RFC 9381) is used for these, reducing to DLEQ/DDH with production implementations in tendermint-rs (already in the stack). EC-VRF verification happens on-chain by validators, not inside ZK circuits, so circuit cost is not a concern for these uses.

**Epoch ID unlinkability:** `beacon_T` rotates every epoch, so `epoch_id_T` values are computationally unlinkable across epochs without `sk`, regardless of `null_v` being a shared input.

**All per-epoch VRF derivations** use Poseidon with explicit domain separators:

| Derivation           | Expression                                                  |
| -------------------- | ----------------------------------------------------------- |
| Epoch ID             | `Poseidon(sk, beacon_T, null_v, "epoch_id")`                |
| Permutation          | `Poseidon(sk, beacon_T, "perm")`                            |
| Chop count           | `Poseidon(sk, beacon_T, "chop_n")`                          |
| Epoch offset         | `Poseidon(sk, "epoch_offset")`                              |
| Niche announce delay | `Poseidon(sk, item_hash, beacon_T, "niche_delay")`          |
| Committee token      | `Poseidon(committee_sk, epoch_id_v, T, "continuity_token")` |
| Leaf salt            | `Poseidon(sk, epoch_T, "leaf_salt")`                        |

All derivations must use distinct (domain_sep, input) pairs for any `sk`. Domain separator collision check resolved — all derivations now have explicit (domain_sep, input_structure) pairs; collision argument reduces to standard Poseidon collision resistance (OQ-4 — closed).

### 4.3 Identity Admission Cost

**Problem:** Free instant identity creation allows unlimited fake identities.

**Tool:** A VDF chain. Inherently sequential — more compute does not help.

```
vdf_proof_T = VDF_eval(vdf_proof_{T-1}, δ_identity)
VDF_verify_chain([vdf_proof_{T-n}, ..., vdf_proof_T], n, δ_identity) = true
```

**Admission is binary.** At the epoch when admission completes, the node's first handoff must include a valid Statement 5 non-suspension proof and a valid `commit_T` ZK proof. A node whose `null_v` is already in SUSP_SMT is rejected at admission without a separate investigation. Zero CF weight and zero routing weight during the admission window.

**Interaction checkpoints** occur at VRF-determined epochs within the admission window. At each checkpoint: PSI handshake with a randomly selected existing node, gossip vector exchange, receipt from that exchange.

**Gap tolerance:** A missed VDF proof resets chain progress to zero. Accumulated temporal depth from prior completed chains is retained.

Default n = 24 (one day). High-security n = 168 (one week).

### 4.4 Preference Privacy

**Problem:** Auditors need to verify properties of a node's preference vector without reading it.

**Tool:** A Pedersen commitment. Binding and hiding.

```
C_p(T) = p_v · G + r_p · H
```

The preference vector `p_v` is fixed for the duration of an epoch. Updates to `p_v` are only permitted at epoch transitions.

### 4.5 Preference Obfuscation in Transit

**Problem:** Even without reading a preference vector, an adversary receiving it multiple times can correlate dimensions across epochs and infer preference count from vector size.

**Tool:** Per-epoch permutation plus variable-size transmission.

```
π_v(T)  = Poseidon(sk, beacon_T, "perm")
n_v(T)  = n_base + Poseidon(sk, beacon_T, "chop_n") mod n_jitter
```

**Variable chopping:** Exactly `n_v(T)` elements are transmitted, selected from the permuted positive preference set, padded with cover items if needed. Neither the number of real preferences nor which preferences are real is inferrable from the transmitted vector size.

Only positive preference weights are included in gossip vectors. Negative weights stay local.

**Cover items:**

```
cover_weight(item) = Uniform(0, cover_scale) / log(1 + trust_total(item) / c)
```

**Chopping vs. Laplace DP** (mutually exclusive per deployment):

- **Chopping** (niche-friendly): transmit `n_v(T)` elements as above
- **Laplace DP** (mainstream, formal guarantee): `gossip_v(T)[i] += Laplace(0, S/ε)` with `‖p_v‖₁ = 1` enforced and L1 sensitivity S = 2

**Sign preservation constraint:**

```
|noise_i| < |p_v[i]|  for all i where p_v[i] ≠ 0
```

**Niche item announcement delay:**

```
announce_delay_v(item) = Poseidon(sk, item_hash, beacon_T, "niche_delay") mod max_delay_epochs
```

### 4.6 Tamper-Evident Behavioral History

**Problem:** A node needs to prove to auditors that its behavior was within protocol limits without revealing its details.

**Tool:** A Merkle tree whose leaves are built from peer attestations collected passively as a side effect of normal protocol traffic.

**Leaf structure:**

```
leaf(ANNOUNCEMENT, T)  = H("ANN"  ‖ T ‖ set_of_peer_signed_observations ‖ salt_v)
leaf(PULL_RESPONSE, T) = H("PULL" ‖ T ‖ set_of_peer_signed_receipts       ‖ salt_v)
leaf(AUDIT_RESP, T)    = H("AUD"  ‖ T ‖ auditor_published_results          ‖ salt_v)
leaf(PARTICIPATION, T) = H("PAR"  ‖ T ‖ self_reported_count ‖ salt_v)
leaf(RATE_LIMIT, T)    = H("RL"   ‖ T ‖ self_reported_count ‖ salt_v)

salt_v = Poseidon(sk, epoch_T, "leaf_salt")
M_v(T) = MerkleRoot(padded_leaves_v(T))
         // padded to a fixed protocol-wide maximum leaf count
```

**Partial reveals are safe:** Fixed padding plus per-leaf VRF salts ensure sibling hashes are opaque.

### 4.7 Cross-Epoch Identity Continuity

**Problem:** After epoch rotation, the auditor committee does not know a node's new `epoch_id` belongs to the same node.

**Tool:** A zero-knowledge proof of Poseidon PRF continuity, submitted to the committee chain only.

```
ZK { sk :
    Poseidon(sk, beacon_T,   null_v, "epoch_id") = epoch_id_T
    Poseidon(sk, beacon_T-1, null_v, "epoch_id") = epoch_id_{T-1}
    null_v = Poseidon(sk, "null_v")
}
```

`null_v` is a private witness — not a public output of this proof. Continuity proofs are never published to the public blockchain. Nodes that choose full unlinkability submit no continuity proof and sacrifice cross-epoch reputation accumulation. Sub-second on Plonky3.

**Enriched rolling chain commitment:**

```
rolling_chain_commitment(T) = Poseidon(
    rolling_chain_commitment(T-1),
    zk_continuity_proof(T),
    audit_interactions(T),
    SUSP_SMT_root_T
)
```

This ties each epoch's commitment to the suspension state at that epoch, preventing replay of old non-suspension proofs against a newer SMT.

**Committee tokens:** When a node reaches an elevated alert level, the committee issues a continuity token:

```
token_v(T)  = Poseidon(committee_sk, epoch_id_v, T, "continuity_token")
commit_v(T) = H(token_v(T))
encrypted_token = Enc(pk_v(T), token_v(T))
```

The node decrypts the token and must incorporate it into the next handoff ZK proof. A node that missed a handoff cannot produce a valid proof because it would need the token. The chain becomes a tamper-evident audit history — gaps cannot be hidden because every subsequent commitment depends on all prior ones.

### 4.8 PSI Cache Decay

```
psi_cache[new_epoch_id] = psi_cache[old_epoch_id] × λ_proof     (λ_proof ≈ 0.95)
cache_weight(U, T)      = base_weight × λ_noproof^(T − last_verified_T)  (λ_noproof ≈ 0.7)
```

Both λ values require empirical calibration (OQ-20).

### 4.9 Nullifier, Suspension Persistence, and Dark Node Closure

#### 4.9.1 The Nullifier

```
null_v = Poseidon(sk, "null_v")
```

`null_v` is:

- **Local** — computed entirely on device, never transmitted in normal operation
- **Private** — lives inside ZK proof circuits as a private witness only
- **Deterministic** — same `sk` always produces the same `null_v`
- **Stable** — does not change across epoch rotations; the beacon is not an input
- **Structurally intrinsic** — a valid `epoch_id_T` cannot be produced from `sk` without `null_v`, because `null_v` is an input to the epoch ID derivation

#### 4.9.2 The SUSP_SMT

A Sparse Merkle Tree maintained as part of the public chain state. Each leaf position corresponds to a possible `null_v` value. A leaf is non-empty if and only if that `null_v` has been inserted following a SUSPENDED verdict. The root `SUSP_SMT_root_T` is included in every block header. The tree is append-only — leaves are never removed.

Non-membership is proven by a Merkle path from the root to the empty leaf at the position `null_v` would occupy if present. This path is computed inside the ZK circuit with `null_v` as a private input. The verifier sees only proof validity, not which position was checked.

#### 4.9.3 The DECRYPTION_SMT

A Sparse Merkle Tree maintained alongside SUSP_SMT. Each leaf position corresponds to a possible `dec_nullifier` value:

```
dec_nullifier = Poseidon(verdict_hash, null_v)
```

A leaf is non-empty if and only if a `null_v_decryption` transaction has been finalized for that verdict. The root `DECRYPTION_SMT_root_T` is included in every block header. The tree is append-only.

**Purpose:** Enforces one decryption per verdict at consensus level. A second `null_v_decryption` transaction referencing the same `verdict_hash` produces the same `dec_nullifier`, which is already in the tree. Honest validators reject the block containing a duplicate. Collision resistance of `dec_nullifier` under adversarial `null_v` reduces to standard Poseidon collision resistance; `verdict_hash` is fixed on-chain before `null_v` is recovered, so chosen-input attacks are not applicable (OQ-5 — closed).

#### 4.9.4 Forward-Secure Nullifier Commitment

**Problem:** `null_v` must be available for extraction after a suspension verdict even if the node is offline, without enabling covert extraction by the committee.

**Tool:** Boneh-Franklin Identity-Based Encryption over BLS12-381 (Boneh & Franklin, CRYPTO 2001). The threshold BLS public key `threshold_BLS_pk_T` serves as the IBE master public key; the identity string is `"SUSPEND epoch_id_T"`; the aggregated threshold BLS signature on that string is the IBE private key for that identity; `null_v` is the plaintext; `commit_T` is the ciphertext. Security reduces to DBDH in the random oracle model. The implementation falls out of blst (already in the stack).

**DST alignment requirement:** The domain separation tag used for hash-to-curve in BLS signing and in IBE key derivation must be explicitly defined and verified to be compatible before implementation. RFC 9380 standardizes hash-to-curve but the specific DST must be specified in the PrivaCF codebase.

```
// At epoch start, after DKG completes:
committee_T        = VRF(beacon_T ‖ "audit_committee" ‖ epoch_id_v, ...)
threshold_BLS_pk_T = DKG_output(committee_T)   // public, derivable by anyone

// Node constructs:
commit_T = ForwardCommit(null_v, epoch_id_T, threshold_BLS_pk_T; r_commit_T)
```

`commit_T` is decryptable if and only if the holder possesses a valid threshold BLS signature from `committee_T` on the statement `"SUSPEND epoch_id_T"`.

**Decryption:** Given a valid threshold BLS aggregate signature `σ` on verdict `"SUSPEND epoch_id_T"`, anyone can compute:

```
null_v = ForwardCommit.Decrypt(commit_T, σ)
```

No committee member needs to be online. No escrow holder needs to act.

**Why forgery is impossible:** `commit_T` is tied to `threshold_BLS_pk_T`, the public key of the specific VRF-selected committee for this node this epoch. Producing a valid aggregate signature under that key requires ⌊K_committee/2⌋ + 1 secret key shares held only by legitimately selected committee members.

ForwardCommit security resolved as Boneh-Franklin IBE over BLS12-381 (Boneh & Franklin, CRYPTO 2001); reduces to DBDH in the random oracle model (OQ-2 — closed).

#### 4.9.5 ZK Proofs

All four statements are evaluated together in the handoff ZK proof each epoch. (Statement 4 was retired during earlier spec consolidation; the gap in numbering is preserved to keep cross-references in implementation work stable.)

**Statement 1 — Preference norm validity** (Bulletproof range proof):

```
‖p_v‖₁ ≤ S
```

**Statement 2 — Directional consistency** (inner product argument):

```
∀ announced item X with noisy_rating > 0 : p_v[X] > 0
∀ announced item X with noisy_rating < 0 : p_v[X] ≤ 0
```

Statement 2 circuit has not been benchmarked for this construction.

**Statement 3 — Temporal consistency** (vector commitment difference):

```
‖p_v(T) − p_v(T−1)‖₁ ≤ Δ
```

**Statement 5 — Non-suspension and forward commitment** (Poseidon evaluation + SMT non-membership + ForwardCommit certification):

```
null_v      = Poseidon(sk, "null_v")
epoch_id_T  = Poseidon(sk, beacon_T, null_v, "epoch_id")
null_v ∉ SUSP_SMT_root_T
commit_T    = ForwardCommit(null_v, epoch_id_T, threshold_BLS_pk_T; r_commit_T)
```

The fourth check shares the same `null_v` wire as the first three. A node cannot commit a different `null_v'` in `commit_T` while satisfying the first two checks — they are the same value in the circuit. Extended Statement 5 circuit cost on mobile hardware requires benchmarking before deployment (OQ-3).

**Fallback — binary ratings:** If a formal influence bound is required before deployment, Config E (binary ratings) narrows the gap to the original DSybil assumptions, though a clean formal guarantee is not claimed — see OQ-10.

#### 4.9.6 Commit-Reveal Verdict Flow

A suspension verdict follows a two-phase commit-reveal process. Committee members lock in their decision publicly before decryption becomes possible. The canonical specification is here; §4.9.10 summarizes the full suspension flow end-to-end.

```
COMMIT PHASE:
    Each committee member i publishes to public chain:
        verdict_commit_i = {
            epoch_id_committee_i: <member epoch ID>,
            commit:               H(BLS_share_i ‖ verdict ‖ nonce_i),
            sig:                  Sign(epoch_id_committee_i, H(commit ‖ T))
        }

    All K_committee commits must appear before reveal phase begins.
    A verdict is invalid without all commits on-chain.
    Members cannot change their verdict after committing.

REVEAL PHASE (after all commits finalized):
    Each committee member i publishes:
        verdict_reveal_i = {
            epoch_id_committee_i: <member epoch ID>,
            bls_share_i:          <BLS secret share contribution>,
            verdict:              "SUSPEND" | "PASS",
            nonce_i:              <random nonce>,
            sig:                  Sign(epoch_id_committee_i,
                                       H(bls_share_i ‖ verdict ‖ nonce_i ‖ T))
        }

    Validators verify:
        H(bls_share_i ‖ verdict ‖ nonce_i) = commit from verdict_commit_i ✓
        BLS share is valid under threshold_BLS_pk_T ✓

AGGREGATION (by anyone, permissionless):
    Once ⌊K_committee/2⌋ + 1 valid reveals are on-chain:
        σ = aggregate(bls_share_1, ..., bls_share_t)
        null_v = ForwardCommit.Decrypt(commit_T, σ)

    Anyone submits null_v_decryption transaction:
        {
            verdict_hash:    H(committee_verdict),
            epoch_id:        <suspended node's last epoch_id>,
            null_v:          <recovered value>,
            dec_nullifier:   Poseidon(verdict_hash, null_v),
            proof:           Verify(threshold_BLS_pk_T, "SUSPEND epoch_id_T", σ) ✓
                             AND ForwardCommit.Verify(commit_T, null_v, σ) ✓
        }

    Validators verify both checks.
    Insert dec_nullifier into DECRYPTION_SMT.
    Insert null_v into SUSP_SMT.
    Update both roots in block header.
```

**Critical ordering property:** Committee members commit to their verdict before the aggregate signature exists and before `commit_T` is decryptable. The decision is irrevocably on-chain before anyone — including the committee — can see `null_v`. This prevents `null_v` from influencing the verdict and prevents covert extraction.

**Non-revealing member:** A committee member who commits but refuses to reveal is in violation of protocol. Consequence: non-response penalty applied to reputation; if threshold reveals are unavailable, the verdict process stalls and the oversight chain is triggered.

#### 4.9.7 Non-Malleability

A node cannot substitute a different `null_v'` while keeping the same `sk`.

**Fabricated null_v':** The circuit checks `null_v' = Poseidon(sk, "null_v")`. If fabricated, this check fails.

**Consistent but distinct null_v':** Satisfying both checks with `null_v' ≠ Poseidon(sk, "null_v")` requires a Poseidon collision. Probability negligible in `λ`.

**Mismatched commit_T:** Committing `null_v'` in `commit_T` while satisfying the first two checks requires the circuit to hold two different values for the same wire. Impossible.

**Different sk:** A new `sk'` produces a new `null_v'`. This is a new identity, not a changed nullifier. Full admission cost applies.

#### 4.9.8 Watchdog Signals and Recursive Oversight

Any node can monitor the public chain for anomalous `verdict_commit` activity:

```
watchdog_signal if:
    count(verdict_commit transactions in epoch T)
    exceeds expected_rate(T) by threshold_watchdog
    AND no corresponding behavioral signals exist at matching rate
```

Expected rate is near zero most epochs — legitimate suspensions are rare. An anomalous burst of `verdict_commit` transactions with no behavioral signal justification is immediately visible before any `null_v` is recovered.

```
watchdog_signal = {
    epoch_id:         <signaling node epoch ID>,
    epoch_T:          <T>,
    observed_commits: <count>,
    expected_rate:    <local estimate>,
    sig:              <Sign(epoch_id, H(epoch_T ‖ observed_commits ‖ T))>
}
```

Watchdog signals from multiple nodes trigger the recursive oversight chain: a meta-committee surveys the original committee; their verdict process follows the same commit-reveal ordering. Each level locks in its decision before the next level's `null_v` becomes accessible.

**Why the chain converges — Chernoff security amplification:** The critical structural property is that each level's committee is drawn independently via VRF with dual cluster diversity constraints — different interest AND behavioral clusters at every level. Given independence, if the adversarial fraction in the committee-eligible pool is q, then:

```
P(compromise at level d) = P(Bin(K_d, q) ≥ ⌊K_d/2⌋+1)
                         ≤ exp(−K_d · D(⌊K_d/2⌋+1)/K_d ‖ q))
```

by the Chernoff bound, where D is the KL divergence. This decays **exponentially** in K_d. With committee size growing linearly across levels (K_d = K_0 + d·ΔK), P(compromise_d) itself shrinks with d, giving doubly-exponential decay in depth. Cumulative escape probability is a product of independent per-level terms each strictly less than 1, so it decays exponentially in depth. Since any polynomial instance count (budget/cost) is dominated by exponential per-instance decay, a finite depth always suffices for any target success probability threshold. This closes OQ-49 as a structural question. What remains is empirical calibration of K_0 and ΔK for the target network (Phase 5 experiment 5.42). The independence guarantee is load-bearing: if committees at different levels were drawn from the same cluster, the Chernoff amplification would not apply. The eligible-pool fraction `q` itself is bounded by Assumption A2: an adversary that pushes `q` above 1/2 in the committee-eligible pool has by definition already broken the honest-majority assumption, at which point BFT consensus, the verdict process, and watchdog signals all collapse simultaneously. q-boundedness is therefore a corollary of A2, not a separate premise.

**Stalling minority:** A minority of committee members refusing to reveal stalls the verdict without triggering SUSPENDED. Handled by non-response penalty plus oversight chain trigger. This failure mode is treated as L3 Suspicious for non-revealing members.

#### 4.9.9 Suspension Persistence Across Epoch Rotation

`null_v` is derived solely from `sk` and a fixed domain separator. The beacon is not an input. Rotating to a new epoch changes `beacon_T` and therefore `epoch_id_T`, but `null_v` is the same value in every epoch for every identity sharing the same `sk`. Once inserted into SUSP_SMT, it blocks all future epoch IDs from that key.

```
Epoch T1: epoch_id_T1 = Poseidon(sk, beacon_T1, null_v, "epoch_id") → null_v ∈ SUSP_SMT → FAIL
Epoch T2: epoch_id_T2 = Poseidon(sk, beacon_T2, null_v, "epoch_id") → null_v ∈ SUSP_SMT → FAIL
Epoch T3: epoch_id_T3 = Poseidon(sk, beacon_T3, null_v, "epoch_id") → null_v ∈ SUSP_SMT → FAIL
...
```

A SUSPENDED verdict is permanent by construction — not by rule.

#### 4.9.10 Full Suspension Flow

Visual recap of §4.9.6 — no new content; included for orientation only.

```
Class 3 audit confirms misbehavior
OR majority handoff rejection
OR double-signing detected
    │
    ▼
Commit phase:
    All K_committee members publish verdict_commit_i on public chain
    Decision locked — visible to entire network
    │
    ▼
Reveal phase:
    All K_committee members publish verdict_reveal_i on public chain
    BLS shares publicly verifiable
    │
    ▼
Aggregation (by anyone):
    σ = aggregate BLS shares
    null_v = ForwardCommit.Decrypt(commit_T, σ)
    │
    ▼
null_v_decryption transaction submitted:
    dec_nullifier = Poseidon(verdict_hash, null_v)
    Inserted into DECRYPTION_SMT
    null_v inserted into SUSP_SMT
    Both roots updated in block header
    │
    ▼
Next epoch: node cannot produce valid Statement 5
Handoff rejected. Epoch transition impossible.
All future identities from same sk permanently excluded.
```

---

## 5. Network

### 5.1 Transport

**Loopix/Sphinx mixnet** (Piotrowska et al., CCS 2017) provides the transport layer. Every unicast message — PSI handshakes, audit responses, verdict commits, gossip vector pushes — is sent as a Sphinx-onion-encrypted packet through a sequence of mix nodes, each of which applies a Poisson-distributed per-hop delay before forwarding. No mix node learns more than the next hop. Sender anonymity, receiver anonymity, and relationship anonymity are formally analyzed under the Loopix model. Mandatory for all production deployments.

Implementation target: **Katzenpost** (open-source Loopix implementation). Each client node connects outbound to a provider (a publicly reachable mix node that buffers inbound messages), which sidesteps NAT traversal for home nodes — no inbound connection is required.

**Loop and drop cover traffic:** Every node emits traffic at a constant Poisson rate regardless of real activity — loop covers (messages to self via the mix) and drop covers (discarded at destination). This is Loopix's native anonymity mechanism and directly subsumes PrivaCF's hand-rolled cover traffic. Cover traffic calibration (§5.8) sets the base Poisson rate; the formal anonymity guarantee holds under this constant-rate assumption.

**Single-Use Reply Blocks (SURBs):** All request-response exchanges (PSI handshakes, audit requests) include a pre-built SURB so the responder can reply anonymously without knowing the requester's mix path.

**Dandelion++** (Fanti et al., SIGMETRICS 2018) is retained for the epidemic broadcast (fluff) phase of gossip propagation, where Loopix's point-to-point model does not apply. Stem phase: random linear relay (p ≈ 0.9 to continue). Fluff phase: epidemic broadcast.

**Retry on failure:** Timeout-only. After k_retry failures, fall back to direct broadcast.

**Clearnet:** Development and testing only.

### 5.2 Uniform Message Frames

Sphinx packets are fixed-size by construction — payload length is padded to a fixed maximum at the sender before onion encryption. An observer on the wire sees fixed-size encrypted blobs and cannot distinguish message types or read contents. A gossip vector push, a Class 3 audit response, a `verdict_commit`, and a Loopix loop or drop cover are indistinguishable on the wire. Frame size estimated 4–8 KB (OQ-30).

Noise Protocol sessions are retained only for any direct connections used in development and clearnet testing; they are redundant for mix-routed production traffic where Sphinx provides per-hop encryption.

### 5.3 Node Discovery and Cluster Re-Discovery

```
NODE DISCOVERY FLOW
─────────────────────────────────────────────────────────
New node                    Network
    │                           │
    │── publish first VDF ──────►│ (public chain)
    │                           │
    │◄── VRF-selected observers─┤ submit first-observation
    │    from diff clusters     │ reports to committee
    │    observe + report       │ chain only
    │                           │
    │── complete n epochs ─────►│
    │   + interaction           │
    │   checkpoints             │
    │                           │
    │◄── admitted ──────────────┤ public chain records
    │                           │ admission decision only

CLUSTER RE-DISCOVERY AFTER EPOCH ROTATION
─────────────────────────────────────────────────────────
    │
    ├── ZK continuity proof submitted to committee chain?
    │       YES: committee attests continuity to cluster peers
    │            update PSI cache with λ_proof decay
    │       NO:  run PSI against new chain entries
    │            with similar item sets
    │
    └── bridge peer: refresh from random DHT each epoch
```

### 5.4 Interest Cluster Peer Selection — Asymmetric PSI

Uses the unbalanced PSI construction from Pinkas, Rosulek, Trieu & Yanai (USENIX Security 2018). The flow is depicted in Appendix I. θ_cluster is community-type dependent; starting range: 0.1–0.3 (OQ-23).

### 5.5 Relay Submission

```
relay_T = VRF(beacon_T ‖ "relay" ‖ epoch_id_v,
              constraints = [
                  different_behavioral_cluster_from_submitter,
                  reputation ≥ median
              ])
```

Relay service contributes positively to per-epoch score via `w_relay`.

### 5.6 Staggered Epochs

```
offset_v = Poseidon(sk, "epoch_offset") mod epoch_duration
```

No inter-node coordination required for epoch transitions.

### 5.7 Two-Tier Peer Selection

```
Interest cluster tier:  2–3 peers · Jaccard PSI confirmed · persistent via ZK continuity
Bridge tier:            1 peer    · random DHT · refreshed each epoch
```

Trust attenuation by hop distance (Stannat Condition 2):

```
cf_weight(vector_from_u) = base_weight × μ^hop_distance(v, u)
```

This attenuation is one of the primary defenses against remote Sybil influence: a node many hops away can contribute at most `μ^k` of base weight regardless of reputation. μ calibration required empirically (OQ-21).

### 5.8 Communication Rhythm

| Signal                                 | Trigger                                                 | Rate limit                                                      | Routing                             |
| -------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------- |
| Gossip vector push                     | T_send = epoch_start + offset + Uniform(0, 0.3 × epoch) | 1 per epoch (hard)                                              | Loopix mix path                     |
| Item announcement (mainstream)         | Positive interaction + random delay                     | ~20/epoch                                                       | Dandelion++ stem → fluff broadcast  |
| Item announcement (niche)              | Positive interaction + VRF-derived epoch delay          | Per item                                                        | Dandelion++ stem → fluff broadcast  |
| Receipt                                | Epoch end (batched)                                     | 1 batch per epoch                                               | Loopix mix path                     |
| Rewind signal                          | q_v(T) drop correlated with recent gossip cohort        | 1 per epoch per node; max 1 Class 3 trigger per N_rewind epochs | Dandelion++ stem → fluff broadcast  |
| On-chain transaction (M_v, C_p, score) | Every n_commit epochs via relay                         | 1 per n_commit epochs                                           | Via relay node                      |
| commit_T + ZK proof                    | Every epoch via relay                                   | 1 per epoch                                                     | Via relay node                      |
| verdict_commit                         | Commit phase of suspension                              | 1 per committee member per verdict                              | Loopix mix path                     |
| verdict_reveal                         | Reveal phase of suspension                              | 1 per committee member per verdict                              | Loopix mix path                     |
| null_v_decryption                      | After threshold reveals available                       | Permissionless                                                  | Direct to chain                     |
| watchdog_signal                        | Anomalous verdict_commit rate                           | 1 per epoch per node                                            | Dandelion++ stem → fluff broadcast  |
| Auditor handoff                        | Epoch end                                               | 1 per epoch                                                     | Loopix mix path to committee        |
| ZK continuity proof                    | Epoch transition (voluntary)                            | 1 per epoch                                                     | Committee chain only                |
| Loop/drop cover traffic                | Constant (Poisson)                                      | Base Poisson rate λ — calibrated per OQ-58                      | Loopix native (loop and drop covers)|

---

## 6. Reputation and Audit

### 6.1 Per-Epoch Score

```
score_v(T) = w₁ × participation_rate(T)
           + w₂ × audit_response_rate(T)
           + w₃ × gossip_validity_rate(T)
           + w₄ × rate_limit_compliance(T)
           + w₅ × cluster_endorsement(T)
           + w₆ × (1 − rewind_signal_rate(T))
           + w_validator × validator_service_indicator(T)
           + w_relay × relay_service_indicator(T)

consistency_v(T) = 1 − Var(score_v(T−k), ..., score_v(T)) / σ²_max
reputation_v(T)  = α × score_v(T) + (1−α) × consistency_v(T)
```

**Slow reputation decay** applies universally each epoch:

```
reputation_v(T) = reputation_v(T) − δ_decay
```

Weights w₁–w₆, δ_decay, and α require empirical calibration. The interactions between score components under adversarial conditions — particularly whether participation_rate and consistency can be driven in opposing directions, and which dominates — have not been formally analyzed and warrant empirical investigation (OQ-9).

Raw scores are stored on the committee chain. The public chain receives only the committee-attested score band (1–4) with fuzzy boundaries, rate-limited to one change per N_band epochs.

### 6.2 Behavioral Cluster Computation

Behavioral clusters are computed locally by each node from public chain timing data:

```
behavioral_fingerprint_v(T) = {
    activity_window:        which parts of the epoch the node is typically active
    announcement_timing:    distribution of delays between interaction and announcement
    transaction_timing:     when within the epoch the on-chain entry is published
    audit_response_rate:    fraction of audit challenges responded to
}
```

Cluster computation is deterministic given the same chain data. Behavioral clusters feed the compound flag system only — never used for direct reputational effects.

**Auditor independence requires both cluster types.** An auditor committee must have members from different interest clusters AND different behavioral clusters.

### 6.3 Admission and First-Observation Interrogation

**The admission window (n epochs):** Zero CF weight, zero routing weight. VDF proof published each epoch. Interaction checkpoints at VRF-determined epochs require real network contact.

**First-observation reports:** When a new `epoch_id` first appears on-chain, VRF-selected existing nodes submit signed first-observation reports to the committee chain only.

**Identity rotation evasion:** On-chain SUSPENDED verdicts are permanent and include the behavioral fingerprint of the suspended `epoch_id`. New `epoch_id`s matching that fingerprint above threshold inherit a suspicion flag:

```
admission_flag if:
    behavioral_similarity(new_epoch_id, suspended_epoch_id) > θ_behavioral
    AND time_since_suspension < T_behavioral_window
```

Additionally, at the epoch when admission completes, the node's first handoff must include a valid Statement 5 non-suspension proof and valid `commit_T`. A node whose `null_v` is already in SUSP_SMT is rejected at admission immediately — no separate investigation required.

**Suspicious restart detection:**

```
suspicious_restart_flag if:
    prior_chain_abandoned_under_active_flags(T_abandon)
    AND new_epoch_id appears within T_window epochs of T_abandon
    AND behavioral_similarity(new_epoch_id, abandoned_epoch_id) > θ_behavioral
```

### 6.4 Multi-Auditor Encrypted State Handoff

**Auditor credibility decay:**

```
credibility_A(T) = credibility_A(T-1) × γ_penalty    // on confirmed false verdict

audit_weight(result_from_A, T_result) = credibility_A(T_result)
    × e^(−λ_audit × (T_now − T_result))
```

γ_penalty and λ_audit require empirical calibration.

```
committee_T = VRF(beacon_T ‖ "audit_committee" ‖ epoch_id_v,
                  k = K_committee,
                  constraints = [
                      different_interest_clusters,
                      different_behavioral_clusters,
                      reputation ≥ median,
                      temporal_depth ≥ D_min
                  ])
```

**The handoff package:**

```
handoff_v(T) = {
    C_p(T),
    M_v(T),
    leaf_counts: {
        ANNOUNCEMENT:    n_ann,
        PULL_RESPONSE:   n_pull,
        AUDIT_RESPONSE:  n_aud,
        PARTICIPATION:   n_part,
        RATE_LIMIT:      n_rl
    },
    SUSP_SMT_root_T,
    commit_T,
    threshold_BLS_pk_T,
    ZK proof that:
        C_p(T) is a valid successor to C_p(T-1)
        M_v(T) is a valid successor to M_v(T-1)
        ||p_v(T) - p_v(T-1)||₁ ≤ Δ              (Statement 3)
        leaf_counts are consistent with M_v(T)
        token_v(T) correctly incorporated if token was issued this epoch
        null_v ∉ SUSP_SMT_root_T                 (Statement 5, line 3)
        commit_T = ForwardCommit(null_v, epoch_id_T,
                                 threshold_BLS_pk_T; r_commit_T) (Statement 5, line 4)
    rolling_chain_commitment: Poseidon(
        rolling_chain_commitment(T-1),
        zk_continuity_proof(T),
        audit_interactions(T),
        SUSP_SMT_root_T
    ),
    zk_continuity_proof:  <committee chain only — not in public handoff>,
    encrypted_shares: [
        Encrypt(pk_auditor_i, shamir_share_i(snapshot_v(T)))
    ]
}
```

Each committee member independently verifies the ZK proof. A threshold of ⌊K_committee / 2⌋ + 1 must sign off. Rejection by a majority triggers the commit-reveal SUSPENDED flow (§4.9.6). Rejection by a minority triggers L3 Suspicious and a Class 3 audit.

**Score band attestation:** The committee publishes a threshold-BLS-signed score band to the public chain.

### 6.5 Audit Classes

**Class 2 — passive, invisible, ~3–4 times per epoch:**

```
┌──────────────────────────────────────────────────────────┐
│  CLASS 2 AUDIT FLOW                                       │
│                                                           │
│  A ──[pull request + embedded nonce]──────────────► B    │
│        indistinguishable from normal pull                 │
│                                                           │
│  A ◄──[gossip vector + H(state ‖ nonce ‖ epoch_id_B)]─── B│
│        indistinguishable from normal pull response        │
│                                                           │
│  A verifies hash against B's C_p(T) and M_v(T) on-chain  │
│  A publishes result on public chain under A's epoch_id   │
└──────────────────────────────────────────────────────────┘
```

**Class 3 — committee-triggered, exceptional:**

```
┌──────────────────────────────────────────────────────────┐
│  CLASS 3 AUDIT FLOW                                       │
│                                                           │
│  Q rewind signals (≥2 interest clusters, ≥D_Q depth,     │
│  correlated with same gossip cohort)                     │
│       │                                                   │
│       ▼                                                   │
│  Committee: VRF-selected (diff interest + behavioral     │
│  clusters · rep ≥ median · depth ≥ D_min)                │
│       │                                                   │
│       ▼                                                   │
│  C_i ──[challenge, formatted as pull request]──────► B   │
│                                                           │
│  B ──[Merkle proof + ZK proof (Stmts 1–3, 5)]──────► C_i │
│     via Dandelion++ stem WITH timeout retry               │
│                                                           │
│  Committee cross-checks against committee chain          │
│  Contacts attestation issuers for peer-attested leaves   │
│  Threshold BLS signature on result                       │
│  Result published on public chain — permanent            │
└──────────────────────────────────────────────────────────┘
```

### 6.6 Rewind Signals and HNSW Snapshots

A rewind signal expresses that a node's recommendation quality has degraded and that a prior snapshot of the local HNSW index was better.

```
rewind_signal = {
    current_T:    <current epoch>,
    preferred_T:  <epoch at which quality was last acceptable>,
    cohort_epoch: <epoch at which implicated gossip vectors entered index>,
    sig:          <Sign(epoch_id, H(current_T ‖ preferred_T ‖ cohort_epoch))>
}
```

**HNSW rollback and network consequences are separate operations.** The HNSW rollback is purely local. Network consequence comes from the Class 3 audit that the rewind signal triggers.

**Rate limit:** A node may contribute to triggering at most one Class 3 audit per N_rewind epochs.

### 6.7 Health Tiers

| Tier               | Conditions                                               | Effect                                                               |
| ------------------ | -------------------------------------------------------- | -------------------------------------------------------------------- |
| HEALTHY            | All score conditions met, no flags, no adverse verdicts  | Full routing weight, normal audit                                    |
| DEGRADED           | Score below threshold, above floor                       | Reduced routing weight, elevated audit                               |
| RECOVERING         | Recently penalized, slow-rise trajectory                 | Low routing weight, elevated audit                                   |
| SUSPENDED          | Committee verdict on public chain via commit-reveal flow | Zero routing weight. Permanent for that epoch_id. null_v in SUSP_SMT |
| ABSENT             | D_v < D_min, no flags                                    | Normal routing weight                                                |
| SUSPICIOUS_ABSENCE | D_v < D_min, with flags                                  | Reduced routing weight, elevated audit                               |
| ADMITTING          | Within n-epoch admission window                          | Zero CF weight, zero routing weight, observable                      |
| NEW                | Admission complete, first N_bootstrap epochs             | Minimum routing weight                                               |

---

## 7. Sybil Resistance

### 7.1 Attack Taxonomy

No symmetric reputation function can be Sybil-proof (Cheng & Friedman, 2005). PrivaCF's defense is not to prevent Sybil identities but to bound their influence and make them expensive.

The taxonomy below names the attacker archetypes informally; §7.9 formalizes the full (tactic × identity-strategy) space and states the detection contract per cell.

| Attack type             | What it does                                   | Primary defense                                                                | Residual risk                                      |
| ----------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------- |
| Random push             | Inflates trust_total with random announcements | DSybil non-overwhelming rule                                                   | CF noise                                           |
| Bandwagon               | Copies honest vectors then pushes target items | FoolsGold (interest + behavioral)                                              | Hard if very patient                               |
| Segment                 | Targets specific interest cluster              | Per-cluster reputation                                                         | Cluster-level degradation                          |
| Coordinated campaign    | Multi-item narrative across clusters           | Behavioral clustering, compound flags                                          | Operator classification required                   |
| Sleeper                 | Builds reputation before activating            | Smoothness detection, handoff chain, asymmetric penalty                        | Hardest to detect                                  |
| Epoch rotator (same sk) | Evades SUSPENDED verdict by rotating epoch ID  | Nullifier mechanism — cryptographically impossible from same sk                | None for same sk                                   |
| Epoch rotator (new sk)  | Re-admits with fresh key after suspension      | Admission cost, behavioral fingerprinting                                      | Sophisticated adversary varying patterns           |
| Dark node rotator       | Goes dark before null_v extraction             | ForwardCommit — committee decrypts without node cooperation                    | Admission window gap only                          |
| Rogue committee         | Mass null_v extraction without verdicts        | Commit-reveal ordering — visible before any null_v recovered; watchdog signals | Threshold collusion (same as consensus assumption) |

### 7.2 Temporal Depth

```
D_v(T) = Σ_{t ∈ A_v, t ≤ T} λ^(T−t),   λ ∈ (0,1)
```

**Asymmetric penalty:**

```
r_v(T)   ← min(r_v(T−1), BAND_1)
r_v(T+k) ← r_v(T+k−1) + Δ_rise
```

The asymmetric penalty creates a tension: `Δ_rise` must be large enough that honest nodes recover reputation at a meaningful rate after absence, but small enough that an adversary cannot exploit recovery periods to accumulate disproportionate reputation through on-off cycling. Whether a single value satisfies both constraints simultaneously is an empirical calibration question addressed in Phase 5 experiment 5.4 (OQ-6, reclassified). λ should be calibrated per community type.

### 7.3 DSybil Non-Overwhelming Rule

```
trust_contribution(v, X) = max(0, r_v(X) + noise) × Δ × (1 + κ × novelty(X))

if trust_total(X) < c:   trust(v) += trust_contribution(v, X)
else:                     trust(v) += 0

trust(v) ≤ α × c
```

Formal bound validated on Digg with binary feedback only. Extension to continuous noisy ratings requires the per-epoch composition lemma (OQ-10).

**Caveat on formal transfer.** The non-overwhelming rule is borrowed from DSybil but the formal bound justifying it in that work does not transfer to PrivaCF's setting. DSybil's theorem requires a persistent social graph, trust propagation via random walks, and a sparse honest/Sybil cut. PrivaCF has none of these — peers are discovered via PSI on item overlap, trust is not propagated transitively, and the topology is intentionally ephemeral. The rule is retained as a well-motivated heuristic with empirical support from the original Digg validation, but formal justification in this setting requires a new argument, likely stochastic block model-based. See OQ-10.

**Novelty term as passive Sybil damping.** The novelty bonus serves a dual purpose. Its primary function is to accelerate trust accumulation for undersurfaced items. A secondary effect is that as `trust_total` approaches `c`, marginal adversarial contributions shrink toward zero — coordinated pushing of an already-popular item has diminishing returns by construction, and organic popularity surges are similarly self-limiting. The converse is a sabotage vector: an adversary who pushes a niche item past an early trust threshold removes its novelty bonus, suppressing the organic discovery acceleration the system provides for long-tail content. This is harder to detect than inflation attacks because it requires no ongoing coordination after the initial push, and may be difficult to distinguish from a genuine early popularity surge. Characterization of this attack and its interaction with the compound flag system is left to Phase 5 adversarial simulation.

### 7.4 Within-Cluster FoolsGold

```
flag_sybil_cluster(v, T) if:
    PSI_Jaccard_similarity(v, cluster_k) ≥ θ_cluster
    AND contribution_cosine_sim(v, cluster_k) > θ_contrib
```

### 7.5 Smoothness Detection

```
smoothness_flag(v, T) if Var(score_v(T−k), ..., score_v(T)) < σ²_floor
```

σ²_floor requires empirical calibration (OQ-29).

### 7.6 Weight Caps and Gini Monitoring

```
G(T) = (Σ_i Σ_j |w_i − w_j|) / (2n Σ_i w_i)
```

No single node exceeds X% of total weight. No cohort exceeds Y%.

### 7.7 Tamper Analysis

| Value                             | Tamperable?                               | Detectable?                                                                        | Consequence                                                                    |
| --------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `null_v`                          | Only by changing `sk`                     | Yes — circuit enforces `null_v = Poseidon(sk, "null_v")`; substitution fails proof | Changing `sk` produces a new identity; same `sk` always produces same `null_v` |
| `commit_T`                        | Only with matching null_v                 | Yes — Statement 5 circuit checks ForwardCommit formation with same null_v wire     | Cannot commit a different null_v without breaking the first two circuit checks |
| `sk`                              | Changing produces a different identity    | N/A                                                                                | All accumulated reputation and PSI relationships lost                          |
| `p_v`                             | Yes — within Statement 1 and 3 bounds     | Partially — nuclear option at L5                                                   | CF manipulation within bounds                                                  |
| `r_p`                             | Loss only                                 | Yes — Class 3 audit permanently fails                                              | SUSPENDED verdict on public chain                                              |
| `π_v(T)`                          | Yes                                       | No                                                                                 | Node's own CF quality degrades                                                 |
| `q_v(T)`                          | Yes                                       | Coordinated false triggering is a compound flag                                    | False triggering costs reputation; suppression is self-harming                 |
| PSI cache                         | Yes                                       | No                                                                                 | Node's cluster degrades. Self-harming only                                     |
| Merkle leaves (before commitment) | Yes                                       | Yes — handoff ZK proof commits to counts                                           | Consistent ZK proof while lying requires breaking the ZK system                |
| Merkle leaves (after commitment)  | Computationally infeasible                | N/A                                                                                | Root is on public chain and VDF-chained                                        |
| Peer attestations                 | Cannot forge                              | Yes if attempted                                                                   | Fails signature verification during audit                                      |
| Handoff ZK proof                  | Cannot forge                              | Yes if attempted                                                                   | Committee rejects. SUSPENDED on public chain                                   |
| On-chain verdict                  | Cannot alter                              | N/A                                                                                | Permanent. Epoch rotation does not erase it                                    |
| SUSP_SMT leaf                     | Cannot alter without forking the chain    | N/A                                                                                | Append-only, VDF-chained                                                       |
| DECRYPTION_SMT leaf               | Cannot alter without forking the chain    | N/A                                                                                | Append-only, VDF-chained                                                       |
| Committee chain entry             | Cannot alter without threshold compromise | Detectable via public chain Merkle root                                            | Requires compromising threshold committee                                      |
| verdict_commit                    | Cannot alter after publication            | Yes — on-chain, signed, VDF-chained                                                | Non-alterable commitment to verdict                                            |
| verdict_reveal                    | Cannot mismatch with commit               | Yes — validators verify H(share ‖ verdict ‖ nonce) = commit                        | Invalid reveal rejected by validators                                          |

### 7.8 Compound Flag System and Alert Levels

| Signals present                                                     | Alert level                             | Automated action                                          | Human review?             |
| ------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------- | ------------------------- |
| High announcement rate alone                                        | L1 Watch                                | None                                                      | No                        |
| Low announcement diversity alone                                    | L1 Watch                                | None                                                      | No                        |
| High rate + low diversity                                           | L2 Elevated                             | Increase audit frequency                                  | No                        |
| L2 + cohort temporal clustering (same behavioral cluster)           | L3 Suspicious                           | Elevate + flag                                            | Recommended               |
| L3 + interest-cluster FoolsGold                                     | L4 Probable Sybil                       | Reduce routing weight + Class 3                           | Yes                       |
| L3 + cross-cluster behavioral similarity                            | L4 Probable Coordinated                 | Reduce routing weight + Class 3                           | Yes                       |
| L4 + Class 3 fail OR handoff rejection (majority)                   | L5 Confirmed                            | Commit-reveal SUSPENDED flow on public chain              | No                        |
| L4 + Class 3 pass                                                   | L2 Elevated                             | Maintain elevated audit, clear L4                         | No                        |
| Smoothness flag alone                                               | L1 Watch                                | None                                                      | No                        |
| Smoothness flag + low temporal depth                                | L2 Elevated                             | Increase audit frequency                                  | No                        |
| First-observation reports inconsistent with VDF start               | L2 Elevated                             | Extend admission observation                              | No                        |
| New epoch_id null_v already in SUSP_SMT                             | Rejected at admission                   | Statement 5 proof fails — no handoff possible             | No — cryptographic        |
| New epoch_id behavioral fingerprint matches suspended               | L2 Elevated                             | Elevated audit from admission                             | No                        |
| Suspicious restart detection                                        | L3 Suspicious                           | Elevated audit + flag                                     | Recommended               |
| Q rewind signals (≥2 interest clusters, correlated cohort)          | L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Coordinated rewind signals from same behavioral cluster             | L3 Suspicious                           | Elevate + flag                                            | Recommended               |
| Handoff rejection (minority of committee)                           | L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Handoff rejection (majority of committee)                           | L5 Confirmed                            | Commit-reveal SUSPENDED flow                              | No                        |
| Validator double-signing detected                                   | L5 Confirmed                            | Commit-reveal SUSPENDED flow, permanent                   | No                        |
| Anomalous verdict_commit rate, no behavioral signal justification   | L3 Suspicious                           | Watchdog signal broadcast + oversight chain               | Recommended               |
| Stalling committee (commit phase started, reveals missing)          | L3 Suspicious for non-revealing members | Non-response penalty + oversight chain                    | Recommended               |
| L5 Confirmed + persistent manipulation signals despite Class 3 pass | L5 Nuclear                              | Committee demands full rolling chain commitment traversal | Committee review required |

---

### 7.9 Detection Contract

§7.1 enumerates attackers and §7.8 enumerates detection actions, but the mapping between them has so far been informal. This subsection makes the mapping explicit. For each meaningful intersection of *manipulation tactic* and *identity/persistence strategy*, the contract states what triggers detection, which mechanism handles it, the strength of the guarantee, and what slips through. Unresolved cells are named so reviewers can falsify them.

#### 7.9.1 Axes

**Manipulation tactic (T) — what the adversary injects:**

| ID  | Tactic                  | Description                                                                                |
| --- | ----------------------- | ------------------------------------------------------------------------------------------ |
| T1  | Random injection        | Random items, random ratings — no specific target                                          |
| T2  | Targeted push           | Inflate `trust_total` of a specific item                                                   |
| T3  | Coordinated narrative   | Multi-item campaign across one or more interest clusters                                   |
| T4  | Novelty kill            | Push a niche item past the trust threshold to suppress its novelty bonus (§7.3 sabotage vector) |
| T5  | Semantic poisoning      | Genuine engagement patterns, manipulated semantic intent                                   |

Suppression in PrivaCF reduces to T2 against competitors of the target — dislikes are local-only and not transmittable, so direct nuke attacks are not in the tactic space.

**Identity / persistence strategy (I) — how the adversary persists or evades:**

| ID  | Strategy                                              | Description                                                                                  |
| --- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| I1  | Single identity, immediate                            | One identity, payload deployed immediately after admission                                   |
| I2  | Single identity, sustained                            | One identity active across many epochs, payload throughout                                   |
| I3  | Single identity, sleeper                              | One identity builds reputation passively, then deploys payload                               |
| I4  | Sybil swarm, fresh keys                               | Many identities each with a distinct `sk`, used briefly                                      |
| I5  | Same-key rotator (post-suspension)                    | Identity suspended; new `epoch_id` derived from same `sk`                                    |
| I6  | New-key rotator, similar fingerprint                  | Identity suspended; new `sk`, behavioral pattern preserved                                   |
| I7  | New-key rotator, varied fingerprint                   | Identity suspended; new `sk`, behavioral pattern deliberately altered                        |
| I8  | Dark node rotator                                     | Identity goes offline before nullifier extraction, then re-admits                            |
| I9  | Rogue committee (audit-layer attack)                  | Compromised committee threshold attempts mass deanonymization or covert decryption           |

**Guarantee level (G) — strength of the detection promise:**

| Level | Meaning                                                                                                                      |
| ----- | ---------------------------------------------------------------------------------------------------------------------------- |
| **C** | **Cryptographic.** Detection (or block) follows by arithmetic from an honest-validator check; failure requires breaking a primitive listed in A3. |
| **B** | **Behavioral-probabilistic.** Detection rate is governed by a calibrated threshold; false positive and false negative rates are characterized empirically. The named OQ governs calibration. |
| **H** | **Heuristic.** A signal is surfaced into the compound flag system; final adjudication requires operator review or correlated evidence across multiple flags. |
| **O** | **Out of scope.** Explicitly not promised. Listed so reviewers can confirm the gap is intentional, not overlooked.            |

#### 7.9.2 Contract Table

Each row names one meaningful (T, I) intersection. Cells not listed collapse to a row that handles them — see §7.9.3.

| #  | (T, I)         | Adversary archetype                          | Triggering signal                                                                                  | Mechanism (§ref)                              | G   | Residual / Calibration                          |
| -- | -------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------- | --- | ----------------------------------------------- |
| 1  | T2 × I1        | Naive opportunist                            | Bursty announcements, low diversity                                                                | §7.8 L1→L2 (rate + diversity)                 | B   | OQ-32                                           |
| 2  | T1 × I4        | Random Sybil flooder                         | Admission-rate spike; FoolsGold contribution patterns; Gini drift                                  | §6.3 first-observation; §7.4; §7.6            | B   | OQ-24, OQ-32                                    |
| 3  | T2 × I2        | Patient pusher (sustained, single identity)  | DSybil cap reached on target item; smoothness flag if score variance is artificially low           | §7.3 cap `c`; §7.5 smoothness                 | B (smoothness); damage structurally bounded by cap `c` regardless of detection | OQ-15, OQ-29 |
| 4  | T2 × I3        | Sleeper activator (single identity)          | Score variance + sudden trajectory change after dormancy                                           | §7.5 smoothness; §7.2 asymmetric penalty      | B   | OQ-29, OQ-6 (`Δ_rise`); hardest single-identity case |
| 5  | T2 × I2 (mimic)| Bandwagon mimic                              | Within-cluster contribution cosine similarity to honest cohort                                     | §7.4 within-cluster FoolsGold                 | B   | OQ-24                                           |
| 6  | T3 × I4        | Coordinated campaign, single cluster         | Cross-Sybil contribution similarity; behavioral cluster overlap                                    | §7.4 + §6.2 behavioral cluster FoolsGold      | B   | OQ-24, OQ-28                                    |
| 7  | T3 × I4-distrib| Coordinated campaign, cross-cluster          | Cross-cluster behavioral similarity (timing, audit response distribution)                          | §7.8 L4 Probable Coordinated                  | H   | OQ-28; operator review required                 |
| 8  | T3 × I3 swarm  | Cross-cluster sleeper swarm                  | Smoothness flag across multiple identities + cross-cluster behavioral similarity                   | §7.5 + §6.2 + §7.8                            | H   | OQ-28, OQ-29; hardest multi-identity case       |
| 9  | T4 × any       | Novelty-kill saboteur                        | Item crosses trust threshold with abnormally fast accumulation + low contributor diversity         | None currently; collapses into "organic surge or coordinated push" | **O** (today) → H (future) | §7.3 caveat; deferred to Phase 5 adversarial simulation |
| 10 | T5 × any       | Semantic poisoner                            | Indistinguishable from genuine signal at the protocol layer                                        | None — by construction                        | O   | Acknowledged residual (§8.1 "Semantic poisoning") |
| 11 | any × I5       | Same-key rotator                             | `null_v ∈ SUSP_SMT` — Statement 5 fails                                                            | §4.9.5 Statement 5 + §4.9.2 SUSP_SMT          | C   | None — fails by arithmetic                      |
| 12 | any × I6       | New-key rotator, similar fingerprint         | `behavioral_similarity > θ_behavioral` within `T_behavioral_window`                                | §6.3 admission_flag; §7.8 L2 Elevated         | B   | OQ-34, OQ-35                                    |
| 13 | any × I7       | New-key rotator, varied fingerprint          | None at identity layer; falls back to whatever T-level defense applies                             | §4.3 admission cost (rate-limits but doesn't block); T-row applies | B (T-only) | Acknowledged residual (§8.1 "Sophisticated epoch rotators") |
| 14 | any × I8 post-publish | Dark node, post-`commit_T`            | ForwardCommit decryption recovers `null_v` from on-chain `commit_T`                                | §4.9.4 ForwardCommit; §4.9.6 commit-reveal    | C   | None — committee can decrypt without node cooperation |
| 15 | any × I8 admission window | Dark node, pre-`commit_T`         | Zero reputation + behavioral fingerprint of admission attempt                                      | §4.3 admission cost; §6.3 first-observation   | B (bounded) | OQ-16; bounded but not eliminated; admission-window-only gap |
| 16 | I9 on-chain    | Rogue committee, on-chain extraction         | Anomalous `verdict_commit` rate vs. behavioral signals                                             | §4.9.8 watchdog + recursive oversight         | B   | OQ-48; bounded by Chernoff (§4.9.8) under A2    |
| 17 | I9 off-chain   | Rogue committee, covert decryption           | None until a `null_v_decryption` transaction is submitted; off-chain σ aggregation leaves no trace | §8.1 "Threshold collusion" carve-out          | O (below A2) | OQ-17, OQ-53; bounded by Byzantine majority assumption |
| 18 | orthogonal     | Validator double-signer                      | Two BLS signatures on competing blocks at same height                                              | §4.1 double-signing detection                 | C   | None — immediate permanent SUSPENDED            |
| 19 | I-orthogonal   | Reputation laundering (proactive rotation)   | Re-admission cost + behavioral fingerprint match if pattern preserved; if varied, falls to row 13  | §4.3 + §6.3                                   | B (with similar fingerprint) / O (with varied) | OQ-57 (cost amortization across cycles)        |
| 20 | I-orthogonal   | Cluster splitting via inconsistent PSI       | Self-harming (degrades node's own cluster); detectable as PSI cache divergence across observers    | §7.7 (PSI cache row)                          | B (self-harming) | Self-harming only; no operator action needed              |
| 21 | T2 × I-targeted PSI | PSI-targeted Sybil (Stannat Cond. 1)    | Sybil constructs item set to enter victim's interest cluster                                       | §5.4 PSI; §7.4 within-cluster FoolsGold       | B (partial) | §8.2 T5 — formal bound not established                  |

#### 7.9.3 Collapse rules

The full Cartesian product of T (5) × I (9) is 45 cells. The table above lists 21 distinguishable rows. The rest collapse:

- **Row 11 absorbs (any T) × I5** — Statement 5 fails before any payload can be deployed.
- **Row 14 absorbs (any T) × I8 post-publish** — `null_v` is recoverable from the prior epoch's `commit_T` regardless of what payload was attempted.
- **Row 10 absorbs T5 × (any I)** — semantic poisoning is undetectable at the protocol layer regardless of identity strategy.
- **(T1) × (I1, I2, I3)** collapse into row 1 (the signal that triggers detection — high rate, low diversity — is identical for random and targeted single-identity push at this scale).

#### 7.9.4 Where the contract is weakest

Three regions of the matrix are where the protocol's promise is genuinely thin and worth flagging to reviewers:

1. **Row 9 (T4 — novelty kill).** No mechanism currently distinguishes a coordinated novelty-suppression push from an organic early-popularity surge. The §7.3 sabotage vector is named but unaddressed. Currently O; should become H once Phase 5 simulation produces a separator.
2. **Row 13 (I7 — new-key rotator with varied fingerprint).** Once the adversary changes both `sk` and behavioral pattern, the only remaining defense is admission cost, which rate-limits but does not detect. Acknowledged in §8.1.
3. **Row 17 (I9 off-chain).** A colluding committee threshold can recover `null_v` covertly without on-chain trace. Bounded by A2 (the same assumption consensus depends on), but no protocol-layer detection exists below that ceiling. This is the weakest link in the entire identity-privacy story.

The contract is strongest at rows 11, 14, 18 (cryptographic guarantees by arithmetic) and at rows 1–6, 12, 15 (behavioral-probabilistic with named calibration OQs). Rows 7, 8, 16 are heuristic and depend on operator review or compound-signal correlation.

#### 7.9.5 Implications for Phase 5 simulation

Each B-level and H-level row in the table corresponds to at least one Phase 5 experiment in §9.2 (with the exception of self-harming rows like row 20, where TPR/FPR characterization is not meaningful — the attacker's own CF quality degrades and operator action is unnecessary). The detection contract above can be used as a checklist: for each non-self-harming row marked B or H, the corresponding experiment must produce a TPR/FPR characterization with an explicit calibration recommendation. Rows marked O are not eliminated by Phase 5 — they are documented residuals.

---

## 8. Known Limitations

### 8.1 What Is Not Protected

- **Within-cluster preference privacy.** Interest cluster peers accumulate observations over time. Accepted tradeoff.
- **Long-term differential privacy.** T epochs of ε-DP gives Tε total loss. Not claimed.
- **Nation-state adversaries.** Loopix provides formal sender/receiver/relationship anonymity under the Poisson traffic model, but mix node compromise and global traffic analysis remain out of scope.
- **Semantic poisoning.** No cryptographic guarantee. Primary unresolved attack.
- **Self-reported Merkle leaves.** PARTICIPATION and RATE_LIMIT remain self-reported, covered by handoff ZK proof but not peer-attested.
- **Dark node rotators — admission window only.** The dark node gap is closed for nodes that have published at least one `epoch_transaction`. The residual gap is nodes that go dark during the admission window before any `commit_T` is published. Bounded by zero reputation, full admission cost, and behavioral fingerprinting.
- **Sophisticated epoch rotators with key change.** An adversary generating a fresh key evades the nullifier mechanism entirely. Admission cost and non-overwhelming trust are the remaining defenses.
- **Poseidon maturity.** Less cryptanalytic history than EC constructions. Resolved by primitive split: local derivations use Poseidon as a keyed PRF; pseudorandomness under standard Poseidon assumptions suffices (OQ-1 — closed).
- **ForwardCommit instantiation maturity.** BLS-based ForwardCommit resolved as Boneh-Franklin IBE over BLS12-381; reduces to DBDH in the random oracle model (OQ-2 — closed).
- **Behavioral fingerprint as persistent identifier.** Derived from public on-chain data and available to any observer. Degraded but not eliminated by per-n-epoch commits, relay submission, and transaction timing jitter.
- **commit_T as per-epoch presence signal.** Published every epoch, exempt from n_commit batching. Opaque without verdict signature but confirms node liveness every epoch.
- **Approximate interest cluster graph reconstruction.** Loopix relationship anonymity substantially degrades this but does not eliminate it — PSI traffic patterns over many epochs may still leak cluster topology to a patient adversary observing mix nodes.
- **Poisson cover traffic bandwidth.** Every node emits traffic at a constant Poisson rate regardless of real activity. This is non-trivial on metered or mobile connections (OQ-58).
- **Committee chain trust.** Compromise of a full committee threshold reveals continuity proofs, raw scores, and fine-grained behavioral data.
- **Score verification trustlessness.** Ordinary nodes cannot recompute raw scores from public chain data alone. Verification is committee-attested. Accepted cost of the dual-chain model.
- **p_v targeted inflation.** An adversary can inflate preference weights for target items within the bounds of Statements 1 and 3.
- **Threshold collusion for null_v extraction.** A colluding supermajority of a committee can aggregate σ off-chain and decrypt `commit_T` without going through the commit-reveal flow, recovering `null_v` without an on-chain trace. Damage is limited to targeted epoch ID linkage — no suspension, no preference exposure, no protocol consequence unless an on-chain transaction is subsequently submitted (at which point the action becomes visible). Acting on the recovered `null_v` in any protocol-meaningful way requires submitting a `null_v_decryption` transaction, which is publicly visible. ForwardCommit provides security against covert deanonymization for all adversaries who cannot both compromise a threshold of committee members AND suppress watchdog signals across the honest majority simultaneously. This requires compromising the same threshold that breaks consensus — the privacy assumption is bounded by the Byzantine majority assumption already in the threat model.

### 8.2 Unresolved Design Tensions

**Privacy tradeoffs**

- **T2 — Niche signal vs. privacy protection.** Chopping vs. Laplace. Mutually exclusive per deployment.
- **T9 — n_commit batching vs. audit freshness.** Larger n_commit improves privacy but widens the undetected drift window.
- **T10 — commit_T per-epoch submission vs. behavioral fingerprinting.** commit_T is exempt from n_commit batching and provides a per-epoch liveness signal. Mitigated by commit_T's opacity — it reveals presence only, not behavior.

**Security tradeoffs**

- **T1 — Δ_rise calibration vs. on-off attack defense.** If no single Δ_rise satisfies both path-responsiveness and on-off attack resistance, governance must choose a point on the tradeoff curve. Characterized empirically in Phase 5 experiment 5.4.
- **T5 — PSI-targeted Sybils and Stannat Condition 1.** Formal bound not established under patient targeted adversary.

**Liveness tradeoffs**

- **T7 — Validator incentives.** Addressed by service score bonus and shirking penalty. Long-term sufficiency without tokens requires analysis.
- **T8 — Committee chain availability.** Shamir share rotation on committee rotation requires careful design to avoid availability gaps.
- **T11 — Commit-reveal latency vs. suspension throughput.** The commit-reveal process adds latency to suspension finality. High volumes of simultaneous suspensions may create block space contention.

**Calibration questions**

- **T3 — Validator set size vs. collusion resistance.**
- **T4 — Admission window length vs. UX.** No middle states by design.
- **T6 — Behavioral cluster false positives.** Real users in the same timezone with similar routines may cluster together. Mitigated by compound flag system rather than direct reputational effects.

---

## 9. Implementation Plan

### 9.1 Minimal Viable PrivaCF

**Core hypothesis:** Decentralized CF with rotating pseudonymous identities, Loopix/Sphinx mixnet transport, Dandelion++ broadcast routing, Jaccard PSI peer selection, Merkle-committed behavioral history with peer attestations, multi-auditor encrypted handoff, a dual-chain architecture for public state, nullifier-based suspension persistence, forward-secure commitment for dark node closure, commit-reveal verdict observability, and light Sybil resistance can surface content that a popularity baseline misses, without a trusted server.

**Stack:** Python or Rust · NumPy/ndarray · hnswlib · EMP-toolkit (Pinkas PSI) · tendermint-rs (BFT consensus) · blst (BLS signatures) · Poseidon crate (arkworks-rs) · Simulated network for Experiments 1–3 · Katzenpost (Loopix/Sphinx) + Dandelion++ for Experiment 4.

**Datasets:**

| Dataset               | Purpose                                      |
| --------------------- | -------------------------------------------- |
| LastFM HetRec 2011    | Long-tail music; sparse; DP-CF benchmark     |
| MovieLens 1M/25M      | Dense mainstream; baseline contrast          |
| RateYourMusic exports | Extreme niche; genuinely sparse              |
| User platform exports | Real niche signal; preference initialization |

**Experiments:**

_E1 — Does it recommend at all?_ Precision@K, NDCG, HR, long-tail discovery rate per segment (head / long-tail). Gate: beats popularity baseline on long-tail discovery.

_E2 — Content discovery under noise per segment._ Chopping vs. Laplace across head / long-tail. Gate: long-tail precision ≥ popularity baseline.

_E3 — Sybil damage by attack type and SSP scenario._ All RobuRec types × Dense/Distributed/Sparse SSP. Gate: damage measurable and bounded.

_E4 — PSI peer selection and identity rotation._ Gate: PSI improves precision@K; VRF degrades by < 20%.

### 9.2 PoC Phases

**Phase 1 — Identity, Network, and Blockchain Core**

Poseidon PRF epoch IDs and permutation; null_v local derivation; staggered epoch offsets; variable chopping with VRF-jittered n_v(T); niche item announcement delay; identity VDF chain with interaction checkpoints; Pedersen commitment; Merkle tree with peer-attested leaves; HNSW snapshot storage for rewind; Shamir distribution to auditor committee; Katzenpost (Loopix/Sphinx) transport with provider-based NAT traversal; SURB-based request-response; Dandelion++ for broadcast fluff phase with timeout retry; Sphinx fixed-size packet padding; Noise Protocol sessions for clearnet/dev only; Loopix loop and drop cover traffic at base Poisson rate; communication rhythm; entry protocol; Class 2 passive audit; first-observation report collection and committee chain submission; ADMITTING health tier.

ForwardCommit construction and per-epoch commit_T publication; Statement 5 extended circuit (four checks + SMT path) in Plonky3; DECRYPTION_SMT initialization; verdict_commit and verdict_reveal transaction types; null_v_decryption transaction type and permissionless aggregation; watchdog_signal transaction type; DKG protocol for per-epoch committee threshold BLS key.

Public blockchain: block structure and VDF chaining; SUSP_SMT initialization; VRF validator and proposer selection with dual cluster constraints; BLS threshold signatures for block finality; Tendermint-style proposer timeout fallback; double-signing detection; genesis validator set and transition protocol; light client block header storage with Merkle inclusion proofs; per-n-epoch commit batching.

Committee chain: threshold-held encrypted ledger; committee handoff protocol between rotating committees; Shamir share rotation; continuity proof storage; first-observation report storage; fine-grained behavioral data storage.

Relay nodes: VRF selection; submission batching; reputation model integration.

_Exit: N nodes cycling through staggered epochs over the Loopix/Sphinx mixnet with public state on public chain and sensitive state on committee chain. Block finality verified. Double-signing detection verified. Light client sync verified. Class 2 audit flow end-to-end verified. Relay submission verified. Statement 5 proof generation and verification end-to-end verified. commit_T published and verified each epoch. Commit-reveal verdict flow end-to-end verified including permissionless aggregation. DECRYPTION_SMT insertion verified. Watchdog signal broadcast verified. Dark node extraction verified — node goes offline after publish, committee decrypts from commit_T._

**Phase 2 — Reputation and Sybil Resistance**

Per-epoch score including validator/relay service components; slow reputation decay; consistency and smoothness detection; rewind signal trigger with cohort correlation; HNSW snapshot rollback; multi-auditor encrypted handoff; Class 3 audit trigger; justified disclosure; compound flag system including coordinated rewind signal detection; behavioral cluster computation; interest cluster FoolsGold; cross-cluster behavioral FoolsGold; inter-cluster reputation; trust attenuation; commit-reveal SUSPENDED verdicts with null_v extraction and SUSP_SMT insertion; behavioral fingerprint matching; suspicious restart detection; committee-attested score band publication; watchdog signal compound flag entry; stalling minority detection and non-response penalty; recursive oversight chain with hard depth limit.

_Exit: Multi-auditor handoff correctly detects inconsistent state. On-chain verdicts survive epoch rotation. null_v correctly inserted into SUSP_SMT on suspension. Re-admission from same sk correctly rejected by Statement 5. Behavioral fingerprint matching flags suspicious new admissions. Both FoolsGold variants functional. Watchdog signal correctly triggers on anomalous commit rate. Stalling member correctly flagged. Oversight chain resolves correctly under honest majority. Rogue committee simulation correctly detected and blocked before null_v recovery._

**Phase 3 — Cryptographic Layer**

ZK consistency proofs (Statements 1–3, 5); sign preservation constraint enforcement; ZK continuity proofs (committee chain); handoff ZK proof; rewind signal aggregation; mobile benchmarks for all ZK components; Poseidon PRF security analysis (closed — OQ-1); domain separator collision check (closed — OQ-4); ForwardCommit security analysis (closed — OQ-2); extended Statement 5 mobile benchmark; dec_nullifier collision resistance analysis (closed — OQ-5); BLS-based ForwardCommit instantiation formal review; permutation reconstruction security benchmark; Pinkas PSI performance on mobile.

**Phase 4 — CF and Noise Calibration**

Full signed preference model; asymmetric PSI cache decay; two-tier peer selection; variable chopping with empirical n calibration; cover items post-n_cover; trust attenuation in CF weight; dislike-aware scoring; noise system comparison per segment (head / long-tail); adjacent-epoch weight validation; behavioral fingerprint calibration; n_commit calibration; niche announcement delay calibration.

**Phase 5 — Adversarial Simulation**

5.1 Recommendation poisoning — all RobuRec types × all SSP scenarios
5.2 Sybil flooding at genesis — join-rate spike detection
5.3 Patient adversary — smoothness detection calibration
5.4 On-off attack — Δ_rise tension validation
5.5 Diversity bonus exploitation
5.6 Interest cluster seeding — gradual infiltration
5.7 Behavioral cluster false positives — co-located legitimate users
5.8 Coordinated announcement vs. viral discovery — TPR/FPR
5.9 Semantic poisoning within chopping obfuscation
5.10 Eclipse attack exposure
5.11 Noise system comparison under attack
5.12 FoolsGold calibration — interest and behavioral variants
5.13 Multi-auditor handoff false rejection rate
5.14 Auditor collusion resistance — K_committee calibration
5.15 Validator collusion resistance — K_validators calibration
5.16 VDF gap tolerance from mobile connectivity data
5.17 Adjacent-epoch CF weight calibration
5.18 Cover item threshold n_cover calibration
5.19 Jaccard PSI threshold calibration
5.20 First-observation aggregation calibration
5.21 Admission window length n calibration
5.22 Behavioral fingerprint matching θ_behavioral and T_behavioral_window calibration
5.23 Epoch rotation evasion — sophisticated adversary varying behavioral patterns
5.24 Blockchain liveness under validator dropout
5.25 Block VDF proposer timeout calibration
5.26 Genesis transition timing — when is the validator pool viable?
5.27 Variable chopping privacy gain vs. CF quality — n_base and n_jitter per sparsity tier (head / long-tail)
5.28 Relay submission batching — timing obfuscation vs. submission latency
5.29 n_commit calibration — behavioral fingerprint degradation vs. audit freshness
5.30 Reputation decay δ_decay — legitimate absence tolerance vs. maintenance incentive
5.31 Committee chain availability under member dropout and rotation
5.32 Rewind signal adversarial triggering — N_rewind calibration
5.33 p_v targeted inflation within Statement 1/3 bounds — damage quantification
5.34 Bootstrap behavioral cluster relaxation — transition timing calibration
5.35 HNSW snapshot storage overhead vs. rewind recovery quality
5.36 Niche item announcement delay — τ_niche and max_delay_epochs calibration
5.37 Dark node re-admission damage — admission window gap
5.38 SUSP_SMT growth rate and non-membership proof latency as function of suspended node count
5.39 Statement 5 circuit performance on mobile hardware across SUSP_SMT depth
5.40 Commit-reveal latency vs. epoch duration — suspension finality timing
5.41 Watchdog signal false positive rate — threshold_watchdog calibration
5.42 Oversight chain depth limit — damage during resolution window
5.43 DKG timing constraint — epoch_transaction submission deadline calibration
5.44 Stalling minority attack — damage before oversight chain resolves
5.45 commit_T presence signal — behavioral fingerprinting impact vs. n_commit
5.46 Reputation laundering — sustained proactive identity rotation; cost amortization across cycles; behavioral fingerprint stability under deliberate variation (OQ-57; §7.9 row 19)
5.47 Novelty-kill saboteur — coordinated push of niche items past trust threshold to suppress novelty bonus; separation from organic early-popularity surges (§7.3 sabotage vector; §7.9 row 9)

### 9.3 Evaluation Metrics

**Recommendation quality:** Precision@K, NDCG, HR, long-tail discovery rate per popularity segment (head: top-X% of `trust_total` distribution; long-tail: remainder — boundary defined per deployment following Park & Tuzhilin, 2008), privacy-utility curve per segment, coverage, Prediction Shift. HNSW rewind recovery quality after poisoning event. The two segments have distinct signal properties: head items have dense co-occurrence signal and DP noise is relatively cheap; long-tail items are sparse, where chopping dominates and Laplace is destructive.

**Privacy:** Cross-epoch linkability; behavioral fingerprint re-identification rate under dual-chain model; interest cluster graph reconstruction rate from PSI traffic patterns; score trajectory entropy; permutation reconstruction time; ε-DP per gossip event (mainstream only); cover item anonymity set per segment; niche item announcement timing anonymity set size.

**Sybil resistance:** PS and HR per attack type and SSP scenario; p_v inflation damage within Statement bounds; patient adversary accumulation rate; smoothness detection false positive rate; FoolsGold TPR/FPR (both variants); announcement anomaly TPR/FPR; coordinated rewind signal detection TPR/FPR; epoch rotation evasion detection rate; dark node re-admission damage.

**Nullifier mechanism:** False rejection rate for honest nodes under Statement 5; SUSP_SMT non-membership proof latency on mobile as tree depth grows; Statement 5 circuit benchmark on mobile.

**Audit and blockchain:** False audit claim rate; handoff rejection false positive rate; auditor collusion detection rate; ZK proof times on mobile; block finality latency; validator dropout tolerance; double-signing detection latency; light client sync overhead; committee chain availability under rotation.

**Network health:** Health tier distribution over time; false positive rate per scenario; recovery time per health tier; Gini coefficient trajectory; gossip convergence time; VDF admission cost per hardware tier; public blockchain storage per light client; committee chain storage per committee member.

---

## 10. Open Questions and Status

### 10.1 Open Questions

| ID    | Question                                                                                                                                                            | Field            | Framework                | Tier | Effort | Status              |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ------------------------ | ---- | ------ | ------------------- |
| OQ-3  | What is the maximum acceptable Statement 5 proof generation time on target mobile hardware across SUSP_SMT depths?                                                  | Cryptography     | empirical                | 3    | 1      | open                |
| OQ-3b | What is the maximum acceptable Statement 2 proof generation time on target mobile hardware at d=128 and d=256?                                                      | Cryptography     | empirical                | 3    | 1      | open                |
| OQ-9  | What weight calibration (w₁–w₆, δ_decay, α) correctly balances reputation score components under adversarial conditions — can `participation_rate` and `consistency` be driven in opposing directions, and which dominates? | Reputation       | empirical                | 3    | 2      | open                |
| OQ-10 | Does a stochastic block model-based argument yield a budget-scaled Sybil influence bound for PrivaCF's cluster topology?                                            | Sybil resistance | theoretical \| empirical | 2    | 5      | open                |
| OQ-11 | Is there a ZK circuit construction for behavioral cluster membership that supports justified disclosure without revealing the underlying fingerprint?               | Cryptography     | theoretical → empirical  | 2    | 4      | resolved (desktop) — two viable paths: (1) BBS+ attestation: committee chain issues a signed cluster attestation each epoch; node uses BBS+ selective disclosure to prove cluster = C without revealing epoch_id or fingerprint values; reuses BLS keys already in the stack (§4.9); simpler to implement first. (2) ZK k-means over public centroids (Plonky3): because centroids are public, squared-distance comparison reduces to an inner product of private F with public coefficient vectors plus a range proof on the result — no quadratic terms; estimated ~2–3k constraints at d=100, k=10; proof time under 100ms on desktop with Plonky3. The remaining design work for path (2) is tying the private fingerprint witness to epoch_id inside the circuit (likely a Merkle path or hash preimage), which adds cost but is not a feasibility blocker. Mobile is a compatibility target, not a PoC requirement; both paths are deferred on mobile pending benchmarks. |
| OQ-12 | What is the minimum genesis set size for bootstrap viability, and at what point can the behavioral cluster diversity constraint be enforced without relaxation?     | Network          | empirical                | 3    | 3      | partial — the genesis set floor is now bounded by interest-cluster committee viability (not dual-cluster coverage), since the recommendation layer remains useful during the behavioral-cluster-relaxed bootstrap phase via content-based cold-start (§13). The enforcement threshold (when behavioral fingerprints have sufficient temporal depth and cluster density) remains open; see OQ-44 for the tightening schedule. |
| OQ-13 | Are validator incentives sufficient to prevent long-term shirking without token rewards?                                                                            | Reputation       | theoretical \| empirical | 2    | 3      | open                |
| OQ-14 | What is the correct staleness window for SUSP_SMT_root references in Statement 5 — how old can the root be before the non-membership proof is no longer meaningful? | Cryptography     | theoretical              | 1    | 2      | open                |
| OQ-15 | Does trust_total converge to a stable distribution under sustained adversarial flooding, or does it oscillate?                                                      | Sybil resistance | theoretical              | 1    | 3      | open                |
| OQ-16 | What is the expected damage from dark node re-admission during the admission window gap, as a function of n and c?                                                  | Sybil resistance | theoretical → empirical  | 2    | 3      | open                |
| OQ-17 | Can off-chain committee collusion executing a covert ForwardCommit decryption be detected, and what is the damage bound below the Byzantine majority threshold?     | Cryptography     | theoretical              | 2    | 3      | open                |
| OQ-18 | What is the correct VDF gap tolerance policy — at what point should a partially completed chain be invalidated vs. allowed to resume?                               | Identity         | empirical                | 3    | 2      | open                |
| OQ-19 | What is the minimum cover item count n_cover that provides meaningful anonymity set protection without degrading CF quality?                                        | Privacy          | empirical                | 3    | 2      | open                |
| OQ-20 | What are the correct PSI cache decay values λ_proof and λ_noproof across community sparsity profiles?                                                               | Network          | empirical                | 3    | 2      | open                |
| OQ-21 | What value of μ correctly attenuates hop-distance trust without suppressing legitimate long-range CF signal?                                                        | CF               | empirical                | 3    | 2      | open                |
| OQ-22 | How long does permutation reconstruction take under realistic gossip observation rates, and does it meaningfully threaten preference privacy?                       | Privacy          | empirical                | 3    | 2      | open                |
| OQ-23 | What Jaccard PSI threshold θ_cluster optimally balances peer quality against cluster size across different community types?                                         | Network          | empirical                | 3    | 2      | open                |
| OQ-24 | What FoolsGold θ_contrib minimizes false positives against coordinated Sybils while tolerating legitimate taste convergence?                                        | Sybil resistance | empirical                | 4    | 3      | open                |
| OQ-25 | Does the 0.5× adjacent-epoch CF weight default correctly discount stale gossip vectors, or does it over-penalize nodes with slow interaction rates?                 | CF               | empirical                | 3    | 2      | open                |
| OQ-26 | What auditor committee size K_committee minimizes collusion probability while remaining viable under cluster diversity constraints?                                 | Reputation       | empirical                | 4    | 3      | open                |
| OQ-27 | What validator set size K_validators correctly balances BFT safety margin against participation overhead?                                                           | Network          | empirical                | 3    | 2      | open                |
| OQ-28 | What behavioral cluster similarity threshold minimizes false positives from co-located legitimate users while catching coordinated Sybils?                          | Sybil resistance | empirical                | 4    | 3      | open                |
| OQ-29 | What smoothness variance floor σ²_floor separates legitimate consistent participation from adversarial reputation smoothing?                                        | Sybil resistance | empirical                | 4    | 3      | open                |
| OQ-30 | What is the correct maximum frame size across all protocol message types?                                                                                           | Network          | empirical                | 1    | 1      | open                |
| OQ-31 | What interaction checkpoint schedule within the admission window best balances re-identification risk against Sybil detection signal?                               | Identity         | empirical                | 3    | 2      | open                |
| OQ-32 | How many first-observation reports are needed for a meaningful coordinated admission signal?                                                                        | Reputation       | empirical                | 3    | 2      | open                |
| OQ-33 | What is the maximum acceptable handoff ZK proof generation time on target mobile hardware?                                                                          | Cryptography     | empirical                | 1    | 1      | open                |
| OQ-34 | What behavioral fingerprint similarity threshold θ_behavioral correctly flags suspicious new admissions without over-penalizing legitimate users?                   | Sybil resistance | empirical                | 4    | 3      | open                |
| OQ-35 | What is the correct T_behavioral_window — how long should a suspended fingerprint continue to flag new admissions?                                                  | Sybil resistance | empirical                | 4    | 2      | open                |
| OQ-36 | Is one epoch sufficient for peer attestation retention, or do audit windows require longer retention?                                                               | Reputation       | empirical                | 1    | 1      | open                |
| OQ-37 | What n_commit value optimally degrades behavioral fingerprinting precision without creating an audit freshness gap?                                                 | Privacy          | empirical                | 3    | 2      | open                |
| OQ-38 | What reputation decay rate δ_decay tolerates legitimate absence without allowing dormant adversarial nodes to maintain inflated reputation?                         | Reputation       | empirical                | 3    | 2      | open                |
| OQ-39 | What committee chain availability protocol survives member dropout and rotation without creating handoff gaps?                                                      | Reputation       | empirical                | 3    | 3      | open                |
| OQ-40 | What relay node batching window provides meaningful submission timing obfuscation without unacceptable submission latency?                                          | Network          | empirical                | 3    | 2      | open                |
| OQ-41 | What n_jitter range provides sufficient vector size obfuscation without degrading CF quality in sparse communities?                                                 | Privacy          | empirical                | 3    | 2      | open                |
| OQ-42 | What N_rewind rate limit prevents adversarial Class 3 triggering while allowing legitimate quality degradation signals through?                                     | Reputation       | empirical                | 3    | 2      | open                |
| OQ-43 | What is the expected p_v inflation damage within Statement 1 and 3 bounds, and at what point does it meaningfully degrade recommendation quality?                   | Sybil resistance | empirical                | 4    | 3      | open                |
| OQ-44 | What is the correct bootstrap behavioral cluster relaxation schedule — how quickly should the diversity constraint tighten as the network matures?                  | Network          | empirical                | 3    | 2      | open                |
| OQ-45 | How many HNSW snapshots should be retained, and at what depth does rewind recovery quality degrade below usefulness?                                                | CF               | empirical                | 3    | 2      | open                |
| OQ-46 | What announcement delay parameters τ_niche and max_delay_epochs correctly balance niche item re-identification risk against discovery signal propagation?           | Privacy          | empirical                | 3    | 2      | open                |
| OQ-47 | How does SUSP_SMT non-membership proof latency scale with suspended node count on target mobile hardware?                                                           | Cryptography     | empirical                | 3    | 2      | open                |
| OQ-48 | What watchdog threshold correctly separates legitimate suspension bursts from rogue committee activity?                                                             | Reputation       | empirical                | 3    | 2      | open                |
| OQ-49 | What oversight chain depth limit and escalation schedule bounds damage during the resolution window without creating liveness risks?                                | Reputation       | empirical                | 4    | 3      | closed — structural question resolved by Chernoff bound; empirical calibration (K_0, ΔK) remains in Phase 5 |
| OQ-50 | What DKG completion deadline correctly constrains the epoch_transaction submission window without creating liveness pressure on slow committee members?             | Network          | empirical                | 3    | 2      | open                |
| OQ-51 | What is the behavioral fingerprinting impact of per-epoch commit_T submission relative to n_commit batching?                                                        | Privacy          | empirical                | 3    | 2      | open                |
| OQ-52 | What is the expected damage from a stalling minority attack before the oversight chain resolves?                                                                    | Reputation       | empirical                | 4    | 3      | open                |
| OQ-53 | Can off-chain committee collusion be detected in arrears from public chain data, and what damage is possible below the Byzantine majority threshold?                | Cryptography     | theoretical              | 2    | 3      | open                |
| OQ-54 | Which noise mechanism (chopping vs. Laplace) and at what parameters correctly trades privacy for CF quality across head and long-tail segments?                     | CF               | empirical                | 3    | 2      | open                |
| OQ-55 | Can the SecLDP trust model from the unified DP-DL MF framework (Cyffers et al., arXiv:2510.17480, 2025) be adapted to derive formal GDP bounds on PrivaCF's gossip exchange, parameterized by n_v(T), the Laplace noise scale, and the permutation key?       | Privacy          | theoretical              | 2    | 3      | open                |
| OQ-56 | Does PrivaCF's item-based CF on accumulated gossip vectors achieve comparable recommendation quality to gossip-based matrix factorization (Hegedűs et al., ECML PKDD 2019) under matched sparsity conditions on MovieLens and RateYourMusic?                    | CF               | empirical                | 3    | 2      | open                |
| OQ-57 | Can sustained reputation laundering — proactive identity rotation across many cycles — amortize admission cost in a way that defeats the rate-limiting effect of the VDF chain, and does behavioral fingerprinting hold against a launderer who deliberately varies patterns across cycles? | Sybil resistance | theoretical \| empirical | 2    | 3      | open                |
| OQ-58 | What base Poisson rate λ for Loopix loop and drop cover traffic provides sufficient anonymity against a mix-node-observing adversary without imposing unacceptable bandwidth overhead on metered or mobile deployments, and what is the correct λ per config (A–E)? | Network | empirical | 3 | 2 | open |

**Notes on selected questions**

**OQ-10 (Sybil influence bound):** The non-overwhelming rule is borrowed from DSybil but the formal theorem does not transfer — it requires a persistent social graph, trust propagation via random walks, and a sparse honest/Sybil cut, none of which exist in PrivaCF. Two parallel formal paths are being pursued.

_Path A — stochastic block model:_ The appropriate formal goal is a stochastic block model-based argument (Holland, Laskey & Leinhardt, 1983) treating clusters as blocks with probabilistic inter-cluster interaction, yielding a budget-scaled bound rather than an absolute one. The approach that closed OQ-49 is the template. There, VRF selection with dual cluster diversity constraints guarantees independent random committee draws from a pool with adversarial fraction q; the Chernoff bound then gives exponential decay in compromise probability as a function of committee size. The same structural property — independent random sampling from a pool with bounded adversarial fraction — holds at the peer selection layer: PSI-selected interest clusters and VRF-selected behavioral clusters together give you independent draws, and admission cost plus behavioral fingerprinting bound q in the eligible pool. The Chernoff argument should therefore yield an exponential concentration bound on adversarial cluster membership as a function of adversary budget. The open work is adapting that bound to the CF influence setting — committee compromise is a clean binary event; CF influence is a continuous quantity that depends on the recommendation scoring function, the trust cap c, and the gossip vector structure. Bounding influence on CF output as a function of adversarial cluster membership fraction is the remaining step — likely requiring a sensitivity argument on the item-based CF scoring function under bounded adversarial weight injection.

_Path B — MeritRank ratio bound:_ Nasrulin et al. (IEEE BRAINS 2022) prove a formal Sybil ratio bound for MeritRank: `lim|S|→∞ w⁺(σS) / w⁻(σS) ≤ c`, where attack profit and cost maintain a constant ratio as Sybil count grows. This is a tighter, cleaner statement than the non-overwhelming heuristic. The bound is proven under random-walk trust propagation, which PrivaCF does not use, so it does not transfer directly. However, PrivaCF's trust cap c directly caps per-item adversarial weight injection by construction, and the non-overwhelming rule ensures c is the ceiling on per-item benefit. A ratio bound of the same form under PrivaCF's PSI-based ephemeral topology — no transitive trust, peer sets refreshed each epoch — would require a new argument, but the MeritRank bound provides both a target statement and a proof structure to adapt. This path may yield a result faster than Path A since the ratio form is simpler than a full sensitivity argument.

The sleeper attack escapes any purely structural argument on either path since it satisfies cluster membership criteria honestly; residual defense for that case remains behavioral. Config E remains the conservative fallback for deployments requiring formal guarantees before this is resolved. See §7.3.

**OQ-49 (Oversight chain depth limit — closed):** See §10.2 and §4.9.8. The structural question is closed by the Chernoff bound argument. Empirical calibration of K_0 and ΔK remains, addressed in Phase 5 experiment 5.42.

**OQ-53 (Off-chain committee collusion):** The Chernoff argument that closed OQ-49 bounds committee compromise for protocol-visible selection events. Off-chain collusion is the residual attack it does not cover — a colluding supermajority can aggregate σ and decrypt `commit_T` without going through the commit-reveal flow, leaving no on-chain trace unless they subsequently submit a `null_v_decryption` transaction. The open question is whether meaningful damage below the Byzantine majority ceiling is detectable in arrears from public chain data alone, and whether per-epoch key rotation tightens the practical damage window below that ceiling.

---

### 10.2 Resolved Prerequisites

All blocking prerequisites have been resolved or reclassified as non-blocking empirical calibration. See §10.1 for open questions.

**Closed or reclassified as non-blocking**

| ID    | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OQ-C1 | `trust_total` convergence under adversarial flooding — closed by inspection. Bounded above by `c` by construction; the update rule halts contributions once the cap is reached regardless of flooding rate. The residual question (can adversaries push `trust_total` to `c` before honest contributions arrive) is a restatement of the Sybil influence problem addressed by OQ-10, not a separate convergence concern.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| OQ-C2 | Single-decryption enforcement — closed by the DECRYPTION_SMT design. A second `null_v_decryption` transaction for the same `verdict_hash` produces the same `dec_nullifier`, already in the tree; honest validators reject the containing block.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| OQ-1  | Poseidon PRF + EC-VRF security — resolved by primitive split. Local derivations (epoch ID, permutation, chop count, offset, niche delay, leaf salt) use Poseidon as a keyed PRF; pseudorandomness under standard Poseidon assumptions suffices and no verifiability property is required. On-chain verifiable selection (validator, committee, relay) uses EC-VRF (RFC 9381), reducing to DLEQ/DDH with production implementations in tendermint-rs. See §4.2.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| OQ-2  | ForwardCommit security — resolved as Boneh-Franklin IBE over BLS12-381 (Boneh & Franklin, CRYPTO 2001). Security reduces to DBDH in the random oracle model. DST alignment between BLS signing and IBE key derivation must be explicitly specified. Collusion carve-out bounded by Byzantine majority assumption. See §4.9.4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| OQ-4  | Domain separator collision resistance — all derivations using `sk` now have a unique explicit (domain_sep, input_structure) pair after adding `"epoch_id"` and `"niche_delay"` separators. Collision argument reduces to standard Poseidon collision resistance. See §4.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| OQ-5  | dec_nullifier collision resistance — reduces to standard Poseidon collision resistance. `verdict_hash` is fixed on-chain before `null_v` is recovered, so chosen-input attacks are not applicable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| OQ-6  | Stannat Condition 3 — reclassified as empirical calibration. The "Stannat Conditions" label was not sourced to any published result. The tension between path-responsiveness and on-off attack defense is real but is a calibration question, not a blocking one. Addressed in Phase 5 experiment 5.4. See §7.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| OQ-7  | Oversight chain liveness — terminates by induction under honest majority (assumption A2). At each recursive level, a VRF-selected meta-committee with escalating size runs the same commit-reveal flow; under A2, each level terminates in finite expected time by the standard BFT argument (Castro & Liskov, 1999). The hard depth limit ensures termination even under degraded honesty conditions by capping the recursion before the honest majority fraction can fall below the BFT threshold. What remains open is the empirical question of how much damage accumulates during the resolution window — addressed by OQ-49.                                                                                                                                                                                                                                                                           |
| OQ-8  | Off-chain committee collusion — damage limited to targeted off-chain epoch ID linkage with no protocol consequence unless an on-chain transaction is submitted (at which point it becomes visible). Fully bounded by Byzantine majority assumption. See §8.1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| OQ-3  | Statement 5 mobile benchmark — reclassified as non-blocking. Not a PoC blocker; required before any mobile deployment. See §10.1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-3b | Statement 2 mobile benchmark — reclassified as non-blocking. Same status as OQ-3. See §10.1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| OQ-49 | Oversight chain depth limit — closed by Chernoff bound argument. Given that each level's committee is drawn independently via VRF with dual cluster diversity constraints, P(compromise at level d) = P(Bin(K_d, q) ≥ ⌊K_d/2⌋+1), which decays exponentially in K_d by the Chernoff bound. Cumulative escape probability is a product of independent per-level terms, each strictly less than 1, giving exponential decay in depth. With K_d growing linearly (K_d = K_0 + d·ΔK), per-level compromise probability itself shrinks with d, yielding doubly-exponential decay overall. Since any polynomial instance count (budget/cost) is dominated by exponential per-instance decay, a finite depth always suffices for any target success probability. The remaining calibration questions — concrete values of K_0 and ΔK for the target network — are addressed in Phase 5 experiment 5.42. See §4.9.8. |

---

### 10.3 Proposed Experiments

Experiments are ordered by dependency tier. Tier 1 requires no infrastructure and no theoretical prerequisites — pen-and-paper or straightforward measurement work only. Tier 2 requires theoretical groundwork before experiment design is meaningful. Tier 3 requires Phase 1 infrastructure. Tier 4 requires Phase 2 or later. Only open questions appear here; closed questions (OQ-4, OQ-5, etc.) have been resolved and are not listed.

---

**Tier 1 — No prerequisites**

_OQ-14 — SUSP_SMT staleness window._ Derive analytically the maximum acceptable age for a SUSP_SMT root reference in Statement 5 such that a suspended node cannot exploit root staleness to pass a non-membership proof. Expected output: a closed-form bound as a function of epoch duration and block finality latency. Effort: low.

_OQ-15 — trust_total convergence under adversarial flooding._ Model trust_total dynamics under sustained adversarial flooding as a bounded accumulator with a cap at `c`. Show analytically whether honest contributions can be crowded out before the cap is reached under different adversarial budget assumptions. Expected output: a characterization of the crowding-out condition as a function of adversarial budget and arrival rate. Effort: moderate.

_OQ-30 — Frame size._ Enumerate all protocol message types from Appendix A. Measure maximum serialized size for each under worst-case inputs. Set frame size to the maximum plus a fixed overhead margin. Expected output: a concrete frame size recommendation. Effort: minimal.

_OQ-33 — Handoff ZK proof generation time._ Build the Statement 5 circuit in Plonky3. Run on target mobile hardware (mid-range Android, iPhone SE class). Measure wall-clock proof generation time. Gate: under 2 seconds. Expected output: a benchmark table across hardware tiers. Effort: low once circuit exists.

_OQ-36 — Peer attestation retention._ Derive analytically the maximum audit query window across all audit classes. Confirm whether one epoch of attestation retention covers all cases or whether longer retention is required. Expected output: a retention period recommendation with justification. Effort: minimal.

---

**Tier 2 — Theoretical groundwork required first**

_OQ-1 — Poseidon PRF security analysis._ **Closed.** Resolved by primitive split: local derivations use Poseidon as a keyed PRF (pseudorandomness under standard Poseidon assumptions suffices); on-chain verifiable selection uses EC-VRF (RFC 9381). See §10.2.

_OQ-2 — ForwardCommit security analysis._ **Closed.** Resolved as Boneh-Franklin IBE over BLS12-381; reduces to DBDH in the random oracle model. DST alignment must be explicitly specified. See §10.2.

_OQ-6 — Stannat Condition 3._ Determine analytically whether a `Δ_rise` value exists that simultaneously satisfies path-responsiveness and on-off attack defense. If no such value exists, characterize the tradeoff curve so governance can make an informed choice. Expected output: either a satisfying `Δ_rise` with proof, or a proof of incompatibility with a tradeoff characterization. Effort: high.

_OQ-10 — Sybil influence bound._ Theoretical route: construct a stochastic block model with clusters as blocks and derive a budget-scaled influence bound. Empirical route: simulate adversarial strategies against the cluster topology on labeled datasets and measure influence as a function of adversarial budget. The theoretical route is prerequisite to interpreting empirical results cleanly. Expected output: either a formal bound or a calibrated empirical characterization with explicit adversary assumptions. Effort: very high.

_OQ-17 — Off-chain committee collusion._ Analyze the maximum damage a colluding committee supermajority can cause by executing a covert off-chain ForwardCommit decryption. The ceiling is the Byzantine majority assumption; the question is whether meaningful damage is possible below that ceiling and whether it is detectable in arrears from public chain data. Expected output: a damage bound and a detectability argument. Effort: moderate.

_OQ-53 — Off-chain collusion detectability._ Related to OQ-17 but focused on the detection side: given only the public chain, can an observer reconstruct evidence of a covert decryption that did not go through the commit-reveal flow? Expected output: either a detection protocol or a proof that covert decryption is undetectable below threshold collusion. Effort: moderate.

---

**Tier 3 — Requires Phase 1 infrastructure**

_OQ-3 — Statement 5 mobile benchmark._ Instrument the full Statement 5 circuit in Plonky3. Benchmark on target mobile hardware across a range of SUSP_SMT depths. Gate: proof generation under per-epoch budget on mid-range hardware. Expected output: a benchmark table and a recommended maximum SUSP_SMT depth. Effort: low once circuit exists.

_OQ-3b — Statement 2 mobile benchmark._ Instrument the inner product argument for directional consistency at d=128 and d=256 on Plonky3/WASM. Benchmark on target mobile hardware. Gate: proof generation under per-epoch budget alongside Statement 5. Expected output: a benchmark table and a recommended maximum vector dimension. Effort: low once circuit exists.

_OQ-18 — VDF gap tolerance._ Run the admission VDF chain on simulated mobile connectivity profiles. Measure chain failure rates as a function of gap tolerance policy. Expected output: a gap tolerance recommendation calibrated to realistic mobile usage. Effort: low.

_OQ-19 — Cover item threshold._ Vary n_cover and measure anonymity set size against CF quality degradation on LastFM and RateYourMusic. Expected output: a recommended n_cover per sparsity tier (head / long-tail). Effort: low.

_OQ-20 — PSI cache decay calibration._ Simulate epoch rotation with varying λ_proof and λ_noproof values. Measure peer set stability against re-identification risk. Expected output: recommended λ values per community sparsity profile. Effort: moderate.

_OQ-21 — μ calibration._ Vary μ and measure CF quality at different hop distances on MovieLens and LastFM. Expected output: a recommended μ value and sensitivity curve. Effort: low.

_OQ-22 — Permutation reconstruction time._ Simulate an adversary observing gossip vectors across multiple epochs and attempting to reconstruct the underlying permutation. Measure reconstruction success rate as a function of observation count and n_jitter range. Expected output: a minimum observation count required for meaningful reconstruction. Effort: moderate.

_OQ-25 — Adjacent-epoch CF weight._ Compare recommendation quality with the 0.5× adjacent-epoch discount applied vs. equal weighting, across dense and sparse datasets. Expected output: a recommended weight and sensitivity analysis. Effort: low.

_OQ-37 — n_commit calibration._ Simulate behavioral fingerprinting attack against public chain timing data at varying n_commit values. Measure re-identification rate against audit freshness window. Expected output: a recommended n_commit value. Effort: moderate.

_OQ-47 — SUSP_SMT proof latency scaling._ Measure SMT non-membership proof generation time on target mobile hardware as tree depth grows to projected maximum. Expected output: a latency curve and a recommended maximum tree depth. Effort: low.

---

**Tier 4 — Requires Phase 2 or later**

_OQ-24 — FoolsGold θ_contrib calibration._ Run both interest-cluster and behavioral-cluster FoolsGold variants against labeled Sybil datasets. Sweep θ_contrib and measure TPR/FPR. Expected output: recommended thresholds per community type. Effort: moderate.

_OQ-26 — Auditor committee size K_committee._ Simulate committee collusion attempts at varying K_committee values under cluster diversity constraints. Measure collusion probability as a function of adversarial budget and cluster structure. Expected output: a recommended K_committee with a collusion probability bound. Effort: moderate.

_OQ-28 — Behavioral cluster false positive rate._ Simulate co-located legitimate users and measure behavioral cluster false positive rate under the compound flag system. Expected output: a characterization of false positive conditions and a recommended θ_behavioral. Effort: moderate.

_OQ-29 — Smoothness floor calibration._ Run smoothness detection against legitimate consistent nodes and adversarial sleeper nodes across varying σ²_floor values. Measure TPR/FPR. Expected output: a recommended σ²_floor per community type. Effort: moderate.

_OQ-34 — Behavioral fingerprint matching calibration._ Simulate sophisticated epoch rotators varying behavioral patterns across re-admission attempts. Measure detection rate as a function of θ_behavioral and T_behavioral_window. Expected output: recommended parameter values with a characterization of the evasion boundary. Effort: high.

_OQ-43 — p_v inflation damage quantification._ Simulate targeted p_v inflation within Statement 1 and 3 bounds on MovieLens and RateYourMusic. Measure recommendation quality degradation as a function of inflation magnitude and target item popularity segment (head / long-tail). Expected output: a damage characterization per segment. Effort: moderate.

_OQ-9 — Reputation weight calibration._ Simulate adversarial nodes attempting to maximize `participation_rate` while degrading `consistency` (and vice versa). Sweep w₁–w₆, δ_decay, and α across ranges. Measure which component dominates under each adversarial strategy and identify weight combinations that resist manipulation. Expected output: recommended default weight values with adversarial resistance characterization. Effort: moderate.

_OQ-54 — Noise system calibration per segment._ On MovieLens and RateYourMusic, split items into head and long-tail by popularity (Park & Tuzhilin boundary). Apply chopping and Laplace DP noise at varying parameters for each segment. Measure Precision@K, NDCG, long-tail discovery rate, and privacy-utility curve per segment. Expected output: recommended noise mechanism and parameters per segment. Effort: moderate. Note: if content-based bootstrapping (§13) is available for long-tail items, the effective signal density for those items improves, shifting where chopping and Laplace diverge — the experiment should be run both with and without content bootstrapping.

_OQ-49 — Oversight chain depth limit._ **Structural question closed** by Chernoff bound argument (see §4.9.8, §10.2). Empirical calibration of K_0 and ΔK remains: simulate recursive oversight chains under varying adversarial committee compositions to produce a recommended depth limit and escalation schedule. Effort: high.

_OQ-52 — Stalling minority damage._ Simulate a stalling minority at varying committee sizes. Measure damage accumulation before the oversight chain resolves. Expected output: a damage bound as a function of minority size and epoch duration. Effort: moderate.

---

## 11. Comparative Analysis

### 11.1 Identity and Privacy Properties

| System         | No central server | Pseudonymous identity       | Admission cost          | Behavioral privacy                  | Deployment |
| -------------- | ----------------- | --------------------------- | ----------------------- | ----------------------------------- | ---------- |
| **EigenTrust** | Partial (DHT)     | No                          | None                    | None                                | Research   |
| **TrustGuard** | Yes               | No                          | None                    | None                                | Research   |
| **SybilGuard** | Yes               | No                          | None                    | None                                | Research   |
| **DSybil**     | Partial           | No                          | None                    | None                                | Research   |
| **McSherry & Mironov (2009)** | No (central required for aggregation) | No | None | ε-DP formal bound on aggregation phase | Research (Netflix-scale) |
| **GOSSPLE**    | Yes               | Weak (proxy, long-term linkable) | None               | Bloom filter digests only; no formal bound | Research (PlanetLab) |
| **Hegedűs et al. (2020)** | Yes           | No                          | None                    | None (model params in plaintext)    | Research   |
| **Web3Recommend + MeritRank (2023)** | Yes | Pseudonym (persistent edges, linkable) | None | None                       | PoC (MusicDAO) |
| **Unified DP-DL MF (2025)** | Yes         | No                          | None                    | GDP formal (LDP / PNDP / SecLDP)   | Research   |
| **PrivaCF**    | Yes               | Yes (Poseidon PRF + EC-VRF) | VDF chain + checkpoints | Chopping/Laplace + ZK + niche delay | PoC        |

### 11.2 Sybil Resistance and Audit Properties

| System         | Sybil resistance                        | On-chain verdicts | Suspension persistence      | Dark node closure   | Observable extraction         | Recommendation output |
| -------------- | --------------------------------------- | ----------------- | --------------------------- | ------------------- | ----------------------------- | --------------------- |
| **EigenTrust** | None                                    | No                | N/A                         | N/A                 | N/A                           | No                    |
| **TrustGuard** | Oscillation detection                   | No                | N/A                         | N/A                 | N/A                           | No                    |
| **SybilGuard** | Graph-cut                               | No                | N/A                         | N/A                 | N/A                           | No                    |
| **DSybil**     | Non-overwhelming rule (heuristic in PrivaCF's setting) | No | N/A              | N/A                 | N/A                           | Partial               |
| **McSherry & Mironov (2009)** | None                   | No                | N/A                         | N/A                 | N/A                           | Yes (Netflix-scale)   |
| **GOSSPLE**    | None (certs assumed externally)         | No                | N/A                         | N/A                 | N/A                           | Yes (empirical)       |
| **Hegedűs et al. (2020)** | None                       | No                | N/A                         | N/A                 | N/A                           | Yes (gossip MF, empirical quality) |
| **Web3Recommend + MeritRank (2023)** | Formal ratio bound (random-walk setting) | No | None      | N/A                 | N/A                           | Yes (MusicDAO PoC)    |
| **Unified DP-DL MF (2025)** | None                      | No                | N/A                         | N/A                 | N/A                           | No                    |
| **PrivaCF**    | Non-overwhelming trust cap + temporal depth + FoolsGold + behavioral clustering (formal bound open — OQ-10) | Yes (permanent)   | Hard (nullifier + SUSP_SMT) | Yes — ForwardCommit | Yes — commit-reveal, watchdog | Yes                   |

### 11.3 Narrative Analysis

**Against the P2P reputation baselines (EigenTrust, TrustGuard, SybilGuard, DSybil):** each addresses one or two of the three core tensions — personalization, privacy, integrity — but none address all three. None provide pseudonymous identities, on-chain verdicts, or suspension persistence. DSybil provides a partial non-overwhelming trust bound but no privacy guarantees and no recommendation output. PrivaCF's contributions over these baselines are clear: rotating pseudonymous identity with cryptographic unlinkability; admission cost via sequential VDF; preference privacy via Pedersen commitments and gossip vector obfuscation; behavioral privacy via Merkle-committed history with ZK consistency proofs; permanent on-chain suspension verdicts surviving epoch rotation via the nullifier mechanism; dark node closure via forward-secure commitment; and observable extraction via commit-reveal ordering with public watchdog signals.

**Against McSherry & Mironov (2009):** this is the strongest comparison on privacy formalism. Their system achieves formal ε-DP for the Netflix Prize algorithms but requires a central server for the aggregation phase — the core architectural trade-off PrivaCF rejects. PrivaCF cannot currently make a comparable formal privacy claim. OQ-55 investigates whether the GDP framework from Cyffers et al. (2025) can close this gap for PrivaCF's gossip exchange without reintroducing central aggregation.

**Against GOSSPLE:** structurally closest to PrivaCF's gossip peer discovery. GOSSPLE uses Bloom filter digests over proxy-based two-hop paths to find interest-similar peers without revealing identity, validated empirically on PlanetLab. The anonymity is weak — proxy paths are linkable over time and no Sybil resistance exists. PrivaCF replaces the proxy with PSI (stronger non-revelation), adds identity rotation, admission cost, and the full audit stack. GOSSPLE's convergence results (~14–20 gossip cycles to stable peer sets) provide a useful lower-bound expectation for PrivaCF's PSI-based discovery phase.

**Against Hegedűs et al. (2020):** their gossip-based matrix factorization on fully distributed data — no central server, model parameters exchanged peer-to-peer — achieves comparable quality to federated learning. This directly validates that decentralized gossip is a viable substrate for CF quality. PrivaCF's gossip vector approach is architecturally similar but trades MF-level accuracy for stronger preference privacy (gossip vectors vs. raw latent factors). OQ-56 formalizes this comparison: whether PrivaCF's item-based CF on accumulated vectors matches Hegedűs-style MF under matched sparsity, giving PrivaCF its first empirical quality benchmark.

**Against Web3Recommend + MeritRank (2023):** the closest architectural competitor. Fully decentralized, gossip-based, Sybil-resistant, with a PoC deployment on a real music platform. MeritRank's formal ratio bound (`lim|S|→∞ w⁺/w⁻ ≤ c`) is a tighter formal statement than PrivaCF currently claims. The critical difference: Web3Recommend operates under pseudonyms with persistent graph edges — any observer can reconstruct the full trust graph and link identities across time. PrivaCF closes this with epoch rotation, the dual-chain architecture, and the nullifier mechanism. Web3Recommend also has no suspension persistence, no dark node closure, and no formal admission cost. The MeritRank ratio bound is being adapted as Path B for OQ-10.

**Against Unified DP-DL MF (2025):** provides formal GDP bounds for decentralized learning under three trust models. Their SecLDP model — privacy conditional on a hidden secret — maps directly onto PrivaCF's permutation-secret gossip exchange (the permutation key is the hidden secret; n_v(T) elements are the partially observable output). This is the technical basis for OQ-55. PrivaCF's Mafalda-SGD-equivalent would be the gossip vector chopping + Laplace noise mechanism; deriving the corresponding GDP bound would give PrivaCF its first formal privacy guarantee without architectural changes.

**Summary of residual gaps:** PrivaCF is the only system in this comparison with unlinkable rotating identity, suspension persistence, dark node closure, and decentralized operation simultaneously. The gaps are: no formal privacy bound (OQ-55 targets this), no formal Sybil influence bound (OQ-10 paths A and B), and no empirical recommendation quality benchmark (OQ-56). The residual architectural gap is threshold collusion for off-chain nullifier extraction, bounded by the same Byzantine majority assumption the consensus layer already depends on.

---

## 12. Related Work

| Reference                                                       | Relevance                                                                                                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Douceur (IPTPS 2002)                                            | Sybil attack definition and impossibility                                                                                                                                      |
| Cheng & Friedman (P2PEcon 2005)                                 | Sybil-proofness impossibility for symmetric functions                                                                                                                          |
| Kamvar, Schlosser & Garcia-Molina (WWW 2003)                    | EigenTrust                                                                                                                                                                     |
| Srivatsa, Kambhampati & Liu (ICDCS 2005)                        | TrustGuard — oscillation detection; asymmetric penalty                                                                                                                         |
| Yu, Kaminsky, Gibbons & Flaxman (SIGCOMM 2006)                  | SybilGuard                                                                                                                                                                     |
| Stannat, Ileri, Gijswijt & Pouwelse (AAMAS 2021)                | Sufficient conditions for personalized-seed Sybil resistance                                                                                                                   |
| Yu, Kaminsky, Gibbons & Flaxman (IEEE S&P 2009)                 | DSybil non-overwhelming trust                                                                                                                                                  |
| Viswanath, Becker, Gummadi & Mislove (IEEE S&P 2008)            | SybilLimit                                                                                                                                                                     |
| Tran, Min, Li & Subramanian (NDSS 2009)                         | SybilInfer                                                                                                                                                                     |
| Damiani et al. (2002)                                           | Reputation-based P2P trust                                                                                                                                                     |
| Fanti et al. (SIGMETRICS 2018)                                  | Dandelion++                                                                                                                                                                    |
| Pinkas, Rosulek, Trieu & Yanai (USENIX Security 2018)           | Unbalanced PSI                                                                                                                                                                 |
| Kolesnikov et al. (CCS 2016)                                    | KKRT circuit PSI (balanced)                                                                                                                                                    |
| Malkov & Yashunin (2018)                                        | HNSW                                                                                                                                                                           |
| Indyk & Motwani (STOC 1998)                                     | LSH                                                                                                                                                                            |
| McSherry & Mironov (KDD 2009)                                   | Differentially private CF                                                                                                                                                      |
| Parsarad & Wagner (2025)                                        | DP harm to sparse user recommendations                                                                                                                                         |
| Dwork, Rothblum & Vadhan (2010)                                 | Basic DP composition theorem                                                                                                                                                   |
| Werthenbach & Pouwelse (arXiv:2306.15044, 2023)                 | SSP attack taxonomy                                                                                                                                                            |
| Nasrulin et al. (IEEE BRAINS 2022)                              | MeritRank                                                                                                                                                                      |
| Sun, Han & Liu (2008)                                           | Asymmetric penalty mechanism                                                                                                                                                   |
| Fung et al. (RAID 2020)                                         | FoolsGold                                                                                                                                                                      |
| Perrin (2018)                                                   | Noise Protocol Framework                                                                                                                                                       |
| Jøsang & Ismail (2002)                                          | Beta Reputation System                                                                                                                                                         |
| Maram et al. (CCS 2021)                                         | CanDID — distributed credential storage                                                                                                                                        |
| Boneh et al. (2018)                                             | VDF constructions                                                                                                                                                              |
| Wesolowski (2018)                                               | Efficient VDF verification                                                                                                                                                     |
| Castro & Liskov (OSDI 1999)                                     | PBFT                                                                                                                                                                           |
| Buchman (2016)                                                  | Tendermint BFT consensus                                                                                                                                                       |
| Boneh, Drijvers & Neven (2018)                                  | BLS multi-signatures                                                                                                                                                           |
| Arshad et al. (IEEE Access 2022)                                | REPUTABLE                                                                                                                                                                      |
| Anonymous (J. Sens. Actuator Netw. 2023)                        | Blockchain + MPC decentralized reputation                                                                                                                                      |
| Shi, Zhang, Yin, Chi & Liu (Results in Engineering 2025)        | DSRep                                                                                                                                                                          |
| Möser et al. (2018)                                             | Monero transaction graph analysis; decoy selection distribution                                                                                                                |
| Sasson et al. (IEEE S&P 2014)                                   | Zcash — nullifier pattern for spent-note detection                                                                                                                             |
| WhiteHat (2019)                                                 | Semaphore — ZK group membership with nullifiers                                                                                                                                |
| Boneh, Bünz & Fisch (CRYPTO 2019)                               | Batched accumulator witnesses; SMT non-membership                                                                                                                              |
| Grassi, Khovratovich et al. (USENIX Security 2021)              | Poseidon hash function                                                                                                                                                         |
| Camenisch & Lysyanskaya (Eurocrypt 2001)                        | Traceable anonymous credentials                                                                                                                                                |
| Chaney, Stewart & Engelhardt (2018)                             | Recommendation feedback loops and filter bubble dynamics                                                                                                                       |
| Adomavicius & Tuzhilin (2005)                                   | CF assumptions survey                                                                                                                                                          |
| Hu, Koren & Volinsky (2008)                                     | Implicit feedback limitations                                                                                                                                                  |
| Leskovec, Adamic & Huberman (2007)                              | Information diffusion patterns, organic vs. coordinated spread                                                                                                                 |
| Blanchard et al. (2017)                                         | Byzantine-resilient aggregation (Krum)                                                                                                                                         |
| Sundaram & Hadjicostis (2011)                                   | Resilient distributed averaging                                                                                                                                                |
| Holland, Laskey & Leinhardt (1983)                              | Stochastic block models — suggested framework for OQ-10 formal analysis                                                                                                        |
| Boneh, Lynn, Shacham (ASIACRYPT 2001)                           | BLS signatures — threshold BLS used in commit-reveal flow                                                                                                                      |
| Pedersen (CRYPTO 1991)                                          | Verifiable secret sharing — basis for commit-reveal scheme                                                                                                                     |
| Siddarth, Ivliev, Siri & Berman (Frontiers in Blockchain, 2020) | "Who Watches the Watchmen?" — survey of subjective approaches to Sybil-resistance; frames the "who verifies the verifier" regress that the recursive oversight chain addresses |
| Park & Tuzhilin (RecSys 2008)                                   | Formal head/long-tail popularity split in CF evaluation; basis for head/long-tail segmentation in §9.3 and OQ-54                                                               |
| Abdollahpouri, Burke & Mobasher (FLAIRS 2019)                   | Popularity bias and re-ranking in recommender systems; head/long-tail framing                                                                                                  |
| Kermarrec, Van Roy, Ganesh & Voulgaris (MIDDLEWARE 2010)        | GOSSPLE — gossip-based anonymous social network using Bloom filter digests and proxy routing for interest-similar peer discovery; convergence results (~14–20 cycles) bound PrivaCF's PSI discovery expectations |
| Hegedűs, Danner & Jelasity (ECML PKDD 2019)                    | Gossip-based matrix factorization on fully distributed data; empirically comparable to federated learning; basis for OQ-56 CF quality benchmark                                |
| Trautwein, Ishmaev & Pouwelse (arXiv:2307.01411, 2023)          | Web3Recommend — decentralized social recommendation with MeritRank Sybil resistance; formal ratio bound `lim\|S\|→∞ w⁺/w⁻ ≤ c`; basis for OQ-10 Path B; persistent graph linkability is the key gap vs. PrivaCF |
| Cyffers et al. (arXiv:2510.17480, 2025)                         | Unified GDP bounds for decentralized learning via matrix factorization; SecLDP trust model maps onto PrivaCF's permutation-secret gossip exchange; basis for OQ-55             |

---

## 13. Recommendation Layer: Open Problems for Deployment

The CF algorithm is intentionally not fixed by the protocol. Different communities have different content types, interaction patterns, sparsity profiles, and privacy/utility tradeoffs. A single recommendation algorithm would serve none of them well. What follows is a speculative enumeration of tensions any deployment will need to address when designing or selecting a recommendation layer. No solutions are proposed — these are community-dependent design problems, not protocol-level ones.

**Sparsity and cold start.** Item-based CF requires sufficient co-occurrence signal to produce reliable similarity estimates. For genuinely niche items the co-occurrence matrix may be too sparse for cosine similarity to be meaningful regardless of privacy mechanisms. The novelty bonus accelerates accumulation but does not substitute for signal density. Deployments targeting extreme long-tail content should evaluate hybrid fallbacks (content-based priors, cluster-level popularity estimates) that do not require centralizing metadata the protocol deliberately avoids.

**Feedback loop and filter bubble risk.** Recommendations influence interactions, which influence preference vectors, which influence future recommendations. This loop is not modeled in the current CF sketch. Under some conditions it could produce runaway local optima or filter bubbles that degrade recommendation diversity over time. Randomness injection at the recommendation layer is a speculative mitigation; calibration is community and content-type dependent. See Chaney, Stewart & Engelhardt (2018).

**Reputation system interaction.** Niche users structurally interact with fewer items and maintain smaller peer sets than mainstream users. Participation-rate-weighted reputation could systematically push niche users toward lower reputation bands, causing their announcements to carry less weight in others' `trust_total` estimates — suppressing exactly the long-tail signal the CF layer is designed to amplify. The niche-specific protocol handling (announcement delays, cluster weight adjustments) partially addresses this but the interaction with reputation bands is not formally analyzed.

**Epoch length and content type.** A single epoch length is simultaneously too long for fast-moving content and potentially too short for slowly-evolving taste domains. Preference vector freezing at epoch boundaries quantizes updates to the epoch cadence. Epoch length should be treated as a community-tunable parameter calibrated to the dominant content type.

**Positive-only signal and neutral interactions.** Dislikes are retained locally and applied as a post-processing filter, which is a meaningful improvement over standard implicit feedback systems that conflate interaction with preference. The residual ambiguity — items interacted with neutrally — is narrower than the standard implicit feedback problem but remains, and is more significant in sparse domains where false positive signal is costlier.

**Niche announcement privacy-utility tradeoff.** Small anonymity sets for niche items create a tension specific to long-tail communities: VRF-derived announcement delays reduce re-identification risk but also delay signal propagation that benefits niche discovery. The right balance is community-dependent and should be evaluated empirically against the anonymity set sizes characteristic of that community's item distribution.

**Content-based hybrid as a future direction.** For content types with publicly available metadata (films, music, books), each node can independently fetch item features from external sources (IMDB, MusicBrainz, Spotify, etc.) without centralizing anything — the metadata is already public. For user-generated content (videos, posts), local AI-based embedding (transcript via Whisper, text or visual similarity via on-device models) produces item similarity signals without sharing embeddings. In both cases the content layer is either public or computed locally; only the interaction signal is shared via the gossip protocol. This directly addresses the new-item cold-start gap for these domains: a new item with zero interactions can be bootstrapped via content similarity to existing items that have accumulated collaborative signal. Sequential recommendation signals (using the order of a user's own interaction history, not just the unordered bag) are similarly local — a user's own sequence is known on-device and can feed a local sequential model without any additional sharing. None of this is protocol-level; it belongs to the recommendation layer each deployment builds on top of PrivaCF.

**Distinguishing coordinated pushing from organic popularity surges.** Naive coordinated pushing is detectable through behavioral synchrony signatures (same epoch, uniform timing, uniform rating distributions). Sophisticated mimicry of organic diffusion patterns — seeding from multiple behavioral clusters with staggered timing — is harder to distinguish from genuine popularity surges using the observables currently available. This is a soft boundary that empirical testing should characterize rather than a problem the protocol claims to solve.

---

## Appendix A — Full Message Schemas

All messages transmitted inside uniform fixed-size encrypted frames via Noise Protocol sessions.

```
// GOSSIP VECTOR PUSH
{
  "type":         "gossip_push",
  "epoch_id":     "<Poseidon(sk, beacon_T, null_v, 'epoch_id')-derived epoch ID>",
  "vector":       "<permuted float array, exactly n_v(T) elements>",
  "noise_system": "chopping | laplace",
  "sig":          "<Sign(epoch_id, H(vector ‖ T))>"
}

// PULL REQUEST + CLASS 2 AUDIT CHALLENGE
{
  "type":        "pull_request",
  "epoch_id":    "<requester epoch ID>",
  "audit_nonce": "<random 256-bit nonce>",
  "sig":         "<Sign(epoch_id, H(nonce ‖ T))>"
}

// PULL RESPONSE + CLASS 2 AUDIT RESPONSE
{
  "type":        "pull_response",
  "epoch_id":    "<responder epoch ID>",
  "vector":      "<permuted float array, exactly n_v(T) elements>",
  "audit_hash":  "<H(state ‖ nonce ‖ epoch_id)>",
  "receipt_sig": "<Sign(responder_epoch_id, H(vector ‖ T))>",
  "sig":         "<Sign(epoch_id, H(vector ‖ audit_hash ‖ T))>"
}

// CLASS 3 AUDIT CHALLENGE
{
  "type":         "pull_request",
  "epoch_id":     "<committee member epoch ID>",
  "audit_nonce":  "<Poseidon(beacon ‖ 'c3_nonce' ‖ committee_epoch_id)>",
  "audit_class":  "3",
  "challenged_T": "<suspect epoch>",
  "sig":          "<Sign(epoch_id, H(nonce ‖ challenged_T ‖ T))>"
}

// CLASS 3 AUDIT RESPONSE
{
  "type":         "audit_response",
  "epoch_id":     "<target epoch ID>",
  "merkle_proof": "<branch paths for challenged leaf categories>",
  "zk_proof":     "<Plonky3 proof for Statements 1–3 and 5>",
  "sig":          "<Sign(epoch_id, H(merkle_proof ‖ zk_proof ‖ T))>"
}

// AUDITOR HANDOFF
{
  "type":                     "auditor_handoff",
  "epoch_id":                 "<node epoch ID>",
  "new_commitment":           "<C_p(T)>",
  "new_merkle_root":          "<M_v(T)>",
  "leaf_counts": {
      "ANNOUNCEMENT":         "<n>",
      "PULL_RESPONSE":        "<n>",
      "AUDIT_RESPONSE":       "<n>",
      "PARTICIPATION":        "<n>",
      "RATE_LIMIT":           "<n>"
  },
  "susp_smt_root_ref":        "<SUSP_SMT_root_T>",
  "commit_T":                 "<ForwardCommit(null_v, epoch_id_T, threshold_BLS_pk_T; r)>",
  "threshold_bls_pk_T":       "<public key of this epoch's committee>",
  "successor_zk_proof":       "<proof: valid successor + leaf count consistency + Statement 5 (4 checks)>",
  "rolling_chain_commitment": "<Poseidon(prior_chain ‖ current_proof ‖ audit_interactions ‖ SUSP_SMT_root_T)>",
  "zk_continuity_proof":      "<committee chain only — not in public handoff>",
  "encrypted_shares":         ["<Encrypt(pk_auditor_i, shamir_share_i)>", "..."],
  "sig":                      "<Sign(epoch_id, H(all fields ‖ T))>"
}

// ON-CHAIN EPOCH TRANSACTION
{
  "type":              "epoch_transaction",
  "epoch_id":          "<node epoch ID>",
  "commit_T":          "<ForwardCommit — every epoch, exempt from n_commit>",
  "commit_T_zk_proof": "<Statement 5 ZK proof — every epoch>",
  "threshold_bls_pk_T":"<committee threshold BLS public key for this epoch>",
  // Fields below submitted only every n_commit epochs:
  "score_band":        "<committee-attested band 1–4>",
  "health_tier":       "<self-reported — committee verdicts override>",
  "commitment":        "<C_p(T)>",
  "merkle_root":       "<M_v(T)>",
  "vdf_proof":         "<identity chain proof for this epoch>",
  "band_attestation":  "<threshold BLS sig from committee on score_band>",
  "susp_smt_root_ref": "<SUSP_SMT_root_T>",
  "inter_cluster_rep": "<float>",
  "sig":               "<Sign(epoch_id, H(all fields ‖ T))>"
}

// ON-CHAIN VERDICT COMMIT
{
  "type":                  "verdict_commit",
  "committee_member_id":   "<member epoch ID>",
  "target_epoch_id":       "<audited node epoch ID>",
  "verdict_epoch":         "<T>",
  "commit":                "<H(bls_share_i ‖ verdict ‖ nonce_i)>",
  "sig":                   "<Sign(committee_member_id, H(commit ‖ T))>"
}

// ON-CHAIN VERDICT REVEAL
{
  "type":                  "verdict_reveal",
  "committee_member_id":   "<member epoch ID>",
  "target_epoch_id":       "<audited node epoch ID>",
  "verdict_epoch":         "<T>",
  "bls_share_i":           "<BLS secret share contribution>",
  "verdict":               "SUSPENDED | PASS",
  "nonce_i":               "<random nonce>",
  "sig":                   "<Sign(committee_member_id, H(bls_share_i ‖ verdict ‖ nonce_i ‖ T))>"
}

// ON-CHAIN NULL_V DECRYPTION
{
  "type":            "null_v_decryption",
  "verdict_hash":    "<H(committee_verdict_transaction)>",
  "epoch_id":        "<suspended node's last epoch_id>",
  "null_v":          "<recovered nullifier value>",
  "dec_nullifier":   "<Poseidon(verdict_hash, null_v)>",
  "sigma":           "<aggregated threshold BLS signature>",
  "proof":           "<Verify(threshold_BLS_pk_T, 'SUSPEND epoch_id_T', sigma) = true
                       AND ForwardCommit.Verify(commit_T, null_v, sigma) = true>"
}

// ON-CHAIN COMMITTEE VERDICT
{
  "type":                   "committee_verdict",
  "committee_ids":          ["<member epoch IDs>"],
  "target_epoch_id":        "<audited node epoch ID>",
  "verdict_epoch":          "<T>",
  "verdict":                "SUSPENDED | DEGRADED | PASS",
  "reason":                 "class3_fail | handoff_reject | double_sign | vdf_fail",
  "behavioral_fingerprint": "<fingerprint hash — SUSPENDED only>",
  "bls_aggregate_sig":      "<threshold BLS aggregate signature>"
}

// ON-CHAIN WATCHDOG SIGNAL
{
  "type":              "watchdog_signal",
  "epoch_id":          "<signaling node epoch ID>",
  "epoch_T":           "<T>",
  "observed_commits":  "<count>",
  "expected_rate":     "<local estimate>",
  "sig":               "<Sign(epoch_id, H(epoch_T ‖ observed_commits ‖ T))>"
}

// ON-CHAIN AUDIT RESULT (Class 2)
{
  "type":          "audit_result",
  "auditor_id":    "<auditing node epoch ID>",
  "target_id":     "<audited node epoch ID>",
  "audit_epoch":   "<T>",
  "result":        "pass | fail | no_response",
  "auditor_sig":   "<Sign(auditor_id, H(all fields ‖ T))>"
}

// ON-CHAIN ADMISSION SUMMARY
{
  "type":          "admission_summary",
  "epoch_id":      "<admitting node epoch ID>",
  "admitted":      "true | false",
  "admitted_T":    "<epoch>",
  "committee_sig": "<threshold BLS sig>"
}

// COMMITTEE CHAIN — FIRST OBSERVATION REPORT
{
  "type":              "first_observation",
  "observer_id":       "<existing node epoch ID>",
  "new_epoch_id":      "<admitting node epoch ID>",
  "first_seen_T":      "<epoch>",
  "first_seen_offset": "<seconds within epoch>",
  "channel":           "chain | gossip | PSI",
  "observer_sig":      "<Sign(observer_id, H(report))>"
}

// COMMITTEE CHAIN — ZK CONTINUITY PROOF
{
  "type":           "zk_continuity",
  "epoch_id_T":     "<current epoch ID>",
  "epoch_id_prev":  "<prior epoch ID>",
  "zk_proof":       "<Plonky3 Poseidon PRF continuity proof>",
  "committee_sig":  "<threshold BLS sig acknowledging receipt>"
}

// REWIND SIGNAL
{
  "type":           "rewind_signal",
  "epoch_id":       "<signaling node epoch ID>",
  "current_T":      "<T>",
  "preferred_T":    "<epoch at which quality was last acceptable>",
  "cohort_epoch":   "<epoch at which implicated gossip vectors entered index>",
  "sig":            "<Sign(epoch_id, H(current_T ‖ preferred_T ‖ cohort_epoch))>"
}

// COVER TRAFFIC
{
  "type":    "cover",
  "payload": "<random bytes padded to frame size>"
}
```

---

## Appendix B — What Each Node Holds

**Private — never leaves the device:**

| Item                | What it is                                                                              |
| ------------------- | --------------------------------------------------------------------------------------- |
| `sk`                | Long-term signing key                                                                   |
| `null_v`            | Nullifier: `Poseidon(sk, "null_v")`. Never transmitted except as circuit witness        |
| `r_commit_T`        | Blinding factor for commit_T this epoch                                                 |
| `p_v`               | Full signed preference vector. Updated only at epoch transitions                        |
| `r_p`               | Pedersen blinding factor. Losing it locks out Class 3 audit responses for that identity |
| `π_v(T)`            | Per-epoch permutation                                                                   |
| Interaction history | Raw log. Aggregated into Merkle leaves; raw data stays local                            |
| `q_v(T)`            | Local acceptance rate                                                                   |
| HNSW snapshots      | Periodic snapshots retained for rewind recovery                                         |
| PSI cache           | Per-peer Jaccard similarity scores and ZK continuity weights                            |
| IP address          | Hidden from all other nodes by Loopix/Sphinx mixnet transport                           |

**On the public blockchain:**

| Item                          | What it reveals                                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `epoch_id_T`                  | Pseudonym for this epoch. Derived as `Poseidon(sk, beacon_T, null_v, "epoch_id")`. Unlinkable to prior epochs without `sk` |
| VDF proof chain               | At least n epochs of sequential computation with mandatory interaction checkpoints                                         |
| `C_p(T)`                      | Pedersen commitment. Binding but reveals nothing about contents                                                            |
| `M_v(T)`                      | Merkle root of behavioral history. Fixed-size padding prevents activity level inference                                    |
| Score band (1–4)              | Coarse reputation quartile — committee-attested                                                                            |
| Item announcements            | Item hash + noisy rating, positive interactions only. Niche items subject to VRF-derived delay                             |
| Committee verdicts            | SUSPENDED and other health determinations. Permanent                                                                       |
| Behavioral fingerprint        | Included only in SUSPENDED verdicts                                                                                        |
| `SUSP_SMT_root_T`             | Root of suspended nullifiers SMT                                                                                           |
| `commit_T`                    | Forward-secure commitment to null_v. Published every epoch. Opaque without verdict signature                               |
| `commit_T_zk_proof`           | ZK proof certifying commit_T is correctly formed                                                                           |
| `DECRYPTION_SMT_root_T`       | Root of executed decryptions SMT                                                                                           |
| `verdict_commit` transactions | Per-committee-member verdict commitments                                                                                   |
| `verdict_reveal` transactions | Per-committee-member BLS shares and verdicts                                                                               |

**On the committee chain — readable only by threshold committee:**

| Item                         | What it contains                                         |
| ---------------------------- | -------------------------------------------------------- |
| ZK continuity proofs         | Links `epoch_id_T` to `epoch_id_{T-1}`                   |
| Fine-grained behavioral data | Per-epoch timing distributions, audit response rates     |
| Handoff history              | Encrypted state chain for each node under audit          |
| First-observation reports    | Observer timing data for coordinated admission detection |
| Raw score                    | Full computed score per epoch                            |

**Off-chain entirely:**

| Item                    | Where it lives                                       |
| ----------------------- | ---------------------------------------------------- |
| PSI relationships       | Local device only                                    |
| Gossip vector exchanges | Direct peer-to-peer                                  |
| Receipt collection      | Local device, retained one epoch for auditor queries |

---

## Appendix C — Reputation Decision Tree

```
SIGNAL RECEIVED
│
├── Protocol violation?
│   ├── Critical (VDF fail, Class 3 non-response, handoff rejected by majority,
│   │            double-signing detected, Statement 5 proof invalid,
│   │            commit_T ZK proof invalid)
│   │   └── → Commit-reveal SUSPENDED flow (see §4.9.6 for canonical specification)
│   └── Minor (rate limit hit, Class 2 mismatch, single auditor handoff dispute)
│       └── → reduce relevant score component

ANOMALOUS VERDICT_COMMIT RATE
  Any node detects rate exceeds expected bound without behavioral signal justification
      → broadcast watchdog_signal
  Multiple watchdog_signals this epoch
      → L3 Suspicious for implicated committee
      → meta-committee assembled via VRF
      → same commit-reveal ordering applies recursively

EPOCH END
  commit_T + Statement 5 ZK proof submitted every epoch (exempt from n_commit)
  Remaining fields submitted every n_commit epochs
  Committee verifies handoff: majority accept → normal · majority reject → SUSPENDED flow
  Score stored on committee chain; band attestation → public chain

ADMISSION — nullifier check
  Node completes n-epoch VDF admission chain
  First handoff must include valid Statement 5 proof + valid commit_T
      null_v ∉ SUSP_SMT: admission proceeds normally
      null_v ∈ SUSP_SMT: admission rejected immediately — cryptographic

IDENTITY ROTATION EVASION
  Same sk: cryptographically impossible
  New sk: fresh null_v', full admission cost required
      Behavioral fingerprint matching → L2 Elevated from admission
  Dark node (same sk): closed by ForwardCommit
  Dark node (admission window, no commit_T published):
      Residual gap — bounded by zero reputation + fingerprinting
```

---

## Appendix D — Node Lifecycle

```
SETUP (one-time)
  Generate sk
  Compute null_v = Poseidon(sk, "null_v")
  Compute epoch offset: offset_v = Poseidon(sk, "epoch_offset") mod epoch_duration
  Begin admission window (n epochs)
      Each epoch: compute and publish identity VDF proof on-chain
      At VRF-determined checkpoint epochs:
          PSI handshake with random existing node (Loopix mix-routed, SURB reply)
          Gossip vector exchange + collect receipt
      First-observation reports submitted to committee chain only
      Public chain records admission decision only on completion
  Epoch n: binary — full admission if chain complete and all checkpoints passed
  First handoff after admission must include valid Statement 5 proof + valid commit_T
      If null_v ∈ SUSP_SMT: admission rejected immediately

EACH EPOCH (offset_v stagger)

  EPOCH START
  ├── Rotate epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")
  ├── Rotate π_v(T) = Poseidon(sk, beacon_T, "perm")
  ├── Derive n_v(T) = n_base + Poseidon(sk, beacon_T, "chop_n") mod n_jitter
  ├── Renew C_p(T)  [p_v updates only permitted here]
  ├── Fetch current SUSP_SMT_root_T from public chain
  ├── Await DKG completion → obtain threshold_BLS_pk_T
  ├── Construct commit_T = BF-IBE.Encrypt(null_v, "SUSPEND epoch_id_T", threshold_BLS_pk_T; r_commit_T)
  ├── Generate Statement 5 ZK proof (4 checks + SMT path)
  ├── Optional ZK continuity proof (committee chain only)
  ├── Refresh bridge peer (DHT + Loopix provider)
  ├── Update PSI cache (λ_proof or λ_noproof)
  └── Store HNSW snapshot if snapshot interval reached

  DURING EPOCH
  ├── Push gossip vector at T_send (first 30% of epoch, randomized)
  ├── Pull from peers — embed Class 2 audit nonce in every pull request
  ├── Respond to pulls — embed audit hash + receipt signature in every response
  ├── Retain issued receipts for one epoch (for auditor queries)
  ├── Announce positive interactions (delay + noise on rating)
  ├── Collect peer attestations passively as receipts arrive
  ├── Update local HNSW from received vectors
  ├── Compute recommendations offline
  ├── Track q_v(T) — rewind signal if acceptance rate drops
  ├── Monitor public chain for anomalous verdict_commit rate
  │   → broadcast watchdog_signal if rate exceeds expected
  └── Maintain constant cover traffic

  EPOCH END (spread across randomized window)
  ├── Assemble Merkle leaves (fixed protocol-wide maximum padding)
  ├── Compute M_v(T)
  ├── Submit commit_T + Statement 5 ZK proof via relay → public chain (every epoch)
  ├── Generate auditor handoff:
  │   successor ZK proof + leaf counts + Statement 5 + commit_T + encrypted shares
  │   ZK continuity proof submitted to committee chain only
  ├── Distribute handoff to committee via Dandelion++ stem
  ├── Await committee threshold signature
  ├── If commit epoch (T mod n_commit = 0):
  │   Submit M_v, C_p, score band, health tier via relay → public chain
  ├── If Class 3 audit pending: submit Merkle + ZK proof (Stmts 1–3, 5) via stem with retry
  │   If rewind confirmed: roll back HNSW to preferred_T snapshot
  │                        discard gossip vectors from implicated cohort
  ├── Compute score_v(T) — stored on committee chain
  ├── Consistency + smoothness check
  ├── Send batch receipts (Dandelion++ stem)
  └── Check public chain for committee verdicts against any peers

  BLOCKCHAIN (validator nodes only)
  ├── Proposer: collect pending transactions, assemble block
  ├── Proposer: verify all commit_T ZK proofs in epoch_transactions
  ├── Proposer: verify verdict_reveal matches against verdict_commit
  ├── Proposer: verify null_v_decryption proofs; update DECRYPTION_SMT and SUSP_SMT
  ├── Proposer: compute block VDF_eval(vdf_output_{T-1}, δ_block)
  ├── Proposer: update SUSP_SMT_root_T and DECRYPTION_SMT_root_T if updated this epoch
  ├── Proposer: broadcast candidate block to validator set
  ├── Validators: verify block contents, VDF output, committee BLS sigs,
  │              root consistency, commit_T ZK proofs, verdict_reveal consistency
  ├── Block final when ⌊K/3⌋×2+1 signatures collected
  ├── Final block broadcast to network
  └── Light clients: sync block header + verify relevant entries via Merkle proof
```

---

## Appendix E — Implementation Readiness

```
TIER 1 — Build now
  Poseidon PRF                     arkworks-rs Poseidon crate; domain separators; local derivations only
  EC-VRF (RFC 9381)                tendermint-rs; on-chain verifiable selection (validator, committee, relay)
  null_v derivation                Poseidon(sk, "null_v") at setup
  SUSP_SMT                         jellyfish-merkle or rs-merkle; append-only
  DECRYPTION_SMT                   Same structure; dec_nullifier = Poseidon(verdict_hash, null_v)
  commit_T per-epoch publication   Exempt from n_commit; every epoch
  DKG for committee threshold BLS  Per-epoch; K≈21; blst crate
  Verdict_commit transaction type  Commit phase; H(share ‖ verdict ‖ nonce)
  Verdict_reveal transaction type  Reveal phase; match against commit
  null_v_decryption transaction    Permissionless aggregation + SUSP_SMT insertion
  Watchdog signal                  Public chain rate monitoring
  Statement 5 circuit              Four checks + ForwardCommit + SMT non-membership (Plonky3)
  Staggered epoch offsets          Poseidon(sk, "epoch_offset") mod epoch_duration
  Variable chopping n_v(T)         Poseidon(sk, beacon_T, "chop_n") mod n_jitter
  Niche announcement delay         Poseidon(sk, item_hash, beacon_T, "niche_delay") mod max_delay
  VDF — identity chain             vdf crate (Chia); per-node sequential
  VDF — block chain                vdf crate (Chia); per-block sequential
  Pedersen commitments             curve25519-dalek / arkworks-rs
  Merkle tree                      rs-merkle; fixed max padding; Poseidon salts
  HNSW snapshot storage            Periodic local snapshots for rewind
  Shamir k-of-n                    sharks crate; extend for k > 3
  Noise Protocol sessions          snow crate
  Dandelion++ gossip               libp2p-gossipsub; broadcast fluff phase only; timeout retry
  Loopix/Sphinx transport          katzenpost (Go); Sphinx packet format; SURB replies; provider-based NAT
  LSH                              FALCONN
  HNSW                             hnswlib / instant-distance
  Plonky3 proofs                   plonky3 crate
  Bulletproofs                     bulletproofs (dalek-crypto)
  Laplace DP (S=2, sign-bounded)   trivial with sign preservation constraint
  BLS signatures                   blst crate
  Item-based CF                    standard linear algebra
  Dislike-aware CF                 trivial post-processing
  Uniform frame padding            trivial
  Peer attestation collection      trivial — receipts in pull responses
  Per-n-epoch commit batching      trivial epoch counter
  Rewind signal cohort correlation local HNSW provenance tracking

TIER 2 — Adapt prior work
  Tendermint-style BFT             tendermint-rs; VRF proposer + VDF-chained
  BLS threshold aggregation        blst; threshold scheme
  Double-signing detection         Standard BFT; epoch_id key structure
  Light client headers + proofs    Standard Merkle SPV
  Genesis transition protocol      Bootstrap behavioral cluster relaxation
  Asymmetric PSI (Pinkas 2018)     Unbalanced; Jaccard threshold; Loopix mix-routed with SURB
  PSI cache asymmetric decay       Jøsang & Ismail basis
  Two-tier peer selection          Cluster + bridge logic
  Class 2 passive audit            Nonce-in-pull; hash-in-response
  Auditor handoff flow             Successor ZK proof + Statement 5
  Multi-auditor committee          VRF with dual cluster constraints
  DSybil with noisy ratings        Binary fallback option
  Interest-cluster FoolsGold       Fung et al. RAID 2020
  Behavioral-cluster FoolsGold     Cross-cluster behavioral similarity
  SSP-adapted simulation           Werthenbach & Pouwelse 2023
  Trust attenuation by hop         Stannat et al. AAMAS 2021
  Asymmetric penalty               Sun et al. 2008
  Smoothness detection             Srivatsa et al. 2005
  Relay node batching              VRF selection; reputation integration
  Validator service score bonus    Trivial score component addition
  Commit-reveal verdict flow       Two-phase; ordering enforcement in block validation
  Permissionless BLS aggregation   Standard threshold BLS
  Recursive oversight chain        Meta-committee VRF; same commit-reveal; depth limit

TIER 3 — Original design required
  Dual-chain architecture          Public chain + committee chain split
  ZK continuity circuit            Plonky3; Poseidon PRF relation; committee chain only
  ZK consistency (Stmts 1–3)      Statement 2 requires sign preservation first
  ZK successor proof (handoff)     C_p + M_v successor + leaf count + Statement 5
  ForwardCommit.Verify in circuit  BLS-based decryption verification as constraint
  Block VDF chaining protocol      Proposer timeout; liveness guarantees
  SUSP_SMT maintenance             Append-only; validator insertion flow
  Behavioral cluster computation   On-chain derived fingerprints
  Merkle peer-attested leaves      Fixed padding; attestation assembly; partial reveal
  Justified disclosure             Compound flag justification
  Full rate-limit enforcement      All event categories
  Cluster formation from PSI       Entry protocol; cache management
  Cover item selection             Post-n_cover local pool
  Epoch interaction checkpoints    VRF scheduling; verification
  Score band attestation flow      Committee threshold BLS → public chain
  Rewind HNSW rollback             Snapshot provenance; cohort identification
  Watchdog rate estimation         Per-node expected suspension rate
  Oversight chain termination      Hard depth limit + escalating committee sizes

TIER 4 — Research required before deployment
  Poseidon PRF security analysis   OQ-1 — closed (primitive split)
  EC-VRF security                  RFC 9381; DLEQ/DDH; tendermint-rs
  Domain separator enumeration     OQ-4 — closed
  ForwardCommit security analysis  OQ-2 — closed
  dec_nullifier collision resist.  OQ-5 — closed
  Statement 5 mobile benchmark     OQ-3 — open (required before mobile deployment)
  Noise system per segment         OQ-54 — open (head / long-tail)
  Reputation weight calibration    OQ-9 — open
  Variable chopping calibration    n_base and n_jitter per sparsity tier (head / long-tail)
  Niche announcement delay         τ_niche and max_delay_epochs
  DSybil composition lemma         Continuous ratings; binary fallback if unproven
  Stannat Condition 3              Does satisfying Δ_rise exist? (OQ-6)
  FoolsGold labeled data           Both θ values; cold-start from simulation
  ZK Statement 2 mobile bench      d=128/256 Plonky3/WASM (OQ-3b)
  ZK successor proof cost          Mobile hardware
  Bootstrap critical mass          Genesis transition; cluster relaxation (OQ-12)
  Validator incentive analysis     Long-term shirking risk (OQ-13)
  Oversight chain termination      Depth limit + damage bound (OQ-49)
  Off-chain collusion bounds       OQ-53
  [Remaining calibration items: see §10.1]
```

---

## Appendix F — Configuration Reference

```
CONFIG A — Open (invite-only, maximum Sybil resistance)
  Transport:      Loopix/Sphinx + Dandelion++ (broadcast only)
  Identity:       Persistent (no epoch rotation)
  Noise:          Chopping + cover items
  ZK:             On by default
  Admission:      n=24
  Chain:          Full participation (can be validator)

CONFIG B — Balanced (recommended default)
  Transport:      Loopix/Sphinx + Dandelion++ (broadcast only)
  Identity:       Poseidon PRF rotation
  Noise:          Chopping + cover items
  ZK:             On by default
  Admission:      n=24
  Chain:          Light client

CONFIG C — High-Security (sensitive content, political contexts)
  Transport:      Loopix/Sphinx + Dandelion++ (broadcast only)
  Identity:       Poseidon PRF rotation
  Noise:          Chopping + cover items
  ZK:             On by default
  Admission:      n=168
  Chain:          Light client

CONFIG D — Mainstream DP (formal guarantees on popular content)
  Transport:      Loopix/Sphinx + Dandelion++ (broadcast only)
  Identity:       Poseidon PRF rotation
  Noise:          Laplace S=2 per segment (head / long-tail), sign-bounded — NO chopping
  ZK:             On by default
  Admission:      n=24
  Chain:          Light client

CONFIG E — Binary Ratings (formal DSybil guarantee)
  Transport:      Loopix/Sphinx + Dandelion++ (broadcast only)
  Identity:       Poseidon PRF rotation
  Noise:          Chopping + cover items
  Ratings:        Binary (liked / not liked)
  ZK:             On by default
  Admission:      n=24
  Chain:          Light client
```

|                         | A   | B   | C   | D   | E   |
| ----------------------- | --- | --- | --- | --- | --- |
| Niche rec quality       | 5   | 5   | 4   | 3   | 4   |
| Mainstream rec quality  | 4   | 4   | 4   | 3   | 3   |
| Preference privacy      | 3   | 4   | 5   | 3   | 4   |
| Identity privacy        | 1   | 4   | 5   | 4   | 4   |
| Sybil resistance        | 5   | 3   | 2   | 3   | 5   |
| Suspension persistence  | 5   | 5   | 5   | 5   | 5   |
| Formal DSybil guarantee | 1   | 1   | 2   | 4   | 5   |
| Formal DP guarantee     | 1   | 1   | 2   | 4   | 1   |
| Mobile / battery        | 5   | 4   | 2   | 4   | 4   |
| Cold start speed        | 5   | 4   | 3   | 4   | 4   |

_All configs: Loopix/Sphinx mixnet mandatory. Dandelion++ retained for epidemic broadcast (fluff) phase only. Clearnet: dev/test only. Nullifier mechanism, SUSP_SMT, DECRYPTION_SMT, ForwardCommit, and commit-reveal verdict flow apply universally. commit_T is published every epoch regardless of n_commit setting._

---

## Appendix G — Node Relationship Diagram

```
                        ┌──────────────┐
                        │    NODE A    │
                        └──────┬───────┘
                               │
          ┌────────────────────┼──────────────────────┐
          │                    │                       │
   ┌──────┴──────┐     ┌───────┴──────┐     ┌─────────┴─────┐
   │ Interest    │     │ Interest     │     │  Bridge Peer  │
   │ Cluster     │     │ Cluster      │     │  (random DHT) │
   │ Peer B      │     │ Peer C       │     │               │
   │ (PSI ✓)     │     │ (PSI ✓)      │     │               │
   └─────────────┘     └──────────────┘     └───────────────┘

   ┌──────────────────────────────────────────────────────┐
   │  AUDITOR COMMITTEE (k members, rotating per epoch)   │
   │  VRF-selected · unpredictable before beacon publish  │
   │  Different interest AND behavioral clusters          │
   │  Reputation ≥ median · temporal depth ≥ D_min        │
   │  Run DKG at epoch start → threshold_BLS_pk           │
   │  Shamir share of encrypted state chain               │
   │  Threshold BLS signature for handoff acceptance      │
   │  Commit-reveal verdict process for suspensions       │
   │  Publish verdicts to public chain                    │
   │  Maintain committee chain (threshold-held)           │
   └──────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────┐
   │  VALIDATOR SET (K_validators members, per epoch)     │
   │  VRF-selected · unpredictable before beacon publish  │
   │  Different interest AND behavioral clusters          │
   │  Reputation ≥ rep_validator · depth ≥ D_validator    │
   │  One proposer assembles block · others validate      │
   │  Threshold BLS signatures for block finality         │
   │  Verify commit_T ZK proofs and DKG completion        │
   │  Maintain DECRYPTION_SMT                             │
   └──────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────┐
   │  RELAY NODES (submission timing obfuscation)         │
   │  VRF-selected · different behavioral cluster         │
   │  Batch submissions · reputation model same as        │
   │  auditor committee                                   │
   └──────────────────────────────────────────────────────┘
```

---

## Appendix H — Identity and Privacy Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  WHAT THE ADVERSARY SEES vs. WHAT IS ACTUALLY HAPPENING         │
│                                                                 │
│  ┌──────────────┐    epoch rotation (Poseidon PRF)  ┌──────────────┐       │
│  │ epoch_id_T   │◄─── Poseidon(sk,  ────┤  secret key  │       │
│  │ (pseudonym)  │     beacon_T,null_v)  │     sk       │       │
│  └──────┬───────┘                        └──────┬───────┘       │
│         │ unlinkable across epochs              │               │
│         │                               ┌───────┴──────┐        │
│         │                               │  null_v      │        │
│         │                               │  Poseidon    │        │
│         │                               │  (sk,"null_v")        │
│         │                               │  stable,     │        │
│         │                               │  private     │        │
│         │                               └──────┬───────┘        │
│         │                                      │ private witness │
│         │                               ┌──────┴───────┐        │
│         │ non-suspension proof          │  ZK circuit  │        │
│         │ (boolean only)       ◄────────┤  null_v ∉    │        │
│         │                               │  SUSP_SMT    │        │
│         │                               │  + commit_T  │        │
│         │                               │  correctly   │        │
│         │                               │  formed      │        │
│         │                               └──────────────┘        │
│         │                                                        │
│  ┌──────┴───────┐    preference privacy                         │
│  │   C_p(T)     │◄──── Pedersen(p_v,r_p)                        │
│  └──────┬───────┘                                               │
│         │                                                        │
│  ┌──────┴───────┐    behavior privacy                           │
│  │   M_v(T)     │◄── Merkle root only                           │
│  └──────┬───────┘                                               │
│         │                                                        │
│  ┌──────┴───────┐                                               │
│  │  ZK proofs   │── auditor committee only ──► committee chain  │
│  │  continuity  │   never on public chain                       │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐    nullifier custody (opaque)                 │
│  │  commit_T    │◄── ForwardCommit(null_v, epoch_id_T,          │
│  │  (public)    │    threshold_BLS_pk(committee_T); r)          │
│  └──────┬───────┘                                               │
│         │ decryptable only by valid verdict signature           │
│         │ verdict requires public commit-reveal process         │
│  ┌──────┴───────┐                                               │
│  │  null_v      │ recovered by anyone after verdict             │
│  │  (post-      │ → inserted into SUSP_SMT                      │
│  │  verdict)    │ → dec_nullifier into DECRYPTION_SMT           │
│  └──────────────┘                                               │
│                                                                 │
│  ADMISSION COST                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │ VDF chain: n sequential proofs, one per epoch        │      │
│  │ each proof depends on the previous — no parallelism  │      │
│  │ interaction checkpoints require real network contact │      │
│  └──────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Appendix I — PSI Peer Selection Flow

```
PSI PEER SELECTION FLOW
─────────────────────────────────────────────────────────
Node A                      Node B
    │                           │
    │── initiate PSI ──────────►│
    │   (Loopix mix-routed,     │
    │    content encrypted,     │
    │    SURB included)         │
    │                           │ compute Jaccard:
    │                           │ |A∩B| / |A∪B| ≥ θ?
    │◄── PSI result ────────────┤
    │   (similarity score       │
    │    only — no set          │
    │    contents revealed)     │
    │                           │
    ├── similarity ≥ θ_cluster? │
    │       YES: add to         │
    │            interest tier  │
    │       NO:  discard        │
─────────────────────────────────────────────────────────
```
