# PrivaCF

## A Privacy-Preserving Decentralized Recommendation Protocol

### Design Document v0.3.1

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
| `commit_T`          | Forward-secure nullifier commitment. **Adopted (publish-`s₁`):** `(s₁, d_T)` — public `s₁` plus the validator ciphertext `d_T` of `s₂`. *High-assurance 2-of-2 profile:* `N_fallback` committee ciphertexts of `s₁` plus `d_T`. | §4.9.4 |
| `s₁`, `s₂`          | Additive shares of `null_v`: `s₁ + s₂ = null_v (mod p)`, `s₂ = r_share` fresh-uniform per epoch. **Adopted:** `s₁` is **published** (uniform, `⟂ null_v`); `s₂` → validators (`VA_pub`). *2-of-2 profile:* `s₁` → committee instead of public. | §4.9.4 |
| `c_T^{(i)}`         | i-th committee ciphertext in `commit_T`, encrypting `s₁` to committee_T^{(i)}'s threshold key (identity `"SUSPEND epoch_id_T"`) | §4.9.4 |
| `d_T`               | Validator ciphertext in `commit_T`, encrypting `s₂` to `VA_pub` (identity `"VERDICT_FINALIZED epoch_id_T"`) | §4.9.4 |
| `VA_pub`            | Standing validator-attestation threshold BLS public key; bootstrap + proactive re-share in §4.1 | §4.9.4, §4.1 |
| `σ_T^VERDICT`       | Validator threshold signature on `"VERDICT_FINALIZED epoch_id_T"`; IBE decryption key for `d_T`, published with the verdict | §4.9.4 |
| `committee_T^{(i)}` | i-th committee for epoch T; i=0 primary, i≥1 fallback | §4.9.4        |
| `N_fallback`        | Number of parallel committees `commit_T` is encrypted to (primary + N_fallback−1 fallbacks) | §4.9.4 |
| `W_primary`         | Epochs the primary committee has to complete commit-reveal before fallback activates | §4.9.6 |
| `W_fallback`        | Epochs each fallback committee has before the next one activates | §4.9.6 |
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
| `n_cluster`         | Epochs between behavioral-centroid recompute/publish | §6.2         |
| `k_cluster`         | Fixed behavioral cluster count for k-means          | §6.2          |
| `δ_decay`           | Per-epoch reputation decay                          | §6.1          |
| `μ`                 | Hop-distance trust attenuation factor               | §5.7          |
| `λ`                 | Temporal depth decay factor                         | §7.2          |
| `β`                 | Global/cluster trust blending factor                | §3.4          |
| `κ`                 | Novelty bonus scaling factor                        | §3.7          |
| `r_v(X)`            | Node v's local preference weight for item X (`p_v[X]`); only positive values enter trust_contribution | §3.4 |
| `Δ_base`            | Base trust increment per announcement               | §3.4          |
| `global_trust_total(X)` | Sum of trust_contribution over all nodes in the network that have announced X | §3.4 |
| `cluster_trust_total(X)` | Sum of trust_contribution over nodes in the receiving node's interest cluster that have announced X | §3.4 |
| `k_rep`             | Rolling window length in epochs for reputation consistency computation | §6.1 |
| `σ²_max`            | Maximum expected score variance for an honest, fully-active node over `k_rep` epochs; normalization constant for consistency | §6.1 |
| `f_cap`             | Per-node trust cap as a fraction of `c`; no single node's accumulated trust may exceed `f_cap × c` | §7.3 |
| `w_node_cap`        | Maximum fraction of total reputation weight any single node may hold | §7.6 |
| `w_cohort_cap`      | Maximum fraction of total reputation weight any cohort may hold | §7.6 |
| `announcement_token(v, X, T)` | Unforgeable per-announcement token: `Poseidon(sk, item_hash(X), beacon_T, "ann_token")` | §4.6 |
| `n_peers`           | Size of the PSI peer tier; grown organically via gossip referrals; requires empirical calibration | §5.7 |
| `n_discovery`       | Max parallel outgoing PSI attempts per epoch; conservative by default; calibrated against network size and bandwidth | §5.4 |
| `n_psi_in`          | Max incoming PSI requests accepted per epoch before silent drop; conservative by default | §5.4 |
| `k_min`             | Minimum PSI neighborhood size; cluster-specific behavior suspended below this threshold | §7.4 |
| `ε`                 | Differential privacy budget per gossip event under Laplace mechanism; cumulative budget over T epochs is Tε | §4.5, §7.4 |

---

## Abstract

Every major recommendation system learns what users like by collecting identity, history, and behavior on a server those users don't control. PrivaCF asks whether that has to be true.

The core challenge is a three-way tension: personalization requires preference data, privacy requires that data not be readable by others, and integrity requires that it reflects real human taste rather than manufactured signals from fake accounts. Prior work resolves at most two simultaneously. PrivaCF attempts all three.

Each participant holds a pseudonymous rotating identity tied to a computational admission cost that makes fake-account flooding expensive. Preferences are never transmitted in recoverable form — only shuffled, partially transmitted approximations that let similar users find each other without revealing what they actually like. Behavioral history is committed to a tamper-evident structure verified by a rotating committee of independent auditors via ZK proof, without access to the underlying data.

Suspension verdicts are permanent and survive identity rotation. A suspended node's nullifier — derived from their secret key — is inserted into a public Sparse Merkle Tree. Every future identity from the same key carries the same nullifier by construction; the membership proof fails by arithmetic, not by rule.

These guarantees are not free-standing: the privacy and Sybil-resistance layers are mutually load-bearing, and both rest on an honest-majority-by-weight assumption the network only satisfies organically once it has grown. At deployment that assumption is underwritten by an externally-trusted bootstrap set — made explicit rather than hidden (§1.7, §5.1.1).

---

## Table of Contents

- [1. How It Works](#1-how-it-works)
  - [1.1 Getting Recommendations](#11-getting-recommendations)
  - [1.2 Being Part of the Network](#12-being-part-of-the-network)
  - [1.3 When Something Goes Wrong](#13-when-something-goes-wrong)
  - [1.4 Joining the Network](#14-joining-the-network)
  - [1.5 The Adversary Model](#15-the-adversary-model)
  - [1.6 Assumptions](#16-assumptions)
  - [1.7 Security Argument](#17-security-argument)
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
  - [4.1 Chain and Arbitration Committee](#41-chain-and-arbitration-committee)
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
  - [7.1a Behavioral Taxonomy of Sybil Attacks](#71a-behavioral-taxonomy-of-sybil-attacks)
  - [7.1b Sybil Influence Model](#71b-sybil-influence-model)
  - [7.2 Temporal Depth](#72-temporal-depth)
  - [7.3 DSybil Non-Overwhelming Rule](#73-dsybil-non-overwhelming-rule)
  - [7.4 Sybil Impact Bounding](#74-sybil-impact-bounding)
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
- [14. Beyond Recommendations: Decentralized Learning Profile](#14-beyond-recommendations-decentralized-learning-profile)
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

Alice's node holds a preference vector — a signed list of how much she likes various items — kept entirely local. Periodically, her node exchanges a shuffled, partially transmitted version of this vector with a small set of peers whose tastes overlap with hers, discovered without revealing what those tastes are. PrivaCF organizes time into discrete epochs; each epoch corresponds to one block on the public chain (defined in §4.1). Each epoch, exactly n_v(T) elements are transmitted — a VRF-jittered count combining real preferences and cover items — so even the transmitted vector size reveals nothing about how many genuine preferences Alice holds.

Alice's node accumulates received vectors over time. Filtering and ranking happens entirely on her device. No recommendations are requested from any server — computation runs locally against data that has already arrived passively through the gossip protocol.

### 1.2 Being Part of the Network

When Alice interacts positively with an item, her node announces it to the network after a random delay, with a small amount of added noise on the rating. Negative interactions stay private. For rare items with small anonymity sets, announcement is further delayed by a VRF-derived number of epochs to prevent timing correlation.

Alice's behavioral history is summarized into a tamper-evident commitment each epoch. A rotating committee of auditors from independent clusters holds Shamir shares of her encrypted prior commitments and can verify consistency of successive commitments via ZK proof alone, without access to the underlying data. Public verdicts and anonymized reputation attestations are written to the public blockchain. Fine-grained behavioral data, continuity proofs, and handoff history are held in encrypted form under the arbitration committee's threshold custody — reconstructable only on a threshold quorum and only when an arbitration is actually invoked. Each per-interaction record (gossip push, pull response, PSI handshake, audit response) takes the form of a **co-receipt** signed by both parties and held locally; either side can later present its half to the committee if the counterparty disputes.

### 1.3 When Something Goes Wrong

If Alice's recommendations start degrading, her node signals this to the network. If enough independent nodes signal the same thing, a rotating committee of auditors is assembled to investigate. Audits are indistinguishable from normal protocol traffic.

If a node is found to be manipulating the network, the committee initiates a commit-reveal verdict process. Each committee member first publishes a commitment to their verdict on the public chain — locking in their decision before anything is decryptable — then reveals it. Once a threshold of SUSPEND reveals is on-chain and the verdict block finalizes, the validator set publishes its verdict attestation `σ_T^VERDICT`; anyone uses it to decrypt the encrypted half (`s₂`) of the node's forward-secure nullifier commitment and recovers `null_v = s₁ + s₂` (the other half `s₁` is already public). See §4.9.4 (adopted publish-`s₁` design) and §4.9.6.

The suspended node's nullifier is inserted into the suspended nullifier tree (SUSP_SMT). Creating a new identity from the same key is impossible: every future epoch ID derived from that key carries the same nullifier by construction, and the non-membership proof fails at the first handoff. Creating a new identity with a genuinely different key requires completing the full admission proof chain again, and new identities matching the behavioral fingerprint of a suspended one are flagged on arrival.

Any node can monitor the public chain for anomalous commit-reveal activity — an unexpected burst of verdict commitments with no corresponding behavioral signals triggers watchdog broadcasts and recursive oversight.

### 1.4 Joining the Network

Creating an identity requires completing a chain of sequential computational proofs over n epochs, interspersed with mandatory protocol interactions with existing nodes. Once all n proofs are complete and all interaction checkpoints have been passed, the identity is admitted and begins accumulating reputation. There are no partial admissions — the proof chain must be completed in full.

### 1.5 The Adversary Model

The threats below are defended across all transport profiles. Profile-specific adversary capabilities are summarized at the end of this section.

**The opportunist** creates a handful of fake accounts to boost their own content. Defended by admission cost, temporal depth, rate limits, and behavioral fingerprinting (the latter is profile-dependent — see §6.2).

**The commercial promoter** operates a sustained campaign of fake accounts with enough patience to build reputation before exploiting it. Defended by the non-overwhelming trust rule, smoothness detection, and within-cluster coordination detection (interest-cluster signal is transport-agnostic; behavioral-cluster signal is available under the Tor/I2P profile only).

**The coordinated campaign** involves many accounts pushing a narrative across many items simultaneously. The system surfaces behavioral anomaly patterns for operator review. Intent classification requires human judgment.

**The epoch rotator** earns a SUSPENDED verdict then attempts to re-enter under a new identity derived from the same key. Defended by the nullifier mechanism: the same key always produces the same nullifier, which is permanently in the suspended set. Re-entry from the same key is cryptographically impossible.

**The dark node rotator** earns a SUSPENDED verdict and goes offline before their nullifier is extracted, then attempts to re-admit from the same key. Defended by the forward-secure commitment: on a finalized verdict, the public share `s₁` and the validator verdict attestation (which decrypts `s₂`) together reconstruct `null_v` without node cooperation (§4.9.4 adopted publish-`s₁` design). Because `null_v` is split and the encrypted share is released only by a public verdict, no present or future compromise — committee or otherwise — can extract it covertly (committees hold no decryption material at all under the adopted design). The residual gap — nodes that go dark during the admission window before publishing any `commit_T` — is bounded by zero reputation and behavioral fingerprinting.

**The rogue committee** attempts mass deanonymization by extracting `null_v` from many nodes without legitimate verdicts. Defended by the commit-reveal ordering: the committee must publicly commit to verdicts before decryption is possible. Anomalous commit rates are visible on the public chain before any `null_v` is recovered, triggering watchdog signals and recursive oversight.

#### Transport-profile-specific adversary capabilities

**Under the self-mixing Loopix profile (default):**

- Defended against the **global passive adversary** observing the full wire — Loopix's per-hop Poisson mixing and constant-rate cover traffic prevent traffic-correlation attacks.
- Weaker detection of **whitewashing** — the post-suspension fingerprint match (§6.3) operates on a thin behavioral fingerprint (§6.2), reducing matching power.
- Weaker detection of **IP-coordinated botnets** — per-client IP↔epoch_id is structurally erased; only aggregate mix-layer density signals are available (§6.3).
- Weaker detection of **sub-epoch coordinated bursts** — sub-epoch timing is destroyed by mixing; the T.2 signal (§7.1a) is dead under this profile.

**Under the Tor/I2P profile:**

- Vulnerable to **global passive adversary** traffic-correlation attacks (Tor's known weakness). Users with this threat model must layer additional OPSEC or select the Loopix profile.
- Stronger detection of **whitewashing** — full behavioral fingerprint (§6.2) makes post-suspension identity match high-dimensional.
- Stronger detection of **IP-coordinated botnets** — only effective against lazy Sybils who do not properly rotate Tor circuits per identity; sophisticated Sybils with disciplined circuit hygiene retain anonymity comparable to the Loopix profile.
- Full **sub-epoch coordinated burst** detection (T.2, T.9 at sub-second resolution).

Nation-state adversaries, compromise of the external randomness beacon, and eclipse attacks are out of scope across all profiles.

### 1.6 Assumptions

**A1 — Honest neighbor.** Every node has at least one honest gossip peer per epoch.

**A2 — Honest majority by weight.** More than half of total accumulated reputation weight belongs to honest nodes.

**A3 — Resource-bounded adversary.** Cannot solve VDFs faster than specified delay, cannot break standard cryptographic primitives, cannot predict the drand beacon before publication, cannot find Poseidon collisions (Grassi et al., USENIX Security 2021), cannot break BLS signature unforgeability.

**A4 — Time-bounded genesis.** The initial bootstrap set is trusted for a finite period only. This is the standard bootstrap assumption for Byzantine-fault-tolerant systems and is treated as an axiom rather than a derived property. A network that cannot trust its genesis set generates a regress that no purely cryptographic mechanism resolves.

### 1.7 Security Argument

The narrative threat model in §1.5 and the assumption list in §1.6 do not, on their own, constitute a security argument. This subsection restates the protocol's intended guarantees as **game-shaped properties** with bounded adversary advantage and reductions to standard primitives or stated assumptions. Properties whose strength depends on empirically-calibrated parameters (smoothness detection, behavioral fingerprint matching) are explicitly separated from properties with cryptographic reductions. Concrete `ε` values are deferred to OQ resolution; the goal here is to fix the *shape* of each claim so that future work can fill in the constants.

**Notational convention for this subsection.** Symbols `ε_X` denote *adversary-advantage bounds* against the primitive or assumption named in `X` (e.g., `ε_PRF`, `ε_BLS`, `ε_IBE`, `ε_Pedersen`, `ε_DP`, `ε_perm`, `ε_Π`). They are conventional cryptographic-reduction names, not protocol parameters, and intentionally do not appear in the global notation table. `δ_DSybil` and `γ_smoothness` in P5 are empirical calibration constants reported against the Phase 4–5 experiments; their values are not pinned at the protocol layer.

**P1 — Identity unlinkability.** For any PPT adversary `A` observing the public chain and the wire under transport profile `Π ∈ {Loopix, Tor/I2P}`:

```
Adv_unlink(A, T, k, Π) = | Pr[A(epoch_id_T, epoch_id_{T+k}) = same_sk] − ½ |
                       ≤ ε_PRF(Poseidon) + ε_Π(traffic_correlation, T, k)
```

Reduces to (a) Poseidon PRF security on `(sk, beacon_T, null_v, "epoch_id")` and (b) the transport profile's traffic-correlation bound. Under Loopix, `ε_Π` is bounded by the per-hop Poisson mixing parameter and cover-traffic rate; under Tor/I2P it is not bounded against a global passive adversary and the property is conditionally claimed.

**P2 — Preference indistinguishability in transit.** For preference vectors `p⁰, p⁰₁` differing in a single component and `gossip_T(p)` the per-epoch gossip output:

```
Adv_pref(A, T) = | Pr[A(gossip_T(p⁰)) = 0] − Pr[A(gossip_T(p¹)) = 0] |
              ≤ ε_DP(T, ε_per_epoch) + ε_perm(π_v) + ε_Pedersen
```

Reduces to (a) per-epoch Laplace/uniform noise (§4.5) composed over `T` epochs via advanced composition (Dwork-Rothblum-Vadhan); (b) Poseidon-derived permutation secrecy of `π_v(T)`; (c) Pedersen hiding for `C_p(T)`. Lifetime DP budget `T · ε_per_epoch` is **not yet pinned** — see OQ-55 and the DP accounting note below.

**P3 — Suspension persistence.** Let `Admit(sk')` denote successful admission with secret key `sk'`. For any adversary holding a key `sk` whose `null_v = Poseidon(sk, "null_v")` has been inserted into `SUSP_SMT`:

```
Pr[A admits with sk' such that Poseidon(sk', "null_v") = null_v] ≤ negl(λ)
```

Reduces to Poseidon PRF collision resistance (A3) plus soundness of the SMT non-membership ZK proof in Statement 5 (§4.9.5). The only re-entry path with the same key is a Poseidon collision; the only re-entry path with a fresh key requires completing the full admission proof chain anew and incurs zero accumulated reputation.

**P4 — Forward-secure nullifier extractability.** Under the adopted publish-`s₁` design (§4.9.4), `commit_T = (s₁, d_T)` with `s₁` public and `null_v = s₁ + s₂`, where `d_T` is the verifiable encryption of `s₂` to the standing validator key `VA_pub`. Recovery requires only the validator verdict attestation `σ_T^VERDICT`:

```
Pr[anyone recovers null_v given σ_T^VERDICT]      = 1           (s₂ = VerEnc.Decrypt(d_T, σ_T^VERDICT); null_v = s₁+s₂)
Pr[anyone recovers null_v without σ_T^VERDICT]    ≤ ε_VE         (s₁ alone is ⟂ null_v)
```

Reduces to threshold BLS unforgeability (Boneh-Lynn-Shacham) + the IND-CPA / binding of the native-group verifiable encryption (DESIGN §9; algebraic core machine-checked in `impl/easycrypt/`). **Forward secrecy of past `commit_T`** is closed cryptographically: committees hold no decryption material at all, so no committee compromise (present or future) touches `null_v`; `s₂` is sealed until a public, slashable validator attestation `σ_T^VERDICT` exists. The decryption lock is validator-only at the BFT quorum `⌊2K_validators/3⌋+1` — covert recovery needs >2/3 validator collusion (beyond A2) plus a slashable equivocation. *Optional high-assurance 2-of-2 profile (§4.9.4):* `s₁` is instead encrypted to `N_fallback` committees, making recovery require *both* `σ_i^SUSPEND` and `σ_T^VERDICT` (`Pr[recover | committee sig alone] ≤ ε_IBE`, yielding only `s₁ ⟂ null_v`); stalling-minority decay exponential in `N_fallback`. Canonical treatment in §8.2 T12.

**P5 — Sybil influence bound.** For an adversary controlling fraction `f` of total admission-cost units (A3, VDF-bounded):

```
E[reputation share of A] ≤ f · (1 + δ_DSybil) + f² · γ_smoothness
```

Reduces to the DSybil non-overwhelming theorem (Yu et al., IEEE S&P 2009) applied per-cluster with cap `c`, plus the FoolsGold-on-PSI-peers detection penalty applied above the smoothness threshold. The `f²` term reflects detection probability scaling with coordination cardinality — calibration-dependent and reported as an empirical bound rather than a proof.

#### Composition over time

Per-epoch failures of A1 (honest neighbor) and per-arbitration failures of the threshold-honesty assumption on the *currently-selected* arbitration committee compose via union bound over the protocol lifetime `T_life`:

```
Pr[lifetime failure of A1] ≤ T_life · Pr[no honest neighbor in epoch T]
Pr[lifetime failure of committee threshold] ≤ N_arbitrations · Pr[≥ K malicious in selected committee]
```

The §4.1 redesign narrows the second bound: it is the union over **arbitrations actually invoked**, not over **all committees ever selected**. With per-epoch member rotation and slashing-enforced share deletion, no past committee retains the capability to reconstruct any `snapshot_v(T)` beyond the epoch in which it was a custodian. This **trust-localization claim** is the main security improvement of the redesign and, *for behavioral-snapshot custody*, remains conditional on share deletion being enforced (§8.1 "Arbitration committee threshold trust"). Note this deletion dependency no longer applies to `null_v` forward secrecy, which the 2-of-2 verdict-binding closes cryptographically (§4.9.4, §8.2 T12).

#### Proven vs. calibrated vs. assumed

| Property                                   | Status      | Reduction or basis                                                                            |
| ------------------------------------------ | ----------- | --------------------------------------------------------------------------------------------- |
| P1 Identity unlinkability                  | proven (sk) | Poseidon PRF + transport profile bound                                                        |
| P2 Preference indistinguishability         | proven (sk) | Pedersen hiding (perfect) + permutation secrecy + **clean `ε`-DP** (clamp post-processing, §4.5) + composition (`ε_eff` open, OQ-55; lifetime `Tε` not claimed) |
| P3 Suspension persistence                  | proven (sk) | Poseidon collision resistance + SMT non-membership soundness                                  |
| P4 Forward-secure extraction               | proven (sk) | Threshold BLS + BF-IBE; FS of past `commit_T` closed by 2-of-2 verdict-binding, bounded by A2 (§4.9.4, §8.2 T12) |
| P5 Sybil influence bound                   | partial (reframed) | Adaptive-adversarial model: structural **influence floor `I_struct` is proven** (caps, §7.1b); the detection multiplier `p_j(S)` is calibrated; two corners (I3 sleeper, row-9 mimic) are named residuals bounded by `I_struct`/cost, not detection. See [SECURITY.md §P5](./SECURITY.md#p5--sybil-influence-via-adaptive-adversarial-modeling) |
| Smoothness detection rate                  | calibrated  | Srivatsa et al. 2005 + empirical thresholds (OQ-9)                                            |
| Behavioral fingerprint matching            | calibrated  | Profile-conditioned; full under Tor/I2P, thin under Loopix (§6.2)                             |
| A1 honest neighbor / A2 weight majority    | assumed     | Standard for gossip/BFT settings; per-epoch and lifetime-bounded by union argument            |
| A4 honest genesis (finite period)          | assumed     | Standard BFT bootstrap axiom                                                                  |
| Committee share deletion (post-rotation)   | assumed     | For **behavioral-snapshot custody** only; enforced by slashing (§8.1). No longer underwrites `null_v` forward secrecy — that is closed by §4.9.4 verdict-binding |
| Validator-attestation accountability (`VA`) | assumed     | Standing validator key; off-chain `VERDICT_FINALIZED` signing is slashable equivocation (§4.1); bounded by A2 |

"Proven (sk)" denotes *proof-sketchable* — the reduction is named and standard. The reduction-level write-ups now live in the companion **[SECURITY.md](./SECURITY.md)** (P1–P5, with games, hybrids, and the primitive each bottoms out in). The companion does **not** yet upgrade any cell to machine-checked; it upgrades them from "reduction named" to "reduction given." Two corrections it surfaced, **both now applied to this spec**: (i) the earlier §4.5 Laplace mode used a data-dependent sign-preservation *reject-resampling* that voided nominal `ε`-DP (neighboring vectors got outputs with different supports); §4.5 now uses the **bounded, clamp-based Laplace mechanism**, which is **clean `ε`-DP by post-processing immunity** (no `δ`), with the diagnosis and derivation in [SECURITY.md §P2](./SECURITY.md#p2--preference-indistinguishability-in-transit); (ii) P5 is reframed as an adaptive-adversarial game with a proven structural influence bound `I_struct` (above; closed form in [SECURITY.md §P5.2](./SECURITY.md#p52-the-provable-structural-bound-i_struct-behavior-independent--closed-form)).

**Substrate-contingency gate (P-feasibility — a hard precondition, not a footnote).** P1–P5 are properties of the *implemented substrate* (Layers 1–4), not of this document. The current PoC exercises only Layer 5 (recommendation) with obfuscation and PSI modeled in the clear. No P1–P5 claim is demonstrated in code yet. Before any P-claim is creditable in deployment: (a) Layers 1–4 must be built through §9.2 Phase 3; and (b) the **desktop** Statement-5 circuit (adopted publish-`s₁` form: `s₁+s₂` split with public `s₁` + `d_T` verifiable-encryption binding + SMT non-membership, **no in-circuit pairing**) must hit its proof-generation benchmark — a *bad* answer here changes the design, not merely the parameters. This is a **release gate** (see §10.1.1, "V1 — feasibility"), tracked as P-feasibility in [SECURITY.md](./SECURITY.md#summary--status-after-this-companion).

**The two halves are mutually load-bearing (A2).** Every property above is stated relative to Assumption A2 (honest majority by weight in the relevant eligible pool), and A2 is not an independent given — it is in part *produced* by the protocol it secures. Sybil resistance is what keeps the adversarial fraction of the mix-eligible pool below the Loopix anonymity threshold; mix anonymity is in turn what makes the privacy machinery — and therefore the identity unlinkability that the reputation/weight system relies on — hold. Neither half stands without the other, and both rest on A2 (§5.1.1). At deployment, before organic temporal depth accumulates, A2 in the mix pool is not self-satisfied: the real root of trust is the externally-published bootstrap mix consortium, and the Loopix anonymity guarantee is **conditional on that consortium's honesty** until the published transition criterion is met (§5.1.1). This conditionality should be read into P1–P5, not treated as a deployment footnote.

#### What this argument does **not** yet bound

- Concrete `ε_per_epoch` for P2 — depends on noise calibration in §4.5 and OQ-55.
- Concrete `δ_DSybil` and `γ_smoothness` constants for P5 — empirical, deferred to Phase 4–5 experiments.
- Forward secrecy of past `commit_T` against future-committee-key compromise — now closed cryptographically by the 2-of-2 verdict-binding (§4.9.4, §8.2 T12); residual bounded by A2 plus slashable validator accountability, not by deletion. Behavioral-*snapshot* forward secrecy (a separate mechanism) still relies on share deletion (§8.1).
- Behavioral fingerprint re-identification rate under Loopix — known thin, quantification deferred.
- Network-level deanonymization under Tor/I2P against a global passive adversary — explicitly out of scope (§1.5).

---

## 2. System Overview

PrivaCF is organized into five layers plus a single public chain, with an on-demand arbitration committee holding sensitive per-node state under threshold custody.

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
│  ARBITRATION COMMITTEE · On-Demand · Sensitive State │
│  VRF-selected · Shamir-shared · Threshold custody│
│  Continuity proofs · Fine-grained behavioral data│
│  Handoff history · Reconstructed only on quorum  │
└─────────────────────────────────────────────────┘
```

**Design principle — self-report is untrusted by default.** The protocol treats self-reported values as untrusted by default. All values feeding reputation scoring, audit decisions, or compound flag conditions rely on one or more of: peer attestation, ZK proof, public commitment, or committee threshold verification. No self-reported leaf types remain. The RATE_LIMIT leaf uses an announcement token set construction (§4.6) — tokens are unforgeable without `sk` and their cardinality is verifiable by the auditor without revealing which items were announced.

### 2.1 Node Relationships

See Appendix G for the full node relationship diagram. In brief: each node maintains peers in two tiers — an interest cluster tier (2–3 nodes confirmed by PSI) and a bridge tier (1 random DHT peer refreshed each epoch). Auditor committees and validator sets are VRF-selected each epoch with dual cluster diversity constraints; neither is predictable before the beacon is published.

**On validator and committee discoverability:** VRF selection means any node can verify who was selected for a given epoch after the beacon is published, but cannot predict it in advance. The cluster diversity constraints are checked deterministically against each candidate's canonical cluster label — the deterministic, recompute-verifiable result of the §6.2 centroid lifecycle, published and signed on the public chain.

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

The recommendation data structure is **HNSW** — Hierarchical Navigable Small World graphs (Malkov & Yashunin, 2018). HNSW organizes items into a layered proximity graph where each node connects to its approximate nearest neighbors. Queries navigate from coarse upper layers to fine lower layers, finding approximate nearest neighbors in O(log n) time with high recall. Each PrivaCF node maintains a local HNSW index built from received gossip vectors; item similarity scores for CF are computed by querying this index. Periodic snapshots are retained to support rewind recovery (§6.6).

Peer discovery uses a separate two-step mechanism — LSH pre-filtering followed by PSI confirmation — described in §5.4.

### 3.3 Clusters

PrivaCF organizes nodes into two independent cluster types, both derived from public data without any central coordinator.

**Interest clusters** group nodes whose item interaction sets overlap significantly, as measured by Jaccard similarity via PSI. Two nodes end up in the same interest cluster because they have interacted with many of the same items — not because they were assigned to one. Interest clusters drive peer selection and CF quality.

**Behavioral clusters** group nodes with similar participation patterns — when they are active within an epoch, how they space out announcements, when they submit on-chain transactions. These are derived entirely from public timing data on the blockchain. Behavioral clusters are used for Sybil detection and to ensure auditor committee independence. They are never used directly for reputation — they feed the compound flag system described in §7. Availability of behavioral-cluster signal is transport-profile-conditioned: full fingerprint under the Tor/I2P profile, thin fingerprint under the Loopix profile. See §5.1 for the profile framework and §6.2 for the per-profile fingerprint definitions.

Cluster membership is not fixed. It is recomputed each epoch from current data and evolves as a node's interaction history grows.

**Privacy implications:** Interest cluster membership is partially inferable by an external observer who watches PSI handshake patterns over time. Behavioral cluster reconstructability is transport-profile-conditioned. Under the Tor/I2P profile, sub-epoch timing signals are visible on the wire and behavioral fingerprints are largely reconstructable from public chain data, with the on-demand arbitration model, per-n-epoch commits, relay submission, and transaction timing jitter degrading but not eliminating their precision. Under the Loopix profile, sub-epoch timing is destroyed by the mix layer — only epoch-granular presence and audit-response rate survive (see §6.2), so behavioral fingerprints are inherently thin and not reconstructable beyond those coarse signals.

### 3.4 Trust Weight and Local trust_total

```
trust_contribution(v, X) = max(0, r_v(X) + noise) × Δ_base × (1 + κ × novelty(X))
```

- `r_v(X)` is node v's local preference weight for item X (`p_v[X]`). Only positive weights are transmitted in gossip vectors; negative weights stay local. Cover items (§4.5) receive a small assigned `cover_weight`; under the `max(0, ...)` guard they enter the sum only when their assigned weight is positive, so cover items contribute their assigned weight to `r_v(X)` and nothing more.
- `noise` is the additive announcement noise applied per §4.5: `Laplace(0, S/ε)` under the DP deployment or a bounded uniform draw under the chopping deployment. Sign preservation is achieved differently per mode: the DP deployment clamps the noisy output to `[0, B]` (data-independent post-processing, §4.5), so a sign-flipping draw projects to `0`; the chopping deployment bounds the uniform draw to `|p_v[X]|`. The `max(0, ·)` guard above makes both modes non-negative on entry to `trust_contribution` regardless.
- `Δ_base` is the base trust increment per announcement. It scales the raw preference weight into the trust_total space and requires empirical calibration.

`trust_total(item)` is not stored on the blockchain. Each node maintains a local estimate updated from received announcements weighted by announcer reputation band. Divergence across nodes is acceptable — CF requires only local consistency.

```
trust_total(X) = Σ_{v : v announced X} trust_contribution(v, X)
```

Items globally popular but not popular within a node's interest cluster are softened. Each node maintains both a global and a cluster-local accumulation:

```
global_trust_total(X)  = Σ_{v ∈ all announcers of X}                          trust_contribution(v, X)
cluster_trust_total(X) = Σ_{v ∈ announcers of X ∩ receiving node's cluster}   trust_contribution(v, X)

effective_trust(X) = β × global_trust_total(X) + (1−β) × cluster_trust_total(X)
item_weight(X)     = 1 / log(1 + effective_trust(X) / c)
```

`item_weight` uses a logarithmic damping analogous to IDF: items that have accumulated large trust totals contribute less marginal weight per additional interaction. The `c` in the denominator normalises the trust total against the DSybil cap, so the damping kicks in proportionally to how close the item is to the ceiling.

> **Implementation note — singularity at zero trust (E1).** As written, `1 / log(1 + effective_trust/c)` diverges to +∞ as `effective_trust → 0`, which is exactly the cold-item / long-tail regime the weight is meant to favour. In a scorer this produces `inf × 0 → NaN` for items with no co-occurrence signal and unbounded weights for near-cold items. The reference implementation regularises the denominator to `1 / log(2 + effective_trust/c)`, which is bounded in `(1/log 3, 1/log 2] ≈ [0.91, 1.44]`, still monotone-decreasing in trust, and agrees with the original to first order away from zero. Deployments must either adopt the `log(2 + ·)` form or restrict `item_weight` to items with strictly positive trust. The unbounded form should not be used directly.

Both trust totals are locally computable. `trust_total` is not stored on the public chain; each node maintains its own estimate by accumulating `trust_contribution(v, X)` values from received announcements, weighting each contribution by the announcer's score band (§6.1). The cluster variant restricts the sum to announcers in the receiving node's PSI peer neighborhood (`peers_v`). Per-node divergence in these estimates is acceptable — CF requires only local consistency, not global agreement.

### 3.5 Dislike-Aware Scoring

Negative preference weights are never transmitted. Dislikes are applied locally as a post-processing filter only:

```
final_score(item_i) = raw_cf_score(item_i)
    − penalty × max(0, Σ_{j ∈ dislike_set} sim(item_i, j) × |p_v[j]|)
```

### 3.6 User-Configurable Reputation Floor

Each node sets a minimum reputation band for gossip vectors incorporated into its local HNSW index. Default: Band 2.

The reputation floor functions as a confidence threshold on peer legitimacy. Whether reputation is modeled as a continuous gradient or discrete bands (as in this protocol) only changes the granularity of that confidence: discrete bands produce two effective states per threshold — zero weight below the floor, full weight above it — while a continuous gradient would scale contributions proportionally to confidence. This connection between reputation floor and expected sybil influence per peer is made explicit in the influence model (§7.1b). Users who wish to eliminate bridge-tier sybil influence entirely may set their bridge peer weight to zero; see the note in §5.7.

### 3.7 Diversity and Novelty

```
novelty(item)         = clamp(1 − effective_trust(item) / c,  0, 1)
trust_contribution(v, X) = max(0, r_v(X) + noise) × Δ_base × (1 + κ × novelty(X))
```

`trust_contribution(v, X)` is the same quantity defined in §3.4; the novelty bonus is the `(1 + κ × novelty(X))` factor that distinguishes its role in this section.

`novelty` is clamped to [0, 1]. When `effective_trust` equals 0 the item is fully novel (novelty = 1); when it reaches `c` novelty reaches 0 and the bonus disappears. Values above `c` are possible transiently if the blended `effective_trust` exceeds the cap before the DSybil gate truncates further contributions — the clamp prevents a negative novelty from inverting the bonus into a penalty.

Novel items accumulate trust weight faster. Nodes in sparse interest clusters receive additional CF aggregation weight.

> **Implementation note — where the novelty bonus must be applied (E1).** The `(1 + κ × novelty(X))` factor changes `trust_contribution(v, X)`, which feeds two distinct downstream uses: (a) the accumulated `trust_total`/announcement weights, and (b) the per-item column of the gossip matrix from which item-item **cosine** similarity is computed. For use (b) the factor is a *no-op*: cosine normalises each item column independently, so any per-column scalar — including `(1 + κ × novelty)` — cancels out and has zero effect on `sim`. The novelty bonus therefore only does work where it is applied as a factor on the **candidate item** at ranking time (a multiplier on `final_score`), not inside the similarity construction. The reference implementation applies the bonus (and the `item_weight` damping) as a candidate-item multiplier at scoring time; building it into the similarity matrix leaves rankings unchanged. The spec's intent — accelerate surfacing of undersurfaced items — is realised only by the ranking-time placement; this distinction should be stated wherever a recommendation algorithm is specified (§13).

> **Calibration note — κ is a discovery↔accuracy dial, and so is β (E1/E4).** The PoC characterizes the κ frontier on MovieLens (top-K, temporal hold-out). The IDF `item_weight` damping (§3.4) is nearly free — it roughly doubles long-tail discovery at a few percent precision cost — so it should default *on*. The novelty strength κ then trades head/overall precision for long-tail recall along a frontier whose useful range is small: at **κ ≈ 0.25** the reference strategy keeps ≈ 90% of plain-CF precision (still above a popularity baseline) while surfacing several-fold more long-tail content; by κ = 1 precision has fallen well below popularity, and **κ ≳ 1 is strictly dominated** — long-tail recall plateaus while precision keeps dropping. A sane deployment default is therefore κ in the **0.2–0.3** band, *not* κ = 1; experiments reported at κ = 1 elsewhere in calibration use the discovery extreme to demonstrate the *capability*, not a recommended operating point. Two further results bear on calibration: (i) the cluster blend `β` (§3.4) is a **second** dial onto the same frontier — lowering β below 1 personalizes which items count as locally novel and, in the PoC, *raised* precision (≈ +15% over global-only) while reducing long-tail recall, navigating the tradeoff via local-vs-global popularity rather than novelty strength; κ and β should be calibrated **jointly**, not independently. (ii) The discovery setting and the Sybil-resistance setting do **not** conflict: the passive damping of §7.3 *is* the novelty/`item_weight` machinery, so a smaller κ does not weaken it (it only makes a cold-item push less rewarding to mount), and the active FoolsGold defense (§7.4) is independent of κ — the "decent-quality" operating point and the "Sybil-resistant" operating point coincide. Concrete per-community κ/β values remain Phase-4 calibration (§9.2); the contribution here is the *shape* of the frontier and the dominated region κ ≳ 1.

> The protocol does not prescribe a recommendation algorithm. For a full discussion of the deployment-level tensions this creates — sparsity, feedback loops, reputation interaction, epoch length, positive-only signal, niche privacy tradeoffs, and the boundary between organic popularity and coordinated pushing — see §13.

### 3.8 Strategy Interface and Catalog

The collaborative filtering construction in §3.1–§3.7 is the **reference recommendation strategy** shipped with the protocol. It is not the protocol. The privacy, identity, Sybil-resistance, and audit machinery in §4–§7 form a **substrate** that exposes a stable set of inputs to a strategy chosen by the node operator. Different nodes on the same network may run different strategies; the substrate guarantees Sybil resistance and privacy regardless of which strategy a node selects.

This separation is load-bearing for the project's positioning: "your node, your algorithm" is meaningful only if the substrate is general enough to host more than one algorithm.

**Substrate-provided inputs to any strategy:**

| Input | Source | Privacy property |
|---|---|---|
| Trust-weighted stream of `(item, endorsement)` from peers | Gossip pulls from PSI peer neighborhood (§3.2, §5.4) | Peer endorsements visible only after PSI confirms overlap |
| Per-item global trust totals | Public chain aggregation (§3.4) | Public by design |
| Cluster membership signals | PSI peer set + behavioral fingerprint (§3.3, §6.2) | Membership inferable only by direct PSI partners |
| Peer trust weights | Local computation (§3.4) | Local-only |
| Item content / content-addressed payloads | Content-addressed fetch (out of band) | Independent of substrate |
| Cross-epoch continuity for follow-style trust | §4.7 handoff | Continuity without linkability |

A strategy is any local computation that consumes some subset of these and produces a ranked list of candidate items. Strategies do not need substrate cooperation beyond the inputs above — they are local-only and freely swappable.

**Strategy catalog (illustrative, not normative):**

| Strategy | Substrate inputs consumed | Locally added | Notes |
|---|---|---|---|
| **Collaborative filtering** (reference, §3) | All | Aggregation formula | Default; works at small scale |
| **Content-based filtering** | Item stream only; ignores peer endorsements | Local embedding model (CLIP, sentence transformers) and item-embedding gossip | Stronger privacy: no preference vector ever leaves the node |
| **Knowledge-graph / semantic** | Item stream + peer-gossiped relation edges | Local graph + spreading-activation ranker | Useful for items with rich structured metadata (music, video, papers) |
| **LLM-based ranking** | Item stream + endorsements + local history | Local LLM (e.g. Llama-class); user-authored ranking prompt | Strongest sovereignty UX: the model explains its picks in your terms |
| **Two-tower / embedding** | Item stream | Content-addressed shared item-tower artifact; locally trained user-tower | Closest analogue to modern industrial recommenders |
| **Contextual bandit** | Item stream + local reward signal | Thompson sampling or LinUCB over peer-supplied candidates | Explicit explore/exploit control |
| **RL with user-defined reward** | Item stream + local outcomes | Local RL agent optimizing a reward function the user defines | Strongest ideological fit: you choose what is optimized |
| **Editorial / follow-graph** | Cross-epoch continuity (§4.7) only | List of trusted pseudonyms | Trivial to implement; useful as a building block |
| **Ensemble** | All of the above | User-set weights between sub-strategies | Most practical UX — combines complementary signals |

**Composition.** Strategies may be composed: an LLM ranker may take a CF candidate list as input; an ensemble may weight a content-based and a bandit strategy; an editorial follow-list may seed a CF run. The substrate is indifferent to composition.

**Substrate guarantees that bind regardless of strategy.** Identity privacy (§4), preference obfuscation in transit (§4.5), tamper-evident behavioral history (§4.6), Sybil resistance (§7), and audit (§6) are properties of the substrate, not of the strategy. A node running an unusual strategy does not lose these guarantees; it only changes how it ranks the items the substrate makes visible to it.

**Out of scope here.** A formal strategy interface specification (concrete data types, callbacks, lifecycle hooks) is not part of this document. The catalog above describes design space, not API. See §13 for the cross-cutting deployment tensions that any strategy must address.

---

## 4. Identity and Privacy

Each cryptographic primitive solves one specific problem. To orient the reader before the formal definitions: a node's long-term key `sk` never leaves the device. From it, the node derives a per-epoch pseudonym (`epoch_id_T`) that is unlinkable across epochs, a permanent nullifier (`null_v`) that ties all epoch IDs together without revealing the link, and a forward-secure commitment (`commit_T`) that lets the committee extract `null_v` after a verdict without any cooperation from the node. The ZK proof system lets auditors verify properties of preference and behavior data they cannot read. The diagram below shows how these relate before each is introduced individually.

See Appendix H for the full identity/privacy relationship diagram.

### 4.1 Chain and Arbitration Committee

**Epoch duration.** PrivaCF targets an epoch duration of 2–3 hours (configurable per deployment). This window is short enough to preserve epoch-granular timing signals usable by Sybil clustering (T.1, T.5, T.9 in §7.1a) under the Loopix profile where sub-epoch timing is unavailable, while remaining long enough to amortize per-epoch handoff costs — ZK proof generation on mobile hardware (OQ-3) and committee DKG latency for the rotating audit/validator committees. Shorter epochs improve detection resolution at the cost of proof-generation throughput; longer epochs invert that tradeoff.

PrivaCF's public state lives on a single public blockchain. Per-interaction state lives in **signed co-receipts** held locally by both parties. State that must survive node rotation but cannot live on the public chain is **Shamir-shared to a rotating committee** that acts as an on-demand arbitrator rather than an active ledger keeper.

**The public blockchain** is the authoritative record for verdicts, anonymized reputation attestations, epoch_id registrations, `commit_T` values, score-band attestations, and the SUSP_SMT and DECRYPTION_SMT roots (see §4.9.2 and §4.9.3 for the SMT definitions). It is a VDF-chained ledger with Byzantine fault-tolerant consensus. Every node can read and verify it. Light clients verify entries via Merkle inclusion proofs against block headers.

**Co-receipts.** Every protocol interaction that needs after-the-fact proof — gossip push acceptance, pull response delivery, PSI handshake completion, audit response delivery — produces a receipt signed by both parties and held locally by both. Volume is low: per node per epoch, roughly one gossip push, a handful of pulls, a few PSI attempts, and the audit responses triggered for that node. Either party can later present its half of a receipt to the arbitration committee (see below) without ever publishing it to a chain. Atomic exchange of the two signatures uses a standard HTLC-style two-step swap so neither party can withhold after seeing the counterparty's signature; full construction in Appendix A.

**Arbitration committee.** A VRF-selected committee of size K_committee, rotating per epoch, is invoked **on demand** for three purposes: (1) verifying the per-epoch handoff package (§6.4); (2) adjudicating co-receipt disputes when a node claims a counterparty cheated; (3) holding Shamir shares of `snapshot_v(T)` — the encrypted per-node behavioral state that supports continuity proofs and Class 3 audits. The committee does **not** maintain an active ledger between invocations. Members hold encrypted shares; reconstruction requires a threshold quorum and is triggered by a specific arbitration request, not by ongoing block production. The same VRF-selection machinery used elsewhere in the protocol (§4.9.4) applies — there is no separate consensus instance.

**Why this is not a chain.** A full committee-held ledger would require continuous threshold consensus among members, share rotation on every membership change, and a separate availability story. The on-demand model eliminates all three. Members store their encrypted shares; the public chain records the committee's selection (via VRF output) and the handoff's score-band attestation; everything else is reconstructed only when an arbitration is actually requested. Trust assumption: threshold honesty of the **currently-selected** committee at arbitration time, not of every committee that has ever existed.

**Handoff state continuity across committee rotation.** When a committee rotates, the outgoing committee re-Shamir-shares each `snapshot_v(T)` it holds to the incoming committee, encrypted to the incoming members' epoch keys. This is a one-shot per-epoch handoff, not a continuous protocol. The re-share is verified by a ZK proof of correct re-encryption; failure to complete it is itself a slashable offense for the outgoing committee.

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

`primary_entries` are the high-priority transactions enumerated below (suspension verdicts, watchdog signals, epoch_id registrations, `commit_T` values, double-signing evidence, Class 3 audit results). `proposer_id` is the VRF-selected node responsible for assembling and proposing the block, per the BFT consensus protocol — analogous to the proposer in any Tendermint-style chain.

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
```

**commit_T and n_commit batching:** `commit_T` and its ZK proof are included in the `epoch_transaction` and submitted every epoch. `M_v(T)`, `C_p(T)`, score band, and health tier batch per `n_commit`. The rationale: `commit_T` must be tied to the current epoch's committee threshold BLS key, which rotates every epoch; batching would create key staleness. `commit_T` is opaque without a verdict signature and reveals only node presence, which is already inferrable from `epoch_id` registration. The threshold key is generated by the VRF-selected committee running a standard distributed key generation (DKG) protocol over BLS12-381 at the start of each epoch — see §4.9.4 for the construction.

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
                          different_behavioral_clusters    // see §6.2; applies under Tor/I2P profile, relaxed under Loopix profile (see §4.9.8)
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

**Standing validator-attestation key (`VA_pub`).** The validator share `s₂` of every node's `commit_T` is encrypted to `VA_pub` (§4.9.4). Unlike the per-epoch audit-committee keys, `VA_pub` is a *single, standing* threshold BLS key whose public value never changes — it must be known at encryption time and stay usable when a verdict finalizes several epochs later. It is a **dedicated** key, separate from the per-validator consensus signing keys (those aggregate into `validator_sigs` but share no master secret, so they cannot serve as an IBE key-generation authority).

```
GENESIS (one-time, under honest-genesis assumption A4):
    genesis validator set runs a DKG over BLS12-381
        → VA_pub        (published in the genesis block; immutable thereafter)
        → VA_share_i    (held by each genesis validator i)

EACH ROTATION  validator_set_T → validator_set_{T+1}:
    proactive re-share (PSS) of the SAME secret behind VA_pub:
        each outgoing member re-Shamir-shares VA_share_i to the incoming
        members (encrypted to their epoch keys) with a ZK proof that the
        re-share is consistent with the fixed VA_pub
        → incoming members combine sub-shares into fresh VA_share'_j
    VA_pub is UNCHANGED; only the shareholding is refreshed.
    Non-completion is slashable for the outgoing set — same rule as the
    arbitration-committee snapshot re-share ("Handoff state continuity"
    above; §8.2 T8).

VERDICT FINALIZATION (epoch T' ≥ T, by whichever set holds the key then):
    IFF a SUSPEND verdict for epoch_id_T is canonically finalized   // never on PASS,
                                                                     // never absent a verdict
        validator_set_{T'} threshold-signs "VERDICT_FINALIZED epoch_id_T"
            → σ_T^VERDICT   (DST distinct from consensus / SUSPEND-IBE / beacon /
                             gossip / relay; §4.9.4)
        published in the verdict block; becomes the IBE decryption key for d_T.
```

**Why re-share rather than regenerate.** Regenerating the key each epoch would change `VA_pub` and strand every already-published `d_T` whose verdict has not yet finalized. Proactive re-sharing preserves the secret — and hence `VA_pub` — while refreshing who holds it. It also buys **proactive security**: because shares are re-randomized every epoch, an adversary cannot accumulate shares across epochs; recovering the secret requires compromising a threshold of validators *within a single epoch window*. This is exactly what makes the §4.9.4 residual precise — covert release of `s₂` requires a break of the **current** validator threshold (an A2 violation) plus a slashable equivocation; shares retained from past validator sets are useless after one re-share. The one irreducible bootstrap dependency is **A4**: a threshold collusion *at the genesis DKG* would learn the master secret directly and retain signing power across all rotations — the standard standing-key genesis caveat, bounded by the honest-genesis assumption and narrowable by the optional forward-secure hardening of `VA_pub` (§4.9.4).

**Accountability.** A `VERDICT_FINALIZED` signature with no matching canonical **SUSPEND** verdict is a validator threshold equivocation — detectable on-chain and slashable under the double-signing rule above. The honest signing path emits `σ_T^VERDICT` only while finalizing a block that carries the corresponding `verdict_reveal` with a SUSPEND outcome; a PASS verdict produces no attestation, so a node that is never suspended never has `s₂` released.

**Threshold coupling (liveness).** The VA reconstruction threshold is set at or below the consensus finalization quorum (`⌊2K_validators/3⌋+1`), and contributing one's VA share is part of the finalization duty for a SUSPEND block. Any validator set that can finalize the SUSPEND verdict can therefore also produce `σ_T^VERDICT`, so `σ_T^VERDICT` liveness reduces to consensus liveness — there is no state in which a suspension finalizes but `s₂` is unrecoverable. (Committee-side `s₁` liveness is handled separately by the `N_fallback` fallback slots, §4.9.6.)

**Custodial cadence (parameter).** By default the VA custodial set tracks the per-epoch validator set, so re-sharing runs every epoch among `K_validators ≈ 21` — PSS at this size is the same order of cost as the per-epoch committee DKG already in the budget, and must complete inside the rotation window (a liveness obligation analogous to §8.2 T8). A deployment may instead pin VA custody to a more slowly rotating quorum to cut re-share overhead, at the cost of a wider single-compromise window for the `s₂` half; this is a calibration choice, not a protocol change.

**Light clients:** Mobile nodes store block headers only and use Merkle inclusion proofs to verify specific entries.

**Per-n-epoch public chain commits:** The `epoch_transaction` merge fires every `n_commit` epochs for `M_v`, `C_p`, score band, and health tier, reducing on-chain timing resolution available for behavioral fingerprinting. `commit_T` is exempt from batching because it is bound to that specific epoch's committee threshold BLS key (which rotates each epoch, per §4.9.4); batching would produce a stale key reference and break the forward-secure construction. n_commit = 2 or 3 is a reasonable starting range.

**On-chain footprint is per-node but commitment-only.** Every active node writes an `epoch_transaction` keyed by its `epoch_id` (Appendix A), so the chain does hold a record for all nodes. But the per-node fields submitted every `n_commit` epochs — `score_band`, `health_tier`, `M_v(T)`, `C_p(T)` — are commitments, roots, and a 2-bit band; never the underlying behavioral data, which stays off-chain behind `M_v` and under Shamir custody (§4.1, Appendix B). The only field written *every* epoch per node is `commit_T` (plus its ZK proof and the epoch's threshold BLS key reference), exempt from batching by construction because its committee key rotates per epoch. That single every-epoch write is therefore the dominant term in both on-chain state growth — O(active_nodes) per epoch, ≈96·(`N_fallback`+1) bytes each (the +1 is the validator ciphertext `d_T`, §4.9.4) — and in the per-epoch presence signal already accepted in §8.1 and §8.2 T10. State growth for large `N` is the standard ledger-pruning concern; light clients verify via block headers and Merkle inclusion proofs rather than holding full per-node history.

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

| Derivation           | Expression                                                   |
| -------------------- | ------------------------------------------------------------ |
| Epoch ID             | `Poseidon(sk, beacon_T, null_v, "epoch_id")`                 |
| Permutation          | `Poseidon(sk, beacon_T, "perm")`                             |
| Chop count           | `Poseidon(sk, beacon_T, "chop_n")`                           |
| Epoch offset         | `Poseidon(sk, "epoch_offset")`                               |
| Niche announce delay | `Poseidon(sk, item_hash, beacon_T, "niche_delay")`           |
| Committee token      | `Poseidon(committee_sk, epoch_id_v, T, "continuity_token")`  |
| Leaf salt            | `Poseidon(sk, epoch_T, "leaf_salt")`                         |

All derivations must use distinct (domain_sep, input) pairs for any `sk`. Domain separator collision check resolved — all derivations now have explicit (domain_sep, input_structure) pairs; collision argument reduces to standard Poseidon collision resistance (OQ-4 — closed).

The leaf salt is intentionally fixed per (node, epoch): it is the same value for every leaf node v writes within epoch T, but distinct across nodes (different `sk`) and across epochs (different `epoch_T`). This shared-within-epoch property is what makes sibling hashes in the Merkle tree opaque under fixed leaf padding (§4.6) — without a per-leaf-position differentiator beyond the salt, leaf positions remain unlinkable to specific event types from an external observer who has not seen the leaf body.

### 4.3 Identity Admission Cost

**Problem:** Free instant identity creation allows unlimited fake identities.

**Tool:** A VDF chain. Inherently sequential — more compute does not help.

```
vdf_proof_{t₀} = H("vdf_genesis", C_id)                  // chain seed BOUND to the identity genesis
vdf_proof_T    = VDF_eval(vdf_proof_{T-1}, δ_identity)
VDF_verify_chain([vdf_proof_{t₀}, ..., vdf_proof_T], n, δ_identity) = true   AND   seed = H("vdf_genesis", C_id)
```

**Chain–identity binding (normative — load-bearing for the rate limit, OQ-57).** The chain seed `vdf_proof_{t₀}` MUST be derived from a commitment `C_id` to the identity genesis (e.g. `null_v` / a commitment to `sk`), and the admission verifier MUST check it. This binds each completed chain to exactly one identity: a chain cannot be replayed to admit a second identity, and chains cannot be precomputed in bulk before identities are chosen. Without this binding the VDF rate-limits *chains* but not *identities*, and reputation laundering by rotation would amortize to `O(1)` cost (the amortization-proofness argument is in [SECURITY.md OQ-57](./SECURITY.md#oq-57--reputation-laundering-vs-the-admission-cost-rate-limit)).

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

The preference vector `p_v` is fixed for the duration of an epoch. Updates to `p_v` are only permitted at epoch transitions. Enforcement is structural: `C_p(T)` is published at the start of the epoch with binding to a specific `p_v(T)`; Pedersen's binding property means a different `p_v'(T)` cannot open the same commitment. At the next handoff, §4.9.5 Statement 3 requires `‖p_v(T) − p_v(T−1)‖₁ ≤ Δ`, which constrains the magnitude of inter-epoch change but does not permit intra-epoch revision of the committed value.

### 4.5 Preference Obfuscation in Transit

**Problem:** Even without reading a preference vector, an adversary receiving it multiple times can correlate dimensions across epochs and infer preference count from vector size.

**Tool:** Per-epoch permutation plus variable-size transmission.

```
π_v(T)  = Poseidon(sk, beacon_T, "perm")                              // sk is per-node, so π_v is independent across nodes
n_v(T)  = n_base + Poseidon(sk, beacon_T, "chop_n") mod n_jitter
```

**Variable chopping:** Exactly `n_v(T)` elements are transmitted, selected from the permuted positive preference set, padded with cover items if needed. Neither the number of real preferences nor which preferences are real is inferrable from the transmitted vector size.

Only positive preference weights are included in gossip vectors. Negative weights stay local.

**Cover items:**

```
cover_weight(item) = Uniform(0, cover_scale) / log(1 + trust_total(item) / c)
```

`cover_scale` is a per-deployment calibration constant bounding the maximum cover weight injected; `c` is the small constant from §3.4's `item_weight` (the DSybil cap normalizer) that prevents log explosion when `trust_total` is near zero. Both require empirical tuning (calibration entries added to OQ-list under §10).

**Chopping vs. Laplace DP** (mutually exclusive per deployment):

- **Chopping** (niche-friendly): transmit `n_v(T)` elements as above. No formal DP claim; the privacy argument is the indistinguishability of which `n_v(T)` positions were kept (permutation + cover padding).
- **Laplace DP** (mainstream, formal guarantee): the gossip vector is released by the **bounded, sign-preserving Laplace mechanism** below, which is **`ε`-DP per gossip event** for L1 sensitivity `S = 2` with `‖p_v‖₁ = 1`.

**Bounded, sign-preserving Laplace mechanism (`ε`-DP by post-processing):**

```
B                = public per-coordinate bound (deployment constant, independent of p_v)
noisy[i]         = p_v[i] + Laplace(0, S/ε)            // standard Laplace → ε-DP on the whole vector
gossip_v(T)[i]   = clamp(noisy[i], 0, B)               // data-independent projection onto [0, B]
gossip_v(T)      = gossip_v(T) / ‖gossip_v(T)‖₁        // data-independent renormalization
```

The first line is the standard Laplace mechanism and is `ε`-DP. The clamp and the renormalization are **deterministic, data-independent functions of the already-released noisy vector**, so by DP's post-processing immunity (Dwork & Roth, Prop. 2.1) the composed mechanism remains **`ε`-DP — no `δ`, no weakening.** Crucially, **sign preservation is the non-negativity clamp**, not a data-dependent rejection: a draw that would flip a positive weight negative is projected to `0` ("not endorsed") rather than resampled against a `|p_v[i]|`-dependent threshold. This is the fix for the earlier reject-resampling construction, whose conditioning on the data-dependent event `|noise_i| < |p_v[i]|` voided the nominal `ε`-DP (neighboring vectors got outputs with different supports; see [SECURITY.md §P2](./SECURITY.md#p2--preference-indistinguishability-in-transit)).

> **What this costs and does not claim.** A coordinate with a small true weight may clamp to `0` and drop from the transmitted set — benign, because the transmitted *set* is already protected by chopping/cover. The corrected E2 (clamp-based) measures the cost: CF quality is now genuinely `ε`-*sensitive* (the earlier "nearly `ε`-insensitive" reading was partly an artifact of the DP-voiding noise-clip), but it stays above the popularity floor at every tested `ε` because the *support* is preserved (noise is on active dims only; which-items is chopping's job) and item-cosine CF is co-occurrence-driven. The `ε`/utility curve is non-monotone (worst near mid-range `ε`; at small `ε` the clamp+renormalize degenerates toward a randomized binarization of the support that CF tolerates). **Lifetime DP is not claimed:** `T` events compose to `Tε` (basic) or `≈ √(2T ln(1/δ'))·ε` (advanced; Dwork–Rothblum–Vadhan), and the cumulative budget is unbounded over a node's lifetime (§8.1, OQ-55). A deployment wanting a tighter utility/`ε` frontier on the bounded domain may substitute the Geng–Viswanath optimal bounded-noise mechanism or the staircase mechanism for the first line; the clamp/renormalize post-processing argument is unchanged.

**Niche item announcement delay:**

```
announce_delay_v(item) = Poseidon(sk, item_hash, beacon_T, "niche_delay") mod max_delay_epochs
```

This delay is a deliberate privacy mechanism: it intentionally degrades the announcement-timing behavioral signal for niche items (the very items that would otherwise be uniquely identifying). The detection cost is acknowledged — see §6.2's transport-profile-conditioned fingerprint definitions, which already account for which timing signals survive each profile.

### 4.6 Tamper-Evident Behavioral History

**Problem:** A node needs to prove to auditors that its behavior was within protocol limits without revealing its details.

**Tool:** A Merkle tree whose leaves are built from peer attestations collected passively as a side effect of normal protocol traffic.

**Leaf structure:**

```
leaf(ANNOUNCEMENT, T)  = H("ANN"  ‖ T ‖ set_of_peer_signed_observations ‖ salt_v)
leaf(PULL_RESPONSE, T) = H("PULL" ‖ T ‖ set_of_peer_signed_receipts       ‖ salt_v)
leaf(AUDIT_RESP, T)    = H("AUD"  ‖ T ‖ auditor_published_results          ‖ salt_v)
leaf(RATE_LIMIT, T)    = H("RL"   ‖ T ‖ announcement_token_set(T)          ‖ salt_v)

announcement_token(v, X, T) = Poseidon(sk, item_hash(X), beacon_T, "ann_token")

`announcement_token_set(T)` is the set of all tokens generated by node v for items announced during epoch T. The RATE_LIMIT leaf commits to this set; the auditor verifies only the cardinality against the rate limit ceiling, without learning which items the tokens correspond to. Each token is unique per (node, item, epoch) — `beacon_T` prevents reuse across epochs and `item_hash(X)` prevents token sharing across items. A node cannot manufacture tokens for announcements it did not make without `sk`, and cannot omit tokens for announcements it did make without the ZK proof over the leaf set failing. The auditor committee verifies the cardinality of `announcement_token_set(T)` against the rate-limit ceiling during the handoff process (§6.4), via a ZK proof over the RATE_LIMIT leaf — see also §7.4 for how rate-limit compliance feeds the per-epoch score.

salt_v = Poseidon(sk, epoch_T, "leaf_salt")
M_v(T) = MerkleRoot(padded_leaves_v(T))
         // padded to a fixed protocol-wide maximum leaf count
```

**Partial reveals are safe:** Fixed padding plus per-leaf VRF salts ensure sibling hashes are opaque.

### 4.7 Cross-Epoch Identity Continuity

**Problem:** After epoch rotation, the auditor committee does not know a node's new `epoch_id` belongs to the same node.

**Tool:** A zero-knowledge proof of Poseidon PRF continuity, submitted to the arbitration committee only.

```
ZK { sk :
    Poseidon(sk, beacon_T,   null_v, "epoch_id") = epoch_id_T
    Poseidon(sk, beacon_T-1, null_v, "epoch_id") = epoch_id_{T-1}
    null_v = Poseidon(sk, "null_v")    // verified inside the ZK circuit; see §4.9.5 Statement 5 for how validity and SUSP_SMT non-membership are jointly proven without revealing null_v
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
encrypted_token = Enc(pk_v(T), token_v(T))    // pk_v(T) is node v's ephemeral encryption public key for epoch T, derived from sk and published alongside epoch_id_T; private decryption key never leaves the device
```

The node decrypts the token and must incorporate it into the next handoff ZK proof. A node that missed a handoff cannot produce a valid proof because it would need the token. The chain becomes a tamper-evident audit history — gaps cannot be hidden because every subsequent commitment depends on all prior ones.

### 4.8 PSI Cache Decay

```
psi_cache[new_epoch_id] = psi_cache[old_epoch_id] × λ_proof     (λ_proof ≈ 0.95)
cache_weight(U, T)      = base_weight × λ_noproof^(T − last_verified_T)  (λ_noproof ≈ 0.7)
```

Both λ values require empirical calibration (OQ-20). The two are distinguished by the evidence available at decay time: `λ_proof` applies when a continuity proof from the peer in the new epoch confirms identity carry-over — light decay (~0.95) since the peer is still verifiably the same node. `λ_noproof` applies when continuity has not been verified for the peer — heavier decay (~0.7) reflecting the higher uncertainty that the cached PSI overlap still applies.

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
- **Structurally intrinsic** — a valid `epoch_id_T` cannot be produced from `sk` without `null_v`, because `null_v` is an input to the epoch ID derivation. Enforced by the ZK proof at each handoff (§4.9.5 Statement 5) and non-malleability (§4.9.7): the circuit constrains `null_v` and `epoch_id_T` to share the same `sk` wire, so a forged or substituted `null_v` cannot satisfy the proof.

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

> **ADOPTED DESIGN — publish-`s₁` (validator-gated).** The protocol adopts the **publish-`s₁`** form of this mechanism (full construction in [DESIGN-f1-verifiable-encryption.md §7](./DESIGN-f1-verifiable-encryption.md#7-alternative-that-dissolves-both-gates--publish-s₁), security in [§9 Cor. 5](./DESIGN-f1-verifiable-encryption.md#9-security-analysis-phase-1-step-1--the-binding-the-construction-stands-on), threat-model sign-off in [§10](./DESIGN-f1-verifiable-encryption.md#10-threat-model-sign-off-for-publish-s₁-phase-1-step-2)). Concretely:
> - `null_v = s₁ + s₂ (mod p)` with `s₂ = r_share` sampled fresh-uniform per epoch; **`s₁` is published in the clear** in `commit_T` (it is uniform and information-theoretically independent of `null_v`, so it leaks nothing).
> - **Only `s₂` is encrypted**, to the standing validator-attestation key `VA_pub` under identity `"VERDICT_FINALIZED epoch_id_T"`, using the **native-group limb verifiable encryption** of DESIGN §3–§4 (no in-circuit pairing). So `commit_T = (s₁, d_T)`.
> - Recovery on a verdict: `s₂ = Decrypt(d_T, σ_T^VERDICT)`; `null_v = s₁ + s₂`. **No committee decryption share exists.** The committee's role is **audit + verdict decision only** (commit-reveal becomes a vote, not a BLS-share aggregation); it needs **no per-node threshold key and no DKG** — handoff/score-band attestation is by **aggregate multisig** over its VRF-selected members. The only threshold-IBE key in the system is the standing `VA_pub`.
> - **Decryption lock:** validator-only. Set the VA reconstruction threshold at the BFT quorum `⌊2K_validators/3⌋+1`, so covert recovery requires a **>2/3 validator collusion — already beyond Assumption A2** — and is a slashable equivocation (§4.1). The rogue-committee residual (§7.9.4 row 17) is **neutralized** (committee holds no decryption material). Governance sign-off recorded in DESIGN §10.1–3.
> - **Consequences:** OQ-63 (per-node DKG load) is **eliminated**; Statement 5 (§4.9.5) drops the per-slot pairing checks (`s₁` is a public circuit input, only `s₂` carries a verifiable-encryption binding); the `N_fallback` committee-ciphertext machinery for `s₁` is **not used**; per-epoch on-chain footprint shrinks (a 32-byte `s₁` + one `d_T`).
>
> Proofs are at sketch level (DESIGN §9) pending EasyCrypt machine-check; the **2-of-2 construction described in the remainder of this subsection is retained as an optional high-assurance profile** (it re-adds the committee lock at the cost of per-node DKG → cohort-sharing, ANALYSIS §4, and AMBER Statement-5 cost). The two profiles share all machinery except `s₁`'s custody.

**Problem.** `null_v` must be recoverable after a suspension verdict even if the node is offline, without enabling covert extraction — contemporaneous *or* retroactive (the forward-secrecy gap, §8.2 T12) — by any party short of a public, accountable verdict.

**Adopted construction (publish-`s₁`) — canonical.** Split `null_v = s₁ + s₂ (mod p)` with `s₂` fresh-uniform per epoch. **`s₁` is published in the clear** inside `commit_T` (it is uniform and information-theoretically independent of `null_v`, so it reveals nothing on its own). **Only `s₂` is encrypted** — to the standing validator-attestation key `VA_pub` under identity `"VERDICT_FINALIZED epoch_id_T"`, using the native-group limb verifiable encryption of [DESIGN §3–§4](./DESIGN-f1-verifiable-encryption.md) (no in-circuit pairing). So `commit_T = (s₁, d_T)`. On a finalized SUSPEND verdict the validator set publishes `σ_T^VERDICT`; anyone computes `s₂ = Decrypt(d_T, σ_T^VERDICT)` and `null_v = s₁ + s₂`. **No committee decryption share exists** — committees audit and vote only (§4.9.6), holding no per-node threshold key and running no DKG; the sole threshold-IBE key is `VA_pub`. The decryption lock is **validator-only**, set at the BFT quorum `⌊2K_validators/3⌋+1`, so covert recovery requires >2/3 validator collusion (beyond Assumption A2) and is a slashable equivocation (§4.1). Forward secrecy: absent a verdict, `σ_T^VERDICT` never exists and `commit_T` is sealed forever; a future committee compromise reveals nothing because committees hold no decryption material. This is the construction §4.9.5 (Statement 5) and §4.9.6 (commit-reveal) specify as primary.

> **Optional high-assurance 2-of-2 profile — the remainder of §4.9.4.** Everything from "**Tool:**" below through the end of this subsection specifies an *optional* profile that additionally locks `s₁` behind a per-epoch audit committee (decryption needs committee ∧ validator). It is **not the default**: it re-incurs the per-node committee DKG (OQ-63 → cohort-sharing, ANALYSIS §4) and the AMBER Statement-5 in-circuit pairing cost (SPIKE §8). The two profiles share all machinery except `s₁`'s custody — under the adopted profile, `s₁` is simply public and only the `s₂`/`d_T` half of what follows is built. Proofs for both are at sketch level (DESIGN §9) with the algebraic core machine-checked (`impl/easycrypt/`).

**Tool:** Boneh-Franklin Identity-Based Encryption over BLS12-381 (Boneh & Franklin, CRYPTO 2001), encrypted in parallel to `N_fallback` independent committees. Each ciphertext uses its committee's threshold BLS public key as the IBE master public key; the identity string is `"SUSPEND epoch_id_T"`; the aggregated threshold BLS signature on that string is the IBE private key for that identity; `null_v` is the plaintext; the i-th ciphertext slot `c_T^{(i)}` is one component of the composite `commit_T`. Security of each slot reduces to DBDH in the random oracle model. The implementation falls out of blst (already in the stack).

The "master key" terminology is inherited from generic IBE and is not held by any single party. Each `threshold_BLS_pk_T^{(i)}` is jointly produced by its VRF-selected committee via DKG — no member holds the corresponding master secret. Producing an IBE decryption key for the identity `"SUSPEND epoch_id_T"` against the i-th slot requires ⌊K_committee/2⌋+1 honest members of `committee_T^{(i)}` to threshold-sign that statement. Safety reduces to the honest-majority Assumption A2 applied per committee.

**DST alignment requirement:** The domain separation tag used for hash-to-curve in BLS signing and in IBE key derivation must be explicitly defined and the SUSPEND-IBE DST kept distinct from all other BLS signing DSTs used by the committee (block signing, gossip authentication, relay attestation). RFC 9380 governs the construction. Validators reject committee BLS signatures that use the SUSPEND-IBE DST outside the explicit verdict reveal flow, preventing a committee member from producing an IBE decryption key by signing an unrelated message. A CI-enforced collision test on the DST table is required before release — the full DST registry, the I1–I4 invariant, and a reference CI check are specified in [SECURITY.md Appendix A](./SECURITY.md#appendix-a--domain-separation-tag-dst-registry-and-ci-invariant) (release blocker). The confidentiality theorem this DST discipline underwrites is [SECURITY.md §P4.1](./SECURITY.md#p41-multi-recipient-2-of-2-confidentiality-theorem).

```
// At epoch start, for each i ∈ {0, ..., N_fallback−1}:
committee_T^{(i)}        = VRF(beacon_T ‖ "audit_committee" ‖ epoch_id_v ‖ i, ...)
                           // disjoint-membership constraint: committee_T^{(i)} ∩ committee_T^{(j)} = ∅ for i ≠ j
threshold_BLS_pk_T^{(i)} = DKG_output(committee_T^{(i)})   // public, derivable by anyone

// Node additively splits null_v into two shares over the scalar field (prime p):
s₂ = r_share                              // random field element (private witness)
s₁ = null_v − s₂   (mod p)                // so that s₁ + s₂ = null_v

// Committee share s₁ → N_fallback parallel ciphertexts (liveness, as before).
// Validator share s₂ → one ciphertext to the standing validator-attestation key VA_pub,
//   bound to a *public* verdict via the identity "VERDICT_FINALIZED epoch_id_T":
commit_T = ( c_T^{(0)}, ..., c_T^{(N_fallback − 1)},  d_T )
    where  c_T^{(i)} = ForwardCommit(s₁, "SUSPEND epoch_id_T",           threshold_BLS_pk_T^{(i)}; r_commit_T^{(i)})
    and    d_T       = ForwardCommit(s₂, "VERDICT_FINALIZED epoch_id_T", VA_pub;                   r_commit_d_T)
```

Each committee slot `c_T^{(i)}` is decryptable if and only if the holder possesses a valid threshold BLS signature from `committee_T^{(i)}` on `"SUSPEND epoch_id_T"`; the N slots are independent ciphertexts of the *same* committee share `s₁`. The validator ciphertext `d_T` is decryptable if and only if the holder possesses the validator set's attestation signature on `"VERDICT_FINALIZED epoch_id_T"`. Statement 5 (§4.9.5) certifies, inside the handoff ZK proof, that all slots carry the same `s₁`, that `d_T` carries `s₂`, and that `s₁ + s₂ = null_v`.

**Decryption (requires both halves).** Recovering `null_v` requires opening one committee slot *and* the validator ciphertext:

```
s₁     = ForwardCommit.Decrypt(c_T^{(i)}, σ_i^SUSPEND)        // any one live slot i; σ_i^SUSPEND from committee_T^{(i)}
s₂     = ForwardCommit.Decrypt(d_T,        σ_T^VERDICT)       // σ_T^VERDICT from the validator set, published with the verdict
null_v = s₁ + s₂   (mod p)
```

Any single committee slot suffices for the `s₁` half (N_fallback gives liveness); the `s₂` half comes from one validator attestation. Both signatures are published as part of the same public verdict reveal, so decryption stays permissionless. No committee member or escrow holder needs to be online. **Crucially, a committee signature alone no longer recovers `null_v`** — it yields only `s₁`, which is independent of `null_v` without `s₂`.

**Step-by-step recap.** (1) At epoch start, `N_fallback` committees are VRF-selected with disjoint membership; (2) each committee runs an independent DKG to produce its `threshold_BLS_pk_T^{(i)}` (all public, derivable by anyone); the standing validator-attestation key `VA_pub` already exists and is known to everyone; (3) the node splits `null_v = s₁ + s₂`, encrypts `s₁` to the committees and `s₂` to `VA_pub`, and publishes `commit_T = (c_T^{(0..N−1)}, d_T)` on chain; (4) if and only if a SUSPEND verdict is finalized, two signatures come into existence and are published with the verdict — the committee's `σ_i^SUSPEND` on `"SUSPEND epoch_id_T"` (IBE decryption key for a committee slot) and the validator set's `σ_T^VERDICT` on `"VERDICT_FINALIZED epoch_id_T"` (IBE decryption key for `d_T`); (5) anyone holding both, plus the public ciphertexts, computes `s₁`, `s₂`, and `null_v = s₁ + s₂`. The node need not be online after step (3); no escrow holder participates; and absent a finalized verdict, `σ_T^VERDICT` never exists, so `null_v` is unrecoverable by anyone.

**Why forgery is impossible:** Each `c_T^{(i)}` is tied to `threshold_BLS_pk_T^{(i)}`, the public key of a specific VRF-selected committee for this node this epoch. Producing a valid aggregate signature under any one of those keys requires ⌊K_committee/2⌋ + 1 secret key shares held only by legitimately selected members of that committee. Disjoint membership across committees means no member can sign for more than one slot.

**Why liveness is preserved.** Stalling the suspension entirely now requires a colluding minority (more than K_committee − ⌊K_committee/2⌋ − 1 non-revealing members) in *every one* of the N_fallback committees simultaneously. Under Assumption A2, this joint probability decays exponentially in N_fallback. A single stalled committee no longer blocks the verdict — control passes to the next slot per §4.9.6.

**Why confidentiality is not weakened.** The security of `commit_T` is the maximum (i.e., the *weakest*) of the per-slot security levels. Because each slot independently reduces to DBDH under its own committee's honesty, and disjoint membership rules out cross-slot collusion of identical sets, the weakest slot is no weaker than the single-committee construction would have been at N=1. Multi-recipient adds liveness without trading confidentiality.

**Parameter choice.** `N_fallback = 3` is the suggested starting value for v1: primary plus two fallbacks tolerates two simultaneous committee-level stalls. Ciphertext size grows linearly: each `c_T^{(i)}` and the single `d_T` is a BLS12-381 G2 element pair (≈96 bytes), so `commit_T ≈ 96 × (N_fallback + 1)` bytes (the `+1` is the validator ciphertext `d_T`). Committee-side overhead grows similarly — `N_fallback × K_committee` nodes run DKG per epoch (only the primary actively audits; fallbacks hold idle keys); the validator share adds no per-epoch DKG, since `VA_pub` is a standing key reshared only at validator rotation. The audit workload itself is unchanged. **Aggregate cost caveat (OQ-63).** Because committees are selected *per node* and `commit_T` is published *every* epoch, this DKG cost is incurred per node per epoch: network-wide it is **O(N) DKGs per epoch**, and a single node is expected to sit on ≈ `N_fallback × K_committee` committees at once. Whether this survives at target network size — or forces committee sharing/batching across nodes (a design change) — is OQ-63 (§10.1.1, §10.3).

A node could attempt to evade by simply omitting `commit_T` from its handoff — but a missing `commit_T` is itself a visible chain artifact (handoff rejection per §4.9.10) and a refusal-to-sign by the committee for a legitimate SUSPEND attempt produces a non-revealing-member signal that triggers oversight (§4.9.6, §4.9.8 watchdog). Both evasion paths are detectable and penalized.

ForwardCommit security resolved as Boneh-Franklin IBE over BLS12-381 (Boneh & Franklin, CRYPTO 2001); reduces to DBDH in the random oracle model (OQ-2 — closed).

**The standing validator-attestation key `VA_pub`.** The validator share `s₂` is encrypted to `VA_pub`, the public key of a **standing threshold BLS key held by the validator set**. Unlike the per-epoch audit committees — which run a fresh DKG each epoch and whose keys are ephemeral — `VA_pub` is generated once at network bootstrap and is **proactively re-shared to each newly VRF-selected validator set at rotation**, reusing the one-shot, ZK-proven, slashable Shamir re-share machinery already specified for arbitration-committee handoff (§8.2 T8). The bootstrap DKG, per-rotation re-share (PSS), signing path, and proactive-security argument are sketched in §4.1 ("Standing validator-attestation key"). Two properties make it the correct recipient for `s₂`, where a per-epoch key cannot be: (a) `VA_pub` is **stable and known at encryption time**, so the node can encrypt `d_T` at epoch `T` even though the verdict may finalize several epochs later under a rotated set; (b) the validator set is a **persistent, identity-bound, slashable body**, so its signing behavior is accountable in a way an anonymous one-shot committee's is not.

The validator set produces `σ_T^VERDICT = threshold-sign_VA("VERDICT_FINALIZED epoch_id_T")` **only** as a canonical part of finalizing a block that carries a **SUSPEND** `verdict_reveal` for `epoch_id_T` (never on a PASS verdict, never absent one), and publishes it in that block. The `"VERDICT_FINALIZED"` DST is kept distinct from the SUSPEND-IBE, block-signing, beacon, gossip, and relay DSTs (extending the §4.9.4 DST-collision CI test to cover it). A `VERDICT_FINALIZED` signature produced outside canonical verdict finalization is an equivocation — a validator threshold signing a verdict that is not in the canonical chain — and is **slashable under the §4.1 double-signing rule**.

**Why this gives forward secrecy.** The split makes `commit_T` decryptable only by combining a committee signature with a validator verdict attestation, which changes the threat in three ways:

- **Committee-side forward secrecy (the actual fix).** A committee that colludes — contemporaneously, or by retaining shares that a future adversary later compromises — now recovers only `s₁`, an additive share that is information-theoretically independent of `null_v` without `s₂`. The lingering-shares threat that motivated §8.2 T12 is neutralized at the committee: **no future compromise of past committees alone can open a past `commit_T`.** Committee share deletion is no longer load-bearing for forward secrecy.
- **The remaining path is consensus-level and accountable.** `s₂` is released only by `σ_T^VERDICT`. It can be obtained two ways: (a) a real on-chain verdict (the intended path); or (b) a threshold of the **current** validator set signing off-chain — which is simultaneously a break of the honest-majority Assumption A2 *and* a slashable equivocation, and even then yields only `s₂` (the attacker still needs `s₁` from the epoch-`T` committee). So covert or retroactive deanonymization now requires breaking consensus-level honest majority **and** cracking the epoch-`T` committee **and** committing a slashable equivocation — strictly stronger than the prior single-committee assumption, and bounded by the same A2 that consensus already rests on.
- **No verdict ⇒ sealed by construction.** If no verdict for `epoch_id_T` is ever finalized, `σ_T^VERDICT` never exists, `d_T` never opens, and `commit_T` is cryptographically sealed forever — even against the full committee. The "decrypt iff suspended" semantics are now enforced by cryptography rather than by deletion policy.

**Optional defense-in-depth.** The residual path (b) can be narrowed further by making `VA_pub` itself forward-secure (Pixel-style key evolution — Drijvers et al., USENIX Security 2020 — puncturing the `epoch_id_T` verdict identity once the bounded verdict window `W_primary`/`W_fallback` closes). This subsumes the v2 forward-secure-BLS plan formerly tracked in §8.2 T12, now applied to a *single standing key* rather than to every per-epoch committee, and is no longer load-bearing — the verdict-binding above already closes the gap under A2.

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

**Statement 3 — Temporal consistency** (vector commitment difference): the ZK proof verifies that `C_p(T)` and `C_p(T−1)` open respectively to `p_v(T)` and `p_v(T−1)` (private witnesses), with the `‖p_v(T) − p_v(T−1)‖₁ ≤ Δ` bound below. Pedersen binding ensures the same commitments cannot open to different vectors, so the prover cannot substitute a fabricated `p_v(T)` that satisfies the bound but is not the committed value.

```
‖p_v(T) − p_v(T−1)‖₁ ≤ Δ
```

**Statement 5 — Non-suspension and forward commitment** (Poseidon evaluation + SMT non-membership + verifiable-encryption binding on the `s₂` share). **Adopted publish-`s₁` form (primary):**

```
null_v      = Poseidon(sk, "null_v")
epoch_id_T  = Poseidon(sk, beacon_T, null_v, "epoch_id")
null_v ∉ SUSP_SMT_root_T
s₁ + s₂ = null_v   (mod p)                       // s₁ a PUBLIC circuit input; s₂ private
d_T = VerEnc(s₂, "VERDICT_FINALIZED epoch_id_T", VA_pub; r_commit_d_T)  // native-group, no pairing
```

`s₁` is revealed (a public input, published in `commit_T`); the circuit certifies only that the published `s₁` and the encrypted `s₂` sum to the `null_v` derived from `sk`, and that `d_T` is a well-formed native-group verifiable encryption of `s₂` to `VA_pub` ([DESIGN §3–§4](./DESIGN-f1-verifiable-encryption.md)) — so a node cannot smuggle a divergent or unrecoverable `s₂` into `d_T`. **No in-circuit pairing** (the verifiable-encryption binding is a native sigma + range argument; `s₁`'s publication removes the committee-slot ciphertexts entirely). Cost ≈ 10⁴ constraints plus the VerEnc bridge openings (~0.3–1 M, AMBER); mobile-hardware benchmarking still required before any mobile deployment (OQ-3), but desktop is the PoC gate.

> **Optional high-assurance 2-of-2 form.** Under the optional profile (§4.9.4), `s₁` is *also* secret and encrypted to the `N_fallback` audit committees, so Statement 5 additionally certifies `∀ i: c_T^{(i)} = ForwardCommit(s₁, "SUSPEND epoch_id_T", threshold_BLS_pk_T^{(i)})` — one in-circuit pairing per committee slot. This is the version the Phase-0 finding below measures; it is **not** built under the adopted profile.

> **Phase-0 feasibility finding (why publish-`s₁` is adopted).** A constraint-count estimate ([SPIKE-statement5.md §8](./SPIKE-statement5.md#8-phase-0a-result--constraint-estimate-2026-06-06), `impl/spike_stmt5_constraints.py`) found the per-slot in-circuit ForwardCommit (BF-IBE-over-BLS12-381) pairing certification of the **2-of-2 form** dominates ≥99% of its constraints — ~2–13 M total, AMBER→RED on desktop and RED on mobile — because BLS12-381 pairings are non-native over Plonky3's small field. Everything else (Poseidons, even a 256-deep SMT path) is rounding error. Two restructurings remove the pairing while preserving handoff-time decryptability (the §4.9.4 dark-node-closure / row-14 property — the naïve "well-formedness only" circuit does **not** preserve it and silently breaks dark-node closure): (1) **native-group verifiable encryption** (F1, [DESIGN-f1-verifiable-encryption.md](./DESIGN-f1-verifiable-encryption.md)) — exponential-ElGamal *limb* encryption decryptable by the verdict signature, ~0.3–1 M constraints (AMBER), dominated by 1–2 non-native Pedersen "bridge" openings; (2) **publish `s₁`** (the adopted form above) — an additive share `⟂ null_v` published in clear, encrypting only `s₂`, which **dissolves this gate *and* OQ-63** at the cost of reducing the decryption lock from 2-of-2 (committee ∧ validator) to validator-only (still A2-bounded + slashable, sign-off in [DESIGN §10](./DESIGN-f1-verifiable-encryption.md#10-threat-model-sign-off-for-publish-s₁-phase-1-step-2)). The algebraic core of F1's security is machine-checked (`impl/easycrypt/`, DESIGN §9). This is the P-feasibility gate (§1.7, §10.1.1); the rest of the substrate is unaffected.

**Fallback — binary ratings:** If a formal influence bound is required before deployment, Config E (binary ratings) narrows the gap to the original DSybil assumptions, though a clean formal guarantee is not claimed — see OQ-10.

#### 4.9.6 Commit-Reveal Verdict Flow

A suspension verdict follows a two-phase commit-reveal process. Committee members lock in their decision publicly before decryption becomes possible. The flow runs against the active committee slot — `committee_T^{(0)}` by default, advancing to `committee_T^{(i+1)}` if slot i stalls past its window. The canonical specification is here; §4.9.10 summarizes the full suspension flow end-to-end.

**Adopted publish-`s₁` flow (primary).** Because `s₁` is already public (in `commit_T`) and committees hold no decryption material, the commit-reveal is over the **verdict decision only**, not over BLS decryption shares:

```
COMMIT:  each member j of the active committee publishes H(verdict ‖ nonce_j), signed.
REVEAL:  each member j opens (verdict, nonce_j), signed; validators check against the commit.
VOTE:    once ⌊K_committee/2⌋+1 matching SUSPEND reveals are on-chain, the verdict is SUSPEND
         (members attest by aggregate multisig over their VRF membership — no DKG, no threshold key).
FINALIZE (validator set, in-block, canonical, only on a SUSPEND verdict for epoch_id_T):
         σ_T^VERDICT = threshold-sign_VA("VERDICT_FINALIZED epoch_id_T")
         s₂          = VerEnc.Decrypt(d_T, σ_T^VERDICT)
         null_v      = s₁ + s₂   (mod p)        // s₁ read from commit_T (public)
DECRYPTION TX (by anyone, permissionless):
         { verdict_hash, epoch_id, null_v, dec_nullifier = Poseidon(verdict_hash, null_v),
           proof: Verify(VA_pub, "VERDICT_FINALIZED epoch_id_T", σ_T^VERDICT) ✓
                  AND VerEnc.Verify(d_T, s₂, σ_T^VERDICT) ✓
                  AND s₁ + s₂ = null_v ✓ }
         Validators insert dec_nullifier into DECRYPTION_SMT and null_v into SUSP_SMT.
```

The commit-reveal ordering property holds trivially: the committee never sees `null_v` (it has no decryption material), so the decision cannot be influenced by it, and `s₂` is released only at validator finalization. Fallback activation (below) still applies to the *verdict vote* — a stalled committee advances to the next VRF-selected slot — but no `s₁` ciphertext is opened. The detailed pseudocode that follows is the **optional high-assurance 2-of-2 profile** (§4.9.4), in which the committee additionally aggregates `σ_i^SUSPEND` to recover `s₁`; it is not built under the adopted profile.

> **Optional high-assurance 2-of-2 profile.**

```
ACTIVE SLOT (initially i = 0; advances on stall, see "Fallback activation" below):

COMMIT PHASE:
    Each member j of committee_T^{(i)} publishes to public chain:
        verdict_commit_j = {
            slot_index:           i,
            epoch_id_committee_j: <member epoch ID>,
            commit:               H(BLS_share_j ‖ verdict ‖ nonce_j),
            sig:                  Sign(epoch_id_committee_j, H(commit ‖ T ‖ i))
        }

    All K_committee commits from committee_T^{(i)} must appear before reveal phase begins.
    A verdict is invalid without all commits on-chain.
    Members cannot change their verdict after committing.

REVEAL PHASE (after all commits finalized):
    Each member j publishes:
        verdict_reveal_j = {
            slot_index:           i,
            epoch_id_committee_j: <member epoch ID>,
            bls_share_j:          <BLS secret share contribution under threshold_BLS_pk_T^{(i)}>,
            verdict:              "SUSPEND" | "PASS",
            nonce_j:              <random nonce>,
            sig:                  Sign(epoch_id_committee_j,
                                       H(bls_share_j ‖ verdict ‖ nonce_j ‖ T ‖ i))
        }

    Validators verify:
        H(bls_share_j ‖ verdict ‖ nonce_j) = commit from verdict_commit_j ✓
        BLS share is valid under threshold_BLS_pk_T^{(i)} ✓

AGGREGATION (by anyone, permissionless):
    Once ⌊K_committee/2⌋ + 1 valid reveals from slot i are on-chain:
        σ_i^SUSPEND = aggregate(bls_share_j₁, ..., bls_share_jₜ)
        s₁          = ForwardCommit.Decrypt(c_T^{(i)}, σ_i^SUSPEND)   // committee share only

    On finalization of the SUSPEND verdict block, the validator set publishes (in-block, canonical):
        σ_T^VERDICT = threshold-sign_VA("VERDICT_FINALIZED epoch_id_T")
        s₂          = ForwardCommit.Decrypt(d_T, σ_T^VERDICT)          // validator share

        null_v      = s₁ + s₂   (mod p)                                // neither share alone suffices

    Anyone submits null_v_decryption transaction:
        {
            verdict_hash:    H(committee_verdict),
            slot_index:      i,
            epoch_id:        <suspended node's last epoch_id>,
            null_v:          <recovered value>,
            dec_nullifier:   Poseidon(verdict_hash, null_v),
            proof:           Verify(threshold_BLS_pk_T^{(i)}, "SUSPEND epoch_id_T", σ_i^SUSPEND) ✓
                             AND Verify(VA_pub, "VERDICT_FINALIZED epoch_id_T", σ_T^VERDICT) ✓
                             AND ForwardCommit.Verify(c_T^{(i)}, s₁, σ_i^SUSPEND) ✓
                             AND ForwardCommit.Verify(d_T, s₂, σ_T^VERDICT) ✓
                             AND s₁ + s₂ = null_v ✓
        }

    Validators verify both checks.
    Insert dec_nullifier into DECRYPTION_SMT.
    Insert null_v into SUSP_SMT.
    Update both roots in block header.
```

**Critical ordering property:** Committee members commit to their verdict before either signature exists and before any ciphertext is decryptable. The decision is irrevocably on-chain before anyone — including the committee — can see `null_v`. The validator share `s₂` is released only at verdict finalization (`σ_T^VERDICT`), so even a committee that aggregates `σ_i^SUSPEND` early holds only `s₁` and learns nothing about `null_v` until the verdict is public. This prevents `null_v` from influencing the verdict and prevents covert extraction — now enforced cryptographically, not merely by commit-reveal ordering.

**Non-revealing member:** A committee member who commits but refuses to reveal is in violation of protocol. Consequence: non-response penalty applied to reputation; if threshold reveals from slot i are unavailable, the slot stalls and the fallback activation rule below moves the verdict to slot i+1 without aborting the suspension.

**Fallback activation.** The verdict flow runs against slot i = 0 by default. If ⌊K_committee/2⌋+1 valid reveals from `committee_T^{(0)}` are not on-chain within `W_primary` epochs of the verdict being invoked, validators automatically advance the active slot to i = 1, and `committee_T^{(1)}` is required to run its own commit-reveal against `c_T^{(1)}`. Successive fallbacks activate at `W_fallback` intervals (i ← i + 1) until either some slot completes or all N_fallback slots have been exhausted. The advance is deterministic and on-chain — no human or committee action is needed to trigger it. Whichever slot completes first yields the unique `null_v`; the DECRYPTION_SMT collision check (§4.9.3) rejects any later decryption transaction from a different slot, since `dec_nullifier = Poseidon(verdict_hash, null_v)` is identical regardless of which `c_T^{(i)}` was opened. Non-revealing members of any stalled slot receive the standard L3 Suspicious classification (§4.9.8) independent of whether the fallback ultimately succeeded.

Exhausting all N_fallback slots without completion is treated as a network-wide liveness incident: the recursive oversight chain (§4.9.8) escalates to a meta-committee selected independently of any of the original N_fallback committees.

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

**Why the chain converges — Chernoff security amplification:** The critical structural property is that each level's committee is drawn independently via VRF with cluster diversity constraints — different interest clusters at every level, and under transport profiles that preserve sub-epoch timing (Tor/I2P, §5.1) also different behavioral clusters. Given independence, if the adversarial fraction in the committee-eligible pool is q, then:

```
P(compromise at level d) = P(Bin(K_d, q) ≥ ⌊K_d/2⌋+1)
                         ≤ exp(−K_d · D(⌊K_d/2⌋+1)/K_d ‖ q))
```

by the Chernoff bound, where D is the KL divergence. This decays **exponentially** in K_d. With committee size growing linearly across levels (K_d = K_0 + d·ΔK), P(compromise_d) itself shrinks with d, giving doubly-exponential decay in depth. Cumulative escape probability is a product of independent per-level terms each strictly less than 1, so it decays exponentially in depth. Since any polynomial instance count (budget/cost) is dominated by exponential per-instance decay, a finite depth always suffices for any target success probability threshold. This closes OQ-49 as a structural question. What remains is empirical calibration of K_0 and ΔK for the target network (Phase 5 experiment 5.42). The independence guarantee is load-bearing: if committees at different levels were drawn from the same cluster, the Chernoff amplification would not apply. The eligible-pool fraction `q` itself is bounded by Assumption A2: an adversary that pushes `q` above 1/2 in the committee-eligible pool has by definition already broken the honest-majority assumption, at which point BFT consensus, the verdict process, and watchdog signals all collapse simultaneously. q-boundedness is therefore a corollary of A2, not a separate premise.

**Transport-profile dependence.** The argument's strength depends on which cluster axes are available for independence. Under the Tor/I2P profile, both interest and behavioral clusters are available (per §6.2), and the dual-cluster constraint gives the strongest independence multiplier. Under the Loopix profile, behavioral-cluster signal is too thin to provide an independent axis, and the argument reduces to interest-cluster diversity alone. To recover equivalent compromise probability under the Loopix profile, `K_d` is scaled upward to compensate for the lost independence dimension — concrete per-profile `K_0` and `ΔK` calibration is Phase 5 work (experiment 5.42, parameterized by profile).

**Stalling minority:** A minority of members in a single committee refusing to reveal stalls only that slot's verdict — control passes to the next fallback slot per §4.9.6 without aborting the suspension. Stalling the suspension entirely requires a colluding minority in *every* one of the N_fallback committees, whose joint probability under Assumption A2 decays exponentially in N_fallback (disjoint membership across committees rules out a single coalition appearing in multiple slots). Non-revealing members in any slot receive the L3 Suspicious classification regardless of whether a fallback slot ultimately completed.

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
Active slot i ← 0  (primary committee_T^{(0)})
    │
    ▼
Commit phase (slot i):
    All K_committee members of committee_T^{(i)} publish verdict_commit_j on public chain
    Decision locked — visible to entire network
    │
    ▼
Reveal phase (slot i):
    All K_committee members publish verdict_reveal_j on public chain
    BLS shares publicly verifiable under threshold_BLS_pk_T^{(i)}
    │
    ▼
Quorum reached within window?  ──── NO ────▶ i ← i + 1   (advance to next fallback)
    │                                            │
    │                                            ├─▶ if i < N_fallback : restart commit phase against committee_T^{(i)}
    │                                            └─▶ else : escalate to recursive oversight (§4.9.8)
    │ YES
    ▼
Aggregation (by anyone):
    σ_i    = aggregate BLS shares from slot i
    null_v = ForwardCommit.Decrypt(c_T^{(i)}, σ_i)
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

PrivaCF defines a **transport interface** rather than mandating a specific transport. Each deployment selects a transport profile that satisfies the required properties below; properties marked optional vary across profiles. Instances do not federate across profiles — a deployment running the Loopix profile and one running the Tor/I2P profile are separate networks with separate Sybil pools.

**Required transport properties** (any conformant profile must satisfy):

- **IP↔epoch_id unlinkability.** A network-level observer cannot link a client's real IP to its rotating `epoch_id_T` identities.
- **Message integrity and authentication.** Tampering with a message in transit is detectable by the recipient.
- **Replay protection.** A captured message cannot be successfully replayed against the protocol.
- **Activity cover.** No external observer can distinguish a node's active-send periods from idle periods at finer than epoch granularity, when the node is online.

**Optional transport properties** (profile-dependent):

- **Per-hop timing decorrelation.** Sub-epoch send times are unobservable by external observers.
- **Fixed-size packets.** Packet sizes are uniform and content-independent, eliminating traffic-size analysis.
- **GPA (global passive adversary) resistance.** Formal anonymity holds against an adversary observing the entire wire.

#### Reference profile (default for MVP): self-mixing Loopix

Loopix/Sphinx mixnet (Piotrowska et al., USENIX Security 2017) provided by PrivaCF nodes themselves — the mix layer is not an external dependency. All required and all optional transport properties are satisfied. Every unicast message — PSI handshakes, audit responses, verdict commits, gossip vector pushes — is sent as a Sphinx-onion-encrypted packet through a sequence of PrivaCF mix-role nodes, each applying a Poisson-distributed per-hop delay. No mix node learns more than the next hop. Sender, receiver, and relationship anonymity are formally analyzed under the Loopix model. See §5.1.1 for the mix-role / client-role split that makes self-mixing possible.

**Loop and drop cover traffic** is the mechanism that satisfies the activity-cover requirement under this profile. Every mix-capable node emits traffic at a constant Poisson rate regardless of real activity — loop covers (messages to self via the mix) and drop covers (discarded at destination). Cover traffic calibration (§5.8) sets the base Poisson rate; the formal anonymity guarantee holds under this constant-rate assumption.

**Single-Use Reply Blocks (SURBs):** All request-response exchanges (PSI handshakes, audit requests) include a pre-built SURB so the responder can reply anonymously without knowing the requester's mix path.

**Dandelion++** (Fanti et al., SIGMETRICS 2018) is retained for the epidemic broadcast (fluff) phase of gossip propagation, where Loopix's point-to-point model does not apply. Stem phase: random linear relay (p ≈ 0.9 to continue). Fluff phase: epidemic broadcast.

Provider role (the publicly-reachable mix-role node that buffers inbound messages for a client) sidesteps NAT traversal for home nodes — no inbound connection is required from the client. Katzenpost remains a viable reference implementation of the mix-node software, integrated into PrivaCF's node binary rather than running as a separate external network.

#### Alternate profile: Tor/I2P

Tor (onion routing) or I2P (garlic routing) provides the required transport properties only. IP↔epoch_id unlinkability, integrity, authentication, and replay protection are inherited from the underlying transport. **Activity cover** is satisfied by a protocol-mandated low-rate Poisson cover-packet stream emitted over the Tor/I2P transport — without this shim the profile is non-conformant. Optional properties (timing decorrelation, fixed-size packets, GPA resistance) are not provided by this profile; users with stronger threat models layer their own OPSEC (additional VPN hops, dedicated routing infrastructure).

Selection of this profile trades the Loopix profile's GPA resistance for stronger sub-epoch behavioral signals available to the Sybil-detection machinery (§6.2, §7.1a). The behavioral-cluster computation in §6.2 and the dual-cluster Chernoff argument in §4.9.8 hold their original form under this profile.

#### Clearnet profile

Development and testing only. Does not satisfy any of the required transport properties. Production deployments must select Loopix or Tor/I2P.

**Retry on failure:** Timeout-only across all profiles. After `k_retry` failures, fall back to direct broadcast.

#### 5.1.1 Mix-role / Client-role split (self-mixing Loopix profile)

Self-mixing requires the mix layer to be implemented by PrivaCF nodes themselves. Each node may operate in two protocol-unlinkable roles on the same machine:

**Mix-role identity.** A long-lived router identity, IP-bound and publicly advertised in a RouterInfo-style record. Used for forwarding others' Sphinx-encrypted traffic. Only a subset of nodes opt into the mix role — uptime and bandwidth requirements rule out most mobile or intermittent clients. Mix-role identities do not rotate per epoch; they persist as long as the node continues advertising as a mix.

**Client-role identity.** The epoch-rotated `epoch_id_T` defined in §4.2, used for PrivaCF protocol participation (gossip, PSI, audits, handoffs). Rotates every epoch and is unlinkable across epochs without `sk`.

The two roles share a machine but are protocol-unlinkable: the mix-role identity is IP-bound and public; the client-role identity is mix-routed and pseudonymous. An observer who knows a node's mix-role IP cannot determine which client identity it operates, and vice versa.

**Provider role.** A further-restricted subset of mix-role nodes that are publicly reachable and offer message buffering for offline or NAT'd clients. Providers must satisfy stricter availability requirements than ordinary mix-role nodes.

**Circular dependency note.** Mix-layer Sybil resistance is bounded by Assumption A2 (honest majority by weight). Because mix nodes are themselves PrivaCF participants, the protocol's Sybil-resistance machinery is what keeps the adversarial fraction in the mix-eligible pool below the threshold required for Loopix anonymity. Conversely, mix anonymity is what enables much of the protocol's privacy machinery. The two are mutually load-bearing under A2; failure of either collapses the other.

**Bootstrapping the initial mix set (deployment concern, not protocol).** Until enough PrivaCF participants have built temporal depth to satisfy A2 in the mix-eligible pool, the circular dependency above cannot self-stabilize. This is a one-shot deployment problem rather than a protocol problem and is out of scope for the protocol spec, but worth recording:

- **Externally trusted initial mix set.** The deployment publishes a small initial mix set drawn from operators whose identity, accountability, and uptime are externally verifiable — for example, a published consortium of known infrastructure operators, university CS departments, or existing privacy-network operators (Tor, Nym, Mixmaster legacy). The set is documented and verifiable out of band; mix anonymity during bootstrap is conditional on the consortium's honesty.
- **Transition criterion.** The deployment publishes a transition criterion — an A2-equivalent measurable condition over the organically-grown mix-eligible pool — at which the externally trusted set's privileged status sunsets and selection becomes purely protocol-internal.
- **Honest bootstrap framing.** Until the transition criterion is met, the Loopix anonymity guarantee for the deployment is **conditional** on the bootstrap consortium and should be advertised that way. This is no worse than how Tor's and Nym's mix anonymity bootstraps in practice — both rely on a real set of operators whose honesty is externally evaluated — but PrivaCF should be explicit about the bootstrap dependency rather than treating A2 as self-evidently satisfied at deploy time.

The protocol itself makes no assumption about how the initial set is chosen; this paragraph is a deployment recommendation, not a normative protocol requirement.

### 5.2 Uniform Message Frames

Sphinx packets are fixed-size by construction — payload length is padded to a fixed maximum at the sender before onion encryption. An observer on the wire sees fixed-size encrypted blobs and cannot distinguish message types or read contents. A gossip vector push, a Class 3 audit response, a `verdict_commit`, and a Loopix loop or drop cover are indistinguishable on the wire. Frame size estimated 4–8 KB (OQ-30).

Noise Protocol sessions are retained only for any direct connections used in development and clearnet testing; they are redundant for mix-routed production traffic where Sphinx provides per-hop encryption.

**Note on audit response timing:** Because Loopix's per-hop Poisson delay dominates response latency and node processing time is negligible relative to mix routing delay, audit response timing is not a usable detection signal. Audit response _rate_ (fraction of challenges responded to) remains a meaningful signal and is captured in §6.2.

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

PEER DISCOVERY (ongoing, each epoch)
─────────────────────────────────────────────────────────
    │
    ├── after epoch rotation: ZK continuity proof submitted?
    │       YES: committee attests continuity to existing peers
    │            update PSI cache with λ_proof decay
    │            skip re-discovery for confirmed peers
    │       NO:  proceed to candidate selection below
    │
    ├── candidate pool ←  random DHT draws (bridge tier)
    │                  +  referrals queued from prior epoch's
    │                     failed PSI, filtered by local MinHash
    │                     estimate; skip if in visited_set_T
    │                     or hop_count = 0
    │
    ├── run up to n_discovery PSI attempts in parallel
    │
    │       on PASS (similarity ≥ θ_cluster):
    │           add to PSI peer set
    │
    │       on FAIL:
    │           responder optionally attaches referral list:
    │               { epoch_id, minhash_signature, hop_count }
    │           initiator queues referrals for next epoch
    │
    └── bridge peer: refresh from random DHT each epoch

INCOMING PSI RATE LIMIT
─────────────────────────────────────────────────────────
    if incoming_psi_count(T) > n_psi_in:
        drop excess requests silently
        // no reputation penalty — absence of psi_ack is
        // indistinguishable from network delay at the initiator
```

### 5.4 Peer Selection — Gossip-Driven Discovery + Asymmetric PSI

Peer selection is a three-step process. Direct chain queries bootstrap discovery; gossipped referrals extend it organically across the network; PSI confirms genuine similarity.

**Step 1 — LSH chain query (bootstrap)**

When a node registers its `epoch_id` on the public chain, it also publishes a MinHash signature computed over its announced items. MinHash approximates Jaccard similarity: for two item sets A and B, each MinHash function returns the same value with probability `|A∩B| / |A∪B|`. Using k hash functions partitioned into b bands, two nodes sharing at least one full band are likely candidates.

A node bootstrapping its peer set queries the chain for `epoch_id`s in the same LSH band. This is a one-time or post-rotation lookup; steady-state discovery is handled by the referral mechanism below.

**Step 2 — Gossip referrals**

On a failed PSI (similarity below θ_cluster), the responder optionally attaches a referral list to the response:

```
referral = { epoch_id, minhash_signature, hop_count }
```

`minhash_signature` is the referred node's published chain value — no new private data is shared. The initiator estimates local Jaccard against its own MinHash before queuing the referral, discarding clearly non-similar candidates before spending a full PSI run. Loop prevention: skip any `epoch_id` already in `visited_set_T`; decrement and discard at `hop_count = 0`.

Over epochs, this creates organic convergence — similar nodes find each other transitively without central coordination and without formal cluster registration.

**Step 3 — PSI confirmation (Pinkas, Rosulek, Trieu & Yanai, USENIX Security 2018)**

Full asymmetric PSI is run against each candidate, using the node's complete private item set. If similarity ≥ θ_cluster the candidate joins the PSI peer set. The handshake is Loopix mix-routed (Appendix I). The responder issues a signed `psi_ack` on receipt regardless of outcome; the initiator retains it as a ZK witness for cross-cluster attempt rate.

**Rate limiting and overload**

`n_discovery` bounds parallel outgoing PSI attempts per epoch. It is conservative by default and should be calibrated against network size, observed bandwidth, and latency (OQ-23). A node that receives more than `n_psi_in` incoming PSI requests in an epoch drops excess silently — no reputation penalty applies, as absent `psi_ack` is indistinguishable from mix routing delay at the initiator. Both parameters should be set conservatively until empirical data from Phase 2 deployment informs tighter bounds; over-aggressive discovery degrades into a DoS vector against well-connected nodes.

**Privacy properties**

MinHash publication leaks only approximate similarity over already-public announced items. Referrals redistribute already-public chain data. PSI operates on the full private item set with strong cryptographic guarantees: neither party learns the other's non-overlapping items. The responder does not learn the initiator's identity (Loopix) so sharing a referral list carries no additional risk to the responder.

`θ_cluster` is community-type dependent; starting range: 0.1–0.3 (OQ-23).

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
PSI peer tier:  n_peers · Jaccard PSI confirmed · grown organically via gossip referrals · persistent via ZK continuity
Bridge tier:    1 peer  · random DHT · refreshed each epoch
```

Cluster-specific behavior activates only when `|peers_v| ≥ k_min` (§7.4). During peer discovery, a node below k_min operates on global trust_total only until its PSI neighborhood reaches the minimum size.

Trust attenuation by hop distance (Stannat et al. 2021):

```
cf_weight(vector_from_u) = base_weight × μ^hop_distance(v, u)
```

This attenuation is one of the primary defenses against remote Sybil influence: a node many hops away can contribute at most `μ^k` of base weight regardless of reputation. μ calibration required empirically (OQ-21).

**Note on bridge peer opt-out:** A user whose interest cluster attracts no sybil attention and who wishes to eliminate bridge-tier sybil influence entirely may set their bridge peer weight to zero. This reduces expected sybil influence on their recommendations to zero (for the cluster tier) at the cost of losing cross-cluster discovery signal. See §7.1b for the formal decomposition. This is a per-node local setting and requires no protocol changes.

### 5.8 Communication Rhythm

| Signal                                 | Trigger                                                 | Rate limit                                                      | Routing                              |
| -------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------ |
| Gossip vector push                     | T_send = epoch_start + offset + Uniform(0, 0.3 × epoch) | 1 per epoch (hard)                                              | Loopix mix path                      |
| Item announcement (mainstream)         | Positive interaction + random delay                     | ~20/epoch                                                       | Dandelion++ stem → fluff broadcast   |
| Item announcement (niche)              | Positive interaction + VRF-derived epoch delay          | Per item                                                        | Dandelion++ stem → fluff broadcast   |
| Receipt                                | Epoch end (batched)                                     | 1 batch per epoch                                               | Loopix mix path                      |
| Rewind signal                          | q_v(T) drop correlated with recent gossip cohort        | 1 per epoch per node; max 1 Class 3 trigger per N_rewind epochs | Dandelion++ stem → fluff broadcast   |
| On-chain transaction (M_v, C_p, score) | Every n_commit epochs via relay                         | 1 per n_commit epochs                                           | Via relay node                       |
| commit_T + ZK proof                    | Every epoch via relay                                   | 1 per epoch                                                     | Via relay node                       |
| verdict_commit                         | Commit phase of suspension                              | 1 per committee member per verdict                              | Loopix mix path                      |
| verdict_reveal                         | Reveal phase of suspension                              | 1 per committee member per verdict                              | Loopix mix path                      |
| null_v_decryption                      | After threshold reveals available                       | Permissionless                                                  | Direct to chain                      |
| watchdog_signal                        | Anomalous verdict_commit rate                           | 1 per epoch per node                                            | Dandelion++ stem → fluff broadcast   |
| Auditor handoff                        | Epoch end                                               | 1 per epoch                                                     | Loopix mix path to committee         |
| ZK continuity proof                    | Epoch transition (voluntary)                            | 1 per epoch                                                     | Arbitration committee only                 |
| Loop/drop cover traffic                | Constant (Poisson)                                      | Base Poisson rate λ — calibrated per OQ-58                      | Loopix native (loop and drop covers) |

---

## 6. Reputation and Audit

### 6.1 Per-Epoch Score

```
score_v(T) = w₁ × audit_response_rate(T)
           + w₂ × gossip_validity_rate(T)
           + w₃ × rate_limit_compliance(T)
           + w₄ × cluster_endorsement(T)
           + w₅ × (1 − rewind_signal_rate(T))
           + w_validator × validator_service_indicator(T)
           + w_relay × relay_service_indicator(T)

consistency_v(T) = clamp(1 − Var(score_v(T−k_rep), ..., score_v(T)) / σ²_max,  0, 1)
reputation_v(T)  = α × score_v(T) + (1−α) × consistency_v(T)
```

- `k_rep` is the rolling window length in epochs over which score variance is measured. A node with fewer than `k_rep` completed epochs uses however many epochs are available. Calibration target: long enough to distinguish genuine volatility from noise, short enough to be responsive to behavioral change (OQ-9).
- `σ²_max` is the maximum score variance expected from an honest, fully-active node over `k_rep` epochs under normal network conditions. It serves as a normalization constant: a node with variance at or above `σ²_max` gets consistency = 0; a node with zero variance gets consistency = 1. `σ²_max` is set empirically from honest-node simulation (OQ-9). The clamp prevents consistency from going negative when variance exceeds `σ²_max`, which can happen for nodes with erratic but not necessarily malicious behavior.
- `α` is the blend weight between current score and historical consistency. Both `α` and the `α` in §7.3 are distinct — §7.3's `α` has been renamed `f_cap` to avoid ambiguity.

**Slow reputation decay** applies universally each epoch:

```
reputation_v(T) = reputation_v(T) − δ_decay
```

Weights w₁–w₅, δ_decay, and α require empirical calibration. The interactions between score components under adversarial conditions have not been formally analyzed and warrant empirical investigation (OQ-9).

Raw scores are held by the arbitration committee under threshold custody. The public chain receives only the committee-attested score band (1–4) with fuzzy boundaries, rate-limited to one change per N_band epochs.

`cluster_endorsement(v, T)` is defined as:

```
cluster_endorsement(v, T) = |{ p ∈ peers_v : p pulled from v in T }| / |peers_v|
```

Excluded (not zeroed) for nodes with `|peers_v| < k_min`: the w₄ term is omitted from the score computation and the remaining weights are renormalized to sum to the same total. This matches the k-anonymity gate of §7.4 — a node activates cluster-specific behavior (`cluster_endorsement` scoring and cluster-weighted `trust_total`) only once its PSI neighborhood reaches `k_min` — and serves two purposes at once: it avoids penalizing nodes that have not yet grown a neighborhood, and it blocks micro-cluster targeting, where an attacker assembles a tiny, highly specific peer set around a victim to manufacture an endorsement signal. Below `k_min` peers the node is scored on the global terms only.

### 6.2 Behavioral Cluster Computation

Behavioral clusters are derived from public chain timing data by a deterministic, publicly-recomputable procedure (the centroid lifecycle below). The *fingerprint* is derived from public chain data — per §8.1 it is observable to others, an accepted persistent-identifier limitation, not a secret — and the *partition* into clusters is its canonical, publicly-recomputable result. The available fingerprint depends on the active transport profile (§5.1):

**Tor/I2P profile — full fingerprint:**

```
behavioral_fingerprint_v(T) = {
    activity_window:        which parts of the epoch the node is typically active
    announcement_timing:    distribution of delays between interaction and announcement
    transaction_timing:     when within the epoch the on-chain entry is published
    audit_response_rate:    fraction of audit challenges responded to
}
```

**Loopix profile — thin fingerprint:**

```
behavioral_fingerprint_v(T) = {
    epoch_presence:         did the node publish in epoch T (binary or rate over recent epochs)
    audit_response_rate:    fraction of audit challenges responded to
}
```

Sub-epoch timing components are unavailable under the Loopix profile because the mix layer destroys them by design. Epoch-granular presence and audit-response rate survive because they are counts/rates rather than timestamps. Under the Loopix profile, the content-based PSI-similarity flagging in §7.4 carries proportionally more weight, since timing-based detection is degraded.

**Canonical clustering — the centroid lifecycle.** Because every input is public, the partition itself is fixed by a deterministic algorithm rather than left to each node's discretion. The procedure:

```
INPUTS (all public / fixed):
    population        = node epoch_ids with an epoch_transaction this cluster-window
    F_v               = behavioral_fingerprint_v normalized by a fixed, published
                        preprocessing (per-feature standardization over the population)
    k_cluster         = fixed cluster count (parameter; Phase-5 calibrated)
    seed              = beacon_{T}            // beacon-seeded k-means++ initialization
    I                 = fixed iteration budget

ALGORITHM:
    centroids, labels = kmeans(F, k_cluster, init = kmeans++(seed), iters = I)
    cluster IDs canonicalized by sorting centroids lexicographically   // stable across
                                                                       // epochs; k-means
                                                                       // labels are otherwise
                                                                       // permutation-arbitrary
```

Because `k_cluster`, `I`, the seed, the preprocessing, and the population's fingerprints are all public and fixed, the centroids and per-node labels are a **deterministic function of public chain data** — anyone can recompute and verify them. This is what backs the "diversity axis checked on the public chain" usage (§1.3, §4.1, §4.9.8): the label is canonical and unforgeable, so a node cannot misreport its cluster to dodge or satisfy a diversity constraint.

**Publication and accountability (committee-published, recompute-checkable).** Recomputing k-means over the whole population every epoch is wasteful, so the **arbitration committee** computes and publishes the signed centroid set and per-node label commitments on chain every `n_cluster` epochs (default `n_cluster` ≈ a small multiple of `n_commit`; behavioral fingerprints drift slowly — Phase-5 calibrated). Steady-state verification just reads the published set. But the published set is **not trusted blindly**: because the algorithm above is deterministic over public data, any node can recompute it and submit a **fraud proof** on mismatch, and the committee is slashable for an incorrect publish (gerrymandering centroids to force targets into one cluster is therefore detectable and penalized). If the committee fails to publish, validators fall back to recomputing the partition themselves — liveness does not depend on the publish.

**Two consumption modes, one partition.** The label produced above feeds two uses that previously appeared to need different authorities; both now anchor on the *same* published centroids:
- *Public diversity axis* (committee / validator / relay selection): the on-chain label is checked directly and is recompute-verifiable. No ZK is needed — the partition is public by construction.
- *Private diversity predicate* (e.g. the §7.1b PSI-ack self-dealing defense, where a node must prove a **hidden** responder set spans distinct clusters): the committee's BBS+ signature over a node's canonical label lets it prove the set is cluster-diverse in zero knowledge **without revealing which counterparties they are** (OQ-11 path 1) — here the ZK hides the linkage to specific identities, not the cluster values, which are public; equivalently a node self-proves its own label against the published public centroids via ZK k-means (OQ-11 path 2). The committee here is a *signer of the deterministic label*, not an independent authority over it.

This reconciles "computed locally" with "attested on chain": the fingerprint is publicly derived, the cluster *label* is the deterministic public result of the procedure above, and the on-chain attestation is a signature over that same value — the two descriptions are one quantity at two stages, not two competing computations.

Behavioral clusters have two roles: (1) input to the compound flag system (§7.8), and (2) under the Tor/I2P profile, a structural diversity axis for auditor committee selection (see below) and for validator/relay diversity constraints where invoked. They are never used for direct reputational effects — no node's per-epoch score is increased or decreased by its behavioral-cluster membership. Under the Loopix profile the fingerprint is only two coarse features, so the partition is weak and is **not** used as the primary diversity axis (§4.9.8, §6.3 substitute the mix-layer AS/density axis); the lifecycle still runs, but its output feeds only the compound flag system, consistent with the "calibrated, not proven" Loopix caveat below.

**Auditor independence requirement is transport-conditioned.** Under the Tor/I2P profile, an auditor committee must have members from different interest clusters AND different behavioral clusters (the dual-cluster constraint). Under the Loopix profile, behavioral-cluster signal is too thin to act as an independent diversity axis. The constraint then reduces to interest-cluster diversity, recovered along two paths: (1) the **mix-layer AS/density signals of §6.3 take over as the second structural independence axis** — they survive under Loopix precisely because PrivaCF operates its own mix layer, so the lost behavioral axis is swapped for an AS-diversity axis rather than simply dropped; and (2) a larger committee. Note that the §4.9.8 Chernoff bound governs how committee size trades against compromise probability for a *given* adversarial fraction `q`; it does **not** by itself model the loss of a diversity axis. Dropping the behavioral axis raises the effective `q` an adversary can reach by concentrating within a single behavioral cluster (the §8.2 T6 timezone-clustering effect working for the adversary), and the committee-size multiplier needed to offset that increase is an open calibration, not a derived result — it is the subject of Phase 5 experiment 5.49. Until 5.49 resolves, the interest-cluster-only auditor guarantee under Loopix is **calibrated, not proven**.

### 6.3 Admission and First-Observation Interrogation

**The admission window (n epochs):** Zero CF weight, zero routing weight. VDF proof published each epoch. Interaction checkpoints at VRF-determined epochs require real network contact.

**First-observation reports:** When a new `epoch_id` first appears on-chain, VRF-selected existing nodes submit signed first-observation reports to the arbitration committee only.

**Cross-node temporal burst aggregation:** The committee aggregates `first_seen_T` and `first_seen_offset` values from first-observation reports across admission windows, computing a burst score over inter-arrival timing distributions. This detects the temporal clustering patterns described in §7.1a T.1 and T.9. The burst score enters the compound flag system at L1 only — no standalone escalation. VRF-determined checkpoint epochs are publicly verifiable after beacon publication, making checkpoint synchrony (T.9) independently verifiable from public chain data by any participant. Threshold calibration (burst window W, burst_score ceiling) is addressed in Phase 5 experiment 5.48 (OQ-59).

**Provider identity in first-observation reports:** First-observation reports include `provider_id`, encoding the mix-role provider node the new client connected through and providing a coarse geographic prior. The committee aggregates provider_id distributions per admission window. Geographic concentration (§7.1a T.3) enters the compound flag system at L1 only, contributing to escalation solely when combined with temporal burst and behavioral synchrony. It is never a standalone signal. Under the Tor/I2P profile this signal degrades because `provider_id` reduces to the Tor exit identity, which is shared across many clients.

**Mix-network density signals (self-mixing Loopix profile).** Because the mix layer is operated by PrivaCF nodes themselves (§5.1.1), the protocol can observe aggregate signals at the mix layer that are unavailable when relying on an external mixnet:

- **Mix node AS-density per epoch:** how many mix-role nodes are advertised from each AS or hosting provider. Sudden concentration in a single AS is a Sybil indicator on the mix layer.
- **Mix node admission timing correlation:** synchronized appearance of new mix-role identities, analogous to T.1 at the client layer.
- **Mix node churn rate per AS:** anomalously high churn from a specific AS suggests disposable mix infrastructure.
- **SUSPEND↔mix-disappearance correlation:** a mix-role node going offline in the same epoch a client `epoch_id` from its AS is suspended is weak but accumulable evidence of co-location.

These signals do not link to specific client `epoch_id`s — they observe the mix layer as a first-party substrate. They catch a Sybil cluster that must operate mix-capable nodes to participate at scale, complementing the per-client `provider_id` mechanism. Aggregate signals feed the compound flag system at L1 only. Under the Tor/I2P profile, mix-layer signals are not available because PrivaCF does not operate the mix layer.

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
        RATE_LIMIT:      n_rl    // cardinality of announcement_token_set(T)
    },
    SUSP_SMT_root_T,
    commit_T = ( s₁, d_T ),                  // ADOPTED publish-s₁: s₁ public, d_T encrypts s₂ to VA_pub
                                             // (2-of-2 profile instead: ( c_T^{(0..N_fallback−1)}, d_T ))
    VA_pub,                                  // (2-of-2 profile also carries threshold_BLS_pk_T^{(0..N_fallback−1)})
    ZK proof that:
        C_p(T) is a valid successor to C_p(T-1)
        M_v(T) is a valid successor to M_v(T-1)
        ||p_v(T) - p_v(T-1)||₁ ≤ Δ              (Statement 3)
        leaf_counts are consistent with M_v(T)
        token_v(T) correctly incorporated if token was issued this epoch
        null_v ∉ SUSP_SMT_root_T                 (Statement 5, line 3)
        s₁ + s₂ = null_v   (s₁ a public input)   (Statement 5, split)
        d_T = VerEnc(s₂, "VERDICT_FINALIZED epoch_id_T", VA_pub; r_commit_d_T)            (Statement 5)
        // 2-of-2 profile additionally: ∀ i : c_T^{(i)} = ForwardCommit(s₁, "SUSPEND epoch_id_T",
        //                                              threshold_BLS_pk_T^{(i)}; r_commit_T^{(i)})
    rolling_chain_commitment: Poseidon(
        rolling_chain_commitment(T-1),
        zk_continuity_proof(T),
        audit_interactions(T),
        SUSP_SMT_root_T
    ),
    zk_continuity_proof:  <verified by committee at handoff; not published>,
    encrypted_shares: [
        Encrypt(pk_committee_i, shamir_share_i(snapshot_v(T))),
        Encrypt(pk_committee_i, shamir_share_i(peer_receipts_v(T)))
    ]
    // Per §4.1: shares are held by the on-demand arbitration committee.
    // peer_receipts_v(T) is retained as Shamir-shared encrypted state, reconstructable only when a Class 3 audit against a historical M_v(T') root is requested.
    // Eliminates per-node local receipt retention beyond one epoch (OQ-36 resolved).
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
│  B ──[Merkle proof + ZK proof (Stmts 1–3, 5)            │
│        + Sign(epoch_id, H(proofs ‖ nonce ‖ T))]───► C_i │
│     via Dandelion++ stem WITH timeout retry               │
│                                                           │
│  Committee cross-checks against handoff snapshots        │
│  Contacts attestation issuers for peer-attested leaves   │
│  Threshold BLS signature on result                       │
│  Result + node's signed proof published on chain         │
└──────────────────────────────────────────────────────────┘
```

**Passive witness verifiability.** The Class 3 audit result transaction (see transaction format below) includes the node's submitted ZK proof, Merkle proof, and the node's own signature over those materials together with the challenge nonce. The proof's public inputs — `M_v(T')` roots for the challenged epochs — are already on the public chain. Because the proof is zero-knowledge, publishing it reveals nothing about the node's behavioral data. Any observer can independently verify the proof against the on-chain commitments without access to any secret.

The node's signature binds the published proof to the specific challenge instance via the `audit_nonce`, preventing the committee from substituting a proof from a different audit or fabricating a failing proof on the node's behalf. This makes the four outcome cases unambiguously checkable by any passive witness:

- **No response:** no proof or node signature on-chain; trivially verifiable.
- **Proof fails, node signature matches:** node submitted this proof; it does not verify; committee verdict is correct.
- **Proof passes, node signature matches, committee said fail:** committee verdict is demonstrably inconsistent with the cryptographic evidence — machine-checkable grounds for watchdog signals and recursive oversight (§4.9.8) to escalate.
- **Proof on-chain but node signature does not match:** committee substituted a different proof than what the node submitted; itself a slashable offense.

Validators must reject a Class 3 audit result transaction that omits `merkle_proof`, `zk_proof`, or `node_sig` when `result = fail` — a bare committee signature on a failure verdict is not sufficient.

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

**Rewind signals as item-level velocity proxy:** Rewind signals whose `cohort_epoch` timestamps cluster around a specific item's rapid `trust_total` rise are a compound signal of coordinated pushing (§7.1a T.8). No new machinery is required — the existing rewind signal mechanism surfaces this connection. When rewind signals from nodes in multiple interest clusters share the same `cohort_epoch` and that epoch coincides with anomalous `trust_total` velocity for a specific item, this enters the compound flag system as a correlated L3 signal. The novelty-kill sabotage vector (§7.3, §7.9 row 9) — a push of a niche item to suppress its novelty bonus where the item may genuinely match attacker taste — does not generate rewind signals from outside the cluster; it is instead separated by the neighbourhood-coherence signal (§7.3), which lifts row 9 from O to PARTIAL (the mimic residual falling to §7.1a timing and §4.3 admission cost), characterized in Phase 5 experiment 5.47.

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

The taxonomy below names the attacker archetypes informally; §7.1a characterizes observable behavioral properties of sybil attacks grounded in the empirical literature; §7.1b provides the influence model that connects those properties to quantifiable bounds; §7.9 formalizes the full (tactic × identity-strategy) space and states the detection contract per cell.

| Attack type             | What it does                                   | Primary defense                                                                | Residual risk                                      |
| ----------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------- |
| Random push             | Inflates trust_total with random announcements | DSybil non-overwhelming rule                                                   | CF noise                                           |
| Bandwagon               | Copies honest vectors then pushes target items | k_min + ε-DP impact bounding (§7.4); weight caps (§7.6)                        | Hard if very patient; impact bounded not detected  |
| Segment                 | Targets specific interest cluster              | Per-cluster reputation                                                         | Cluster-level degradation                          |
| Coordinated campaign    | Multi-item narrative across clusters           | Behavioral clustering, compound flags                                          | Operator classification required                   |
| Sleeper                 | Builds reputation before activating            | Smoothness detection, handoff chain, asymmetric penalty                        | Hardest to detect                                  |
| Epoch rotator (same sk) | Evades SUSPENDED verdict by rotating epoch ID  | Nullifier mechanism — cryptographically impossible from same sk                | None for same sk                                   |
| Epoch rotator (new sk)  | Re-admits with fresh key after suspension      | Admission cost, behavioral fingerprinting                                      | Sophisticated adversary varying patterns           |
| Dark node rotator       | Goes dark before null_v extraction             | ForwardCommit — committee decrypts without node cooperation                    | Admission window gap only                          |
| Rogue committee         | Mass null_v extraction without verdicts        | Commit-reveal ordering — visible before any null_v recovered; watchdog signals | Threshold collusion (same as consensus assumption) |

---

### 7.1a Behavioral Taxonomy of Sybil Attacks

This section characterizes observable properties that sybil attacks exhibit in practice, grounded in the empirical literature. These are not guarantees of detection — they are signals that sybil nodes tend to produce and that a detection system can exploit. Each property is stated as a tendency, not a certainty, because sophisticated adversaries can suppress individual signals at increasing cost.

The taxonomy is organized by the observable dimension rather than by attack type, since the same attack may exhibit multiple properties simultaneously and the compound of signals is more informative than any single one.

#### T.1 Temporal clustering on join

Sybil campaigns tend to produce bursts of identity creation within narrow time windows. This is reported consistently across OSN bot detection (Stringhini et al., ACSAC 2010; Yang et al., WWW 2014), review fraud (Mukherjee et al., WWW 2013), and DHT sybil studies (Urdaneta et al., ACM Computing Surveys 2011). The signal persists even as adversaries improve on other behavioral dimensions — Yang et al.'s successive spambot generations each showed temporal clustering despite improvements in content diversity and timing randomization of individual actions.

In PrivaCF's setting this manifests as a burst of epoch_id registrations and VDF proof submissions appearing on-chain within a narrow window, with first_seen_T values clustering tightly in first-observation reports. The committee aggregates these across admission windows as described in §6.3.

Suppression cost: low for a single campaign. An adversary who staggers identity creation across many epochs defeats this signal entirely. The cost is time, not resources — staggering admissions is free but slow, and each additional epoch of staggering is an epoch during which the identities are not yet usable.

#### T.2 Temporal clustering on action

Distinct from join timing. Coordinated campaigns show correlated action timing — announcements, rating submissions, protocol interactions — even when content is deliberately diversified. This is one of the most robust signals across the empirical literature: Yang et al. found it survived all three generations of spambot evolution, and Varol et al. (ICWSM 2017) found action timing among the top predictors of bot status across six bot categories.

In PrivaCF's setting this manifests as correlated announcement timing, gossip vector push timing, and on-chain transaction timing across a set of nodes, observable through behavioral cluster computation from public chain data (§6.2).

Suppression cost: moderate. Introducing timing randomization requires active coordination across the sybil set and degrades the efficiency of coordinated campaigns — nodes that randomize timing independently lose synchrony with each other, which undermines the campaign's aggregate effect.

#### T.3 Geographic concentration

Sybil campaigns tend to originate from a small number of geographic regions, reflecting the operational infrastructure of the attacker. This is a weak standalone signal — Stringhini et al. found it insufficient alone — but a strong compound signal that significantly improves detection precision when combined with temporal clustering and behavioral similarity.

In PrivaCF's setting geographic signal is degraded by the transport profile's IP hiding (Loopix profile destroys it entirely; Tor/I2P profile collapses it to the Tor exit). A meaningful fraction of legitimate users will also use additional VPN layers given the protocol's privacy focus. Provider identity — observable at admission through the mix-role provider node the new client connects through, under the self-mixing Loopix profile — gives a coarse regional prior that is weaker than IP but costs nothing to observe. It is recorded in first-observation reports and aggregated by the committee as described in §6.3. Under the Tor/I2P profile the provider_id signal degrades because the apparent provider is a Tor exit shared across many clients.

Suppression cost: trivial. A VPN or Tor exit node defeats IP-based geographic correlation entirely. Provider identity survives VPN use unless the adversary also routes their provider connection through an anonymity network, which is possible but adds operational friction.

#### T.4 Behavioral similarity within the sybil set

Sybil nodes in coordinated campaigns show higher pairwise cosine similarity in their behavior vectors than legitimate nodes in the same interest cluster. Cao et al. (IMC 2012) found that pairwise similarity distributions of sybil clusters have lower variance and higher mean than legitimate clusters — the sybil distribution is tighter around a high similarity value. This reflects the difficulty of generating genuinely idiosyncratic behavior programmatically: human taste is idiosyncratic in ways that scripted behavior is not.

In PrivaCF's setting the behavioral coherence requirement constrains attacker effectiveness: a Sybil farm that randomizes behavior enough to avoid detection also degrades the coordinated signal it is trying to inject. Impact is bounded structurally via k_min, ε-DP, and weight caps (§7.4, §7.6) rather than by detection. Anomalously similar behavioral fingerprints across nodes in the same behavioral cluster remain a signal in the compound flag system (§6.2).

Suppression cost: high and increasing. Yang et al.'s third-generation spambots introduced deliberate randomization to reduce behavioral similarity, but at the cost of reduced campaign coherence. An adversary who randomizes behavior sufficiently to evade similarity detection is also randomizing the coordinated signal they are trying to inject, which reduces attack effectiveness. There is a fundamental tension between behavioral diversity (for evasion) and signal coherence (for effect).

#### T.5 Anomalous trajectory smoothness

Legitimate nodes show variance in reputation and participation trajectories across epochs because real participation is noisy — connectivity varies, interest shifts, availability fluctuates. Sybil nodes maintaining a carefully controlled behavioral profile show anomalously low variance. This is distinct from temporal clustering on action: a node can have variable action timing (defeating T.2 detection) while still maintaining an anomalously smooth overall participation trajectory.

Srivatsa et al. (ICDCS 2005) identified trajectory smoothness as a signal in the TrustGuard context. In the OSN bot detection literature, Varol et al. found that temporal activity patterns — which encode smoothness indirectly — were consistently among the top predictors across bot categories.

In PrivaCF's setting this manifests as low σ² in the score trajectory over a rolling window, captured by smoothness detection (§7.5).

Suppression cost: moderate to high. Introducing genuine variance in participation is possible but requires the adversary to accept periods of lower participation, which reduces the campaign's throughput and may trigger the asymmetric penalty if the variance includes score drops.

#### T.6 Whitewashing and identity cycling

Whitewashing — abandoning a penalized identity and re-entering under a new one — is empirically the most common evasion strategy across P2P reputation systems (Hoffman et al., ACM Computing Surveys 2009). It is the dominant strategy in zero-admission-cost systems precisely because replacement is free. In high-admission-cost systems the economics change fundamentally: each new identity requires paying the full admission cost, which shifts the rational strategy away from proliferation toward identity preservation.

In PrivaCF's setting same-key whitewashing is cryptographically impossible via the nullifier mechanism. New-key whitewashing requires full admission cost and faces behavioral fingerprint matching on re-entry. The empirical dominance of whitewashing in other systems is therefore evidence that the nullifier mechanism addresses the most common real-world evasion strategy first.

Suppression cost in PrivaCF: high for same-key (cryptographically blocked), moderate for new-key (admission cost plus behavioral fingerprinting), low for new-key with deliberate fingerprint variation (admission cost only).

#### T.7 Solipsistic cluster structure

Sybil clusters tend to be densely internally connected and sparsely connected to the honest network, creating a detectable cut in the interaction graph. This is the basis of SybilGuard and SybilLimit's graph-cut detection. In systems with a persistent observable social graph, this is one of the strongest available signals.

In PrivaCF's setting the interaction graph is ephemeral and not directly observable, making graph-cut detection structurally unavailable — the ephemeral peer relationship model means no persistent graph exists to cut. The behavioral consequences of solipsistic cluster structure are however observable without seeing the graph: a node structurally positioned in a sybil cluster will show rare cross-cluster PSI attempts, high intra-cluster behavioral synchrony, low variance in peer set composition across epochs, and rewind signals from any bridge connections it maintains. These are behavioral proxies for graph structure rather than direct observation of it, and enter the compound flag system accordingly (§7.8).

Cross-cluster PSI attempt rate as a signal: The PSI responder issues a signed acknowledgment of receipt regardless of whether the handshake succeeds, distinct from the success receipt issued on PSI completion. The acknowledgment confirms a cross-cluster PSI attempt was received without revealing similarity score or item sets. The initiating node includes received acknowledgments as private witnesses in its handoff ZK proof, proving attempt rate without revealing who was contacted. Legitimate interest in cross-cluster discovery is genuine — any node seeking peers outside its immediate cluster has real motivation to attempt cross-cluster PSI, so the signal reflects real behavior. Nodes could spam cross-cluster PSI attempts to generate acknowledgments. Three sub-cases, each bounded (OQ-61, resolved as design):

- **Inflation by contacting honest nodes** is self-defeating — genuinely reaching many distinct honest responders *is* the honest behavior the signal rewards, and imposes the high suppression cost noted above. The counted signal additionally **saturates at `n_discovery`** (the per-epoch outbound PSI cap, §5.4), so collecting more acks confers no marginal signal, and the responder-side `n_psi_in` cap bounds resource consumption — no separate throttle parameter is required.
- **Self-dealing** (a sybil ring acking its own members) is the real attack. It is defeated by defining the signal as *diversity-weighted* rather than raw count: acks from a responder set with low behavioral diversity or high mutual correlation (§6.2) establish little genuine cross-cluster reach, and a ring acking itself exhibits exactly the intra-cluster synchrony this section already flags. This collides with the privacy goal — the ZK witness hides counterparties — and is resolved by having the witness prove a *diversity predicate* over the hidden responder set (the N acks carry N distinct behavioral-cluster attestations, reusing the OQ-11 BBS+ cluster-attestation machinery) rather than a bare count.
- **Ack pooling** — the base schema signs `H(ack_nonce ‖ T)` with no binding to the collector, so a ring could *share* one member's collected acks. Closed by deriving `ack_nonce = Poseidon(sk_initiator, responder_id, T, "psi_ack")` and having the handoff witness prove knowledge of the `sk` behind each nonce: acks become **non-transferable** while the initiator stays pseudonymous to the responder.

Privacy: the ack binds only `responder_id`, `T`, and the initiator-derived nonce — never the initiator's identity in the clear. Under Loopix an external observer sees only fixed-size mix packets, and the responder learns only the initiator's per-epoch rotating `epoch_id` (linkage destroyed by rotation, no worse than the PSI handshake itself reveals). **Determination:** this is an *extension* of the network/handoff layer — the underlying Pinkas PSI protocol is unchanged; only the nonce-derivation rule and the handoff ZK predicate are added. The diversity predicate is the sole part pulling in additional (OQ-11) machinery, and its circuit cost is the remaining empirical item for Phase 5.

Suppression cost: high. Maintaining genuine cross-cluster connections to defeat this signal requires genuinely interacting with the honest network, which imposes behavioral cost and creates detection surface.

#### T.8 Velocity of targeted item trust accumulation

Coordinated pushing campaigns produce anomalously rapid trust accumulation for targeted items concentrated in narrow time windows. Mukherjee et al. on Yelp review fraud found velocity to be the strongest single discriminator of fake review campaigns — stronger than content similarity or reviewer behavior in isolation.

In PrivaCF's setting this manifests as anomalously rapid trust_total rise for a specific item within a narrow epoch window. The trust cap c bounds the ceiling of this accumulation but does not flag the velocity. Rewind signals provide a compound proxy: a coordinated push that inflates trust_total for an item that does not match the honest network's taste will degrade recommendation quality for outside nodes, generating rewind signals pointing at the epoch when those vectors entered the index. When rewind signals from multiple interest clusters share the same cohort_epoch coinciding with anomalous trust_total velocity for a specific item, this compound signal enters L3 (§6.6).

Suppression cost: moderate for detection via rewind signals (requires the pushed item to genuinely match honest taste, which constrains attack targets), high for direct velocity detection (requires staggering the push across many epochs, reducing campaign coherence).

#### T.9 Interaction checkpoint synchrony

During the admission window, VRF-determined interaction checkpoint epochs differ per node by construction. Genuine synchrony in checkpoint completion timing across multiple admitting nodes is therefore improbable by chance and is a signal of coordinated admission. This is a PrivaCF-specific signal with no direct analog in the general sybil literature, arising from the VRF-based admission structure. It is subsumed into the burst score computed by the committee over first-observation timing (§6.3), since VRF-determined checkpoint epochs are publicly verifiable after beacon publication and independently checkable by any participant.

Suppression cost: low to moderate. An adversary who staggers admissions across epochs loses checkpoint synchrony but also loses the efficiency of batch identity creation.

---

### 7.1b Sybil Influence Model

No purely structural argument can bound sybil influence in PrivaCF's setting without presuppositions about adversarial behavior, and no closed-form bound is achievable without empirical data about how sybil nodes actually behave in deployment. This subsection states the influence model explicitly, derives what can be bounded structurally, and is honest about what requires empirical calibration to go further.

#### Baseline bound

With random peer selection and no reputation filtering, the expected fraction of sybil-influenced recommendations received by any node is exactly:

```
p(recommendation is sybil-influenced) = |S| / |N|
```

where S is the sybil set and N is the total network. This is both the worst-case upper bound with no defenses active and the exact probability under random connection. With a perfect reputation system that identifies all sybil nodes with certainty, the probability goes to zero. The actual system sits between these bounds, and the reputation system is the mechanism that drives them apart.

#### Cluster/bridge decomposition

The two-tier peer selection structure decomposes expected sybil influence into two independent terms:

```
E[sybil influence] =
    p(rec from cluster peer) × p(cluster peer is sybil | PSI match)
    × E[influence | sybil cluster peer]
  + p(rec from bridge peer) × p(bridge peer is sybil)
    × E[influence | sybil bridge peer]
```

The two terms have structurally different sybil exposure. Cluster peers are PSI-filtered on item overlap, so p(cluster peer is sybil | PSI match) depends on whether sybil nodes have constructed item sets that overlap with the target's niche. Bridge peers are selected from a broader pool, so p(bridge peer is sybil) approximates the base rate |S|/|N| in the worst case.

For a user whose niche attracts no sybil interest — the common case for genuine long-tail content — the cluster term approaches zero by PSI filtering alone, and only the bridge term remains. This bridge term is bounded by:

```
p(bridge influence) ≤ p(bridge rec) × |S|/|N|
```

A user who sets bridge peer weight to zero (§5.7) reduces this term to zero entirely, at the cost of losing cross-cluster discovery. For a user whose niche is actively targeted, the cluster term dominates and PSI filtering provides weaker protection, since a targeted sybil constructs its item set specifically to match. This is the targeted-PSI Sybil case (§5.7, row 21 in the detection contract).

Both terms are further attenuated by hop-distance trust attenuation (μ^hop_distance), the trust cap c, and the reputation floor each node applies to its local HNSW index (§3.6). The reputation floor functions as a confidence threshold: under discrete bands, contributions from peers below the floor are zero-weighted; under a continuous gradient, they would be proportionally attenuated. Expected influence per sybil peer is therefore structurally bounded independent of detection, though the bound is loose when the sybil peer achieves high reputation through sustained legitimate behavior before activating.

A closed-form upper bound on per-target influence under **no detection** is derived in [SECURITY.md §P5.2](./SECURITY.md#p52-the-provable-structural-bound-i_struct-behavior-independent--closed-form): writing `w_c, w_b` for a node's cluster/bridge aggregation weights, `π_s` for the post-PSI sybil rate among cluster peers, and `f_cap, μ, w_cohort_cap` for the §7.3/§5.7/§7.6 caps,
```
I_struct ≤ min( f_cap · μ · (w_c · π_s + w_b · |S|/|N|),  w_cohort_cap ).
```
This is the behavior-independent floor that the adaptive Sybil model (P5) proves around; it vanishes for a non-targeted niche with bridge weight zeroed (`π_s → 0`, `w_b = 0`) and is non-zero only in the targeted-cluster residual (§8.2 T5).

#### Flag compounding across epochs

For a sybil node maintaining behavioral strategy S across epochs, the probability of remaining undetected after n epochs is:

```
p(undetected after n epochs | strategy S) = ∏_i (1 - p(flag_i raised | S))^n
```

This decays toward zero exponentially in n if any flag has nonzero detection probability under strategy S. The adversary's optimization is to choose S to minimize each p(flag_i raised | S) subject to achieving sufficient influence — exactly the evasion cost argument. The behavioral taxonomy in §7.1a assigns nonzero p(flag_i raised) to sybil nodes exhibiting each property, and the suppression cost estimates characterize how adversarial investment shifts those probabilities downward.

The compound decay is meaningful rather than trivially defeatable because suppressing each flag has an independent cost. An adversary who suppresses temporal clustering (T.1) by staggering admissions, suppresses behavioral similarity (T.4) by introducing randomization, and suppresses trajectory smoothness (T.5) by introducing participation variance is paying three independent costs simultaneously, each of which reduces campaign effectiveness in addition to reducing detection probability.

The hardest case is a sleeper node (I3 in the detection contract) that generates zero flags during the accumulation phase because it behaves entirely legitimately. For this node the compounding argument does not apply during accumulation — p(flag raised) ≈ 0 for all flags by construction. The defense in this case is not detection but damage bounding: trust cap c, hop-distance attenuation, and reputation floor collectively limit what even a fully undetected high-reputation node can inject into any target's recommendations.

#### What requires empirical data

The flag probability terms p(flag_i raised | S) cannot be computed from first principles without presuppositions about adversarial behavior, and those presuppositions cannot be grounded without empirical data. Two approaches are available, both limited:

**Empirical estimation from observed attacks.** The behavioral literature (§7.1a citations) provides base rates for each signal property across documented sybil campaigns. These estimates are biased — documented attacks are not a random sample of all attacks, and sophisticated attacks that went undetected are by definition absent from the data. Additionally, many documented large-scale sybil attacks have been conducted by state-level actors who are explicitly out of scope (§1.5); under the stated assumptions (A1–A4) they would be detectable, but their behavioral profiles may not generalize to the in-scope adversary population.

**Simulation over presupposed behavioral models.** Phase 5 adversarial simulation (§9.2) models sybil nodes following explicit behavioral strategies and measures empirical flag raise rates. This produces calibrated estimates conditional on the presupposed strategy, with the honest limitation that real adversaries will adapt their strategies in response to protocol analysis in ways that simulation cannot fully anticipate.

Running instances of the protocol against real adversaries who are motivated to analyze and attack it is the only source of ground truth. Adversaries who have studied the protocol will attempt to either fulfill its requirements legitimately or find exploits, both of which produce different attack signatures than synthetic simulation. The interaction between literature-grounded presuppositions, simulation-calibrated estimates, and live deployment data is the right methodology — each addresses gaps the others cannot.

#### Honest limitations

- p(flag_i raised | S) is not known for any S without empirical calibration from live deployment.
- Documented sybil attacks are a biased sample toward detected and reported campaigns.
- Adversaries who analyze the protocol will adapt their strategies to the specific flag system, producing attack patterns that historical data cannot anticipate.
- The influence bound is loose for high-reputation sleeper nodes before activation.
- Nation-state adversaries are explicitly out of scope. Under the stated assumptions (A1–A4) they would be detectable, but those assumptions are axioms rather than derived properties.

These limitations do not invalidate the model. They bound what claims the model can honestly support: structural upper bounds on influence per tier, exponential decay in detection probability across epochs for non-sleeper strategies, and damage bounding for sleeper strategies through trust cap and attenuation. Going beyond these bounds requires empirical data from live deployment, which Phase 5 begins to approximate under controlled conditions.

---

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
trust_contribution(v, X) = max(0, r_v(X) + noise) × Δ_base × (1 + κ × novelty(X))

if trust_total(X) < c:   trust(v) += trust_contribution(v, X)
else:                     trust(v) += 0

trust(v) ≤ f_cap × c
```

- `r_v(X)`, `noise`, and `Δ_base` are as defined in §3.4.
- `f_cap` is the per-node trust cap as a fraction of `c`. It bounds how much of the global trust ceiling any single node can claim. This is a distinct parameter from the `α` blend weight in §6.1.

Formal bound validated on Digg with binary feedback only. Extension to continuous noisy ratings requires the per-epoch composition lemma (OQ-10).

**Caveat on formal transfer.** The non-overwhelming rule is borrowed from DSybil but the formal bound justifying it in that work does not transfer to PrivaCF's setting. DSybil's theorem requires a persistent social graph, trust propagation via random walks, and a sparse honest/Sybil cut. PrivaCF has none of these — peers are discovered via PSI on item overlap, trust is not propagated transitively, and the topology is intentionally ephemeral. The rule is retained as a well-motivated heuristic with empirical support from the original Digg validation, but formal justification in this setting requires empirical data from live deployment. See OQ-10.

**Novelty term as passive Sybil damping.** The novelty bonus serves a dual purpose. Its primary function is to accelerate trust accumulation for undersurfaced items. A secondary effect is that as `trust_total` approaches `c`, marginal adversarial contributions shrink toward zero — coordinated pushing of an already-popular item has diminishing returns by construction, and organic popularity surges are similarly self-limiting. The converse is a sabotage vector: an adversary who pushes a niche item past an early trust threshold removes its novelty bonus, suppressing the organic discovery acceleration the system provides for long-tail content. This is harder to detect than inflation attacks because it requires no ongoing coordination after the initial push, and may be difficult to distinguish from a genuine early popularity surge. Characterization of this attack and its interaction with the compound flag system is left to Phase 5 adversarial simulation.

> **Implementation note — distinguishing the novelty-kill from an organic surge (exp 5.47).** A proof-of-concept simulation (ml-100k) tested whether this vector can be separated from a genuine early-popularity surge. The natural first candidate — the §7.4 FoolsGold mutual-similarity flag — does *not* work: a genuine niche surge is itself a tight cluster, so FoolsGold false-positives on it (ᾱ_organic ≈ 0.00), while a kill that diversifies its filler per Sybil evades FoolsGold entirely (ᾱ ≈ 1.00). The discriminating property is instead **neighbourhood coherence**: does the pushing cohort share the victim item's *pre-existing* taste cluster N(X), or only the victim itself? A naive (shared-filler) or diversified kill is a "star" assembled solely to push X — its preference mass outside the victim lands almost nowhere in N(X) (coherence ≈ 0.05–0.09) — and is cleanly separated from a genuine surge whose members really do share the cluster (coherence ≈ 1.0). This is a content signal **distinct from §7.4**, added as a new compound-flag input (§7.8), not reused from FoolsGold. **Irreducible residual:** an adversary that reconstructs N(X) and emits diverse-yet-coherent fans is, statistically, a genuine niche surge — no content signal can split them. That residual is addressed only by non-content axes: the *cost* of reconstructing the audience plus per-Sybil admission, and the orthogonal §7.1a admission-burst / trust-velocity **timing** signals (a fabricated surge arrives in a tighter window than organic word-of-mouth). **Net: row 9 of the detection contract (§7.9.2) moves from O to PARTIAL** — coherence handles the realistic naive and diversified kills; the mimic residual is content-irreducible and falls to timing and admission cost. (A prior PoC pass that claimed a clean FoolsGold separator, O→H, was an artifact of comparing a naive attack against a generic-diverse crowd rather than a realistic niche cluster; it does not hold.)

> **Implementation note — what the cap bounds, and what it does not (E3).** A proof-of-concept push attack (a Sybil cohort endorsing a cold target item to force it into honest users' top-K, across RobuRec profiles × SSP scenarios) confirms the passive-damping claim above *empirically*: with the full §3 ranking machinery and **no** active Sybil detection, the push of a cold item collapses to near-zero realized damage, because the endorsement raises the target's `trust_total`, which strips exactly the novelty/`item_weight` boost the attack relied on — the push defeats itself. **But this protection flows through the ranking terms, not through the similarity channel.** In an item-based CF strategy the item-item similarity is computed from the *raw* co-occurrence of gossiped contributions, which the cap `c` does **not** bound; the cap bounds `trust_total`, and damage is suppressed only because `novelty` and `item_weight` (which *are* derived from the capped trust) discount the pushed item at ranking time. Consequently the cap's structural bound is **strategy-contingent**: a pluggable strategy (§3.8) that consumes the gossip stream *without* the novelty/`item_weight` damping — e.g. plain cosine CF — receives no protection from `c` against a co-occurrence push, and must rely on the §7.4 FoolsGold-on-PSI-peers signal as the active defense. This refines the §7.9 row-3 reading of "damage structurally bounded by cap `c` regardless of detection": it is bounded regardless of *detection*, but conditional on the ranking strategy actually applying the capped-trust-derived terms. The PoC also confirms the bound is real where those terms are applied — damage saturates sub-linearly in Sybil count and FoolsGold drives the residual to zero — and that there is no stealthy-and-effective regime: an attack diffuse enough to evade the FoolsGold similarity flag is, by the same diffuseness, too uncoordinated to move the ranking.

**`trust_total` convergence (OQ-15).** `trust_total(X)` has no autonomous oscillation mode. Three structural facts establish this: (1) each `trust_contribution` is non-negative (`max(0, ·)`) and contributions halt once `trust_total(X)` reaches the cap `c` — the accumulator *saturates* rather than overshooting; (2) the novelty factor and the `item_weight` damping (§3.4) are *monotone-decreasing* in `trust_total`, so the only feedback from `trust_total` onto its own growth is negative (self-limiting), which cannot sustain a limit cycle; (3) the announcer-reputation weighting (§6.1 score band) does **not** depend on any item's `trust_total` — the §6.1 score has no `trust_total` term — so there is no reputation↔`trust_total` coupling that could oscillate. `trust_total` is therefore a bounded, saturating readout of the reputation/preference vector and converges to a fixed point for fixed inputs. The only way to drive it cyclically is *exogenous*: an adversary cycling its own reputation through the decay/recovery loop (the on-off attack), which `trust_total` passively tracks but cannot amplify. That loop is the `Δ_rise` decay/recovery tension already isolated as §8.2 T1 and calibrated in Phase 5 experiment 5.4 — a parameter-calibration question, not a convergence failure. This sharpens OQ-C1 (§10.2): the guarantee is not merely `trust_total ≤ c`, but the *absence of any positive-feedback or cross-coupling path* through which flooding could induce oscillation.

### 7.4 Sybil Impact Bounding and Local PSI-Similarity Flagging

Detection difficulty is transport-profile-dependent. Under the Tor/I2P profile, sub-epoch timing signals are available and the §7.1a taxonomy operates at fine resolution. Under the Loopix profile, sub-epoch timing is destroyed by mixing, leaving content-based signals (PSI similarity, gossip vector statistics) and epoch-granular signals (admission timing, audit-response rate) as the primary detection axes. PrivaCF combines (a) structural impact bounds that limit damage independent of detection, and (b) the content-based PSI-similarity flag described later in this section, which is transport-agnostic and carries proportionally more weight under the Loopix profile.

**k-anonymity for PSI neighborhoods.** A node activates cluster-specific behavior (cluster_endorsement scoring, cluster-weighted trust_total) only if `|peers_v| ≥ k_min`. Below this threshold the node falls back to global trust_total only. This prevents micro-cluster targeting: a Sybil attacker cannot construct a small, highly specific cluster around a victim and accumulate identifying signal across epochs.

```
cluster_behavior_active(v, T) = (|peers_v| ≥ k_min)
```

`k_min` requires empirical calibration. A conservative starting value is k_min = 20; larger values provide stronger anonymity at the cost of slower peer discovery convergence (OQ-32).

**Formal ε-DP privacy budget.** Laplace noise in §4.5 is parameterized by ε. Each gossip event leaks at most ε bits of preference information. Over T epochs the cumulative budget is Tε. A Sybil attacker controlling some fraction of a node's PSI neighborhood cannot re-identify the victim from gossip output alone within this budget. See OQ-55 for the formal derivation under the SecLDP framework.

**Structural caps as primary Sybil defense.** With k_min enforcing minimum crowd size and ε bounding per-event leakage, any Sybils that enter a neighborhood can neither target individuals nor accumulate identifying signal efficiently. The caps in §7.6 then bound influence regardless of detection:

- `w_node_cap` / `w_cohort_cap`: no node or cohort dominates reputation weight
- `f_cap`: individual trust accumulation capped at `f_cap × c`
- Hop-distance attenuation (§5.7): remote Sybils contribute at most `μ^k` of base weight

**Local PSI-similarity flagging (content-based, transport-agnostic).** Each node passively computes cosine similarity of received contribution vectors against the average of its PSI peer set, flagging anomalously high pairwise similarity. This is the protocol's primary content-based Sybil signal and operates identically across transport profiles, since it depends on gossiped content rather than timing.

```
sim_flag(p, q, T) if cosine(contrib_p(T), contrib_q(T)) > θ_psi_sim
                     AND |peers_v| ≥ n_foolsgold_min
```

The flag is local, passive (computed from already-received vectors), and submitted via the handoff package — no extra messaging cost. Below `n_foolsgold_min` peers the signal is suppressed to avoid small-sample false positives.

**Two-sided cross-peer flagging.** Peers exchange flag-rate aggregates each epoch (not the flags themselves — only the count or rate of similarity-pairs flagged in their local view). A node whose surrounding peers all show elevated flag rates around it is itself implicated, even if its own self-reported flag rate is suspiciously low. This catches the case where a Sybil cluster suppresses its own internal flags.

**On-flag PSI overlap proof escalation.** When the committee receives a similarity flag, it can compel the flagged pair to run a full PSI overlap proof against each other. The proof reveals the actual intersection size *to the committee only*, not publicly. Honest nodes whose taste happens to converge benignly cleared by the proof; coordinated Sybil pairs are identified by the overlap profile. The expensive PSI overlap step is gated on the cheap cosine flag, keeping average cost low.

**Transport-conditioned threshold.** Under the Loopix profile, where timing signals are degraded, `θ_psi_sim` is tightened to make the content signal more sensitive. Under the Tor/I2P profile, where timing signals carry independent detection power, `θ_psi_sim` is looser to reduce false positives. Both thresholds require empirical calibration (OQ-24, profile-parameterized).

This mechanism does not solve the original attribution problem in full — a confirmed similarity pair does not by itself imply Sybil control rather than benign convergence — but escalation to a committee-mediated PSI overlap proof addresses the attribution gap by surfacing the actual evidence to a body authorized to act on it.

### 7.5 Smoothness Detection

```
smoothness_flag(v, T) if Var(score_v(T−k), ..., score_v(T)) < σ²_floor
```

σ²_floor requires empirical calibration (OQ-29). Calibration should explicitly include recovery trajectory patterns — anomalously smooth post-penalty recovery is a specific case of the smoothness signal and should be represented in the OQ-29 test suite.

### 7.6 Weight Caps and Gini Monitoring

```
G(T) = (Σ_i Σ_j |w_i − w_j|) / (2n Σ_i w_i)
```

No single node exceeds `w_node_cap` of total weight. No cohort exceeds `w_cohort_cap` of total weight. Both parameters require empirical calibration; reasonable starting ranges are w_node_cap ∈ [1%, 5%] and w_cohort_cap ∈ [10%, 20%] depending on expected network size and cluster structure (OQ-32).

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
| Arbitration committee entry             | Cannot alter without threshold compromise | Detectable via public chain Merkle root                                            | Requires compromising threshold committee                                      |
| verdict_commit                    | Cannot alter after publication            | Yes — on-chain, signed, VDF-chained                                                | Non-alterable commitment to verdict                                            |
| verdict_reveal                    | Cannot mismatch with commit               | Yes — validators verify H(share ‖ verdict ‖ nonce) = commit                        | Invalid reveal rejected by validators                                          |

### 7.8 Compound Flag System and Alert Levels

| Signals present                                                     | Alert level                             | Automated action                                          | Human review?             |
| ------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------- | ------------------------- |
| High announcement rate alone                                        | L1 Watch                                | None                                                      | No                        |
| Low announcement diversity alone                                    | L1 Watch                                | None                                                      | No                        |
| High rate + low diversity                                           | L2 Elevated                             | Increase audit frequency                                  | No                        |
| L2 + cohort temporal clustering (same behavioral cluster)           | L3 Suspicious                           | Elevate + flag                                            | Recommended               |
| L3 + PSI neighborhood below k_min threshold                         | L4 Probable Sybil                       | Suspend cluster behavior + Class 3                        | Yes                       |
| L3 + cross-cluster behavioral similarity                            | L4 Probable Coordinated                 | Reduce routing weight + Class 3                           | Yes                       |
| L4 + Class 3 fail OR handoff rejection (majority)                   | L5 Confirmed                            | Commit-reveal SUSPENDED flow on public chain              | No                        |
| L4 + Class 3 pass                                                   | L2 Elevated                             | Maintain elevated audit, clear L4                         | No                        |
| Smoothness flag alone                                               | L1 Watch                                | None                                                      | No                        |
| Smoothness flag + low temporal depth                                | L2 Elevated                             | Increase audit frequency                                  | No                        |
| First-observation reports inconsistent with VDF start               | L2 Elevated                             | Extend admission observation                              | No                        |
| Temporal burst score above threshold (§6.3)                         | L1 Watch                                | None — contributes to compound flag only                  | No                        |
| Geographic concentration flag (§6.3)                                | L1 Watch                                | None — contributes to compound flag only when combined    | No                        |
| Temporal burst + geographic concentration + behavioral synchrony    | L2 Elevated                             | Increase audit frequency                                  | No                        |
| New epoch_id null_v already in SUSP_SMT                             | Rejected at admission                   | Statement 5 proof fails — no handoff possible             | No — cryptographic        |
| New epoch_id behavioral fingerprint matches suspended               | L2 Elevated                             | Elevated audit from admission                             | No                        |
| Suspicious restart detection                                        | L3 Suspicious                           | Elevated audit + flag                                     | Recommended               |
| Q rewind signals (≥2 interest clusters, correlated cohort)          | L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Rewind signals correlated with specific item trust_total velocity   | L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Niche item trust surge with low cohort neighbourhood coherence (§7.3)| L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Coordinated rewind signals from same behavioral cluster             | L3 Suspicious                           | Elevate + flag                                            | Recommended               |
| Handoff rejection (minority of committee)                           | L3 Suspicious                           | Trigger Class 3                                           | No                        |
| Handoff rejection (majority of committee)                           | L5 Confirmed                            | Commit-reveal SUSPENDED flow                              | No                        |
| Validator double-signing detected                                   | L5 Confirmed                            | Commit-reveal SUSPENDED flow, permanent                   | No                        |
| Anomalous verdict_commit rate, no behavioral signal justification   | L3 Suspicious                           | Watchdog signal broadcast + oversight chain               | Recommended               |
| Stalling committee (commit phase started, reveals missing)          | L3 Suspicious for non-revealing members | Non-response penalty + oversight chain                    | Recommended               |
| L5 Confirmed + persistent manipulation signals despite Class 3 pass | L5 Nuclear                              | Committee demands full rolling chain commitment traversal | Committee review required |

---

### 7.9 Detection Contract

§7.1 enumerates attackers and §7.8 enumerates detection actions, but the mapping between them has so far been informal. This subsection makes the mapping explicit. For each meaningful intersection of _manipulation tactic_ and _identity/persistence strategy_, the contract states what triggers detection, which mechanism handles it, the strength of the guarantee, and what slips through. Unresolved cells are named so reviewers can falsify them.

#### 7.9.1 Axes

**Manipulation tactic (T) — what the adversary injects:**

| ID  | Tactic                | Description                                                                                     |
| --- | --------------------- | ----------------------------------------------------------------------------------------------- |
| T1  | Random injection      | Random items, random ratings — no specific target                                               |
| T2  | Targeted push         | Inflate `trust_total` of a specific item                                                        |
| T3  | Coordinated narrative | Multi-item campaign across one or more interest clusters                                        |
| T4  | Novelty kill          | Push a niche item past the trust threshold to suppress its novelty bonus (§7.3 sabotage vector) |
| T5  | Semantic poisoning    | Genuine engagement patterns, manipulated semantic intent                                        |

Suppression in PrivaCF reduces to T2 against competitors of the target — dislikes are local-only and not transmittable, so direct nuke attacks are not in the tactic space.

**Identity / persistence strategy (I) — how the adversary persists or evades:**

| ID  | Strategy                             | Description                                                                        |
| --- | ------------------------------------ | ---------------------------------------------------------------------------------- |
| I1  | Single identity, immediate           | One identity, payload deployed immediately after admission                         |
| I2  | Single identity, sustained           | One identity active across many epochs, payload throughout                         |
| I3  | Single identity, sleeper             | One identity builds reputation passively, then deploys payload                     |
| I4  | Sybil swarm, fresh keys              | Many identities each with a distinct `sk`, used briefly                            |
| I5  | Same-key rotator (post-suspension)   | Identity suspended; new `epoch_id` derived from same `sk`                          |
| I6  | New-key rotator, similar fingerprint | Identity suspended; new `sk`, behavioral pattern preserved                         |
| I7  | New-key rotator, varied fingerprint  | Identity suspended; new `sk`, behavioral pattern deliberately altered              |
| I8  | Dark node rotator                    | Identity goes offline before nullifier extraction, then re-admits                  |
| I9  | Rogue committee (audit-layer attack) | Compromised committee threshold attempts mass deanonymization or covert decryption |

**Guarantee level (G) — strength of the detection promise:**

| Level | Meaning                                                                                                                                                                                      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **C** | **Cryptographic.** Detection (or block) follows by arithmetic from an honest-validator check; failure requires breaking a primitive listed in A3.                                            |
| **B** | **Behavioral-probabilistic.** Detection rate is governed by a calibrated threshold; false positive and false negative rates are characterized empirically. The named OQ governs calibration. |
| **H** | **Heuristic.** A signal is surfaced into the compound flag system; final adjudication requires operator review or correlated evidence across multiple flags.                                 |
| **PARTIAL** | **Heuristic with a named residual.** The realistic instances of the tactic are surfaced into the compound flag system (as H), but a specific, characterized sub-case is content-irreducible and is bounded only by non-content axes (cost, timing), not eliminated. Stronger than O (the common case is detected), weaker than H (a residual is explicitly carved out). |
| **O** | **Out of scope.** Explicitly not promised. Listed so reviewers can confirm the gap is intentional, not overlooked.                                                                           |

#### 7.9.2 Contract Table

Each row names one meaningful (T, I) intersection. Cells not listed collapse to a row that handles them — see §7.9.3.

| #   | (T, I)                    | Adversary archetype                         | Triggering signal                                                                                  | Mechanism (§ref)                                                   | G                                                                              | Residual / Calibration                                       |
| --- | ------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| 1   | T2 × I1                   | Naive opportunist                           | Bursty announcements, low diversity                                                                | §7.8 L1→L2 (rate + diversity)                                      | B                                                                              | OQ-32                                                        |
| 2   | T1 × I4                   | Random Sybil flooder                        | Admission-rate spike; Gini drift; influence bounded by caps                                        | §6.3 first-observation; §7.4; §7.6                                 | B                                                                              | OQ-32                                                        |
| 3   | T2 × I2                   | Patient pusher (sustained, single identity) | DSybil cap reached on target item; smoothness flag if score variance is artificially low           | §7.3 cap `c`; §7.5 smoothness                                      | B (smoothness); damage structurally bounded by cap `c` regardless of detection | OQ-15, OQ-29                                                 |
| 4   | T2 × I3                   | Sleeper activator (single identity)         | Score variance + sudden trajectory change after dormancy                                           | §7.5 smoothness; §7.2 asymmetric penalty                           | B                                                                              | OQ-29, OQ-6 (`Δ_rise`); hardest single-identity case         |
| 5   | T2 × I2 (mimic)           | Bandwagon mimic                             | Influence bounded by k_min + ε-DP + weight caps; no direct detection                              | §7.4 impact bounding; §7.6                                         | B                                                                              | OQ-32                                                        |
| 6   | T3 × I4                   | Coordinated campaign, single cluster        | Behavioral cluster overlap; influence bounded by caps                                              | §6.2 behavioral cluster signal; §7.4; §7.6                         | B                                                                              | OQ-28                                                        |
| 7   | T3 × I4-distrib           | Coordinated campaign, cross-cluster         | Cross-cluster behavioral similarity (timing, audit response distribution)                          | §7.8 L4 Probable Coordinated                                       | H                                                                              | OQ-28; operator review required                              |
| 8   | T3 × I3 swarm             | Cross-cluster sleeper swarm                 | Smoothness flag across multiple identities + cross-cluster behavioral similarity                   | §7.5 + §6.2 + §7.8                                                 | H                                                                              | OQ-28, OQ-29; hardest multi-identity case                    |
| 9   | T4 × any                  | Novelty-kill saboteur                       | Pushing cohort shares only the victim item, not its neighbourhood N(X) — low neighbourhood coherence (§7.3); + admission-burst / trust-velocity timing (§7.1a) | §7.3 neighbourhood-coherence flag → §7.8 compound flag; §7.1a timing + §4.3 admission cost for the mimic residual | **PARTIAL** (coherence handles naive + diversified kills; mimic residual → timing/cost) | Mimic kill (reconstructed N(X)) is content-irreducible; bounded by §7.1a timing + admission cost. exp 5.47 |
| 10  | T5 × any                  | Semantic poisoner                           | Indistinguishable from genuine signal at the protocol layer                                        | None — by construction                                             | O                                                                              | Acknowledged residual (§8.1 "Semantic poisoning")            |
| 11  | any × I5                  | Same-key rotator                            | `null_v ∈ SUSP_SMT` — Statement 5 fails                                                            | §4.9.5 Statement 5 + §4.9.2 SUSP_SMT                               | C                                                                              | None — fails by arithmetic                                   |
| 12  | any × I6                  | New-key rotator, similar fingerprint        | `behavioral_similarity > θ_behavioral` within `T_behavioral_window`                                | §6.3 admission_flag; §7.8 L2 Elevated                              | B                                                                              | OQ-34, OQ-35                                                 |
| 13  | any × I7                  | New-key rotator, varied fingerprint         | None at identity layer; falls back to whatever T-level defense applies                             | §4.3 admission cost (rate-limits but doesn't block); T-row applies | B (T-only)                                                                     | Acknowledged residual (§8.1 "Sophisticated epoch rotators")  |
| 14  | any × I8 post-publish     | Dark node, post-`commit_T`                  | On a finalized verdict, public `s₁` + validator attestation (decrypting `s₂`) reconstruct `null_v` from on-chain `commit_T` (adopted publish-`s₁`); 2-of-2 profile instead needs committee `σ^SUSPEND` ∧ validator `σ^VERDICT` | §4.9.4 (publish-`s₁`); §4.9.6 commit-reveal          | C                                                                              | None — recoverable without node cooperation; covert recovery requires >2/3 validator collusion + slashable equivocation (2-of-2 profile: also a committee threshold) |
| 15  | any × I8 admission window | Dark node, pre-`commit_T`                   | Zero reputation + behavioral fingerprint of admission attempt                                      | §4.3 admission cost; §6.3 first-observation                        | B (bounded)                                                                    | OQ-16; bounded but not eliminated; admission-window-only gap |
| 16  | I9 on-chain               | Rogue committee, on-chain extraction        | Anomalous `verdict_commit` rate vs. behavioral signals                                             | §4.9.8 watchdog + recursive oversight                              | B                                                                              | OQ-48; bounded by Chernoff (§4.9.8) under A2                 |
| 17  | I9 off-chain              | Rogue committee, covert decryption          | None until a `null_v_decryption` transaction is submitted; off-chain σ aggregation leaves no trace | §8.1 "Threshold collusion" carve-out                               | O (below A2)                                                                   | OQ-17, OQ-53; bounded by Byzantine majority assumption       |
| 18  | orthogonal                | Validator double-signer                     | Two BLS signatures on competing blocks at same height                                              | §4.1 double-signing detection                                      | C                                                                              | None — immediate permanent SUSPENDED                         |
| 19  | I-orthogonal              | Reputation laundering (proactive rotation)  | Re-admission cost + behavioral fingerprint match if pattern preserved; if varied, falls to row 13  | §4.3 + §6.3                                                        | B (with similar fingerprint) / O (with varied)                                 | OQ-57 (cost amortization across cycles)                      |
| 20  | I-orthogonal              | Cluster splitting via inconsistent PSI      | Self-harming (degrades node's own cluster); detectable as PSI cache divergence across observers    | §7.7 (PSI cache row)                                               | B (self-harming)                                                               | Self-harming only; no operator action needed                 |
| 21  | T2 × I-targeted PSI       | PSI-targeted Sybil                          | Sybil constructs item set to enter victim's interest cluster                                       | §5.4 PSI; §7.4 k_min + ε-DP impact bounding                       | B (partial)                                                                    | §8.2 T5 — formal bound not established                       |

#### 7.9.3 Collapse rules

The full Cartesian product of T (5) × I (9) is 45 cells. The table above lists 21 distinguishable rows. The rest collapse:

- **Row 11 absorbs (any T) × I5** — Statement 5 fails before any payload can be deployed.
- **Row 14 absorbs (any T) × I8 post-publish** — `null_v` is recoverable from the prior epoch's `commit_T` regardless of what payload was attempted.
- **Row 10 absorbs T5 × (any I)** — semantic poisoning is undetectable at the protocol layer regardless of identity strategy.
- **(T1) × (I1, I2, I3)** collapse into row 1 (the signal that triggers detection — high rate, low diversity — is identical for random and targeted single-identity push at this scale).

#### 7.9.4 Where the contract is weakest

Three regions of the matrix are where the protocol's promise is genuinely thin and worth flagging to reviewers:

1. **Row 9 (T4 — novelty kill).** A coordinated novelty-suppression push is separable from an organic early-popularity surge by **neighbourhood coherence** (§7.3): a kill cohort shares only the victim item, not its pre-existing taste cluster N(X), whereas a genuine surge shares the cluster. The §7.4 FoolsGold flag is *not* the right tool — it false-positives on genuine niche clusters and is evaded by diversified fillers (exp 5.47). Coherence handles the realistic naive and diversified kills (surfaced into the §7.8 compound flag system); the irreducible residual is a *mimic* kill that reconstructs N(X) and is statistically indistinguishable from a genuine surge by any content signal, bounded only by admission cost (§4.3) and the orthogonal §7.1a admission-burst / trust-velocity timing axes. Was O; now **PARTIAL** — meaning the realistic cases are surfaced heuristically (as H) but a content-irreducible residual remains, closed only by the non-content axes above rather than eliminated.
2. **Row 13 (I7 — new-key rotator with varied fingerprint).** Once the adversary changes both `sk` and behavioral pattern, the only remaining defense is admission cost, which rate-limits but does not detect. Acknowledged in §8.1.
3. **Row 17 (I9 off-chain).** A colluding committee threshold can recover `null_v` covertly without on-chain trace. Bounded by A2 (the same assumption consensus depends on), but no protocol-layer detection exists below that ceiling. This is the weakest link in the entire identity-privacy story.

The contract is strongest at rows 11, 14, 18 (cryptographic guarantees by arithmetic) and at rows 1–6, 12, 15 (behavioral-probabilistic with named calibration OQs). Rows 7, 8, 16 are heuristic and depend on operator review or compound-signal correlation.

#### 7.9.5 Implications for Phase 5 simulation

Each B-level, H-level, and PARTIAL row in the table corresponds to at least one Phase 5 experiment in §9.2 (with the exception of self-harming rows like row 20, where TPR/FPR characterization is not meaningful — the attacker's own CF quality degrades and operator action is unnecessary). The detection contract above can be used as a checklist: for each non-self-harming row marked B, H, or PARTIAL, the corresponding experiment must produce a TPR/FPR characterization with an explicit calibration recommendation (for PARTIAL rows, the characterization must also state the content-irreducible residual and which non-content axis bounds it). Rows marked O are not eliminated by Phase 5 — they are documented residuals.

---

## 8. Known Limitations

### 8.1 What Is Not Protected

- **Within-cluster preference privacy.** Interest cluster peers accumulate observations over time. Accepted tradeoff.
- **Long-term differential privacy.** T epochs of ε-DP gives Tε total loss. Not claimed.
- **Nation-state adversaries.** Loopix provides formal sender/receiver/relationship anonymity under the Poisson traffic model, but mix node compromise and global traffic analysis remain out of scope.
- **Semantic poisoning.** Structurally unresolvable at the protocol layer — an epistemic problem, not a security one.
- **Announcement token unforgeability assumes sk integrity.** The RATE_LIMIT leaf construction proves announcement count without revealing items, but relies on the node's `sk` not being compromised. A node with a stolen key could have tokens manufactured on its behalf; this is subsumed by the general key compromise threat and is not specific to this construction.
- **Dark node rotators — admission window only.** The dark node gap is closed for nodes that have published at least one `epoch_transaction`. The residual gap is nodes that go dark during the admission window before any `commit_T` is published. Bounded by zero reputation, full admission cost, and behavioral fingerprinting.
- **Sophisticated epoch rotators with key change.** An adversary generating a fresh key evades the nullifier mechanism entirely. Admission cost and non-overwhelming trust are the remaining defenses.
- **Poseidon maturity.** Less cryptanalytic history than EC constructions. Resolved by primitive split: local derivations use Poseidon as a keyed PRF; pseudorandomness under standard Poseidon assumptions suffices (OQ-1 — closed).
- **ForwardCommit instantiation maturity.** BLS-based ForwardCommit resolved as Boneh-Franklin IBE over BLS12-381; reduces to DBDH in the random oracle model (OQ-2 — closed).
- **Behavioral fingerprint as persistent identifier.** Derived from public on-chain data and available to any observer. Degraded but not eliminated by per-n-epoch commits, relay submission, and transaction timing jitter.
- **commit_T as per-epoch presence signal.** Published every epoch, exempt from n_commit batching. Opaque without verdict signature but confirms node liveness every epoch.
- **Approximate interest cluster graph reconstruction.** Loopix relationship anonymity substantially degrades this but does not eliminate it — PSI traffic patterns over many epochs may still leak cluster topology to a patient adversary observing mix nodes.
- **Poisson cover traffic bandwidth.** Every node emits traffic at a constant Poisson rate regardless of real activity. This is non-trivial on metered or mobile connections (OQ-58).
- **Arbitration committee threshold trust.** Compromise of a threshold quorum of the **currently-selected** arbitration committee (§4.1) can reconstruct any `snapshot_v(T)` whose shares that committee holds — fine-grained behavioral data and peer-receipt sets for the epoch. Bounded by per-epoch committee rotation and Shamir handoff to the incoming committee; not bounded by the lifetime trust of every prior committee, as a full encrypted ledger would have been.
- **Score verification trustlessness.** Ordinary nodes cannot recompute raw scores from public chain data alone. Verification is committee-attested. Accepted cost of the committee-attested score model.
- **p_v targeted inflation.** An adversary can inflate preference weights for target items within the bounds of Statements 1 and 3.
- **Threshold collusion for null_v extraction.** Under the **adopted publish-`s₁` design** (§4.9.4), committees hold *no* decryption material — `s₁` is public and only `s₂` is encrypted, to the standing validator key `VA_pub`. Covert recovery therefore requires obtaining `σ_T^VERDICT` from the **current** validator set off-chain: a threshold (`⌊2K_validators/3⌋+1`) signing `"VERDICT_FINALIZED epoch_id_T"` with no canonical verdict — simultaneously a break of the honest-majority assumption A2 *and* a slashable equivocation (§4.1, detectable double-signing). There is no committee path to weaken. *(Optional 2-of-2 profile: `s₁` is instead split to the committees, so a colluding committee supermajority that aggregates `σ^SUSPEND` recovers only `s₁ ⟂ null_v`, and covert deanonymization additionally requires the same validator equivocation — committee threshold **and** validator threshold **and** slashable equivocation.)* As before, any protocol-meaningful use of a recovered `null_v` requires a publicly visible `null_v_decryption` transaction. The privacy assumption is bounded by the Byzantine majority assumption already in the threat model, and by the public, slashable accountability of the validator attestation.

### 8.2 Unresolved Design Tensions

**Privacy tradeoffs**

- **T2 — Niche signal vs. privacy protection.** Chopping vs. Laplace. Mutually exclusive per deployment.
- **T9 — n_commit batching vs. audit freshness.** Larger n_commit improves privacy but widens the undetected drift window.
- **T10 — commit_T per-epoch submission vs. behavioral fingerprinting.** commit_T is exempt from n_commit batching and provides a per-epoch liveness signal. Mitigated by commit_T's opacity — it reveals presence only, not behavior.

**Security tradeoffs**

- **T1 — Δ_rise calibration vs. on-off attack defense.** If no single Δ_rise satisfies both path-responsiveness and on-off attack resistance, governance must choose a point on the tradeoff curve. Characterized empirically in Phase 5 experiment 5.4.
  - **PoC update (damage-coupled exp 5.4).** A proof-of-concept run that couples the reputation dynamics to an actual recommendation push (reputation gates an announcer's gossip weight per §3.4, so a higher-reputation Sybil pushes harder) finds that **for *recommendation* damage this tradeoff is non-critical.** Two results drive this: (1) reputation does amplify the *undefended* push, but the §7.3 passive damping and §7.4 FoolsGold signal bound the realized push to ≈ 0 *at every reputation level* — the defenses act downstream of reputation; and (2) under the faithful decay model (absence costs only the §6.1 slow `δ_decay`; the `BAND_1` cliff above is reserved for an actual detected violation, **not** ordinary absence), an on-off adversary retains near-full reputation while staying dark, so `Δ_rise` barely constrains it — yet it still achieves no feed damage. The honest-recovery cost of `Δ_rise` is real only after *extended* outages and is decoupled from recommendation damage entirely. **Net: the `Δ_rise` tension applies to what reputation *else* gates (committee / validator / relay eligibility), not to feed poisoning; the recommendation layer is robust to the on-off attack independent of `Δ_rise`.** A caveat worth carrying into Phase 5: an earlier PoC pass that scored the attack in *reputation* units (snapping to `BAND_1` on every absent epoch, against an arbitrary fairness baseline) produced a spurious "knife-edge `Δ_rise`" — the experiment must be damage-coupled and must not treat absence as a violation, or it mis-calibrates. Absolute numbers depend on the toy reputation parameters and the asymmetric-penalty model rather than the full §6.1 score; the *qualitative* result (defenses bound the push regardless of reputation) is the load-bearing claim.
- **T5 — PSI-targeted Sybils.** Formal bound not established under patient targeted adversary who constructs an item set specifically to enter a victim's interest cluster.
- **T12 — Forward secrecy of past `commit_T` (closed by verdict-binding, §4.9.4).** The original concern: a future committee whose threshold BLS shares are compromised could decrypt **past** `commit_T` values without a corresponding verdict, recovering `null_v` for prior epochs. The earlier v1 mitigation — mandatory share deletion enforced by slashing — was weak: it deters only on-chain *misuse* (a decryption surfaced via a `null_v_decryption` tx), not covert deanonymization, which leaves no trace and which is the privacy-relevant use; and deletion is unverifiable. **This is now resolved cryptographically by the 2-of-2 split (§4.9.4):** `null_v = s₁ + s₂`, with `s₁` held by the committee and `s₂` released only by the validator set's `σ_T^VERDICT` attestation, which exists only alongside a finalized on-chain verdict. A committee compromise — present or future — yields only `s₁`, which is independent of `null_v`. Retroactive recovery now additionally requires a threshold of the **current** validators to sign `"VERDICT_FINALIZED epoch_id_T"` off-chain, which is both an A2 break and a slashable equivocation (§4.1). The residual is therefore bounded by the same honest-majority assumption consensus already rests on, no longer by an unverifiable deletion assumption. *Optional defense-in-depth:* make `VA_pub` itself forward-secure (Pixel-style key evolution, Drijvers et al. 2020, puncturing past verdict identities after the `W_primary`/`W_fallback` window) — applied to one standing key rather than every per-epoch committee, no longer load-bearing. Referenced by §1.7 P4. **Adopted-design update (publish-`s₁`, §4.9.4):** with `s₁` public and only `s₂` encrypted to `VA_pub`, forward secrecy is *cleaner still* — the committee is entirely out of the decryption path, so no committee compromise (present or future) touches `null_v` at all, and `s₂` is sealed until `σ_T^VERDICT`. The lock is validator-only; covert recovery requires a `>2/3` validator collusion (beyond A2) plus a slashable equivocation. Forward secrecy of past `commit_T` against future validator-key compromise is preserved by the `VA_pub` PSS re-share (§4.1) exactly as for the `d_T` half here.

**Liveness tradeoffs**

- **T7 — Validator incentives.** Addressed by service score bonus and shirking penalty. Long-term sufficiency without tokens requires analysis.
- **T8 — Shamir re-share availability during committee rotation.** The one-shot re-share from outgoing to incoming arbitration committee (§4.1) must complete inside the rotation window. Failure modes: outgoing committee partially online, re-share ZK proofs failing, incoming committee key publication slow. Mitigated by slashing the outgoing committee for non-completion, but the residual availability gap during the rotation window itself requires calibration. **The standing validator-attestation key `VA_pub` (§4.1, §4.9.4) rides the same machinery** — its per-rotation proactive re-share (PSS) shares the same window, ZK-correctness, and slashing-on-non-completion obligations, and the same residual calibration question. One difference sharpens the stakes: a failed `snapshot_v` re-share loses recoverable behavioral state for audits, whereas a failed `VA_pub` re-share would strand the `s₂` half of every not-yet-finalized `commit_T` (dark-node extraction), so the `VA_pub` re-share is the higher-criticality of the two and its threshold should be provisioned accordingly.
- **T11 — Commit-reveal latency vs. suspension throughput.** The commit-reveal process adds latency to suspension finality. High volumes of simultaneous suspensions may create block space contention.

**Calibration questions**

- **T3 — Validator set size vs. collusion resistance.**
- **T4 — Admission window length vs. UX.** No middle states by design.
- **T6 — Behavioral cluster false positives.** Real users in the same timezone with similar routines may cluster together. Mitigated by compound flag system rather than direct reputational effects.

---

## 9. Implementation Plan

### 9.1 Minimal Viable PrivaCF

**Reference transport profile.** The MVP targets the self-mixing Loopix profile (§5.1) as the default. The Tor/I2P alternate profile is fully specified but not implemented in Phase 1–2; reference-profile interoperability with the alternate profile is not required (per §5.1, instances do not federate across profiles).

**Mobile policy.** The PoC targets desktop / simulated hardware. Mobile benchmarks are *collected* in Phases 3 and 5 (e.g. experiment 5.39) to characterize feasibility, but a slow mobile proof time does not fail the PoC: mobile acceptability is a post-PoC hardening concern, not a Phase 1–5 gate. The mobile-acceptance questions OQ-3, OQ-3b, OQ-33, and OQ-47 are therefore data-collection items in V1 and acceptance gates only in V2 (§10.1.1).

**Core hypothesis:** Decentralized CF with rotating pseudonymous identities, self-mixing Loopix/Sphinx transport (mix layer provided by PrivaCF mix-role nodes themselves, §5.1.1), Dandelion++ broadcast routing, Jaccard PSI peer selection, Merkle-committed behavioral history with peer attestations, multi-auditor encrypted handoff, a single public chain with arbitration-committee custody of sensitive state, nullifier-based suspension persistence, forward-secure commitment for dark node closure, commit-reveal verdict observability, and light Sybil resistance can surface content that a popularity baseline misses, without a trusted server.

**Stack:** Python or Rust · NumPy/ndarray · hnswlib · EMP-toolkit (Pinkas PSI) · tendermint-rs (BFT consensus) · blst (BLS signatures) · Poseidon crate (arkworks-rs) · Simulated network for Experiments 1–3 · self-mixing Loopix/Sphinx mix-node implementation (Katzenpost code reused as the in-tree mix-node component rather than as an external network) + Dandelion++ for Experiment 4.

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

Poseidon PRF epoch IDs and permutation; null_v local derivation; staggered epoch offsets; variable chopping with VRF-jittered n_v(T); niche item announcement delay; identity VDF chain with interaction checkpoints; Pedersen commitment; Merkle tree with peer-attested leaves; HNSW snapshot storage for rewind; Shamir distribution to auditor committee; **self-mixing Loopix/Sphinx transport** — mix-role node implementation (Sphinx packet processing, Poisson per-hop delay scheduler, RouterInfo advertisement), client-role / mix-role split per §5.1.1, provider-based NAT traversal; SURB-based request-response; Dandelion++ for broadcast fluff phase with timeout retry; Sphinx fixed-size packet padding; Noise Protocol sessions for clearnet/dev only; Loopix loop and drop cover traffic at base Poisson rate; communication rhythm; entry protocol; Class 2 passive audit; first-observation report collection and arbitration committee submission including provider_id field; burst score aggregation over first-observation timing; mix-network density aggregate signals (§6.3); ADMITTING health tier.

**Adopted publish-`s₁` forward-secure nullifier (§4.9.4):** `null_v = s₁ + s₂` split with **`s₁` published in the clear** and per-epoch `commit_T = (s₁, d_T)` publication, where `d_T` is the native-group verifiable encryption (DESIGN §3–§4) of `s₂` to `VA_pub`; standing validator-attestation key `VA_pub` with proactive Shamir re-share across validator rotations (§4.1); `VERDICT_FINALIZED` validator threshold attestation emitted at verdict finalization, with a distinct DST and double-signing slashing for off-chain forgery; Statement 5 circuit (split check with public `s₁` + `d_T` VerEnc binding + SMT path, **no in-circuit pairing**) in Plonky3; DECRYPTION_SMT initialization; verdict_commit and verdict_reveal transaction types (verdict-vote commit-reveal); null_v_decryption transaction type (validator attestation) and permissionless aggregation; watchdog_signal transaction type. Committees attest/vote by **aggregate multisig over VRF membership — no per-node DKG, no threshold committee key**. *(Optional high-assurance 2-of-2 profile instead re-adds: committee ciphertexts of `s₁`, per-slot in-circuit ForwardCommit certification, and a DKG protocol for the per-epoch committee threshold BLS key — see §4.9.4.)*

Public blockchain: block structure and VDF chaining; SUSP_SMT initialization; VRF validator and proposer selection with dual cluster constraints; BLS threshold signatures for block finality; Tendermint-style proposer timeout fallback; double-signing detection; genesis validator set and transition protocol; light client block header storage with Merkle inclusion proofs; per-n-epoch commit batching.

Arbitration committee: threshold-held encrypted ledger; committee handoff protocol between rotating committees; Shamir share rotation; continuity proof storage; first-observation report storage; fine-grained behavioral data storage.

Relay nodes: VRF selection; submission batching; reputation model integration.

PSI acknowledgment message type: signed acknowledgment of cross-cluster PSI receipt, independent of handshake success; rate limit implementation (OQ-61 pending full analysis).

_Exit: N nodes cycling through staggered epochs over the self-mixing Loopix/Sphinx network (mix layer provided by a subset of those same nodes operating mix-role identities) with public state on the public chain and sensitive state held under arbitration committee threshold custody. Block finality verified. Double-signing detection verified. Light client sync verified. Class 2 audit flow end-to-end verified. Relay submission verified. Statement 5 proof generation and verification end-to-end verified. commit_T published and verified each epoch. Commit-reveal verdict flow end-to-end verified including permissionless aggregation. DECRYPTION_SMT insertion verified. Watchdog signal broadcast verified. Dark node extraction verified — node goes offline after publish, committee decrypts from commit_T. Burst score computation verified against synthetic admission timing data. Provider_id field included in first-observation reports. Mix-role/client-role unlinkability verified under adversarial probing._

**Phase 2 — Reputation and Sybil Resistance**

Per-epoch score including validator/relay service components; slow reputation decay; consistency and smoothness detection including recovery trajectory patterns in test suite; rewind signal trigger with cohort correlation; item-level trust_total velocity correlation with rewind cohort_epoch; HNSW snapshot rollback; multi-auditor encrypted handoff; Class 3 audit trigger; justified disclosure; compound flag system including coordinated rewind signal detection and item-velocity compound signal; behavioral cluster computation; inter-cluster reputation; trust attenuation; commit-reveal SUSPENDED verdicts with null_v extraction and SUSP_SMT insertion; behavioral fingerprint matching; suspicious restart detection; committee-attested score band publication; watchdog signal compound flag entry; stalling minority detection and non-response penalty; recursive oversight chain with hard depth limit.

_Exit: Multi-auditor handoff correctly detects inconsistent state. On-chain verdicts survive epoch rotation. null_v correctly inserted into SUSP_SMT on suspension. Re-admission from same sk correctly rejected by Statement 5. Behavioral fingerprint matching flags suspicious new admissions. Watchdog signal correctly triggers on anomalous commit rate. Stalling member correctly flagged. Oversight chain resolves correctly under honest majority. Rogue committee simulation correctly detected and blocked before null_v recovery. Item-velocity compound signal correctly triggers on synthetic coordinated push._

**Phase 3 — Cryptographic Layer**

ZK consistency proofs (Statements 1–3, 5); bounded clamp-based Laplace mechanism (sign preservation as post-processing, §4.5); ZK continuity proofs (arbitration committee); handoff ZK proof including PSI acknowledgment witnesses; rewind signal aggregation; desktop ZK benchmarks for all components (PoC gate); mobile benchmarks for all ZK components (data collection only — not a PoC gate, per §9.1 Mobile policy); Poseidon PRF security analysis (closed — OQ-1); domain separator collision check (closed — OQ-4); ForwardCommit security analysis (closed — OQ-2); extended Statement 5 mobile benchmark; dec_nullifier collision resistance analysis (closed — OQ-5); BLS-based ForwardCommit instantiation formal review; permutation reconstruction security benchmark; Pinkas PSI performance on mobile.

**Phase 4 — CF and Noise Calibration**

Full signed preference model; asymmetric PSI cache decay; two-tier peer selection; variable chopping with empirical n calibration; cover items post-n_cover; trust attenuation in CF weight; dislike-aware scoring; noise system comparison per segment (head / long-tail); adjacent-epoch weight validation; behavioral fingerprint calibration; n_commit calibration; niche announcement delay calibration.

**Phase 5 — Adversarial Simulation**

5.1 Recommendation poisoning — all RobuRec types × all SSP scenarios
5.2 Sybil flooding at genesis — join-rate spike detection
5.3 Patient adversary — smoothness detection calibration
5.4 On-off attack — Δ_rise tension validation (PoC damage-coupled run finds Δ_rise non-critical for *recommendation* damage — defenses bound the push downstream of reputation; see §8.2 T1 PoC update. Phase-5 work extends this to reputation's committee/validator gating under the full §6.1 score.)
5.5 Diversity bonus exploitation
5.6 Interest cluster seeding — gradual infiltration
5.7 Behavioral cluster false positives — co-located legitimate users
5.8 Coordinated announcement vs. viral discovery — TPR/FPR
5.9 Semantic poisoning within chopping obfuscation
5.10 Eclipse attack exposure
5.11 Noise system comparison under attack
5.12 k_min calibration — PSI neighborhood size vs. anonymity/quality tradeoff
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
5.31 Arbitration committee availability under member dropout and rotation
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
5.47 Novelty-kill saboteur — coordinated push of niche items past trust threshold to suppress novelty bonus; separation from organic early-popularity surges via the neighbourhood-coherence signal (§7.3), against an evading adversary (naive / diversified / mimic filler taxonomy); characterize coherence TPR/FPR and the content-irreducible mimic residual bounded by §7.1a timing + §4.3 admission cost (§7.3 sabotage vector; §7.9 row 9, PARTIAL)
5.48 Coordinated admission burst threshold — separating organic community growth from sybil admission campaigns; calibration of burst window W and burst_score ceiling (OQ-59)
5.49 Per-transport-profile Chernoff K_d calibration — committee size needed under interest-cluster-only diversity (Loopix profile) vs. dual-cluster diversity (Tor/I2P profile), per §4.9.8
5.50 Per-transport-profile PSI-similarity threshold calibration — θ_psi_sim under Loopix (tight) vs. Tor/I2P (loose), per §7.4
5.51 Mix-network density signal calibration (self-mixing Loopix profile only) — AS-density anomaly threshold, mix-churn baseline, SUSPEND↔mix-disappearance correlation strength
5.52 Behavioral centroid lifecycle calibration (§6.2) — k_cluster, n_cluster republish cadence, and feature preprocessing; cluster-partition stability vs. fingerprint drift across epochs; committee recompute/publish cost and fraud-proof challenge rate

**Tor/I2P alternate profile.** The alternate transport profile (§5.1) is fully specified but not in the Phase 1–2 implementation scope. A separate deployment track may instantiate it post-Phase 5 once per-profile calibration data is available; profile selection is a deployment-time decision.

### 9.3 Evaluation Metrics

**Recommendation quality:** Precision@K, NDCG, HR, long-tail discovery rate per popularity segment (head: top-X% of `trust_total` distribution; long-tail: remainder — boundary defined per deployment following Park & Tuzhilin, 2008), privacy-utility curve per segment, coverage, Prediction Shift. HNSW rewind recovery quality after poisoning event. The two segments have distinct signal properties: head items have dense co-occurrence signal and DP noise is relatively cheap; long-tail items are sparse, where chopping dominates and Laplace is destructive.

**Privacy:** Cross-epoch linkability; behavioral fingerprint re-identification rate under the arbitration-committee model; interest cluster graph reconstruction rate from PSI traffic patterns; score trajectory entropy; permutation reconstruction time; ε-DP per gossip event (mainstream only); cover item anonymity set per segment; niche item announcement timing anonymity set size.

**Sybil resistance:** PS and HR per attack type and SSP scenario; p_v inflation damage within Statement bounds; patient adversary accumulation rate; smoothness detection false positive rate; announcement anomaly TPR/FPR; coordinated rewind signal detection TPR/FPR; item-velocity compound signal TPR/FPR; epoch rotation evasion detection rate; dark node re-admission damage; burst score false positive rate vs. organic growth events.

**Nullifier mechanism:** False rejection rate for honest nodes under Statement 5; SUSP_SMT non-membership proof latency on mobile as tree depth grows; Statement 5 circuit benchmark on mobile.

**Audit and blockchain:** False audit claim rate; handoff rejection false positive rate; auditor collusion detection rate; ZK proof times on mobile; block finality latency; validator dropout tolerance; double-signing detection latency; light client sync overhead; arbitration committee availability under rotation.

**Network health:** Health tier distribution over time; false positive rate per scenario; recovery time per health tier; Gini coefficient trajectory; gossip convergence time; VDF admission cost per hardware tier; public blockchain storage per light client; arbitration committee storage per committee member.

---

## 10. Open Questions and Status

### 10.1 Open Questions

| ID    | Question                                                                                                                                                                                                                                                                                    | Field            | Framework                | Tier | Effort | Status                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ------------------------ | ---- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OQ-3  | What is the maximum acceptable Statement 5 proof generation time on target mobile hardware across SUSP_SMT depths?                                                                                                                                                                          | Cryptography     | empirical                | 3    | 1      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-3b | What is the maximum acceptable Statement 2 proof generation time on target mobile hardware at d=128 and d=256?                                                                                                                                                                              | Cryptography     | empirical                | 3    | 1      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-9  | What weight calibration (w₁–w₅, δ_decay, α) correctly balances reputation score components under adversarial conditions — can any pair of components be driven in opposing directions, and which dominates?                                                                 | Reputation       | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-10 | What is the empirically observed sybil influence on recommendation quality in live deployments, and how do flag raise rates vary across documented sybil behavioral strategies?                                                                                                             | Sybil resistance | empirical                | 2    | 5      | **partially resolved** — structural bounds established in §7.1b; closed-form bound requires empirical data from live deployment; paths A (stochastic block model) and B (MeritRank ratio) remain as routes to sharpen structural bounds; calibrated flag probability terms deferred to Phase 5 and live deployment                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| OQ-11 | Is there a ZK circuit construction for behavioral cluster membership that supports justified disclosure without revealing the underlying fingerprint?                                                                                                                                       | Cryptography     | theoretical → empirical  | 2    | 4      | resolved (desktop) — the public centroids both paths presuppose are now produced by the §6.2 centroid lifecycle (deterministic algorithm over public chain data; committee-published every n_cluster epochs; recompute-checkable with fraud proofs), so the two paths anchor on the same canonical partition rather than competing authorities. Two viable paths: (1) BBS+ attestation: arbitration committee issues a signed cluster attestation each epoch (the signature is over the §6.2 canonical label, not an independent computation); node uses BBS+ selective disclosure to prove cluster = C without revealing epoch_id or fingerprint values; reuses BLS keys already in the stack (§4.9); simpler to implement first. (2) ZK k-means over public centroids (Plonky3): because centroids are public, squared-distance comparison reduces to an inner product of private F with public coefficient vectors plus a range proof on the result — no quadratic terms; estimated ~2–3k constraints at d=100, k=10; proof time under 100ms on desktop with Plonky3. The remaining design work for path (2) is tying the private fingerprint witness to epoch_id inside the circuit (likely a Merkle path or hash preimage), which adds cost but is not a feasibility blocker. Mobile is a compatibility target, not a PoC requirement; both paths are deferred on mobile pending benchmarks. |
| OQ-12 | What is the minimum genesis set size for bootstrap viability, and at what point can the behavioral cluster diversity constraint be enforced without relaxation?                                                                                                                             | Network          | empirical                | 3    | 3      | partial — the genesis set floor is now bounded by interest-cluster committee viability (not dual-cluster coverage), since the recommendation layer remains useful during the behavioral-cluster-relaxed bootstrap phase via content-based cold-start (§13). The enforcement threshold (when behavioral fingerprints have sufficient temporal depth and cluster density) remains open; see OQ-44 for the tightening schedule.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| OQ-13 | Are validator incentives sufficient to prevent long-term shirking without token rewards?                                                                                                                                                                                                    | Reputation       | theoretical \| empirical | 2    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-14 | What is the correct staleness window for SUSP_SMT_root references in Statement 5 — how old can the root be before the non-membership proof is no longer meaningful?                                                                                                                         | Cryptography     | theoretical              | 1    | 2      | **closed** — the staleness window is zero by construction. The handoff package (§6.4) fixes exactly one `SUSP_SMT_root_T` per epoch as a named field; it is also chained into the rolling_chain_commitment. There is no prover choice of root — the epoch-T root is the only valid input. Any null_v inserted in epoch T-1 is present in every epoch-T root, because the commit-reveal flow spans multiple epochs and cannot finalize a suspension mid-epoch without prior evidence epochs. The question of staleness does not arise: the protocol admits exactly one valid root per epoch, and that root is always post-suspension for any node suspended in a prior epoch.                                                                                                                                                                                                                                                                                                        |
| OQ-15 | Does trust_total converge to a stable distribution under sustained adversarial flooding, or does it oscillate?                                                                                                                                                                              | Sybil resistance | theoretical              | 1    | 3      | **resolved (proposition written)** — [SECURITY.md OQ-15](./SECURITY.md#oq-15--trust_total-stability-under-flooding-convergence-no-autonomous-oscillation) proves it: `trust_total` is a bounded monotone accumulator (gate freezes at cap c, per-node share ≤ f_cap·c), converges by monotone-convergence, and is a **cascade with strictly-negative feedback** (item_weight/novelty both monotone-decreasing; §6.1 reputation has no trust_total term → no loop), so it has **no autonomous oscillation**. Any oscillation is *forced* tracking of the exogenous on-off loop (§8.2 T1), bounded by `(b₄/b₁)·f_cap·c` and damped by Δ_rise. Residual = amplitude/quality impact, = exp 5.4 calibration (not convergence). See §7.3, OQ-C1 (§10.2). |
| OQ-16 | What is the expected damage from dark node re-admission during the admission window gap, as a function of n and c?                                                                                                                                                                          | Sybil resistance | theoretical → empirical  | 2    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-17 | Can off-chain committee collusion executing a covert ForwardCommit decryption be detected, and what is the damage bound below the Byzantine majority threshold?                                                                                                                             | Cryptography     | theoretical              | 2    | 3      | **resolved by §8.1** — covert ForwardCommit decryption by a colluding threshold yields only targeted epoch_id linkage: no suspension, no preference exposure, no protocol consequence until a visible null_v_decryption tx is submitted. Damage = one epoch_id de-anonymized, gated by the same Byzantine-majority assumption already in the threat model; detectability is moot (consequence-free until on-chain). Formal write-up deferred to the security-analysis companion doc. See §10.1.1. |
| OQ-18 | What is the correct VDF gap tolerance policy — at what point should a partially completed chain be invalidated vs. allowed to resume?                                                                                                                                                       | Identity         | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-19 | What is the minimum cover item count n_cover that provides meaningful anonymity set protection without degrading CF quality?                                                                                                                                                                | Privacy          | empirical                | 3    | 2      | **partially resolved** — structural bound derived analytically. Under a capacity-bounded colluding-receiver adversary controlling k_adv peers, item X with K honest likers achieves (δ, ε_conc)-failure-probability anonymity when: `n_cover(K) ≥ C_effective/(N−K) × [m_fixed/δ_anon − K_eff + √((N−K)×ln(1/δ_conc)/2)]` where m_fixed = k_adv×(T_epochs−τ_niche), K_eff = Σ min(1, n_v(T)/d_v) over honest likers, δ = δ_anon+δ_conc+δ_loopix, and δ_loopix = m_fixed×ε_loopix. Requires Loopix sender-anonymity guarantee (ε_loopix-approximate uniformity). Numerical evaluation blocked on OQ-58 (ε_loopix uncharacterized). CF quality degradation calibration remains empirical (Phase 3). §4.5 confirmed: permutation is over positive-preference set (line 499: "selected from the permuted positive preference set") — d_v denominator in p_real = min(1, n_v(T)/d_v) is correct.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| OQ-20 | What are the correct PSI cache decay values λ_proof and λ_noproof across community sparsity profiles?                                                                                                                                                                                       | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-21 | What value of μ correctly attenuates hop-distance trust without suppressing legitimate long-range CF signal?                                                                                                                                                                                | CF               | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-22 | How long does permutation reconstruction take under realistic gossip observation rates, and does it meaningfully threaten preference privacy?                                                                                                                                               | Privacy          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-23 | What Jaccard PSI threshold θ_cluster optimally balances peer quality against cluster size across different community types?                                                                                                                                                                 | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-24 | What value of k_min correctly balances PSI neighborhood anonymity against recommendation quality and peer discovery convergence speed across community density profiles?                                                                                                                     | Sybil resistance | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| OQ-62 | Can Byzantine-robust aggregation (coordinate-wise median or trimmed mean) be applied to committee aggregation steps in PrivaCF without requiring nodes to open committed values beyond what the existing audit mechanism already reveals?                                                    | Sybil resistance | theoretical              | 3    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| OQ-25 | Does the 0.5× adjacent-epoch CF weight default correctly discount stale gossip vectors, or does it over-penalize nodes with slow interaction rates?                                                                                                                                         | CF               | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-26 | What auditor committee size K_committee minimizes collusion probability while remaining viable under cluster diversity constraints?                                                                                                                                                         | Reputation       | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-27 | What validator set size K_validators correctly balances BFT safety margin against participation overhead?                                                                                                                                                                                   | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-28 | What behavioral cluster similarity threshold minimizes false positives from co-located legitimate users while catching coordinated Sybils?                                                                                                                                                  | Sybil resistance | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-29 | What smoothness variance floor σ²_floor separates legitimate consistent participation from adversarial reputation smoothing, including recovery trajectory patterns?                                                                                                                        | Sybil resistance | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-30 | What is the correct maximum frame size across all protocol message types, including the PSI acknowledgment message type?                                                                                                                                                                    | Network          | empirical                | 1    | 1      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-31 | What interaction checkpoint schedule within the admission window best balances re-identification risk against Sybil detection signal?                                                                                                                                                       | Identity         | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-32 | How many first-observation reports are needed for a meaningful coordinated admission signal?                                                                                                                                                                                                | Reputation       | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-33 | What is the maximum acceptable handoff ZK proof generation time on target mobile hardware?                                                                                                                                                                                                  | Cryptography     | empirical                | 1    | 1      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-34 | What behavioral fingerprint similarity threshold θ_behavioral correctly flags suspicious new admissions without over-penalizing legitimate users?                                                                                                                                           | Sybil resistance | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-35 | What is the correct T_behavioral_window — how long should a suspended fingerprint continue to flag new admissions?                                                                                                                                                                          | Sybil resistance | empirical                | 4    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-36 | Is one epoch sufficient for peer attestation retention, or do audit windows require longer retention?                                                                                                                                                                                       | Reputation       | empirical                | 1    | 1      | **resolved** — one epoch is sufficient for Class 2 audits (current-epoch pull response receipts only). Insufficient for Class 3 audits, which may challenge any epoch T' for which M_v(T') is committed on-chain. Resolution: receipts (set_of_peer_signed_receipts composing PULL_RESPONSE leaves) are included in the encrypted_shares payload of the auditor handoff, retained by the arbitration committee under threshold custody for the lifetime of the node's audit chain. Class 3 audits query the arbitration committee directly for historical receipts, eliminating the need for per-node local retention beyond one epoch. See §6.4 handoff package update.                                                                                                                                                                                                                                                                                                                                                |
| OQ-37 | What n_commit value optimally degrades behavioral fingerprinting precision without creating an audit freshness gap?                                                                                                                                                                         | Privacy          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-38 | What reputation decay rate δ_decay tolerates legitimate absence without allowing dormant adversarial nodes to maintain inflated reputation?                                                                                                                                                 | Reputation       | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-39 | What arbitration committee availability protocol survives member dropout and rotation without creating handoff gaps?                                                                                                                                                                              | Reputation       | empirical                | 3    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-40 | What relay node batching window provides meaningful submission timing obfuscation without unacceptable submission latency?                                                                                                                                                                  | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-41 | What n_jitter range provides sufficient vector size obfuscation without degrading CF quality in sparse communities?                                                                                                                                                                         | Privacy          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-42 | What N_rewind rate limit prevents adversarial Class 3 triggering while allowing legitimate quality degradation signals through?                                                                                                                                                             | Reputation       | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-43 | What is the expected p_v inflation damage within Statement 1 and 3 bounds, and at what point does it meaningfully degrade recommendation quality?                                                                                                                                           | Sybil resistance | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-44 | What is the correct bootstrap behavioral cluster relaxation schedule — how quickly should the diversity constraint tighten as the network matures?                                                                                                                                          | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-45 | How many HNSW snapshots should be retained, and at what depth does rewind recovery quality degrade below usefulness?                                                                                                                                                                        | CF               | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-46 | What announcement delay parameters τ_niche and max_delay_epochs correctly balance niche item re-identification risk against discovery signal propagation?                                                                                                                                   | Privacy          | empirical                | 3    | 2      | **partially resolved** — tradeoff structure derived analytically from OQ-19 bound. τ_niche reduces the adversary's effective observation window, replacing T_epochs with (T_epochs−τ_niche) in m_fixed. The tradeoff between n_cover and τ_niche is linear with constant substitution rate Λ = C_effective×k_adv/((N−K)×δ_anon): `n_cover = Λ×(T_epochs−τ_niche)`, `dn_cover/dτ_niche = −Λ`. Any (n_cover, τ_niche) pair on the line `n_cover + Λ×τ_niche = Λ×T_epochs` achieves the target failure probability — the choice between high cover/low delay and low cover/high delay is a UX decision, not a security one. Numerical calibration of Λ requires k_adv estimate (Phase 5) and OQ-58 resolution (ε_loopix). Calibration against community sparsity profiles remains empirical.                                                                                                                                                                                                                                                                                                                                                                                              |
| OQ-47 | How does SUSP_SMT non-membership proof latency scale with suspended node count on target mobile hardware?                                                                                                                                                                                   | Cryptography     | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-48 | What watchdog threshold correctly separates legitimate suspension bursts from rogue committee activity?                                                                                                                                                                                     | Reputation       | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-49 | What oversight chain depth limit and escalation schedule bounds damage during the resolution window without creating liveness risks?                                                                                                                                                        | Reputation       | empirical                | 4    | 3      | closed — structural question resolved by Chernoff bound; empirical calibration (K_0, ΔK) remains in Phase 5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| OQ-50 | What DKG completion deadline correctly constrains the epoch_transaction submission window without creating liveness pressure on slow committee members?                                                                                                                                     | Network          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-51 | What is the behavioral fingerprinting impact of per-epoch commit_T submission relative to n_commit batching?                                                                                                                                                                                | Privacy          | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-52 | What is the expected damage from a stalling minority attack before the oversight chain resolves?                                                                                                                                                                                            | Reputation       | empirical                | 4    | 3      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-53 | Can off-chain committee collusion be detected in arrears from public chain data, and what damage is possible below the Byzantine majority threshold?                                                                                                                                        | Cryptography     | theoretical              | 2    | 3      | **resolved by §8.1 (with OQ-17)** — off-chain collusion leaves no on-chain trace and is undetectable in arrears, but is consequence-free until a null_v_decryption tx surfaces; damage below the Byzantine threshold is bounded to single epoch_id linkage. Companion-doc write-up pending. |
| OQ-54 | Which noise mechanism (chopping vs. Laplace) and at what parameters correctly trades privacy for CF quality across head and long-tail segments?                                                                                                                                             | CF               | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-55 | Can the SecLDP trust model from the unified DP-DL MF framework (Cyffers et al., arXiv:2510.17480, 2025) be adapted to derive formal GDP bounds on PrivaCF's gossip exchange, parameterized by n_v(T), the Laplace noise scale, and the permutation key?                                     | Privacy          | theoretical              | 2    | 3      | **partially resolved** — SecLDP framework maps cleanly onto PrivaCF's gossip mechanism. The permutation key sk_perm is the hidden secret S in the SecLDP trust model; n_v(T) elements of the positive-preference set (size d_v) are the partially observable output. Lemma 14 (Cyffers et al.) removes the permutation-attributable component from the adversary's view matrix, giving effective sensitivity sens_eff = sens × (n_v(T)/d_v) — privacy amplification by subsampling at rate p = n_v(T)/d_v. Under Gaussian mechanism: Theorem 8 gives 1/σ_eff-GDP where σ_eff = ν/sens_eff = ν×d_v/(sens×n_v(T)). Under Laplace mechanism (PrivaCF's deployed mode): privacy amplification by subsampling yields effective ε_eff = log(1 + p×(e^ε−1)) ≈ p×ε for small ε, but formal equivalence between Lemma 14's matrix argument and the Laplace subsampling amplification theorem (Balle et al., ICML 2020) has not been verified. Remaining blocking work: (a) verify that Lemma 14 applies to Laplace mechanism, or derive a parallel statement; (b) map Statement 1 noise injection to Theorem 3/4 of Cyffers et al. to confirm the sens_Π(C;B) computation; (c) characterize interaction between ε_loopix and the GDP bound (OQ-58). See §10.1 notes on OQ-55 assumptions. |
| OQ-56 | Does PrivaCF's item-based CF on accumulated gossip vectors achieve comparable recommendation quality to gossip-based matrix factorization (Hegedűs et al., ECML PKDD 2019) under matched sparsity conditions on MovieLens and RateYourMusic?                                                | CF               | empirical                | 3    | 2      | open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| OQ-57 | Can sustained reputation laundering — proactive identity rotation across many cycles — amortize admission cost in a way that defeats the rate-limiting effect of the VDF chain, and does behavioral fingerprinting hold against a launderer who deliberately varies patterns across cycles? | Sybil resistance | theoretical \| empirical | 2    | 3      | **Half 1 closed analytically, Half 2 empirical (demoted)** — [SECURITY.md OQ-57](./SECURITY.md#oq-57--reputation-laundering-vs-the-admission-cost-rate-limit). *Cost amortization (Half 1):* the three routes are blocked — sequential VDF (no within-chain speedup → `k` identities cost `k·n·τ` processor-time, marginal cost unchanged), per-identity binding of reputation/depth to `sk` (zero carryover), and live beacon-bound interaction checkpoints (no precompute; `n`-epoch calendar floor per identity; visible to §7.1a). **Surfaced a normative hardening (now in §4.3): the VDF chain seed must be bound to the identity genesis** `C_id` — without it the VDF rate-limits chains not identities and Half 1 fails. *Fingerprint (Half 2):* stays empirical (exp 5.46) but **non-load-bearing** — even a perfect mimic is still rate-limited by Half 1, so fingerprinting is defense-in-depth. See §4.3, §7.6 T.6. |
| OQ-58 | What base Poisson rate λ for Loopix loop and drop cover traffic provides sufficient anonymity against a mix-node-observing adversary without imposing unacceptable bandwidth overhead on metered or mobile deployments, and what is the correct λ per config (A–E)?                         | Network          | empirical                | 3    | 2      | **analytical pre-bound DERIVED (keystone)** — `ε_loopix ≤ f^L + (1−f^L)·ρ_SDA`, `ρ_SDA ≤ C_SDA·m_obs/(n̄·(1+r))`, `n̄ = λ_mix/μ`, written out in [SECURITY.md §P1.1](./SECURITY.md#p11-conservative-ε_loopix-pre-bound-oq-58). The `f^L` (full-path-compromise) term is rigorous and sizes path length `L`; only the `O(1)` SDA constant `C_SDA` and the per-config `λ` remain. Unblocks numerical evaluation of OQ-19/46/55. Phase 5 exp 5.51 pins `C_SDA` and refines λ per config A–E rather than deriving the bound from scratch. See §10.1.1. |
| OQ-59 | What threshold W and burst_score ceiling separates coordinated admission bursts from organic community growth at realistic network sizes?                                                                                                                                                   | Sybil resistance | empirical                | 3    | 2      | open — Phase 5 experiment 5.48                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| OQ-61 | What rate limit on cross-cluster PSI acknowledgment attempts prevents spam while preserving the signal, and what are the privacy implications of the acknowledgment message type?                                                                                                           | Network          | theoretical → empirical  | 2    | 3      | **resolved as design** — rate-limit = saturate the counted signal at n_discovery (existing n_psi_in bounds DoS); self-dealing defeated by diversity-weighting (ZK witness proves a behavioral-cluster-diversity predicate over the hidden responder set, reusing OQ-11 BBS+); ack-pooling closed by a non-transferable Poseidon-derived ack_nonce. Determination: an extension of the network/handoff layer, NOT a PSI-protocol change (Pinkas PSI unchanged). Residual: diversity-predicate circuit cost → Phase 5. See §7.1b. |

**Notes on selected questions**

**OQ-10 (Sybil influence bound — reframed):** The question has been reframed from "does a stochastic block model argument yield a budget-scaled influence bound" to "what is the empirically observed sybil influence in live deployments." The reason is that §7.1b establishes that no closed-form bound is achievable without presuppositions about adversarial behavior, and those presuppositions cannot be grounded without empirical data. The structural bounds (baseline, cluster/bridge decomposition, flag compounding decay, damage bounding) are established and do not require further theoretical work. What remains is empirical calibration of the flag probability terms p(flag_i raised | S), which cannot be computed from first principles.

Two formal paths remain open as routes to sharpen the structural bounds:

_Path A — stochastic block model:_ PSI-selected interest clusters and VRF-selected behavioral clusters together provide independent random sampling from a pool with bounded adversarial fraction. The Chernoff argument that closed OQ-49 is the structural template. The open work is adapting it to a continuous influence quantity rather than a binary compromise event — requiring a sensitivity argument on the item-based CF scoring function under bounded adversarial weight injection.

_Path B — MeritRank ratio bound:_ Nasrulin et al. (IEEE BRAINS 2022) prove `lim|S|→∞ w⁺(σS) / w⁻(σS) ≤ c` under random-walk trust propagation. PrivaCF's trust cap c directly caps per-item adversarial weight injection by construction. Adapting the ratio bound to PrivaCF's PSI-based ephemeral topology — no transitive trust, peer sets refreshed each epoch — requires a new argument but the target statement and proof structure are available.

Both paths sharpen bounds but do not eliminate the presupposition dependency. Live deployment data is the only source of ground truth, and the sleeper attack escapes any purely structural argument since it satisfies cluster membership criteria honestly.

**OQ-49 (Oversight chain depth limit — closed):** See §10.2 and §4.9.8. Empirical calibration of K_0 and ΔK remains, addressed in Phase 5 experiment 5.42.

**OQ-53 (Off-chain committee collusion):** The Chernoff argument that closed OQ-49 bounds committee compromise for protocol-visible selection events. Off-chain collusion is the residual attack it does not cover — a colluding supermajority can aggregate σ and decrypt `commit_T` without going through the commit-reveal flow, leaving no on-chain trace unless they subsequently submit a `null_v_decryption` transaction.

**OQ-55 (SecLDP-GDP — explicit assumptions):** The partial resolution rests on four assumptions that must be stated explicitly before the bound can be used in a security argument:

1. _Epoch independence._ Beacon rotation produces a fresh permutation key each epoch. Cross-epoch information leakage is bounded by Loopix sender anonymity; the adversary's view from epoch T is independent of epoch T' given ε_loopix. Without this, the subsampling amplification calculation degrades because the adversary accumulates views.

2. _Cover item approximate uniformity._ Cover items are drawn approximately uniformly from the local cluster. This is a conservative direction: if cover items are clustered around the node's true interests, p = n_v(T)/d_v overestimates the adversary's information per epoch, making the bound tighter than reality (safe). The cover weight formula in §4.5 is trust-decay-weighted, not uniform, so this assumption is approximate; the error is bounded by the trust-weight variance over cover items.

3. _Capacity-bounded adversary._ The adversary controls k_adv fixed peers (not a fraction of traffic). This prevents circularity in the n_cover bound (OQ-19/OQ-46). Under a rate-bounded model (α × traffic), m_fixed grows with n_cover and the bound becomes vacuous.

4. _ε_loopix-approximate Loopix uniformity._ Loopix provides ε_loopix-approximate sender anonymity: for any two senders u, u', the adversary's posterior over sender identity given the observed traffic pattern is within multiplicative factor e^{ε_loopix} of uniform. This is the standard Loopix anonymity model. OQ-58 must characterize ε_loopix per config (A–E) before numerical bounds from OQ-19/OQ-46/OQ-55 can be instantiated.

**OQ-55 remaining blocking work (theoretical, pre-experiment):**

_Step 1 — Lemma 14 / Laplace equivalence._ The partial resolution uses Lemma 14 (Cyffers et al.) to remove permutation-attributable components from the adversary's view matrix, then invokes Theorem 8 for Gaussian mechanism. PrivaCF's deployed mode uses Laplace noise. The question is whether the matrix factorization argument of Lemma 14 is compatible with Balle et al. (ICML 2020) subsampling amplification for Laplace: if the subsampling structure induced by the permutation matches the "Poisson subsampling" model of Balle et al., then ε_eff = log(1 + p×(e^ε−1)) where p = n_v(T)/d_v is formally justified and OQ-55 closes under Laplace. If the permutation induces "sampling without replacement" instead, the Balle et al. bound is slightly different (tighter) and an explicit theorem reference is needed. This check requires reading §3 of Balle et al. against the Lemma 14 matrix structure — no new math, just confirming which subsampling model applies.

_Step 2 — sens_Π(C;B) computation._ Cyffers et al. Theorem 3/4 defines sens_Π(C;B) = max_{G,G': neighbors} ||C(G−G')||_{B†B} where G is the gossip graph and C, B are the mixing and observation matrices. For PrivaCF's gossip exchange: C is the n_v(T)×d_v subsampling matrix (one row per transmitted element, column per preference dimension), B is the identity (adversary directly observes transmitted elements with Laplace noise). The computation reduces to bounding the column norm of C under the permutation constraint — each column has exactly one nonzero entry (the element lands in exactly one position), so ||C(G−G')||_{B†B} = ||G−G'||_2 restricted to the transmitted coordinates. The sensitivity is then sens = max change in preference weight per dimension = 2 (L1-normalized vector, bounded by §4.5). Writing this out explicitly closes Step 2 and gives a concrete σ_eff formula ready for numerical instantiation once OQ-58 resolves ε_loopix.

**OQ-58 analytical lower bound (pre-experiment):** OQ-58 is listed as empirical (calibrating λ per config), but a conservative analytical bound on ε_loopix is derivable from Piotrowska et al. (USENIX Security 2017) before any experiment. The Loopix anonymity analysis gives sender anonymity as a function of λ (Poisson cover rate), mix topology (number of mixes, stratification), and adversary observation fraction. Specifically, the probability that the adversary correctly identifies a sender given traffic observation is bounded by a function of λ and the number of cover messages per real message. Inverting this gives a conservative ε_loopix(λ) per config. This analytical bound would unblock numerical evaluation of OQ-19, OQ-46, and OQ-55 without waiting for Phase 5 experiments — the experiments would then refine the bound rather than provide it from scratch.

### 10.1.1 Release Triage

Open questions are cut against a single test: **must this be resolved to build and validate the PoC through Phase 5?** Closed and structurally-resolved questions (OQ-11, 14, 36, 49; and the structural parts of OQ-10, 12, 19, 46, 55) are omitted from the cut below.

**V1 — feasibility / soundness (resolve early; a bad answer changes the design).**

- **P-feasibility (substrate gate) — *hard release gate*.** None of P1–P5 (§1.7) is creditable until (a) Layers 1–4 are built through Phase 3 and (b) the **desktop** Statement-5 circuit hits its proof-generation benchmark (= the desktop half of OQ-3, already a Phase-3 PoC gate). A bad answer changes the design. The PoC to date is Layer 5 only with crypto modeled in the clear; this gate makes that boundary explicit rather than implicit. Tracked in [SECURITY.md](./SECURITY.md#summary--status-after-this-companion). **Phase-0 estimate done** ([SPIKE-statement5.md §8](./SPIKE-statement5.md#8-phase-0a-result--constraint-estimate-2026-06-06)): Statement 5 *as specified* is AMBER/RED — the in-circuit ForwardCommit pairing is ≥99% of constraints — and must be restructured (move BF-IBE ciphertext-well-formedness to a public publish-time validator check; keep only the cheap `s₁+s₂=null_v` Poseidon binding in ZK) before the build. Not a dead end; a "redesign one component first" gate. Phase-1 spike confirms.
- **OQ-63 — aggregate per-epoch committee-DKG load. RESOLVED by the adopted publish-`s₁` design (§4.9.4):** with `s₁` public, no committee holds a decryption share, so committees need **no per-node threshold key and no DKG** (they attest by aggregate multisig, vote on verdicts) — the per-node DKG load that OQ-63 was about does not exist. The analysis below stands as the justification and as the cost model for the optional high-assurance 2-of-2 profile (which would re-incur it and need cohort-sharing). *Scalability soundness.* Analyzed closed-form in [ANALYSIS-dkg-load.md](./ANALYSIS-dkg-load.md). Key correction: per-node DKG load is **`O(1)` in `N`** (≈ `N_fallback × K_committee` committees per eligible node, *independent* of network size), not an O(N) blowup — the real knobs are the **eligible-pool concentration factor `N/E`** and the **liveness of running that many concurrent multi-round DKGs over the high-latency mixnet inside the §4.1 DKG window**. Compute is trivial and raw bandwidth modest; latency/liveness binds. Likely landing spot is **per-cohort shared committees** (one DKG'd key serves many nodes via per-node IBE identities), which the 2-of-2 split (§4.9.4) makes security-cheap — a shared-committee compromise yields only `s₁ ⟂ null_v`, not deanonymization. Run in parallel with the Statement-5 spike before the Layer-1–4 build. See §4.9.4 parameter note and §10.3. **Sim done** ([ANALYSIS-dkg-load.md §8](./ANALYSIS-dkg-load.md#8-sim-result-2026-06-06), `impl/spike_dkg_liveness.py`): per-node committees (option A) are **RED** at realistic concentration `N/E ≥ 3` or modest mixnet send rate — the wall is **throughput** (pushing `(N/E)·F·K²·R` messages through the fixed-rate Loopix sender), not latency. Per-cohort sharing (`g ≈ 5–20`) restores GREEN (option B). **Stronger resolution:** the **publish-`s₁`** F1 variant ([DESIGN §7, §10](./DESIGN-f1-verifiable-encryption.md#10-threat-model-sign-off-for-publish-s₁-phase-1-step-2)) *eliminates per-node DKG entirely* — the only per-node *threshold* key was the `s₁` ForwardCommit; remove it and committees attest by **aggregate multisig** (no DKG) and vote (not BLS-share aggregation), leaving only the standing `VA_pub` as a threshold key. If publish-`s₁` is adopted, OQ-63 is moot; otherwise adopt option B.
- **OQ-58 — Loopix λ → ε_loopix.** *Keystone.* Numerically blocks OQ-19, OQ-46, and OQ-55. The conservative analytical pre-bound is now **derived** in [SECURITY.md §P1.1](./SECURITY.md#p11-conservative-ε_loopix-pre-bound-oq-58): `ε_loopix ≤ f^L + (1−f^L)·ρ_SDA` with `ρ_SDA ≤ C_SDA·m_obs/(n̄·(1+r))` and `n̄ = λ_mix/μ` the honest-mix pool size. The `f^L` term is rigorous and immediately sizes path length `L`; only the `O(1)` constant `C_SDA` and per-config `λ` remain (exp 5.51). This unblocks OQ-19/46/55 numerically now.
- **OQ-17, OQ-53 — off-chain committee collusion.** *Resolved by §8.1:* covert decryption yields only single-`epoch_id` linkage, consequence-free until a visible `null_v_decryption` tx; damage below the Byzantine threshold is bounded, and detectability is moot. Formal write-up deferred to the companion doc.
- **OQ-15 — `trust_total` convergence vs. oscillation** under sustained flooding. If it oscillates, scoring is unusable.
- **OQ-61 — PSI-ack rate limit + privacy.** Self-flagged as requiring PSI-protocol-change analysis *before* Phase 5 scoping.
- **OQ-57 — reputation laundering vs. the VDF rate limit.** Sybil soundness; if defeatable, admission cost is bypassable. The cost-amortization half closes analytically (the VDF chain is sequential per identity — rotation cannot parallelize it); the fingerprint-stability-under-deliberate-variation half needs exp 5.46.

**V1 — build parameters (need a build-time starting value for Phase 1–3).** OQ-30 (frame size), OQ-18 (VDF gap policy), OQ-50 (DKG deadline), OQ-27 (K_validators), OQ-26 (K_committee). The last four are refined by Phase-5 calibration but must be initialized to implement the code.

**V1 — calibration (Phase 4–5 simulation; in scope, not blocking).** Each maps to a Phase-5 experiment: reputation/CF (OQ-9, 20, 21, 23, 24, 25, 38, 41, 42, 45, 54); Sybil thresholds (OQ-28, 29, 31, 32, 34, 35, 43, 44, 48, 59); privacy params (OQ-19, 37, 46, 51); liveness/infra (OQ-12, 39, 40, 52). OQ-55's DP formalization is needed only to state P2's `ε` explicitly; otherwise deferrable.

**V2+ — deferred past the PoC.**

- **Mobile acceptance thresholds:** OQ-3, OQ-3b, OQ-33, OQ-47. Benchmarks are still collected in Phase 3/5 as data, but mobile acceptability is not a PoC gate (§9.1 Mobile policy).
- **Live-deployment only:** OQ-10 (empirically observed influence rate — no closed form without deployment data); **OQ-13** (validator-incentive *sufficiency* — the mechanism, service-score bonus + shirking penalty, is built in V1, but long-term sufficiency without tokens is deployment-dependent, = §8.2 T7).
- **Defense-in-depth, not gating:** OQ-62 (Byzantine-robust committee aggregation — an enhancement over the honest-majority-plus-audit baseline; add post-PoC, not a blocker).
- **Comparative, non-gating:** OQ-56 (parity with gossip-MF; E1's gate is the popularity baseline, not Hegedűs et al.).
- **OQ-22** (permutation-reconstruction speed) may slip to V2 if Phase 3 is tight.

---

### 10.2 Resolved Prerequisites

All blocking prerequisites have been resolved or reclassified as non-blocking empirical calibration.

**Closed or reclassified as non-blocking**

| ID    | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OQ-C1 | `trust_total` convergence under adversarial flooding — closed by inspection. Bounded above by `c` by construction; the update rule halts contributions once the cap is reached regardless of flooding rate. The residual question (can adversaries push `trust_total` to `c` before honest contributions arrive) is a restatement of the Sybil influence problem addressed by OQ-10, not a separate convergence concern. Sharpened in §7.3 (OQ-15): beyond the `≤ c` bound, there is no positive-feedback or reputation↔`trust_total` coupling path, so the only cyclic driver is the exogenous on-off reputation loop (§8.2 T1, exp 5.4).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| OQ-C2 | Single-decryption enforcement — closed by the DECRYPTION_SMT design. A second `null_v_decryption` transaction for the same `verdict_hash` produces the same `dec_nullifier`, already in the tree; honest validators reject the containing block.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| OQ-1  | Poseidon PRF + EC-VRF security — resolved by primitive split. Local per-epoch derivations (epoch ID, permutation, chop count, offset, niche delay, leaf salt) use Poseidon as a keyed PRF; pseudorandomness under standard Poseidon assumptions suffices and no verifiability property is required. On-chain verifiable selection (validator, committee, relay) uses EC-VRF (RFC 9381), reducing to DLEQ/DDH with production implementations in tendermint-rs. See §4.2.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| OQ-2  | ForwardCommit security — resolved as Boneh-Franklin IBE over BLS12-381 (Boneh & Franklin, CRYPTO 2001). Security reduces to DBDH in the random oracle model. DST alignment between BLS signing and IBE key derivation must be explicitly specified. Collusion carve-out bounded by Byzantine majority assumption. See §4.9.4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| OQ-4  | Domain separator collision resistance — all derivations using `sk` now have a unique explicit (domain_sep, input_structure) pair after adding `"epoch_id"` and `"niche_delay"` separators. Collision argument reduces to standard Poseidon collision resistance. See §4.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| OQ-5  | dec_nullifier collision resistance — reduces to standard Poseidon collision resistance. `verdict_hash` is fixed on-chain before `null_v` is recovered, so chosen-input attacks are not applicable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| OQ-6  | Δ_rise calibration — reclassified as empirical. The tension between path-responsiveness and on-off attack defense is real but is a calibration question, not a blocking one. Addressed in Phase 5 experiment 5.4 and tracked as §8.2 T1. See §7.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
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

_OQ-14 — SUSP_SMT staleness window._ **Closed** — see §10.1 status. No experiment required.

_OQ-15 — trust_total convergence under adversarial flooding._ Model trust_total dynamics under sustained adversarial flooding as a bounded accumulator with a cap at `c`. Show analytically whether honest contributions can be crowded out before the cap is reached under different adversarial budget assumptions. Expected output: a characterization of the crowding-out condition as a function of adversarial budget and arrival rate. Effort: moderate.

_OQ-30 — Frame size._ Enumerate all protocol message types from Appendix A, including the PSI acknowledgment message type. Measure maximum serialized size for each under worst-case inputs. Set frame size to the maximum plus a fixed overhead margin. Expected output: a concrete frame size recommendation. Effort: minimal.

_OQ-63 — Aggregate per-epoch committee-DKG load._ **Analytic pass DONE** in [ANALYSIS-dkg-load.md](./ANALYSIS-dkg-load.md): closed-form counts (per-eligible-node memberships = `(N/E)·N_fallback·K_committee`), the correction that per-node load is `O(1)` in `N` (the binding factors are eligible-pool concentration `N/E` and concurrent-DKG liveness over the mixnet, not raw scale), the cost breakdown (compute trivial, bandwidth modest, latency binds), and the mitigation spectrum (per-node → per-cohort shared committees → single network committee) with the finding that the §4.9.4 2-of-2 split makes committee-sharing security-cheap (compromise yields only `s₁ ⟂ null_v`). Remaining: the confirming sim — `m` concurrent DKGs over a model Loopix latency distribution, sweep `m ∈ {21,63,315}` and window `W_dkg`, measure fraction missing the window; output a recommended cohort size if the per-node model is RED. Effort: afternoon (analytic, done) + a couple of days (sim). Sequence in V1 alongside the Statement-5 spike — a bad answer is a design change, not a parameter.

_OQ-33 — Handoff ZK proof generation time._ Build the Statement 5 circuit in Plonky3. Run on target mobile hardware (mid-range Android, iPhone SE class). Measure wall-clock proof generation time. Gate: under 2 seconds. Expected output: a benchmark table across hardware tiers. Effort: low once circuit exists.

_OQ-36 — Peer attestation retention._ Derive analytically the maximum audit query window across all audit classes. Confirm whether one epoch of attestation retention covers all cases or whether longer retention is required. Expected output: a retention period recommendation with justification. Effort: minimal.

---

**Tier 2 — Theoretical groundwork required first**

_OQ-10 — Sybil influence empirical baseline._ Collect flag raise rate data from Phase 5 simulation runs across all B-level and H-level detection contract rows. For each row, produce a TPR/FPR characterization conditioned on the simulated adversarial strategy. Use this to ground the p(flag_i raised | S) terms in §7.1b's flag compounding model. Paths A and B (stochastic block model and MeritRank ratio) may be pursued in parallel to sharpen structural bounds but are not prerequisites for empirical calibration. Expected output: a table of empirical flag probability estimates per strategy per detection mechanism, with confidence intervals and explicit statement of which adversarial behavioral presuppositions generated each estimate. Effort: very high.

_OQ-17 — Off-chain committee collusion._ Analyze the maximum damage a colluding committee supermajority can cause by executing a covert off-chain ForwardCommit decryption. The ceiling is the Byzantine majority assumption; the question is whether meaningful damage is possible below that ceiling and whether it is detectable in arrears from public chain data. Expected output: a damage bound and a detectability argument. Effort: moderate.

_OQ-53 — Off-chain collusion detectability._ Related to OQ-17 but focused on the detection side: given only the public chain, can an observer reconstruct evidence of a covert decryption that did not go through the commit-reveal flow? Expected output: either a detection protocol or a proof that covert decryption is undetectable below threshold collusion. Effort: moderate.

_OQ-61 — PSI acknowledgment rate limit and privacy analysis._ Design resolved in §7.1b: rate-limit by signal saturation at `n_discovery` (responder-side `n_psi_in` bounds DoS); non-transferable Poseidon-derived `ack_nonce`; diversity-weighted signal via a ZK behavioral-cluster-diversity predicate over the hidden responder set; implemented as a network/handoff-layer extension, not a PSI-protocol change (Pinkas PSI unchanged). Remaining work is empirical: calibrate the diversity weighting against self-dealing sybil rings, and benchmark the diversity-predicate circuit cost (reusing the OQ-11 attestation machinery). Effort: moderate.

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

_OQ-59 — Burst score threshold calibration._ Run synthetic admission timing data through the committee burst score aggregation at varying network sizes. Simulate both organic community growth events and coordinated admission campaigns. Measure false positive rate (organic growth flagged) and false negative rate (campaigns not flagged) as a function of burst window W and burst_score ceiling. Expected output: recommended W and ceiling values per network size tier. Effort: moderate.

---

**Tier 4 — Requires Phase 2 or later**

_OQ-24 — k_min calibration._ Simulate PSI neighborhood growth across community density profiles. Measure recommendation quality degradation and peer discovery convergence time as a function of k_min. Expected output: recommended k_min per community density tier. Effort: moderate.

_OQ-26 — Auditor committee size K_committee._ Simulate committee collusion attempts at varying K_committee values under cluster diversity constraints. Measure collusion probability as a function of adversarial budget and cluster structure. Expected output: a recommended K_committee with a collusion probability bound. Effort: moderate.

_OQ-28 — Behavioral cluster false positive rate._ Simulate co-located legitimate users and measure behavioral cluster false positive rate under the compound flag system. Expected output: a characterization of false positive conditions and a recommended θ_behavioral. Effort: moderate.

_OQ-29 — Smoothness floor calibration._ Run smoothness detection against legitimate consistent nodes and adversarial sleeper nodes across varying σ²_floor values. Test suite must explicitly include recovery trajectory patterns as a distinct test case. Measure TPR/FPR. Expected output: a recommended σ²_floor per community type with recovery-trajectory-specific characterization. Effort: moderate.

_OQ-34 — Behavioral fingerprint matching calibration._ Simulate sophisticated epoch rotators varying behavioral patterns across re-admission attempts. Measure detection rate as a function of θ_behavioral and T_behavioral_window. Expected output: recommended parameter values with a characterization of the evasion boundary. Effort: high.

_OQ-43 — p_v inflation damage quantification._ Simulate targeted p_v inflation within Statement 1 and 3 bounds on MovieLens and RateYourMusic. Measure recommendation quality degradation as a function of inflation magnitude and target item popularity segment (head / long-tail). Expected output: a damage characterization per segment. Effort: moderate.

_OQ-9 — Reputation weight calibration._ Simulate adversarial nodes attempting to maximize individual score components while degrading others. Sweep w₁–w₅, δ_decay, and α across ranges. Measure which component dominates under each adversarial strategy and identify weight combinations that resist manipulation. Expected output: recommended default weight values with adversarial resistance characterization. Effort: moderate.

_OQ-54 — Noise system calibration per segment._ On MovieLens and RateYourMusic, split items into head and long-tail by popularity (Park & Tuzhilin boundary). Apply chopping and Laplace DP noise at varying parameters for each segment. Measure Precision@K, NDCG, long-tail discovery rate, and privacy-utility curve per segment. Expected output: recommended noise mechanism and parameters per segment. Effort: moderate. Note: if content-based bootstrapping (§13) is available for long-tail items, the effective signal density for those items improves, shifting where chopping and Laplace diverge — the experiment should be run both with and without content bootstrapping.

_OQ-49 — Oversight chain depth limit._ **Structural question closed** by Chernoff bound argument (see §4.9.8, §10.2). Empirical calibration of K_0 and ΔK remains: simulate recursive oversight chains under varying adversarial committee compositions to produce a recommended depth limit and escalation schedule. Effort: high.

_OQ-52 — Stalling minority damage._ Simulate a stalling minority at varying committee sizes. Measure damage accumulation before the oversight chain resolves. Expected output: a damage bound as a function of minority size and epoch duration. Effort: moderate.

---

## 11. Comparative Analysis

### 11.1 Identity and Privacy Properties

| System                               | No central server                     | Pseudonymous identity                  | Admission cost          | Behavioral privacy                         | Deployment               |
| ------------------------------------ | ------------------------------------- | -------------------------------------- | ----------------------- | ------------------------------------------ | ------------------------ |
| **EigenTrust**                       | Partial (DHT)                         | No                                     | None                    | None                                       | Research                 |
| **TrustGuard**                       | Yes                                   | No                                     | None                    | None                                       | Research                 |
| **SybilGuard**                       | Yes                                   | No                                     | None                    | None                                       | Research                 |
| **DSybil**                           | Partial                               | No                                     | None                    | None                                       | Research                 |
| **McSherry & Mironov (2009)**        | No (central required for aggregation) | No                                     | None                    | ε-DP formal bound on aggregation phase     | Research (Netflix-scale) |
| **GOSSPLE**                          | Yes                                   | Weak (proxy, long-term linkable)       | None                    | Bloom filter digests only; no formal bound | Research (PlanetLab)     |
| **Hegedűs et al. (2020)**            | Yes                                   | No                                     | None                    | None (model params in plaintext)           | Research                 |
| **Web3Recommend + MeritRank (2023)** | Yes                                   | Pseudonym (persistent edges, linkable) | None                    | None                                       | PoC (MusicDAO)           |
| **Unified DP-DL MF (2025)**          | Yes                                   | No                                     | None                    | GDP formal (LDP / PNDP / SecLDP)           | Research                 |
| **PrivaCF (Loopix profile)**         | Yes                                   | Yes (Poseidon PRF + EC-VRF)            | VDF chain + checkpoints | Chopping/Laplace + ZK + niche delay + GPA-resistant transport          | PoC                      |
| **PrivaCF (Tor/I2P profile)**        | Yes                                   | Yes (Poseidon PRF + EC-VRF)            | VDF chain + checkpoints | Chopping/Laplace + ZK + niche delay (no GPA resistance at transport)   | Spec only                |

The two PrivaCF rows reflect the transport profile choice in §5.1. Profile-independent properties (identity rotation, admission cost, content-level chopping/Laplace, ZK preference privacy) are identical across rows; the differentiator is wire-level anonymity against a global passive adversary.

### 11.2 Sybil Resistance and Audit Properties

| System                               | Sybil resistance                                                                                                                                        | On-chain verdicts | Suspension persistence      | Dark node closure   | Observable extraction         | Recommendation output              |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------------------------- | ------------------- | ----------------------------- | ---------------------------------- |
| **EigenTrust**                       | None                                                                                                                                                    | No                | N/A                         | N/A                 | N/A                           | No                                 |
| **TrustGuard**                       | Oscillation detection                                                                                                                                   | No                | N/A                         | N/A                 | N/A                           | No                                 |
| **SybilGuard**                       | Graph-cut                                                                                                                                               | No                | N/A                         | N/A                 | N/A                           | No                                 |
| **DSybil**                           | Non-overwhelming rule (heuristic in PrivaCF's setting)                                                                                                  | No                | N/A                         | N/A                 | N/A                           | Partial                            |
| **McSherry & Mironov (2009)**        | None                                                                                                                                                    | No                | N/A                         | N/A                 | N/A                           | Yes (Netflix-scale)                |
| **GOSSPLE**                          | None (certs assumed externally)                                                                                                                         | No                | N/A                         | N/A                 | N/A                           | Yes (empirical)                    |
| **Hegedűs et al. (2020)**            | None                                                                                                                                                    | No                | N/A                         | N/A                 | N/A                           | Yes (gossip MF, empirical quality) |
| **Web3Recommend + MeritRank (2023)** | Formal ratio bound (random-walk setting)                                                                                                                | No                | None                        | N/A                 | N/A                           | Yes (MusicDAO PoC)                 |
| **Unified DP-DL MF (2025)**          | None                                                                                                                                                    | No                | N/A                         | N/A                 | N/A                           | No                                 |
| **PrivaCF (Loopix profile)**         | Non-overwhelming trust cap + temporal depth + k_min/ε-DP impact bounding + content-based PSI-similarity flagging (§7.4) + epoch-granular behavioral signals + mix-layer density signals. Sub-epoch timing signals unavailable. Empirical calibration deferred to Phase 5 (OQ-10).        | Yes (permanent)   | Hard (nullifier + SUSP_SMT) | Yes — ForwardCommit | Yes — commit-reveal, watchdog | Yes                                |
| **PrivaCF (Tor/I2P profile)**        | Non-overwhelming trust cap + temporal depth + k_min/ε-DP impact bounding + full behavioral clustering (§6.2 4-tuple fingerprint) + sub-epoch coordination detection + PSI-similarity flagging. Mix-layer signals unavailable. Empirical calibration deferred to Phase 5 (OQ-10).         | Yes (permanent)   | Hard (nullifier + SUSP_SMT) | Yes — ForwardCommit | Yes — commit-reveal, watchdog | Yes                                |

### 11.3 Narrative Analysis

**Against the P2P reputation baselines (EigenTrust, TrustGuard, SybilGuard, DSybil):** each addresses one or two of the three core tensions — personalization, privacy, integrity — but none address all three. None provide pseudonymous identities, on-chain verdicts, or suspension persistence. DSybil provides a partial non-overwhelming trust bound but no privacy guarantees and no recommendation output. PrivaCF's contributions over these baselines are clear: rotating pseudonymous identity with cryptographic unlinkability; admission cost via sequential VDF; preference privacy via Pedersen commitments and gossip vector obfuscation; behavioral privacy via Merkle-committed history with ZK consistency proofs; permanent on-chain suspension verdicts surviving epoch rotation via the nullifier mechanism; dark node closure via forward-secure commitment; and observable extraction via commit-reveal ordering with public watchdog signals.

Graph-cut detection as used in SybilGuard and SybilLimit is structurally unavailable in PrivaCF due to the ephemeral peer relationship model — no persistent graph exists to cut. The behavioral consequences of solipsistic cluster structure are observable without explicit graph visibility through the compound flag system (§7.1a T.7, §7.8), at the cost of a behavioral-probabilistic rather than graph-cut deterministic guarantee. The tradeoff is intentional.

**Against McSherry & Mironov (2009):** this is the strongest comparison on privacy formalism. Their system achieves formal ε-DP for the Netflix Prize algorithms but requires a central server for the aggregation phase — the core architectural trade-off PrivaCF rejects. PrivaCF cannot currently make a comparable formal privacy claim. OQ-55 investigates whether the GDP framework from Cyffers et al. (2025) can close this gap for PrivaCF's gossip exchange without reintroducing central aggregation.

**Against GOSSPLE:** structurally closest to PrivaCF's gossip peer discovery. GOSSPLE uses Bloom filter digests over proxy-based two-hop paths to find interest-similar peers without revealing identity, validated empirically on PlanetLab. The anonymity is weak — proxy paths are linkable over time and no Sybil resistance exists. PrivaCF replaces the proxy with PSI (stronger non-revelation), adds identity rotation, admission cost, and the full audit stack. GOSSPLE's convergence results (~14–20 gossip cycles to stable peer sets) provide a useful lower-bound expectation for PrivaCF's PSI-based discovery phase.

**Against Hegedűs et al. (2020):** their gossip-based matrix factorization on fully distributed data — no central server, model parameters exchanged peer-to-peer — achieves comparable quality to federated learning. This directly validates that decentralized gossip is a viable substrate for CF quality. PrivaCF's gossip vector approach is architecturally similar but trades MF-level accuracy for stronger preference privacy (gossip vectors vs. raw latent factors). OQ-56 formalizes this comparison: whether PrivaCF's item-based CF on accumulated vectors matches Hegedűs-style MF under matched sparsity, giving PrivaCF its first empirical quality benchmark.

**Against Web3Recommend + MeritRank (2023):** the closest architectural competitor. Fully decentralized, gossip-based, Sybil-resistant, with a PoC deployment on a real music platform. MeritRank's formal ratio bound (`lim|S|→∞ w⁺/w⁻ ≤ c`) is a tighter formal statement than PrivaCF currently claims. The critical difference: Web3Recommend operates under pseudonyms with persistent graph edges — any observer can reconstruct the full trust graph and link identities across time. PrivaCF closes this with epoch rotation, arbitration-committee custody of sensitive state, and the nullifier mechanism. Web3Recommend also has no suspension persistence, no dark node closure, and no formal admission cost. The MeritRank ratio bound is being adapted as Path B for OQ-10.

**Against Unified DP-DL MF (2025):** provides formal GDP bounds for decentralized learning under three trust models. Their SecLDP model — privacy conditional on a hidden secret — maps directly onto PrivaCF's permutation-secret gossip exchange (the permutation key is the hidden secret; n_v(T) elements are the partially observable output). This is the technical basis for OQ-55. PrivaCF's Mafalda-SGD-equivalent would be the gossip vector chopping + Laplace noise mechanism; deriving the corresponding GDP bound would give PrivaCF its first formal privacy guarantee without architectural changes.

**Summary of residual gaps:** PrivaCF is the only system in this comparison with unlinkable rotating identity, suspension persistence, dark node closure, and decentralized operation simultaneously. The gaps are: no formal privacy bound (OQ-55 targets this), no formally proven Sybil influence bound (OQ-10 reframed as empirical — structural bounds established, flag probability terms require live deployment data), and no empirical recommendation quality benchmark (OQ-56). The residual architectural gap is threshold collusion for off-chain nullifier extraction, bounded by the same Byzantine majority assumption the consensus layer already depends on.

**Transport-profile design choice.** PrivaCF defines two transport profiles (§5.1) rather than mandating one — Loopix profile prioritizes wire-level anonymity, Tor/I2P profile prioritizes Sybil-detection signal richness. The choice reflects an explicit acknowledgement that anonymity-set strength and behavioral observability are antagonistic at the wire layer; instead of picking one absolute ranking, the spec lets each deployment choose. No other system in this comparison exposes this choice as a deployment-time decision: most mandate clearnet (and therefore implicitly Tor-equivalent observability), and McSherry & Mironov mandate central aggregation. The profile-based framing is novel as a comparative axis.

---

## 12. Related Work

| Reference                                                       | Relevance                                                                                                                                                                                                        |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Douceur (IPTPS 2002)                                            | Sybil attack definition and impossibility                                                                                                                                                                        |
| Cheng & Friedman (P2PEcon 2005)                                 | Sybil-proofness impossibility for symmetric functions                                                                                                                                                            |
| Kamvar, Schlosser & Garcia-Molina (WWW 2003)                    | EigenTrust                                                                                                                                                                                                       |
| Srivatsa, Kambhampati & Liu (ICDCS 2005)                        | TrustGuard — oscillation detection; asymmetric penalty                                                                                                                                                           |
| Yu, Kaminsky, Gibbons & Flaxman (SIGCOMM 2006)                  | SybilGuard                                                                                                                                                                                                       |
| Stannat, Ileri, Gijswijt & Pouwelse (AAMAS 2021)                | Sufficient conditions for personalized-seed Sybil resistance                                                                                                                                                     |
| Yu, Kaminsky, Gibbons & Flaxman (IEEE S&P 2009)                 | DSybil non-overwhelming trust                                                                                                                                                                                    |
| Viswanath, Becker, Gummadi & Mislove (IEEE S&P 2008)            | SybilLimit                                                                                                                                                                                                       |
| Tran, Min, Li & Subramanian (NDSS 2009)                         | SybilInfer                                                                                                                                                                                                       |
| Damiani et al. (2002)                                           | Reputation-based P2P trust                                                                                                                                                                                       |
| Fanti et al. (SIGMETRICS 2018)                                  | Dandelion++                                                                                                                                                                                                      |
| Pinkas, Rosulek, Trieu & Yanai (USENIX Security 2018)           | Unbalanced PSI                                                                                                                                                                                                   |
| Kolesnikov et al. (CCS 2016)                                    | KKRT circuit PSI (balanced)                                                                                                                                                                                      |
| Malkov & Yashunin (2018)                                        | HNSW                                                                                                                                                                                                             |
| Indyk & Motwani (STOC 1998)                                     | LSH                                                                                                                                                                                                              |
| McSherry & Mironov (KDD 2009)                                   | Differentially private CF                                                                                                                                                                                        |
| Parsarad & Wagner (2025)                                        | DP harm to sparse user recommendations                                                                                                                                                                           |
| Dwork, Rothblum & Vadhan (2010)                                 | Basic DP composition theorem                                                                                                                                                                                     |
| Werthenbach & Pouwelse (arXiv:2306.15044, 2023)                 | SSP attack taxonomy                                                                                                                                                                                              |
| Nasrulin et al. (IEEE BRAINS 2022)                              | MeritRank                                                                                                                                                                                                        |
| Sun, Han & Liu (2008)                                           | Asymmetric penalty mechanism                                                                                                                                                                                     |
| Fung et al. (RAID 2020)                                         | FoolsGold — Sybil detection via contribution vector similarity; not adopted (incompatible with privacy stack, see §7.4)                                                                                          |
| Perrin (2018)                                                   | Noise Protocol Framework                                                                                                                                                                                         |
| Jøsang & Ismail (2002)                                          | Beta Reputation System                                                                                                                                                                                           |
| Maram et al. (CCS 2021)                                         | CanDID — distributed credential storage                                                                                                                                                                          |
| Boneh et al. (2018)                                             | VDF constructions                                                                                                                                                                                                |
| Wesolowski (2018)                                               | Efficient VDF verification                                                                                                                                                                                       |
| Castro & Liskov (OSDI 1999)                                     | PBFT                                                                                                                                                                                                             |
| Buchman (2016)                                                  | Tendermint BFT consensus                                                                                                                                                                                         |
| Boneh, Drijvers & Neven (2018)                                  | BLS multi-signatures                                                                                                                                                                                             |
| Arshad et al. (IEEE Access 2022)                                | REPUTABLE                                                                                                                                                                                                        |
| Anonymous (J. Sens. Actuator Netw. 2023)                        | Blockchain + MPC decentralized reputation                                                                                                                                                                        |
| Shi, Zhang, Yin, Chi & Liu (Results in Engineering 2025)        | DSRep                                                                                                                                                                                                            |
| Möser et al. (2018)                                             | Monero transaction graph analysis; decoy selection distribution                                                                                                                                                  |
| Sasson et al. (IEEE S&P 2014)                                   | Zcash — nullifier pattern for spent-note detection                                                                                                                                                               |
| WhiteHat (2019)                                                 | Semaphore — ZK group membership with nullifiers                                                                                                                                                                  |
| Boneh, Bünz & Fisch (CRYPTO 2019)                               | Batched accumulator witnesses; SMT non-membership                                                                                                                                                                |
| Grassi, Khovratovich et al. (USENIX Security 2021)              | Poseidon hash function                                                                                                                                                                                           |
| Camenisch & Lysyanskaya (Eurocrypt 2001)                        | Traceable anonymous credentials                                                                                                                                                                                  |
| Chaney, Stewart & Engelhardt (2018)                             | Recommendation feedback loops and filter bubble dynamics                                                                                                                                                         |
| Adomavicius & Tuzhilin (2005)                                   | CF assumptions survey                                                                                                                                                                                            |
| Hu, Koren & Volinsky (2008)                                     | Implicit feedback limitations                                                                                                                                                                                    |
| Leskovec, Adamic & Huberman (2007)                              | Information diffusion patterns, organic vs. coordinated spread                                                                                                                                                   |
| Blanchard et al. (2017)                                         | Byzantine-resilient aggregation (Krum)                                                                                                                                                                           |
| Sundaram & Hadjicostis (2011)                                   | Resilient distributed averaging                                                                                                                                                                                  |
| Holland, Laskey & Leinhardt (1983)                              | Stochastic block models — suggested framework for OQ-10 Path A                                                                                                                                                   |
| Boneh, Lynn, Shacham (ASIACRYPT 2001)                           | BLS signatures — threshold BLS used in commit-reveal flow                                                                                                                                                        |
| Pedersen (CRYPTO 1991)                                          | Verifiable secret sharing — basis for commit-reveal scheme                                                                                                                                                       |
| Siddarth, Ivliev, Siri & Berman (Frontiers in Blockchain, 2020) | "Who Watches the Watchmen?" — survey of subjective approaches to Sybil-resistance; frames the "who verifies the verifier" regress that the recursive oversight chain addresses                                   |
| Park & Tuzhilin (RecSys 2008)                                   | Formal head/long-tail popularity split in CF evaluation; basis for head/long-tail segmentation in §9.3 and OQ-54                                                                                                 |
| Abdollahpouri, Burke & Mobasher (FLAIRS 2019)                   | Popularity bias and re-ranking in recommender systems; head/long-tail framing                                                                                                                                    |
| Kermarrec, Van Roy, Ganesh & Voulgaris (MIDDLEWARE 2010)        | GOSSPLE — gossip-based anonymous social network using Bloom filter digests and proxy routing for interest-similar peer discovery; convergence results (~14–20 cycles) bound PrivaCF's PSI discovery expectations |
| Hegedűs, Danner & Jelasity (ECML PKDD 2019)                     | Gossip-based matrix factorization on fully distributed data; empirically comparable to federated learning; basis for OQ-56 CF quality benchmark                                                                  |
| Trautwein, Ishmaev & Pouwelse (arXiv:2307.01411, 2023)          | Web3Recommend — decentralized social recommendation with MeritRank Sybil resistance; formal ratio bound `lim\|S\|→∞ w⁺/w⁻ ≤ c`; basis for OQ-10 Path B; persistent graph linkability is the key gap vs. PrivaCF  |
| Cyffers et al. (arXiv:2510.17480, 2025)                         | Unified GDP bounds for decentralized learning via matrix factorization; SecLDP trust model maps onto PrivaCF's permutation-secret gossip exchange; basis for OQ-55                                               |
| Stringhini et al. (ACSAC 2010)                                  | OSN bot detection — temporal clustering on join and action as persistent signals; basis for T.1 and T.2 in §7.1a                                                                                                 |
| Yang et al. (WWW 2014)                                          | Spambot evolution across three generations — temporal clustering survives content diversification; behavioral similarity degrades with randomization; basis for T.1, T.2, T.4                                    |
| Mukherjee et al. (WWW 2013)                                     | Yelp review fraud — velocity as strongest discriminator of fake campaigns; basis for T.8                                                                                                                         |
| Urdaneta et al. (ACM Computing Surveys 2011)                    | DHT sybil studies — temporal clustering on join; basis for T.1                                                                                                                                                   |
| Varol et al. (ICWSM 2017)                                       | Bot detection across six categories — action timing among top predictors; trajectory smoothness as indirect predictor; basis for T.2 and T.5                                                                     |
| Cao et al. (IMC 2012)                                           | Pairwise similarity distributions of sybil clusters — lower variance, higher mean than legitimate clusters; basis for T.4                                                                                        |
| Hoffman et al. (ACM Computing Surveys 2009)                     | Whitewashing as dominant evasion strategy in P2P reputation systems; basis for T.6                                                                                                                               |

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

## 14. Beyond Recommendations: Decentralized Learning Profile

The substrate (§4–§7) is not specific to recommendation. The same machinery — pseudonymous rotating identity with cross-epoch continuity, PSI peer neighborhoods, trust-weighted contribution aggregation, FoolsGold-on-PSI-peers Sybil suppression, and the Loopix transport — describes a general **privacy-preserving, Sybil-resistant contribution aggregation protocol**. Recommendation is one instantiation. Decentralized learning is another.

This section stakes the claim without specifying the protocol. A full DL profile is out of scope for v0.3.1; the goal here is to make the substrate's scope explicit and to record what would be required to host a DL workload.

### 14.1 Why DL fits the substrate

In decentralized learning (Lian et al., NeurIPS 2017; Hegedűs, Danner & Jelasity, ECML PKDD 2019; Bittensor) peers exchange model updates directly without a central aggregator. Convergence depends on a mixing matrix that propagates each peer's gradient through the network, and on Sybil-resistance over the contribution pool. Both are problems the substrate already solves for the recommendation case:

| Recommendation construct | Decentralized learning analogue |
|---|---|
| Preference vector `p_v` | Local gradient or weight delta `g_v` |
| PSI on item-interaction sets | PSI / similarity on gradient direction or local data distribution |
| `trust_weight(v)` over peers | Per-peer aggregation weight |
| Gossip vector push | Gradient push to PSI peer neighborhood |
| `announcement_token` rate limit | Per-round update budget per pseudonymous client |
| FoolsGold-on-PSI-peers (§7.4) | Direct Sybil defense — FoolsGold was originally a federated-learning defense |
| Handoff state (§6.4) | Optimizer state / momentum carry-over across epoch rotations |
| Cross-epoch continuity (§4.7) | Stable per-client contribution history without persistent linkability |
| Content-addressed item payloads | Content-addressed model artifacts (architectures, base weights, training scripts) |

FoolsGold's presence in §7.4 is the clearest tell: the protocol already runs a federated-learning Sybil defense over PSI peer neighborhoods. The construction transfers directly when the contribution is a gradient rather than a preference endorsement.

### 14.2 What the substrate would need to add

A DL profile is not a free upgrade. At minimum:

- **Secure aggregation.** Recommendation tolerates peers seeing each other's contributions through PSI — preferences are coarse-grained and obfuscated (§4.5). Gradients leak training-data reconstruction via gradient-inversion attacks (Geiping et al., NeurIPS 2020), so a DL profile must layer Bonawitz-style masked aggregation or homomorphic accumulation over the gossip exchange. The Loopix transport and the multi-recipient commit_T construction (§4.9) compose cleanly with masked aggregation but neither substitutes for it.
- **Distribution-aware peer selection.** Recommendation peer selection uses PSI on item-interaction sets — overlap predicts taste similarity. DL convergence under non-IID data requires peers whose distributions are heterogeneous enough to propagate signal across the network. The PSI primitive applies; the selection criterion inverts.
- **Model-artifact distribution.** Items in the recommendation case are content-addressed and pulled out of band. Model artifacts (architectures, base weights, training scripts) follow the same pattern but at substantially larger size. No protocol change is required, but a deployment must provide content-addressed storage sized for model artifacts.
- **Convergence accounting.** Recommendation quality is judged at any time by the local node. DL workloads converge over rounds; the substrate must expose round-aligned epochs (the existing epoch boundary suffices) and a way to publish "model at round T" as a content-addressed artifact for late-joining clients to bootstrap from.
- **Reward / contribution accounting (if incentivized).** Bittensor-style economic incentives over decentralized training require a contribution-quality signal. The per-epoch score (§6.1) is the natural anchor — adapted from "endorsement uptake" to "gradient quality / convergence contribution" — but the formula is a deployment choice.

### 14.3 Privacy and Sybil properties under a DL profile

All substrate guarantees survive a DL profile unchanged:

- IP↔epoch_id unlinkability (§5.1) holds — gradients are transmitted over the same transport.
- Cross-epoch contribution unlinkability without `sk` (§4.2) holds.
- DSybil + FoolsGold + temporal depth (§7) directly defend the aggregation step.
- The compound flag system (§7.8) reuses unchanged.

The DL-specific risk added beyond the recommendation case is **gradient inversion** — a per-message rather than per-protocol risk — which the secure-aggregation requirement above is exactly designed to address.

### 14.4 Status

Stated, not specified. A v0.4 or later revision may define a normative DL profile if the recommendation deployment validates the substrate. The framing here is to make explicit that the substrate's scope is broader than recommendation, and that the project's "post-big-tech" positioning extends naturally to model training — the domain where centralized compute monopolies are most entrenched and decentralized alternatives are most needed.

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
  "sig":          "<Sign(epoch_id, H(merkle_proof ‖ zk_proof ‖ audit_nonce ‖ T))>"
  // audit_nonce binds this response to the specific challenge instance,
  // preventing the committee from substituting a proof from a different audit
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
      "RATE_LIMIT":           "<n>"
  },
  "susp_smt_root_ref":        "<SUSP_SMT_root_T>",
  "commit_T":                 "<ADOPTED publish-s₁: ( s₁ (public),  d_T = VerEnc(s₂,'VERDICT_FINALIZED epoch_id_T',VA_pub;r) ),  s₁+s₂=null_v.  2-of-2 profile: ( c_T^{(0..N_fallback−1)} = ForwardCommit(s₁,'SUSPEND epoch_id_T',threshold_BLS_pk_T^{(i)};r),  d_T )>",
  "successor_zk_proof":       "<proof: valid successor + leaf count consistency + Statement 5 (publish-s₁: split with public s₁ + d_T VerEnc binding + SMT non-membership) + PSI acknowledgment witnesses>",
  "rolling_chain_commitment": "<Poseidon(prior_chain ‖ current_proof ‖ audit_interactions ‖ SUSP_SMT_root_T)>",
  "zk_continuity_proof":      "<arbitration committee only — not in public handoff>",
  "encrypted_shares":         ["<Encrypt(pk_auditor_i, shamir_share_i)>", "..."],
  "sig":                      "<Sign(epoch_id, H(all fields ‖ T))>"
}

// ON-CHAIN EPOCH TRANSACTION
{
  "type":              "epoch_transaction",
  "epoch_id":          "<node epoch ID>",
  "commit_T":          "<ADOPTED publish-s₁: ( s₁ public, d_T = VerEnc(s₂) to VA_pub ) — every epoch, exempt from n_commit.  2-of-2 profile: ( committee ciphertexts of s₁, d_T )>",
  "commit_T_zk_proof": "<Statement 5 ZK proof — every epoch>",
  // 2-of-2 profile only: "threshold_bls_pk_T": "<committee threshold BLS public key for this epoch>" (no committee threshold key under publish-s₁)
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
  // ADOPTED publish-s₁: the reveal is a verdict VOTE (no decryption share); members attest by aggregate multisig.
  // bls_share_i is present ONLY in the 2-of-2 profile, where the committee aggregates σ_i^SUSPEND to recover s₁:
  "bls_share_i":           "<2-of-2 profile only: BLS secret share contribution>",
  "verdict":               "SUSPENDED | PASS",
  "nonce_i":               "<random nonce>",
  "sig":                   "<Sign(committee_member_id, H(verdict ‖ nonce_i ‖ T))  [2-of-2: also binds bls_share_i]>"
}

// ON-CHAIN NULL_V DECRYPTION
{
  "type":            "null_v_decryption",
  "verdict_hash":    "<H(committee_verdict_transaction)>",
  "epoch_id":        "<suspended node's last epoch_id>",
  "null_v":          "<recovered nullifier value>",
  "dec_nullifier":   "<Poseidon(verdict_hash, null_v)>",
  // ADOPTED publish-s₁: s₁ is read from the public commit_T; only the validator attestation is needed.
  "sigma_verdict":   "<validator threshold signature σ_T^VERDICT on 'VERDICT_FINALIZED epoch_id_T'>",
  // "sigma_suspend": 2-of-2 profile only — aggregated committee threshold BLS sig on 'SUSPEND epoch_id_T' (recovers s₁)
  "proof":           "<Verify(VA_pub, 'VERDICT_FINALIZED epoch_id_T', sigma_verdict) = true
                       AND VerEnc.Verify(d_T, s₂, sigma_verdict) = true
                       AND s₁ + s₂ = null_v = true              (s₁ from public commit_T)
                       [2-of-2 profile also: Verify(threshold_BLS_pk_T,'SUSPEND epoch_id_T',sigma_suspend)
                        AND ForwardCommit.Verify(c_T^{(i)}, s₁, sigma_suspend)]>"
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

// ON-CHAIN AUDIT RESULT (Class 3)
{
  "type":            "audit_result_c3",
  "committee_ids":   ["<member epoch IDs>"],
  "target_id":       "<audited node epoch ID>",
  "audit_epoch":     "<T>",
  "challenged_T":    "<suspect epoch>",
  "audit_nonce":     "<Poseidon(beacon ‖ 'c3_nonce' ‖ committee_epoch_id)>",
  "result":          "pass | fail | no_response",
  "merkle_proof":    "<node's submitted branch paths — omitted if no_response>",
  "zk_proof":        "<node's submitted Plonky3 proof for Stmts 1–3 and 5 — omitted if no_response>",
  "node_sig":        "<node's Sign(epoch_id, H(merkle_proof ‖ zk_proof ‖ audit_nonce ‖ T)) — omitted if no_response>",
  "committee_sig":   "<threshold BLS aggregate signature on H(all fields)>"
  // Validators reject this transaction if result = fail and merkle_proof,
  // zk_proof, or node_sig are absent. A bare committee signature on a
  // failure verdict is not sufficient.
}

// ON-CHAIN ADMISSION SUMMARY
{
  "type":          "admission_summary",
  "epoch_id":      "<admitting node epoch ID>",
  "admitted":      "true | false",
  "admitted_T":    "<epoch>",
  "committee_sig": "<threshold BLS sig>"
}

// ARBITRATION COMMITTEE — FIRST OBSERVATION REPORT
{
  "type":              "first_observation",
  "observer_id":       "<existing node epoch ID>",
  "new_epoch_id":      "<admitting node epoch ID>",
  "first_seen_T":      "<epoch>",
  "first_seen_offset": "<seconds within epoch>",
  "provider_id":       "<mix-role provider ID under Loopix profile, Tor exit identity under Tor/I2P profile — coarse geographic prior, see §5.1>",
  "channel":           "chain | gossip | PSI",
  "observer_sig":      "<Sign(observer_id, H(report))>"
}

// ARBITRATION COMMITTEE — ZK CONTINUITY PROOF
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

// PSI ACKNOWLEDGMENT (cross-cluster attempt receipt)
{
  "type":        "psi_ack",
  "responder_id":"<responder epoch ID>",
  "epoch_T":     "<T>",
  "ack_nonce":   "<Poseidon(sk_initiator, responder_id, T, \"psi_ack\") — binds the ack to the initiator so it is non-transferable across a sybil ring; the initiator proves knowledge of the sk behind each nonce in the handoff witness, staying pseudonymous to the responder (OQ-61)>",
  "sig":         "<Sign(responder_id, H(ack_nonce ‖ T))>"
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
| `r_commit_T`        | Blinding factors for the committee ciphertexts `c_T^{(i)}` this epoch                   |
| `r_commit_d_T`      | Blinding factor for the validator ciphertext `d_T` this epoch                           |
| `s₁`, `s₂`          | Additive shares of `null_v` (`s₁ + s₂ = null_v`); `s₂` is the fresh per-epoch randomness |
| `p_v`               | Full signed preference vector. Updated only at epoch transitions                        |
| `r_p`               | Pedersen blinding factor. Losing it locks out Class 3 audit responses for that identity |
| `π_v(T)`            | Per-epoch permutation                                                                   |
| Interaction history | Raw log. Aggregated into Merkle leaves; raw data stays local                            |
| `q_v(T)`            | Local acceptance rate                                                                   |
| HNSW snapshots      | Periodic snapshots retained for rewind recovery                                         |
| PSI cache           | Per-peer Jaccard similarity scores and ZK continuity weights                            |
| PSI acknowledgments | Received cross-cluster PSI acknowledgments, retained as ZK witnesses for handoff proof  |
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

**Held by the arbitration committee — under threshold custody, accessible only on quorum:**

| Item                         | What it contains                                                         |
| ---------------------------- | ------------------------------------------------------------------------ |
| ZK continuity proofs         | Links `epoch_id_T` to `epoch_id_{T-1}`                                   |
| Fine-grained behavioral data | Per-epoch timing distributions, audit response rates                     |
| Handoff history              | Encrypted state chain for each node under audit                          |
| First-observation reports    | Observer timing data and provider_id for coordinated admission detection |
| Raw score                    | Full computed score per epoch                                            |

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
  Score held under arbitration committee custody; band attestation → public chain

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
      First-observation reports submitted to arbitration committee only (including provider_id)
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
  ├── Split null_v = s₁ + s₂ (mod p); construct commit_T = (
  │       c_T^{(i)} = BF-IBE.Encrypt(s₁, "SUSPEND epoch_id_T",           threshold_BLS_pk_T^{(i)}; r_commit_T),
  │       d_T       = BF-IBE.Encrypt(s₂, "VERDICT_FINALIZED epoch_id_T", VA_pub;                   r_commit_d_T) )
  ├── Generate Statement 5 ZK proof (4 checks + SMT path)
  ├── Optional ZK continuity proof (arbitration committee only)
  ├── Refresh bridge peer (DHT + Loopix provider)
  ├── Update PSI cache (λ_proof or λ_noproof)
  └── Store HNSW snapshot if snapshot interval reached

  DURING EPOCH
  ├── Push gossip vector at T_send (first 30% of epoch, randomized)
  ├── Pull from peers — embed Class 2 audit nonce in every pull request
  ├── Respond to pulls — embed audit hash + receipt signature in every response
  ├── Respond to cross-cluster PSI attempts — issue signed psi_ack regardless of handshake outcome
  ├── Collect received psi_ack messages as ZK witnesses for handoff proof
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
  │   + PSI acknowledgment witnesses (cross-cluster attempt rate proof)
  │   ZK continuity proof submitted to arbitration committee only
  ├── Distribute handoff to committee via Dandelion++ stem
  ├── Await committee threshold signature
  ├── If commit epoch (T mod n_commit = 0):
  │   Submit M_v, C_p, score band, health tier via relay → public chain
  ├── If Class 3 audit pending: submit Merkle + ZK proof (Stmts 1–3, 5) via stem with retry
  │   If rewind confirmed: roll back HNSW to preferred_T snapshot
  │                        discard gossip vectors from implicated cohort
  ├── Compute score_v(T) — held under arbitration committee custody
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

  COMMITTEE (burst score aggregation)
  └── At end of each admission window:
      Aggregate first_seen_T and first_seen_offset across first-observation reports
      Aggregate provider_id distributions
      Compute burst score over inter-arrival timing distributions
      Compute geographic concentration signal
      Both enter compound flag system at L1 only
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
  Laplace DP (S=2, clamp-bounded)  trivial; clamp+renormalize post-processing (§4.5)
  BLS signatures                   blst crate
  Item-based CF                    standard linear algebra
  Dislike-aware CF                 trivial post-processing
  Uniform frame padding            trivial
  Peer attestation collection      trivial — receipts in pull responses
  Per-n-epoch commit batching      trivial epoch counter
  Rewind signal cohort correlation local HNSW provenance tracking
  provider_id field in first-obs   trivial schema extension
  Burst score aggregation          committee-side inter-arrival computation over first-observation reports
  PSI acknowledgment message       new message type; signed; rate-limited (OQ-61)
  PSI ack witness collection       local retention; fed into handoff ZK proof

TIER 2 — Adapt prior work
  Tendermint-style BFT             tendermint-rs; VRF proposer + VDF-chained
  BLS threshold aggregation        blst; threshold scheme
  Double-signing detection         Standard BFT; epoch_id key structure
  Light client headers + proofs    Standard Merkle SPV
  Genesis transition protocol      Bootstrap behavioral cluster relaxation
  Asymmetric PSI (Pinkas 2018)     Unbalanced; Jaccard threshold; Loopix mix-routed with SURB
  PSI cache asymmetric decay       Jøsang & Ismail basis
  Two-tier peer selection          Cluster + bridge logic; bridge weight opt-out
  Class 2 passive audit            Nonce-in-pull; hash-in-response
  Auditor handoff flow             Successor ZK proof + Statement 5 + PSI ack witnesses
  Multi-auditor committee          VRF with dual cluster constraints
  DSybil with noisy ratings        Binary fallback option
  k_min impact bounding            PSI neighborhood size gate (§7.4)
  SSP-adapted simulation           Werthenbach & Pouwelse 2023
  Trust attenuation by hop         Stannat et al. AAMAS 2021
  Asymmetric penalty               Sun et al. 2008
  Smoothness detection             Srivatsa et al. 2005; recovery trajectory in test suite
  Relay node batching              VRF selection; reputation integration
  Validator service score bonus    Trivial score component addition
  Commit-reveal verdict flow       Two-phase; ordering enforcement in block validation
  Permissionless BLS aggregation   Standard threshold BLS
  Recursive oversight chain        Meta-committee VRF; same commit-reveal; depth limit
  Item-velocity rewind correlation Cohort_epoch × trust_total velocity compound signal

TIER 3 — Original design required
  Chain + arbitration committee    Single public chain + on-demand threshold-custody committee
  ZK continuity circuit            Plonky3; Poseidon PRF relation; arbitration committee only
  ZK consistency (Stmts 1–3)      Statement 2 requires sign preservation first
  ZK successor proof (handoff)     C_p + M_v successor + leaf count + Statement 5 + PSI ack witnesses
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
  Geographic concentration signal  Provider_id aggregation + compound flag entry

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
  Δ_rise calibration               Path-responsiveness vs. on-off defense (OQ-6, §8.2 T1)
  k_min calibration                Community density profiles; OQ-24
  ZK Statement 2 mobile bench      d=128/256 Plonky3/WASM (OQ-3b)
  ZK successor proof cost          Mobile hardware; includes PSI ack witness cost
  Bootstrap critical mass          Genesis transition; cluster relaxation (OQ-12)
  Validator incentive analysis     Long-term shirking risk (OQ-13)
  Oversight chain termination      Depth limit + damage bound (OQ-49)
  Off-chain collusion bounds       OQ-53
  PSI ack rate limit + privacy     OQ-61 — required before deployment
  Burst score threshold            OQ-59 — Phase 5 experiment 5.48
  Sybil influence empirical data   OQ-10 — Phase 5 + live deployment
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

_All configs: deployment must select a conformant transport profile per §5.1; self-mixing Loopix is the reference default for MVP, Tor/I2P is a specified alternate. Dandelion++ retained for epidemic broadcast (fluff) phase only across profiles. Clearnet: dev/test only. Nullifier mechanism, SUSP_SMT, DECRYPTION_SMT, ForwardCommit, and commit-reveal verdict flow apply universally. commit_T is published every epoch regardless of n_commit setting. Bridge peer weight opt-out is a per-node local setting available in all configs._

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
   │ Peer B      │     │ Peer C       │     │  (weight      │
   │ (PSI ✓)     │     │ (PSI ✓)      │     │   opt-out     │
   └─────────────┘     └──────────────┘     │   available)  │
                                            └───────────────┘

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
   │  Hold Shamir-shared snapshots (threshold custody)    │
   │  Aggregate burst score + provider_id distributions   │
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
│  │  ZK proofs   │── auditor committee only ──► arbitration committee  │
│  │  continuity  │   never on public chain                       │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐    nullifier custody (opaque)                 │
│  │  commit_T    │◄── s₁ → committee, identity SUSPEND epoch_id_T │
│  │  (public)    │    s₂ → validators VA_pub, VERDICT_FINALIZED   │
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
    │                           │ issue signed psi_ack immediately
    │                           │ (regardless of handshake outcome)
    │◄── psi_ack ───────────────┤
    │   (confirms attempt       │
    │    received; no set       │
    │    contents revealed)     │
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
    │                           │
    A retains psi_ack as ZK     │
    witness for handoff proof   │
─────────────────────────────────────────────────────────
```
