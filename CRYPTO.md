# PrivaCF — Cryptographic Primitives Reference

This document explains the cryptographic building blocks used in the PrivaCF specification. It is intended for readers with a general technical background who may not be specialists in the specific constructions PrivaCF relies on. Each entry covers what the primitive is, what property PrivaCF needs from it, and where in the spec it appears.

---

## Index

- [BLS Signatures](#bls-signatures)
- [Byzantine Faults and BFT Consensus](#byzantine-faults-and-bft-consensus)
- [Dandelion++](#dandelion)
- [EC-VRF](#ec-vrf)
- [Loopix / Sphinx](#loopix--sphinx)
- [Merkle Trees and Sparse Merkle Trees](#merkle-trees-and-sparse-merkle-trees)
- [Pedersen Commitments](#pedersen-commitments)
- [Poseidon PRF](#poseidon-prf)
- [PSI (Private Set Intersection)](#psi-private-set-intersection)
- Boneh-Franklin IBE _(placeholder)_
- VDF (Verifiable Delay Function) _(placeholder)_
- Plonky3 / ZK Proof System _(placeholder)_
- BLS12-381 Curve _(placeholder)_

---

## BLS Signatures

**Reference:** Boneh, Lynn & Shacham, "Short Signatures from the Weil Pairing", ASIACRYPT 2001.

### What it is

BLS is a digital signature scheme built on bilinear pairings over elliptic curves. A pairing is a map `e(P, Q) → F` that takes two points from different elliptic curve groups and produces an element of a third group, with the property that it interacts predictably with scalar multiplication:

```
e(a·P, Q) = e(P, a·Q) = e(P, Q)^a
```

This algebraic structure gives BLS two properties that most signature schemes do not have:

**Aggregation.** Multiple BLS signatures on the same message — produced by different private keys — can be combined into a single signature of the same size. A verifier can check the aggregate against the combined public key without seeing the individual signatures. This is how validator sets in PrivaCF sign blocks without producing O(K) signatures per block.

**Threshold signing (Shamir + BLS).** A private key can be split into `n` shares using Shamir secret sharing such that any `t` shares suffice to reconstruct a valid signature, but fewer than `t` shares reveal nothing about the key. Each shareholder signs independently; the `t` partial signatures are combined into one valid aggregate. No party ever holds the full private key.

### What PrivaCF needs from it

PrivaCF uses threshold BLS in two distinct roles:

1. **Validator block finality (§4.1).** The validator set for each epoch is VRF-selected. Validators sign the proposed block with their individual BLS keys; once `⌊K_validators/3⌋ × 2 + 1` signatures are collected, they are aggregated into a single compact signature included in the block header. Deterministic finality follows immediately.

2. **Nullifier decryption via IBE, with a 2-of-2 verdict-binding split (§4.9.4, §4.9.6).** `null_v` is additively split into `s₁ + s₂`. The committee's threshold BLS keypair is the IBE master key for `s₁` under identity `"SUSPEND epoch_id_T"`; a standing validator-attestation key `VA_pub` is the IBE master key for `s₂` under identity `"VERDICT_FINALIZED epoch_id_T"`. On a suspension verdict, the committee publishes its BLS shares (aggregating to the decryption key for `s₁`) **and** the validator set publishes its threshold attestation `σ_T^VERDICT` (the decryption key for `s₂`) as a canonical part of finalizing the verdict block. Only the combination recovers `null_v = s₁ + s₂`. This is what gives **forward secrecy**: a committee compromise — present or future — yields only `s₁`; `s₂` is released solely by a public verdict, and an off-chain `VERDICT_FINALIZED` signature is slashable equivocation (§4.1). No committee member needs to be online after publishing its share.

### Security property assumed

Unforgeability under the co-CDH assumption (computational co-Diffie-Hellman on the pairing groups). In practice this reduces to the hardness of the discrete logarithm on BLS12-381, the specific curve PrivaCF targets. This assumption is standard and widely accepted; BLS12-381 is used in Ethereum's beacon chain for the same purpose.

### What it does not provide

BLS signatures are not zero-knowledge. Publishing a BLS share reveals that the holder participated and what their verdict was. This is intentional in PrivaCF's commit-reveal flow: the transparency of share publication is what makes the verdict process publicly auditable.

---

## Byzantine Faults and BFT Consensus

**Reference:** Lamport, Shostak & Pease, "The Byzantine Generals Problem", ACM TOPLAS 1982. Practical instantiation: Castro & Liskov, "Practical Byzantine Fault Tolerance", OSDI 1999.

### Byzantine behavior

A node is said to behave *Byzantine* when it deviates arbitrarily from the protocol — not just crashing or going silent, but actively misbehaving: sending conflicting messages to different peers, lying about its state, selectively omitting information, or colluding with other malicious nodes. The name comes from the thought experiment of generals who must coordinate an attack over unreliable messengers, some of whom may be traitors sending contradictory orders to different recipients.

The key distinction from simpler fault models is that a Byzantine node is not merely broken — it is adversarially strategic. A crashed node is easy to handle (it stops sending messages). A Byzantine node may send carefully crafted messages designed to maximally disrupt the system while remaining individually plausible.

### Byzantine fault tolerance (BFT)

A system is *Byzantine fault tolerant* if it continues to reach correct agreement even when some fraction of its participants behave Byzantine. The foundational result (Lamport et al.) is that tolerating `f` Byzantine nodes requires at least `3f + 1` total nodes — a system with fewer cannot distinguish between a Byzantine minority and an honest majority, because the Byzantine nodes can impersonate the missing honest nodes.

This gives the standard BFT threshold: a system of `n` nodes requires at least `⌊n/3⌋ × 2 + 1` (i.e., more than two-thirds) to agree before accepting a result as final. Below that threshold, a Byzantine minority can prevent agreement; above it, honest nodes always outvote them.

### What PrivaCF needs from it

PrivaCF's public blockchain uses BFT consensus directly. Block finality requires `⌊K_validators/3⌋ × 2 + 1` BLS signatures from the VRF-selected validator set (§4.1) — the standard two-thirds-plus-one threshold. Once that many validators have signed, the block is final; no subsequent vote can reverse it. This is *deterministic* finality, as opposed to probabilistic finality in proof-of-work chains where a block can in principle always be orphaned by a longer chain.

The honest majority assumption A2 (§1.6) is the BFT assumption restated for PrivaCF's reputation-weighted setting: more than half of total accumulated reputation weight belongs to honest nodes. This is a stronger condition than needed for raw BFT (which only needs two-thirds of validators honest), but it is the assumption required for the reputation and CF layers to behave correctly, not just the consensus layer.

Double-signing — a validator signing two competing blocks at the same height — is a detectable Byzantine behavior. Because both signatures are on-chain and BLS signatures are publicly verifiable, any node can produce the evidence. The consequence in PrivaCF is an immediate permanent SUSPENDED verdict (§4.1).

### What it does not protect against

BFT consensus tolerates Byzantine behavior among validators but does not protect against a Byzantine *majority*. If more than one-third of validators are colluding adversaries, they can stall the chain (liveness failure) or, with more than two-thirds, force acceptance of invalid blocks (safety failure). PrivaCF's dual cluster diversity constraint on validator selection (different interest and behavioral clusters) makes it structurally harder to accumulate a correlated Byzantine third, but it does not eliminate the possibility if the adversary controls enough of the eligible pool.

---

## EC-VRF

**Reference:** Goldberg et al., "Verifiable Random Functions (VRFs)", RFC 9381, 2023.

### What it is

A Verifiable Random Function takes a private key and an input and produces two outputs: a pseudorandom value and a proof. Anyone holding the corresponding public key can verify that the pseudorandom value was computed correctly from that input under that key — without learning the private key. The value itself is indistinguishable from random to anyone who does not hold the key, and it cannot be predicted before the proof is published.

The EC-VRF construction (RFC 9381) builds this on elliptic curve discrete logarithm hardness. The proof is a DLEQ (discrete log equality) proof: a non-interactive sigma protocol that shows the same secret scalar was used in both the key and the output, without revealing it. Security reduces to the DDH (Decisional Diffie-Hellman) assumption on the curve.

The critical property that distinguishes a VRF from a plain PRF is that the output is **publicly verifiable**. A node cannot lie about what value it computed — the proof either checks out or it does not.

### What PrivaCF needs from it

PrivaCF uses EC-VRF for every selection that must be both unpredictable before the epoch beacon is published and independently verifiable afterwards:

- **Validator set selection (§4.1).** The proposer evaluates `EC-VRF(sk_proposer, beacon_T ‖ "validators")` to select that epoch's validator set. Any node can verify the result after the beacon is published; no node can predict it before.
- **Auditor committee selection (§6.4).** Same mechanism, different domain separator and constraint set (reputation floor, cluster diversity).
- **Relay node selection (§5.5).** Each node's relay for on-chain submission is VRF-selected per epoch from nodes in a different behavioral cluster.

All three selections share the same guarantee: a node knows it was selected only after the beacon drops, and everyone else can verify that selection independently.

### Why not Poseidon for these too?

Poseidon (used for local per-epoch derivations) is a PRF — it produces pseudorandom output under a secret key but provides no proof of correct evaluation. A node could claim any validator set composition it liked and no one could falsify it without the key. EC-VRF's proof is what makes the selection auditable on-chain. The spec's "primitive split" note in §4.2 covers this distinction directly.

### Security property assumed

Pseudorandomness and unpredictability under DDH on the underlying elliptic curve. The DLEQ proof is honest-verifier zero-knowledge and simulation-sound. PrivaCF targets the same curve as its BLS operations (BLS12-381) to reuse the existing cryptographic stack; the tendermint-rs codebase provides a production EC-VRF implementation.

---

## Loopix / Sphinx

**References:** Piotrowska et al., "The Loopix Anonymity System", USENIX Security 2017. Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format", IEEE S&P 2009.

### What it is

Loopix is a mixnet architecture that provides strong, formally analyzed anonymity for network-level communication. All messages are routed through a sequence of *mix nodes*, each of which decrypts one layer of onion encryption, applies a random Poisson-distributed delay, and forwards the packet to the next hop. No mix node learns more than its immediate predecessor and successor in the path.

Sphinx is the packet format underlying Loopix. A Sphinx packet encodes the full routing path in onion-encrypted layers: each mix node peels one layer, revealing only the address of the next hop, nothing about the origin or the remaining path. Packets are padded to a fixed size, so an observer on the wire cannot distinguish message types, payload sizes, or routing depth.

**Loop covers** are packets a node sends to itself via the mix network, routed through the full path and discarded at arrival. **Drop covers** are packets discarded at an intermediate node. Both are emitted at a constant Poisson rate regardless of real activity. Because all traffic — real messages and cover traffic — is statistically identical on the wire, an observer cannot determine when a node is sending real messages vs. emitting covers.

**Single-Use Reply Blocks (SURBs)** allow a responder to reply anonymously to a sender without knowing the sender's identity or mix path. The sender pre-builds a partial Sphinx packet encoding their return path, encrypts it to the responder, and includes it in the request. The responder drops the SURB into the mix without learning where it goes.

### What PrivaCF needs from it

Every unicast message in PrivaCF — PSI handshakes, audit responses, gossip vector pushes, verdict commits, verdict reveals — is sent as a Sphinx packet through the Loopix mix. This provides:

- **Sender anonymity:** mix nodes and observers cannot determine which node originated a message.
- **Receiver anonymity:** with SURBs, the responder does not learn the requester's identity or return address.
- **Relationship anonymity:** an observer cannot link a specific sender to a specific receiver.
- **Traffic analysis resistance:** constant-rate cover traffic means activity patterns reveal nothing about when real communication occurs.

The implementation target is Katzenpost, an open-source Loopix implementation. Nodes connect outbound to a provider (a publicly reachable mix node that buffers inbound messages), which eliminates the need for inbound connections and handles NAT traversal for home nodes.

Because Sphinx packets are fixed-size by construction, all PrivaCF messages — gossip vectors, audit responses, verdict commits, loop covers, drop covers — are indistinguishable on the wire.

### What it does not protect against

Loopix's formal anonymity guarantees hold against a *passive* global observer. An adversary who can actively drop, delay, or inject packets at the network level — and who controls a significant fraction of mix nodes — can degrade anonymity through intersection attacks. Nation-state adversaries with this capability are explicitly out of scope (§1.5).

---

## Dandelion++

**Reference:** Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees", ACM SIGMETRICS 2018.

### What it is

Dandelion++ is a two-phase gossip protocol designed to hide the origin of broadcast messages.

In the **stem phase**, the message is forwarded along a randomly chosen path — each node independently decides with probability `p ≈ 0.9` to continue forwarding to a single random peer, or with probability `1 − p` to transition to the fluff phase. This means the message travels a geometrically distributed number of hops before entering broadcast, so the node that first broadcasts it to many peers is several hops removed from the originator.

In the **fluff phase**, the message is propagated via standard epidemic broadcast — each node that receives it forwards it to all its peers. By this point, the true origin is obscured by the stem path.

The key guarantee: without controlling the stem path, an observer cannot reliably identify the originator from the broadcast pattern, even while watching the entire network. The formal anonymity guarantees are in terms of precision-recall tradeoffs for origin inference under adversarial observation.

### What PrivaCF needs from it

Loopix handles point-to-point messages well but is not suited to epidemic broadcast, where a message must fan out to many peers simultaneously. PrivaCF uses Dandelion++ for all broadcast-style traffic:

- **Item announcements** (§5.8) — positive interaction announcements that need to reach the network without revealing which node originated them.
- **Rewind signals** (§6.6) — signals that a node's recommendation quality has degraded, correlated to a gossip cohort epoch.
- **Watchdog signals** (§4.9.8) — alerts about anomalous verdict-commit rates.

These messages are not point-to-point requests with a specific recipient, so Loopix's SURB-based model does not apply. Dandelion++ provides sender anonymity for the broadcast case at low overhead.

---

## Merkle Trees and Sparse Merkle Trees

**Reference:** Merkle, "A Digital Signature Based on a Conventional Encryption Function", CRYPTO 1987.

### What it is

A Merkle tree is a binary tree in which every leaf node holds a hash of a data block, and every internal node holds a hash of its two children. The root — the Merkle root — is a single hash that commits to the entire set of leaves. If any leaf changes, the root changes.

**Membership proofs** are compact: to prove that a specific value is leaf `i`, you only need the sibling hashes along the path from leaf `i` to the root — O(log n) hashes for a tree with n leaves. A verifier recomputes the root from those siblings and checks it matches the published root.

A **Sparse Merkle Tree (SMT)** extends this to a conceptually enormous fixed-size index space (e.g., all 2^256 possible values), where nearly all leaves are empty. The tree is defined over the full space but is stored compactly by collapsing subtrees of empty leaves. The key additional capability is **non-membership proofs**: to prove that a value is *not* in the tree, you provide the Merkle path to the position where it would appear and show the leaf is empty. This proof is the same size as a membership proof.

### What PrivaCF needs from it

PrivaCF uses Merkle trees in three distinct roles:

**Behavioral history (§4.6).** Each node accumulates a Merkle tree `M_v(T)` whose leaves encode its behavioral events for an epoch (announcements, pull responses, audit responses, participation counts). The root commits to the full history without revealing it. Auditors verify ZK proofs about the tree's contents without reading the leaves. Partial reveals are safe because leaves are individually salted with a VRF-derived value and the tree is padded to a fixed protocol-wide maximum leaf count — sibling hashes are opaque even to an auditor who sees one opened path.

**SUSP_SMT (§4.9.2).** A public Sparse Merkle Tree over the nullifier space. A leaf is non-empty if and only if that `null_v` has been inserted following a SUSPENDED verdict. Every new epoch ID must prove non-membership — that its `null_v` is not in the tree — inside a ZK circuit, with `null_v` as a private witness. The verifier sees only proof validity, not which position was checked. The tree is append-only; leaves are never removed.

**DECRYPTION_SMT (§4.9.3).** A parallel SMT over `dec_nullifier` values, enforcing at the consensus layer that each suspension verdict triggers at most one nullifier decryption. A second decryption attempt produces the same `dec_nullifier`, which is already in the tree; honest validators reject the block.

---

## Pedersen Commitments

**Reference:** Pedersen, "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing", CRYPTO 1991.

### What it is

A Pedersen commitment to a value `m` is:

```
C = m·G + r·H
```

where `G` and `H` are independent public elliptic curve generators (no one knows the discrete log of `H` relative to `G`), and `r` is a random blinding factor chosen by the committer.

The scheme has two security properties:

**Perfectly hiding.** `C` reveals nothing about `m`. For any fixed `C`, every possible value of `m` is consistent with some choice of `r`. An unbounded adversary cannot learn `m` from `C`.

**Computationally binding.** The committer cannot open `C` to a different value `m'`. Doing so would require finding `r'` such that `m'·G + r'·H = m·G + r·H`, which rearranges to `(m − m')·G = (r' − r)·H` — a discrete log relation between `G` and `H` that is assumed hard.

Pedersen commitments are *additively homomorphic*: `C(m₁) + C(m₂) = C(m₁ + m₂)`, which makes them composable with inner product arguments and range proofs.

### What PrivaCF needs from it

PrivaCF uses Pedersen commitments to bind a node's preference vector `p_v` for an epoch without revealing it:

```
C_p(T) = p_v · G + r_p · H
```

`C_p(T)` is submitted to the committee chain each epoch. Auditors can verify ZK proofs about properties of `p_v` — that its L1 norm is within bounds (Statement 1), that it is consistent with announced ratings (Statement 2), and that it has not changed too abruptly since last epoch (Statement 3) — without the commitment revealing what `p_v` actually contains.

The blinding factor `r_p` is held locally. If `r_p` is lost, the ZK proof cannot be reconstructed and the Class 3 audit permanently fails, resulting in a SUSPENDED verdict (§7.7). This is intentional: it creates a strong incentive to maintain the blinding factor, and the inability to prove consistency is treated as equivalent to having tampered with it.

---

## Poseidon PRF

**Reference:** Grassi et al., "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems", USENIX Security 2021.

### What it is

Poseidon is a cryptographic hash function designed specifically for use inside arithmetic proof circuits. Most general-purpose hash functions (SHA-256, BLAKE3) are built from bitwise operations — XOR, AND, bit rotations — which are cheap in hardware but expensive to represent as arithmetic constraints in a ZK proof system. Poseidon's round function instead uses low-degree polynomial substitutions over a prime field, the same arithmetic native to ZK systems. This makes it dramatically cheaper to prove: a Poseidon evaluation costs a few hundred Plonky3 constraints, compared to tens of thousands for SHA-256.

Structurally, Poseidon follows a sponge construction with a permutation built from alternating *full rounds* (all state elements pass through a non-linear layer) and *partial rounds* (only one element does), tuned to minimize constraint count while maintaining security against algebraic and differential attacks.

**Used as a PRF.** When keyed with a secret input, Poseidon behaves as a pseudorandom function. This is distinct from a VRF (see EC-VRF): Poseidon output is pseudorandom under the key but there is no proof of correct evaluation. A node cannot convince others it computed a Poseidon value honestly — it can only be verified by someone who also knows the key. This is the right primitive for *local* derivations where only the node itself needs to compute the value; it is the wrong primitive for on-chain selections that others must be able to verify independently (see EC-VRF).

### What PrivaCF needs from it

Poseidon is used for every local per-epoch derivation in PrivaCF — all values a node computes from its secret key that need to be cheap to prove inside a ZK circuit:

| Derivation | Expression |
|---|---|
| Nullifier | `Poseidon(sk, "null_v")` |
| Epoch ID | `Poseidon(sk, beacon_T, null_v, "epoch_id")` |
| Permutation seed | `Poseidon(sk, beacon_T, "perm")` |
| Chop count | `Poseidon(sk, beacon_T, "chop_n")` |
| Epoch offset | `Poseidon(sk, "epoch_offset")` |
| Niche announce delay | `Poseidon(sk, item_hash, beacon_T, "niche_delay")` |
| Leaf salt | `Poseidon(sk, epoch_T, "leaf_salt")` |

Each use includes a distinct domain separator string to prevent output from one derivation being used as input to another. Domain separator collision resistance reduces to standard Poseidon collision resistance.

### Security property assumed

Collision resistance and pseudorandomness of the sponge construction over the underlying prime field. This is the same assumption required by the ZK proof system — Poseidon introduces no additional hardness requirements. The assumption is new relative to SHA-256 (which has decades of cryptanalysis) and should be treated with appropriate caution; Poseidon has been analyzed extensively since 2019 but is younger than SHA-2.

---

## PSI (Private Set Intersection)

**Reference:** Pinkas, Rosulek, Trieu & Yanai, "SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension", USENIX Security 2019. Unbalanced variant: Pinkas, Rosulek, Trieu & Yanai, USENIX Security 2018.

### What it is

Private Set Intersection (PSI) is a two-party protocol where Alice holds a set `A` and Bob holds a set `B`, and at the end Alice learns `A ∩ B` — the items they have in common — without Bob learning anything about `A`, and without Alice learning anything about `B` beyond what the intersection itself reveals.

The *unbalanced* PSI variant handles the case where one set is much larger than the other. PrivaCF uses this because one party (the server or the node with broader item history) may hold a much larger set than a newly joining peer.

The protocol is typically built on oblivious transfer (OT) extension or polynomial-based techniques. At a high level: each party encodes their set as a polynomial or hashed structure; they run an interactive protocol that allows each party to evaluate the other's structure on their own elements without the other party learning which elements were queried.

### What PrivaCF needs from it

PrivaCF uses asymmetric PSI for interest cluster peer selection (§5.4). When a node wants to find peers whose item interaction sets overlap significantly with its own, it cannot simply broadcast its item list — that would reveal its preference history. PSI lets two nodes determine their Jaccard similarity and identify overlapping items without either party learning the full contents of the other's set.

The process (depicted in Appendix I of the spec):

1. Two candidate nodes run the PSI protocol on their item interaction sets.
2. The intersection size (and optionally the intersection itself) is revealed to the initiating node.
3. If the Jaccard similarity exceeds `θ_cluster`, the node qualifies as an interest cluster peer.
4. The result is cached with a decay factor `λ_proof`; after epoch rotation, cached results are re-weighted rather than discarded immediately, since PSI is expensive to re-run every epoch.

The key privacy property: a node that fails the Jaccard threshold learns only that the overlap was insufficient, not what items the other node holds. A node that passes learns only the overlapping items, not the non-overlapping ones.

### What it does not protect against

PSI reveals the intersection to the initiating party. Over many PSI runs with different peers, an adversary who controls many nodes can build up a partial picture of a target's item set by observing which items appear repeatedly in intersection results. PrivaCF mitigates this through the PSI cache (avoiding redundant runs), the cluster size limits (bounding the number of peers a node runs PSI with), and the preference obfuscation in transit (§4.5), but residual inference from repeated PSI is an acknowledged limitation.
