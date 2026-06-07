# PrivaCF — Security Analysis Companion

### Companion to [SPEC.md](./SPEC.md) §1.7 · v0.1.0 (draft)

> **Status:** Proof *sketches*, not machine-checked proofs. Each property below names the
> game, the reduction, and the standard primitive or assumption it bottoms out in, and
> states explicitly what is left for a full write-up. This document upgrades the "proven
> (sk) = proof-sketchable" cells of SPEC §1.7 from "reduction named" to "reduction
> *given*"; it does not yet upgrade any of them to "formally verified."
>
> **Two standing caveats apply to every property here and are not repeated per-property:**
>
> - **(C-A2) Honest-majority contingency.** Every bound is stated *relative to* Assumption
>   A2 (honest majority by weight in the relevant eligible pool). A2 is partly produced by
>   the protocol it secures and, at deployment, is underwritten by the externally-trusted
>   bootstrap consortium until the §5.1.1 transition criterion is met. Read this into P1–P5;
>   it is not a footnote.
> - **(C-SUB) Substrate contingency.** These are properties of the *implemented substrate*
>   (SPEC Layers 1–4). The current proof-of-concept exercises only Layer 5 (recommendation)
>   with obfuscation and PSI modeled in the clear. **No P1–P5 claim is demonstrated in code
>   yet, and P-feasibility (below) is a hard precondition for all of them.** See SPEC §1.7
>   "Substrate-contingency gate" and §10.1.1.

---

## 0. Conventions

- **Security parameter** `λ`. `negl(λ)` is any function smaller than every inverse polynomial.
- **Adversary** `A` is PPT unless stated. "Advantage" `Adv_X(A)` is `|Pr[A wins game X] − p_triv|`
  where `p_triv` is the trivial guessing probability for that game (½ for a decision game, 0
  for a forgery/extraction game).
- **Primitive-advantage bounds** (named, not pinned): `ε_PRF` (Poseidon keyed-PRF
  distinguishing), `ε_coll` (Poseidon collision), `ε_BLS` (threshold-BLS / co-CDH
  unforgeability), `ε_IBE` (Boneh–Franklin IBE / DBDH-ROM), `ε_Π` (Plonky3 proof-system
  knowledge-soundness), `ε_SMT` (SMT non-membership soundness, ⊆ `ε_Π` when the path is
  checked in-circuit), `ε_Pedersen` (Pedersen binding; hiding is *perfect* → 0), `ε_perm`
  (permutation-seed secrecy, ⊆ `ε_PRF`), `ε_transport(Π,·)` (transport-profile traffic
  correlation). All are conventional reduction names, not protocol parameters.
- **Assumptions** A1–A4 are exactly as in SPEC §1.6. We additionally use **A3-prim**: the
  primitive bounds above are each `negl(λ)` for the chosen instantiations (BLS12-381,
  Poseidon-128, Plonky3 over the Goldilocks/BabyBear field, RFC 9381 EC-VRF).

The properties P1–P5 restate SPEC §1.7 verbatim in their *claim*; this document adds the
*derivation*.

---

## P1 — Identity unlinkability

**Game `Unlink(A, T, k, Π)`.** The challenger samples `sk`, runs the protocol honestly
under transport profile `Π`, and exposes to `A` everything on the public chain and the wire.
`A` is given two epoch identities `(id₀, id₁)` and a bit `b`: if `b = 0` they are
`(epoch_id_T, epoch_id_{T+k})` from the *same* `sk`; if `b = 1`, `epoch_id_{T+k}` is replaced
by a fresh independent key's identity. `A` outputs `b'` and wins if `b' = b`.

```
Adv_unlink(A,T,k,Π) = |Pr[b'=b] − ½| ≤ ε_PRF(Poseidon) + ε_transport(Π,T,k)
```

**Reduction (sketch).** Hybrid argument in two steps.

- **H0 = real game.** `epoch_id_T = Poseidon(sk, beacon_T, null_v, "epoch_id")`,
  `epoch_id_{T+k} = Poseidon(sk, beacon_{T+k}, null_v, "epoch_id")`.
- **H1.** Replace the keyed function `Poseidon(sk, ·)` by a truly random function `F(·)`.
  A distinguisher between H0 and H1 with advantage `δ` yields a Poseidon-PRF distinguisher
  with the same `δ` (it forwards `A`'s two-input transcript to its PRF oracle). Hence
  `|Pr[A wins | H0] − Pr[A wins | H1]| ≤ ε_PRF`.
- **In H1**, since `beacon_T ≠ beacon_{T+k}` (distinct drand outputs, A3) the two inputs to
  `F` differ, so `F(beacon_T,·)` and `F(beacon_{T+k},·)` are independent and uniform. The
  shared `null_v` is an *input* to `F`, never an output, so it induces no correlation an
  unbounded analysis could exploit. Thus in H1 the chain transcript carries **zero**
  same-key signal: `Pr[A wins | H1] = ½ + (signal from the wire only)`.
- The residual wire signal is exactly the transport profile's traffic-correlation term,
  bounded by `ε_transport(Π,T,k)`: under Loopix this is bounded by the per-hop Poisson mix
  parameter and cover rate; under Tor/I2P it is **not** bounded against a global passive
  adversary, so P1 is *conditionally* claimed there (SPEC §1.5).

Combining, `Adv_unlink ≤ ε_PRF + ε_transport`. ∎(sketch)

**Scope — what P1 does NOT cover.**
1. P1 is unlinkability against an **external** chain+wire observer. A node that voluntarily
   submits a §4.7 continuity proof links its own epochs **to the arbitration committee**
   (by design, for reputation carryover). Nodes choosing full unlinkability submit none and
   forgo cross-epoch reputation. This is a deliberate disclosure channel, not a break.
2. **Interest-cluster topology** leaks slowly to a patient mix-observing adversary via PSI
   handshake patterns (SPEC §8.1). P1 bounds *identity* linkage, not *cluster-graph*
   reconstruction, which is an explicit residual.

**What remains for the full proof.** A concrete `ε_transport(Loopix; λ_mix, r_cover)` — OQ-58,
the "keystone." A conservative analytical pre-bound is given in §P1.1 below; the full constant
is pinned by Phase-5 exp 5.51.

### P1.1 Conservative `ε_loopix` pre-bound (OQ-58)

OQ-58 is listed as empirical (calibrate the cover rate `λ` per config), but the *shape* of the
sender-anonymity bound — and a conservative number usable before any experiment — follows
analytically from the Loopix analysis (Piotrowska et al., USENIX Security 2017). We give it
here so P1's `ε_transport` term is no longer a black box.

**Model.** Stratified topology of `L` layers, `W` mix-role nodes per layer, adversary controls
a fraction `f` of mixes (and is a global passive observer of the wire). Each mix delays a
message by `Exp(μ)` (mean `1/μ`). Each client emits payload, loop, and drop traffic at Poisson
rates `λ_P, λ_L, λ_D`; write the cover ratio `r = (λ_L + λ_D)/λ_P`. With `N_act` active clients,
the aggregate arrival rate to a mix is `λ_mix ≈ N_act·(λ_P+λ_L+λ_D)/W`, and by M/M/∞ steady
state the **expected pool a message is mixed into** is

```
n̄ = λ_mix / μ        (expected number of other messages co-resident in an honest mix)
```

**Bound.** The adversary's advantage in the P1 cross-epoch link decomposes into a *full-path
compromise* term and a *statistical-disclosure-through-honest-mixing* term:

```
ε_loopix(T, k)  ≤   f^L                          (every mix on the path is adversarial → no mixing)
                  + (1 − f^L) · ρ_SDA            (≥1 honest mix → message hidden in its pool n̄)

with   ρ_SDA  ≤  min( 1,  C_SDA · m_obs / ( n̄ · (1 + r) ) )
```

- **`f^L` is rigorous and immediately usable.** It is the probability that an independent
  per-layer path draw lands on an adversarial mix in *every* layer, so the adversary sees the
  message end-to-end with no mixing protection. Given a target `ε` and an estimate of `f`, this
  alone sizes the path length: `L ≥ log ε / log f`. (E.g. `f = 0.2`, target `f^L ≤ 10⁻³` ⇒
  `L ≥ 5`.)
- **The residual `ρ_SDA`** is the leak a patient statistical-disclosure adversary
  (Danezis 2003; Mathewson & Dingledine 2004) extracts *through* an honest mix over `m_obs`
  correlated observations of the (T, T+k) traffic. It shrinks with the honest-mix pool `n̄` and
  with cover `r`: classical SDA needs `Θ(n̄·(1+r))` observations to disambiguate a persistent
  relationship, so the per-observation leak is `O(1/(n̄(1+r)))`. `C_SDA` is the only deferred
  constant — an `O(1)` factor pinned by exp 5.51; the bound's *shape* (and the `f^L` term) need
  no experiment.

**Why this is the keystone.** `n̄ = λ_mix/μ` grows with `N_act` (more honest participants =
bigger pools) and with cover `r`, while `f^L` shrinks as Sybil resistance keeps `f` low. So
`ε_loopix` is exactly where the **mutually-load-bearing A2 coupling** (SPEC §1.7) becomes
quantitative: Sybil resistance lowers `f`, honest participation raises `n̄`, and both directly
tighten the transport term that P1 (and, downstream, the whole privacy stack) depends on.
Plugging this `ε_loopix(λ)` into the OQ-19 / OQ-46 / OQ-55 bounds unblocks their numerical
evaluation (those are written as functions of `ε_loopix`).

**What remains.** Pin `C_SDA` (exp 5.51) and calibrate `λ` (hence `r`, `n̄`) per config A–E.
Until then P1 is "PRF-tight, transport-bounded by `f^L` + an `n̄`/cover-decaying residual."

---

## P2 — Preference indistinguishability in transit

**Game `Pref(A,T)`.** Challenger fixes neighboring preference vectors `p⁰, p¹` (differing in
a single coordinate, `‖p⁰‖₁ = ‖p¹‖₁ = 1`), samples `b`, and gives `A` the full per-epoch
gossip output `gossip_T(p^b)` = (permuted, chopped, noised positive-weight vector) together
with the Pedersen commitment `C_p(T)`. `A` outputs `b'`.

```
Adv_pref(A,T) ≤ ε_DP(T, ε_eff) + ε_perm(π_v) + ε_Pedersen[hiding]
```

where `ε_DP` is the advantage against the **clean `ε`-DP** Laplace mechanism now adopted in
§4.5 (clamp-based, δ = 0; see §P2.2). The earlier reject-resampling construction did *not*
achieve this — that diagnosis (the reason for the fix) is preserved in §P2.1.

**Reduction (sketch), component by component.**

- **Pedersen `C_p(T)` contributes 0.** Pedersen is *perfectly* hiding: for every `C_p` and
  every candidate `p`, a blinding `r_p` exists making them consistent. So `C_p(T)` is
  independent of `b` even against an unbounded `A`. (`ε_Pedersen` enters the *binding*
  direction used by Statements 1/3 in P-integrity, not here.)
- **Permutation `π_v(T)`** is seeded by `Poseidon(sk, beacon_T, "perm")`. Within one epoch,
  secrecy of which coordinate maps where reduces to the same PRF step as P1: replacing the
  seed by random makes the applied permutation uniform and independent of the data, bounded
  by `ε_perm ≤ ε_PRF`. (Cross-epoch permutation reconstruction over many observations is
  OQ-22 and is *not* covered by the single-epoch game.)
- **The Laplace term** is `ε`-DP under the §4.5 clamp-based mechanism (§P2.2). §P2.1 records
  *why* the original reject-resampling construction did not qualify — kept as the diagnosis
  that motivated the fix.

### P2.1 Why the original reject-resampling broke nominal ε-DP (diagnosis; now fixed)

§4.5 *as originally written* added Laplace noise `Lap(0, S/ε)` (sensitivity `S = 2`,
`‖p_v‖₁ = 1`) and then enforced sign preservation by **reject-resampling** until
`|noise_i| < |p_v[i]|` for every active coordinate. The plain Laplace mechanism is `ε`-DP;
the reject-resampling step is **not** post-processing — it conditions the output on a
*data-dependent* event, and that voided the nominal guarantee:

> For neighbors differing in coordinate `i` with `|p⁰[i]| ≠ |p¹[i]|`, the truncated outputs
> have **different supports** (`(−|p⁰[i]|, |p⁰[i]|)` vs `(−|p¹[i]|, |p¹[i]|)`). Near the
> wider support's boundary the likelihood ratio is unbounded, so **no finite `ε` bounds it.**
> Pure `ε`-DP fails on exactly the coordinate the game queries.

**What genuinely holds (three honest statements):**

1. **Sign is not a secret to protect.** Only positive weights are gossiped (§4.5); negatives
   stay local. So "sign preservation" only guarantees a transmitted positive stays positive —
   it leaks nothing not already public. The privacy claim is therefore about **magnitudes of
   transmitted positive weights** and **which coordinates are transmitted** (the latter is
   handled by permutation + chopping + cover, *not* by Laplace).

2. **Per-coordinate `(ε, δ)` in the slack regime.** SPEC sizes `σ` so the 99.7th Laplace
   percentile lies below `|p_v[i]|`. Where that holds with margin (`|p_v[i]| ≳ 3·S/ε`) the
   truncation almost never binds, and the mechanism is `(ε, δ_i)`-DP with `δ_i` ≈ the
   per-coordinate tail mass that differs between neighbors (≈ the resampling probability,
   `O(e^{−|p_v[i]|·ε/S})`). For **small** `|p_v[i]|` (the long-tail, near-cold preferences)
   the truncation binds hard and the effective `ε` blows up — these coordinates get *weak*
   privacy. The E2 `laplace[legacy]` rows confirm this empirically: that method's quality is
   nearly **ε-independent** (flat across ε = 4, 1, 0.5) — but that flatness is the *artifact*
   of the data-dependent clip making the perturbation proportional to each weight, **not** a
   property of a valid DP mechanism. The corrected clamp method (§P2.2) is genuinely
   ε-sensitive, as the `laplace[clamp]` rows show.

3. **Composition.** Per-event `(ε, δ)` composes to `(Tε, Tδ)` (basic) or
   `(√(2T ln(1/δ'))·ε + Tε(e^ε−1), Tδ + δ')` (advanced; Dwork–Rothblum–Vadhan). **Lifetime
   budget is unbounded and not claimed** (SPEC §8.1). P2 is a *per-epoch* property.

### P2.2 The adopted fix — clean ε-DP by post-processing (now in §4.5)

Replace the data-dependent reject-resample with **plain Laplace + a data-independent
projection**:

```
1. noisy[i]  = p_v[i] + Lap(0, S/ε)        // standard Laplace → ε-DP on the whole vector
2. clamp     = clamp(noisy[i], 0, B)       // B a PUBLIC deployment constant
3. release   = clamp / ‖clamp‖₁            // renormalize to ‖·‖₁ = 1
```

Steps 2–3 are **deterministic, data-independent functions of the released noisy vector**, and
DP is closed under post-processing (Dwork & Roth, Prop. 2.1). So the released mechanism is
**clean `ε`-DP — `δ = 0`, no weakening** — *and* sign is preserved (a sign-flipping draw
projects to `0` = "not endorsed") without any `|p_v[i]|`-dependent conditioning. The likelihood
ratio is `≤ e^ε` everywhere, including the atoms the clamp creates at `0` and `B`, because
clamping a `≤ e^ε`-bounded density preserves the bound (group-privacy on the pre-clamp law).

The cost: a coordinate with a small true weight may clamp to `0` and drop out — benign,
because the transmitted *set* is already protected by chopping/cover. The corrected E2 (run
with this method, ml-1m) shows CF quality is now genuinely `ε`-**sensitive** — tail P@10 dips
from 0.0296 (ε=∞) to a worst 0.0216 at mid-range ε≈4 and partly recovers to 0.0253 at ε=0.5 —
yet stays above the popularity floor at every tested `ε`. It survives because support is
preserved (noise on active dims only) and item-cosine CF is co-occurrence-driven; at small `ε`
the clamp+renormalize degenerates toward a randomized binarization of the support that CF
tolerates (hence the non-monotone curve). A deployment wanting a tighter utility/`ε` frontier
on the bounded domain may swap step 1 for the Geng–Viswanath optimal bounded-noise mechanism or
the staircase mechanism; the post-processing argument is unchanged. **This is now the §4.5
normative construction**, replacing the reject-resample.

**What remains.** Pin the per-event `ε_eff` (OQ-55, SecLDP framing). Lifetime budget `Tε`
remains unbounded and **not** claimed (§8.1) — P2 is a per-epoch property. The §4.5 "formal DP
guarantee" label is now accurate (clean `ε`-DP), where before it overstated.

---

## P3 — Suspension persistence

**Game `Persist(A)`.** `A` is given a key `sk` whose `null_v = Poseidon(sk, "null_v")` has
been inserted into `SUSP_SMT` (root on-chain). `A` wins if it produces *any* accepted
admission/handoff for an identity it controls that derives from a key colliding on `null_v`,
or a valid Statement-5 proof for a `null_v` that is in the tree.

```
Pr[A wins] ≤ ε_coll(Poseidon) + ε_Π(Statement 5 soundness)   = negl(λ)
```

**Reduction (sketch).** Exactly three re-entry paths exist; we bound each.

- **Same `sk`.** `null_v` is identical (deterministic, beacon-independent — §4.9.9). The
  SUSP_SMT leaf at that position is occupied, so a *sound* non-membership proof cannot exist;
  producing an accepted one breaks Statement-5 knowledge-soundness → `≤ ε_Π`. Probability of
  honest-validator acceptance is otherwise 0.
- **Different `sk'`, same `null_v` (collision).** Requires `Poseidon(sk', "null_v") =
  Poseidon(sk, "null_v")` with `sk' ≠ sk` → a Poseidon collision → `≤ ε_coll`.
- **Different `sk'`, different `null_v` (fresh identity).** This is **not** a break of P3:
  it is a brand-new identity with `null_v' ∉ SUSP_SMT`, zero accumulated reputation, and the
  full §4.3 VDF admission chain to re-pay. Persistence is a property of the *suspended key*,
  not of the human; reputation laundering via fresh keys is governed by P5 / detection-contract
  rows 13, 19, not P3.

Non-malleability (§4.9.7) closes the "substitute `null_v'` while keeping `sk`" sub-case: the
circuit pins `null_v` and `epoch_id_T` to the *same* `sk` wire, so a substituted nullifier
fails the `epoch_id` derivation check — again `≤ ε_Π`. ∎(sketch)

**This is the cleanest property in the system.** "Fails by arithmetic, not by rule" is
accurate: there is no policy lever, only `ε_coll + ε_Π`. The full write-up is a direct
soundness instantiation once the Statement-5 circuit is fixed (P-feasibility).

---

## P4 — Forward-secure nullifier extractability

Let `commit_T = (c_T^{(0..N−1)}, d_T)` with `null_v = s₁ + s₂ (mod p)`, `s₁` encrypted to the
`N_fallback` committee threshold keys under identity `"SUSPEND epoch_id_T"`, `s₂` encrypted to
the standing `VA_pub` under identity `"VERDICT_FINALIZED epoch_id_T"` (§4.9.4).

**Three claims (a recoverability lemma + two confidentiality bounds):**

```
(P4.a) Pr[recover null_v | σ_i^SUSPEND ∧ σ_T^VERDICT] = 1
(P4.b) Pr[recover null_v | σ_i^SUSPEND only]          ≤ ε_IBE     // yields only s₁ ⟂ null_v
(P4.c) Pr[recover null_v | no σ_T^VERDICT]            ≤ ε_BLS + ε_IBE
```

**P4.a — recoverability (correctness).** Given a committee SUSPEND signature for slot `i` and
the validator verdict attestation, IBE decryption correctness yields `s₁` and `s₂`
respectively, and `null_v = s₁ + s₂`. Holds with probability 1 by IBE correctness +
field arithmetic. *No node cooperation, no escrow.* This is the dark-node-closure guarantee
(detection-contract row 14, level **C**).

**P4.b — committee-only confidentiality (the forward-secrecy fix).** Suppose `A` holds a full
committee threshold (even *all* `N_fallback` committees, present or future-compromised) but
not `σ_T^VERDICT`. `A` can decrypt every `c_T^{(i)}` and learn `s₁`. But `s₂ = r_share` was
sampled uniformly by the node, so `s₁ = null_v − s₂` is **uniform and information-theoretically
independent of `null_v`.** Learning `null_v` therefore requires learning `s₂` from `d_T`
without `σ_T^VERDICT`, i.e., breaking BF-IBE confidentiality on the `VERDICT_FINALIZED`
identity → `≤ ε_IBE` (reduces to DBDH in the ROM). **Crucially, a committee signature alone
— at any time, including a future compromise of a long-past committee — no longer recovers
`null_v`.** This is what retires the old §8.2 T12 deletion dependency for `null_v` (it still
applies to behavioral *snapshots*, a separate mechanism).

**P4.c — no verdict at all.** Without any `σ_T^VERDICT` in existence, `A` must forge a
validator threshold attestation (`≤ ε_BLS`, co-CDH on BLS12-381) *and* break `d_T` (`≤ ε_IBE`)
to get `s₂`. If no SUSPEND verdict is ever finalized, `σ_T^VERDICT` never exists, so `d_T` is
sealed forever and `commit_T` is unconditionally confidential against everyone — "decrypt iff
suspended" is now enforced by cryptography, not by a deletion policy.

**Confidentiality is not weakened by replication.** Security of `commit_T` is the *weakest*
slot's security; since each `c_T^{(i)}` reduces independently to DBDH under its own committee's
honesty, disjoint membership rules out a single coalition spanning slots, and `s₁` is `⟂ null_v`
regardless — replicating `s₁` to `N` committees adds liveness, not exposure.

**Liveness.**
- `s₁`: any one live slot suffices; stalling needs a colluding non-revealing minority in
  *every* one of `N_fallback` disjoint committees simultaneously → joint probability decays
  exponentially in `N_fallback` under A2 (§4.9.4, §4.9.6 fallback activation).
- `s₂`: the VA reconstruction threshold is set ≤ the consensus finalization quorum and
  contributing one's VA share is part of the finalization duty for a SUSPEND block, so
  `σ_T^VERDICT` liveness **reduces to consensus liveness** (§4.1 "Threshold coupling"). There
  is no finalized-suspension-but-unrecoverable-`s₂` state.

**Covert/retroactive deanonymization now requires, jointly:** (i) an epoch-`T` committee
threshold break, (ii) a *current*-validator threshold break (an A2 violation), and (iii) a
slashable `VERDICT_FINALIZED` equivocation (§4.1) — strictly stronger than the prior
single-committee assumption, and bounded by the same A2 consensus already rests on.

**Residual — the permanent genesis caveat (honest).** `VA_pub` is a *standing* key. Proactive
re-sharing (PSS) at each validator rotation gives proactive security against share
accumulation across epochs, **but** a threshold collusion *at the genesis DKG* (A4) learns the
master secret directly and retains `s₂`-signing power across all rotations forever. So P4.b/c
carry a genesis asterisk: forward secrecy holds against all *post-genesis* committee/validator
compromises under A2, and against genesis compromise only under A4. The optional Pixel-style
forward-secure hardening of `VA_pub` (Drijvers et al. 2020, puncturing past verdict identities
after the `W_primary`/`W_fallback` window) narrows this and is the recommended v2 hardening; it
is *not* load-bearing for the A2-bounded claim.

### P4.1 Multi-recipient 2-of-2 confidentiality theorem

The sketch above asserts P4.b/c; here is the theorem they instantiate, against the BF-IBE +
threshold-BLS-as-KDF construction precisely (the DST registry it depends on is in Appendix A).

**Setup.** `commit_T = (c_T^{(0..N−1)}, d_T)` where `c_T^{(i)} = IBE.Enc(pk_i, "SUSPEND epoch_id_T", s₁)`
under committee `i`'s threshold key `pk_i` (`N = N_fallback`), and
`d_T = IBE.Enc(VA_pub, "VERDICT_FINALIZED epoch_id_T", s₂)`. The node samples `s₂ ←$ 𝔽_p`
uniformly and sets `s₁ = null_v − s₂`. The IBE decryption key for identity `id` under master
key `mk` is the threshold BLS signature `σ = Sign_mk(id)` (this is the "signature *is* the IBE
key" instantiation — DST-separated per Appendix A).

**Lemma 1 (share independence).** `s₁` is uniform on `𝔽_p` and independent of `null_v`; the pair
`(s₁, null_v)` is recoverable from `s₁` alone with probability `1/|𝔽_p| = negl`. *(Immediate:
`s₂` uniform ⇒ `s₁ = null_v − s₂` uniform, and `null_v = s₁ + s₂` is determined only once `s₂`
is known.)*

**Theorem P4 (forward-secrecy regime — committee compromised, validators not).** Let `A` be PPT,
given `commit_T`, all public keys, and **every** committee signature `{σ_i^SUSPEND}` (hence `s₁`),
but no validator attestation `σ_T^VERDICT`. Then

```
Adv^{recover-null_v}(A)  ≤  ε_BLS^{VA}  +  ε_IBE^{DBDH}
```

where `ε_BLS^{VA}` bounds forging a threshold signature under `VA_pub` (threshold-BLS EUF-CMA,
reducing to co-CDH on BLS12-381) and `ε_IBE^{DBDH}` bounds breaking one BF-IBE ciphertext
(IND-ID-CPA, reducing to DBDH in the ROM).

*Proof (hybrid).* **G0** = real game. By Lemma 1, `A`'s view is independent of `null_v` unless it
obtains `s₂`, which is encrypted only in `d_T` under identity `"VERDICT_FINALIZED epoch_id_T"`.
To obtain `s₂`, `A` must either (a) acquire the decryption key `σ_T^VERDICT` — but no honest
party emits it absent a finalized SUSPEND verdict (SPEC §4.1), so `A` must forge it: bounded by
`ε_BLS^{VA}`; or (b) break `d_T` without the key. Define **G1** = G0 with `d_T` replaced by
`IBE.Enc(VA_pub, "VERDICT_FINALIZED epoch_id_T", s₂')` for fresh random `s₂'`. Any distinguisher
`G0/G1` is an IND-ID-CPA adversary on BF-IBE: `|Pr[A wins G0] − Pr[A wins G1]| ≤ ε_IBE^{DBDH}`.
In **G1**, `null_v = s₁ + s₂` with `s₂` never encrypted anywhere `A` can open, so by Lemma 1
`Pr[A wins G1] ≤ 1/|𝔽_p|`. The `N` committee slots all carry the *same* `s₁` (certified by
Statement 5, §4.9.5), which `A` already holds and which is `⟂ null_v`, so they contribute
nothing — no per-slot hybrid is needed in this regime. Summing the two transitions gives the
bound. ∎

**Corollary (full-confidentiality regime — neither side compromised).** If `A` holds no
committee signatures either, the committee slots must also be hidden; a standard multi-recipient
hybrid over the `N+1` ciphertexts gives

```
Adv^{recover-null_v}(A)  ≤  ε_BLS^{VA}  +  ε_BLS^{committee}  +  (N+1)·ε_IBE^{DBDH}.
```

**Reading.** The forward-secrecy theorem is the load-bearing one: it shows a committee
compromise — *contemporaneous or a future compromise of a long-past committee's lingering
shares* — recovers only `s₁ ⟂ null_v`, so covert/retroactive deanonymization additionally
requires forging or extracting a *current*-validator attestation, which is simultaneously an A2
break and a slashable equivocation (§4.1). The bound is `negl` under co-CDH + DBDH **plus** the
A4 genesis caveat on `VA_pub`'s master secret (§P4, "Residual"). Both reductions are in the ROM;
hardening `VA_pub` to a forward-secure (Pixel) key removes the ROM/standing-key residual but is
not needed for the A2-bounded statement.

**What remains.** A machine-checked version (e.g. in EasyCrypt) and a tight concrete-security
accounting of the `(N+1)` hybrid loss for the full-confidentiality corollary. The
forward-secrecy theorem above is the deployment-relevant one and is loss-factor-1.

**Feasibility note — the in-circuit-pairing form of this is too expensive; restructured.** The
literal §4.9.5 way of certifying `commit_T` (an in-circuit BF-IBE pairing per slot) is the
P-feasibility wall (≥99% of Statement 5's constraints; SPIKE §8). It is replaced by **native-group
verifiable encryption** — exponential-ElGamal *limb* encryption decryptable by the verdict
signature, proven correct by a native sigma + range proof, with a security analysis (confidentiality
= co-DBDH, binding = DL/Bulletproofs, **no new assumption**) in
[DESIGN-f1-verifiable-encryption.md §9](./DESIGN-f1-verifiable-encryption.md#9-security-analysis-phase-1-step-1--the-binding-the-construction-stands-on).
Its Theorem 2 re-establishes the dark-node-closure binding (P4.a / row 14) *without* the pairing.
The sharper **publish-`s₁`** variant (Corollary 5) reduces the lock to validator-only and *fully
eliminates* per-node DKG (OQ-63), with a threat-model sign-off in
[DESIGN §10](./DESIGN-f1-verifiable-encryption.md#10-threat-model-sign-off-for-publish-s₁-phase-1-step-2):
with the VA reconstruction threshold pinned at the BFT `⌊2K/3⌋+1` quorum, covert deanonymization
requires a **>2/3 validator collusion — already beyond A2** — and stays slashable + un-actable
without an on-chain trace; meanwhile the rogue-committee residual (row 17) is *neutralized*
(the committee holds no decryption material). **Recommended as default; F1-VE (2-of-2) retained as
a high-assurance profile.** Phase-1 step 1 (security) discharged at sketch level; step 2 (sign-off)
done pending governance affirmation of §10.1–3; machine-check pending.

---

## P5 — Sybil influence, via adaptive adversarial modeling

The original P5 read `E[rep share] ≤ f·(1+δ_DSybil) + f²·γ_smoothness`. The honest problem
(SPEC §7.3 caveat): **the DSybil formal bound does not transfer** to PrivaCF (no persistent
social graph, no transitive trust, ephemeral PSI topology), so `δ_DSybil` is a constant we
cannot derive, only fit. Rather than ship a number we can't justify, we reframe P5 as a
**Stackelberg game with a provable structural floor**. This converts the claim from "a
constant" to "a frontier with a proven worst-case-defense lower bound, empirically traced
elsewhere."

### P5.1 The game

A two-stage game `SybilStack`:

- **Defender (leader)** commits, publicly, to a detection mechanism `M = (flags {f_j}, thresholds {θ_j})`
  and structural caps `Σ_struct = (c, f_cap, μ, reputation-floor ρ, w_node_cap, w_cohort_cap,
  k_min, ε_DP)`.
- **Adversary (follower)**, knowing `M` and `Σ_struct`, controls a fraction `f` of admission-cost
  units (A3, VDF-bounded) and chooses a behavioral strategy `S ∈ Σ` (timing, filler
  composition, reputation-build schedule, cluster targeting, coordination cardinality) and an
  allocation of its budget, to maximize realized influence.

Define on strategy `S`:

```
I(S)        = expected fraction of a target's recommendations the adversary controls
p_j(S)      = per-epoch probability flag f_j fires under S      (∈ [0,1])
Surv(S,n)   = ∏_j (1 − p_j(S))^n                                 (survival over n epochs)
C(S)        = admission VDF cost + audience-reconstruction cost + evasion opportunity cost
B           = adversary budget (A3)
```

The adversary's program and the resulting influence bound:

```
E[influence] ≤  max_{S ∈ Σ,  C(S) ≤ B}   I(S) · Surv(S, n)
```

### P5.2 The provable structural bound `I_struct` (behavior-independent) — closed form

The inner `I(S)` is capped *regardless of detection* by `Σ_struct`. This is the part provable
**without any empirical `p_j(S)`** — the worst-case (undetected sleeper, I3) guarantee. We
derive a closed form for `I_struct`, the maximum fraction of a *single target node `v`'s*
recommendation-aggregation weight an adversary can control with **no detector firing**.

**Model.** Node `v` ranks candidates by aggregating trust-weighted endorsements from its peers
(§3.2, §3.4). Split `v`'s aggregation weight into the two tiers of §5.7 / §7.1b:
`w_c` on the cluster (PSI-confirmed) tier and `w_b` on the bridge tier, `w_c + w_b = 1`, with
`w_b` user-settable and `w_b = 0` a permitted choice (§5.7). Write:

```
π_s  := p(a cluster peer is sybil | it passed PSI overlap θ_cluster)      // §7.1b cluster term
β_s  := p(a bridge peer is sybil) ≤ |S|/|N|                               // §7.1b bridge term, base rate
h_c, h_b := hop distance of the cluster / bridge contribution (direct peer = 1)
```

and recall the per-source structural attenuators (all in `Σ_struct`): hop attenuation
`μ^{h}` (§5.7), the per-node trust cap `f_cap` (a sybil supplies at most fraction `f_cap` of
any item's capped trust `c`, §7.3), the reputation floor `ρ` (a sybil contributes **0** until
its band reaches `ρ`; let `1_{≥ρ} ∈ {0,1}` be that gate under discrete bands), and the
network-wide cohort cap `w_cohort_cap` (§7.6).

**Derivation.** Per tier, the controlled-weight fraction is (sybil rate) × (per-source cap)
× (hop attenuation) × (floor gate), and the two tiers add (§7.1b decomposition):

```
I_struct(v) = min(  w_c · π_s · f_cap · μ^{h_c} · 1_{≥ρ}      // cluster term
                  + w_b · β_s · f_cap · μ^{h_b} · 1_{≥ρ},     // bridge term
                  w_cohort_cap )                              // network-wide cap binds the sum
            ≤ min(  f_cap · μ · ( w_c · π_s + w_b · |S|/|N| ),   w_cohort_cap )   // direct peers h=1, β_s ≤ |S|/|N|
```

**`E[influence] ≤ I_struct(v)` holds with no detection**, because each factor is a hard
structural cap, not a detector output. The two operating regimes that matter (matching the
§7.1b prose):

- **Non-targeted niche (the common long-tail case).** Sybils did not construct item sets
  overlapping `v`'s niche, so PSI filtering drives `π_s → 0` and the cluster term vanishes:
  `I_struct(v) ≤ w_b · f_cap · μ · |S|/|N|`. **Setting `w_b = 0` (§5.7) makes this exactly
  `0`** — a fully-undetected adversary of *any* size injects nothing into a non-targeted
  niche, at the cost of losing cross-cluster discovery.
- **Targeted niche (§8.2 T5 / row 21 residual).** A patient adversary builds item sets
  specifically to pass `θ_cluster`, so `π_s` can approach `1` and the cluster term dominates:
  `I_struct(v) ≤ f_cap · μ · w_c  (+ bridge term)`, capped by `w_cohort_cap`. Non-zero but
  bounded — this is exactly the named residual where PSI filtering is weak.

**Sanity / monotonicity.** `I_struct` scales linearly in the adversary base rate `|S|/|N|`
(bridge) and in `π_s` (cluster) — bigger or better-targeted adversary, more influence, as
expected; shrinks with `μ<1` and `f_cap<1`; is killed by `w_b=0` (non-targeted) or `π_s=0`
(PSI filter); and is hard-capped by `w_cohort_cap` network-wide. **This is the honest,
provable core of P5** — a direct consequence of the caps, no detector required — and it
isolates the single irreducible term (targeted cluster) rather than burying it in a fitted
constant.

> **Strategy-contingency caveat (E3, §7.3).** `I_struct` flows through the *ranking* terms
> (`novelty`, `item_weight`) that derive from capped trust — **not** through the raw
> co-occurrence similarity channel, which `c` does not bound. A pluggable strategy (§3.8) that
> consumes the gossip stream *without* the capped-trust-derived damping (e.g. plain cosine CF)
> does **not** inherit `I_struct` against a co-occurrence push and must rely on the active
> §7.4 FoolsGold signal. P5.2 is therefore a guarantee for the *reference* strategy and any
> strategy that applies the capped-trust terms; it is **not** substrate-universal. This is a
> real limit worth stating prominently.

### P5.3 The detection multiplier (calibrated, not proven) — and why it isn't trivially defeated

Above the floor, `Surv(S,n)` is what detection buys. We cannot prove `p_j(S) > 0` for an
arbitrary `S` from first principles, but we *can* prove the **structure** that makes evasion
costly:

- **Compound decay.** If any flag has `p_j(S) > 0`, `Surv(S,n) → 0` exponentially in `n`
  (§7.1b). The only escape is `p_j(S) ≈ 0` for *all* `j` simultaneously.
- **Independent evasion costs.** Driving each `p_j(S)` down has an independent price that also
  *reduces `I(S)`*: staggering admissions (kills T.1) delays payload; randomizing filler (kills
  T.4 similarity) dilutes the push; adding participation variance (kills T.5 smoothness)
  forfeits the smooth high-reputation that gave leverage. So the `max` in P5.1 is taken over a
  region where lowering detection lowers influence — the source of the original `f²·γ` term,
  now interpreted as **the curvature of the influence/detection Pareto frontier** rather than a
  fitted constant.
- **Closed-loop adaptation is bounded by observability.** An *adaptive* adversary adjusts `S`
  using observed flag outcomes. PrivaCF deliberately limits that gradient: committee-side flags
  and **two-sided cross-peer flag-rate exchange** (§7.4) mean the adversary cannot fully observe
  whether it has been flagged, so it cannot cleanly hill-climb to the `p_j ≈ 0` corner. This is
  the design lever that keeps the adaptive game from collapsing to "find the blind spot once."
  Formalized in §P5.3.1.

#### P5.3.1 The observability bound (formal shape)

Let `F_t ∈ {0,1}^J` be the adversary's true per-flag state at epoch `t` (which of the `J` flags
fired on it) and `O_t` the adversary's *observations* of that state. A closed-loop adversary's
only advantage over the **open-loop** optimum (commit to one `S` from priors, never adapt) comes
from the information `O_t` carries about `F_t`. Per epoch that information is the mutual
information `I(F_t ; O_t)`, and by the data-processing + Pinsker chain the closed-loop edge over
`n` epochs is bounded by

```
Adv_closed(n) − Adv_open  ≤  Σ_{t≤n} √( ½ · I(F_t ; O_t) )  ≤  n · √( ½ · I_max ),
   where  I_max = max_t I(F_t ; O_t)  ≤  H(O_t)  ≤  log |𝒪|
```

and `𝒪` is the alphabet of what the adversary can actually see. The PrivaCF design drives
`I_max` down by construction:

- **Own flags are not self-reported.** `sim_flag` and the compound flags are computed
  committee-side / by peers (§7.4), so the adversary never directly reads `F_t` — it sees only
  downstream *consequences* (audit frequency, eventual verdicts), which are delayed and coarse.
- **Only flag-*rate aggregates* are exchanged**, not per-pair flags (§7.4 "two-sided
  cross-peer flagging"), so `|𝒪|` is the small alphabet of a rate bucket, not the `2^J` of the
  full flag vector. `log|𝒪|` is therefore a handful of bits, not `J` bits.

**What this gives, and what it does not.** The bound shows closed-loop adaptation cannot help
*more than* `n·√(I_max/2)`, and that `I_max` is a **tunable design parameter**: coarser
aggregation and more committee-side (vs. self-reported) flag computation shrink it toward an
open-loop game, where the P5.2 floor + P5.3 compound decay already apply. It is **not** a clean
theorem yet — `I(F_t;O_t)` must be bounded for the *concrete* aggregation scheme (how many
buckets, how delayed, how noised), which is calibration-dependent. So P5.3.1 is a *conditional*
bound: it reduces "can an adaptive adversary defeat detection" to "bound `I(F_t;O_t)` for the
deployed flag-aggregation scheme," and tells the implementer which knob (`I_max`) controls it.

### P5.4 The irreducible corner (named residual)

Two strategies sit at the hard corner and define what P5 does **not** promise:

1. **The sleeper (I3).** `p_j(S) ≈ 0` during accumulation by construction (behaves legitimately,
   then activates). Compound decay does not apply; **the only defense is the structural floor
   `I_struct`** (P5.2). P5's promise here is *damage-bounding*, not detection.
2. **The mimic novelty-kill (row 9, T4).** An adversary that reconstructs a victim's
   pre-existing neighborhood `N(X)` and emits diverse-yet-coherent fans is *statistically a
   genuine niche surge* — **no content signal can split them** (exp 5.47 / `experiment_killsep`).
   Bounded only by non-content axes: audience-reconstruction cost + per-Sybil admission cost
   (`C(S)`), and the §7.1a admission-burst / trust-velocity *timing* signals. This is exactly
   why row 9 is **PARTIAL**, not H.

### P5.5 What P5 now claims, honestly

```
P5 (adaptive form).  For any adversary strategy S in the budget-feasible region:
   E[influence] ≤  I_struct                                        — PROVEN  (caps; §7.1b)
                 · Surv(S, n)                                       — CALIBRATED (p_j(S) empirical)
   with Surv(S,n) → 0 exponentially in n  unless  p_j(S) ≈ 0 ∀ j,  — STRUCTURAL (§7.1b)
   and the p_j ≈ 0 corner is reachable only by the I3 sleeper and the row-9 mimic,
   for which the binding guarantee is I_struct and C(S), not detection.    — NAMED RESIDUAL
```

**This is strictly more honest *and* stronger than the old single-`δ_DSybil` line:** the
floor is genuinely proven, the decay structure is genuinely structural, and the two corners
where neither helps are named rather than buried in a fitted constant. Phase 5 (§9.2) supplies
the empirical `p_j(S)` curves; the detection contract §7.9 is the per-`(T,I)`-cell instantiation
of this game, and each B/H/PARTIAL row is one measured point on the frontier.

**What remains.** (i) ~~Pin `I_struct` to a closed form~~ — **done** (§P5.2); what is left is
*empirical estimation of `π_s`* (the post-PSI sybil rate among cluster peers) for a targeted
adversary, which is an OQ-10 path-A/B (stochastic-block-model) sharpening. (ii) Phase-5
measurement of `p_j(S)` for the detection-contract strategy set (OQ-10, very high effort,
partly live-deployment-only). (iii) A formal statement of the observability bound in P5.3 (how
much the cross-peer flagging degrades closed-loop adaptation) — currently a design argument,
not a theorem.

---

## Committee compromise scaling — `q_eff(profile)` (exp-5.49 scaffold)

§4.9.8 bounds oversight-chain compromise by a Chernoff argument: for a committee of size `K_d`
drawn from an eligible pool with adversarial fraction `q`, a majority-threshold compromise has

```
P(level-d compromise) = P( Bin(K_d, q) ≥ ⌊K_d/2⌋+1 )  ≤  exp( −K_d · D(½ ‖ q) ),
   with  D(½ ‖ q) = −½ ln( 4 q (1−q) )      (Bernoulli KL, decreasing in q on (0, ½))
```

The open question §4.9.8 defers is *how the transport profile changes the effective `q`*, and
hence how much larger `K_d` must be under Loopix (one diversity axis) than under Tor/I2P (two).
This scaffold makes that precise so exp-5.49 only has to supply two constants.

**Effective-`q` model.** Committee selection is constrained to spread members across cluster
partitions on `m` independent diversity axes (`m = 1` interest-only under Loopix; `m = 2`
interest + behavioral under Tor/I2P — behavioral signal is too thin under Loopix, SPEC §6.2).
Each independent axis the committee is forced to spread across dilutes a *concentrated*
adversary's reachable seats by a per-axis factor `ρ ∈ (0,1]` (how much of the adversary's mass
survives one extra orthogonal partition constraint):

```
q_eff(m) = q_raw · ρ^{m−1}        ⇒   q_Loopix = q_raw   (m=1),   q_Tor = q_raw·ρ   (m=2)
```

**Committee-size compensation.** Setting the two profiles' per-level compromise probabilities
equal, `K_Loopix · D(½‖q_Loopix) = K_Tor · D(½‖q_Tor)`, gives the size ratio Loopix must pay for
its lost axis:

```
K_Loopix / K_Tor  =  D(½ ‖ q_raw·ρ) / D(½ ‖ q_raw)   >  1
```

(strictly `> 1` because `q_raw·ρ < q_raw` and `D(½‖·)` is decreasing, so the Tor divergence is
larger). This is the formal content of the spec's "scale `K_d` up under Loopix to compensate"
(§4.9.8) — Loopix needs a proportionally larger committee, by exactly the ratio of KL
divergences at the two effective `q`s.

**Worked shape.** With `q_raw = 0.3` and a moderate per-axis dilution `ρ = 0.7`
(`q_Tor = 0.21`): `D(½‖0.3) ≈ 0.0823`, `D(½‖0.21) ≈ 0.196`, so `K_Loopix/K_Tor ≈ 2.4`. A
Tor/I2P committee of `K = 9` would need `K ≈ 21` under Loopix for equal compromise resistance —
illustrative only; the load-bearing claim is the *ratio formula*, not these numbers.

**`q` is bounded by A2.** `q_raw` is itself capped by Assumption A2: an adversary pushing
`q_raw ≥ ½` in the eligible pool has already broken honest-majority, at which point consensus,
the verdict process, and watchdogs collapse together (§4.9.8). So this scaffold operates strictly
in the `q < ½` regime where `D(½‖q) > 0` and the bound bites.

**What remains (exp-5.49).** Two constants: the eligible-pool `q_raw` for the target network and
the per-axis dilution `ρ` (equivalently, measure `q_eff` directly per profile). Plug into the
ratio for the per-profile `K_0, ΔK`. This is the `q_eff(profile)` scaffold the prior session
left open; it now reduces exp-5.49/5.42 to estimating `(q_raw, ρ)` rather than designing the
model from scratch.

## Composition over the protocol lifetime

Per-epoch failures of A1 and per-arbitration committee-threshold failures compose by union
bound (SPEC §1.7):

```
Pr[lifetime A1 failure]            ≤ T_life · Pr[no honest neighbor in an epoch]
Pr[lifetime committee-threshold]   ≤ N_arbitrations · Pr[≥K malicious in a selected committee]
```

The §4.1 redesign makes the second a union over **arbitrations actually invoked**, not over
all committees ever selected — the trust-localization improvement. With per-epoch member
rotation + slashing-enforced share deletion, no past committee retains capability to
reconstruct any `snapshot_v(T)` beyond its custody epoch. This deletion dependency remains for
**behavioral-snapshot** custody (assumed, slashing-enforced) but **no longer** for `null_v`
forward secrecy (closed by P4). Oversight-chain escape probability decays exponentially in
depth by the Chernoff argument (§4.9.8), under committee independence.

---

## OQ-15 — `trust_total` stability under flooding (convergence, no autonomous oscillation)

**Claim.** The local `trust_total` accumulator has **no autonomous oscillatory mode**. For any
fixed input regime it converges monotonically to a fixed point bounded by the DSybil cap `c`.
Any oscillation observed under sustained adversarial flooding is **forced** — a faithful, bounded
tracking of a time-varying input (the on-off reputation loop, SPEC §8.2 T1), not an instability
the trust mechanism generates on its own.

**Model.** Fix an item `X` at a receiving node. Per SPEC §3.4 / §7.3, the node accumulates

```
trust_total_t(X) = Σ_{v ∈ A_t(X)}  b_t(v) · g(v, X),     g(v,X) = max(0, r_v(X)+noise)·Δ_base·(1+κ·novelty(X)) ≥ 0
```

over the set `A_t(X)` of announcers seen up to epoch `t`, each contribution scaled by the
announcer's score-band weight `b_t(v) ∈ {b₁<…<b₄}` (§6.1, a bounded multiplier, `b₄/b₁ = O(1)`).
The DSybil gate (§7.3) freezes accumulation once the cap is reached, and the per-node share is
capped:

```
if trust_total_t(X) ≥ c:  no further contribution is admitted
per-node:                 b_t(v)·g(v,X) ≤ f_cap · c
```

**Proof.**

1. *Boundedness.* The gate admits new mass only while `trust_total < c`, and a single admitted
   contribution is `≤ f_cap·c`. Hence `trust_total_t(X) ≤ c + f_cap·c = (1+f_cap)·c` for all `t`
   (one bounded overshoot at the boundary epoch, then frozen). The state lives in a compact
   interval `[0, (1+f_cap)c]`.

2. *Monotonicity for fixed bands.* Hold the band weights `b(v)` fixed (the "fixed input regime").
   Every term is `≥ 0` (the `max(0,·)` guard) and the announcer set only grows (`A_t ⊆ A_{t+1}`),
   so `{trust_total_t}` is non-decreasing. A non-decreasing sequence bounded above converges
   (monotone convergence). **A monotone sequence cannot oscillate** — there is no decrease
   operator in the dynamics, so no limit cycle exists.

3. *No positive feedback, no cross-coupling (the structural core).* The two quantities derived
   from `trust_total` are both **strictly monotone-decreasing** in it:
   `item_weight = 1/log(2 + effective_trust/c)` and the novelty damping `(1+κ·novelty)` as
   `trust_total → c`. Both are *negative* feedback. Crucially, the §6.1 reputation score contains
   **no `trust_total` term**, so the only coupling is one-directional
   `band → trust_contribution`; there is no loop `trust_total → reputation → band → trust_total`.
   The system is a **cascade, not a feedback loop** — a cascade of a convergent monotone stage
   into monotone-decreasing read-outs cannot self-oscillate.

4. *Forced oscillation is bounded tracking.* Drop the fixed-band assumption: under SPEC §8.2 T1
   an adversary drives an announcer's band up and down (on-off). Then `b_t(v)` is an exogenous
   square wave and `trust_total` tracks it. This is *forced*, not autonomous: amplitude is bounded
   by the band ratio times the capped per-node share, `≤ (b₄/b₁)·f_cap·c = O(c)`, and the driver
   T1 is itself damped by the `Δ_rise` rate limit and calibrated independently (exp 5.4). A stable
   linear/saturating stage driven by a bounded periodic input produces a bounded periodic output
   of the same period — expected behavior, not a stability defect.

**Conclusion.** OQ-15's structural half is **closed**: `trust_total` is a bounded, convergent,
strictly-negative-feedback accumulator with no autonomous oscillation. The only residual is the
*amplitude/quality impact* of the forced T1 oscillation on recommendations, which is the existing
exp-5.4 calibration of `Δ_rise` (not a convergence question). Cross-ref SPEC §7.3, §10.2 OQ-C1.

---

## OQ-57 — reputation laundering vs. the admission-cost rate limit

OQ-57 has two halves. The **cost-amortization half closes analytically** (below), conditional on
one spec hardening; the **fingerprint half is empirical but non-load-bearing** because admission
cost is the floor regardless.

**Half 1 — laundering does not amortize admission cost (analytic).**

*Threat.* An adversary cycles through `k` identities (whitewashing / proactive rotation, SPEC
§7.6 T.6), hoping the per-identity admission cost amortizes across cycles so the effective
identity-creation rate exceeds the A3 budget model.

*The three amortization routes and why each is blocked:*

1. **Compute amortization — blocked by the VDF being sequential.** Admission requires an `n`-step
   VDF chain `vdf_proof_t = VDF_eval(vdf_proof_{t-1}, δ_identity)` (SPEC §4.3). Within one chain
   the VDF is *inherently sequential* — more cores give no speedup. Across `k` independent
   identities the adversary may run `k` chains in parallel, but that consumes `k·n·τ`
   processor-seconds (`τ = time(δ_identity)`): the marginal cost of the `k`-th identity is exactly
   `n·τ`, identical to the first. Identity-creation rate is therefore `≤ (processor budget)/(n·τ)`
   — precisely the linear A3 admission-cost-fraction model. **No within-chain speedup ⇒ no
   compute amortization.**

2. **Reputation/temporal-depth amortization — blocked by per-identity binding.** Reputation and
   temporal depth attach to `epoch_id = Poseidon(sk, beacon_T, null_v, …)` (§4.2), derived from
   the identity's own `sk`. A fresh identity has a fresh `sk`, hence zero inherited reputation and
   zero depth; the §4.3 "accumulated temporal depth is retained" clause applies to the *same*
   identity resuming after a gap, not to transfer across identities. So laundering forfeits all
   accrued reputation each cycle — there is nothing to amortize, only to abandon.

3. **Precomputation amortization — blocked by live, beacon-bound checkpoints.** The admission
   window interleaves the VDF with **interaction checkpoints at VRF-determined epochs** requiring
   live PSI handshakes with randomly-selected existing nodes (§4.3). These depend on future
   `beacon_T` values and the live peer set, so they cannot be precomputed ahead of choosing the
   identity, and they impose a **calendar-time floor of `n` epochs per identity** that no amount
   of hardware removes. They also load the honest peer set — exactly the surface the §7.1a
   admission-burst / first-observation detector watches, so `k` concurrent admissions are *more*
   visible, not less.

> **Required spec hardening (surfaced by this analysis — the load-bearing precondition for route
> 1).** SPEC §4.3 writes the chain recurrence but does **not** state what seeds the chain start
> `vdf_proof_{t₀}`. For the VDF to rate-limit *identities* (not merely *chains*), the chain must be
> **cryptographically bound to the identity genesis** — i.e. `vdf_proof_{t₀} = H("vdf_genesis", C_id)`
> where `C_id` commits to the identity (e.g. `null_v` / a genesis commitment to `sk`), and the
> admission verifier checks this seed. Without it, one completed chain could be replayed to admit
> many identities, or chains could be precomputed in bulk before identities are chosen — collapsing
> the linear cost to `O(1)` and **defeating OQ-57's Half 1**. With it, each identity needs its own
> from-scratch chain and Half 1 holds. This is added to §4.3 as a normative requirement.

*Half-1 conclusion.* Under the genesis-seeded chain, the three amortization routes are closed:
laundering costs full `n·τ` processor-time **and** a full `n`-epoch live-checkpoint window **per
identity**, with zero reputation carryover. The admission-cost rate limit is **amortization-proof**;
sustained rotation buys nothing over one-shot Sybil creation. Closed analytically.

**Half 2 — fingerprint stability under deliberate variation (empirical, but bounded).**

The second half — does behavioral fingerprinting (§6.2) still re-link a launderer who
*deliberately varies* their behavior across cycles — cannot be settled analytically: robustness
of a behavioral classifier against an adaptive mimic is inherently a measurement question
(exp 5.46). SPEC §7.6 T.6 already concedes the worst case: against deliberate variation the
fingerprint degrades and the defense reduces to *admission cost alone*. The point this analysis
adds: **that worst case is non-catastrophic.** Because Half 1 makes admission cost amortization-
proof, even a perfect behavioral mimic remains rate-limited at `(budget)/(n·τ)` identities;
fingerprinting is a *secondary* detection layer whose failure narrows but does not breach the
primary rate limit. The residual is bounded, named, and reduces to the same A3 budget the whole
Sybil story already rests on.

**Net for OQ-57.** Half 1 (cost amortization) is **closed** modulo the §4.3 genesis-seed
hardening; Half 2 (fingerprint) stays empirical (exp 5.46) but is demoted to defense-in-depth by
Half 1. Cross-ref SPEC §4.3, §7.6 T.6, §7.2.

---

## Summary — status after this companion

| Property | Was (SPEC §1.7) | Now | Bottoms out in | Hardest open item |
|---|---|---|---|---|
| **P1** Unlinkability | proven (sk) | sketch given; PRF-tight; **`ε_loopix` pre-bound derived (§P1.1)** | `ε_PRF` + `ε_transport` (`≤ f^L + residual/n̄`) | pin `C_SDA` (exp 5.51) |
| **P2** Pref. indist. | proven (sk) | sketch given; **DP fix adopted in §4.5** (clean `ε`-DP, δ=0, clamp post-processing) | Pedersen(perfect) + `ε_perm` + clean `ε`-DP | pin `ε_eff` (OQ-55); lifetime `Tε` not claimed |
| **P3** Suspension | proven (sk) | sketch given; cleanest | `ε_coll` + `ε_Π` | none (needs circuit, = P-feasibility) |
| **P4** Forward-secure | proven (sk) | **theorem (§P4.1)** + DST registry (App. A) + **F1 verifiable-encryption restructuring proven (DESIGN §9, no new assumption)** | `ε_BLS` + `ε_IBE` / co-DBDH + DL, A2/A4 | machine-check (P4.1 + DESIGN §9); bridge benchmark |
| **P5** Sybil influence | partial | **closed-form `I_struct` (§P5.2) + observability bound (§P5.3.1) + named corners** | caps (proven) + `p_j(S)` (empirical) | OQ-10 `p_j(S)`; bound `I(F;O)` for real scheme |
| **OQ-15** `trust_total` stability | structural (asserted) | **proposition: convergent, no autonomous oscillation** (cascade w/ negative feedback) | monotone-convergence + no `trust_total`→reputation loop | amplitude of *forced* T1 oscillation (exp 5.4, calibration) |
| **OQ-57** laundering vs. rate limit | open | **Half 1 (cost) closed analytically**; Half 2 (fingerprint) demoted to defense-in-depth | sequential VDF + per-identity binding + live checkpoints (A3) | §4.3 genesis-seed hardening (added); fingerprint robustness (exp 5.46) |
| **P-feasibility** | — | **NEW HARD GATE** | Statement-5 desktop benchmark (OQ-3 desktop), substrate built | blocks all of the above in practice |

**P-feasibility (the gate, concern #4).** None of P1–P5 is a property of a *paper*; they are
properties of the *implemented substrate*. Before any P-claim is creditable in deployment:
(a) Layers 1–4 must be implemented through SPEC §9.2 Phase 3; (b) the desktop Statement-5
circuit (adopted publish-`s₁` form: split with public `s₁` + `d_T` verifiable-encryption binding
+ SMT non-membership, **no in-circuit pairing**) must hit its benchmark — a *bad* answer here
changes the design, not just the parameters. This is now a release gate in SPEC §1.7 and §10.1.1,
not an implicit assumption.

---

## Appendix A — Domain-separation-tag (DST) registry and CI invariant

P4's confidentiality rests on a hidden assumption that the spec states in prose but never
pins: that no BLS signature produced for one purpose can serve as the IBE decryption key for
another. The "signature *is* the IBE key" instantiation (§4.9.4, P4.1) makes this load-bearing
— a DST collision between, say, block signing and `SUSPEND-IBE` would let an ordinary consensus
signature decrypt a committee `s₁` share. This appendix fixes the registry and the CI invariant
that must enforce it. It is a **release blocker** (§4.9.4, §10.1.1).

**BLS hash-to-curve DST registry** (RFC 9380 framing; one row per distinct signing purpose):

| Tag                       | Purpose                                              | Signer set        | Doubles as IBE key for |
|---------------------------|------------------------------------------------------|-------------------|------------------------|
| `DST_CONSENSUS`           | block-finality threshold signature (`validator_sigs`)| validator set     | — |
| `DST_SCOREBAND`           | committee score-band attestation (§4.1)              | audit committee   | — |
| `DST_SUSPEND_IBE`         | committee sig on `"SUSPEND epoch_id_T"`              | audit committee   | `c_T^{(i)}` (share `s₁`) |
| `DST_VERDICT_FINALIZED`   | validator sig on `"VERDICT_FINALIZED epoch_id_T"`    | validator set     | `d_T` (share `s₂`) |
| `DST_GOSSIP_AUTH`         | gossip-message authentication                        | individual node   | — |
| `DST_RELAY_ATTEST`        | relay-submission attestation                         | relay node        | — |
| `DST_VRF` (RFC 9381 suite)| validator / committee / relay selection             | individual node   | — (separate VRF suite) |

*(The Poseidon input domain separators — `"null_v"`, `"epoch_id"`, `"perm"`, `"chop_n"`,
`"epoch_offset"`, `"niche_delay"`, `"continuity_token"`, `"leaf_salt"`, `"ann_token"`,
`"psi_ack"` — live in a **separate namespace** (Poseidon inputs, not hash-to-curve DSTs); their
collision-freedom is OQ-4, closed. The CI test below covers the BLS/VRF table, which is the one
P4 depends on.)*

**CI invariant (must hold at every release):**

```
I1  Pairwise distinctness.  All tags in the registry are byte-distinct.
I2  Non-prefix.             No tag is a prefix of another (belt-and-suspenders over RFC 9380
                            length framing).
I3  IBE alignment.          The hash-to-curve DST used by ForwardCommit.Enc for slot c_T^{(i)}
                            equals DST_SUSPEND_IBE, and for d_T equals DST_VERDICT_FINALIZED —
                            encryption and the signature-as-decryption-key use the SAME tag.
I4  Usage isolation.        DST_SUSPEND_IBE and DST_VERDICT_FINALIZED are emitted ONLY inside
                            their canonical flows (verdict reveal §4.9.6 / verdict finalization
                            §4.1). Validators MUST reject any signature presented under these
                            two tags outside those flows — this is what prevents a committee
                            member or validator from minting an IBE decryption key by signing an
                            unrelated message.
```

**Reference CI check (pseudocode — the build fails if it raises):**

```python
DST = {  # the single source of truth; mirrored by the implementation's constants
  "CONSENSUS", "SCOREBAND", "SUSPEND_IBE", "VERDICT_FINALIZED",
  "GOSSIP_AUTH", "RELAY_ATTEST", "VRF",
}
tags = [actual_dst_bytes(name) for name in DST]      # pull the real byte strings
assert len(set(tags)) == len(tags)                   # I1
for a in tags:                                        # I2
    assert not any(b != a and b.startswith(a) for b in tags)
assert ibe_enc_dst("SUSPEND")  == actual_dst_bytes("SUSPEND_IBE")        # I3
assert ibe_enc_dst("VERDICT")  == actual_dst_bytes("VERDICT_FINALIZED")  # I3
# I4 is a runtime consensus rule, asserted by a verifier unit test:
assert verifier_rejects_sig_under(dst="SUSPEND_IBE",      outside_flow=True)
assert verifier_rejects_sig_under(dst="VERDICT_FINALIZED", outside_flow=True)
```

I1–I3 are static (a few lines, run on every build). I4 is a consensus-rule unit test against the
block validator. Together they discharge the "DST-collision CI test required before release"
clause (§4.9.4) and close the only non-cryptographic assumption P4.1 leans on.
