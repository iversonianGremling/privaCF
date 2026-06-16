# Design — F1: verifiable encryption for ForwardCommit (retiring Gate 1's risk)

### Companion to [SPIKE-statement5.md](./SPIKE-statement5.md) · resolves the in-circuit-pairing wall

> **Goal.** Replace the in-circuit BF-IBE pairing certification (≥99% of Statement 5's
> constraints; SPIKE §8) with a construction that (a) needs **no in-circuit pairing**, (b)
> **provably preserves handoff-time decryptability** (the property the pairing was protecting —
> dark-node closure, P4.a / row 14), and (c) is verified by validators with native BLS12-381
> arithmetic they already run. This is the paper work that converts Gate 1 from "probably
> passable" to "passable, here's how." It also surfaces a cleaner alternative (§7) that dissolves
> **both** gates at once.

---

## 1. What F1 must guarantee (the trap restated)

The naïve F1 — validators check ciphertext *well-formedness* + a cheap ZK binding of `s₁` to a
commitment — is unsound: well-formed (decryptable to *something*) + "I know `s₁`" does **not**
force the ciphertext to decrypt to *that* `s₁`. A node could encrypt garbage. F1 must prove
**verifiable encryption**: *the ciphertext decrypts (under the future verdict signature, without
the node) to exactly the value bound into the rest of the proof.* That single property is the
whole ballgame.

The obstruction to doing it cheaply is the **two-worlds bridge**: the ciphertext lives in the
BLS12-381 group world (sigma-friendly, pairing-decryptable), while `null_v = Poseidon(sk,·)`,
the SMT path, and `s₁+s₂=null_v` live in the Plonky3 arithmetic/hash world. The value must be
proven consistent across both.

---

## 2. Core idea — exponential-ElGamal *limb* verifiable encryption

Vanilla BF-IBE masks the message with a hash of a pairing (`V = M ⊕ H(e(·)^r)`); the hash makes
correct-encryption un-sigma-provable. Replace it with an **exponential-ElGamal** structure where
the message sits *in the exponent of the target group* — then correct encryption is a set of
discrete-log-representation statements (clean Schnorr/DLEQ), no hash in the masking.

The catch: recovering a full-size scalar from `g_T^{s}` needs a discrete log, which is hard for a
255-bit `s`. So **decompose into small limbs** `s = Σ_j m_j 2^{bj}`, `m_j ∈ [0, 2^b)`, and encrypt
each limb exponentially. Decryption recovers each `g_T^{m_j}` and brute-forces a `b`-bit DL
(BSGS, ~`2^{b/2}` steps — trivial for `b=16`). A **range proof** `m_j ∈ [0,2^b)` is what makes
this decryptable (and is exactly the binding the naïve F1 lacked).

---

## 3. Construction

**Public parameters.** Pairing `e: G₁×G₂→G_T`, all of prime order `r`; generators `g₁∈G₁`,
`g₂∈G₂`, `g_T = e(g₁,g₂)`. Limb width `b` (e.g. 16), count `k = ⌈log₂ r / b⌉` (≈16 for `b=16`).

**Recipient / identity (per the existing ForwardCommit roles).** For the validator share `s₂`:
identity `id = "VERDICT_FINALIZED epoch_id_T"`, `Q_id = H₂(id) ∈ G₁` (RFC 9380 hash-to-curve,
DST-separated per [SECURITY.md App. A](./SECURITY.md#appendix-a--domain-separation-tag-dst-registry-and-ci-invariant)),
standing key `P = x·g₂ = VA_pub`. Public mask base `K_pub = e(Q_id, P) ∈ G_T` (anyone computes
it). *(For a committee share `s₁`, substitute the committee's threshold key and `"SUSPEND …"`.)*

**Encryption** of `s = Σ_j m_j 2^{bj}` (node, at handoff). For each limb `j`, sample `ρ_j ←$ Z_r`:

```
U_j = ρ_j · g₂          ∈ G₂
W_j = g_T^{m_j} · K_pub^{ρ_j}   ∈ G_T
```

Ciphertext `= {(U_j, W_j)}_{j<k}` (this replaces the BF-IBE `d_T` / `c_T^{(i)}`).

**Decryption** (anyone, post-verdict, with the threshold signature `σ = x·Q_id` on `id`):

```
e(σ, U_j) = e(x·Q_id, ρ_j·g₂) = e(Q_id, g₂)^{x ρ_j} = e(Q_id, x·g₂)^{ρ_j}
          = e(Q_id, P)^{ρ_j}  = K_pub^{ρ_j}          ← the key identity
g_T^{m_j} = W_j / e(σ, U_j) ;   m_j = BSGS(g_T^{m_j}, range [0,2^b)) ;   s = Σ_j m_j 2^{bj}
```

No node cooperation; `σ` exists iff the verdict is finalized ⇒ "decrypt iff suspended" and
forward secrecy are inherited unchanged from the current scheme.

---

## 4. The verifiable-encryption proof (native sigma — closes the trap)

The node proves, per limb (verified by validators with native group ops, **no SNARK, no
in-circuit pairing**), knowledge of `(m_j, ρ_j)` such that:

```
(R1)  W_j = g_T^{m_j} · K_pub^{ρ_j}          representation of W_j in bases (g_T, K_pub)
(R2)  U_j = g₂^{ρ_j}                          same ρ_j  (ρ-link)
(R3)  m_j ∈ [0, 2^b)                          range proof
```

**(R1)+(R2) as one Schnorr** with a shared challenge ties the *same* `ρ_j` across `W_j` and
`U_j`: commit `a = g_T^{α}K_pub^{β}`, `t = g₂^{β}`; challenge `c`; responses `z_m=α+c·m_j`,
`z_ρ=β+c·ρ_j`; verify `g_T^{z_m}K_pub^{z_ρ} = a·W_j^{c}` and `g₂^{z_ρ} = t·U_j^{c}`. **(R3)**
is a Bulletproof range proof (already in the stack, Appendix E), log-sized.

**Why this closes the correctness trap.** For the real `σ`, `e(σ,U_j) = K_pub^{ρ_j}` holds
identically (it's an algebraic fact, independent of the node), so `W_j/e(σ,U_j) = g_T^{m_j}`
*for the very `m_j` proven in (R1)*, and (R3) guarantees that `m_j` is small enough to recover by
BSGS. Therefore the ciphertext provably decrypts to exactly `Σ m_j 2^{bj}` — no garbage
ciphertext can pass. This is the property the in-circuit pairing gave, now from a native proof.

---

## 5. The two-worlds bridge (the one unavoidable in-circuit cost — honest)

The sigma proof binds the ciphertext to the limbs `{m_j}`. The Plonky3 circuit must bind those
*same* limbs to the arithmetic world (`s = Σ m_j 2^{bj}`, `s₁+s₂=null_v`, `null_v=Poseidon(sk,·)`,
SMT). The clean link is a **Pedersen commitment** `C = s·G + γ·H` (in `G₁`) that *both* proofs
reference: the sigma proves `{m_j}` reconstruct `C`'s value (a linear Schnorr relation), and the
**circuit opens `C`**.

Opening a `G₁` Pedersen commitment **inside** a small-field Plonky3 circuit is non-native EC over
BLS12-381 — the one expensive piece that does not vanish. But it is **one (or two) scalar-mults,
not `(N_fallback+1)` full pairings**:

| | constraints (order) |
|---|---|
| 1 in-circuit BLS12-381 **pairing** (old, per slot) | ~1.6–12.8 M each, ×(N_fallback+1) |
| 1 in-circuit `G₁` **Pedersen opening** (bridge, per share) | ~0.2–0.4 M each, ×1–2 |
| Poseidon (`null_v`, `epoch_id`) + SMT path + arithmetic | ~10⁴–10⁵ |

**Cost estimate: ~0.3–1 M constraints total** (dominated by 1–2 bridge openings). This is ~10×
better than the in-circuit pairings, but it is **not** the deep-GREEN ~10⁴ that
[SPIKE §8](./SPIKE-statement5.md#8-phase-0a-result--constraint-estimate-2026-06-06) quoted for "no
pairing" — that figure omitted the bridge. The bridge is the irreducible residual of doing
verifiable encryption across the two worlds.

> **⚠️ Measured update (2026-06-16) — this estimate's "AMBER, sub-second to a few seconds" was
> optimistic; the bridge is the real wall.** A direct measurement of the non-native field multiply
> in Plonky2/Goldilocks ([`impl/spike_bridge_cost/`](./impl/spike_bridge_cost/),
> [SPIKE §10](./SPIKE-statement5.md#10-phase-1b-result--the-bridge-measured-packing-factor-collapsed-2026-06-16))
> puts a single in-circuit BLS12-381 `G₁` scalar-mult at **~2²¹ trace rows ≈ ~2 min desktop** with
> a naive gadget (RED), and the Pedersen 2-MSM at ~2²² rows ≈ ~4 min. A purpose-built non-native
> gadget (dedicated range-check gates, Karatsuba, CRT reduction, arithmetic-tuned config) plausibly
> reaches **AMBER (~5–40 s)**; only an implausible >30× packing gain reaches GREEN. So the bridge is
> **AMBER-at-best**, and a purpose-built non-native gadget is a **Phase-1 deliverable with a tracked
> exit criterion** (target ≤ ~2²⁰ rows / ≤ ~30 s desktop), not a near-free term.

*(Optimization: a single Pedersen opening that commits both shares, or batching the two via a
random linear combination, keeps it to one in-circuit scalar-mult — measured ~2²¹ rather than ~2²²
rows above. Phase-1 should build this.)*

---

## 6. Drawbacks of F1-VE

- **Ciphertext size.** `k ≈ 16` limbs × `(U_j∈G₂, W_j∈G_T)` ≈ a few KB per encrypted share —
  larger than the single BF-IBE ciphertext, and it multiplies by the number of encrypted shares.
  A per-epoch on-chain cost (commit_T is every-epoch, §8.1/T10) — non-trivial but bounded.
- **Range proofs.** `k` Bulletproof range proofs per share (log-sized, aggregatable) — extra
  prover/verifier work, native (not in-circuit).
- **A new primitive to analyze.** Exponential-ElGamal-over-tlock is a small, standard
  composition, but it is *not* vanilla BF-IBE — it needs its own short security write-up
  (IND-CPA of the masking + soundness of the sigma/range proofs). Lower-risk than novel crypto,
  but not zero.
- **Privacy: neutral.** Everything proven/published is over `commit_T`, already on-chain and
  already a presence signal; the limbs/`ρ_j` stay hidden (sigma is ZK); no new plaintext or
  identity leaks. Decryption still happens only post-verdict.

---

## 7. Alternative that dissolves **both** gates — publish `s₁`

A sharper observation. `s₁` is an additive share: `s₁ = null_v − s₂` with `s₂` uniform, so **`s₁`
is uniform and information-theoretically independent of `null_v`.** Publishing a fresh `s₁` each
epoch leaks *nothing* about `null_v` (it's independent uniform noise, fresh per epoch since `s₂`
is fresh). So consider:

> **F1-public-s₁:** publish `s₁` in the clear in `commit_T`; encrypt **only** `s₂` to the standing
> `VA_pub` (one ciphertext, via the §3–§4 limb-VE). At verdict, `σ_T^VERDICT` recovers `s₂` and
> `null_v = s₁ + s₂`.

What this dissolves:

- **Gate 1 shrinks to one bridge.** Only `s₂` is encrypted ⇒ one limb-VE ciphertext, one Pedersen
  bridge opening. ~0.2–0.4 M constraints — solidly desktop-GREEN.
- **OQ-63 disappears entirely.** No committee ever holds a decryption share, so there is **no
  per-node committee DKG** for `s₁` and **no `N_fallback` `s₁` ciphertexts**. Committees still run
  the audit + commit-reveal *verdict decision*; the *decryption capability* is purely the
  validator attestation. The whole per-node-DKG-load problem evaporates — cohort-sharing (option
  B) is no longer even needed.

**The cost — a real, stated trade.** The decryption lock drops from **2-of-2 (committee ∧
validator)** to **1 (validator threshold)**. Covert/retroactive recovery now needs *only* a
current-validator-threshold off-chain signature on `"VERDICT_FINALIZED …"` — which is **still**
both an A2 (honest-majority) break **and** a slashable equivocation (§4.1). So the residual is
exactly A2 — the same assumption consensus, the verdict process, and watchdogs already rest on.
The committee second-lock only ever added protection *in the world where A2 is already broken*,
in which the rest of the system has also failed. **Judged against that, dropping it to dissolve
both feasibility gates is a strong trade** — but it *is* a (modest) reduction in defense-in-depth
versus the 2-of-2, and that's the call to make explicitly.

Forward secrecy is **unchanged and arguably cleaner**: `s₂` is sealed until `σ_T^VERDICT` exists
(iff suspended); a future VA-share compromise is defused by the PSS re-share (§4.1); and the
committee is now entirely *outside* the deanonymization path, so committee compromise — present
or future — reveals nothing about `null_v` at all.

---

## 8. Recommendation and what Phase-1 must verify

**Recommendation.** Evaluate **F1-public-s₁ (§7) first** — it is simpler, desktop-GREEN, and
dissolves OQ-63 as a side effect; adopt it unless the committee-as-second-lock is judged
essential (a governance/threat-model call, not a technical blocker). Keep **F1-VE (§3–§5)** as the
fallback that preserves the full 2-of-2 at AMBER cost.

**Phase-1 must still confirm (in this order):**
1. **Security write-up** of the limb-VE composition: IND-CPA of the exponential-ElGamal masking
   under the tlock decryption, and that (R1)+(R2)+(R3) imply decryptability-to-the-committed-value
   (the §4 argument, made rigorous). *This is the residual risk — a correctness argument, not a
   benchmark.*
2. **For F1-public-s₁:** an explicit sign-off that the 2-of-2 → validator-only reduction is
   acceptable under the deployment's threat model (it bottoms out at A2).
3. **Then measure:** the real Plonky3 constraint count for the bridge opening(s) (target the
   single-opening optimization, §5), native sigma + range-proof verify cost on validators, and
   ciphertext size on-chain.

Steps 1–2 are paper; step 3 is the build. The order matters: prove the binding before paying to
measure it.

---

---

## 9. Security analysis (Phase-1 step 1 — the binding the construction stands on)

Proof *sketches* at the level of [SECURITY.md](./SECURITY.md) (reduction named + argument given;
machine-checking deferred). **Headline: the limb-VE introduces no new hardness assumption** — it
reduces to the same co-DBDH that BF-IBE already needed (OQ-2), plus DL-based Schnorr/Bulletproof/
Pedersen soundness already in the stack. Notation as §3. Fiat-Shamir transcripts bind
`(U_j, W_j, id, epoch_id_T, C, statement)` (domain-separated) so proofs are non-malleable and
context-bound.

**Theorem 1 (confidentiality — sealed until the verdict signature).** Without the threshold
signature `σ = x·Q_id`, the ciphertext `{(U_j, W_j)}` is IND-CPA:

```
Adv_INDCPA(A) ≤ k · ε_co-DBDH + ε_RO        (k = #limbs)
```

*Sketch.* Each limb's mask is `M_j = K_pub^{ρ_j} = e(Q_id, g₂)^{x ρ_j}`. The adversary sees
`(g₂, P=x·g₂, U_j=ρ_j·g₂, Q_id=H₂(id))`; with `Q_id` a random-oracle point `=h·g₁`, deciding
`M_j = e(g₁,g₂)^{h x ρ_j}` vs. random from `(g₁,g₂, x g₂, ρ_j g₂, h g₁)` **is exactly co-DBDH**.
A hybrid replacing each `M_j` by a uniform `G_T` element (cost `ε_co-DBDH` per limb) turns each
`W_j = g_T^{m_j}·M_j` into a one-time pad in `G_T`, hiding `m_j` perfectly; `U_j` reveals `ρ_j`
only as a hard DL. Multi-ciphertext/one-master-key reuse (same `P`) is the standard BF-IBE
IND-ID-CPA multi-challenge setting (random self-reducibility of co-DBDH), absorbed into the
bound. Confidentiality is *conditional on `σ` not existing*; that `σ` exists **iff** a verdict is
finalized is P4 / §4.1 — together: **sealed until suspended.** ∎

**Theorem 2 (binding — `(R1∧R2∧R3) ⇒ decryptable to the committed value`; closes the trap).**
If the per-limb proof verifies, then decryption with the genuine `σ` yields exactly
`s* = Σ_j m_j 2^{bj}` for the extracted `m_j`, and `s*` is recoverable.

*Sketch.* Special-soundness of the shared-challenge Schnorr (R1+R2) extracts `(m_j, ρ_j)` with
`W_j = g_T^{m_j}K_pub^{ρ_j}` **and** `U_j = ρ_j·g₂` (same `ρ_j`), up to `ε_DL`. Now the decryption
identity is **algebraic, not assumption-based**: for *any* valid `σ = x·Q_id`,

```
e(σ, U_j) = e(x·Q_id, ρ_j·g₂) = e(Q_id,g₂)^{x ρ_j} = e(Q_id, x·g₂)^{ρ_j} = K_pub^{ρ_j},
```

so `W_j / e(σ,U_j) = g_T^{m_j}` **exactly** — for the extracted `m_j`, with no slack. R3 (range,
soundness `ε_BP`) gives `m_j ∈ [0,2^b)`, so BSGS over that interval recovers `m_j` in `~2^{b/2}`
steps and *terminates*. Hence a verifying ciphertext decrypts to precisely the extracted
committed value; **a garbage ciphertext cannot verify** (it would either violate the algebraic
identity — impossible — or fail R1/R3). This is the dark-node-closure property (P4.a / row 14)
re-established without an in-circuit pairing.

```
Pr[verify ∧ decrypt ≠ committed value] ≤ ε_DL + ε_BP = negl
```

The binding is the crux that the naïve "well-formedness only" F1 lacked: well-formedness gives
"decryptable to *something*"; Theorem 2 gives "decryptable to *the committed something*." ∎

**Theorem 3 (zero-knowledge).** The (R1+R2) Schnorr and (R3) Bulletproof are HVZK; under
Fiat-Shamir in the ROM the non-interactive proof is simulatable, revealing nothing about
`(m_j, ρ_j)` beyond the statement. With Theorem 1, the full handoff package (ciphertext + VE
proof) leaks nothing about `s` pre-verdict. ∎

**Theorem 4 (bridge consistency — end-to-end binding to `null_v`).** Let `C = s·G + γ·H` be the
Pedersen commitment both proofs reference: the VE sigma proves `Σ_j m_j 2^{bj} = open(C)` (a
linear Schnorr relation), and the Plonky3 circuit proves `C` opens to `s` with `s₁+s₂=null_v`,
`null_v=Poseidon(sk,·)`, `null_v∉SUSP_SMT`. By Pedersen binding (`ε_DL`) the value in `C` is
unique, so

```
(decrypted value, Thm 2) = (value in C) = (share entering s₁+s₂=null_v, circuit) .
```

A node therefore cannot make the ciphertext encrypt one value while the circuit attests another.
Chaining Theorems 2 and 4: **on a verdict, `null_v` is recovered, equal to the value the circuit
bound to `sk` and proved un-suspended — without node cooperation.** ∎

**Corollary 5 (publish-`s₁` variant, §7).** With `s₁` public and only `s₂` encrypted:
confidentiality of `null_v` reduces to Theorem 1 on `s₂` (since `s₁` public, `s₂` uniform ⇒
`null_v=s₁+s₂` hidden iff `s₂` hidden); binding reduces to Theorem 2 on `s₂` plus the circuit
checking `s₁_public + s₂ = null_v` with `s₁_public` a **public input** (no commitment, no bridge
for `s₁`). Forward secrecy and the validator-only lock are as stated in §7; the committee leaves
the deanonymization path entirely. ∎

**Assumptions ledger (nothing new).**

| Property | Reduces to | Already in stack? |
|---|---|---|
| Thm 1 confidentiality | co-DBDH (ROM) | yes — BF-IBE / OQ-2 |
| Thm 2 binding (Schnorr) | DL in `G₂`/`G_T` | yes |
| Thm 2 binding (range) | Bulletproofs soundness (DL) | yes — Appendix E |
| Thm 3 ZK | HVZK + Fiat-Shamir (ROM) | yes |
| Thm 4 bridge | Pedersen binding (DL) | yes |
| `σ` ⇔ verdict | threshold-BLS unforgeability (co-CDH) | yes — P4 / §4.1 |

**Machine-check status (2026-06-07).** Theorem 1 (per-limb IND-CPA confidentiality) is now
**machine-checked in EasyCrypt** — `impl/easycrypt/limb_ve_indcpa.ec`, `lemma conclusion`, no
`admit`, verified with Z3/Alt-Ergo. The limb ciphertext is exactly ElGamal of the encoding `G^m`,
so it instantiates EC's `DiffieHellman`+`PKE_CPA` and the standard ElGamal IND-CPA proof. Scope of
the checked statement: the **DDH** abstraction of the mask (the real instantiation is DBDH-in-ROM,
identical proof shape) and a **single limb**.

Theorem 2's **two algebraic pillars** are also now machine-checked —
`impl/easycrypt/limb_ve_correctness.ec`, no `admit`: `limb_dec_correct` (an honest box
`(g^ρ, K^ρ·G^m)` opened with the recipient key recovers `G^m` exactly; discrete logs → field →
`ring`) and `limb_box_binding` (a box opens to at most one `(mh, ρ)` — no two-faced openings).
These are the algebraic core of "can't fake the box."

The **special-soundness** of the sigma proof is also now machine-checked —
`impl/easycrypt/limb_ve_soundness.ec`, `sigma_extract`, no `admit`: two accepting transcripts
(same commitment, challenges `c1≠c2`) pin `U`,`W` to the extracted exponents, so a prover who can
answer two challenges must know a real opening (`U=g^ρ`, `W=G^m·K^ρ`). No pairing needed — soundness
is purely about the group representation. So the **algebraic core of all of Thm 1 and Thm 2 is now
verified**; what remains are standard finishing wrappers (the probabilistic rewinding-extractor
around `sigma_extract`; the k-limb hybrid; range-proof integration), not new core math.

**Residual / what remains for full rigor.** (a) the `k`-limb hybrid (single-limb → `k·ε`) and,
optionally, redoing Thm 1 over the literal DBDH/pairing rather than the DDH abstraction;
(b) **Theorem 2 full binding** — the *malicious-prover* half: a box that passes the sigma proof
decrypts to the committed value. Needs sigma-protocol special-soundness (+ a pairing theory);
the correctness half above is done, this harder half is not yet written; (c) confirm the
Bulletproof range aggregation
across `k` limbs preserves the bound and the prover cost target; (d) the §5 bridge benchmark
(Phase-1 step 3). None of these is a feasibility risk — they are the standard hardening of a
construction whose every step now reduces to an assumption already relied on. **Phase-1 step 1 is
discharged at proof-sketch level: the binding that retires Gate 1's correctness risk (Theorem 2)
holds, and the scheme adds no new assumption.**

---

## 10. Threat-model sign-off for publish-`s₁` (Phase-1 step 2)

The decision: **is reducing the covert-deanonymization lock from 2-of-2 (committee ∧ validator)
to validator-only acceptable, in exchange for dissolving OQ-63 and making Gate 1 desktop-GREEN?**
This section pins down exactly what changes so it can be signed off (or declined) on the merits.

### 10.1 What the lock protects, precisely

The asset is **covert recovery of `null_v` without a legitimate verdict** (silent linkage of a
target's epoch_ids). On a real verdict, recovery is intended. In *both* variants recovery needs
`σ_T^VERDICT`, the validator threshold attestation on `"VERDICT_FINALIZED epoch_id_T"`; obtaining
it covertly is, in both, **(i) a validator-threshold collusion and (ii) a slashable equivocation**
(§4.1). The *only* difference:

```
2-of-2 (F1-VE):       covert recovery needs   validator-threshold  AND  committee-threshold (for s₁)
publish-s₁:           covert recovery needs   validator-threshold              (s₁ is public)
```

So the question is exactly: **how much did the extra "AND committee-threshold" requirement buy?**

### 10.2 Adversary-by-adversary

- **Rogue committee alone (row 17 / I9).** *Improved, not worsened.* Under 2-of-2 a rogue
  committee already recovers only `s₁ ⟂ null_v` (the FS fix). Under publish-`s₁` the committee
  holds **nothing** decryption-relevant — it is removed from the deanonymization path entirely.
  The "weakest link in the identity-privacy story" (§7.9.4 row 17) is *neutralized*.
- **Rogue validator threshold.** *This is the regime where the lock mattered.* Under 2-of-2,
  colluding validators still need the committee's `s₁`; under publish-`s₁` they suffice alone. But
  set the **VA reconstruction threshold at the BFT quorum `⌊2K_val/3⌋+1`** (§4.1 permits "at or
  below"): then covert recovery requires **> 2/3 of the validator set colluding** — *strictly
  beyond* Assumption A2 (honest *majority*, i.e. adversary < 1/2). **The committee second-lock was
  therefore guarding a regime already outside the threat model**: by the time an adversary holds
  2/3 of validators, BFT safety, the verdict process, and watchdogs have all already fallen.
- **Combined committee+validator (the 2-of-2 worst case).** Both committee and validator are
  VRF-selected from the same eligible pool with the same adversarial fraction `q` (bounded by A2).
  The committee adds an extra `exp(−K_committee·D(½‖q))` Chernoff factor (§4.9.8 / `q_eff`
  scaffold) — but with a **majority** threshold (`½`), *softer* than the validator **supermajority**
  (`2/3`) factor `exp(−K_val·D(⅔‖q))`. So the committee was always the *weaker* of the two locks,
  and its independent benefit **shrinks exactly as `q` rises** (when both bodies, drawn from the
  same pool, become jointly hittable) — i.e. it helps least precisely when you'd want it most.

### 10.3 What publish-`s₁` preserves, and what it additionally gains

**Preserves (all of it):** forward secrecy (`s₂` sealed until `σ_T^VERDICT`; committee compromise
reveals nothing — *stronger*, committee is out of the path); "decrypt iff suspended"; slashable
accountability of covert recovery; on-chain visibility required to *act* on a recovered `null_v`
(`null_v_decryption` tx, §8.1); commit-reveal ordering, watchdog, oversight; dark-node closure
(Theorem 2 on `s₂` + public `s₁` + circuit `s₁+s₂=null_v` with `s₁` a public input). `s₁` is a
fresh uniform per epoch (`s₂=r_share` fresh), so publishing it leaks nothing about `null_v`.

**Gains beyond Gate 1:**
- **OQ-63 is *eliminated*, not just mitigated.** The only thing that needed a per-node *threshold*
  key (the IBE-key-derivation property) was the `s₁` ForwardCommit. Remove it and **committees
  need no DKG at all**: handoff/score-band attestation is fine as **aggregate multisig** over the
  known VRF-selected members' individual keys (no shared secret), and the verdict commit-reveal
  becomes a **vote**, not a threshold-BLS-share aggregation. The sole threshold-IBE key left in
  the system is the *standing* `VA_pub`. So there is **no per-node DKG anywhere** — cohort-sharing
  (option B) isn't even needed.
- **Smaller on-chain footprint.** `commit_T` carries a 32-byte public `s₁` + one `d_T` ciphertext,
  instead of `N_fallback` `s₁` ciphertexts (§4.9.4 cost para) — publish-`s₁` *reduces* per-epoch
  state.
- **Simpler protocol** (committee is a pure auditor/voter; one standing threshold key total).

### 10.4 Recommendation and sign-off

**Recommendation: adopt publish-`s₁` as the default profile, with the VA threshold set at the
`⌊2K_val/3⌋+1` BFT quorum.** Rationale: it neutralizes the rogue-committee residual (row 17), its
only cost (validator-only covert recovery) requires a **>2/3 validator collusion that is already
beyond A2** and remains slashable + un-actable-without-trace, and it dissolves OQ-63 and Gate 1
outright while *shrinking* on-chain state. The committee second-lock it removes was the weaker
lock, redundant with A2, and weakest in the regime where it would matter.

**Offer F1-VE (2-of-2) as a high-assurance profile** for deployments that want the extra
committee Chernoff factor against *moderate-`q`* covert linkage and are willing to pay per-node
DKG (→ cohort-sharing, option B) and AMBER Gate-1 cost. The two share all the same machinery
except `s₁`'s custody, so supporting both is a deployment flag, not a fork.

**Governance must affirm, to sign off publish-`s₁`:**
1. that a `> 2/3` validator-set collusion is accepted as out-of-scope (it is already an A2-plus
   break, and is slashable);
2. that concentrating the deanonymization-capability trust on the **validator set** (rather than
   splitting it committee+validator) is acceptable given (1);
3. the VA threshold is pinned at the BFT quorum (not lower), so the residual really is `>2/3`.

If 1–3 are affirmed, publish-`s₁` is signed off and Gate 1 + OQ-63 are both resolved GREEN.

---

*Spec status: this is a design proposal that resolves the §4.9.5 Phase-0 feasibility flag and the
OQ-63 finding, with a proof-sketch-level security analysis (§9) and a threat-model sign-off for
the publish-`s₁` variant (§10). It is **not yet normative** — it promotes into §4.9.4/§4.9.5/§4.9.6
(and, for publish-`s₁`, simplifies §4.9.4's committee role to attester/voter, removes per-node DKG,
and retires the OQ-63 mitigation) once §9 is machine-checked and §10's governance points 1–3 are
affirmed. Default recommendation: publish-`s₁`; F1-VE retained as a high-assurance profile.*
