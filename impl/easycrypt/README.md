# EasyCrypt formalization — limb verifiable encryption (DESIGN §9)

Machine-checking the security write-up for the F1 construction
(`../../DESIGN-f1-verifiable-encryption.md` §9).

## Status — honest

These are **v0 scaffolds for a run → paste-errors → fix loop**, not verified proofs.
EasyCrypt syntax and stdlib names drift between versions, and the author could not
run EC in the environment where these were written. Expect the first `easycrypt`
run to surface syntax/name errors; paste them back and they get fixed iteratively.

| File | Target | State |
|---|---|---|
| `limb_ve_indcpa.ec` | **Thm 1** — IND-CPA of one limb, reduced to DDH | **PROVED** (easycrypt exit 0, **no `admit`**, 2026-06-07). The per-limb IND-CPA advantage = the DDH advantage (`lemma conclusion`), machine-checked with Z3/Alt-Ergo. Built on the insight that the limb ciphertext `(g^ρ, K^ρ·G^m)` *is* ElGamal of `G^m`, so it instantiates EC's `DiffieHellman`+`PKE_CPA` and reuses the standard ElGamal proof. **Scope:** DDH abstraction of the mask (real instantiation is DBDH-in-ROM, identical proof shape); single limb (k-limb hybrid = next); does not cover Thm 2. |
| `limb_ve_correctness.ec` | **Thm 2, algebraic pillars** — correctness + binding | **PROVED** (easycrypt exit 0, no `admit`, 2026-06-07). `limb_dec_correct`: honest box `(g^ρ, K^ρ·G^m)` opened with the recipient key recovers `G^m` exactly (discrete logs → field → `ring`). `limb_box_binding`: a box opens to at most one `(mh, ρ)` — no two-faced openings (logs → field-cancellation via `smt(@ZPF)`). |
| `limb_ve_soundness.ec` | **Thm 2, protocol piece** — special-soundness of the sigma proof | **PROVED** (easycrypt exit 0, no `admit`, 2026-06-07). `sigma_extract`: two accepting transcripts (same commitment `(A,B)`, different challenges `c1≠c2`) pin `U`,`W` to the extracted exponents — i.e. a prover answering two challenges must know a real opening (`U=g^ρ`, `W=G^m·K^ρ`). Proof: logs of the verifier equations → field linear-combination → `ring`. **No pairing needed** (soundness is about the group representation). |

**Fix-loop log (Thm 1):** v0 had two issues — untyped multi-`var` (cosmetic; types added) and the local name `U` clashing with an EC builtin → renamed `U`,`W` to `cu`,`cw`. After that, exit 0.

## How to run

```bash
eval $(opam env)          # if a fresh shell
easycrypt limb_ve_indcpa.ec
```

Silent exit = it checked. Run all three: `for f in limb_ve_*.ec; do easycrypt $f; done`.

## What's done (all machine-checked, no `admit`, 2026-06-07)

The **algebraic core of both theorems** is verified across four lemmas:
- Thm 1 confidentiality — `limb_ve_indcpa.ec : conclusion`
- Thm 2 correctness — `limb_ve_correctness.ec : limb_dec_correct`
- Thm 2 binding (group-level) — `limb_ve_correctness.ec : limb_box_binding`
- Thm 2 binding (message-level) — `limb_ve_correctness.ec : limb_msg_unique` (unique *limb* m, given G a generator)
- Thm 2 special-soundness (extraction) — `limb_ve_soundness.ec : sigma_extract`

## ⚠️ ULTRAPLAN — truly hard tasks (research-grade EC, do NOT "go for it" casually)

> These are **not** the algebra lemmas already banked. Each is a qualitatively harder class
> of EasyCrypt formalization: multi-day, expert-level, real chance of *not* converging in a
> blind run→fix loop. None changes the security *story* — the cores they build on are already
> machine-checked and the math is textbook — but formalizing them is a slog. Tackle one only
> as a **deliberate, scoped mini-project** with the expectation of many iterations, never as a
> quick follow-up. Difficulty ratings are relative to the 5 banked algebra lemmas (= 🟢).
>
> If you (the user) want one of these done, say so explicitly and expect it to be slow.

1. **🔴🔴 Soundness PoK wrapper (rewinding extractor).** Wrap `sigma_extract` in a
   probabilistic rewinding/forking argument: turn "a prover who answers two distinct challenges
   on the same commitment" into "the prover knows the witness with non-negligible probability."
   Notoriously hard to formalize in EC (probabilistic reasoning over rewound executions,
   `pHoare`/`byphoare` plumbing, the forking lemma). The *extraction algebra* it relies on is
   already done (`sigma_extract`); this is purely the probabilistic envelope.

2. **🔴 k-limb hybrid for Thm 1.** Lift single-limb IND-CPA (`conclusion`) to all `k≈16` limbs:
   a game-hop chain over independent `ρ_j`, advantage `→ k·ε`. ~100+ lines, new multi-message
   module + a sequence of `equiv` hops. Routine in *kind* for an EC expert, but a real
   bookkeeping effort and easy to stall on stdlib/version drift.

3. **🔴 Range-proof integration** (`m_j ∈ [0,2^b)`). Needed for "decryption *terminates*"
   (BSGS bound), complementary to binding/extraction. Requires modeling the range argument and
   threading its guarantee into the decryption-termination statement.

4. **🔴🔴 (optional rigor) Literal DBDH/pairing redo of Thm 1.** Redo confidentiality over the
   actual DBDH/pairing instead of the DDH abstraction, and build a genuine pairing theory for
   the decryption identity `e(σ,U)=K^ρ` (currently captured by the standard ElGamal
   sk-knowledge abstraction). Largest of the four — essentially standing up a pairing
   formalization. Pure rigor upgrade; the abstraction it replaces is already accepted practice.

## Proof-technique notes (banked for reuse)

- **Group equalities → take discrete logs** (`apply log_bij` / `rewrite log_bij`), push `loge`
  inward (`logDr`, `logrzM`, `loggK`, `logg1`), then **`ring`** (or `smt(@ZPF)`) over the
  exponent field. SMT can't do multiplicative-group algebra directly.
- Field-typed power lemmas live in `PowZMod` inside `Group.ec` (`expM/expD/exp0/expN/loge*`);
  the top-level `Group.ec` `expM/expD` are **int**-typed and won't match.
- Pitfalls hit: local name `U` clashes with an EC builtin (rename); `rewrite -h in H`
  (reverse-rewrite-in-hypothesis with a local hyp) throws "unknown lemma" — restructure to
  rewrite the goal; pass the field theory to smt as `smt(@ZPF)`, bare `smt()` under-powers.
