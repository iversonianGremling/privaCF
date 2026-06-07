# Plain-English explainer — what all the "proof stuff" actually means

> You don't need the math to follow this. It's the map for everything in
> `SECURITY.md`, `DESIGN-f1-verifiable-encryption.md`, the `SPIKE-*` / `ANALYSIS-*`
> docs, and `impl/easycrypt/`. If a word looks scary, check the glossary at the end.

---

## 0. The 30-second version

PrivaCF is a recommendation system ("you might also like…") with **no company in the
middle** — nobody owns your data, nobody can see what you like, and fake accounts can't
easily cheat. That's a hard promise. **"The proof stuff" is us checking the promise is
actually true, not just hopeful.** Recently we (a) checked it can really be built, (b) fixed
the two things that didn't quite work, and (c) started getting a *computer* to confirm the
privacy promise is airtight. One big chunk of that is now computer-confirmed; one is still
in progress.

---

## 1. Why bother "proving" anything?

A security claim like *"nobody can unmask a user"* is easy to say and easy to get wrong.
A **proof** means: we show the claim follows from a few well-known, widely-trusted
assumptions — the same kind of math that secures your bank login and HTTPS. If the proof
holds, breaking our promise would require breaking that underlying math, which nobody knows
how to do. **Without a proof, "it's private" is just a vibe.**

There are three honesty levels you'll see in the docs:
- **Proven / machine-checked** — airtight, a computer verified it.
- **Proof sketch** — we've written the argument and named what it relies on, but haven't
  fully formalized it. Strong, but a human could still have missed something.
- **Assumed** — we're taking it as given (e.g. "most of the network is honest").

---

## 2. The one mechanism almost all of this is about: "banned means banned"

The trickiest promise in PrivaCF is: **if you get banned, you can't just make a new account
and come back — but the system also can't spy on you while you're behaving.**

The way it works: every user has a secret **fingerprint** (we call it the *nullifier*). When
someone is banned, the system reveals *just enough* to recognize that fingerprint forever, so
they can't sneak back. The danger is obvious: **what if that fingerprint could be revealed
when you're NOT banned?** That would be silent spying. So a huge amount of "the proof stuff"
is about guaranteeing: *the fingerprint can be unlocked only by a legitimate ban, never
otherwise.*

Think of it as a **lockbox** holding your fingerprint. The whole game is proving the box
opens only when a real ban happens.

---

## 3. The two "can we even build this?" checks (the "gates")

Before building, we checked two things that, if they failed, would mean redesigning:

- **Gate 1 — is the privacy math fast enough?** The lockbox uses heavy cryptography. Could a
  phone actually do it in reasonable time? We found the original design had one step that was
  *way* too slow.
- **Gate 2 — does it clog the network?** The system uses little "juries" to keep people
  honest. We found the original setup made every user run *far* too many jury setups, which
  would flood the network.

**Both had a problem; both got a fix; neither needed a redesign.** Details below.

---

## 4. The two fixes, in plain words

**Fix for Gate 2 — "publish half the secret."** The fingerprint-lockbox secret is split into
two halves. It turns out **one half is completely safe to just publish in the open** (on its
own it's random noise — useless without the other half). Once we publish that half, the juries
no longer need to hold any secret, so the network-clogging setup disappears. The only cost:
unlocking now depends on the network's main referees alone — but cheating them requires more
than two-thirds of them to secretly conspire, which would already mean the whole system has
collapsed. You picked this fix. ✅

**Fix for Gate 1 — "verifiable encryption."** Instead of an expensive in-circuit step, we put
the *other* (locked) half in a box using a cheaper scheme — but with a twist: you can **prove
you put the *right* thing in the box without opening it.** That "prove the right thing is
inside" property is the crucial part (without it, a banned person could stuff the box with
garbage and dodge their ban). The cheaper scheme is called *verifiable encryption*.

A separate measurement (real Rust code, `impl/spike_pairing_cost/`) also showed the original
"slow step" is only slow because of a specific tech choice — on the right setup it's actually
cheap. So Gate 1 has multiple ways out; we picked the one that also fixes Gate 2.

---

## 5. What is EasyCrypt, and what does "machine-checked" mean?

**EasyCrypt is a program that checks security proofs are airtight.** You write the claim and
the argument in its language; it refuses to accept anything with a gap, a hand-wave, or a
logical mistake. Humans miss subtle errors all the time; EasyCrypt doesn't.

So **"machine-checked" is the gold standard**: it means a computer confirmed the proof is
correct, *given* the underlying assumptions. It's much stronger than "an expert read it and it
looks right."

(You installed EasyCrypt on your machine — that's why I can now actually run these checks
instead of just writing them out.)

---

## 6. What we actually got the computer to confirm

**Theorem 1 — "the box keeps the secret hidden until a real ban."** In plain terms: someone
watching everything PrivaCF publishes **cannot figure out your fingerprint** as long as you
haven't earned a ban. We wrote this in EasyCrypt and it **passed — machine-checked, no
gaps** (`impl/easycrypt/limb_ve_indcpa.ec`).

How we pulled it off cheaply: it turned out our box is mathematically *identical* to a famous
50-year-old encryption scheme (ElGamal) whose privacy is already a textbook proof. So we
reused that proof instead of inventing one.

**Two honest asterisks** (these don't undermine it, but I won't pretend they're not there):
- It's proven against a slightly **simplified math model** of the assumption (the standard one
  used for this kind of scheme — the full version has the same shape).
- It covers **one box at a time**. The real thing uses ~16 little boxes; proving "all 16
  together" is routine bookkeeping we haven't done yet.

---

## 7. What's still to prove (and it's the important one)

**Theorem 2 — "you can't cheat by putting garbage in the box."** This is the property that
actually stops a banned person from dodging their ban with a fake box. It has **three pieces**:
- **The box gives back exactly what you put in** (honest case, right key). ✅ **machine-checked**
  (`impl/easycrypt/limb_ve_correctness.ec`).
- **A box can be opened to only one secret** ("binding" — you can't open the same box two
  different ways). ✅ **machine-checked** (same file).
- **The verification check actually catches a malformed box.** ✅ its **core is now
  machine-checked** (`impl/easycrypt/limb_ve_soundness.ec`): the math proving that *if you can
  answer two different random challenges for the same box, a real secret can be pulled out of
  your answers* — i.e. you can't bluff the check. What's left is a **standard finishing wrapper**
  (called a "rewinding extractor") that turns "can answer twice" into "definitely knows the
  secret"; it's routine formal bookkeeping, not new math.

So if Theorem 1 is "the box hides the secret," Theorem 2 is "the box can't be faked" — and the
**math behind all three of its pieces is now machine-checked**, with only standard finishing
wrappers (the rewinding step here; the "all 16 boxes at once" hybrid for Theorem 1) remaining.

---

## 8. Honest scorecard (no jargon)

| The promise | Plain meaning | Where it stands |
|---|---|---|
| Hidden until banned | Can't learn your fingerprint unless you're really banned | ✅ **machine-checked** (1 box, simplified model) |
| Box returns what you put in | Opened with the right key, the box gives back the exact value (honest case) | ✅ **machine-checked** |
| Box opens to only one secret | You can't open the same box to two different values ("binding") | ✅ **machine-checked** |
| The check catches a fake box | A banned user can't slip a *malformed* box past the verification step | ✅ **core machine-checked** (the math: "you can't answer two random challenges without actually holding a real secret") — a standard finishing wrapper ("rewinding") remains |
| All ~16 boxes together | The full-size version, not just one box | ⏳ routine, not done |
| Banned-means-banned | Same key always → same fingerprint → stays out | ✅ proof-sketch (clean, in `SECURITY.md`) |
| Can build it (speed) | Phones can do the crypto in time | ✅ resolved (the fix in §4) |
| Can build it (network) | Doesn't flood the network | ✅ resolved (publish-half-the-secret) |
| "Most of the network is honest" | The thing everything ultimately leans on | 🔒 assumed (standard, unavoidable) |

---

## 9. Glossary — scary word → one line

- **Nullifier** — your secret, permanent fingerprint; the thing the lockbox protects.
- **Forward secrecy** — even if attackers break in *later*, they still can't unlock *past*
  secrets.
- **IND-CPA** — the formal name for "an eavesdropper can't tell what's encrypted." (Theorem 1.)
- **Binding / soundness** — the formal name for "you can't have put a different thing in the
  box than you claimed." (Theorem 2.)
- **DDH / DBDH** — the well-known hard math problem our privacy rests on (cousins of the math
  behind HTTPS). "Breaking our privacy = solving this," which nobody can.
- **Verifiable encryption** — a box you can prove you filled correctly without opening it.
- **Zero-knowledge proof** — proving a statement is true while revealing nothing else.
- **Sigma protocol** — a common, efficient style of zero-knowledge proof.
- **EasyCrypt** — the program that machine-checks security proofs.
- **The two "gates"** — the two "can we even build this?" feasibility checks (speed; network load).
- **publish-`s₁`** — the chosen fix: publish the safe half of the split secret.
- **Committee / validators** — the rotating "juries" and the main "referees" that keep the
  network honest.

---

## 10. Where to go for the real version

- **Big picture + all promises:** `SECURITY.md` (the security companion).
- **The Gate-1 fix in full:** `DESIGN-f1-verifiable-encryption.md` (§7 publish-`s₁`, §9 the
  proofs, §10 the decision you signed off).
- **The "can we build it" checks:** `SPIKE-statement5.md`, `ANALYSIS-dkg-load.md`.
- **The actual machine-checked proof:** `impl/easycrypt/limb_ve_indcpa.ec` (run it with
  `easycrypt impl/easycrypt/limb_ve_indcpa.ec` — silent = it passed).
