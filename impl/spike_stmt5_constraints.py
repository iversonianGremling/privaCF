"""Statement-5 Phase-0a constraint estimate — companion to ../SPIKE-statement5.md.

The real benchmark needs a Plonky3/Rust build. But the *decisive* Phase-0a question —
"is the in-circuit ForwardCommit (BF-IBE over BLS12-381) pairing the wall?" — can be
answered now from published gadget constraint costs, to order of magnitude. That is
enough to choose GREEN vs the RED fix path before anyone writes a circuit.

Cost model (all annotated with their basis; ranges = low/high to bound the estimate):

  Poseidon 2-to-1 hash      ~135–300 constraints   (Plonky2/3 native Poseidon)
  SMT non-membership path   depth · Poseidon       (naive depth 256; compacted ~log2(occupied))
  non-native Fp mul         ~50–200 constraints    (381-bit BLS12-381 base field emulated
                                                     over Plonky3's small field, schoolbook
                                                     limbs + modular reduction)
  Fp muls per ate pairing   ~8 000–16 000          (BLS12-381 optimal-ate: Miller loop +
                                                     final exponentiation, Fp12 via Karatsuba)
  pairings in Statement 5   N_fallback + 1         (one ForwardCommit check per committee slot
                                                     + d_T; §4.9.5)

The pairing term is non-native because Plonky3 proves over a small field (Goldilocks/
BabyBear), while BLS12-381 arithmetic lives in a 381-bit field — every Fp op becomes many
small-field limb ops. This is the classic in-circuit-pairing blowup (the reason 2-chains
like BLS12-377/BW6-761 exist).

Run:  python3 spike_stmt5_constraints.py
"""

from __future__ import annotations


def stmt5(poseidon, smt_depth, n_fallback, fp_mul, fp_per_pairing):
    n_pairings = n_fallback + 1
    c_poseidon = (2 + smt_depth) * poseidon          # null_v, epoch_id, + SMT path
    c_pairing = n_pairings * fp_per_pairing * fp_mul  # the suspect
    return c_poseidon, c_pairing, c_poseidon + c_pairing


def fmt(n):
    return f"{n/1e6:.2f}M" if n >= 1e6 else (f"{n/1e3:.0f}k" if n >= 1e3 else f"{n:.0f}")


def proof_band(constraints):
    """Order-of-magnitude desktop (multicore) proof-gen, anchored at ~1M constraints ≈
    1–5 s for a FRI prover and scaled linearly. DELIBERATELY rough — a leaning, not a
    measurement (the real number is the spike's Phase-1 output)."""
    lo = constraints / 1e6 * 1.0
    hi = constraints / 1e6 * 5.0
    return lo, hi


def line(label, poseidon, smt_depth, F, fp_mul, fp_pair):
    cp, cpair, tot = stmt5(poseidon, smt_depth, F, fp_mul, fp_pair)
    lo, hi = proof_band(tot)
    share = cpair / tot * 100
    print(f"  {label:<28} {fmt(cp):>8} {fmt(cpair):>9} {fmt(tot):>9}  {share:>5.1f}%   ~{lo:.0f}–{hi:.0f}s")


def main():
    F = 3  # N_fallback
    print("=" * 92)
    print("Statement-5 constraint estimate  (N_fallback=%d ⇒ %d in-circuit pairings)" % (F, F + 1))
    print("=" * 92)
    hdr = f"  {'scenario':<28} {'poseidon':>8} {'pairing':>9} {'TOTAL':>9}  {'pair%':>6}   proof-gen (rough)"
    print(hdr); print("  " + "-" * (len(hdr) - 2))

    # SMT compacted (~25 levels for ~10^7 occupied) unless noted; pairing low/high bracket.
    print("  --- WITH in-circuit pairing (Statement 5 as specified, §4.9.5) ---")
    line("optimistic (fp_mul=50)",   200, 25, F, 50,  8000)
    line("midpoint  (fp_mul=120)",   200, 25, F, 120, 12000)
    line("pessimistic(fp_mul=200)",  200, 25, F, 200, 16000)
    line("+ naive SMT depth 256",    200, 256, F, 120, 12000)

    print("  --- WITHOUT in-circuit pairing (RED-fix #1: bind via hash, verify enc off-circuit) ---")
    # Zero pairings: Statement 5 = Poseidons (null_v, epoch_id) + SMT path + ~8 extra
    # Poseidon binds of s1/s2/ciphertext commitments. No Fp/pairing emulation at all.
    cp = (2 + 25 + 8) * 200          # poseidon-only; n_pairings = 0
    tot = cp
    lo, hi = proof_band(tot)
    print(f"  {'hash-bind only':<28} {fmt(cp):>8} {fmt(0):>9} {fmt(tot):>9}  {0.0:>5.1f}%   ~{lo*1000:.0f}–{hi*1000:.0f}ms")

    print("  " + "-" * (len(hdr) - 2))
    print("\nReading:")
    print("  • The in-circuit pairing DOMINATES — ~99%+ of constraints in every WITH-pairing")
    print("    row. Everything else (Poseidons, even a naive 256-deep SMT) is rounding error")
    print("    next to (N_fallback+1) BLS12-381 pairings emulated over a small field.")
    print("  • WITH pairing: ~2–10M constraints ⇒ desktop AMBER/RED and mobile RED (OQ-3).")
    print("  • WITHOUT pairing (move ForwardCommit encryption-correctness OUT of the ZK circuit,")
    print("    bind s₁/s₂/ciphertext with Poseidon, let validators run ForwardCommit.Verify")
    print("    non-ZK at reveal, §4.9.6): ~10–20k constraints ⇒ sub-second, GREEN, mobile-plausible.")
    print("  • VERDICT: Statement 5 as literally specified is AMBER/RED; the dominant cost is")
    print("    a design choice (in-circuit pairing), not a fundamental cost. Take RED-fix #1.")
    print("  • Caveat: order-of-magnitude estimate from published gadget costs, NOT a Plonky3")
    print("    run. The 99%-pairing-dominance conclusion is robust to the ranges; the absolute")
    print("    proof-time band is rough and must be confirmed by the spike's Phase-1 build.")
    print("=" * 92)


if __name__ == "__main__":
    main()
