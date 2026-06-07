"""OQ-63 feasibility sim — per-epoch committee-DKG liveness over a Loopix mixnet.

Companion to ../ANALYSIS-dkg-load.md. The analytic pass established that per-node DKG
load is O(1) in N (≈ N_fallback·K_committee committees per eligible node) and that the
binding constraints are (a) eligible-pool concentration N/E and (b) getting that many
concurrent multi-round DKGs to complete inside the §4.1 DKG window over a high-latency,
fixed-send-rate mixnet. Compute is negligible; this sim models the two real walls:

  THROUGHPUT  a node can only push λ_send messages/sec into the mixnet (the Loopix
              cover-traffic send rate, OQ-58). Its per-epoch DKG out-volume is
                  V_out = memberships · K · R
                        = (N/E)·F·K  ·  K · R   = (N/E)·F·K²·R
              (each committee membership ⇒ ~K share/broadcast messages per round, R
              rounds). Time to push them is V_out/λ_send; if that alone exceeds the
              window W_dkg, the node cannot complete its DKG duties — RED, independent
              of latency.

  LATENCY     even with infinite send rate, each DKG serializes R rounds, and a round
              completes only when the slowest of its ~K² messages arrives. Per-message
              latency is the sum of H per-hop Exp delays (Gamma(H, d_hop)). The latency
              floor for one DKG is  R · E[max over K² of Gamma(H,d_hop)].

Verdict per cell: bind = max(throughput_time, latency_floor) vs W_dkg.

No dependency beyond numpy. Run:  python3 spike_dkg_liveness.py
"""

from __future__ import annotations
import numpy as np

RNG = np.random.default_rng(0)


def round_max_latency(K, H, d_hop, n_mc=20000):
    """E[max over K*(K-1) messages of Gamma(H, mean=d_hop)] — the time for one DKG
    round to complete (all members have all shares). Monte Carlo."""
    n_msg = K * (K - 1)
    # Gamma(shape=H, scale=d_hop): sum of H Exp(mean d_hop) per-hop delays.
    draws = RNG.gamma(shape=H, scale=d_hop, size=(n_mc, n_msg))
    return draws.max(axis=1).mean()


def dkg_time(K, F, R, H, d_hop, lam_send, n_over_e):
    """Total wall-clock for a node to discharge its DKG duties this epoch.
    Returns (throughput_time, latency_floor, binding_time, V_out)."""
    memberships = n_over_e * F * K              # committees this node sits on
    V_out = memberships * K * R                 # out-messages this epoch
    throughput_time = V_out / lam_send          # send-rate limited
    latency_floor = R * round_max_latency(K, H, d_hop)  # one DKG's serial round latency
    # The node runs its memberships' DKGs concurrently; the binding time is the larger
    # of "time to physically send all messages" and "latency to finish the slowest DKG".
    binding = max(throughput_time, latency_floor)
    return throughput_time, latency_floor, binding, V_out


def verdict(binding, W_dkg):
    if binding <= 0.5 * W_dkg:
        return "GREEN"
    if binding <= W_dkg:
        return "AMBER"
    return "RED"


def main():
    # --- fixed protocol defaults (§4.9.4) ---
    K = 21          # K_committee
    F = 3           # N_fallback
    R = 3           # DKG rounds (commit / share / finalize) — Pedersen-style
    H = 3           # Loopix path length (hops)
    EPOCH = 3 * 3600  # 3 h epoch (§4.1), seconds

    print("=" * 80)
    print("OQ-63 — committee-DKG liveness over Loopix  (K=%d, F=%d, R=%d, H=%d hops)" % (K, F, R, H))
    print("per-eligible-node out-volume  V_out = (N/E)·F·K²·R = (N/E)·%d messages/epoch" % (F * K * K * R))
    print("=" * 80)

    # --- sweep the real knobs ---
    n_over_e_vals = [1, 3, 5, 10]          # eligible-pool concentration N/E
    lam_send_vals = [1.0, 2.0, 5.0]        # mixnet send rate (msg/s) — Loopix cover rate (OQ-58)
    d_hop = 5.0                            # mean per-hop mix delay (s) — mid Loopix setting
    W_frac = 0.20                          # DKG window = 20% of epoch (§4.1)
    W_dkg = W_frac * EPOCH

    print(f"\nDKG window W_dkg = {W_frac:.0%} of epoch = {W_dkg/60:.0f} min ;  "
          f"per-hop mix delay d_hop = {d_hop:.0f}s ;  latency floor / DKG "
          f"= {R*round_max_latency(K,H,d_hop)/60:.1f} min\n")

    hdr = f"  {'N/E':>4} {'λ_send':>7} {'V_out':>8} {'send-time':>10} {'lat-floor':>10} {'binding':>9}  {'vs W':>6}  verdict"
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for noe in n_over_e_vals:
        for lam in lam_send_vals:
            tput, lat, binding, V = dkg_time(K, F, R, H, d_hop, lam, noe)
            v = verdict(binding, W_dkg)
            print(f"  {noe:>4} {lam:>6.0f}/s {V:>8.0f} {tput/60:>8.1f}m {lat/60:>8.1f}m "
                  f"{binding/60:>7.1f}m  {binding/W_dkg:>5.2f}x  {v}")
    print("  " + "-" * (len(hdr) - 2))

    # --- what's the binding wall? throughput almost always, since V_out is large ---
    print("\nReading:")
    print("  • LATENCY is a non-issue: one DKG's R rounds finish in a couple of minutes,")
    print("    far inside a %d-min window. Mixnet *delay* is not the wall." % (W_dkg/60))
    print("  • THROUGHPUT is the wall: pushing V_out = (N/E)·F·K²·R messages through a")
    print("    fixed-rate (λ_send) Loopix sender is what blows the window. Required rate:")
    for noe in n_over_e_vals:
        V = noe * F * K * K * R
        req = V / W_dkg
        print(f"      N/E={noe:>2}:  V_out={V:>6}  ⇒  need {req:>4.1f} msg/s sustained for {W_dkg/60:.0f} min")
    print("  • This couples directly to OQ-58: λ_send is the anonymity cover rate; you cannot")
    print("    raise it freely to clear DKG without spending bandwidth/anonymity budget.")

    # --- mitigation B: per-cohort shared committees collapse the membership count ---
    print("\nMitigation B (per-cohort shared committees) — one DKG'd key serves a cohort of")
    print("  size g, so a node's *own* commit_T needs only its F committees done, and the")
    print("  network runs (N/g)·F DKGs total instead of N·F. Per-eligible-node memberships")
    print("  fall by ~g.  Required send rate at N/E=5 vs cohort size g:")
    noe = 5
    for g in [1, 5, 20, 100]:
        V = (noe / g) * F * K * K * R
        req = V / W_dkg
        tag = "(= per-node, option A)" if g == 1 else ""
        print(f"      g={g:>3}:  V_out≈{V:>6.0f}  ⇒  {req:>4.1f} msg/s  {tag}")
    print("  The 2-of-2 split (P4) makes sharing security-cheap: a shared-committee compromise")
    print("  yields only s₁ ⟂ null_v, not cohort-wide deanonymization.")
    print("=" * 80)


if __name__ == "__main__":
    main()
