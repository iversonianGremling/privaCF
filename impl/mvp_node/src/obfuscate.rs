//! Preference obfuscation in transit — SPEC §4.5, ported from the Python PoC `obfuscate.py`.
//!
//! Two mutually-exclusive deployment modes transform the *gossip* a node broadcasts (its
//! positive-preference row), while the node's own local vector — the query in `recommend::score_all`
//! — stays clean (negative weights and the un-obfuscated history never leave the device):
//!
//!   * [`chop`] (niche-friendly): transmit ~`keep_frac` of each row's positive entries, the rest
//!     dropped; optionally pad back up with cover items drawn toward low-trust (novel) items so the
//!     transmitted *count* is uninformative about the true preference count. §4.5 "Variable chopping".
//!   * [`laplace`] (formal DP): L1-normalise the row, add `Laplace(0, S/ε)` (S = 2) on the *active*
//!     dimensions, then **clamp the output to `[0, B]`** (B public) and renormalise. §4.5.
//!
//! Faithful detail (the 2026-06-06 correction to SPEC §4.5 / SECURITY.md §P2): the DP mode achieves
//! sign preservation by a **data-independent output clamp** to `[0, B]`, NOT by the old
//! data-dependent noise truncation `|noiseᵢ| < |p_v[i]|`. The clamp + renormalise are post-processing
//! of the noised vector, so by DP's post-processing immunity the mechanism is **clean ε-DP (δ = 0)**.
//! The old clip conditioned the output on a data-dependent event and therefore voided nominal ε-DP;
//! [`LaplaceMethod::ClipLegacy`] is retained only so the E2 experiment can show the contrast. Noise is
//! applied to active dimensions only — which-items privacy is chopping/permutation's job (§4.5), so
//! inactive dims stay exactly 0 in both methods.

use crate::recommend::Matrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const EPS: f64 = 1e-8;

/// Inverse-CDF Laplace(0, b) sampler. With `U ~ Uniform(-1/2, 1/2)`,
/// `X = -b·sgn(U)·ln(1 − 2|U|)` is Laplace-distributed with scale `b`.
fn laplace_sample(rng: &mut StdRng, scale: f64) -> f64 {
    let u: f64 = rng.gen::<f64>() - 0.5; // U ∈ (−0.5, 0.5]
    let s = if u < 0.0 { -1.0 } else { 1.0 };
    -scale * s * (1.0 - 2.0 * u.abs()).max(f64::MIN_POSITIVE).ln()
}

/// Which post-processing the DP mechanism applies after adding noise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaplaceMethod {
    /// Default — **correct, clean ε-DP (δ = 0)**: `renormalise(clamp(p + noise, 0, B))`.
    Clamp,
    /// **Old — voids ε-DP; kept only for the E2 contrast**: `max(0, p + clip(noise, −|p|, |p|))`.
    ClipLegacy,
}

/// Laplace DP obfuscation (§4.5, corrected to clean ε-DP).
///
/// L1-normalises each row (so `‖p_v‖₁ = 1`, making sensitivity `S = 2` meaningful when `normalize`),
/// adds `Laplace(0, S/ε)` on the active dimensions, then post-processes per `method`. A non-finite
/// `epsilon` is the normalise-only reference point (isolates the cost of noise from the cost of the L1
/// renormalisation). `bound` is the public deployment constant `B`.
pub fn laplace(
    pref_pos: &Matrix,
    epsilon: f64,
    seed: u64,
    sensitivity: f64,
    bound: f64,
    normalize: bool,
    method: LaplaceMethod,
) -> Matrix {
    let mut rng = StdRng::seed_from_u64(seed);

    pref_pos
        .iter()
        .map(|row| {
            // L1-normalise the row.
            let mut out: Vec<f64> = row.clone();
            if normalize {
                let l1: f64 = out.iter().map(|x| x.abs()).sum();
                let l1 = if l1 == 0.0 { 1.0 } else { l1 };
                out.iter_mut().for_each(|x| *x /= l1);
            }

            // ε = ∞ ⇒ normalise-only reference (just the non-negativity projection).
            if !epsilon.is_finite() {
                return out.iter().map(|&x| x.max(0.0)).collect();
            }

            let scale = sensitivity / epsilon;
            match method {
                LaplaceMethod::Clamp => {
                    for x in out.iter_mut() {
                        if *x > 0.0 {
                            let noise = laplace_sample(&mut rng, scale);
                            *x = (*x + noise).clamp(0.0, bound); // data-independent → ε-DP preserved
                        }
                    }
                    if normalize {
                        let l1: f64 = out.iter().sum();
                        let l1 = if l1 == 0.0 { 1.0 } else { l1 };
                        out.iter_mut().for_each(|x| *x /= l1); // renormalise (post-processing)
                    }
                    out
                }
                LaplaceMethod::ClipLegacy => {
                    for x in out.iter_mut() {
                        if *x > 0.0 {
                            let cap = x.abs(); // data-dependent cap (DP-voiding)
                            let noise = laplace_sample(&mut rng, scale).clamp(-cap, cap);
                            *x = (*x + noise).max(0.0);
                        }
                    }
                    out
                }
            }
        })
        .collect()
}

/// Variable chopping (§4.5). Each node transmits a subset of its positive preferences: ~`keep_frac`
/// of each row's nonzero entries (at least 1 if the row has any), chosen by a per-node random draw.
/// With `cover = true` the dropped slots are padded back with cover items so the transmitted count is
/// uninformative about the true preference count; cover items are sampled toward low-trust (novel)
/// items per `trust_total`/`c` (favouring items with little global trust).
pub fn chop(
    pref_pos: &Matrix,
    keep_frac: f64,
    seed: u64,
    cover: bool,
    cover_scale: f64,
    trust_total: Option<&[f64]>,
    c: Option<f64>,
) -> Matrix {
    let mut rng = StdRng::seed_from_u64(seed);
    let n_items = pref_pos.first().map_or(0, |r| r.len());

    // Cover-item base weights ∝ 1/log(2 + trust_total/c): low-trust (novel) items favoured.
    let base_w: Vec<f64> = match trust_total {
        None => vec![1.0; n_items],
        Some(tt) => {
            let cc = c.unwrap_or_else(|| {
                let mut pos: Vec<f64> = tt.iter().copied().filter(|&x| x > 0.0).collect();
                pos.sort_by(|a, b| a.partial_cmp(b).unwrap());
                percentile(&pos, 90.0)
            });
            let cc = cc.max(EPS);
            tt.iter().map(|&x| 1.0 / (1.0 + x.max(0.0) / cc + 1.0).ln()).collect()
        }
    };

    pref_pos
        .iter()
        .map(|row| {
            let pos: Vec<bool> = row.iter().map(|&x| x > 0.0).collect();
            let n_pos = pos.iter().filter(|&&p| p).count();
            let n_keep = if n_pos == 0 {
                0
            } else {
                ((keep_frac * n_pos as f64).round() as i64).max(1).min(n_pos as i64) as usize
            };

            // Per-row random ranking of the positive entries; keep the n_keep smallest-rank.
            let mut ranks: Vec<(f64, usize)> = (0..row.len())
                .map(|j| (if pos[j] { rng.gen::<f64>() } else { 2.0 }, j))
                .collect();
            ranks.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

            let mut out = vec![0.0; row.len()];
            for &(_, j) in ranks.iter().take(n_keep) {
                out[j] = row[j];
            }

            if cover {
                let n_cover = n_pos - n_keep;
                add_cover(&mut out, &pos, n_cover, &base_w, cover_scale, &mut rng);
            }
            out
        })
        .collect()
}

/// Pad a row with `n_cover` cover items sampled (without replacement) ∝ `base_w`, excluding the row's
/// real positives, at a small uniform `cover_scale` weight.
fn add_cover(out: &mut [f64], real_pos: &[bool], n_cover: usize, base_w: &[f64], cover_scale: f64, rng: &mut StdRng) {
    if n_cover == 0 {
        return;
    }
    let mut w: Vec<f64> = base_w.to_vec();
    for (j, &p) in real_pos.iter().enumerate() {
        if p {
            w[j] = 0.0; // never cover an item that's already real
        }
    }
    let available = w.iter().filter(|&&x| x > 0.0).count();
    let k = n_cover.min(available);
    for _ in 0..k {
        let total: f64 = w.iter().sum();
        if total <= 0.0 {
            break;
        }
        // Weighted draw without replacement.
        let mut t = rng.gen::<f64>() * total;
        let mut pick = 0;
        for (j, &wj) in w.iter().enumerate() {
            t -= wj;
            if t <= 0.0 && wj > 0.0 {
                pick = j;
                break;
            }
        }
        out[pick] = rng.gen::<f64>() * cover_scale;
        w[pick] = 0.0; // without replacement
    }
}

/// Linear-interpolation percentile of an ascending-sorted slice (numpy `linear` method).
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 1.0;
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        sorted[lo] + (rank - lo as f64) * (sorted[hi] - sorted[lo])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laplace_sampler_matches_its_moments() {
        // Mean ≈ 0, variance ≈ 2b² for Laplace(0, b).
        let mut rng = StdRng::seed_from_u64(7);
        let b = 1.5;
        let n = 200_000;
        let xs: Vec<f64> = (0..n).map(|_| laplace_sample(&mut rng, b)).collect();
        let mean = xs.iter().sum::<f64>() / n as f64;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.02, "mean ~0, got {mean}");
        assert!((var - 2.0 * b * b).abs() < 0.2, "var ~2b²={}, got {var}", 2.0 * b * b);
    }

    #[test]
    fn laplace_clamp_keeps_inactive_dims_zero_and_renormalises() {
        let pref = vec![vec![1.0, 0.0, 3.0, 0.0]];
        let out = laplace(&pref, 1.0, 1, 2.0, 1.0, true, LaplaceMethod::Clamp);
        // Inactive dims (indices 1, 3) stay exactly 0 — which-items privacy is chopping's job.
        assert_eq!(out[0][1], 0.0);
        assert_eq!(out[0][3], 0.0);
        // Renormalised to a (sub-)probability row summing to ~1 (or 0 if everything clamped out).
        let s: f64 = out[0].iter().sum();
        assert!((s - 1.0).abs() < 1e-9 || s == 0.0, "row sums to ~1 or 0, got {s}");
        // Output stays in [0, B].
        assert!(out[0].iter().all(|&x| (0.0..=1.0 + 1e-9).contains(&x)));
    }

    #[test]
    fn laplace_infinite_epsilon_is_normalise_only() {
        let pref = vec![vec![2.0, 0.0, 2.0]];
        let out = laplace(&pref, f64::INFINITY, 0, 2.0, 1.0, true, LaplaceMethod::Clamp);
        // No noise: just L1-normalise → [0.5, 0, 0.5].
        assert!((out[0][0] - 0.5).abs() < 1e-9);
        assert_eq!(out[0][1], 0.0);
        assert!((out[0][2] - 0.5).abs() < 1e-9);
    }

    #[test]
    fn smaller_epsilon_loses_more_support() {
        // The corrected (clamp) Laplace is genuinely ε-sensitive: a small active weight whose draw
        // goes negative clamps to 0. Averaged over many rows, lower ε drops more active items.
        let rows: Matrix = (0..400).map(|_| vec![1.0, 0.2, 0.2, 0.2, 0.2]).collect();
        let support = |eps: f64, seed: u64| -> f64 {
            let out = laplace(&rows, eps, seed, 2.0, 1.0, true, LaplaceMethod::Clamp);
            out.iter().map(|r| r.iter().filter(|&&x| x > 0.0).count()).sum::<usize>() as f64 / rows.len() as f64
        };
        let lo = support(0.2, 11); // strong noise
        let hi = support(20.0, 11); // weak noise
        assert!(hi > lo, "weaker noise (large ε) preserves more support: hi={hi} lo={lo}");
    }

    #[test]
    fn chop_keeps_a_fraction_and_drops_the_rest() {
        let pref = vec![vec![1.0, 1.0, 1.0, 1.0, 0.0, 0.0]]; // 4 positives
        let out = chop(&pref, 0.5, 3, false, 1.0, None, None);
        let kept = out[0].iter().filter(|&&x| x > 0.0).count();
        assert_eq!(kept, 2, "keep_frac 0.5 of 4 positives keeps 2");
        // Inactive dims never become active without cover.
        assert_eq!(out[0][4], 0.0);
        assert_eq!(out[0][5], 0.0);
    }

    #[test]
    fn chop_keeps_at_least_one_positive() {
        let pref = vec![vec![1.0, 1.0, 1.0, 0.0]];
        let out = chop(&pref, 0.01, 4, false, 1.0, None, None); // keep_frac → 0
        let kept = out[0].iter().filter(|&&x| x > 0.0).count();
        assert_eq!(kept, 1, "at least one positive survives chopping");
    }

    #[test]
    fn chop_with_cover_pads_the_count_back_up() {
        let pref = vec![vec![1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0]]; // 4 positives
        let out = chop(&pref, 0.5, 5, true, 1.0, None, None);
        let active = out[0].iter().filter(|&&x| x > 0.0).count();
        // 2 kept reals + 2 cover items ≈ original count of 4 — the transmitted count is uninformative.
        assert_eq!(active, 4, "cover pads the transmitted count back to the original");
    }

    #[test]
    fn chop_cover_favours_low_trust_items() {
        // With a sharp trust gradient, cover items should land overwhelmingly on the low-trust
        // (novel) tail. Real positives are items {0,1}; keep_frac 0.5 forces 1 cover item per row,
        // drawn from items {2,3} (low-trust) vs item... none other available — so compare the two
        // candidate columns: build rows whose real positive is item 0 only, leaving {1,2,3} eligible.
        let pref: Matrix = (0..800).map(|_| vec![1.0, 1.0, 0.0, 0.0]).collect(); // reals {0,1}
        let trust = vec![0.0, 0.0, 100.0, 0.01]; // item 2 high-trust, item 3 low-trust (both eligible cover)
        let out = chop(&pref, 0.5, 9, true, 1.0, Some(&trust), Some(50.0));
        let cover_hi = out.iter().filter(|r| r[2] > 0.0).count(); // high-trust item picked as cover
        let cover_lo = out.iter().filter(|r| r[3] > 0.0).count(); // low-trust item picked as cover
        assert!(cover_lo > cover_hi, "cover favours the low-trust item: lo={cover_lo} hi={cover_hi}");
    }
}
