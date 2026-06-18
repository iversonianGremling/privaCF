//! Sybil detection (SPEC §7). Two complementary defences, ported from the Python PoC (`attack.py`)
//! and the §P5 security analysis:
//!   * **FoolsGold** (Fung et al.) — soft per-node trust weights from the *mutual similarity* of
//!     contribution vectors. A tightly-coordinated group (Sybils pushing the same items) is mutually
//!     similar and gets weights ≈ 0; diverse honest nodes get ≈ 1. This is the *empirical* signal.
//!   * **Structural influence bound** `I_struct` (§P5.2) — the *proven* floor on adversary influence
//!     from hard caps alone (no detection needed): per-node trust cap, hop attenuation, and a
//!     reputation-band gate below which a Sybil contributes nothing.

const EPS: f64 = 1e-12;

/// FoolsGold per-node weights `α ∈ [0,1]`: ≈1 for diverse contributors, ≈0 for a mutually-similar
/// (coordinated) group. Includes the pardoning step (don't over-penalise an honest node that merely
/// resembles a Sybil) and the logit confidence rescaling. `contrib[i]` is node `i`'s contribution
/// vector (e.g. its gossiped per-item preferences).
pub fn foolsgold(contrib: &[Vec<f64>], confidence: f64) -> Vec<f64> {
    let n = contrib.len();
    if n == 0 {
        return Vec::new();
    }
    // L2-normalise rows.
    let cn: Vec<Vec<f64>> = contrib
        .iter()
        .map(|row| {
            let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt() + EPS;
            row.iter().map(|x| x / norm).collect()
        })
        .collect();
    // Cosine-similarity matrix, zero diagonal.
    let mut cs = vec![vec![0.0f64; n]; n];
    for i in 0..n {
        for j in 0..n {
            if i != j {
                cs[i][j] = cn[i].iter().zip(&cn[j]).map(|(a, b)| a * b).sum();
            }
        }
    }
    let row_max = |row: &[f64]| row.iter().copied().fold(f64::MIN, f64::max);
    let v: Vec<f64> = cs.iter().map(|r| row_max(r)).collect();
    // Pardoning: scale cs[i][j] down when j is more suspicious than i (v[j] > v[i]).
    for i in 0..n {
        for j in 0..n {
            if v[j] > v[i] {
                cs[i][j] *= (v[i] / (v[j] + EPS)).min(1.0);
            }
        }
    }
    let mut alpha: Vec<f64> = cs.iter().map(|r| (1.0 - row_max(r)).clamp(0.0, 1.0)).collect();
    // Rescale so the most-trusted node → 1.
    let mx = alpha.iter().copied().fold(0.0, f64::max);
    if mx > 0.0 {
        for a in &mut alpha {
            *a /= mx;
        }
    }
    // Logit rescaling: sharpen the honest(~1)/Sybil(~0) separation.
    for a in &mut alpha {
        let x = a.clamp(EPS, 1.0 - EPS);
        *a = (confidence * ((x / (1.0 - x)).ln() + 0.5)).clamp(0.0, 1.0);
    }
    alpha
}

/// Parameters of the structural influence bound (§P5.2).
#[derive(Clone, Copy, Debug)]
pub struct StructConfig {
    pub w_c: f64,        // cluster weight fraction
    pub w_b: f64,        // bridge weight fraction
    pub f_cap: f64,      // per-node trust cap as a fraction of the DSybil cap
    pub mu: f64,         // hop-distance attenuation (∈ (0,1])
    pub cohort_cap: f64, // network-wide cohort-cap ceiling
    pub rho_band: u8,    // reputation band a Sybil must reach before it contributes
}

/// The proven structural floor on adversary influence (§P5.2), `min(cluster + bridge, cohort_cap)`,
/// gated to zero below the reputation band `ρ`. `pi_s` = post-PSI sybil rate among cluster peers;
/// `beta_s` = bridge-peer base-rate sybil rate; `h_c`/`h_b` = hop distances of the contributions.
pub fn structural_influence_bound(cfg: StructConfig, pi_s: f64, beta_s: f64, h_c: i32, h_b: i32, band: u8) -> f64 {
    if band < cfg.rho_band {
        return 0.0; // the gate: a low-reputation Sybil contributes nothing
    }
    let cluster = cfg.w_c * pi_s * cfg.f_cap * cfg.mu.powi(h_c);
    let bridge = cfg.w_b * beta_s * cfg.f_cap * cfg.mu.powi(h_b);
    (cluster + bridge).min(cfg.cohort_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foolsgold_damps_a_coordinated_group_and_trusts_diverse_nodes() {
        // Two honest nodes with diverse preferences + two Sybils pushing the same item hard.
        let contrib = vec![
            vec![5.0, 1.0, 0.0, 0.0], // honest A
            vec![0.0, 0.0, 4.0, 2.0], // honest B (different niche)
            vec![0.0, 9.0, 0.0, 0.0], // sybil 1 — pushes item 1
            vec![0.0, 9.0, 0.0, 0.0], // sybil 2 — identical push
        ];
        let w = foolsgold(&contrib, 1.0);
        // The two mutually-identical Sybils are damped well below the diverse honest nodes.
        assert!(w[2] < 0.5 && w[3] < 0.5, "coordinated Sybils are damped: {w:?}");
        assert!(w[0] > w[2] && w[1] > w[3], "diverse honest nodes keep more weight");
    }

    #[test]
    fn an_independent_honest_set_keeps_high_weight() {
        // Four diverse honest nodes — none should be heavily damped.
        let contrib = vec![
            vec![5.0, 0.0, 0.0, 0.0],
            vec![0.0, 5.0, 0.0, 0.0],
            vec![0.0, 0.0, 5.0, 0.0],
            vec![0.0, 0.0, 0.0, 5.0],
        ];
        let w = foolsgold(&contrib, 1.0);
        assert!(w.iter().all(|&a| a > 0.5), "independent honest nodes are trusted: {w:?}");
    }

    #[test]
    fn structural_bound_gates_below_rho_and_caps_above() {
        let cfg = StructConfig { w_c: 0.5, w_b: 0.5, f_cap: 0.1, mu: 0.5, cohort_cap: 0.2, rho_band: 3 };
        // Below the reputation gate: zero influence regardless of sybil rates.
        assert_eq!(structural_influence_bound(cfg, 1.0, 1.0, 1, 1, 2), 0.0, "gated below ρ");
        // Non-targeted niche (no cluster/bridge sybils) → zero.
        assert_eq!(structural_influence_bound(cfg, 0.0, 0.0, 1, 1, 4), 0.0, "no sybils → no influence");
        // A targeted cohort is bounded by the cohort cap, never unbounded.
        let big = structural_influence_bound(cfg, 1.0, 1.0, 0, 0, 4);
        assert!(big <= cfg.cohort_cap + 1e-12, "influence is capped: {big}");
    }
}
