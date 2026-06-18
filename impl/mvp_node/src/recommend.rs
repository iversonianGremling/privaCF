//! Item-based collaborative filtering — the Layer-5 recommendation core (SPEC §3), ported from the
//! Python PoC `cf.py`. This is the payoff the whole substrate exists to enable: turn the network's
//! gossiped (obfuscated) preference vectors into personalized rankings, with adversary influence
//! bounded by the **DSybil trust cap** `c` (§7.3) so a Sybil pushing one item cannot dominate.
//!
//! Pipeline (§3.2/§3.4/§3.7):
//!   * `trust_total(X) = min(Σ_peers max(0, p+noise)·Δ_base, c)` — contributions to an item halt at
//!     the cap `c`, so no amount of Sybil pushing exceeds it;
//!   * `novelty(X) = clip(1 − eff/c, 0, 1)` and IDF `item_weight(X) = 1/ln(2 + eff/c)` lift long-tail
//!     items at ranking time (cosine normalises columns, so these must NOT enter the similarity);
//!   * item–item cosine similarity over the contribution columns;
//!   * `score(u,i) = item_weight(i)·(1 + κ·novelty(i))·Σ_j pref_pos[u,j]·sim(j,i) − penalty·max(0,
//!     Σ_j pref_neg[u,j]·sim(j,i))`, seen items set to −∞.
//!
//! Dense `f64` matrices (rows = peers/users, cols = items) — faithful and testable; a sparse backend
//! (`sprs`) is the scale optimization the Python uses via scipy.

const EPS: f64 = 1e-8;

pub type Matrix = Vec<Vec<f64>>;

/// CF hyperparameters (defaults match the PoC `CFConfig`).
#[derive(Clone, Debug)]
pub struct CFConfig {
    pub delta_base: f64,
    pub kappa: f64,           // novelty bonus strength (§3.7); 0 disables novelty
    pub beta: f64,            // 1.0 = pure global trust_total; <1 blends in cluster trust
    pub c: Option<f64>,       // DSybil cap; None ⇒ data-driven percentile
    pub c_percentile: f64,    // percentile of positive global trust used when c is None
    pub use_item_weight: bool, // apply the §3.4 IDF damping
    pub dislike_penalty: f64, // §3.5 penalty coefficient (0 disables)
}

impl Default for CFConfig {
    fn default() -> Self {
        Self {
            delta_base: 1.0,
            kappa: 1.0,
            beta: 1.0,
            c: None,
            c_percentile: 90.0,
            use_item_weight: true,
            dislike_penalty: 1.0,
        }
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

/// A fitted item-CF recommender.
pub struct ItemCF {
    cfg: CFConfig,
    sim: Matrix,                  // [n_items, n_items], zero diagonal
    item_weight: Vec<f64>,        // [n_items]
    novelty: Vec<f64>,            // [n_items]
    pub effective_trust: Vec<f64>, // [n_items], capped at c
    pub c: f64,
}

impl ItemCF {
    /// Build from the network's positive preference matrix `gossip_pos` (rows = peers, cols = items),
    /// optional per-entry `noise` (§4.5) and `cluster_mask` (peers in the receiver's PSI cluster, for
    /// the `β < 1` blend).
    pub fn fit(cfg: CFConfig, gossip_pos: &Matrix, noise: Option<&Matrix>, cluster_mask: Option<&[bool]>) -> Self {
        let n_peers = gossip_pos.len();
        let n_items = gossip_pos.first().map_or(0, |r| r.len());

        // base_contrib = max(0, p + noise) · Δ_base
        let mut base = vec![vec![0.0; n_items]; n_peers];
        for i in 0..n_peers {
            for j in 0..n_items {
                let nz = noise.map_or(0.0, |m| m[i][j]);
                base[i][j] = (gossip_pos[i][j] + nz).max(0.0) * cfg.delta_base;
            }
        }

        // global trust_total (capped at c), with data-driven c when unset.
        let mut global_raw = vec![0.0; n_items];
        for j in 0..n_items {
            global_raw[j] = (0..n_peers).map(|i| base[i][j]).sum();
        }
        let c = cfg.c.unwrap_or_else(|| {
            let mut pos: Vec<f64> = global_raw.iter().copied().filter(|&x| x > 0.0).collect();
            pos.sort_by(|a, b| a.partial_cmp(b).unwrap());
            percentile(&pos, cfg.c_percentile)
        });
        let c = c.max(EPS);
        let global_tt: Vec<f64> = global_raw.iter().map(|&x| x.min(c)).collect();

        // cluster trust_total + effective blend (β = 1 ⇒ global only).
        let effective_trust: Vec<f64> = if cfg.beta < 1.0 {
            let mask = cluster_mask.unwrap_or(&[]);
            (0..n_items)
                .map(|j| {
                    let cluster: f64 =
                        (0..n_peers).filter(|&i| mask.get(i).copied().unwrap_or(false)).map(|i| base[i][j]).sum::<f64>().min(c);
                    cfg.beta * global_tt[j] + (1.0 - cfg.beta) * cluster
                })
                .collect()
        } else {
            global_tt.clone()
        };

        let novelty: Vec<f64> = effective_trust.iter().map(|&e| (1.0 - e / c).clamp(0.0, 1.0)).collect();
        let item_weight: Vec<f64> = effective_trust.iter().map(|&e| 1.0 / (2.0 + e / c).ln()).collect();

        // item–item cosine similarity over the (un-novelty-scaled) contribution columns.
        let mut norm = vec![0.0; n_items];
        for j in 0..n_items {
            norm[j] = (0..n_peers).map(|i| base[i][j] * base[i][j]).sum::<f64>().sqrt() + EPS;
        }
        let mut sim = vec![vec![0.0; n_items]; n_items];
        for a in 0..n_items {
            for b in 0..n_items {
                if a != b {
                    let dot: f64 = (0..n_peers).map(|i| (base[i][a] / norm[a]) * (base[i][b] / norm[b])).sum();
                    sim[a][b] = dot;
                }
            }
        }

        Self { cfg, sim, item_weight, novelty, effective_trust, c }
    }

    /// Score every `(user, item)` from each user's own interactions. `pref_pos`/`pref_neg` are
    /// [n_users, n_items]; `seen[u][i]` masks already-interacted items to −∞.
    pub fn score_all(&self, pref_pos: &Matrix, pref_neg: &Matrix, seen: &[Vec<bool>]) -> Matrix {
        let n_users = pref_pos.len();
        let n_items = self.sim.len();
        let boost: Vec<f64> = (0..n_items)
            .map(|i| {
                let mut b = 1.0;
                if self.cfg.kappa > 0.0 {
                    b *= 1.0 + self.cfg.kappa * self.novelty[i];
                }
                if self.cfg.use_item_weight {
                    b *= self.item_weight[i];
                }
                b
            })
            .collect();

        let mut scores = vec![vec![0.0; n_items]; n_users];
        for u in 0..n_users {
            for i in 0..n_items {
                let raw: f64 = (0..n_items).map(|j| pref_pos[u][j] * self.sim[j][i]).sum();
                let mut s = raw * boost[i];
                if self.cfg.dislike_penalty > 0.0 {
                    let dislike: f64 = (0..n_items).map(|j| pref_neg[u][j] * self.sim[j][i]).sum();
                    s -= self.cfg.dislike_penalty * dislike.max(0.0);
                }
                scores[u][i] = if seen[u][i] { f64::NEG_INFINITY } else { s };
            }
        }
        scores
    }
}

/// Assemble the on-chain gossip matrix from a set of epoch transactions: each tx carrying a
/// [`PreferencePayload`](crate::epoch::PreferencePayload) contributes one row (its obfuscated
/// gossip), zero-padded to the widest row; txs without a payload are skipped. This is the bridge from
/// the substrate's finalized epoch transactions to the CF engine — recommendation over real on-chain
/// gossip rather than a hand-built matrix.
pub fn gossip_matrix(txs: &[crate::epoch::EpochTransaction]) -> Matrix {
    let width = txs.iter().filter_map(|t| t.pref.as_ref()).map(|p| p.gossip.len()).max().unwrap_or(0);
    txs.iter()
        .filter_map(|t| t.pref.as_ref())
        .map(|p| {
            let mut row = vec![0.0; width];
            for (j, &v) in p.gossip.iter().enumerate() {
                row[j] = v as f64;
            }
            row
        })
        .collect()
}

/// Top-`k` item indices per user, ranked by score descending.
pub fn top_k(scores: &Matrix, k: usize) -> Vec<Vec<usize>> {
    scores
        .iter()
        .map(|row| {
            let mut idx: Vec<usize> = (0..row.len()).collect();
            idx.sort_by(|&a, &b| row[b].partial_cmp(&row[a]).unwrap_or(std::cmp::Ordering::Equal));
            idx.into_iter().take(k).collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dsybil_cap_bounds_a_pushed_item() {
        // Items 0 and 1 are genuinely co-liked by honest peers; item 4 is hammered by a Sybil.
        let gossip = vec![
            vec![1.0, 1.0, 0.0, 0.0, 0.0], // honest peer
            vec![1.0, 1.0, 0.0, 0.0, 0.0], // honest peer
            vec![0.0, 0.0, 1.0, 1.0, 0.0], // honest peer (other niche)
            vec![0.0, 0.0, 0.0, 0.0, 100.0], // SYBIL pushing item 4
        ];
        let cf = ItemCF::fit(CFConfig { c: Some(2.0), ..Default::default() }, &gossip, None, None);
        // The Sybil's raw push is 100 but trust is capped at c = 2.
        assert!((cf.effective_trust[4] - 2.0).abs() < 1e-9, "the pushed item's trust is capped at c");
    }

    #[test]
    fn a_user_is_recommended_co_liked_items() {
        // Honest co-likes: items 0,1 together; items 2,3 together.
        let gossip = vec![
            vec![1.0, 1.0, 0.0, 0.0],
            vec![1.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 1.0],
            vec![0.0, 0.0, 1.0, 1.0],
        ];
        let cf = ItemCF::fit(CFConfig::default(), &gossip, None, None);
        // A user who interacted with item 0 (and hasn't seen item 1) should rank item 1 top.
        let pref_pos = vec![vec![1.0, 0.0, 0.0, 0.0]];
        let pref_neg = vec![vec![0.0; 4]];
        let seen = vec![vec![true, false, false, false]]; // item 0 already seen
        let scores = cf.score_all(&pref_pos, &pref_neg, &seen);
        let rec = top_k(&scores, 1);
        assert_eq!(rec[0][0], 1, "the co-liked neighbour of item 0 is recommended");
    }

    #[test]
    fn novelty_and_idf_lift_a_long_tail_candidate() {
        // Two items equally similar to the user's interest, but item B is far more popular (high
        // trust) than item A. The novelty + IDF boost should rank the long-tail item A above B.
        let gossip = vec![
            vec![1.0, 1.0, 1.0], // peers co-like item 0 with both 1 (A) and 2 (B)
            vec![1.0, 1.0, 1.0],
            vec![0.0, 0.0, 1.0], // extra popularity for item 2 (B)
            vec![0.0, 0.0, 1.0],
            vec![0.0, 0.0, 1.0],
        ];
        let cf = ItemCF::fit(CFConfig { c: Some(5.0), ..Default::default() }, &gossip, None, None);
        let pref_pos = vec![vec![1.0, 0.0, 0.0]];
        let seen = vec![vec![true, false, false]];
        let scores = cf.score_all(&pref_pos, &vec![vec![0.0; 3]], &seen);
        assert!(scores[0][1] > scores[0][2], "the less-popular long-tail candidate is lifted above the popular one");
    }
}
