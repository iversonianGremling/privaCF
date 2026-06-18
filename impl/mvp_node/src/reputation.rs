//! Per-epoch reputation with the asymmetric penalty (SPEC §6.1, §7.2). A node's score `q_v(T)` lives
//! in `[0, BAND_MAX]` and maps to discrete bands 1–4. Two distinct mechanisms erode it, and which one
//! an event triggers is the crux of the on-off analysis:
//!   * **§6.1 universal slow decay** `− δ_decay` every epoch (always applied);
//!   * **§7.2 asymmetric penalty** `r ← min(r, BAND_1)` — a hard cliff, on an *actual detected
//!     violation* only.
//! Climbing is linear at `+ Δ_rise` per active epoch. The asymmetry is the point: a violation drops
//! you to the floor instantly, but recovery is slow. Merely going quiet (absent, no violation) costs
//! only the slow decay — the faithful reading (the snap-on-absence reading over-punishes honest
//! downtime and manufactures a spurious knife-edge), ported from the Python `temporal.py`.

/// Reputation update parameters (defaults match the PoC `RepConfig`).
#[derive(Clone, Copy, Debug)]
pub struct RepConfig {
    pub delta_rise: f64,  // Δ_rise: gained per active epoch (§7.2)
    pub delta_decay: f64, // δ_decay: universal slow decay per epoch (§6.1)
    pub band_1: f64,      // BAND_1: the floor a violation snaps to
    pub band_max: f64,    // BAND_MAX: top of band 4
}

impl Default for RepConfig {
    fn default() -> Self {
        Self { delta_rise: 0.5, delta_decay: 0.05, band_1: 1.0, band_max: 4.0 }
    }
}

/// A node's evolving reputation.
#[derive(Clone, Copy, Debug)]
pub struct Reputation {
    r: f64,
    cfg: RepConfig,
}

impl Reputation {
    /// A fresh, fully-reputable node (starts at `BAND_MAX`).
    pub fn new(cfg: RepConfig) -> Self {
        Self { r: cfg.band_max, cfg }
    }

    pub fn with_score(cfg: RepConfig, r0: f64) -> Self {
        Self { r: r0.clamp(0.0, cfg.band_max), cfg }
    }

    /// The continuous score `q_v(T)`.
    pub fn score(&self) -> f64 {
        self.r
    }

    /// The discrete band 1–4 (§6.1): `[0, ¼·max)→1 … [¾·max, max]→4`.
    pub fn band(&self) -> u8 {
        let frac = (self.r / self.cfg.band_max).clamp(0.0, 1.0);
        (1 + ((frac * 4.0).floor() as u8).min(3)).min(4)
    }

    /// One epoch: climb if `active`, snap to `BAND_1` on a detected `violation`, then slow-decay.
    /// Absence (not active, no violation) costs only the decay — the faithful reading.
    pub fn update(&mut self, active: bool, violation: bool) {
        if active {
            self.r = (self.r + self.cfg.delta_rise).min(self.cfg.band_max);
        }
        if violation {
            self.r = self.r.min(self.cfg.band_1); // the §7.2 cliff
        }
        self.r = (self.r - self.cfg.delta_decay).clamp(0.0, self.cfg.band_max);
    }
}

/// Run a reputation trajectory over an `active`/`violation` schedule (for analysis/tests).
pub fn simulate(active: &[bool], violation: &[bool], cfg: RepConfig) -> Vec<f64> {
    let mut rep = Reputation::new(cfg);
    active
        .iter()
        .zip(violation.iter())
        .map(|(&a, &v)| {
            rep.update(a, v);
            rep.score()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_always_active_node_holds_the_top_band() {
        let cfg = RepConfig::default();
        let mut rep = Reputation::new(cfg);
        for _ in 0..50 {
            rep.update(true, false);
        }
        // Climb caps at BAND_MAX, then the universal decay always applies, so the steady state is
        // BAND_MAX − δ_decay — still firmly band 4.
        assert!((rep.score() - (cfg.band_max - cfg.delta_decay)).abs() < 1e-9, "active node pins near the top");
        assert_eq!(rep.band(), 4);
    }

    #[test]
    fn a_violation_snaps_to_the_floor_then_recovers_slowly() {
        let cfg = RepConfig::default();
        let mut rep = Reputation::new(cfg);
        rep.update(false, true); // detected violation
        assert!(rep.score() <= cfg.band_1, "a violation drops to the floor");
        assert_eq!(rep.band(), 1);
        // Recovery is linear: each active epoch adds ~ (Δ_rise − δ_decay).
        let before = rep.score();
        rep.update(true, false);
        assert!(rep.score() > before && rep.score() < cfg.band_max, "recovery is slow, not instant");
    }

    #[test]
    fn quiet_absence_costs_only_slow_decay() {
        // The faithful reading: going quiet (no violation) is NOT a cliff. A single absence costs
        // just δ_decay, vastly less than a violation snap.
        let cfg = RepConfig::default();
        let mut quiet = Reputation::new(cfg);
        quiet.update(false, false);
        assert!((cfg.band_max - quiet.score() - cfg.delta_decay).abs() < 1e-9, "absence = one δ_decay");
        assert!(quiet.score() > cfg.band_1, "a single quiet epoch does not drop to the floor");
    }

    #[test]
    fn an_always_absent_node_decays_to_zero() {
        let cfg = RepConfig::default();
        let traj = simulate(&[false; 200], &[false; 200], cfg);
        assert!(*traj.last().unwrap() <= 0.0 + 1e-9, "sustained absence decays to 0");
    }
}
