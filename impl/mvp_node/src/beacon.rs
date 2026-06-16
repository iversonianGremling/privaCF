//! Mock beacon chain. SPEC §4.1 has `beacon_T = H(drand_T ‖ vdf_output_{T-1})`. The MVP has no
//! drand and no VDF, so the beacon is a deterministic Poseidon hash chain seeded at genesis:
//! `beacon_T = Poseidon(beacon_{T-1}, T)`. It is identical for every node (deterministic from the
//! genesis seed), which is what lets the chain converge — but it is trivially grindable/predictable
//! and carries none of the unpredictability the real beacon provides.

use crate::field::{from_u64, to_u64, Fp};
use crate::hash::poseidon_scalar;

/// Genesis beacon seed (height 0). Any fixed value all nodes share.
pub const GENESIS_BEACON: u64 = 0x50_72_69_76_61_43_46_00; // "PrivaCF\0"

/// `beacon_T = Poseidon(beacon_{T-1}, T)` (canonical u64).
pub fn next_beacon(prev_beacon: u64, height: u64) -> u64 {
    let b: Fp = poseidon_scalar(&[from_u64(prev_beacon), from_u64(height)]);
    to_u64(b)
}
