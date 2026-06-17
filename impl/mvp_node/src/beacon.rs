//! Randomness beacon chain. SPEC §4.1 has `beacon_T = H(drand_T ‖ vdf_output_{T-1})`. The MVP has
//! no drand and no VDF, but now that leader election uses a real EC-VRF (`vrf.rs`) we chain the
//! beacon through the finalized blocks' VRF outputs (Ouroboros-Praos style):
//!
//! `beacon_T = Poseidon(beacon_{T-1}, T, fold(vrf_output_of_block_{T-1}))`.
//!
//! Because each block's VRF output is *unique and ungrindable* (the proposer cannot bias its own
//! output), the beacon — and therefore the leader schedule beyond the current head — is no longer
//! computable from the genesis seed alone: you cannot know who leads height T+2 until height T+1
//! finalizes. Every node still derives the identical beacon from the identical finalized chain, so
//! the chain converges.
//!
//! Residual weakness (honest): a malicious leader still has a *last-revealer* bias — by choosing to
//! withhold its block it forces a view-change to a different leader, whose different VRF output
//! yields a different next beacon (one bit of grinding per slot it controls). Removing that needs a
//! VDF (so the next beacon can't be computed fast enough to act on) or a drand-style beacon — the
//! SPEC's real source.

use crate::field::{from_u64, to_u64, Fp};
use crate::hash::poseidon_scalar;

/// Genesis beacon seed (height 0). Any fixed value all nodes share.
pub const GENESIS_BEACON: u64 = 0x50_72_69_76_61_43_46_00; // "PrivaCF\0"

/// VRF output of the genesis block — all zeros (genesis has no proposer). The height-1 beacon is
/// thus `next_beacon(GENESIS_BEACON, &GENESIS_VRF_OUTPUT, 1)`, deterministic for every node.
pub const GENESIS_VRF_OUTPUT: [u8; 32] = [0u8; 32];

/// `beacon_T = Poseidon(beacon_{T-1}, T, fold(vrf_output_{T-1}))` (canonical u64). The 32-byte VRF
/// output of the previous block is folded in as four field-element limbs.
pub fn next_beacon(prev_beacon: u64, prev_vrf_output: &[u8; 32], height: u64) -> u64 {
    let mut inputs = vec![from_u64(prev_beacon), from_u64(height)];
    for chunk in prev_vrf_output.chunks_exact(8) {
        inputs.push(from_u64(u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"))));
    }
    let b: Fp = poseidon_scalar(&inputs);
    to_u64(b)
}
