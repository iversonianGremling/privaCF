//! Consensus / proposer seam. Stub: a single round-robin proposer per epoch over the sorted
//! genesis validator set — NO Byzantine fault tolerance (a single proposer is trusted per height;
//! equivocation is undetected, and a dead proposer stalls that height).
//!
//! Real future impl: `BftConsensus` — EC-VRF proposer selection over registered `epoch_id`s plus
//! threshold-BLS `validator_sigs` and a real fork-choice (SPEC §4.1). This is the first seam to
//! harden, since every later property builds on an equivocation-resistant ledger.

pub trait Proposer: Send + Sync {
    /// The stable peer id that proposes block `height`, given the sorted validator set.
    fn proposer_for(&self, height: u64, validators_sorted: &[[u8; 32]]) -> [u8; 32];
}

pub struct RoundRobinProposer;

impl Proposer for RoundRobinProposer {
    fn proposer_for(&self, height: u64, validators_sorted: &[[u8; 32]]) -> [u8; 32] {
        validators_sorted[(height as usize) % validators_sorted.len()]
    }
}
