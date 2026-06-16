//! Admission seam. Stub: accept all joiners (Sybil-trivial).
//!
//! Real future impl: `VdfAdmission` — a VDF admission chain bound to the identity genesis
//! (`vdf_proof_{t₀} = H("vdf_genesis", C_id)`, SPEC §4.3) that rate-limits identity creation.

pub trait Admission: Send + Sync {
    fn admit(&self, peer_id: &[u8; 32]) -> bool;
}

pub struct AcceptAll;

impl Admission for AcceptAll {
    fn admit(&self, _peer_id: &[u8; 32]) -> bool {
        true
    }
}
