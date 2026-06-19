//! Dynamic validator-set membership (SPEC §4.1, §4.3). The genesis validator set is no longer
//! frozen: validators can **join** or **leave**, and the active set — and therefore the BFT quorum
//! — at any height is a *deterministic function of the finalized chain below it*. Because every node
//! derives the same active set from the same finalized prefix, there is no split-brain: a membership
//! change recorded in the (finalized) block at height `H` takes effect for consensus at height
//! `H+1`, by which point block `H` is final and identical for everyone. This is the standard "config
//! change at a stable, totally-ordered boundary" reconfiguration pattern.
//!
//! Authorization: every op is **self-signed** by its subject's long-term ed25519 key, so nobody can
//! inject a validator that did not consent (which would let an attacker inflate the set and break the
//! quorum arithmetic) nor evict a member that did not consent. Beyond proving key-control the MVP
//! applies **AcceptAll** admission (Sybil-trivial) — the real gate is the deferred `Admission` seam
//! (`VdfAdmission`, SPEC §4.3). The aggregatable-BLS quorum certificate already records its own
//! signer set, so a *changing* set works without a fixed threshold key; a DKG threshold key
//! (`VA_pub`) remains the separate deferred construct.

use std::collections::HashMap;

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::identity::{verify as verify_ed25519, NodeIdentity};

/// A validator's public record: its stable id, dial address, and the public keys peers need to
/// verify its consensus votes (BLS) and leadership claims (VRF). This is the unit a membership `Add`
/// installs and the genesis set is built from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub peer_id: [u8; 32],
    pub addr: String,
    #[serde(with = "BigArray")]
    pub bls_pk: [u8; 48],
    pub vrf_pk: [u8; 32],
    /// The validator's Ristretto mix public key (`identity.mix_pk()`) — peers seal confidential
    /// committee messages (e.g. arbitration custody parcels, `arbitration.rs`) to it.
    pub mix_pk: [u8; 32],
}

/// Bytes a joining validator signs to authorize its own admission (binds the keys, not the address).
fn join_sig_bytes(r: &ValidatorRecord) -> Vec<u8> {
    bincode::serialize(&("join", r.peer_id, &r.bls_pk[..], r.vrf_pk, r.mix_pk)).expect("join serialize")
}

/// Bytes a leaving validator signs to authorize its own departure.
fn leave_sig_bytes(peer_id: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&("leave", peer_id)).expect("leave serialize")
}

fn check_sig(peer: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    match <[u8; 64]>::try_from(sig) {
        Ok(arr) => verify_ed25519(peer, msg, &Signature::from_bytes(&arr)),
        Err(_) => false,
    }
}

/// A self-authorized membership change, recorded in a block header and applied at the next height.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MembershipOp {
    /// Admit `record` as a validator (the joiner signs `join_sig_bytes`). `vdf` is an optional
    /// admission proof-of-work (a serialized `vdf::VdfProof` over the joiner's `peer_id`) — empty
    /// under AcceptAll admission, required and verified under `VdfAdmission`. It is **not** covered by
    /// `sig` because the VDF already binds the `peer_id` (it is self-authenticating evidence, like the
    /// quorum certificate), so it needs no separate signature.
    Add { record: ValidatorRecord, sig: Vec<u8>, vdf: Vec<u8> },
    /// Remove `peer_id` from the validator set (the leaver signs `leave_sig_bytes`).
    Remove { peer_id: [u8; 32], sig: Vec<u8> },
}

impl MembershipOp {
    /// Build a self-signed join op for `identity` advertising `addr` (AcceptAll — no VDF proof).
    pub fn add(identity: &NodeIdentity, addr: String) -> Self {
        Self::add_with_vdf(identity, addr, Vec::new())
    }

    /// Build a self-signed join op carrying an admission VDF proof (`VdfAdmission`).
    pub fn add_with_vdf(identity: &NodeIdentity, addr: String, vdf: Vec<u8>) -> Self {
        let record = ValidatorRecord {
            peer_id: identity.peer_id(),
            addr,
            bls_pk: identity.bls_pk(),
            vrf_pk: identity.vrf_pk(),
            mix_pk: identity.mix_pk(),
        };
        let sig = identity.sign(&join_sig_bytes(&record)).to_bytes().to_vec();
        MembershipOp::Add { record, sig, vdf }
    }

    /// The serialized admission VDF proof carried by an `Add` op (empty for `Remove`/AcceptAll).
    pub fn vdf_proof(&self) -> &[u8] {
        match self {
            MembershipOp::Add { vdf, .. } => vdf,
            MembershipOp::Remove { .. } => &[],
        }
    }

    /// Build a self-signed leave op for `identity`.
    pub fn remove(identity: &NodeIdentity) -> Self {
        let peer_id = identity.peer_id();
        let sig = identity.sign(&leave_sig_bytes(&peer_id)).to_bytes().to_vec();
        MembershipOp::Remove { peer_id, sig }
    }

    /// The peer this op concerns.
    pub fn subject(&self) -> [u8; 32] {
        match self {
            MembershipOp::Add { record, .. } => record.peer_id,
            MembershipOp::Remove { peer_id, .. } => *peer_id,
        }
    }

    /// Self-authorization check: the subject signed this op (AcceptAll admission beyond key-control).
    /// This is the safety-critical validity check — an op that fails it must never enter a block.
    pub fn verify(&self) -> bool {
        match self {
            MembershipOp::Add { record, sig, .. } => check_sig(&record.peer_id, &join_sig_bytes(record), sig),
            MembershipOp::Remove { peer_id, sig } => check_sig(peer_id, &leave_sig_bytes(peer_id), sig),
        }
    }
}

/// The active validator set at some height: the members plus the key/address lookups consensus
/// needs. Built from the genesis records and folded forward by `apply` over the finalized ops.
#[derive(Clone, Default)]
pub struct ValidatorSet {
    /// Member peer ids, sorted (the canonical order for leader election / iteration).
    pub peers: Vec<[u8; 32]>,
    pub bls: HashMap<[u8; 32], [u8; 48]>,
    pub vrf: HashMap<[u8; 32], [u8; 32]>,
    pub addr: HashMap<[u8; 32], String>,
    /// Per-member Ristretto mix public key — peers seal confidential committee messages to it.
    pub mix: HashMap<[u8; 32], [u8; 32]>,
}

impl ValidatorSet {
    /// Build the initial set from genesis records.
    pub fn from_records(records: &[ValidatorRecord]) -> Self {
        let mut s = ValidatorSet::default();
        for r in records {
            s.insert(r.clone());
        }
        s
    }

    fn insert(&mut self, r: ValidatorRecord) {
        if !self.bls.contains_key(&r.peer_id) {
            self.peers.push(r.peer_id);
            self.peers.sort();
        }
        self.bls.insert(r.peer_id, r.bls_pk);
        self.vrf.insert(r.peer_id, r.vrf_pk);
        self.addr.insert(r.peer_id, r.addr);
        self.mix.insert(r.peer_id, r.mix_pk);
    }

    fn remove(&mut self, peer: &[u8; 32]) {
        self.peers.retain(|p| p != peer);
        self.bls.remove(peer);
        self.vrf.remove(peer);
        self.addr.remove(peer);
        self.mix.remove(peer);
    }

    /// Apply one finalized membership op (deterministic: idempotent for already-applied effects).
    pub fn apply(&mut self, op: &MembershipOp) {
        match op {
            MembershipOp::Add { record, .. } => self.insert(record.clone()),
            MembershipOp::Remove { peer_id, .. } => self.remove(peer_id),
        }
    }

    pub fn contains(&self, peer: &[u8; 32]) -> bool {
        self.bls.contains_key(peer)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn ops_are_self_authorized_and_apply_deterministically() {
        let a = NodeIdentity::from_seed(1);
        let b = NodeIdentity::from_seed(2);
        let rec_a = ValidatorRecord {
            peer_id: a.peer_id(),
            addr: "a".into(),
            bls_pk: a.bls_pk(),
            vrf_pk: a.vrf_pk(),
            mix_pk: a.mix_pk(),
        };
        let mut set = ValidatorSet::from_records(&[rec_a]);
        assert_eq!(set.len(), 1);

        // A self-signed join verifies and admits the joiner.
        let join = MembershipOp::add(&b, "b".into());
        assert!(join.verify());
        set.apply(&join);
        assert!(set.contains(&b.peer_id()) && set.len() == 2);

        // A forged join (b's record but a's signature) is rejected.
        let forged = match MembershipOp::add(&b, "b".into()) {
            MembershipOp::Add { record, .. } => MembershipOp::Add {
                record,
                sig: a.sign(b"nonsense").to_bytes().to_vec(),
                vdf: Vec::new(),
            },
            other => other,
        };
        assert!(!forged.verify());

        // A self-signed leave verifies and removes the leaver; re-applying is a harmless no-op.
        let leave = MembershipOp::remove(&b);
        assert!(leave.verify());
        set.apply(&leave);
        set.apply(&leave);
        assert!(!set.contains(&b.peer_id()) && set.len() == 1);
    }
}
