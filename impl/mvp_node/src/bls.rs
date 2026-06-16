//! BLS12-381 aggregate-multisignature seam (via `blst`) — the only place `blst` is touched.
//!
//! Validator votes are BLS signatures over the block id; a quorum certificate aggregates ≥ quorum
//! of them into ONE signature, verified against the aggregated signer public keys. This is the
//! spec's `validator_sigs` finality mechanism (SPEC §4.1): an aggregatable MULTISIG — each
//! validator holds its own key and the signer set is recorded — NOT a DKG threshold key (that is
//! `VA_pub`, a separate construct). min_pk encoding: public keys in G1 (48 B), signatures in G2
//! (96 B).

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

/// Domain-separation tag for consensus votes (must be distinct from every other BLS DST, cf.
/// SECURITY.md Appendix A DST registry).
pub const DST: &[u8] = b"PRIVACF_BLS_VOTE_v1";

/// Deterministic keypair from input keying material → (secret-key bytes, compressed public key).
pub fn keypair_from_ikm(ikm: &[u8]) -> ([u8; 32], [u8; 48]) {
    let sk = SecretKey::key_gen(ikm, &[]).expect("bls keygen (ikm >= 32 bytes)");
    (sk.to_bytes(), sk.sk_to_pk().to_bytes())
}

/// Sign `msg` with a secret key (bytes) → compressed signature.
pub fn sign(sk_bytes: &[u8; 32], msg: &[u8]) -> [u8; 96] {
    let sk = SecretKey::from_bytes(sk_bytes).expect("valid sk bytes");
    sk.sign(msg, DST, &[]).to_bytes()
}

/// Verify a single signature against a public key (both as bytes).
pub fn verify(pk_bytes: &[u8; 48], msg: &[u8], sig_bytes: &[u8; 96]) -> bool {
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(true, msg, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

/// Aggregate signatures (all over the same message) into one. Returns None on any malformed input.
pub fn aggregate(sigs: &[[u8; 96]]) -> Option<[u8; 96]> {
    let parsed: Vec<Signature> = sigs.iter().filter_map(|s| Signature::from_bytes(s).ok()).collect();
    if parsed.len() != sigs.len() || parsed.is_empty() {
        return None;
    }
    let refs: Vec<&Signature> = parsed.iter().collect();
    AggregateSignature::aggregate(&refs, true).ok().map(|a| a.to_signature().to_bytes())
}

/// Verify an aggregate signature over `msg` against the signer public keys (same-message fast path).
pub fn verify_aggregate(pks: &[[u8; 48]], msg: &[u8], agg_sig: &[u8; 96]) -> bool {
    let parsed: Vec<PublicKey> = pks.iter().filter_map(|p| PublicKey::from_bytes(p).ok()).collect();
    if parsed.len() != pks.len() || parsed.is_empty() {
        return false;
    }
    let refs: Vec<&PublicKey> = parsed.iter().collect();
    let sig = match Signature::from_bytes(agg_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.fast_aggregate_verify(true, msg, DST, &refs) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_verifies_and_rejects_tampering() {
        let kps: Vec<([u8; 32], [u8; 48])> =
            (0..4u64).map(|i| keypair_from_ikm(blake3::hash(&i.to_le_bytes()).as_bytes())).collect();
        let msg = b"block-id-bytes";
        let sigs: Vec<[u8; 96]> = kps[..3].iter().map(|(sk, _)| sign(sk, msg)).collect();
        let agg = aggregate(&sigs).expect("aggregate");
        let pks: Vec<[u8; 48]> = kps[..3].iter().map(|(_, pk)| *pk).collect();

        assert!(verify_aggregate(&pks, msg, &agg), "honest aggregate must verify");
        assert!(!verify_aggregate(&pks, b"other-msg", &agg), "wrong message must reject");
        let mut wrong = pks.clone();
        wrong[2] = kps[3].1; // claim a signer who did not sign
        assert!(!verify_aggregate(&wrong, msg, &agg), "wrong signer set must reject");
    }
}
