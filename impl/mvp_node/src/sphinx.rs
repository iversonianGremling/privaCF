//! Sphinx mix packets (SPEC §5.1 — the `LoopixTransport` seam). A Sphinx packet is the unit a
//! mixnet forwards: a **fixed-size** onion that each mix peels by one layer, learning *only* the
//! next hop and a per-hop delay — never the origin, the final destination, the payload, or its own
//! position in the path. Two packets entering and leaving a mix are **bitwise unlinkable**: every
//! byte (the group element `alpha`, the routing header `beta`, the MAC `gamma`, and the payload)
//! changes across the hop, so a passive network observer cannot correlate them. This bitwise
//! unlinkability — together with the Poisson per-hop delay and cover traffic in `loopix.rs` — is the
//! actual *who-talks-to-whom* hiding that the `epoch_id` rotation exists to make meaningful (Noise,
//! `transport.rs`, hides content but not the traffic pattern).
//!
//! Construction (Danezis–Goldberg Sphinx) — the crypto is isolated to this module:
//!   * **Group**: Ristretto over Curve25519 (prime-order, no cofactor, no X25519 clamping), so the
//!     multiplicative **key-blinding** chain is clean. The sender picks one ephemeral scalar `x`;
//!     hop `i` sees `alpha_i = x·(∏_{j<i} b_j)·G` and recovers the shared secret `s_i = sk_i·alpha_i`.
//!     It derives the blinding factor `b_i = H(alpha_i, s_i)` and forwards `alpha_{i+1} = b_i·alpha_i`
//!     — a single 32-byte element regardless of path length (the fixed-size trick).
//!   * **Header `beta`** (fixed `BETA_LEN`): a layered, stream-cipher-encrypted routing blob. Each
//!     hop XORs a keystream `rho(s_i)`, reads its `HOP_DATA` routing block (flag ‖ next-id ‖ delay)
//!     and the next hop's MAC, then shifts the remainder forward — padded by a sender-computed
//!     **filler** so the blob stays exactly `BETA_LEN` bytes and every hop's MAC verifies. The
//!     per-hop MAC `gamma = mu(s_i, beta)` gives routing integrity (a tampered header is rejected).
//!   * **Payload** (fixed `PAYLOAD_LEN`): commutatively stream-layered — the sender XORs every hop's
//!     `pay(s_i)` keystream, each hop peels its own, so intermediates see only ciphertext and the
//!     destination recovers the plaintext (verified by an embedded magic + BLAKE3 digest).
//!
//! Honest simplification: the payload uses XOR stream-layering (confidential, fixed-size, integrity
//! checked **at the destination**) rather than a wide-block SPRP (LIONESS). That means an *active*
//! mid-path attacker could maul payload bytes undetectably until delivery (the destination still
//! detects it via the digest, but cannot blame the hop). Production Sphinx uses LIONESS so any
//! payload bit-flip randomises the whole block; the routing header here already has full per-hop MAC
//! integrity. Keystreams/MACs use BLAKE3 (keyed hash + XOF), reusing the existing `blake3` dep
//! rather than pulling in a separate stream cipher.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Maximum mix path length a packet header can encode.
pub const MAX_HOPS: usize = 5;
/// Per-hop routing block: `flag(1) ‖ next_id(32) ‖ delay_ms(8)`.
const FLAG_LEN: usize = 1;
const ID_LEN: usize = 32;
const DELAY_LEN: usize = 8;
const HOP_DATA: usize = FLAG_LEN + ID_LEN + DELAY_LEN; // 41
/// Per-hop MAC length (truncated BLAKE3 keyed hash).
const MAC_LEN: usize = 16;
/// One header "block" consumed per hop: routing block + the next hop's MAC.
const BLOCK: usize = HOP_DATA + MAC_LEN; // 57
/// Fixed routing-header length — capacity for `MAX_HOPS` blocks.
pub const BETA_LEN: usize = MAX_HOPS * BLOCK; // 285
/// Fixed payload length (body + trailing digest). Bodies larger than `MAX_BODY` are rejected.
pub const PAYLOAD_LEN: usize = 1024;
const DIGEST_LEN: usize = 32;
const BODY_LEN: usize = PAYLOAD_LEN - DIGEST_LEN; // 992
/// Body layout: `MAGIC(4) ‖ len(u16 LE) ‖ data ‖ zero-pad`.
const MAGIC: [u8; 4] = *b"PCFx";
/// The largest plaintext one packet can carry (callers fragment or fall back above this).
pub const MAX_BODY: usize = BODY_LEN - MAGIC.len() - 2;

const FLAG_FORWARD: u8 = 0;
const FLAG_DELIVER: u8 = 1;

/// A hop in a mix path: its network id (peer_id, what a forwarding mix dials) and its Ristretto mix
/// public key (compressed). Assembled from the genesis mix directory (`loopix.rs`).
#[derive(Clone, Copy, Debug)]
pub struct Hop {
    pub id: [u8; 32],
    pub pk: [u8; 32],
}

/// A fixed-size Sphinx packet — the same byte length for every path length and payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// The blinded group element for the current hop (compressed Ristretto).
    pub alpha: [u8; 32],
    /// The layered routing header.
    #[serde(with = "BigArray")]
    pub beta: [u8; BETA_LEN],
    /// MAC of `beta` under the current hop's key.
    pub gamma: [u8; MAC_LEN],
    /// The onion-layered payload.
    #[serde(with = "BigArray")]
    pub payload: [u8; PAYLOAD_LEN],
}

/// The result of a mix processing one packet.
pub enum Processed {
    /// Forward the inner packet to `next` after waiting `delay_ms`.
    Forward { next: [u8; 32], delay_ms: u64, packet: SphinxPacket },
    /// This mix is the destination; `data` is the recovered plaintext.
    Deliver { data: Vec<u8> },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SphinxError {
    BadPoint,
    BadMac,
    BadPayload,
    PathTooLong,
    PayloadTooLarge,
    EmptyPath,
}

// --- key derivation from a shared secret (all BLAKE3) -------------------------------------------

fn subkey(s: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-sphinx-v1");
    h.update(domain);
    h.update(s);
    *h.finalize().as_bytes()
}

/// `rho` keystream of `len` bytes, keyed by the shared secret (header stream cipher).
fn rho(s: &[u8; 32], len: usize) -> Vec<u8> {
    let key = subkey(s, b"rho");
    let mut out = vec![0u8; len];
    blake3::Hasher::new_keyed(&key).finalize_xof().fill(&mut out);
    out
}

/// `mu` MAC of `beta` under the shared secret (header integrity).
fn mu(s: &[u8; 32], beta: &[u8]) -> [u8; MAC_LEN] {
    let key = subkey(s, b"mu");
    let tag = blake3::keyed_hash(&key, beta);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&tag.as_bytes()[..MAC_LEN]);
    out
}

/// `pay` keystream for the payload onion layer (one per hop, XORed commutatively).
fn pay_keystream(s: &[u8; 32]) -> [u8; PAYLOAD_LEN] {
    let key = subkey(s, b"pay");
    let mut out = [0u8; PAYLOAD_LEN];
    blake3::Hasher::new_keyed(&key).finalize_xof().fill(&mut out);
    out
}

/// Blinding factor `b_i = H(alpha_i ‖ s_i)` as a Ristretto scalar.
fn blinding(alpha_bytes: &[u8; 32], s: &[u8; 32]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-sphinx-blind");
    h.update(alpha_bytes);
    h.update(s);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn scalar_from_sk(sk: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*sk)
}

/// Derive a Ristretto mix keypair `(secret_scalar_bytes, public_compressed)` from 32 bytes of input
/// key material. Kept here so curve25519 stays isolated to this module (`identity.rs` stores bytes).
pub fn derive_mix_keypair(ikm: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-sphinx-mixkey");
    h.update(ikm);
    h.finalize_xof().fill(&mut wide);
    let sk = Scalar::from_bytes_mod_order_wide(&wide);
    let pk = (RISTRETTO_BASEPOINT_POINT * sk).compress().to_bytes();
    (sk.to_bytes(), pk)
}

// --- sender ---------------------------------------------------------------------------------------

/// The sender's per-hop filler: the bytes that must occupy the tail of the innermost `beta` so that
/// every hop's shift-and-pad reproduces exactly the header the next hop's MAC was computed over.
/// Accumulates the keystream tails of hops `0..v-1` (see the module derivation).
fn filler(secrets: &[[u8; 32]]) -> Vec<u8> {
    let v = secrets.len();
    let mut phi: Vec<u8> = Vec::new();
    for s in secrets.iter().take(v - 1) {
        let k = rho(s, BETA_LEN + BLOCK);
        let new_len = phi.len() + BLOCK;
        let ks = &k[(BETA_LEN + BLOCK - new_len)..(BETA_LEN + BLOCK)];
        phi.resize(new_len, 0u8);
        for (j, b) in phi.iter_mut().enumerate() {
            *b ^= ks[j];
        }
    }
    phi // length (v-1)*BLOCK
}

fn routing_block(flag: u8, next_id: &[u8; 32], delay_ms: u64) -> [u8; HOP_DATA] {
    let mut r = [0u8; HOP_DATA];
    r[0] = flag;
    r[1..1 + ID_LEN].copy_from_slice(next_id);
    r[1 + ID_LEN..].copy_from_slice(&delay_ms.to_le_bytes());
    r
}

/// Build a Sphinx packet routing `payload` along `path` with per-hop `delays` (ms). `delays[i]` is
/// the delay mix `i` applies before forwarding. The final hop is the destination.
pub fn create(path: &[Hop], delays: &[u64], payload: &[u8]) -> Result<SphinxPacket, SphinxError> {
    create_with_rng(path, delays, payload, &mut rand::thread_rng())
}

pub fn create_with_rng(
    path: &[Hop],
    delays: &[u64],
    payload: &[u8],
    rng: &mut impl RngCore,
) -> Result<SphinxPacket, SphinxError> {
    let v = path.len();
    if v == 0 {
        return Err(SphinxError::EmptyPath);
    }
    if v > MAX_HOPS {
        return Err(SphinxError::PathTooLong);
    }
    if payload.len() > MAX_BODY {
        return Err(SphinxError::PayloadTooLarge);
    }

    // 1. Ephemeral scalar x; walk the blinding chain to get every alpha_i and shared secret s_i.
    let mut xbytes = [0u8; 64];
    rng.fill_bytes(&mut xbytes);
    let x = Scalar::from_bytes_mod_order_wide(&xbytes);

    let mut blind_acc = x; // x * ∏_{j<i} b_j
    let mut alpha_point = RISTRETTO_BASEPOINT_POINT * x; // alpha_0
    let alpha0 = alpha_point.compress().to_bytes();
    let mut secrets: Vec<[u8; 32]> = Vec::with_capacity(v);
    for hop in path {
        let alpha_i_bytes = alpha_point.compress().to_bytes();
        let y_i = CompressedRistretto(hop.pk).decompress().ok_or(SphinxError::BadPoint)?;
        let s_i = (y_i * blind_acc).compress().to_bytes();
        secrets.push(s_i);
        let b_i = blinding(&alpha_i_bytes, &s_i);
        blind_acc *= b_i;
        alpha_point *= b_i; // alpha_{i+1}
    }

    // 2. Filler so the header stays fixed-size through every shift.
    let phi = filler(&secrets);
    debug_assert_eq!(phi.len(), (v - 1) * BLOCK);

    // 3. Innermost beta (for the destination hop v-1): routing region (encrypted) ‖ filler.
    let region_len = BETA_LEN - phi.len();
    let mut region = vec![0u8; region_len];
    // The destination only reads HOP_DATA; the rest is random padding (incl. the unused MAC slot).
    rng.fill_bytes(&mut region);
    region[..HOP_DATA].copy_from_slice(&routing_block(FLAG_DELIVER, &[0u8; 32], delays[v - 1]));
    let k_last = rho(&secrets[v - 1], region_len);
    for (j, b) in region.iter_mut().enumerate() {
        *b ^= k_last[j];
    }
    let mut beta = vec![0u8; BETA_LEN];
    beta[..region_len].copy_from_slice(&region);
    beta[region_len..].copy_from_slice(&phi);
    let mut gamma = mu(&secrets[v - 1], &beta);

    // 4. Wrap outward: for i = v-2 .. 0, prepend (routing_i ‖ gamma_{i+1}), shift, encrypt, re-MAC.
    for i in (0..v - 1).rev() {
        let r_i = routing_block(FLAG_FORWARD, &path[i + 1].id, delays[i]);
        let mut plain = Vec::with_capacity(BLOCK + BETA_LEN);
        plain.extend_from_slice(&r_i);
        plain.extend_from_slice(&gamma);
        plain.extend_from_slice(&beta);
        plain.truncate(BETA_LEN); // drop the last BLOCK bytes
        let k_i = rho(&secrets[i], BETA_LEN);
        for (j, b) in plain.iter_mut().enumerate() {
            *b ^= k_i[j];
        }
        beta.copy_from_slice(&plain);
        gamma = mu(&secrets[i], &beta);
    }

    // 5. Payload: inner body (magic ‖ len ‖ data ‖ pad) ‖ digest, then XOR every hop's layer.
    let mut body = [0u8; BODY_LEN];
    body[..MAGIC.len()].copy_from_slice(&MAGIC);
    body[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    body[MAGIC.len() + 2..MAGIC.len() + 2 + payload.len()].copy_from_slice(payload);
    let digest = blake3::hash(&body);
    let mut onion = [0u8; PAYLOAD_LEN];
    onion[..BODY_LEN].copy_from_slice(&body);
    onion[BODY_LEN..].copy_from_slice(digest.as_bytes());
    for s in &secrets {
        let ks = pay_keystream(s);
        for (b, k) in onion.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
    }

    let mut beta_arr = [0u8; BETA_LEN];
    beta_arr.copy_from_slice(&beta);
    Ok(SphinxPacket { alpha: alpha0, beta: beta_arr, gamma, payload: onion })
}

// --- mix ------------------------------------------------------------------------------------------

/// Process one packet at a mix holding secret-key bytes `mix_sk`. Returns either the next hop +
/// delay (with the peeled inner packet) or the recovered plaintext if this mix is the destination.
pub fn process(mix_sk: &[u8; 32], pkt: &SphinxPacket) -> Result<Processed, SphinxError> {
    let alpha = CompressedRistretto(pkt.alpha).decompress().ok_or(SphinxError::BadPoint)?;
    let s = (alpha * scalar_from_sk(mix_sk)).compress().to_bytes();

    // Routing integrity: the MAC must match before we trust any header byte.
    if mu(&s, &pkt.beta) != pkt.gamma {
        return Err(SphinxError::BadMac);
    }

    // Peel the header: append BLOCK zeros, XOR the keystream, read this hop's block, keep the shift.
    let k = rho(&s, BETA_LEN + BLOCK);
    let mut stripped = vec![0u8; BETA_LEN + BLOCK];
    stripped[..BETA_LEN].copy_from_slice(&pkt.beta);
    for (j, b) in stripped.iter_mut().enumerate() {
        *b ^= k[j];
    }
    let flag = stripped[0];
    let mut next_id = [0u8; 32];
    next_id.copy_from_slice(&stripped[1..1 + ID_LEN]);
    let mut delay_b = [0u8; 8];
    delay_b.copy_from_slice(&stripped[1 + ID_LEN..HOP_DATA]);
    let delay_ms = u64::from_le_bytes(delay_b);
    let mut gamma_next = [0u8; MAC_LEN];
    gamma_next.copy_from_slice(&stripped[HOP_DATA..BLOCK]);
    let beta_next = &stripped[BLOCK..BLOCK + BETA_LEN];

    // Peel one payload layer.
    let mut payload = pkt.payload;
    let ks = pay_keystream(&s);
    for (b, kk) in payload.iter_mut().zip(ks.iter()) {
        *b ^= *kk;
    }

    if flag == FLAG_DELIVER {
        return Ok(Processed::Deliver { data: open_payload(&payload)? });
    }

    // Forward: blind alpha for the next hop.
    let b_i = blinding(&pkt.alpha, &s);
    let alpha_next = (alpha * b_i).compress().to_bytes();
    let mut beta_arr = [0u8; BETA_LEN];
    beta_arr.copy_from_slice(beta_next);
    Ok(Processed::Forward {
        next: next_id,
        delay_ms,
        packet: SphinxPacket { alpha: alpha_next, beta: beta_arr, gamma: gamma_next, payload },
    })
}

/// Verify and extract the destination plaintext from a fully-peeled payload.
fn open_payload(payload: &[u8; PAYLOAD_LEN]) -> Result<Vec<u8>, SphinxError> {
    let body = &payload[..BODY_LEN];
    let digest = &payload[BODY_LEN..];
    if blake3::hash(body).as_bytes() != digest {
        return Err(SphinxError::BadPayload);
    }
    if body[..MAGIC.len()] != MAGIC {
        return Err(SphinxError::BadPayload);
    }
    let len = u16::from_le_bytes([body[MAGIC.len()], body[MAGIC.len() + 1]]) as usize;
    if len > MAX_BODY {
        return Err(SphinxError::BadPayload);
    }
    Ok(body[MAGIC.len() + 2..MAGIC.len() + 2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of `n` mixes with deterministic keys; returns (hops, secret-key bytes per hop).
    fn make_mixes(n: usize) -> (Vec<Hop>, Vec<[u8; 32]>) {
        let mut hops = Vec::new();
        let mut sks = Vec::new();
        for i in 0..n {
            let ikm = blake3::hash(format!("mix-{i}").as_bytes());
            let (sk, pk) = derive_mix_keypair(ikm.as_bytes());
            let id = *blake3::hash(format!("id-{i}").as_bytes()).as_bytes();
            hops.push(Hop { id, pk });
            sks.push(sk);
        }
        (hops, sks)
    }

    /// Route a packet through every hop and assert the destination recovers the plaintext.
    fn roundtrip_len(v: usize) {
        let (hops, sks) = make_mixes(v);
        let delays: Vec<u64> = (0..v).map(|i| (i as u64 + 1) * 10).collect();
        let msg = format!("hello via {v} hops").into_bytes();
        let mut pkt = create(&hops, &delays, &msg).unwrap();

        for i in 0..v {
            match process(&sks[i], &pkt).unwrap() {
                Processed::Forward { next, delay_ms, packet } => {
                    assert!(i < v - 1, "non-final hop {i} should forward");
                    assert_eq!(next, hops[i + 1].id, "hop {i} must point at the next hop");
                    assert_eq!(delay_ms, delays[i], "hop {i} delay must survive");
                    pkt = packet;
                }
                Processed::Deliver { data } => {
                    assert_eq!(i, v - 1, "only the final hop delivers");
                    assert_eq!(data, msg, "destination must recover the plaintext");
                }
            }
        }
    }

    #[test]
    fn roundtrips_for_every_path_length() {
        for v in 1..=MAX_HOPS {
            roundtrip_len(v);
        }
    }

    #[test]
    fn packet_is_fixed_size_regardless_of_path_or_payload() {
        let (h5, _) = make_mixes(5);
        let (h1, _) = make_mixes(1);
        let big = vec![7u8; MAX_BODY];
        let a = create(&h5, &[1, 2, 3, 4, 5], b"x").unwrap();
        let b = create(&h1[..1], &[9], &big).unwrap();
        let sa = bincode::serialize(&a).unwrap();
        let sb = bincode::serialize(&b).unwrap();
        assert_eq!(sa.len(), sb.len(), "all Sphinx packets must serialize to one fixed size");
    }

    #[test]
    fn every_byte_changes_across_a_hop() {
        // Bitwise unlinkability: the packet a mix emits shares no field with the one it received.
        let (hops, sks) = make_mixes(3);
        let pkt = create(&hops, &[5, 5, 5], b"unlink").unwrap();
        match process(&sks[0], &pkt).unwrap() {
            Processed::Forward { packet, .. } => {
                assert_ne!(packet.alpha, pkt.alpha, "alpha must change");
                assert_ne!(packet.beta, pkt.beta, "beta must change");
                assert_ne!(packet.gamma, pkt.gamma, "gamma must change");
                assert_ne!(packet.payload, pkt.payload, "payload must change");
            }
            _ => panic!("first of three hops must forward"),
        }
    }

    #[test]
    fn a_tampered_header_is_rejected() {
        let (hops, sks) = make_mixes(3);
        let mut pkt = create(&hops, &[5, 5, 5], b"tamper").unwrap();
        pkt.beta[0] ^= 0x01;
        assert!(matches!(process(&sks[0], &pkt), Err(SphinxError::BadMac)));
    }

    #[test]
    fn the_wrong_mix_key_cannot_process() {
        let (hops, _) = make_mixes(2);
        let (wrong_sk, _) = derive_mix_keypair(blake3::hash(b"unrelated").as_bytes());
        let pkt = create(&hops, &[5, 5], b"nope").unwrap();
        // A different key yields a different shared secret, so the MAC fails.
        assert!(matches!(process(&wrong_sk, &pkt), Err(SphinxError::BadMac)));
    }

    #[test]
    fn intermediate_hops_cannot_read_the_payload() {
        // After the first hop peels its layer the payload is still masked by the remaining layers,
        // so a mid-path mix sees no magic and cannot open it.
        let (hops, sks) = make_mixes(3);
        let pkt = create(&hops, &[1, 1, 1], b"secret-cargo").unwrap();
        let mid = match process(&sks[0], &pkt).unwrap() {
            Processed::Forward { packet, .. } => packet,
            _ => panic!(),
        };
        assert!(open_payload(&mid.payload).is_err(), "a half-peeled payload must not open");
    }

    #[test]
    fn rejects_oversize_payload_and_overlong_path() {
        let (h1, _) = make_mixes(1);
        assert!(matches!(
            create(&h1, &[1], &vec![0u8; MAX_BODY + 1]),
            Err(SphinxError::PayloadTooLarge)
        ));
        let (h6, _) = make_mixes(6);
        let d = vec![1u64; 6];
        assert!(matches!(create(&h6, &d, b"x"), Err(SphinxError::PathTooLong)));
    }
}
