//! Transport seam. The MVP now runs every peer connection over a real **Noise** channel
//! (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, via `snow`): an authenticated key exchange giving
//! confidentiality, integrity, and forward secrecy on the wire. The crypto is isolated to this
//! module (the one place `snow` is used), mirroring the `bls.rs`/`vrf.rs`/`hash.rs` discipline.
//!
//! What Noise gives us here:
//!   * **Confidentiality + integrity** — frames are ChaCha20-Poly1305 AEAD, not plaintext bincode.
//!   * **Forward secrecy** — the XX handshake mixes fresh ephemeral DH keys, so recording the
//!     ciphertext and later compromising a node does not retroactively decrypt past sessions.
//!   * **A channel-binding hash** — `get_handshake_hash()` is unique per handshake; `node.rs` signs
//!     it with the long-term ed25519 identity key inside the first (encrypted) `Hello`, so the
//!     authenticated identity is bound to *this* channel. A man-in-the-middle relaying the two legs
//!     gets two different handshake hashes, so the relayed signature fails to verify — this is what
//!     turns XX's anonymous-static exchange into mutual identity authentication without adding a
//!     long-term X25519 key to the validator set.
//!
//! What it still does NOT give: **anonymity / unlinkability**. A network observer still sees who
//! talks to whom and when. That is the job of the real future impl — `LoopixTransport` (self-mixing
//! Loopix/Sphinx: Poisson per-hop delay, cover traffic, SURBs; SPEC §5.1) — and is the whole reason
//! `epoch_id` rotates. Noise removes the *plaintext-wire* caveat; Loopix removes the *linkability*
//! one.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message::Message;

/// Network transport seam. Marker trait — see module docs.
pub trait Transport: Send + Sync {}

/// Clearnet TCP transport, now wrapped in a Noise channel (dev/test; no mixing yet).
pub struct TcpTransport;
impl Transport for TcpTransport {}

/// The Noise pattern: XX = mutual, both sides transmit a (per-connection ephemeral) static key.
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Noise's hard per-message ceiling (handshake and transport messages alike).
const NOISE_MAX_MSG: usize = 65535;
/// Max plaintext we put in one Noise transport message, leaving room for the 16-byte AEAD tag.
const MAX_NOISE_PLAINTEXT: usize = NOISE_MAX_MSG - 16;

/// Maximum accepted *application* frame size, reassembled across Noise chunks (defensive bound;
/// the real `frame_size` is OQ-30, §10.1.1).
const MAX_FRAME: usize = 1 << 22;

fn noise_err<E: std::fmt::Debug>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("noise: {e:?}"))
}

fn invalid<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// An established Noise channel. Holds the post-handshake cipher state in *stateless* mode so the
/// two halves of a split `TcpStream` can encrypt/decrypt independently: each direction keeps its
/// own monotonic nonce counter (passed into `write_frame`/`read_frame`), and the two counters never
/// touch, so no lock is needed across the reader/writer split.
pub struct NoiseChannel {
    transport: snow::StatelessTransportState,
}

/// Perform the Noise XX handshake over `stream`, returning the established channel and the 32-byte
/// handshake hash (the channel-binding value `node.rs` signs with its ed25519 identity key). The
/// dialer is the Noise initiator; the listener is the responder.
pub async fn noise_handshake<S>(stream: &mut S, initiator: bool) -> std::io::Result<(NoiseChannel, [u8; 32])>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().map_err(noise_err)?;
    let builder = snow::Builder::new(params);
    // A fresh static keypair per connection: XX transmits it, but identity is established by the
    // ed25519 channel binding (node.rs), so this static key need not persist.
    let keypair = builder.generate_keypair().map_err(noise_err)?;
    let builder = builder.local_private_key(&keypair.private);
    let mut hs = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(noise_err)?;

    let mut buf = vec![0u8; NOISE_MAX_MSG];
    if initiator {
        // -> e
        let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        write_hs(stream, &buf[..n]).await?;
        // <- e, ee, s, es
        let msg = read_hs(stream).await?;
        hs.read_message(&msg, &mut buf).map_err(noise_err)?;
        // -> s, se
        let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        write_hs(stream, &buf[..n]).await?;
    } else {
        let msg = read_hs(stream).await?;
        hs.read_message(&msg, &mut buf).map_err(noise_err)?;
        let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        write_hs(stream, &buf[..n]).await?;
        let msg = read_hs(stream).await?;
        hs.read_message(&msg, &mut buf).map_err(noise_err)?;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(hs.get_handshake_hash());
    let transport = hs.into_stateless_transport_mode().map_err(noise_err)?;
    Ok((NoiseChannel { transport }, hash))
}

/// Write one raw (plaintext) Noise *handshake* message, u16-length-prefixed.
async fn write_hs<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    w.write_all(&(msg.len() as u16).to_le_bytes()).await?;
    w.write_all(msg).await?;
    w.flush().await?;
    Ok(())
}

/// Read one raw (plaintext) Noise *handshake* message, u16-length-prefixed.
async fn read_hs<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_le_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write one application frame over the Noise channel: a u32 plaintext length, then one or more
/// `[u16 ciphertext_len][ciphertext]` Noise transport messages reassembling to that plaintext.
/// `nonce` is this direction's monotonic counter — the caller owns it and it advances per chunk.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    chan: &NoiseChannel,
    nonce: &mut u64,
    msg: &Message,
) -> std::io::Result<()> {
    let bytes = bincode::serialize(msg).map_err(invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    // A zero-length frame still emits no chunks; bincode never produces one for our Message enum.
    for chunk in bytes.chunks(MAX_NOISE_PLAINTEXT) {
        let mut out = vec![0u8; chunk.len() + 16];
        let n = chan.transport.write_message(*nonce, chunk, &mut out).map_err(noise_err)?;
        *nonce += 1;
        w.write_all(&(n as u16).to_le_bytes()).await?;
        w.write_all(&out[..n]).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Read one application frame written by `write_frame`, decrypting and reassembling the chunks.
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
    chan: &NoiseChannel,
    nonce: &mut u64,
) -> std::io::Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let total = u32::from_le_bytes(len) as usize;
    if total > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    let mut acc = Vec::with_capacity(total);
    while acc.len() < total {
        let mut clen = [0u8; 2];
        r.read_exact(&mut clen).await?;
        let clen = u16::from_le_bytes(clen) as usize;
        // A transport message is at least the 16-byte AEAD tag; anything shorter is malformed
        // (and would otherwise risk a no-progress loop).
        if clen < 16 || clen > NOISE_MAX_MSG {
            return Err(invalid("bad noise chunk length"));
        }
        let mut cbuf = vec![0u8; clen];
        r.read_exact(&mut cbuf).await?;
        let mut pbuf = vec![0u8; clen];
        let n = chan.transport.read_message(*nonce, &cbuf, &mut pbuf).map_err(noise_err)?;
        *nonce += 1;
        acc.extend_from_slice(&pbuf[..n]);
        if acc.len() > total {
            return Err(invalid("frame overrun"));
        }
    }
    bincode::deserialize(&acc).map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the XX handshake over an in-memory duplex pair and return both established channels and
    /// their (shared) handshake hash.
    async fn connected() -> (NoiseChannel, [u8; 32], NoiseChannel, [u8; 32]) {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (ra, rb) = tokio::join!(noise_handshake(&mut a, true), noise_handshake(&mut b, false));
        let (ca, ha) = ra.unwrap();
        let (cb, hb) = rb.unwrap();
        (ca, ha, cb, hb)
    }

    #[tokio::test]
    async fn handshake_agrees_and_channel_is_confidential_and_authenticated() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (ra, rb) = tokio::join!(noise_handshake(&mut a, true), noise_handshake(&mut b, false));
        let (chan_a, hash_a) = ra.unwrap();
        let (chan_b, hash_b) = rb.unwrap();

        // Both ends derive the identical channel-binding hash — this is the value node.rs signs with
        // its ed25519 key, and a MITM (two separate handshakes) could not make these agree.
        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, [0u8; 32]);

        // A frame round-trips through the encrypted channel (each direction owns its own nonce).
        let mut ns = 0u64;
        let mut nr = 0u64;
        write_frame(&mut a, &chan_a, &mut ns, &Message::GetChain { from_height: 42 }).await.unwrap();
        match read_frame(&mut b, &chan_b, &mut nr).await.unwrap() {
            Message::GetChain { from_height } => assert_eq!(from_height, 42),
            other => panic!("wrong message: {other:?}"),
        }

        // Confidentiality: the on-wire chunk is not the plaintext. Integrity: flipping one bit makes
        // the AEAD tag fail, so the chunk does not decrypt.
        let mut ct = vec![0u8; 64];
        let n = chan_a.transport.write_message(7, b"secret-payload", &mut ct).unwrap();
        assert_ne!(&ct[..14], b"secret-payload");
        ct[0] ^= 0x01;
        let mut pt = vec![0u8; 64];
        assert!(chan_b.transport.read_message(7, &ct[..n], &mut pt).is_err());
    }

    #[tokio::test]
    async fn a_large_multi_chunk_frame_reassembles() {
        let (chan_a, _, chan_b, _) = connected().await;
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let mut ns = 0u64;
        let mut nr = 0u64;
        // A payload far larger than one Noise message (>64 KiB) forces multi-chunk framing.
        let payload: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let msg = Message::Hello { peer_id: [9u8; 32], listen_addr: String::new(), binding: payload.clone() };
        write_frame(&mut a, &chan_a, &mut ns, &msg).await.unwrap();
        match read_frame(&mut b, &chan_b, &mut nr).await.unwrap() {
            Message::Hello { binding, .. } => assert_eq!(binding, payload),
            other => panic!("wrong message: {other:?}"),
        }
        assert!(ns > 1, "a 200 KB frame must span multiple Noise chunks");
    }

    #[tokio::test]
    async fn independent_handshakes_have_distinct_binding_hashes() {
        // Per-channel uniqueness is what makes the ed25519 channel binding meaningful: a signature
        // over one channel's hash cannot be replayed onto another.
        let (_, h1, _, _) = connected().await;
        let (_, h2, _, _) = connected().await;
        assert_ne!(h1, h2);
    }
}
