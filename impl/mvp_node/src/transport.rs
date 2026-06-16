//! Transport seam. Stub: clearnet TCP with length-prefixed bincode framing — the spec permits
//! clearnet for development/testing (SPEC §5.1.1), with the explicit caveat that it satisfies NONE
//! of the required transport properties (no anonymity, fully linkable to a network observer).
//!
//! Real future impl: `LoopixTransport` — self-mixing Loopix/Sphinx (Poisson per-hop delay, cover
//! traffic, SURBs; SPEC §5.1). The `Transport` trait marks the seam; the MVP has exactly one impl
//! and drives `tokio::net::TcpStream` directly with the framing helpers below.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message::Message;

/// Network transport seam. Marker trait — see module docs.
pub trait Transport: Send + Sync {}

/// Clearnet TCP transport (dev/test only).
pub struct TcpTransport;
impl Transport for TcpTransport {}

/// Maximum accepted frame size (defensive bound; real `frame_size` is OQ-30, §10.1.1).
const MAX_FRAME: usize = 1 << 22;

/// Write one length-prefixed bincode frame.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &Message) -> std::io::Result<()> {
    let bytes = bincode::serialize(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed bincode frame.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
