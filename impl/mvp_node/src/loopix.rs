//! The Loopix mix layer (SPEC §5.1 — the `LoopixTransport` seam): a self-mixing mixnet built on the
//! fixed-size Sphinx packets of `sphinx.rs`, running over the existing Noise channels (`transport.rs`).
//! This is the piece that finally provides **unlinkability** — the who-talks-to-whom hiding the
//! `epoch_id` rotation exists to make meaningful. Noise already hides *content*; Loopix hides the
//! *traffic pattern*.
//!
//! Two design choices are fixed per the project directive — **presuppose a good genesis** and
//! **extract the entropy from the blockchain**:
//!   * **Genesis mix directory** (`MixDirectory`): every mix's network id, dial address, and
//!     Ristretto mix public key are taken as published at a trusted genesis (the same nodes that are
//!     genesis validators). No trustless directory-authority / PKI bootstrap is attempted here.
//!   * **Chain-derived entropy**: the mix **path**, the per-hop **Poisson delays**, and the
//!     **cover-traffic** schedule are all seeded from the chain's VRF-chained `beacon_T`
//!     (`beacon.rs`) — the protocol's existing, already-unpredictable randomness — rather than an
//!     external VDF/drand. A per-message `nonce` is folded in so two messages in the same epoch take
//!     independent paths. Because the beacon is unpredictable until the prior block finalizes, an
//!     adversary cannot precompute future paths; because it is a deterministic function of the
//!     finalized chain, any party (e.g. for audit) can recompute a path from public data.
//!
//! What this gives, and what it does not: real Sphinx unlinkability per hop, Poisson per-hop delay
//! (stop-and-go mixing), and loop **cover traffic** indistinguishable from real packets. It does
//! *not* yet model drop cover, SURB-based anonymous replies, or per-provider mailboxing, and the
//! statistical anonymity-set guarantees are asserted only at the mechanism level (correct multi-hop
//! delivery, bitwise unlinkability, delay distribution) — the full traffic-analysis resistance is a
//! deployment-scale property. Routing consensus gossip *through* this layer (so the BFT messages
//! themselves are unlinkable) is the next integration step; here the mixnet is exercised end-to-end
//! as its own transport.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::debug;

use crate::identity::NodeIdentity;
use crate::message::Message;
use crate::sphinx::{self, Hop, Processed, SphinxPacket};
use crate::transport::{noise_handshake, read_frame, write_frame};

/// One mix's public record in the genesis directory.
#[derive(Clone, Debug)]
pub struct MixEntry {
    pub peer_id: [u8; 32],
    pub addr: String,
    pub mix_pk: [u8; 32],
}

/// The genesis mix directory — presupposed published at a trusted genesis.
#[derive(Clone, Debug, Default)]
pub struct MixDirectory {
    entries: Vec<MixEntry>,
}

impl MixDirectory {
    pub fn new(mut entries: Vec<MixEntry>) -> Self {
        entries.sort_by_key(|e| e.peer_id);
        entries.dedup_by_key(|e| e.peer_id);
        Self { entries }
    }

    /// Build the directory from a set of (genesis) identities listening on given addresses.
    pub fn from_identities(ids: &[(&NodeIdentity, String)]) -> Self {
        let entries = ids
            .iter()
            .map(|(id, addr)| MixEntry {
                peer_id: id.peer_id(),
                addr: addr.clone(),
                mix_pk: id.mix_pk(),
            })
            .collect();
        Self::new(entries)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entry(&self, peer_id: &[u8; 32]) -> Option<&MixEntry> {
        self.entries.iter().find(|e| &e.peer_id == peer_id)
    }

    /// The Sphinx hop (id + mix key) for a directory member.
    pub fn hop(&self, peer_id: &[u8; 32]) -> Option<Hop> {
        self.entry(peer_id).map(|e| Hop { id: e.peer_id, pk: e.mix_pk })
    }

    /// The dial address for a directory member.
    pub fn addr(&self, peer_id: &[u8; 32]) -> Option<String> {
        self.entry(peer_id).map(|e| e.addr.clone())
    }

    /// All member ids (sorted).
    pub fn ids(&self) -> Vec<[u8; 32]> {
        self.entries.iter().map(|e| e.peer_id).collect()
    }
}

// --- chain-derived entropy ------------------------------------------------------------------------

/// A deterministic byte/number source keyed by a 32-byte seed (BLAKE3 XOF). All Loopix randomness
/// (path, delays, cover schedule) flows from a chain-beacon-derived seed through one of these, so it
/// is reproducible from public chain data yet unpredictable before the beacon is revealed.
struct DetRng {
    reader: blake3::OutputReader,
}

impl DetRng {
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// A uniform index in `0..n` (n > 0). The modulo bias is negligible for directory-sized `n`.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// A uniform double in the open interval (0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 2.0)
    }
}

/// Seed the Loopix RNG from the chain beacon and a per-message nonce (domain-separated).
fn beacon_rng(beacon: u64, nonce: u64, domain: &[u8]) -> DetRng {
    let mut h = blake3::Hasher::new();
    h.update(b"privacf-loopix-v1");
    h.update(domain);
    h.update(&beacon.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    let seed = *h.finalize().as_bytes();
    DetRng { reader: blake3::Hasher::new_keyed(&seed).finalize_xof() }
}

/// Select a mix path of `hops` total hops (including the final `dest`) from `dir`, seeded by the
/// chain beacon. Intermediate hops exclude `source` and `dest`; the last hop is always `dest` (which
/// may equal `source` for a loop/cover packet). Returns `None` if the directory lacks enough
/// distinct mixes. Deterministic in `(beacon, nonce)`.
pub fn select_path(
    dir: &MixDirectory,
    source: &[u8; 32],
    dest: &[u8; 32],
    hops: usize,
    beacon: u64,
    nonce: u64,
) -> Option<Hop> {
    select_full_path(dir, source, dest, hops, beacon, nonce).and_then(|p| p.into_iter().next())
}

/// As `select_path`, returning the entire ordered hop list.
pub fn select_full_path(
    dir: &MixDirectory,
    source: &[u8; 32],
    dest: &[u8; 32],
    hops: usize,
    beacon: u64,
    nonce: u64,
) -> Option<Vec<Hop>> {
    if hops == 0 || hops > sphinx::MAX_HOPS {
        return None;
    }
    let dest_hop = dir.hop(dest)?;
    let need = hops - 1; // intermediate mixes before the destination
    let mut candidates: Vec<[u8; 32]> =
        dir.ids().into_iter().filter(|p| p != source && p != dest).collect();
    if candidates.len() < need {
        return None;
    }
    let mut rng = beacon_rng(beacon, nonce, b"path");
    let mut path = Vec::with_capacity(hops);
    for _ in 0..need {
        let idx = rng.below(candidates.len());
        let id = candidates.remove(idx);
        path.push(dir.hop(&id)?);
    }
    path.push(dest_hop);
    Some(path)
}

/// Sample `n` independent per-hop delays (ms) from an exponential distribution with the given mean,
/// seeded by the chain beacon (the Loopix stop-and-go mixing delays). Deterministic in
/// `(beacon, nonce)`.
pub fn sample_delays(n: usize, mean_ms: u64, beacon: u64, nonce: u64) -> Vec<u64> {
    if mean_ms == 0 {
        return vec![0; n];
    }
    let mut rng = beacon_rng(beacon, nonce, b"delay");
    (0..n)
        .map(|_| {
            // Inverse-CDF of Exp(1/mean): -mean * ln(u), u ~ Uniform(0,1).
            (-(mean_ms as f64) * rng.unit().ln()) as u64
        })
        .collect()
}

// --- fragmentation / reassembly -------------------------------------------------------------------
//
// A Sphinx payload is a fixed `PAYLOAD_LEN`; a serialized message (a block-bearing `Proposal` or
// `Finalized` especially) can exceed the `MAX_BODY` one packet carries. So every mix-routed message
// is split into one or more **fragments**, each its own Sphinx packet, reassembled at the
// destination. Single-packet messages are just a 1-fragment message (uniform path). Each fragment is
// framed `msg_id(16) ‖ index(u16 LE) ‖ count(u16 LE) ‖ chunk`.

/// Fragment framing header length.
pub const FRAG_HEADER: usize = 16 + 2 + 2;
/// Max original-message bytes carried per fragment (the rest of the Sphinx body is the header).
pub const FRAG_CHUNK: usize = sphinx::MAX_BODY - FRAG_HEADER;

/// Split `payload` into framed fragments (≥1) sharing `msg_id`, each ≤ `sphinx::MAX_BODY` and ready
/// to hand to `sphinx::create`.
pub fn fragment(msg_id: [u8; 16], payload: &[u8]) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> =
        if payload.is_empty() { vec![&[][..]] } else { payload.chunks(FRAG_CHUNK).collect() };
    let count = chunks.len().min(u16::MAX as usize) as u16;
    chunks
        .into_iter()
        .take(count as usize)
        .enumerate()
        .map(|(i, c)| {
            let mut f = Vec::with_capacity(FRAG_HEADER + c.len());
            f.extend_from_slice(&msg_id);
            f.extend_from_slice(&(i as u16).to_le_bytes());
            f.extend_from_slice(&count.to_le_bytes());
            f.extend_from_slice(c);
            f
        })
        .collect()
}

struct Partial {
    count: u16,
    parts: Vec<Option<Vec<u8>>>,
    seq: u64,
}

/// Reassembles fragments back into whole messages, keyed by `msg_id`. Bounded: at most
/// `max_partials` incomplete messages are buffered; the oldest is evicted past that (so lost
/// fragments cannot grow memory without limit).
pub struct Reassembler {
    partials: HashMap<[u8; 16], Partial>,
    seq: u64,
    max_partials: usize,
}

impl Reassembler {
    pub fn new(max_partials: usize) -> Self {
        Self { partials: HashMap::new(), seq: 0, max_partials: max_partials.max(1) }
    }

    /// Accept one framed fragment; returns the fully reassembled message bytes once its last
    /// fragment arrives (fragments may arrive out of order, interleaved across messages).
    pub fn accept(&mut self, frag: &[u8]) -> Option<Vec<u8>> {
        if frag.len() < FRAG_HEADER {
            return None;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&frag[..16]);
        let index = u16::from_le_bytes([frag[16], frag[17]]) as usize;
        let count = u16::from_le_bytes([frag[18], frag[19]]);
        if count == 0 || index >= count as usize {
            return None;
        }
        let chunk = frag[FRAG_HEADER..].to_vec();
        let seq = self.seq;
        self.seq += 1;
        let entry = self
            .partials
            .entry(id)
            .or_insert_with(|| Partial { count, parts: vec![None; count as usize], seq });
        if entry.count != count {
            return None; // inconsistent re-use of a msg_id; ignore
        }
        entry.parts[index] = Some(chunk);
        if entry.parts.iter().all(|p| p.is_some()) {
            let p = self.partials.remove(&id).expect("present");
            return Some(p.parts.into_iter().flatten().flatten().collect());
        }
        if self.partials.len() > self.max_partials {
            let oldest = self.partials.iter().min_by_key(|(_, v)| v.seq).map(|(k, _)| *k);
            if let Some(old) = oldest {
                self.partials.remove(&old);
            }
        }
        None
    }
}

// --- the mix node engine --------------------------------------------------------------------------

type Peers = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

/// Cover-traffic payload markers. Loopix sends two kinds of indistinguishable cover so an observer
/// cannot tell when a node genuinely transmits: a **loop** packet (routed back to the sender, which
/// recognizes its return — a liveness/active-attack monitor) and a **drop** packet (routed to a
/// random other mix, which silently discards it — pure padding). Real app payloads carry neither
/// marker. The markers live in the (decrypted, reassembled) payload, so they are invisible on the
/// wire — every Sphinx packet looks identical.
const LOOP_MARKER: &[u8] = b"\x00cover";
const DROP_MARKER: &[u8] = b"\x00drop";

/// What a delivered payload is, by its marker.
enum Delivery {
    Real,
    Loop,
    Drop,
}

fn classify(payload: &[u8]) -> Delivery {
    if payload.starts_with(LOOP_MARKER) {
        Delivery::Loop
    } else if payload.starts_with(DROP_MARKER) {
        Delivery::Drop
    } else {
        Delivery::Real
    }
}

/// A request to send `payload` to `dest` through a chain-selected `hops`-hop path, using `beacon`
/// (+`nonce`) as the entropy source and `mean_delay_ms` as the per-hop Poisson delay mean. Set
/// `dest = self` for a loop cover packet.
#[derive(Clone, Debug)]
pub struct Injection {
    pub payload: Vec<u8>,
    pub dest: [u8; 32],
    pub hops: usize,
    pub beacon: u64,
    pub nonce: u64,
    pub mean_delay_ms: u64,
}

/// Configuration for a running mix node.
pub struct MixConfig {
    pub listen_addr: String,
    pub directory: MixDirectory,
    /// If > 0, emit a **loop** cover packet on an exponential timer with this mean (ms) — routed back
    /// to self, indistinguishable on the wire from real traffic.
    pub cover_mean_ms: u64,
    /// Hop count for loop cover packets.
    pub cover_hops: usize,
    /// Per-hop delay mean (ms) for loop cover packets.
    pub cover_delay_ms: u64,
    /// If > 0, emit a **drop** cover packet on an exponential timer with this mean (ms) — routed to a
    /// random other mix, which silently discards it (pure padding traffic).
    pub drop_cover_mean_ms: u64,
    /// Hop count for drop cover packets.
    pub drop_cover_hops: usize,
    /// Per-hop delay mean (ms) for drop cover packets.
    pub drop_cover_delay_ms: u64,
}

/// Handle to a spawned mix node: a stream of *real* payloads delivered to this node, an injector to
/// send from this node, and counters for observed cover traffic (loop packets that returned to us,
/// drop packets we received and discarded) — cover never appears on the `delivered` stream.
pub struct MixHandle {
    pub delivered: mpsc::UnboundedReceiver<Vec<u8>>,
    pub inject: mpsc::UnboundedSender<Injection>,
    pub cover_returned: Arc<AtomicU64>,
    pub cover_dropped: Arc<AtomicU64>,
}

/// Spawn a mix node: bind a listener, dial the larger-id directory peers (one Noise channel per
/// pair), and run the peel→delay→forward / deliver loop. Returns a handle once listening.
pub async fn spawn(identity: Arc<NodeIdentity>, config: MixConfig) -> std::io::Result<MixHandle> {
    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
    let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<(Option<[u8; 32]>, Message)>();
    let (delivered_tx, delivered_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<Injection>();
    let my_id = identity.peer_id();
    let mix_sk = identity.mix_sk();
    let directory = Arc::new(config.directory);
    let cover_returned = Arc::new(AtomicU64::new(0));
    let cover_dropped = Arc::new(AtomicU64::new(0));

    let listener = TcpListener::bind(&config.listen_addr).await?;
    // Accept loop (Noise responder).
    {
        let (peers, inbox, identity, addr) =
            (peers.clone(), inbox_tx.clone(), identity.clone(), config.listen_addr.clone());
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(run_conn(stream, identity.clone(), addr.clone(), false, inbox.clone(), peers.clone()));
                }
            }
        });
    }
    // Dial task: the smaller-id side dials, so each pair forms exactly one connection.
    {
        let (peers, inbox, identity, addr, dir) =
            (peers.clone(), inbox_tx.clone(), identity.clone(), config.listen_addr.clone(), directory.clone());
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(150));
            loop {
                ticker.tick().await;
                let targets: Vec<(_, _)> = dir
                    .ids()
                    .into_iter()
                    .filter(|p| *p > my_id)
                    .filter(|p| !peers.lock().unwrap().contains_key(p))
                    .filter_map(|p| dir.addr(&p).map(|a| (p, a)))
                    .collect();
                for (_pid, a) in targets {
                    if let Ok(stream) = TcpStream::connect(&a).await {
                        let (peers, inbox, identity, addr) =
                            (peers.clone(), inbox.clone(), identity.clone(), addr.clone());
                        tokio::spawn(run_conn(stream, identity, addr, true, inbox, peers));
                    }
                }
            }
        });
    }

    // Inbound packet processor: peel each Sphinx packet, then forward (after its delay) or
    // reassemble-and-deliver. The reassembler is owned by this single task (no lock needed).
    {
        let (peers, mix_sk) = (peers.clone(), mix_sk);
        let (cover_returned, cover_dropped) = (cover_returned.clone(), cover_dropped.clone());
        tokio::spawn(async move {
            let mut reasm = Reassembler::new(256);
            while let Some((_from, msg)) = inbox_rx.recv().await {
                if let Message::Sphinx(pkt) = msg {
                    match sphinx::process(&mix_sk, &pkt) {
                        Ok(Processed::Deliver { data }) => {
                            if let Some(full) = reasm.accept(&data) {
                                // Cover never reaches the app: a returned loop / a discarded drop is
                                // only counted; real payloads flow on.
                                match classify(&full) {
                                    Delivery::Real => {
                                        let _ = delivered_tx.send(full);
                                    }
                                    Delivery::Loop => {
                                        cover_returned.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Delivery::Drop => {
                                        cover_dropped.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        Ok(Processed::Forward { next, delay_ms, packet }) => {
                            let peers = peers.clone();
                            tokio::spawn(async move {
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                send_to(&peers, &next, Message::Sphinx(packet));
                            });
                        }
                        Err(e) => debug!(?e, "dropping un-processable mix packet"),
                    }
                }
            }
        });
    }

    // Injector: fragment each outbound request and route every fragment as its own chain-selected
    // Sphinx packet, so a payload larger than one fixed packet still routes through the mixnet.
    {
        let (peers, dir) = (peers.clone(), directory.clone());
        tokio::spawn(async move {
            let mut msg_seq = 0u64;
            while let Some(inj) = inject_rx.recv().await {
                let mut msg_id = [0u8; 16];
                msg_id[..8].copy_from_slice(&my_id[..8]);
                msg_id[8..].copy_from_slice(&msg_seq.to_le_bytes());
                msg_seq = msg_seq.wrapping_add(1);
                for (first, pkt) in route_message(&dir, &my_id, &inj, msg_id) {
                    send_to(&peers, &first, Message::Sphinx(pkt));
                }
            }
        });
    }

    // Loop cover: packets routed back to self on an exponential timer, indistinguishable on the wire
    // from real sends — an observer cannot tell when this node genuinely transmits.
    if config.cover_mean_ms > 0 {
        let inject = inject_tx.clone();
        let (mean, hops, delay) = (config.cover_mean_ms, config.cover_hops, config.cover_delay_ms);
        tokio::spawn(async move {
            let mut nonce = 0u64;
            loop {
                // Exponential inter-cover wait (deterministic per nonce so tests are reproducible).
                let wait = sample_delays(1, mean, 0, nonce).first().copied().unwrap_or(mean).max(1);
                tokio::time::sleep(Duration::from_millis(wait)).await;
                nonce = nonce.wrapping_add(1);
                let inj = Injection {
                    payload: LOOP_MARKER.to_vec(),
                    dest: my_id, // a loop back to self
                    hops,
                    beacon: 0,
                    nonce: nonce.wrapping_add(0xC0FFEE),
                    mean_delay_ms: delay,
                };
                if inject.send(inj).is_err() {
                    break;
                }
            }
        });
    }

    // Drop cover: packets routed to a random *other* mix (which discards them) on an exponential
    // timer — pure padding that thickens the anonymity set without ever reaching an application.
    if config.drop_cover_mean_ms > 0 && directory.len() > 1 {
        let inject = inject_tx.clone();
        let dir = directory.clone();
        let (mean, hops, delay) =
            (config.drop_cover_mean_ms, config.drop_cover_hops, config.drop_cover_delay_ms);
        tokio::spawn(async move {
            let others: Vec<[u8; 32]> = dir.ids().into_iter().filter(|p| *p != my_id).collect();
            let mut nonce = 0u64;
            loop {
                let wait = sample_delays(1, mean, 1, nonce).first().copied().unwrap_or(mean).max(1);
                tokio::time::sleep(Duration::from_millis(wait)).await;
                nonce = nonce.wrapping_add(1);
                // Pick a random other mix as the (discarding) destination, from the cover nonce.
                let pick = others[(nonce as usize).wrapping_mul(2654435761) % others.len()];
                let inj = Injection {
                    payload: DROP_MARKER.to_vec(),
                    dest: pick,
                    hops,
                    beacon: 0,
                    nonce: nonce.wrapping_add(0xD0_0D),
                    mean_delay_ms: delay,
                };
                if inject.send(inj).is_err() {
                    break;
                }
            }
        });
    }

    Ok(MixHandle { delivered: delivered_rx, inject: inject_tx, cover_returned, cover_dropped })
}

/// Fragment an injection's payload and build one chain-routed Sphinx packet per fragment, returning
/// each with its first-hop id. Each fragment takes its own path (nonce varied by index).
fn route_message(
    dir: &MixDirectory,
    source: &[u8; 32],
    inj: &Injection,
    msg_id: [u8; 16],
) -> Vec<([u8; 32], SphinxPacket)> {
    let frags = fragment(msg_id, &inj.payload);
    let mut out = Vec::with_capacity(frags.len());
    for (i, frag) in frags.iter().enumerate() {
        let nonce = inj.nonce.wrapping_add(i as u64);
        let path = match select_full_path(dir, source, &inj.dest, inj.hops, inj.beacon, nonce) {
            Some(p) => p,
            None => continue,
        };
        let delays = sample_delays(path.len(), inj.mean_delay_ms, inj.beacon, nonce ^ 0x5d);
        if let (Ok(pkt), Some(first)) = (sphinx::create(&path, &delays, frag), path.first()) {
            out.push((first.id, pkt));
        }
    }
    out
}

fn send_to(peers: &Peers, peer: &[u8; 32], msg: Message) {
    if let Some(tx) = peers.lock().unwrap().get(peer) {
        let _ = tx.send(msg);
    }
}

/// Drive one peer connection: Noise XX handshake, a minimal `Hello` to learn the remote's id, then a
/// read loop forwarding decrypted frames to the inbox. (The genesis directory is trusted, so this
/// uses a plain id `Hello`; a production deployment layers the authenticated channel-binding `Hello`
/// of `node.rs`.)
async fn run_conn(
    stream: TcpStream,
    identity: Arc<NodeIdentity>,
    listen_addr: String,
    initiator: bool,
    inbox: mpsc::UnboundedSender<(Option<[u8; 32]>, Message)>,
    peers: Peers,
) {
    let _ = stream.set_nodelay(true);
    let mut stream = stream;
    let (chan, _hs) = match noise_handshake(&mut stream, initiator).await {
        Ok(x) => x,
        Err(_) => return,
    };
    let chan = Arc::new(chan);
    let (mut rd, mut wr) = stream.into_split();
    let mut send_nonce = 0u64;
    let mut recv_nonce = 0u64;

    let hello = Message::Hello { peer_id: identity.peer_id(), listen_addr, binding: Vec::new() };
    if write_frame(&mut wr, &chan, &mut send_nonce, &hello).await.is_err() {
        return;
    }
    let remote = match read_frame(&mut rd, &chan, &mut recv_nonce).await {
        Ok(Message::Hello { peer_id, .. }) => peer_id,
        _ => return,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    {
        let mut p = peers.lock().unwrap();
        if p.contains_key(&remote) {
            return; // dedup: one channel per pair
        }
        p.insert(remote, tx);
    }
    let chan_w = chan.clone();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if write_frame(&mut wr, &chan_w, &mut send_nonce, &m).await.is_err() {
                break;
            }
        }
    });
    loop {
        match read_frame(&mut rd, &chan, &mut recv_nonce).await {
            Ok(m) => {
                if inbox.send((Some(remote), m)).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    peers.lock().unwrap().remove(&remote);
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    fn dir_of(n: usize) -> (MixDirectory, Vec<[u8; 32]>) {
        let mut entries = Vec::new();
        let mut ids = Vec::new();
        for i in 0..n {
            let id = NodeIdentity::from_seed(100 + i as u64);
            ids.push(id.peer_id());
            entries.push(MixEntry {
                peer_id: id.peer_id(),
                addr: format!("127.0.0.1:{}", 9000 + i),
                mix_pk: id.mix_pk(),
            });
        }
        (MixDirectory::new(entries), ids)
    }

    #[test]
    fn path_is_deterministic_in_the_beacon_and_excludes_the_source() {
        let (dir, ids) = dir_of(6);
        let (src, dst) = (ids[0], ids[5]);
        let p1 = select_full_path(&dir, &src, &dst, 3, 777, 0).unwrap();
        let p2 = select_full_path(&dir, &src, &dst, 3, 777, 0).unwrap();
        let ids1: Vec<_> = p1.iter().map(|h| h.id).collect();
        let ids2: Vec<_> = p2.iter().map(|h| h.id).collect();
        assert_eq!(ids1, ids2, "same beacon+nonce must give the same path");
        assert_eq!(p1.len(), 3);
        assert_eq!(p1.last().unwrap().id, dst, "the last hop is the destination");
        assert!(!ids1[..2].contains(&src), "the source is never an intermediate hop");
        assert!(!ids1[..2].contains(&dst), "the destination is not also an intermediate hop");
    }

    #[test]
    fn different_beacons_generally_pick_different_paths() {
        // A wide directory so the 4-hop path space is large and a collision is negligible.
        let (dir, ids) = dir_of(12);
        let (src, dst) = (ids[0], ids[11]);
        let a: Vec<_> = select_full_path(&dir, &src, &dst, 4, 1, 0).unwrap().iter().map(|h| h.id).collect();
        let b: Vec<_> = select_full_path(&dir, &src, &dst, 4, 2, 0).unwrap().iter().map(|h| h.id).collect();
        assert_ne!(a, b, "distinct beacons should route distinctly (with high probability)");
    }

    #[test]
    fn a_loop_path_ends_back_at_the_source() {
        let (dir, ids) = dir_of(6);
        let me = ids[2];
        let p = select_full_path(&dir, &me, &me, 3, 55, 9).unwrap();
        assert_eq!(p.last().unwrap().id, me, "a loop returns to its origin");
        assert!(!p[..2].iter().any(|h| h.id == me), "origin is not a relay in its own loop");
    }

    #[test]
    fn too_few_mixes_yields_no_path() {
        let (dir, ids) = dir_of(2);
        // 4 hops needs 3 distinct intermediates, but only 2 mixes exist beyond source/dest.
        assert!(select_full_path(&dir, &ids[0], &ids[1], 4, 1, 0).is_none());
    }

    #[test]
    fn a_large_message_fragments_and_reassembles_even_out_of_order() {
        // A payload several packets long splits, then reassembles from shuffled fragments.
        let payload: Vec<u8> = (0..(FRAG_CHUNK * 3 + 17) as u32).map(|i| (i % 251) as u8).collect();
        let frags = fragment([7u8; 16], &payload);
        assert_eq!(frags.len(), 4, "3 full chunks + a remainder = 4 fragments");
        assert!(frags.iter().all(|f| f.len() <= sphinx::MAX_BODY), "each fragment fits a packet");

        let mut r = Reassembler::new(16);
        // Feed out of order (reversed); only the last one completes the message.
        let mut done = None;
        for f in frags.iter().rev() {
            if let Some(msg) = r.accept(f) {
                done = Some(msg);
            }
        }
        assert_eq!(done.as_deref(), Some(payload.as_slice()), "reassembled bytes match the original");
    }

    #[test]
    fn cover_markers_classify_distinctly_from_real_traffic() {
        assert!(matches!(classify(LOOP_MARKER), Delivery::Loop));
        assert!(matches!(classify(DROP_MARKER), Delivery::Drop));
        assert!(matches!(classify(b"a real application payload"), Delivery::Real));
        // A real payload that merely starts with a NUL but not a marker is still real.
        assert!(matches!(classify(b"\x00ordinary"), Delivery::Real));
    }

    #[test]
    fn a_single_fragment_message_reassembles_immediately() {
        let frags = fragment([1u8; 16], b"small");
        assert_eq!(frags.len(), 1);
        let mut r = Reassembler::new(16);
        assert_eq!(r.accept(&frags[0]).as_deref(), Some(&b"small"[..]));
    }

    #[test]
    fn two_interleaved_messages_reassemble_independently() {
        let a = fragment([0xAA; 16], &vec![1u8; FRAG_CHUNK + 5]); // 2 fragments
        let b = fragment([0xBB; 16], &vec![2u8; FRAG_CHUNK + 5]); // 2 fragments
        let mut r = Reassembler::new(16);
        assert!(r.accept(&a[0]).is_none());
        assert!(r.accept(&b[1]).is_none());
        assert!(r.accept(&a[1]).is_some(), "a completes when its second fragment lands");
        assert!(r.accept(&b[0]).is_some(), "b completes independently");
    }

    #[test]
    fn delays_are_deterministic_and_average_near_the_mean() {
        let mean = 100u64;
        let d1 = sample_delays(2000, mean, 42, 0);
        let d2 = sample_delays(2000, mean, 42, 0);
        assert_eq!(d1, d2, "delays are reproducible from the beacon");
        let avg = d1.iter().sum::<u64>() as f64 / d1.len() as f64;
        assert!((avg - mean as f64).abs() < 20.0, "exponential mean ~{mean}, got {avg}");
    }
}
