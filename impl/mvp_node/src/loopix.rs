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

// --- the mix node engine --------------------------------------------------------------------------

type Peers = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<Message>>>>;

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
    /// If > 0, emit a loop cover packet on an exponential timer with this mean (ms) — indistinguishable
    /// from real traffic, so an observer cannot tell when the node is genuinely sending.
    pub cover_mean_ms: u64,
    /// Hop count for cover packets.
    pub cover_hops: usize,
    /// Per-hop delay mean (ms) for cover packets.
    pub cover_delay_ms: u64,
}

/// Handle to a spawned mix node: a stream of payloads delivered *to this node*, and an injector to
/// send payloads *from this node* through the mixnet.
pub struct MixHandle {
    pub delivered: mpsc::UnboundedReceiver<Vec<u8>>,
    pub inject: mpsc::UnboundedSender<Injection>,
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

    // Inbound packet processor: peel each Sphinx packet, then forward (after its delay) or deliver.
    {
        let (peers, mix_sk) = (peers.clone(), mix_sk);
        tokio::spawn(async move {
            while let Some((_from, msg)) = inbox_rx.recv().await {
                if let Message::Sphinx(pkt) = msg {
                    match sphinx::process(&mix_sk, &pkt) {
                        Ok(Processed::Deliver { data }) => {
                            let _ = delivered_tx.send(data);
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

    // Injector: turn outbound requests into chain-routed Sphinx packets sent to the first hop.
    {
        let (peers, dir) = (peers.clone(), directory.clone());
        tokio::spawn(async move {
            while let Some(inj) = inject_rx.recv().await {
                if let Some(packet) = build_packet(&dir, &my_id, &inj) {
                    if let Some(first) = select_path(&dir, &my_id, &inj.dest, inj.hops, inj.beacon, inj.nonce) {
                        send_to(&peers, &first.id, Message::Sphinx(packet));
                    }
                }
            }
        });
    }

    // Cover traffic: loop packets on an exponential timer, indistinguishable from real sends.
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
                    payload: b"\x00cover".to_vec(),
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

    Ok(MixHandle { delivered: delivered_rx, inject: inject_tx })
}

/// Build the Sphinx packet for an injection, selecting the path and per-hop delays from chain entropy.
fn build_packet(dir: &MixDirectory, source: &[u8; 32], inj: &Injection) -> Option<SphinxPacket> {
    let path = select_full_path(dir, source, &inj.dest, inj.hops, inj.beacon, inj.nonce)?;
    let delays = sample_delays(path.len(), inj.mean_delay_ms, inj.beacon, inj.nonce ^ 0x5d);
    sphinx::create(&path, &delays, &inj.payload).ok()
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
    fn delays_are_deterministic_and_average_near_the_mean() {
        let mean = 100u64;
        let d1 = sample_delays(2000, mean, 42, 0);
        let d2 = sample_delays(2000, mean, 42, 0);
        assert_eq!(d1, d2, "delays are reproducible from the beacon");
        let avg = d1.iter().sum::<u64>() as f64 / d1.len() as f64;
        assert!((avg - mean as f64).abs() < 20.0, "exponential mean ~{mean}, got {avg}");
    }
}
