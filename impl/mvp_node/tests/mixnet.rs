//! End-to-end Loopix mixnet integration tests. Spin up real mix nodes over Noise-encrypted TCP and
//! exercise the headline properties: a message routed along a **chain-beacon-selected** multi-hop
//! path arrives intact at its destination and *only* there, and **loop cover traffic** returns to
//! its sender. (The Sphinx crypto itself — fixed size, per-hop bitwise unlinkability, MAC integrity —
//! is unit-tested in `src/sphinx.rs`; the path/delay entropy in `src/loopix.rs`.)

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mvp_node::identity::NodeIdentity;
use mvp_node::loopix::{self, Injection, MixConfig, MixDirectory, MixEntry};

/// Build `n` mix identities + a genesis directory over `127.0.0.1:(base+i)`.
fn network(n: usize, base: u16) -> (Vec<Arc<NodeIdentity>>, MixDirectory) {
    let ids: Vec<Arc<NodeIdentity>> =
        (0..n).map(|i| Arc::new(NodeIdentity::from_seed(500 + i as u64))).collect();
    let entries = ids
        .iter()
        .enumerate()
        .map(|(i, id)| MixEntry {
            peer_id: id.peer_id(),
            addr: format!("127.0.0.1:{}", base + i as u16),
            mix_pk: id.mix_pk(),
        })
        .collect();
    (ids, MixDirectory::new(entries))
}

fn config(dir: &MixDirectory, addr: String) -> MixConfig {
    MixConfig {
        listen_addr: addr,
        directory: dir.clone(),
        cover_mean_ms: 0,
        cover_hops: 3,
        cover_delay_ms: 0,
        drop_cover_mean_ms: 0,
        drop_cover_hops: 3,
        drop_cover_delay_ms: 0,
    }
}

/// Poll `f` every 50ms until it is true or `tries` elapse.
async fn eventually(tries: u32, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..tries {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_routes_through_a_chain_selected_path_to_its_destination() {
    let base = 19100u16;
    let (ids, dir) = network(5, base);

    // Spawn all five mixes; keep each delivery receiver.
    let mut handles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let cfg = config(&dir, format!("127.0.0.1:{}", base + i as u16));
        handles.push(loopix::spawn(id.clone(), cfg).await.expect("spawn mix"));
    }
    // Let the full Noise mesh form.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Node 0 sends to node 4 over a beacon-selected 3-hop path with ~30ms/hop Poisson delay.
    let (src, dst) = (0usize, 4usize);
    let beacon = 0xBEAC_0017u64;
    let payload = b"the quick brown fox".to_vec();
    handles[src]
        .inject
        .send(Injection {
            payload: payload.clone(),
            dest: ids[dst].peer_id(),
            hops: 3,
            beacon,
            nonce: 1,
            mean_delay_ms: 30,
        })
        .expect("inject");

    // The destination receives exactly the payload, within a generous window (3 hops × Poisson 30ms).
    let got = tokio::time::timeout(Duration::from_secs(3), handles[dst].delivered.recv())
        .await
        .expect("destination must deliver within the timeout")
        .expect("delivered channel open");
    assert_eq!(got, payload, "destination recovers the exact plaintext");

    // No other node delivered it (relays only forward ciphertext; they never see the plaintext).
    for (i, h) in handles.iter_mut().enumerate() {
        if i != dst {
            assert!(h.delivered.try_recv().is_err(), "node {i} must not deliver a relayed packet");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_message_fragments_across_packets_and_reassembles_at_the_destination() {
    let base = 19300u16;
    let (ids, dir) = network(5, base);

    let mut handles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let cfg = config(&dir, format!("127.0.0.1:{}", base + i as u16));
        handles.push(loopix::spawn(id.clone(), cfg).await.expect("spawn mix"));
    }
    tokio::time::sleep(Duration::from_millis(700)).await;

    // A ~6 KB payload — far larger than one fixed Sphinx packet — must split into many fragments,
    // each routed independently, and reassemble byte-exact at the destination.
    let (src, dst) = (0usize, 4usize);
    let payload: Vec<u8> = (0..6000u32).map(|i| (i * 31 + 7) as u8).collect();
    handles[src]
        .inject
        .send(Injection {
            payload: payload.clone(),
            dest: ids[dst].peer_id(),
            hops: 3,
            beacon: 0x5152_5354,
            nonce: 11,
            mean_delay_ms: 10,
        })
        .expect("inject");

    let got = tokio::time::timeout(Duration::from_secs(4), handles[dst].delivered.recv())
        .await
        .expect("destination must reassemble within the timeout")
        .expect("delivered channel open");
    assert_eq!(got, payload, "the multi-fragment message reassembles byte-exact");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_surb_carries_an_anonymous_reply_back_to_its_creator() {
    let base = 19600u16;
    let (ids, dir) = network(5, base);

    let mut handles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let cfg = config(&dir, format!("127.0.0.1:{}", base + i as u16));
        handles.push(loopix::spawn(id.clone(), cfg).await.expect("spawn mix"));
    }
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Node 0 (A) mints a SURB whose return path leads back to itself, and hands it to node 4 (B).
    // (Delivering the SURB to B is an ordinary forward message, already covered; here we pass it
    // directly to focus on the anonymous return journey.)
    let surb = handles[0].mint_surb(3, 10, 0xA11CE).expect("mint a SURB");

    // B replies through the SURB without ever learning A's identity.
    handles[4].reply.send((surb, b"anonymous reply to A".to_vec())).expect("send reply");

    // A recovers the reply on its anonymous-replies stream.
    let got = tokio::time::timeout(Duration::from_secs(3), handles[0].replies.recv())
        .await
        .expect("the SURB reply must return to its creator")
        .expect("replies channel open");
    assert_eq!(got, b"anonymous reply to A", "A recovers B's reply via the SURB");

    // The reply never appears as ordinary application delivery on any node.
    for (i, h) in handles.iter_mut().enumerate() {
        assert!(h.delivered.try_recv().is_err(), "node {i} must not see a SURB reply as a delivery");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loop_cover_traffic_returns_to_its_sender() {
    let base = 19200u16;
    let (ids, dir) = network(5, base);

    // Node 0 emits loop cover traffic (~40ms mean); every other node is a plain relay.
    let mut handles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let mut cfg = config(&dir, format!("127.0.0.1:{}", base + i as u16));
        if i == 0 {
            cfg.cover_mean_ms = 40;
            cfg.cover_hops = 3;
            cfg.cover_delay_ms = 5;
        }
        handles.push(loopix::spawn(id.clone(), cfg).await.expect("spawn mix"));
    }
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Loop cover packets route through the mixnet and come back to node 0, which counts the return
    // (cover never surfaces as application traffic).
    let returned = eventually(50, || handles[0].cover_returned.load(Ordering::Relaxed) > 0).await;
    assert!(returned, "a loop cover packet must return to its sender and be counted");

    // No node ever saw cover as an application delivery.
    for (i, h) in handles.iter_mut().enumerate() {
        assert!(h.delivered.try_recv().is_err(), "node {i} must not deliver cover traffic to the app");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_cover_traffic_is_received_and_silently_discarded() {
    let base = 19500u16;
    let (ids, dir) = network(5, base);

    // Node 0 emits drop cover (~40ms mean) addressed to random other mixes; they discard it.
    let mut handles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let mut cfg = config(&dir, format!("127.0.0.1:{}", base + i as u16));
        if i == 0 {
            cfg.drop_cover_mean_ms = 40;
            cfg.drop_cover_hops = 3;
            cfg.drop_cover_delay_ms = 5;
        }
        handles.push(loopix::spawn(id.clone(), cfg).await.expect("spawn mix"));
    }
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Some other node receives and discards drop cover (counted, never surfaced).
    let dropped = eventually(50, || {
        handles.iter().skip(1).map(|h| h.cover_dropped.load(Ordering::Relaxed)).sum::<u64>() > 0
    })
    .await;
    assert!(dropped, "drop cover must reach some other mix and be discarded");

    // Real traffic still flows undisturbed: node 0 sends to node 4, which delivers it.
    handles[0]
        .inject
        .send(Injection {
            payload: b"real-amid-cover".to_vec(),
            dest: ids[4].peer_id(),
            hops: 3,
            beacon: 7,
            nonce: 3,
            mean_delay_ms: 10,
        })
        .expect("inject");
    let got = tokio::time::timeout(Duration::from_secs(3), handles[4].delivered.recv())
        .await
        .expect("real message delivers despite cover")
        .expect("channel open");
    assert_eq!(got, b"real-amid-cover", "drop cover never contaminates real delivery");
}
