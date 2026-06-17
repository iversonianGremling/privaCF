//! End-to-end Loopix mixnet integration tests. Spin up real mix nodes over Noise-encrypted TCP and
//! exercise the headline properties: a message routed along a **chain-beacon-selected** multi-hop
//! path arrives intact at its destination and *only* there, and **loop cover traffic** returns to
//! its sender. (The Sphinx crypto itself — fixed size, per-hop bitwise unlinkability, MAC integrity —
//! is unit-tested in `src/sphinx.rs`; the path/delay entropy in `src/loopix.rs`.)

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
    }
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

    // A loop cover packet routes through the mixnet and comes back to node 0 as a delivery.
    let got = tokio::time::timeout(Duration::from_secs(3), handles[0].delivered.recv())
        .await
        .expect("a loop cover packet must return to its sender")
        .expect("delivered channel open");
    assert_eq!(got, b"\x00cover", "the returned loop carries the cover marker");

    // No relay node delivered the cover packet (it is addressed back to node 0).
    for (i, h) in handles.iter_mut().enumerate().skip(1) {
        assert!(h.delivered.try_recv().is_err(), "relay {i} must not deliver a loop cover packet");
    }
}
