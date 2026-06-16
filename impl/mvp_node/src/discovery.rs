//! Peer-discovery seam. Stub: connect to a static seed/validator set from config and learn peers'
//! `epoch_id`s by reading their registrations off the chain.
//!
//! Real future impl: `PsiDiscovery` — gossip-referral + private-set-intersection peer matching
//! (SPEC §5.3/§5.4), where peers are selected by similarity ≥ θ_cluster without revealing item sets.

pub trait Discovery: Send + Sync {
    /// The (peer_id, listen_addr) pairs to connect to at startup.
    fn seed_peers(&self) -> Vec<([u8; 32], String)>;
}

pub struct ConnectKnown {
    pub peers: Vec<([u8; 32], String)>,
}

impl Discovery for ConnectKnown {
    fn seed_peers(&self) -> Vec<([u8; 32], String)> {
        self.peers.clone()
    }
}
