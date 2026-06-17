//! PrivaCF substrate thin-skeleton MVP.
//!
//! N nodes join a network, each generates an identity, and they cycle through staggered epochs
//! publishing per-epoch commitments to a shared minimal chain. Research-grade components
//! (Loopix transport, BFT consensus, VDF admission, verifiable encryption, PSI discovery) are
//! stubbed behind named trait seams — see the per-module docs.

pub mod admission;
pub mod beacon;
pub mod bls;
pub mod chain;
pub mod commit;
pub mod consensus;
pub mod discovery;
pub mod epoch;
pub mod field;
pub mod hash;
pub mod identity;
pub mod loopix;
pub mod membership;
pub mod message;
pub mod node;
pub mod sphinx;
pub mod transport;
pub mod vrf;

#[cfg(test)]
mod tests {
    use super::field::*;
    use super::identity::NodeIdentity;
    use rand::SeedableRng;

    #[test]
    fn null_v_and_epoch_id_derive_and_split_holds() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let id = NodeIdentity::generate(&mut rng);

        let b1 = from_u64(1001);
        let b2 = from_u64(1002);
        let e1 = id.epoch_id(b1);
        let e1_again = id.epoch_id(b1);
        let e2 = id.epoch_id(b2);
        assert_eq!(e1, e1_again, "epoch_id must be deterministic in (sk, beacon)");
        assert_ne!(e1, e2, "epoch_id must rotate with the beacon");

        let s2 = random_field(&mut rng);
        let s1 = sub_mod(id.null_v, s2);
        assert_eq!(add_mod(s1, s2), id.null_v, "s1 + s2 must reconstruct null_v");
    }

    #[test]
    fn distinct_nodes_have_distinct_identities() {
        let a = NodeIdentity::from_seed(1);
        let b = NodeIdentity::from_seed(2);
        assert_ne!(a.null_v, b.null_v);
        assert_ne!(a.peer_id(), b.peer_id());
        let beacon = from_u64(999);
        assert_ne!(a.epoch_id(beacon), b.epoch_id(beacon));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let a = NodeIdentity::from_seed(5);
        let b = NodeIdentity::from_seed(5);
        assert_eq!(a.peer_id(), b.peer_id());
        assert_eq!(a.null_v, b.null_v);
    }
}
