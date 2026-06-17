//! Multi-node local demo: spawn N nodes (in-process tokio tasks over real loopback TCP) that join
//! the network and cycle K staggered epochs, then print a convergence summary.
//!
//! Run: `cargo +nightly run --release --bin demo -- --nodes 4 --epochs 5`

use clap::Parser;
use tracing_subscriber::EnvFilter;

use mvp_node::identity::NodeIdentity;
use mvp_node::loopix::{MixDirectory, MixEntry};
use mvp_node::node::{genesis_validator_set, MixSettings, Node, NodeConfig};

#[derive(Parser)]
#[command(about = "PrivaCF thin-skeleton node-network demo")]
struct Args {
    #[arg(long, default_value_t = 4)]
    nodes: u64,
    #[arg(long, default_value_t = 5)]
    epochs: u64,
    #[arg(long, default_value_t = 9100)]
    base_port: u16,
    #[arg(long, default_value_t = 300)]
    window_ms: u64,
    /// Route consensus control messages (VRF claims, votes, txs) through the Loopix mixnet rather
    /// than broadcasting them in the clear — exercises the unlinkability layer under live consensus.
    #[arg(long, default_value_t = false)]
    mix: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let args = Args::parse();
    let validators = genesis_validator_set(args.nodes, args.base_port);

    // When --mix is set, build the genesis mix directory (each validator is also a mix) so consensus
    // control messages route through the mixnet. A grace bump absorbs the per-hop mixing latency.
    let mix = args.mix.then(|| {
        let directory = MixDirectory::new(
            (0..args.nodes)
                .map(|i| {
                    let id = NodeIdentity::from_seed(i);
                    MixEntry {
                        peer_id: id.peer_id(),
                        addr: format!("127.0.0.1:{}", args.base_port + i as u16),
                        mix_pk: id.mix_pk(),
                    }
                })
                .collect(),
        );
        MixSettings { directory, hops: if args.nodes >= 4 { 3 } else { 2 }, mean_delay_ms: 8 }
    });

    println!(
        "Spawning {} nodes over loopback TCP, {} epochs, {}ms window{}...\n",
        args.nodes,
        args.epochs,
        args.window_ms,
        if args.mix { " (consensus routed through the Loopix mixnet)" } else { "" }
    );

    let mut handles = Vec::new();
    for i in 0..args.nodes {
        let grace_mult = if args.mix { 14 } else { 8 };
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", args.base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms: args.window_ms,
            max_height: args.epochs,
            grace_ms: args.window_ms * grace_mult,
        };
        let id = NodeIdentity::from_seed(i);
        let node = Node::new(id, cfg);
        let node = match &mix {
            Some(s) => node.with_mixnet(s.clone()),
            None => node,
        };
        handles.push(tokio::spawn(node.run()));
    }

    let mut outcomes = Vec::new();
    for h in handles {
        outcomes.push(h.await.expect("node task panicked"));
    }

    let head0 = outcomes[0].head_hash;
    let len0 = outcomes[0].blocks_len;
    let converged = outcomes.iter().all(|o| o.head_hash == head0 && o.blocks_len == len0);

    println!("\n=== DEMO SUMMARY ===");
    for o in &outcomes {
        println!(
            "  node {}  blocks={}  head={}  split_ok={}  qc_valid={}  epoch_ids={:?}",
            hex::encode(&o.peer_id[..4]),
            o.blocks_len,
            hex::encode(&o.head_hash[..4]),
            o.split_ok,
            o.all_qc_valid,
            o.epoch_ids.iter().map(|(_, e)| e % 100000).collect::<Vec<_>>(),
        );
    }
    println!(
        "\n  CONVERGED: {}  ({} nodes share head {} at height {})",
        converged,
        outcomes.len(),
        hex::encode(&head0[..4]),
        len0 as u64 - 1,
    );
    std::process::exit(if converged { 0 } else { 1 });
}
