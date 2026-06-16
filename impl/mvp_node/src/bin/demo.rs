//! Multi-node local demo: spawn N nodes (in-process tokio tasks over real loopback TCP) that join
//! the network and cycle K staggered epochs, then print a convergence summary.
//!
//! Run: `cargo +nightly run --release --bin demo -- --nodes 4 --epochs 5`

use clap::Parser;
use tracing_subscriber::EnvFilter;

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let args = Args::parse();
    let validators = genesis_validator_set(args.nodes, args.base_port);

    println!(
        "Spawning {} nodes over loopback TCP, {} epochs, {}ms window...\n",
        args.nodes, args.epochs, args.window_ms
    );

    let mut handles = Vec::new();
    for i in 0..args.nodes {
        let cfg = NodeConfig {
            listen_addr: format!("127.0.0.1:{}", args.base_port + i as u16),
            genesis_validators: validators.clone(),
            window_ms: args.window_ms,
            max_height: args.epochs,
            grace_ms: args.window_ms * 8,
        };
        let id = NodeIdentity::from_seed(i);
        handles.push(tokio::spawn(Node::new(id, cfg).run()));
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
            "  node {}  blocks={}  head={}  split_ok={}  epoch_ids={:?}",
            hex::encode(&o.peer_id[..4]),
            o.blocks_len,
            hex::encode(&o.head_hash[..4]),
            o.split_ok,
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
