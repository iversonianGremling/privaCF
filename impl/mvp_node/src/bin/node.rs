//! A single node, joining a seed-derived network. Lets you run a real multi-terminal network:
//!   terminal 0:  cargo +nightly run --release --bin node -- --index 0 --nodes 3
//!   terminal 1:  cargo +nightly run --release --bin node -- --index 1 --nodes 3
//!   terminal 2:  cargo +nightly run --release --bin node -- --index 2 --nodes 3
//! All nodes derive the same genesis validator set from `--nodes`/`--base-port`, so they agree on
//! the round-robin schedule without a config file.

use clap::Parser;
use tracing_subscriber::EnvFilter;

use mvp_node::identity::NodeIdentity;
use mvp_node::node::{genesis_validator_set, Node, NodeConfig};

#[derive(Parser)]
#[command(about = "PrivaCF thin-skeleton substrate node")]
struct Args {
    /// This node's index (0..nodes); selects its seed identity and listen port.
    #[arg(long)]
    index: u64,
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
    assert!(args.index < args.nodes, "--index must be < --nodes");

    let validators = genesis_validator_set(args.nodes, args.base_port);
    let cfg = NodeConfig {
        listen_addr: format!("127.0.0.1:{}", args.base_port + args.index as u16),
        genesis_validators: validators,
        window_ms: args.window_ms,
        max_height: args.epochs,
        grace_ms: args.window_ms * 8,
    };
    let id = NodeIdentity::from_seed(args.index);
    let outcome = Node::new(id, cfg).run().await;

    println!(
        "node {} done: blocks={} head={} split_ok={}",
        args.index,
        outcome.blocks_len,
        hex::encode(&outcome.head_hash[..4]),
        outcome.split_ok
    );
}
