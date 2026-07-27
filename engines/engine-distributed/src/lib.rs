//! engine-distributed — distributed cracking across network nodes
//!
//! Master-worker architecture over ZeroMQ/TCP:
//! - Master: keyspace partitioning, work distribution, result collection
//! - Worker: batch processing with local CPU/GPU/FPGA, result reporting
//! - Tier-aware dispatching
//! - Checkpoint/resume per node

pub mod master;
pub mod worker;
pub mod protocol;
pub mod discovery;

use std::net::SocketAddr;

pub struct DistributedConfig {
    pub listen_addr: SocketAddr,
    pub master_addr: Option<SocketAddr>,
    pub node_name: String,
    pub heartbeat_secs: u64,
    pub checkpoint_interval: u64,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        DistributedConfig {
            listen_addr: "0.0.0.0:5555".parse().unwrap(),
            master_addr: None,
            node_name: hostname(),
            heartbeat_secs: 5,
            checkpoint_interval: 60,
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}
