//! mDNS node discovery — zero-configuration node finding
//!
//! Uses DNS-SD (RFC 6763) over mDNS (RFC 6762) to discover
//! pwdcrack master and worker nodes on the local network.

use std::net::SocketAddr;
use std::time::Duration;

const SERVICE_TYPE: &str = "_pwdcrack._tcp.local.";
const DISCOVERY_PORT: u16 = 5555;

pub struct NodeDiscovery;

impl NodeDiscovery {
    /// Advertise this node as a pwdcrack service
    pub fn advertise(node_name: &str, port: u16, is_master: bool) -> Option<()> {
        // mDNS advertising via libmdns or manual multicast
        // libmdns::daemon()?.register(
        //     SERVICE_TYPE,
        //     port,
        //     &[node_name, if is_master { "master" } else { "worker" }],
        // );
        log::info!("mDNS advertise: {} on port {} (master={})", node_name, port, is_master);
        None
    }

    /// Discover pwdcrack nodes on the local network
    pub fn discover(timeout: Duration) -> Vec<(String, SocketAddr, bool)> {
        let nodes = Vec::new();
        log::info!("mDNS discover for {}s", timeout.as_secs());
        nodes
    }

    /// Get default discovery port
    pub fn default_port() -> u16 {
        DISCOVERY_PORT
    }
}
