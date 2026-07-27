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

impl DistributedConfig {
    pub fn is_master(&self) -> bool {
        self.master_addr.is_none()
    }

    pub async fn run(&self) -> Result<(), String> {
        if self.is_master() {
            let master = master::MasterNode::new(&self.listen_addr.to_string());
            master.run().await
        } else {
            let mut worker = worker::WorkerNode::new(
                &self.master_addr.unwrap().to_string()
            );
            worker.run_worker_loop().await
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}
