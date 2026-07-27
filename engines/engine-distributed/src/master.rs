//! Distributed cracking master node

use std::collections::HashMap;

pub struct MasterNode {
    pub listen_addr: String,
    pub workers: HashMap<String, WorkerInfo>,
}

pub struct WorkerInfo {
    addr: String,
    caps: crate::protocol::Capabilities,
    last_heartbeat: std::time::Instant,
}
