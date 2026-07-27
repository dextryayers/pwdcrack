//! Distributed cracking worker node

pub struct WorkerNode {
    pub master_addr: String,
    pub node_name: String,
}

impl WorkerNode {
    pub fn connect(master_addr: &str) -> Self {
        WorkerNode {
            master_addr: master_addr.to_string(),
            node_name: crate::hostname(),
        }
    }
}
