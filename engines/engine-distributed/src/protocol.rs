//! Network protocol for distributed cracking

use serde::{Serialize, Deserialize};

/// Message sent between master and worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // Worker → Master
    Handshake {
        node_name: String,
        tier: String,
        caps: Capabilities,
    },
    Heartbeat {
        node_name: String,
        stats: WorkerStats,
    },
    Result {
        node_name: String,
        batch_id: u64,
        cracked: Vec<CrackedEntry>,
    },

    // Master → Worker
    AssignWork {
        worker_id: u64,
        batch_id: u64,
        work: WorkUnit,
    },
    Shutdown {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub simd: String,
    pub gpu: bool,
    pub fpga: bool,
    pub max_threads: usize,
    pub ram_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStats {
    pub hashes_sec: f64,
    pub total_cracked: u64,
    pub power_watts: f64,
    pub temperature_c: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedEntry {
    pub hash: String,
    pub password: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkUnit {
    pub hash_type: String,
    pub target_hash: String,
    pub attack_type: AttackType,
    pub keyspace_start: u64,
    pub keyspace_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackType {
    Dictionary {
        wordlist_path: String,
        rules: Vec<String>,
    },
    BruteForce {
        mask: String,
    },
    Combinator {
        left_words: Vec<String>,
        right_words: Vec<String>,
    },
}
