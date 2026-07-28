use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // Bidirectional
    Ping,
    Pong,

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
    WorkProgress {
        node_name: String,
        batch_id: u64,
        tested: u64,
        hashes_sec: f64,
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

impl WorkUnit {
    pub fn total_size(&self) -> u64 {
        self.keyspace_end.saturating_sub(self.keyspace_start)
    }
}
