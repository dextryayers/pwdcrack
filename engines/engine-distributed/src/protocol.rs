use serde::{Serialize, Deserialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

pub async fn read_msg<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Message>, String> {
    let mut len_buf = [0u8; 4];
    if reader.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err("message too large".to_string());
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&data).map(Some).map_err(|e| e.to_string())
}

pub async fn write_msg<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, msg: &Message) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await.map_err(|e| e.to_string())?;
    writer.write_all(&data).await.map_err(|e| e.to_string())?;
    Ok(())
}
