use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::protocol::Message;

pub struct MasterNode {
    pub listen_addr: String,
    pub workers: Arc<Mutex<HashMap<String, WorkerInfo>>>,
    total_work_assigned: Arc<std::sync::atomic::AtomicU64>,
}

pub struct WorkerInfo {
    pub addr: String,
    pub caps: crate::protocol::Capabilities,
    pub last_heartbeat: std::time::Instant,
    pub stats: crate::protocol::WorkerStats,
    pub busy: bool,
}

impl MasterNode {
    pub fn new(listen_addr: &str) -> Self {
        MasterNode {
            listen_addr: listen_addr.to_string(),
            workers: Arc::new(Mutex::new(HashMap::new())),
            total_work_assigned: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        let listener = TcpListener::bind(&self.listen_addr).await.map_err(|e| e.to_string())?;
        log::info!("Master listening on {}", self.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await.map_err(|e| e.to_string())?;
            log::info!("Worker connected from {}", addr);
            let workers = Arc::clone(&self.workers);
            let total = Arc::clone(&self.total_work_assigned);
            tokio::spawn(async move {
                if let Err(e) = handle_worker(socket, workers, total).await {
                    log::error!("Worker {} error: {}", addr, e);
                }
            });
        }
    }

    pub async fn worker_count(&self) -> usize {
        self.workers.lock().await.len()
    }

    pub async fn available_workers(&self) -> Vec<String> {
        let workers = self.workers.lock().await;
        workers.iter()
            .filter(|(_, info)| !info.busy)
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn assign_id(&self) -> u64 {
        self.total_work_assigned.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

async fn read_msg(socket: &mut TcpStream) -> Result<Option<Message>, String> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; len];
    socket.read_exact(&mut data).await.map_err(|e| e.to_string())?;

    match serde_json::from_slice(&data) {
        Ok(msg) => Ok(Some(msg)),
        Err(e) => {
            log::error!("deserialize error: {}", e);
            Ok(None)
        }
    }
}

async fn handle_worker(
    mut socket: TcpStream,
    workers: Arc<Mutex<HashMap<String, WorkerInfo>>>,
    _total: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), String> {
    while let Some(msg) = read_msg(&mut socket).await? {
        match msg {
            Message::Handshake { node_name, tier, caps } => {
                log::info!("Worker '{}' handshake: tier={}, caps={:?}", node_name, tier, caps);
                workers.lock().await.insert(node_name.clone(), WorkerInfo {
                    addr: node_name,
                    caps,
                    last_heartbeat: std::time::Instant::now(),
                    stats: crate::protocol::WorkerStats {
                        hashes_sec: 0.0,
                        total_cracked: 0,
                        power_watts: 0.0,
                        temperature_c: 0.0,
                    },
                    busy: false,
                });
            }
            Message::Heartbeat { node_name, stats } => {
                let mut w = workers.lock().await;
                if let Some(info) = w.get_mut(&node_name) {
                    info.last_heartbeat = std::time::Instant::now();
                    info.stats = stats;
                }
            }
            Message::Result { node_name, batch_id, cracked } => {
                log::info!("Worker '{}' batch {}: {} cracked", node_name, batch_id, cracked.len());
                let mut w = workers.lock().await;
                if let Some(info) = w.get_mut(&node_name) {
                    info.busy = false;
                }
            }
            _ => {}
        }
    }

    Ok(())
}
