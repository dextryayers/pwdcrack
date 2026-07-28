use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time;

use crate::protocol::{
    Message, WorkerStats, CrackedEntry, WorkUnit, Capabilities, AttackType,
};

#[derive(Debug, Clone)]
pub struct PendingWork {
    pub batch_id: u64,
    pub work: WorkUnit,
}

#[derive(Debug, Clone)]
pub struct InFlightWork {
    pub batch_id: u64,
    pub worker_name: String,
    pub work: WorkUnit,
    pub assigned_at: Instant,
}

pub struct MasterNode {
    pub listen_addr: String,
    pub workers: Arc<Mutex<HashMap<String, WorkerInfo>>>,
    work_queue: Arc<Mutex<VecDeque<PendingWork>>>,
    in_flight: Arc<Mutex<HashMap<u64, InFlightWork>>>,
    completed: Arc<Mutex<Vec<CrackedEntry>>>,
    next_batch_id: Arc<std::sync::atomic::AtomicU64>,
    checkpoint_path: String,
}

pub struct WorkerInfo {
    pub addr: String,
    pub caps: Capabilities,
    pub last_heartbeat: Instant,
    pub stats: WorkerStats,
    pub busy: bool,
    pub current_batch: Option<u64>,
}

impl MasterNode {
    pub fn new(listen_addr: &str, checkpoint_path: &str) -> Self {
        MasterNode {
            listen_addr: listen_addr.to_string(),
            workers: Arc::new(Mutex::new(HashMap::new())),
            work_queue: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            next_batch_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            checkpoint_path: checkpoint_path.to_string(),
        }
    }

    pub fn enqueue_work(&self, work: WorkUnit) -> u64 {
        let bid = self.next_batch_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut q = self.work_queue.blocking_lock();
        q.push_back(PendingWork { batch_id: bid, work });
        bid
    }

    pub fn enqueue_batches(
        &self,
        target_hash: String,
        hash_type: String,
        attack_type: AttackType,
        chunk_size: u64,
    ) -> u64 {
        let total = total_keyspace(&attack_type);
        let mut count = 0u64;
        let mut start = 0u64;
        while start < total {
            let end = (start + chunk_size).min(total);
            let wu = WorkUnit {
                hash_type: hash_type.clone(),
                target_hash: target_hash.clone(),
                attack_type: match &attack_type {
                    AttackType::BruteForce { mask } =>
                        AttackType::BruteForce { mask: mask.clone() },
                    AttackType::Dictionary { wordlist_path, rules } =>
                        AttackType::Dictionary {
                            wordlist_path: wordlist_path.clone(),
                            rules: rules.clone(),
                        },
                    AttackType::Combinator { left_words, right_words } =>
                        AttackType::Combinator {
                            left_words: left_words.clone(),
                            right_words: right_words.clone(),
                        },
                },
                keyspace_start: start,
                keyspace_end: end,
            };
            self.enqueue_work(wu);
            count += 1;
            start = end;
        }
        count
    }

    pub fn save_checkpoint(&self) -> Result<(), String> {
        let completed = self.completed.blocking_lock();
        let in_flight = self.in_flight.blocking_lock();
        let q = self.work_queue.blocking_lock();
        #[derive(serde::Serialize)]
        struct Checkpoint {
            completed: Vec<CrackedEntry>,
            in_flight_batches: Vec<u64>,
            pending_count: usize,
            timestamp: String,
        }
        let cp = Checkpoint {
            completed: completed.clone(),
            in_flight_batches: in_flight.keys().copied().collect(),
            pending_count: q.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let data = serde_json::to_string_pretty(&cp).map_err(|e| e.to_string())?;
        std::fs::write(&self.checkpoint_path, &data).map_err(|e| e.to_string())?;
        log::info!("Checkpoint saved: {} completed, {} in-flight, {} pending",
            completed.len(), in_flight.len(), q.len());
        Ok(())
    }

    pub fn load_checkpoint(&self) -> Result<(), String> {
        let data = std::fs::read_to_string(&self.checkpoint_path).map_err(|e| e.to_string())?;
        #[derive(serde::Deserialize)]
        struct Checkpoint {
            #[allow(dead_code)]
            completed: Vec<CrackedEntry>,
            #[allow(dead_code)]
            in_flight_batches: Vec<u64>,
            #[allow(dead_code)]
            pending_count: usize,
            #[allow(dead_code)]
            timestamp: String,
        }
        let cp: Checkpoint = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        let mut completed = self.completed.blocking_lock();
        *completed = cp.completed;
        log::info!("Checkpoint loaded: {} previously cracked", completed.len());
        Ok(())
    }

    async fn assign_next(&self, worker_name: &str) -> Option<PendingWork> {
        let mut q = self.work_queue.lock().await;
        let next = q.pop_front()?;

        let mut inflight = self.in_flight.lock().await;
        inflight.insert(next.batch_id, InFlightWork {
            batch_id: next.batch_id,
            worker_name: worker_name.to_string(),
            work: next.work.clone(),
            assigned_at: Instant::now(),
        });

        let mut workers = self.workers.lock().await;
        if let Some(info) = workers.get_mut(worker_name) {
            info.busy = true;
            info.current_batch = Some(next.batch_id);
        }

        Some(next)
    }

    #[allow(dead_code)]
    fn reclaim_orphaned(&self) {
        let now = Instant::now();
        let mut inflight = self.in_flight.blocking_lock();
        let mut q = self.work_queue.blocking_lock();
        let workers = self.workers.blocking_lock();

        let mut orphaned = Vec::new();
        inflight.retain(|bid, infl| {
            let is_orphaned = workers.get(&infl.worker_name)
                .map_or(true, |w| {
                    w.last_heartbeat.elapsed() > Duration::from_secs(30)
                });
            if is_orphaned || now.duration_since(infl.assigned_at) > Duration::from_secs(3600) {
                orphaned.push(PendingWork {
                    batch_id: *bid,
                    work: infl.work.clone(),
                });
                return false;
            }
            true
        });

        for pw in orphaned {
            log::warn!("Re-queuing orphaned batch {}", pw.batch_id);
            q.push_front(pw);
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        let listener = TcpListener::bind(&self.listen_addr).await.map_err(|e| e.to_string())?;
        log::info!("Master listening on {}", self.listen_addr);

        let bg_workers = Arc::clone(&self.workers);
        let bg_inflight = Arc::clone(&self.in_flight);
        let bg_queue = Arc::clone(&self.work_queue);
        let bg_completed = Arc::clone(&self.completed);
        let cp_path = self.checkpoint_path.clone();
        tokio::spawn(async move {
            let mut tick = time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let mut orphaned = Vec::new();
                {
                    let wl = bg_workers.lock().await;
                    let mut infl = bg_inflight.lock().await;
                    let now = Instant::now();
                    infl.retain(|bid, infl| {
                        let is_dead = wl.get(&infl.worker_name)
                            .map_or(true, |w| w.last_heartbeat.elapsed() > Duration::from_secs(30));
                        if is_dead || now.duration_since(infl.assigned_at) > Duration::from_secs(3600) {
                            orphaned.push(PendingWork { batch_id: *bid, work: infl.work.clone() });
                            return false;
                        }
                        true
                    });
                }
                if !orphaned.is_empty() {
                    let mut q = bg_queue.lock().await;
                    for pw in orphaned {
                        log::warn!("Re-queuing orphaned batch {}", pw.batch_id);
                        q.push_front(pw);
                    }
                }
                // Periodic checkpoint
                let data = {
                    let c = bg_completed.lock().await;
                    let infl = bg_inflight.lock().await;
                    let q = bg_queue.lock().await;
                    format!(
                        r#"{{"completed":{},"in_flight":{},"pending":{},"time":"{}"}}"#,
                        serde_json::to_string(&*c).unwrap_or_default(),
                        serde_json::to_string(&infl.keys().copied().collect::<Vec<_>>()).unwrap_or_default(),
                        q.len(),
                        chrono::Utc::now().to_rfc3339(),
                    )
                };
                let _ = std::fs::write(&cp_path, &data);
            }
        });

        loop {
            let (socket, addr) = listener.accept().await.map_err(|e| e.to_string())?;
            log::info!("Worker connected from {}", addr);
            let workers = Arc::clone(&self.workers);
            let in_flight = Arc::clone(&self.in_flight);
            let completed = Arc::clone(&self.completed);
            let work_queue = Arc::clone(&self.work_queue);
            tokio::spawn(async move {
                if let Err(e) = handle_worker(socket, workers, work_queue, in_flight, completed).await {
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
        self.next_batch_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

async fn read_msg(socket: &mut TcpStream) -> Result<Option<Message>, String> {
    let mut len_buf = [0u8; 4];
    if socket.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err("message too large".to_string());
    }
    let mut data = vec![0u8; len];
    socket.read_exact(&mut data).await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&data).map(Some).map_err(|e| e.to_string())
}

async fn write_msg(socket: &mut TcpStream, msg: &Message) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len = (data.len() as u32).to_be_bytes();
    socket.write_all(&len).await.map_err(|e| e.to_string())?;
    socket.write_all(&data).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn handle_worker(
    mut socket: TcpStream,
    workers: Arc<Mutex<HashMap<String, WorkerInfo>>>,
    work_queue: Arc<Mutex<VecDeque<PendingWork>>>,
    in_flight: Arc<Mutex<HashMap<u64, InFlightWork>>>,
    completed: Arc<Mutex<Vec<CrackedEntry>>>,
) -> Result<(), String> {
    let mut worker_name = String::new();

    while let Some(msg) = read_msg(&mut socket).await? {
        // Respond to Ping immediately
        if matches!(msg, Message::Ping) {
            write_msg(&mut socket, &Message::Pong).await?;
            continue;
        }

        match msg {
            Message::Handshake { node_name, tier, caps } => {
                worker_name = node_name.clone();
                log::info!("Worker '{}' handshake: tier={}, caps={:?}", node_name, tier, caps);
                workers.lock().await.insert(node_name.clone(), WorkerInfo {
                    addr: node_name.clone(),
                    caps,
                    last_heartbeat: Instant::now(),
                    stats: WorkerStats {
                        hashes_sec: 0.0,
                        total_cracked: 0,
                        power_watts: 0.0,
                        temperature_c: 0.0,
                    },
                    busy: false,
                    current_batch: None,
                });
            }
            Message::Heartbeat { node_name, stats } => {
                let mut w = workers.lock().await;
                if let Some(info) = w.get_mut(&node_name) {
                    info.last_heartbeat = Instant::now();
                    info.stats = stats;
                }
            }
            Message::WorkProgress { node_name, batch_id, tested, hashes_sec } => {
                let mut w = workers.lock().await;
                if let Some(info) = w.get_mut(&node_name) {
                    info.stats.hashes_sec = hashes_sec;
                }
                log::debug!("Worker {} batch {}: {} tested ({:.0} H/s)",
                    node_name, batch_id, tested, hashes_sec);
            }
            Message::Result { node_name, batch_id, cracked } => {
                log::info!("Worker '{}' batch {}: {} cracked", node_name, batch_id, cracked.len());
                {
                    let mut w = workers.lock().await;
                    if let Some(info) = w.get_mut(&node_name) {
                        info.busy = false;
                        info.current_batch = None;
                        info.stats.total_cracked += cracked.len() as u64;
                    }
                }
                {
                    let mut infl = in_flight.lock().await;
                    infl.remove(&batch_id);
                }
                {
                    let mut c = completed.lock().await;
                    c.extend(cracked);
                }

                // Assign next work unit if available
                let next = {
                    let mut q = work_queue.lock().await;
                    q.pop_front()
                };
                if let Some(pw) = next {
                    let mut infl = in_flight.lock().await;
                    infl.insert(pw.batch_id, InFlightWork {
                        batch_id: pw.batch_id,
                        worker_name: node_name.clone(),
                        work: pw.work.clone(),
                        assigned_at: Instant::now(),
                    });
                    {
                        let mut w = workers.lock().await;
                        if let Some(info) = w.get_mut(&node_name) {
                            info.busy = true;
                            info.current_batch = Some(pw.batch_id);
                        }
                    }
                    let assign = Message::AssignWork {
                        worker_id: 0,
                        batch_id: pw.batch_id,
                        work: pw.work,
                    };
                    write_msg(&mut socket, &assign).await?;
                }
            }
            Message::Shutdown { .. } => {
                let wn = if worker_name.is_empty() { "unknown" } else { &worker_name };
                log::info!("Worker {} requested shutdown", wn);
                break;
            }
            _ => {}
        }
    }

    // Worker disconnected — reclaim its in-flight work
    if !worker_name.is_empty() {
        let mut infl = in_flight.lock().await;
        let mut q = work_queue.lock().await;
        let mut to_reclaim = Vec::new();
        infl.retain(|bid, infl| {
            if infl.worker_name == worker_name {
                to_reclaim.push(PendingWork { batch_id: *bid, work: infl.work.clone() });
                return false;
            }
            true
        });
        for pw in to_reclaim {
            log::warn!("Re-queuing {}'s batch {}", worker_name, pw.batch_id);
            q.push_front(pw);
        }
        workers.lock().await.remove(&worker_name);
    }

    Ok(())
}

fn total_keyspace(attack: &AttackType) -> u64 {
    match attack {
        AttackType::BruteForce { mask } => {
            // Estimate total keyspace from mask placeholders
            let placeholders: u64 = mask.chars().filter(|c| *c == '?').count() as u64;
            if placeholders == 0 { return 1; }
            // Assume average charset size ~ 26 for estimate
            26u64.saturating_pow(placeholders as u32)
        }
        AttackType::Dictionary { .. } => {
            // Wordlist-based — estimate by file size
            10_000_000 // default estimate
        }
        AttackType::Combinator { left_words, right_words } => {
            left_words.len().saturating_mul(right_words.len()) as u64
        }
    }
}
