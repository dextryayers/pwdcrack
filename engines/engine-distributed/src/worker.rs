use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;
use tokio::time;

use crate::verify;
use crate::protocol::{
    Message, WorkerStats, Capabilities, CrackedEntry, WorkUnit, AttackType,
};

async fn read_msg<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Message>, String> {
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

async fn write_msg<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, msg: &Message) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await.map_err(|e| e.to_string())?;
    writer.write_all(&data).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub struct WorkerNode {
    pub master_addr: String,
    pub node_name: String,
    pub stream: Option<TcpStream>,
    tested: Arc<AtomicU64>,
    cracked: Arc<AtomicU64>,
}

impl WorkerNode {
    pub fn new(master_addr: &str) -> Self {
        WorkerNode {
            master_addr: master_addr.to_string(),
            node_name: crate::hostname(),
            stream: None,
            tested: Arc::new(AtomicU64::new(0)),
            cracked: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        let stream = TcpStream::connect(&self.master_addr).await.map_err(|e| e.to_string())?;
        log::info!("Connected to master at {}", self.master_addr);
        self.stream = Some(stream);
        Ok(())
    }

    pub async fn send_handshake(&mut self) -> Result<(), String> {
        let stream = self.stream.as_mut().unwrap();
        let handshake = Message::Handshake {
            node_name: self.node_name.clone(),
            tier: std::env::consts::ARCH.to_string(),
            caps: Capabilities {
                simd: "detect".to_string(),
                gpu: false,
                fpga: false,
                max_threads: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
                ram_mb: 4096,
            },
        };
        write_msg(stream, &handshake).await?;
        log::info!("Sent handshake as '{}'", self.node_name);
        Ok(())
    }

    async fn crack_work_unit(&self, work: &WorkUnit) -> Vec<CrackedEntry> {
        let mut results = Vec::new();
        let start = work.keyspace_start;
        let end = work.keyspace_end;
        let total = end.saturating_sub(start);
        if total == 0 { return Vec::new(); }

        let local_tested = AtomicU64::new(0);
        let begin = std::time::Instant::now();

        match &work.attack_type {
            AttackType::BruteForce { mask } => {
                let mask_chars = parse_mask(mask);
                let charsets = build_charsets(&mask_chars);
                let mut candidate_buf = vec![0u8; mask.len()];

                for idx in start..end {
                    generate_candidate(&mask_chars, &charsets, idx, &mut candidate_buf);
                    let pw = std::str::from_utf8(&candidate_buf)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                    if verify::verify(&work.hash_type, &work.target_hash, &pw) {
                        log::info!("CRACKED: {} -> {}", work.target_hash, pw);
                        results.push(CrackedEntry {
                            hash: work.target_hash.clone(),
                            password: pw,
                            algorithm: work.hash_type.clone(),
                        });
                        break;
                    }
                    local_tested.fetch_add(1, Ordering::SeqCst);
                }
            }
            AttackType::Dictionary { wordlist_path, rules } => {
                let words = match read_wordlist_lines(wordlist_path, start, end) {
                    Ok(w) => w,
                    Err(e) => {
                        log::error!("Failed to read wordlist '{}': {}", wordlist_path, e);
                        return Vec::new();
                    }
                };

                let parsed_rules: Vec<Vec<_>> = rules.iter()
                    .filter_map(|r| parse_rule(r).ok())
                    .collect();

                for word in &words {
                    let candidates: Vec<String> = if parsed_rules.is_empty() {
                        vec![word.clone()]
                    } else {
                        let mut all = Vec::new();
                        for rule_ops in &parsed_rules {
                            all.extend(apply_rule(word, rule_ops));
                        }
                        all
                    };

                    for pw in &candidates {
                        if verify::verify(&work.hash_type, &work.target_hash, pw) {
                            log::info!("CRACKED: {} -> {}", work.target_hash, pw);
                            results.push(CrackedEntry {
                                hash: work.target_hash.clone(),
                                password: pw.clone(),
                                algorithm: work.hash_type.clone(),
                            });
                            break;
                        }
                    }
                    local_tested.fetch_add(1, Ordering::SeqCst);
                    if !results.is_empty() { break; }
                }
            }
            AttackType::Combinator { left_words, right_words } => {
                if left_words.is_empty() || right_words.is_empty() {
                    return Vec::new();
                }
                let mut pair_idx = 0u64;
                'outer: for left in left_words {
                    for right in right_words {
                        if pair_idx >= end { break 'outer; }
                        if pair_idx >= start {
                            let pw = format!("{}{}", left, right);
                            if verify::verify(&work.hash_type, &work.target_hash, &pw) {
                                log::info!("CRACKED: {} -> {}", work.target_hash, pw);
                                results.push(CrackedEntry {
                                    hash: work.target_hash.clone(),
                                    password: pw,
                                    algorithm: work.hash_type.clone(),
                                });
                                break 'outer;
                            }
                            local_tested.fetch_add(1, Ordering::SeqCst);
                        }
                        pair_idx += 1;
                    }
                }
            }
        }

        let elapsed = begin.elapsed().as_secs_f64().max(0.001);
        let count = local_tested.load(Ordering::SeqCst);
        let hps = count as f64 / elapsed;
        log::info!("Batch {} range [{},{}): {} tested in {:.1}s ({:.0} H/s), {} cracked",
            work.hash_type, start, end, count, elapsed, hps, results.len());

        self.tested.fetch_add(count, Ordering::SeqCst);
        self.cracked.fetch_add(results.len() as u64, Ordering::SeqCst);
        results
    }

    pub async fn run_worker_loop(&mut self) -> Result<(), String> {
        self.connect().await?;
        self.send_handshake().await?;

        let mut stream = self.stream.take().ok_or("stream already taken")?;
        let (mut reader, mut writer) = tokio::io::split(&mut stream);

        let node_name = self.node_name.clone();
        let _tested = Arc::clone(&self.tested);
        let cracked = Arc::clone(&self.cracked);
        let mut hb_interval = time::interval(Duration::from_secs(5));
        hb_interval.tick().await;

        loop {
            let read_fut = read_msg(&mut reader);

            tokio::select! {
                msg_result = read_fut => {
                    match msg_result? {
                        Some(Message::AssignWork { worker_id: _, batch_id, work }) => {
                            log::info!("Received batch {}: {} range [{}, {})",
                                batch_id, work.hash_type, work.keyspace_start, work.keyspace_end);
                            let cracked_entries = self.crack_work_unit(&work).await;
                            let result = Message::Result {
                                node_name: node_name.clone(),
                                batch_id,
                                cracked: cracked_entries,
                            };
                            write_msg(&mut writer, &result).await?;
                        }
                        Some(Message::Ping) => {
                            write_msg(&mut writer, &Message::Pong).await?;
                        }
                        Some(Message::Shutdown { reason }) => {
                            log::info!("Master shutdown: {}", reason);
                            break;
                        }
                        None => {
                            log::warn!("Connection to master lost");
                            break;
                        }
                        _ => {}
                    }
                }
                _ = hb_interval.tick() => {
                    let hb = Message::Heartbeat {
                        node_name: node_name.clone(),
                        stats: WorkerStats {
                            hashes_sec: 0.0,
                            total_cracked: cracked.load(Ordering::SeqCst),
                            power_watts: 0.0,
                            temperature_c: 0.0,
                        },
                    };
                    write_msg(&mut writer, &hb).await?;
                }
            }
        }

        log::info!("Worker '{}' shutting down", node_name);
        Ok(())
    }
}

fn parse_mask(mask: &str) -> Vec<MaskChar> {
    let mut chars = Vec::new();
    let bytes = mask.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'?' && i + 1 < bytes.len() {
            let mc = match bytes[i + 1] {
                b'l' => MaskChar::Lower,
                b'u' => MaskChar::Upper,
                b'd' => MaskChar::Digit,
                b's' => MaskChar::Special,
                b'a' => MaskChar::All,
                b'h' => MaskChar::HexLower,
                b'H' => MaskChar::HexUpper,
                b'b' => MaskChar::Byte,
                b'1'..=b'9' => MaskChar::Custom((bytes[i+1] - b'0') as usize),
                _ => MaskChar::Literal(bytes[i+1] as char),
            };
            chars.push(mc);
            i += 2;
        } else {
            chars.push(MaskChar::Literal(bytes[i] as char));
            i += 1;
        }
    }
    chars
}

#[derive(Clone)]
enum MaskChar {
    Lower, Upper, Digit, Special, All,
    HexLower, HexUpper, Byte, Custom(usize), Literal(char),
}

fn build_charsets(mask_chars: &[MaskChar]) -> Vec<Vec<u8>> {
    mask_chars.iter().map(|mc| match mc {
        MaskChar::Lower => (b'a'..=b'z').collect(),
        MaskChar::Upper => (b'A'..=b'Z').collect(),
        MaskChar::Digit => (b'0'..=b'9').collect(),
        MaskChar::Special => b"!@#$%^&*()-_+=~`[]{}|;:',.<>?/".to_vec(),
        MaskChar::All => (b'!'..=b'~').collect(),
        MaskChar::HexLower => b"0123456789abcdef".to_vec(),
        MaskChar::HexUpper => b"0123456789ABCDEF".to_vec(),
        MaskChar::Byte => (0u8..=255).collect(),
        MaskChar::Custom(_) => b"abcdefghijklmnopqrstuvwxyz".to_vec(),
        MaskChar::Literal(c) => vec![*c as u8],
    }).collect()
}

fn generate_candidate(mask_chars: &[MaskChar], charsets: &[Vec<u8>], idx: u64, buf: &mut [u8]) {
    let mut remaining = idx;
    for (pos, mc) in mask_chars.iter().enumerate() {
        match mc {
            MaskChar::Literal(c) => {
                buf[pos] = *c as u8;
            }
            _ => {
                let charset = &charsets[pos];
                if charset.is_empty() { continue; }
                let ci = (remaining as usize) % charset.len();
                buf[pos] = charset[ci];
                remaining /= charset.len() as u64;
            }
        }
    }
}

fn parse_rule(rule: &str) -> Result<Vec<RuleOp>, String> {
    // Minimal rule parser for common operations
    let mut ops = Vec::new();
    let bytes = rule.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'l' => ops.push(RuleOp::Lowercase),
            b'u' => ops.push(RuleOp::Uppercase),
            b'r' => ops.push(RuleOp::Reverse),
            b'd' => ops.push(RuleOp::Duplicate),
            b'f' => ops.push(RuleOp::Reflect),
            b'{' => ops.push(RuleOp::RotateLeft),
            b'}' => ops.push(RuleOp::RotateRight),
            b'$' if i + 1 < bytes.len() => {
                ops.push(RuleOp::Append(bytes[i+1] as char));
                i += 1;
            }
            b'^' if i + 1 < bytes.len() => {
                ops.push(RuleOp::Prepend(bytes[i+1] as char));
                i += 1;
            }
            b'T' if i + 2 < bytes.len() => {
                let pos = (bytes[i+1] - b'0') as usize;
                ops.push(RuleOp::ToggleAt(pos));
                i += 2;
            }
            b'D' if i + 2 < bytes.len() => {
                let pos = (bytes[i+1] - b'0') as usize;
                ops.push(RuleOp::DeleteAt(pos));
                i += 2;
            }
            b'p' if i + 3 < bytes.len() => {
                let l = (bytes[i+1] - b'0') as usize;
                let r = (bytes[i+2] - b'0') as usize;
                ops.push(RuleOp::SwapAt(l, r));
                i += 3;
            }
            b':' => ops.push(RuleOp::Pure),
            _ => {}
        }
        i += 1;
    }
    Ok(ops)
}

#[derive(Clone)]
enum RuleOp {
    Lowercase, Uppercase, Reverse, Duplicate, Reflect,
    RotateLeft, RotateRight, Append(char), Prepend(char),
    ToggleAt(usize), DeleteAt(usize), SwapAt(usize, usize), Pure,
}

fn apply_rule(word: &str, ops: &[RuleOp]) -> Vec<String> {
    let mut results = vec![word.to_string()];
    for op in ops {
        results = results.into_iter().flat_map(|w| apply_one(&w, op)).collect();
    }
    results
}

fn apply_one(word: &str, op: &RuleOp) -> Vec<String> {
    match op {
        RuleOp::Pure => vec![word.to_string()],
        RuleOp::Lowercase => vec![word.to_lowercase()],
        RuleOp::Uppercase => vec![word.to_uppercase()],
        RuleOp::Reverse => vec![word.chars().rev().collect()],
        RuleOp::Duplicate => vec![format!("{}{}", word, word)],
        RuleOp::Reflect => {
            let rev: String = word.chars().rev().collect();
            vec![format!("{}{}", word, rev)]
        }
        RuleOp::RotateLeft => {
            let mut c: Vec<char> = word.chars().collect();
            if !c.is_empty() { c.rotate_left(1); }
            vec![c.into_iter().collect()]
        }
        RuleOp::RotateRight => {
            let mut c: Vec<char> = word.chars().collect();
            if !c.is_empty() { c.rotate_right(1); }
            vec![c.into_iter().collect()]
        }
        RuleOp::Append(ch) => vec![format!("{}{}", word, ch)],
        RuleOp::Prepend(ch) => vec![format!("{}{}", ch, word)],
        RuleOp::ToggleAt(pos) => {
            let mut c: Vec<char> = word.chars().collect();
            if *pos < c.len() {
                if c[*pos].is_ascii_lowercase() {
                    c[*pos] = c[*pos].to_ascii_uppercase();
                } else if c[*pos].is_ascii_uppercase() {
                    c[*pos] = c[*pos].to_ascii_lowercase();
                }
            }
            vec![c.into_iter().collect()]
        }
        RuleOp::DeleteAt(pos) => {
            let mut c: Vec<char> = word.chars().collect();
            if *pos < c.len() { c.remove(*pos); }
            vec![c.into_iter().collect()]
        }
        RuleOp::SwapAt(l, r) => {
            let mut c: Vec<char> = word.chars().collect();
            if *l < c.len() && *r < c.len() {
                c.swap(*l, *r);
            }
            vec![c.into_iter().collect()]
        }
    }
}

fn read_wordlist_lines(path: &str, start: u64, end: u64) -> Result<Vec<String>, String> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {}", path, e))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let i = i as u64;
        if i >= end { break; }
        if i < start { continue; }
        match line {
            Ok(l) => lines.push(l),
            Err(e) => return Err(format!("read {} line {}: {}", path, i, e)),
        }
    }
    Ok(lines)
}
