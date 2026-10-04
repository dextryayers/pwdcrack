use std::io::BufRead;
use crate::hash::{HashCracker, HashEntry};
use crate::attack::CrackResult;
use crate::attack::setup_progress;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn gen_toggle(word: &str, max: usize) -> Vec<String> {
    let chars: Vec<char> = word.chars().collect();
    let positions: Vec<usize> = chars.iter().enumerate()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .collect();
    let max_combos = 1usize << positions.len().min(max);
    let mut results = Vec::with_capacity(max_combos);
    for mask in 0..max_combos {
        let mut w: Vec<char> = chars.clone();
        for (j, &pos) in positions.iter().enumerate() {
            if j >= max { break; }
            if (mask >> j) & 1 == 1 {
                w[pos] = w[pos].to_ascii_uppercase();
            } else {
                w[pos] = w[pos].to_ascii_lowercase();
            }
        }
        results.push(w.iter().collect());
    }
    results
}

pub fn run_toggle(
    hashes: &mut [HashEntry],
    cracker: &dyn HashCracker,
    wordlist: &str,
    quiet: bool,
    low_mem: bool,
) -> Vec<CrackResult> {
    let words: Vec<String> = if low_mem {
        Vec::new()
    } else {
        let w: Vec<String> = std::fs::read_to_string(wordlist)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if w.is_empty() {
            eprintln!("[!] Empty wordlist: {}", wordlist);
            return vec![];
        }
        w
    };
    let total = if low_mem { 0 } else { words.len() as u64 };
    let pb = setup_progress(total, quiet);
    let pb2 = pb.as_ref();
    let results = std::sync::Mutex::new(Vec::new());
    let finished = Arc::new(AtomicBool::new(false));
    let progress = std::sync::atomic::AtomicU64::new(0);

    if low_mem {
        let file = match std::fs::File::open(wordlist) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] Failed to open wordlist: {}", e);
                return vec![];
            }
        };
        let reader = std::io::BufReader::with_capacity(4096, file);
        crossbeam::scope(|s| {
            s.spawn(|_| {
                for line_result in reader.lines() {
                    let word = match line_result {
                        Ok(w) => w.trim().to_string(),
                        Err(_) => continue,
                    };
                    if word.is_empty() { continue; }
                    if finished.load(Ordering::Relaxed) { return; }
                    for toggle in gen_toggle(&word, 4) {
                        for i in 0..hashes.len() {
                            if hashes[i].cracked { continue; }
                            if cracker.verify(&toggle, &hashes[i]) {
                                let raw = hashes[i].raw.clone();
                                results.lock().unwrap().push(CrackResult {
                                    original: raw.clone(),
                                    hash_type: cracker.name().to_string(),
                                    password: Some(toggle.clone()),
                                });
                                hashes[i].cracked = true;
                                hashes[i].password = Some(toggle.clone());
                            }
                        }
                    }
                    progress.fetch_add(1, Ordering::Relaxed);
                }
            });
        }).unwrap();
    } else {
        crossbeam::scope(|s| {
            s.spawn(|_| {
                for chunk in words.chunks(512) {
                    for word in chunk {
                        if finished.load(Ordering::Relaxed) { return; }
                        for toggle in gen_toggle(word, 4) {
                            for i in 0..hashes.len() {
                                if hashes[i].cracked { continue; }
                                if cracker.verify(&toggle, &hashes[i]) {
                                    let raw = hashes[i].raw.clone();
                                    results.lock().unwrap().push(CrackResult {
                                        original: raw.clone(),
                                        hash_type: cracker.name().to_string(),
                                        password: Some(toggle.clone()),
                                    });
                                    hashes[i].cracked = true;
                                    hashes[i].password = Some(toggle.clone());
                                }
                            }
                        }
                        progress.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(ref p) = pb2 {
                        p.set_position(progress.load(Ordering::Relaxed));
                    }
                }
            });
        }).unwrap();
    }
    if let Some(ref p) = pb { p.finish_and_clear(); }
    results.into_inner().unwrap()
}
