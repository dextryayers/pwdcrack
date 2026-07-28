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
) -> Vec<CrackResult> {
    let words: Vec<String> = std::fs::read_to_string(wordlist)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if words.is_empty() {
        eprintln!("[!] Empty wordlist: {}", wordlist);
        return vec![];
    }
    let total = words.len() as u64;
    let pb = setup_progress(total, quiet);
    let pb2 = pb.as_ref();
    let results = std::sync::Mutex::new(Vec::new());
    let finished = Arc::new(AtomicBool::new(false));
    let progress = std::sync::atomic::AtomicU64::new(0);
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
    if let Some(ref p) = pb { p.finish_and_clear(); }
    results.into_inner().unwrap()
}
