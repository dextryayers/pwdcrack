use std::io::BufRead;
use crate::hash::{HashCracker, HashEntry};
use crate::attack::CrackResult;
use crate::attack::setup_progress;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static SUBS_LEVEL1: &[(char, char)] = &[
    ('a', '@'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '$'),
];
static SUBS_LEVEL2: &[(char, char)] = &[
    ('a', '@'), ('a', '4'), ('e', '3'), ('i', '1'), ('i', '!'),
    ('o', '0'), ('s', '$'), ('s', '5'), ('t', '+'), ('b', '8'),
];
static SUBS_LEVEL3: &[(char, char)] = &[
    ('a', '@'), ('a', '4'), ('e', '3'), ('i', '1'), ('i', '!'),
    ('o', '0'), ('s', '$'), ('s', '5'), ('t', '+'), ('b', '8'),
    ('g', '9'), ('z', '2'), ('h', '#'), ('c', '('), ('l', '|'),
];

fn apply_subs(word: &str, level: u8) -> Vec<String> {
    let rules: &[(char, char)] = match level {
        1 => SUBS_LEVEL1,
        2 => SUBS_LEVEL2,
        _ => SUBS_LEVEL3,
    };
    let _chars: Vec<char> = word.chars().collect();
    let mut results = vec![word.to_string()];
    for &(from, to) in rules {
        for i in 0..results.len() {
            let w: String = results[i].chars().map(|c| if c == from { to } else { c }).collect();
            if w != results[i] {
                results.push(w);
            }
        }
    }
    results
}

pub fn run_substitute(
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
                    for sub in apply_subs(&word, 2) {
                        for i in 0..hashes.len() {
                            if hashes[i].cracked { continue; }
                            if cracker.verify(&sub, &hashes[i]) {
                                let raw = hashes[i].raw.clone();
                                results.lock().unwrap().push(CrackResult {
                                    original: raw.clone(),
                                    hash_type: cracker.name().to_string(),
                                    password: Some(sub.clone()),
                                });
                                hashes[i].cracked = true;
                                hashes[i].password = Some(sub.clone());
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
                        for sub in apply_subs(word, 2) {
                            for i in 0..hashes.len() {
                                if hashes[i].cracked { continue; }
                                if cracker.verify(&sub, &hashes[i]) {
                                    let raw = hashes[i].raw.clone();
                                    results.lock().unwrap().push(CrackResult {
                                        original: raw.clone(),
                                        hash_type: cracker.name().to_string(),
                                        password: Some(sub.clone()),
                                    });
                                    hashes[i].cracked = true;
                                    hashes[i].password = Some(sub.clone());
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
