use crate::hash::{HashCracker, HashEntry};
use crate::attack::CrackResult;
use crate::attack::setup_progress;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn run_prince(
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
    let finished2 = finished.clone();
    let progress = std::sync::atomic::AtomicU64::new(0);
    crossbeam::scope(|s| {
        s.spawn(|_| {
            for chunk in words.chunks(1024) {
                for word in chunk {
                    if finished2.load(Ordering::Relaxed) { return; }
                    for i in 0..hashes.len() {
                        if hashes[i].cracked { continue; }
                        if cracker.verify(word, &hashes[i]) {
                            let raw = hashes[i].raw.clone();
                            results.lock().unwrap().push(CrackResult {
                                original: raw.clone(),
                                hash_type: cracker.name().to_string(),
                                password: Some(word.clone()),
                            });
                            hashes[i].cracked = true;
                            hashes[i].password = Some(word.clone());
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
