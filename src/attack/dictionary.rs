use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, setup_progress, ProgressStats};
use crate::attack::rules::engine::{parse_rule, apply_rule};
use crate::attack::rules::load_rules;

#[cfg(feature = "mmap")]
use memmap2::Mmap;

#[cfg(feature = "progress-rich")]
fn print_speed(stats: &ProgressStats) {
    let rate = stats.hash_rate();
    let eta = stats.eta();
    eprint!("\r[*] {} H/s | {} cracked | {}", rate, stats.cracked(), eta);
}

pub fn run_dictionary(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist_path: &str,
    rules_path: Option<&str>,
    _threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    let rules = match rules_path {
        Some(path) => match load_rules(path) {
            Ok(r) => {
                if !quiet {
                    eprintln!("[*] Loaded {} rules from {}", r.len(), path);
                }
                Some(r)
            }
            Err(e) => {
                eprintln!("[!] {}", e);
                None
            }
        },
        None => None,
    };

    let file = match fs::File::open(Path::new(wordlist_path)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist: {}", e);
            return Vec::new();
        }
    };

    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let rule_count = rules.as_ref().map(|r| r.len()).unwrap_or(0);
    let total_hashes = hashes.len();

    #[cfg(feature = "mmap")]
    let (chunks, word_count_hint) = {
        let mmap = unsafe { Mmap::map(&file) };
        match mmap {
            Ok(m) => {
                let hint = file_size / 16;
                if !quiet {
                    eprintln!("[*] mmap wordlist: {} MB (≈{} lines est.)", file_size >> 20, hint);
                }
                (Some(m), hint)
            }
            Err(_) => {
                if !quiet { eprintln!("[*] mmap failed, falling back to streaming"); }
                (None, 0)
            }
        }
    };

    #[cfg(not(feature = "mmap"))]
    let word_count_hint = file_size / 16;

    let pb = setup_progress(if cfg!(feature = "mmap") { 1 } else { 0 }, quiet);

    let results: std::sync::Mutex<Vec<CrackResult>> = std::sync::Mutex::new(Vec::new());
    let line_count = AtomicU64::new(0);
    let cracked_count = AtomicU64::new(0);
    let progress = ProgressStats::new();

    #[cfg(feature = "mmap")]
    if let Some(ref mmap) = chunks {
        // mmap fast path: split memory into lines in parallel
        let ptr = mmap.as_ptr();
        let _len = mmap.len();

        let lines: Vec<&[u8]> = mmap
            .split(|b| *b == b'\n')
            .collect();

        let plines: Vec<&[u8]> = lines.into_par_iter()
            .filter(|l| !l.is_empty())
            .collect();

        let pbar = pb.as_ref();
        let cr = &results;
        let lc = &line_count;
        let cc = &cracked_count;
        let pr = &progress;

        plines.into_par_iter().for_each(|line_bytes| {
            let word = match std::str::from_utf8(line_bytes) {
                Ok(s) => s.trim().to_string(),
                Err(_) => return,
            };
            if word.is_empty() { return; }

            let mut local_results = Vec::new();

            for entry in hashes.iter() {
                if cracker.verify(&word, entry) {
                    local_results.push(CrackResult {
                        original: entry.raw.clone(),
                        hash_type: cracker.name().to_string(),
                        password: Some(word.clone()),
                    });
                    cc.fetch_add(1, Ordering::Relaxed);
                }
            }

            if let Some(rules) = &rules {
                for rule_str in rules {
                    match parse_rule(rule_str) {
                        Ok(ops) => {
                            for mutated in apply_rule(&word, &ops) {
                                for entry in hashes.iter() {
                                    if cracker.verify(&mutated, entry) {
                                        local_results.push(CrackResult {
                                            original: entry.raw.clone(),
                                            hash_type: cracker.name().to_string(),
                                            password: Some(mutated.clone()),
                                        });
                                    }
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }

            if !local_results.is_empty() {
                let mut all = cr.lock().unwrap();
                all.extend(local_results);
            }

            if let Some(ref pbar) = pbar {
                pbar.inc(1 + rule_count as u64);
            }
            lc.fetch_add(1, Ordering::Relaxed);

            #[cfg(feature = "progress-rich")]
            {
                pr.record_tested(1 + rule_count as u64);
                if lc.load(Ordering::Relaxed) % 10000 == 0 {
                    print_speed(pr);
                }
            }
        });

        #[cfg(feature = "progress-rich")]
        eprintln!();

        if let Some(ref pbar) = pb {
            pbar.finish_with_message("Done!");
        }
    } else {
        // Fallback: streaming via BufReader
        run_streaming(file, &rules, hashes, cracker, rule_count, total_hashes, &results, &line_count, &cracked_count, &progress, pb, quiet, word_count_hint);
    }

    #[cfg(not(feature = "mmap"))]
    run_streaming(file, &rules, hashes, cracker, rule_count, total_hashes, &results, &line_count, &cracked_count, &progress, pb, quiet, word_count_hint);

    let results = results.into_inner().unwrap();
    if !quiet {
        eprintln!("[*] Cracked {}/{} hashes", results.len(), total_hashes);
    }

    results
}

fn run_streaming(
    file: fs::File,
    rules: &Option<Vec<String>>,
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    rule_count: usize,
    _total_hashes: usize,
    results: &std::sync::Mutex<Vec<CrackResult>>,
    line_count: &AtomicU64,
    cracked_count: &AtomicU64,
    #[cfg(not(feature = "progress-rich"))] _progress: &ProgressStats,
    #[cfg(feature = "progress-rich")] progress: &ProgressStats,
    pb: Option<indicatif::ProgressBar>,
    quiet: bool,
    _word_count_hint: u64,
) {
    let reader = BufReader::new(file);

    if !quiet {
        eprintln!("[*] Streaming wordlist");
    }

    reader.lines()
        .par_bridge()
        .for_each(|line_result| {
            let word = match line_result {
                Ok(w) => w.trim().to_string(),
                Err(_) => return,
            };
            if word.is_empty() { return; }

            let mut local_results = Vec::new();

            for entry in hashes.iter() {
                if cracker.verify(&word, entry) {
                    local_results.push(CrackResult {
                        original: entry.raw.clone(),
                        hash_type: cracker.name().to_string(),
                        password: Some(word.clone()),
                    });
                    cracked_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            if let Some(rules) = rules {
                for rule_str in rules {
                    match parse_rule(rule_str) {
                        Ok(ops) => {
                            for mutated in apply_rule(&word, &ops) {
                                for entry in hashes.iter() {
                                    if cracker.verify(&mutated, entry) {
                                        local_results.push(CrackResult {
                                            original: entry.raw.clone(),
                                            hash_type: cracker.name().to_string(),
                                            password: Some(mutated.clone()),
                                        });
                                    }
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }

            if !local_results.is_empty() {
                let mut all = results.lock().unwrap();
                all.extend(local_results);
            }

            if let Some(ref pb) = pb {
                pb.inc(1 + rule_count as u64);
            }
            line_count.fetch_add(1, Ordering::Relaxed);

            #[cfg(feature = "progress-rich")]
            {
                progress.record_tested(1 + rule_count as u64);
                if line_count.load(Ordering::Relaxed) % 10000 == 0 {
                    print_speed(progress);
                }
            }
        });

    #[cfg(feature = "progress-rich")]
    eprintln!();

    if let Some(ref pb) = pb {
        pb.finish_with_message("Done!");
    }
}
