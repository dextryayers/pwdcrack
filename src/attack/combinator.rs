use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, ProgressStats};

#[cfg(feature = "mmap")]
use memmap2::Mmap;

#[cfg(feature = "progress-rich")]
fn print_speed(stats: &ProgressStats) {
    eprint!("\r[*] {} H/s | {} tested | {}", stats.hash_rate(), stats.total_tested(), stats.eta());
}

/// Runs a combinator attack: concatenates every word from wordlist1 with every word
/// from wordlist2 and tests each combination.
pub fn run_combinator(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist1: &str,
    wordlist2: &str,
    _threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    let words2 = load_wordlist(wordlist2);
    if words2.is_empty() {
        eprintln!("[!] Empty wordlist2");
        return Vec::new();
    }

    if !quiet {
        eprintln!("[*] Wordlist2: {} words", words2.len());
    }

    let w1_count = fs::File::open(Path::new(wordlist1)).ok().map(|f| {
        BufReader::new(f).lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .count() as u64
    }).unwrap_or(0);

    let file1 = match fs::File::open(Path::new(wordlist1)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist1: {}", e);
            return Vec::new();
        }
    };
    let reader = BufReader::new(file1);
    let total_hashes = hashes.len();
    let results: std::sync::Mutex<Vec<CrackResult>> = std::sync::Mutex::new(Vec::new());
    let line_count = AtomicU64::new(0);
    let total_est = w1_count * words2.len() as u64;
    #[cfg(feature = "progress-rich")]
    let progress = ProgressStats::new(total_est);
    #[cfg(not(feature = "progress-rich"))]
    let _progress = ProgressStats::new(total_est);

    if !quiet {
        eprintln!("[*] Wordlist1: streaming");
    }

    reader.lines()
        .par_bridge()
        .for_each(|line_result| {
            let w1 = match line_result {
                Ok(w) => w.trim().to_string(),
                Err(_) => return,
            };
            if w1.is_empty() { return; }

            let mut local = Vec::new();
            for w2 in &words2 {
                let combined = format!("{}{}", w1, w2);
                for entry in hashes.iter() {
                    if cracker.verify(&combined, entry) {
                        local.push(CrackResult {
                            original: entry.raw.clone(),
                            hash_type: cracker.name().to_string(),
                            password: Some(combined.clone()),
                        });
                    }
                }
            }

            if !local.is_empty() {
                let mut all = results.lock().unwrap();
                all.extend(local);
            }

            let tested = words2.len() as u64;
            #[cfg(not(feature = "progress-rich"))]
            let _tested = tested;
            line_count.fetch_add(1, Ordering::Relaxed);

            #[cfg(feature = "progress-rich")]
            {
                progress.record_tested(tested);
                if line_count.load(Ordering::Relaxed) % 1000 == 0 {
                    print_speed(&progress);
                }
            }
        });

    #[cfg(feature = "progress-rich")]
    eprintln!();

    let results = results.into_inner().unwrap_or_else(|_| Vec::new());
    if !quiet {
        eprintln!("[*] Cracked {}/{} hashes", results.len(), total_hashes);
    }
    results
}

fn load_wordlist(path: &str) -> Vec<String> {
    #[cfg(feature = "mmap")]
    if let Ok(file) = fs::File::open(Path::new(path)) {
        if let Ok(mmap) = unsafe {
            // SAFETY: Mmap::map is safe because `file` is a valid open File handle
            // with read permissions. The returned mmap is read-only and its lifetime
            // is scoped to this function via the `chunks` local variable.
            Mmap::map(&file)
        } {
            let words: Vec<String> = mmap
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .filter_map(|l| std::str::from_utf8(l).ok())
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            return words;
        }
    }

    let file = match fs::File::open(Path::new(path)) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    BufReader::new(file).lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}
