use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::CrackResult;

pub fn run_combinator(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist1: &str,
    wordlist2: &str,
    threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    // For combinator, we must load wordlist2 fully (inner loop needs random access)
    // But wordlist1 can stream
    let file2 = match fs::File::open(Path::new(wordlist2)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist2: {}", e);
            return Vec::new();
        }
    };

    let words2: Vec<String> = BufReader::new(file2).lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let file1 = match fs::File::open(Path::new(wordlist1)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist1: {}", e);
            return Vec::new();
        }
    };

    let reader = BufReader::new(file1);

    if !quiet {
        eprintln!("[*] Wordlist2: {} words (loaded)", words2.len());
        eprintln!("[*] Wordlist1: streaming");
    }

    let results: std::sync::Mutex<Vec<CrackResult>> = std::sync::Mutex::new(Vec::new());
    let total_hashes = hashes.len();

    reader.lines()
        .par_bridge()
        .for_each(|line_result| {
            let w1 = match line_result {
                Ok(w) => w.trim().to_string(),
                Err(_) => return,
            };
            if w1.is_empty() {
                return;
            }

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
        });

    let results = results.into_inner().unwrap();

    if !quiet {
        eprintln!("[*] Cracked {}/{} hashes", results.len(), total_hashes);
    }

    results
}
