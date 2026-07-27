use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, setup_progress};

pub fn run_combinator(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist1: &str,
    wordlist2: &str,
    threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    let file1 = match fs::File::open(Path::new(wordlist1)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist1: {}", e);
            return Vec::new();
        }
    };
    let file2 = match fs::File::open(Path::new(wordlist2)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open wordlist2: {}", e);
            return Vec::new();
        }
    };

    let words1: Vec<String> = BufReader::new(file1).lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let words2: Vec<String> = BufReader::new(file2).lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let total = words1.len().saturating_mul(words2.len());

    if !quiet {
        eprintln!("[*] Wordlist1: {} words", words1.len());
        eprintln!("[*] Wordlist2: {} words", words2.len());
        eprintln!("[*] Total combinations: {}", total);
    }

    let pb = setup_progress(total as u64, quiet);

    let results: Vec<CrackResult> = words1.par_iter()
        .with_max_len(if threads == 0 { 1 } else { words1.len() / threads + 1 })
        .flat_map(|w1| {
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
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
            }
            local
        })
        .collect();

    if let Some(ref pb) = pb {
        pb.finish_with_message("Done!");
    }

    results
}
