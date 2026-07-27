use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, setup_progress};
use crate::attack::rules::engine::{parse_rule, apply_rule};
use crate::attack::rules::load_rules;

pub fn run_dictionary(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist_path: &str,
    rules_path: Option<&str>,
    threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    let _rules = match rules_path {
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

    let reader = BufReader::new(file);
    let words: Vec<String> = reader.lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let total_base = words.len();
    let total = match &_rules {
        Some(r) => total_base * (1 + r.len()),
        None => total_base,
    };

    if !quiet {
        eprintln!("[*] Loaded {} words from {}", words.len(), wordlist_path);
        eprintln!("[*] Total candidates: {}", total);
    }

    let pb = setup_progress(total as u64, quiet);
    let total_hashes = hashes.len();

    let results: Vec<CrackResult> = words.par_iter()
        .with_max_len(if threads == 0 { 1 } else { total_base / threads + 1 })
        .flat_map(|word| {
            let mut local_results = Vec::new();

            for entry in hashes.iter() {
                if cracker.verify(word, entry) {
                    local_results.push(CrackResult {
                        original: entry.raw.clone(),
                        hash_type: cracker.name().to_string(),
                        password: Some(word.clone()),
                    });
                }
            }

            if let Some(rules) = &_rules {
                for rule_str in rules {
                    match parse_rule(rule_str) {
                        Ok(ops) => {
                            for mutated in apply_rule(word, &ops) {
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

            if let Some(ref pb) = pb {
                pb.inc(1);
            }

            local_results
        })
        .collect();

    if let Some(ref pb) = pb {
        pb.finish_with_message("Done!");
    }

    if !quiet {
        eprintln!("[*] Cracked {}/{} hashes", results.len(), total_hashes);
    }

    results
}
