use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, setup_progress, ProgressStats};
use crate::attack::rules::engine::{parse_rule, apply_rule, RuleOp};
use crate::attack::rules::load_rules;

#[cfg(feature = "mmap")]
use memmap2::Mmap;

#[cfg(feature = "progress-rich")]
fn print_speed(stats: &ProgressStats) {
    let rate = stats.hash_rate();
    let eta = stats.eta();
    eprint!("\r[*] {} H/s | {} cracked | {}", rate, stats.cracked(), eta);
}

/// Runs a dictionary attack: hashes each word from a wordlist (optionally with rule-based
/// mangling) against the given cracker.
pub fn run_dictionary(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist_path: &str,
    rules_path: Option<&str>,
    _threads: usize,
    quiet: bool,
    low_mem: bool,
) -> Vec<CrackResult> {
    let rules: Option<Vec<Vec<RuleOp>>> = match rules_path {
        Some(path) => match load_rules(path) {
            Ok(rules_strs) => {
                let parsed: Vec<Vec<RuleOp>> = rules_strs
                    .iter()
                    .filter_map(|s| parse_rule(s).ok())
                    .collect();
                if !quiet {
                    eprintln!("[*] Loaded {} rules from {}", parsed.len(), path);
                }
                Some(parsed)
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
        let mmap = unsafe {
            // SAFETY: Mmap::map is safe because `file` is a valid open File handle
            // with read permissions. The returned mmap is read-only and its lifetime
            // is scoped to this function via the `chunks` local variable.
            Mmap::map(&file)
        };
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

    let results: std::sync::Mutex<Vec<CrackResult>> = std::sync::Mutex::new(Vec::with_capacity(hashes.len()));
    let line_count = AtomicU64::new(0);
    let cracked_count = AtomicU64::new(0);

    #[cfg(feature = "mmap")]
    if let Some(ref mmap) = chunks {
        let lines: Vec<&[u8]> = mmap
            .split(|b| *b == b'\n')
            .collect();

        let plines: Vec<&[u8]> = lines.into_par_iter()
            .filter(|l| !l.is_empty())
            .collect();

        let total_est = plines.len() as u64 * (1 + rule_count as u64);
        let progress = ProgressStats::new(total_est);
        let pb = setup_progress(total_est, quiet);

        let batch = WordBatch {
            hashes,
            cracker,
            rules: &rules,
            rule_count,
            results: &results,
            line_count: &line_count,
            cracked_count: &cracked_count,
            progress: &progress,
            pbar: pb.as_ref(),
        };

        plines.par_chunks(VERIFY_GROUP).for_each(|chunk| batch.verify_lines(chunk));

        #[cfg(feature = "progress-rich")]
        eprintln!();

        if let Some(ref pbar) = pb {
            pbar.finish_with_message("Done!");
        }
    } else {
        let total_est = (file_size / 16).max(1) * (1 + rule_count as u64);
        let progress = ProgressStats::new(total_est);
        let pb = setup_progress(total_est, quiet);
        run_streaming(file, &rules, hashes, cracker, rule_count, total_hashes, &results, &line_count, &cracked_count, &progress, pb, quiet, word_count_hint, low_mem);
    }

    #[cfg(not(feature = "mmap"))]
    {
        let total_est = word_count_hint.max(1) * (1 + rule_count as u64);
        let progress = ProgressStats::new(total_est);
        let pb = setup_progress(total_est, quiet);
        run_streaming(file, &rules, hashes, cracker, rule_count, total_hashes, &results, &line_count, &cracked_count, &progress, pb, quiet, word_count_hint, low_mem);
    }

    let results = results.into_inner().unwrap_or_else(|_| Vec::new());
    if !quiet {
        eprintln!("[*] Cracked {}/{} hashes", results.len(), total_hashes);
    }

    results
}

/// Candidate group size handed to [`HashCracker::verify_batch`].
///
/// One traversal of the target list then pays one batched call per target
/// instead of one call per candidate, which is what lets a multi-buffer kernel
/// see eight candidates per pass. Measured on this host with the NTLM kernel, a
/// group of 512 candidates ran at 1.4x the per candidate path and a group of
/// eight at 0.9x, where the fixed cost of a batched call is not amortised yet.
const VERIFY_GROUP: usize = 512;

/// Lines read from a streamed wordlist before the block is verified in parallel.
///
/// The streaming path has no group of its own, so batching there requires
/// accumulating lines first. 8192 lines is large enough for the chunks inside a
/// block to be evenly sized and small enough that the block stays a rounding
/// error next to the file.
const STREAM_BLOCK: usize = 8192;

/// Shared state for verifying a group of candidates against every target.
///
/// Both wordlist paths use this, so the batching, the progress accounting and
/// the match recording exist once. The mmap path hands it a group of raw line
/// bytes, the streaming path a group of already decoded lines.
struct WordBatch<'a> {
    hashes: &'a [HashEntry],
    cracker: &'a dyn HashCracker,
    rules: &'a Option<Vec<Vec<RuleOp>>>,
    rule_count: usize,
    results: &'a std::sync::Mutex<Vec<CrackResult>>,
    line_count: &'a AtomicU64,
    cracked_count: &'a AtomicU64,
    /// Only read under `progress-rich`, which is the only build that prints a
    /// live rate.
    #[cfg_attr(not(feature = "progress-rich"), allow(dead_code))]
    progress: &'a ProgressStats,
    pbar: Option<&'a indicatif::ProgressBar>,
}

impl WordBatch<'_> {
    /// Decodes a group of raw wordlist lines and verifies it.
    ///
    /// Only the mmap path has raw line bytes to decode; the streaming path hands
    /// [`WordBatch::verify_group`] lines it has already decoded.
    #[cfg(feature = "mmap")]
    fn verify_lines(&self, lines: &[&[u8]]) {
        let mut words: Vec<&str> = Vec::with_capacity(lines.len());
        for line in lines {
            if let Ok(text) = std::str::from_utf8(line) {
                let text = text.trim();
                if !text.is_empty() {
                    words.push(text);
                }
            }
        }
        self.verify_group(&words);
    }

    /// Verifies one group of decoded candidates against every target.
    ///
    /// Both the raw candidates and every rule mangled candidate go through
    /// [`HashCracker::verify_batch`], so a cracker with a vector kernel sees a
    /// whole group per call. Crackers without one keep the per candidate
    /// behaviour, because that method's default implementation calls `verify` in
    /// a loop and returns the same matches.
    fn verify_group(&self, words: &[&str]) {
        if words.is_empty() {
            return;
        }

        // A cracker that reports it cannot compute this hash never returns a
        // match, so the whole group is skipped rather than hashed.
        if self.cracker.is_verifiable() {
            let name = self.cracker.name();
            let mut local: Vec<CrackResult> = Vec::new();

            for entry in self.hashes {
                for hit in self.cracker.verify_batch(words, entry) {
                    local.push(CrackResult {
                        original: entry.raw.clone(),
                        hash_type: name.to_string(),
                        password: Some(hit.to_string()),
                    });
                    self.cracked_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            if let Some(rules) = self.rules {
                let mut mutated: Vec<String> = Vec::new();
                for ops in rules {
                    for word in words {
                        mutated.extend(apply_rule(word, ops));
                    }
                }
                let refs: Vec<&str> = mutated.iter().map(|s| s.as_str()).collect();
                for entry in self.hashes {
                    for hit in self.cracker.verify_batch(&refs, entry) {
                        local.push(CrackResult {
                            original: entry.raw.clone(),
                            hash_type: name.to_string(),
                            password: Some(hit.to_string()),
                        });
                    }
                }
            }

            if !local.is_empty() {
                let mut all = self.results.lock().unwrap();
                all.extend(local);
            }
        }

        self.account(words.len() as u64);
    }

    /// Records progress for a group of `n` candidates.
    fn account(&self, n: u64) {
        let units = n * (1 + self.rule_count as u64);
        if let Some(pb) = self.pbar {
            pb.inc(units);
        }
        let before = self.line_count.fetch_add(n, Ordering::Relaxed);
        #[cfg(not(feature = "progress-rich"))]
        let _ = before;

        #[cfg(feature = "progress-rich")]
        {
            self.progress.record_tested(units);
            // The rate line prints when the line count crosses a multiple of
            // 10000. A group moves the count by more than one, so testing for an
            // exact multiple would skip the boundary and the line would stop
            // appearing once groups are used.
            if before / 10_000 != (before + n) / 10_000 {
                print_speed(self.progress);
            }
        }
    }
}

fn run_streaming(
    file: fs::File,
    rules: &Option<Vec<Vec<RuleOp>>>,
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    rule_count: usize,
    _total_hashes: usize,
    results: &std::sync::Mutex<Vec<CrackResult>>,
    line_count: &AtomicU64,
    cracked_count: &AtomicU64,
    progress: &ProgressStats,
    pb: Option<indicatif::ProgressBar>,
    quiet: bool,
    _word_count_hint: u64,
    low_mem: bool,
) {
    let buf_cap = if low_mem { 4096 } else { 8192 };
    let reader = BufReader::with_capacity(buf_cap, file);

    if !quiet {
        eprintln!("[*] Streaming wordlist{}", if low_mem { " (low-mem mode)" } else { "" });
    }

    let batch = WordBatch {
        hashes,
        cracker,
        rules,
        rule_count,
        results,
        line_count,
        cracked_count,
        progress,
        pbar: pb.as_ref(),
    };

    // Lines are accumulated into blocks and each block is then verified in
    // parallel. The previous shape bridged the line iterator straight into rayon
    // with `par_bridge`, which hands one candidate to one worker at a time and
    // therefore has no group to give a batch verifier, so nothing in this path
    // could be accelerated.
    let mut block: Vec<String> = Vec::with_capacity(STREAM_BLOCK);
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        let word = line.trim();
        if word.is_empty() {
            continue;
        }
        block.push(word.to_string());
        if block.len() == STREAM_BLOCK {
            verify_block(&batch, &block);
            block.clear();
        }
    }
    if !block.is_empty() {
        verify_block(&batch, &block);
    }

    #[cfg(feature = "progress-rich")]
    eprintln!();

    if let Some(ref pb) = pb {
        pb.finish_with_message("Done!");
    }
}

/// Verifies one block of decoded lines, one group at a time, in parallel.
fn verify_block(batch: &WordBatch<'_>, block: &[String]) {
    block.par_chunks(VERIFY_GROUP).for_each(|chunk| {
        let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        batch.verify_group(&refs);
    });
}
