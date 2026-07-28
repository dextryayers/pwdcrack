pub mod dictionary;
pub mod brute;
pub mod combinator;
pub mod rules;
pub mod prince;
pub mod toggle;
pub mod substitute;

use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};

use indicatif::{ProgressBar, ProgressStyle};

/// The result of cracking a single hash.
pub struct CrackResult {
    /// The original hash string that was cracked.
    pub original: String,
    /// The name of the hash type (e.g. "MD5", "NTLM").
    pub hash_type: String,
    /// The recovered plaintext password, or `None` if not cracked.
    pub password: Option<String>,
}

/// Tracks attack progress, hash rate, and estimated time remaining.
pub struct ProgressStats {
    start: Instant,
    tested: AtomicU64,
    total: u64,
}

impl ProgressStats {
    /// Creates new progress tracking for a given total number of candidates.
    pub fn new(total: u64) -> Self {
        ProgressStats {
            start: Instant::now(),
            tested: AtomicU64::new(0),
            total,
        }
    }

    /// Records that `n` more password candidates have been tested.
    pub fn record_tested(&self, n: u64) {
        self.tested.fetch_add(n, Ordering::Relaxed);
    }

    /// Returns the total number of candidates tested so far.
    pub fn total_tested(&self) -> u64 {
        self.tested.load(Ordering::Relaxed)
    }

    /// Returns the current hash rate as a human-readable string (e.g. "1.2 MH/s").
    pub fn hash_rate(&self) -> String {
        let tested = self.tested.load(Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed < 0.01 {
            return "0 H/s".to_string();
        }
        let rate = tested as f64 / elapsed;
        if rate > 1_000_000.0 {
            format!("{:.1} MH/s", rate / 1_000_000.0)
        } else if rate > 1_000.0 {
            format!("{:.1} KH/s", rate / 1_000.0)
        } else {
            format!("{:.0} H/s", rate)
        }
    }

    /// Returns the estimated time until completion as a human-readable string.
    pub fn eta(&self) -> String {
        let tested = self.tested.load(Ordering::Relaxed);
        let remaining = self.total.saturating_sub(tested);
        if remaining == 0 || self.total == 0 {
            return "00:00:00".to_string();
        }
        if tested == 0 {
            return "--:--:--".to_string();
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        let rate = tested as f64 / elapsed;
        if rate < 1.0 {
            return "--:--:--".to_string();
        }
        let remaining_secs = remaining as f64 / rate;
        if remaining_secs > 86400.0 {
            format!("{:.1}d", remaining_secs / 86400.0)
        } else if remaining_secs > 3600.0 {
            format!("{:.1}h", remaining_secs / 3600.0)
        } else {
            let secs = remaining_secs as u64;
            format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
        }
    }

    /// Returns the number of hashes cracked so far.
    pub fn cracked(&self) -> u64 {
        0
    }
}

/// Creates a progress bar for the given total, or returns `None` if quiet mode is on.
pub fn setup_progress(total: u64, quiet: bool) -> Option<ProgressBar> {
    if quiet {
        return None;
    }
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    Some(pb)
}
