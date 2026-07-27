pub mod dictionary;
pub mod brute;
pub mod combinator;
pub mod rules;

use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};

use indicatif::{ProgressBar, ProgressStyle};

pub struct CrackResult {
    pub original: String,
    pub hash_type: String,
    pub password: Option<String>,
}

pub struct ProgressStats {
    start: Instant,
    tested: AtomicU64,
    prev_tested: AtomicU64,
    prev_time: std::sync::Mutex<Instant>,
}

impl ProgressStats {
    pub fn new() -> Self {
        ProgressStats {
            start: Instant::now(),
            tested: AtomicU64::new(0),
            prev_tested: AtomicU64::new(0),
            prev_time: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn record_tested(&self, n: u64) {
        self.tested.fetch_add(n, Ordering::Relaxed);
    }

    pub fn total_tested(&self) -> u64 {
        self.tested.load(Ordering::Relaxed)
    }

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

    pub fn eta(&self) -> String {
        let tested = self.tested.load(Ordering::Relaxed);
        if tested == 0 {
            return "--:--:--".to_string();
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        let rate = tested as f64 / elapsed;
        if rate < 1.0 {
            return "--:--:--".to_string();
        }
        let remaining_secs = (u64::MAX - tested) as f64 / rate;
        if remaining_secs > 86400.0 {
            format!("{:.1}d", remaining_secs / 86400.0)
        } else if remaining_secs > 3600.0 {
            format!("{:.1}h", remaining_secs / 3600.0)
        } else {
            let secs = remaining_secs as u64;
            format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
        }
    }

    pub fn cracked(&self) -> u64 {
        0
    }
}

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
