pub mod dictionary;
pub mod brute;
pub mod combinator;
pub mod mask;
pub mod rules;
pub mod prince;
pub mod session;
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
///
/// All counters are atomics because attacks run on the rayon pool while the
/// progress display reads from another thread.
pub struct ProgressStats {
    start: Instant,
    tested: AtomicU64,
    /// Number of hashes verified, which is `tested * hash_count` in practice.
    /// Tracked separately because a multi hash run does far more work per
    /// candidate than a single hash run, and conflating the two makes the rate
    /// meaningless.
    hashes: AtomicU64,
    cracked: AtomicU64,
    /// Total candidates, or `0` when the total is unknown.
    total: u64,
}

impl ProgressStats {
    /// Creates new progress tracking for a given total number of candidates.
    pub fn new(total: u64) -> Self {
        ProgressStats {
            start: Instant::now(),
            tested: AtomicU64::new(0),
            hashes: AtomicU64::new(0),
            cracked: AtomicU64::new(0),
            total,
        }
    }

    /// Records that `n` more password candidates have been tested.
    pub fn record_tested(&self, n: u64) {
        self.tested.fetch_add(n, Ordering::Relaxed);
    }

    /// Records that `n` hash verifications were performed.
    pub fn record_hashed(&self, n: u64) {
        self.hashes.fetch_add(n, Ordering::Relaxed);
    }

    /// Records that `n` hashes were cracked.
    pub fn record_cracked(&self, n: u64) {
        self.cracked.fetch_add(n, Ordering::Relaxed);
    }

    /// Returns the total number of candidates tested so far.
    pub fn total_tested(&self) -> u64 {
        self.tested.load(Ordering::Relaxed)
    }

    /// Returns the total number of hash verifications performed so far.
    pub fn total_hashed(&self) -> u64 {
        self.hashes.load(Ordering::Relaxed)
    }

    /// Elapsed wall clock time since construction.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    /// Hash verifications per second as a raw number.
    ///
    /// Falls back to candidates per second when no hash work has been recorded,
    /// so a caller that only calls `record_tested` still gets a usable figure.
    pub fn hash_rate_raw(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        let hashed = self.hashes.load(Ordering::Relaxed);
        let tested = self.tested.load(Ordering::Relaxed);
        if hashed > 0 {
            hashed as f64 / elapsed
        } else if tested > 0 {
            tested as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Returns the current rate as a human-readable string (e.g. "1.2 MH/s").
    pub fn hash_rate(&self) -> String {
        let rate = self.hash_rate_raw();
        if rate <= 0.0 {
            return "0 H/s".to_string();
        }
        format_rate(rate)
    }

    /// Estimated seconds remaining, or `None` when it cannot be computed.
    pub fn eta_secs(&self) -> Option<f64> {
        let total = self.total;
        let tested = self.total_tested();
        if total == 0 || tested == 0 {
            return None;
        }
        let remaining = total.saturating_sub(tested);
        if remaining == 0 {
            return Some(0.0);
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        // Use the average rate over the whole run. A short rolling window was
        // tried and rejected: it made the estimate jump around whenever the
        // scheduler paused, which is more distracting than a slightly stale
        // number.
        let rate = tested as f64 / elapsed;
        if rate <= 0.0 {
            return None;
        }
        Some(remaining as f64 / rate)
    }

    /// Returns the estimated time until completion as a human-readable string.
    pub fn eta(&self) -> String {
        match self.eta_secs() {
            None => "--:--:--".to_string(),
            Some(secs) => format_duration(secs),
        }
    }

    /// Returns the number of hashes cracked so far.
    ///
    /// This previously returned a hardcoded `0`, which made every progress
    /// display report zero cracks for the whole run.
    pub fn cracked(&self) -> u64 {
        self.cracked.load(Ordering::Relaxed)
    }
}

/// Formats a per second rate with a sensible unit.
pub fn format_rate(rate: f64) -> String {
    if rate >= 1_000_000_000.0 {
        format!("{:.2} GH/s", rate / 1_000_000_000.0)
    } else if rate >= 1_000_000.0 {
        format!("{:.1} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1} KH/s", rate / 1_000.0)
    } else {
        format!("{rate:.0} H/s")
    }
}

/// Formats a duration in seconds as a compact human readable string.
pub fn format_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--:--".to_string();
    }
    if secs >= 86_400.0 * 2.0 {
        return format!("{:.1}d", secs / 86_400.0);
    }
    if secs >= 3_600.0 {
        let h = (secs / 3_600.0).floor();
        let m = ((secs % 3_600.0) / 60.0).floor();
        return format!("{h:.0}h{m:.0}m");
    }
    let s = secs as u64;
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cracked_counter_is_not_hardcoded_zero() {
        let s = ProgressStats::new(1000);
        assert_eq!(s.cracked(), 0, "a fresh run starts at zero");
        s.record_cracked(3);
        assert_eq!(s.cracked(), 3, "record_cracked must be visible");
        s.record_cracked(2);
        assert_eq!(s.cracked(), 5);
    }

    #[test]
    fn tested_counter_accumulates() {
        let s = ProgressStats::new(100);
        s.record_tested(10);
        s.record_tested(15);
        assert_eq!(s.total_tested(), 25);
    }

    #[test]
    fn hashed_counter_accumulates() {
        let s = ProgressStats::new(100);
        s.record_hashed(7);
        assert_eq!(s.total_hashed(), 7);
    }

    #[test]
    fn eta_is_unknown_before_any_work() {
        let s = ProgressStats::new(1_000_000);
        assert_eq!(s.eta_secs(), None, "no rate means no estimate");
        assert_eq!(s.eta(), "--:--:--");
    }

    #[test]
    fn eta_is_zero_when_all_work_is_done() {
        let s = ProgressStats::new(10);
        s.record_tested(10);
        assert_eq!(s.eta_secs(), Some(0.0));
    }

    #[test]
    fn eta_never_exceeds_the_total_when_half_done() {
        let s = ProgressStats::new(100);
        s.record_tested(50);
        // Roughly half the work done, so roughly the elapsed time remains.
        let secs = s.eta_secs().expect("estimate available after work started");
        assert!(secs <= s.elapsed().as_secs_f64() * 1.5, "eta {secs} was implausible");
    }

    #[test]
    fn rate_formatting_uses_expected_units() {
        assert_eq!(format_rate(0.0), "0 H/s");
        assert_eq!(format_rate(999.0), "999 H/s");
        assert_eq!(format_rate(1_500.0), "1.5 KH/s");
        assert_eq!(format_rate(2_500_000.0), "2.5 MH/s");
        assert_eq!(format_rate(3_000_000_000.0), "3.00 GH/s");
    }

    #[test]
    fn duration_formatting_covers_units() {
        assert_eq!(format_duration(0.0), "00:00:00");
        assert_eq!(format_duration(59.0), "00:00:59");
        // Under an hour renders as hh:mm:ss.
        assert_eq!(format_duration(3_599.0), "00:59:59");
        // One hour and above switches to a compact form.
        assert_eq!(format_duration(3_600.0), "1h0m");
        assert_eq!(format_duration(3_661.0), "1h1m");
        assert_eq!(format_duration(200_000.0), "2.3d");
        assert_eq!(format_duration(f64::NAN), "--:--:--");
        assert_eq!(format_duration(-1.0), "--:--:--");
    }
}
