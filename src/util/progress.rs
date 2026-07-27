use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct Progress {
    bar: Option<ProgressBar>,
}

impl Progress {
    pub fn new(total: u64, quiet: bool) -> Self {
        if quiet {
            return Progress { bar: None };
        }
        let bar = ProgressBar::new(total);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));
        Progress { bar: Some(bar) }
    }

    pub fn inc(&self, n: u64) {
        if let Some(ref bar) = self.bar {
            bar.inc(n);
        }
    }

    pub fn set_message(&self, msg: &str) {
        if let Some(ref bar) = self.bar {
            bar.set_message(msg.to_string());
        }
    }

    pub fn finish(&self) {
        if let Some(ref bar) = self.bar {
            bar.finish_and_clear();
        }
    }

    pub fn finish_with_message(&self, msg: &str) {
        if let Some(ref bar) = self.bar {
            bar.finish_with_message(msg.to_string());
        }
    }
}
