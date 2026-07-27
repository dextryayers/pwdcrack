pub mod dictionary;
pub mod brute;
pub mod combinator;
pub mod rules;

use indicatif::{ProgressBar, ProgressStyle};

pub struct CrackResult {
    pub original: String,
    pub hash_type: String,
    pub password: Option<String>,
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
