//! engine-android — Android/Termux-specific optimizations
//!
//! - Termux environment detection
//! - Battery-aware cracking (pause on low battery)
//! - Storage Access Framework (SAF) for file access
//! - Thermal throttling detection
//! - NEON SIMD for ARM64/ARM32

pub mod termux;
pub mod saf;
pub mod thermal;

use std::sync::atomic::AtomicBool;

pub struct AndroidEnv {
    pub is_termux: bool,
    pub has_saf: bool,
    pub data_dir: String,
    pub thermal_limited: AtomicBool,
}

impl AndroidEnv {
    /// Detect Android/Termux environment
    pub fn detect() -> Self {
        let is_termux = std::env::var("TERMUX_VERSION").is_ok();
        let data_dir = if is_termux {
            "/data/data/com.termux/files/home".to_string()
        } else {
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
        };

        AndroidEnv {
            is_termux,
            has_saf: false,
            data_dir,
            thermal_limited: AtomicBool::new(false),
        }
    }

    pub fn is_android() -> bool {
        cfg!(target_os = "android")
    }

    pub fn info(&self) -> String {
        format!(
            "Android: termux={}, data_dir={}",
            self.is_termux,
            self.data_dir,
        )
    }
}
