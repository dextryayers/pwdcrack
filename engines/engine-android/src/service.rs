//! Background service mode — continuous cracking without TUI
//! Designed for Termux:Background to keep running after terminal closes

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct BackgroundService {
    pub running: Arc<AtomicBool>,
    pub paused: Arc<AtomicBool>,
}

impl BackgroundService {
    pub fn new() -> Self {
        BackgroundService {
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_background_mode() -> bool {
        std::env::var("PWDCRACK_BACKGROUND").is_ok()
            || std::env::var("TERMUX_BACKGROUND").is_ok()
    }

    pub fn pid_file_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.pwdcrack.pid", home)
    }

    pub fn write_pid() -> Option<()> {
        let pid = std::process::id().to_string();
        std::fs::write(Self::pid_file_path(), &pid).ok()
    }

    pub fn remove_pid() {
        let _ = std::fs::remove_file(Self::pid_file_path());
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        log::info!("Background service paused");
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
        log::info!("Background service resumed");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        log::info!("Background service stopping");
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn start_monitor(self: &Arc<Self>) {
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            // Monitor stdin: if pipe breaks (terminal closed), continue running
            loop {
                if !this.is_running() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }
}
