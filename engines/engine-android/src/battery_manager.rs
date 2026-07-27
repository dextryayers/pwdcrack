//! Battery-aware cracking modes — pause/resume based on battery level

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryMode {
    Normal,    // >50% — full speed
    Eco,       // 20-50% — single thread, freq cap
    Critical,  // <20% — paused, save session
    Charging,  // Plugged in — full speed
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerSource {
    Battery,
    Charging,
    AcPower,
}

pub struct BatteryManager {
    pub mode: Arc<std::sync::Mutex<BatteryMode>>,
    pub paused: Arc<AtomicBool>,
    last_capacity: std::sync::Mutex<u8>,
}

impl BatteryManager {
    pub fn new() -> Self {
        BatteryManager {
            mode: Arc::new(std::sync::Mutex::new(BatteryMode::Charging)),
            paused: Arc::new(AtomicBool::new(false)),
            last_capacity: std::sync::Mutex::new(100),
        }
    }

    fn read_capacity() -> Option<u8> {
        let path = "/sys/class/power_supply/battery/capacity";
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    fn read_status() -> String {
        let path = "/sys/class/power_supply/battery/status";
        std::fs::read_to_string(path).ok().unwrap_or_default().trim().to_string()
    }

    fn detect_source() -> PowerSource {
        match Self::read_status().as_str() {
            "Charging" => PowerSource::Charging,
            "Full" => PowerSource::AcPower,
            _ => PowerSource::Battery,
        }
    }

    pub fn update(&self) -> BatteryMode {
        let source = Self::detect_source();
        let mode = match source {
            PowerSource::Charging | PowerSource::AcPower => BatteryMode::Charging,
            PowerSource::Battery => {
                match Self::read_capacity() {
                    Some(cap) if cap < 10 => {
                        self.paused.store(true, Ordering::Relaxed);
                        BatteryMode::Critical
                    }
                    Some(cap) if cap < 30 => {
                        self.paused.store(false, Ordering::Relaxed);
                        BatteryMode::Eco
                    }
                    Some(_) => {
                        self.paused.store(false, Ordering::Relaxed);
                        BatteryMode::Normal
                    }
                    None => BatteryMode::Charging,
                }
            }
        };
        *self.mode.lock().unwrap() = mode;
        mode
    }

    pub fn current_mode(&self) -> BatteryMode {
        *self.mode.lock().unwrap()
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> u8 {
        Self::read_capacity().unwrap_or(100)
    }

    pub fn start_monitor_thread(self: &Arc<Self>, interval_secs: u64) {
        let this = Arc::clone(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(interval_secs));
            let mode = this.update();
            log::info!("Battery mode: {:?}, capacity: {}%", mode, this.capacity());
        });
    }

    pub fn recommended_threads(&self) -> usize {
        match self.current_mode() {
            BatteryMode::Charging | BatteryMode::Normal => {
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
            }
            BatteryMode::Eco => 1,
            BatteryMode::Critical => 0,
        }
    }

    pub fn freq_ratio(&self) -> f64 {
        match self.current_mode() {
            BatteryMode::Charging => 1.0,
            BatteryMode::Normal => 0.8,
            BatteryMode::Eco => 0.2,
            BatteryMode::Critical => 0.0,
        }
    }
}
