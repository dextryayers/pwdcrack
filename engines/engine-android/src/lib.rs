pub mod termux;
pub mod saf;
pub mod thermal;
pub mod battery_manager;
pub mod session;
pub mod notification;
pub mod service;
pub mod limits;

use std::sync::atomic::{AtomicBool};
use std::sync::Arc;
use std::time::Duration;

pub struct AndroidEngine {
    pub env: AndroidEnv,
    pub battery: Arc<battery_manager::BatteryManager>,
    pub session: session::SessionManager,
    pub limits: limits::AndroidLimits,
    pub bg_service: service::BackgroundService,
    has_termux_notifications: bool,
    last_notification_time: std::sync::Mutex<std::time::Instant>,
}

pub struct AndroidEnv {
    pub is_termux: bool,
    pub has_saf: bool,
    pub data_dir: String,
    pub thermal_limited: AtomicBool,
}

impl AndroidEnv {
    pub fn detect() -> Self {
        let is_termux = termux::is_termux();
        let data_dir = if is_termux {
            termux::termux_home()
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
            self.is_termux, self.data_dir,
        )
    }
}

impl AndroidEngine {
    pub fn new() -> Self {
        let env = AndroidEnv::detect();
        let has_nt = std::process::Command::new("termux-notification")
            .arg("--help")
            .output()
            .is_ok();

        AndroidEngine {
            battery: Arc::new(battery_manager::BatteryManager::new()),
            session: session::SessionManager::new(None, 30),
            limits: limits::AndroidLimits::detect(),
            bg_service: service::BackgroundService::new(),
            env,
            has_termux_notifications: has_nt,
            last_notification_time: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    pub fn init(&mut self) {
        if self.env.is_termux {
            log::info!("Termux detected: {}", self.env.data_dir);
            log::info!("RAM limit: {}", self.limits.info());
            self.battery.update();
            self.session.load_or_create();
            service::BackgroundService::write_pid();
        }
    }

    pub fn shutdown(&mut self) {
        self.session.save();
        service::BackgroundService::remove_pid();
    }

    pub fn on_crack_found(&self, password: &str, hash: &str, hash_type: &str) {
        if self.has_termux_notifications {
            notification::AndroidNotification::notify_cracked(password, hash, hash_type);
        }
        log::info!("CRACKED: {} [{}] ← {}", hash, hash_type, password);
    }

    pub fn should_throttle(&self) -> bool {
        let thermal = thermal::check_thermal_status();
        let battery_mode = self.battery.current_mode();

        if thermal == thermal::ThermalStatus::Critical {
            log::warn!("Thermal critical! Pausing.");
            return true;
        }
        if battery_mode == battery_manager::BatteryMode::Critical {
            log::warn!("Battery critical! Pausing.");
            return true;
        }
        if thermal == thermal::ThermalStatus::Hot {
            return true;
        }

        thermal == thermal::ThermalStatus::Warm && battery_mode != battery_manager::BatteryMode::Charging
    }

    pub fn throttle_reason(&self) -> Option<String> {
        let thermal = thermal::check_thermal_status();
        let battery_mode = self.battery.current_mode();

        if thermal == thermal::ThermalStatus::Critical {
            return Some("thermal critical".to_string());
        }
        if battery_mode == battery_manager::BatteryMode::Critical {
            return Some("battery critical".to_string());
        }
        if thermal == thermal::ThermalStatus::Hot {
            return Some("thermal hot".to_string());
        }
        if thermal == thermal::ThermalStatus::Warm && battery_mode != battery_manager::BatteryMode::Charging {
            return Some("thermal warm + battery".to_string());
        }
        None
    }

    pub fn recommended_threads(&self) -> usize {
        let battery_threads = self.battery.recommended_threads();
        let limit_threads = self.limits.recommended_threads();
        battery_threads.min(limit_threads)
    }

    pub fn start_battery_monitor(self: &Arc<Self>, interval_secs: u64) {
        let this = Arc::clone(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(interval_secs));
            let mode = this.battery.update();
            let thermal = thermal::check_thermal_status();
            log::debug!(
                "Android: battery={:?}, capacity={}%, thermal={:?}",
                mode, this.battery.capacity(), thermal
            );
        });
    }

    pub fn info(&self) -> String {
        format!(
            "termux={}, battery={:?}, capacity={}%, thermal={:?}, RAM={}MB, {}",
            self.env.is_termux,
            self.battery.current_mode(),
            self.battery.capacity(),
            thermal::check_thermal_status(),
            self.limits.total_ram_mb,
            self.limits.info(),
        )
    }
}
