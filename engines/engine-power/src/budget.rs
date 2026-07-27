//! Power budget enforcement — limit power consumption to user-specified max

use crate::WorkloadType;
use crate::governor;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct PowerBudget {
    max_watts: f64,
    current_watts: AtomicU64,
    enabled: bool,
}

impl PowerBudget {
    pub fn new(max_watts: f64) -> Self {
        PowerBudget {
            max_watts,
            current_watts: AtomicU64::new(0),
            enabled: max_watts > 0.0,
        }
    }

    pub fn disabled() -> Self {
        PowerBudget {
            max_watts: f64::MAX,
            current_watts: AtomicU64::new(0),
            enabled: false,
        }
    }

    pub fn update(&self, measured_watts: f64) {
        self.current_watts.store(measured_watts as u64, Ordering::Relaxed);
        if !self.enabled || measured_watts <= self.max_watts {
            return;
        }

        let over_pct = measured_watts / self.max_watts;
        let ratio = (1.0 / over_pct).clamp(0.1, 1.0);

        let min_freq = governor::min_frequency().unwrap_or(800_000);
        let max_freq = governor::max_frequency().unwrap_or(3_000_000);
        let target = min_freq as f64 + (max_freq - min_freq) as f64 * ratio;
        let _ = governor::set_frequency(target as u64);

        log::warn!(
            "Power budget {:.0}W exceeded ({:.0}W). Throttling to {:.0}% freq.",
            self.max_watts,
            measured_watts,
            ratio * 100.0,
        );
    }

    pub fn enforce(&self, _workload: WorkloadType) {
        if !self.enabled {
            return;
        }
        let measured = self.current_watts.load(Ordering::Relaxed) as f64;
        self.update(measured);
    }

    pub fn is_exceeded(&self) -> bool {
        self.enabled && self.current_watts.load(Ordering::Relaxed) as f64 > self.max_watts
    }

    pub fn max_watts(&self) -> f64 {
        self.max_watts
    }
}
