pub mod rapl;
pub mod amd;
pub mod gpu_power;
pub mod governor;
pub mod battery;
pub mod cstate;
pub mod stats;
pub mod budget;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkloadType {
    ComputeBound,
    MemoryBound,
    Mixed,
    GpuOffload,
    Idle,
}

impl WorkloadType {
    pub fn freq_ratio(&self) -> f64 {
        match self {
            Self::ComputeBound => 1.0,
            Self::MemoryBound => 0.3,
            Self::Mixed => 0.6,
            Self::GpuOffload => 0.1,
            Self::Idle => 0.0,
        }
    }
}

pub struct PowerManager {
    pub stats: stats::PowerStats,
    budget: budget::PowerBudget,
    last_rapl_uj: AtomicU64,
    last_amd_uj: AtomicU64,
    has_rapl: bool,
    has_amd: bool,
    has_gpu_power: bool,
    workload: std::sync::Mutex<WorkloadType>,
    monitor_active: AtomicU64,
}

impl PowerManager {
    pub fn new(power_budget_watts: f64) -> Self {
        let has_rapl = rapl::is_available();
        let has_amd = amd::is_available();
        let has_gpu = matches!(gpu_power::detect_source(), gpu_power::GpuPowerSource::Amd | gpu_power::GpuPowerSource::Nvidia);

        let initial_uj = if has_rapl {
            rapl::read_energy_uj().unwrap_or(0)
        } else if has_amd {
            amd::read_energy_uj().unwrap_or(0)
        } else {
            0
        };

        PowerManager {
            stats: stats::PowerStats::new(),
            budget: if power_budget_watts > 0.0 {
                budget::PowerBudget::new(power_budget_watts)
            } else {
                budget::PowerBudget::disabled()
            },
            last_rapl_uj: AtomicU64::new(initial_uj),
            last_amd_uj: AtomicU64::new(initial_uj),
            has_rapl,
            has_amd,
            has_gpu_power: has_gpu,
            workload: std::sync::Mutex::new(WorkloadType::MemoryBound),
            monitor_active: AtomicU64::new(0),
        }
    }

    pub fn sample(&self) {
        if self.has_rapl {
            if let Some(uj) = rapl::read_energy_uj() {
                let prev = self.last_rapl_uj.swap(uj, Ordering::Relaxed);
                let delta_uj = if uj >= prev { uj - prev } else { u64::MAX - prev + uj };
                self.stats.record_energy(delta_uj);
            }
        } else if self.has_amd {
            if let Some(uj) = amd::read_energy_uj() {
                let prev = self.last_amd_uj.swap(uj, Ordering::Relaxed);
                let delta_uj = if uj >= prev { uj - prev } else { u64::MAX - prev + uj };
                self.stats.record_energy(delta_uj);
            }
        }

        let watts = self.stats.current_watts();
        self.budget.update(watts);
    }

    pub fn set_workload(&self, workload: WorkloadType) {
        *self.workload.lock().unwrap() = workload;
        governor::apply_workload_policy(workload);
        self.budget.enforce(workload);
    }

    pub fn record_hashes(&self, count: u64) {
        self.stats.record_hashes(count);
    }

    pub fn report(&self) -> String {
        let mut parts = vec![self.stats.report()];
        if self.has_rapl {
            parts.push("RAPL".to_string());
        }
        if self.has_amd {
            parts.push("AMD".to_string());
        }
        if self.has_gpu_power {
            parts.push("GPU".to_string());
        }
        if self.budget.max_watts() < f64::MAX / 2.0 {
            parts.push(format!("budget {:.0}W", self.budget.max_watts()));
        }
        if self.budget.is_exceeded() {
            parts.push("THROTTLED".to_string());
        }
        format!("[{}]", parts.join(", "))
    }

    pub fn current_workload(&self) -> WorkloadType {
        *self.workload.lock().unwrap()
    }

    pub fn has_power_monitoring(&self) -> bool {
        self.has_rapl || self.has_amd || self.has_gpu_power
    }

    pub fn start_monitor_thread(self: &Arc<Self>, interval_ms: u64) {
        if self.monitor_active.fetch_add(1, Ordering::Relaxed) > 0 {
            return;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(interval_ms));
                this.sample();
            }
        });
    }
}
