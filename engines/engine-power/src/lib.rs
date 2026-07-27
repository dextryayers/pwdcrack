//! engine-power — Power management subsystem
//!
//! Monitors power consumption via RAPL (Intel) / AMD / hwmon,
//! dynamically scales CPU frequency based on workload type,
//! and enforces user-specified power budgets.

pub mod rapl;
pub mod governor;
pub mod battery;

use std::sync::atomic::AtomicU64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkloadType {
    ComputeBound, // bcrypt, Argon2, scrypt → high freq
    MemoryBound,  // dictionary, streaming → low freq
    Mixed,        // combinator → medium freq
    GpuOffload,   // GPU doing work → sleep CPU cores
    Idle,         // No work → deepest sleep
}

impl WorkloadType {
    /// Optimal frequency ratio (0.0 - 1.0) for this workload
    pub fn freq_ratio(&self) -> f64 {
        match self {
            WorkloadType::ComputeBound => 1.0,
            WorkloadType::MemoryBound => 0.3,
            WorkloadType::Mixed => 0.6,
            WorkloadType::GpuOffload => 0.1,
            WorkloadType::Idle => 0.0,
        }
    }
}

pub struct PowerStats {
    /// Total energy used (microjoules)
    pub energy_uj: AtomicU64,
    /// Current power draw (watts)
    pub current_watts: AtomicU64,
    /// Average watts per hash
    pub joules_per_hash: AtomicU64,
}

impl PowerStats {
    pub fn new() -> Self {
        PowerStats {
            energy_uj: AtomicU64::new(0),
            current_watts: AtomicU64::new(0),
            joules_per_hash: AtomicU64::new(0),
        }
    }
}
