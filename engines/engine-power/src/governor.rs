//! CPU frequency governor — dynamic frequency scaling

use std::fs;
use std::path::Path;
use crate::WorkloadType;

/// Set CPU frequency scaling governor
pub fn set_governor(governor: &str) -> std::io::Result<()> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    if Path::new(path).exists() {
        fs::write(path, governor)?;
    }
    Ok(())
}

/// Set CPU frequency (kHz)
pub fn set_frequency(freq_khz: u64) -> std::io::Result<()> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed";
    if Path::new(path).exists() {
        fs::write(path, freq_khz.to_string())?;
    }
    Ok(())
}

/// Get current frequency (kHz)
pub fn current_frequency() -> Option<u64> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq";
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

/// Get min frequency (kHz)
pub fn min_frequency() -> Option<u64> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq";
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

/// Get max frequency (kHz)
pub fn max_frequency() -> Option<u64> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

/// Apply frequency based on workload type
pub fn apply_workload_policy(workload: WorkloadType) {
    let min = min_frequency().unwrap_or(800_000);
    let max = max_frequency().unwrap_or(3_000_000);

    let target = min as f64 + (max - min) as f64 * workload.freq_ratio();
    let _ = set_frequency(target as u64);

    match workload {
        WorkloadType::ComputeBound => {
            let _ = set_governor("performance");
        }
        WorkloadType::MemoryBound => {
            let _ = set_governor("powersave");
        }
        WorkloadType::GpuOffload | WorkloadType::Idle => {
            let _ = set_governor("powersave");
            let _ = set_frequency(min);
        }
        WorkloadType::Mixed => {
            let _ = set_governor("ondemand");
        }
    }

    log::debug!(
        "Power: workload={:?}, freq={}kHz (range {} - {} kHz)",
        workload,
        target as u64,
        min,
        max,
    );
}
