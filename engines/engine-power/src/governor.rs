//! CPU frequency governor — dynamic frequency scaling

use std::fs;
use std::path::Path;
use crate::WorkloadType;

/// Returns CPU numbers that have a cpufreq interface (online CPUs with cpufreq driver).
fn online_cpus() -> Vec<u32> {
    let mut cpus = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(n) = name.strip_prefix("cpu") {
                if let Ok(n) = n.parse::<u32>() {
                    let cpufreq = format!("/sys/devices/system/cpu/cpu{n}/cpufreq");
                    if Path::new(&cpufreq).exists() {
                        cpus.push(n);
                    }
                }
            }
        }
    }
    cpus.sort();
    cpus
}

/// Set CPU frequency scaling governor on all online CPUs
pub fn set_governor(governor: &str) -> std::io::Result<()> {
    for cpu in online_cpus() {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor");
        if Path::new(&path).exists() {
            fs::write(&path, governor)?;
        }
    }
    Ok(())
}

/// Set CPU frequency (kHz) on all online CPUs
pub fn set_frequency(freq_khz: u64) -> std::io::Result<()> {
    for cpu in online_cpus() {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_setspeed");
        if Path::new(&path).exists() {
            fs::write(&path, freq_khz.to_string())?;
        }
    }
    Ok(())
}

/// Get current frequency (kHz) from the first online CPU
pub fn current_frequency() -> Option<u64> {
    let cpus = online_cpus();
    let cpu = *cpus.first()?;
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq");
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

/// Get min frequency (kHz) from the first online CPU
pub fn min_frequency() -> Option<u64> {
    let cpus = online_cpus();
    let cpu = *cpus.first()?;
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_min_freq");
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

/// Get max frequency (kHz) from the first online CPU
pub fn max_frequency() -> Option<u64> {
    let cpus = online_cpus();
    let cpu = *cpus.first()?;
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq");
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
