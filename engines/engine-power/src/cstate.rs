//! C-state control — idle core deep sleep management

use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn present_cpus() -> Vec<u32> {
    let mut cpus = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(n) = name.strip_prefix("cpu") {
                if let Ok(n) = n.parse::<u32>() {
                    cpus.push(n);
                }
            }
        }
    }
    cpus.sort();
    cpus
}

/// Enable deepest idle state for all cores.
/// Writes "1" to state0/disable to disable the shallowest state,
/// forcing the CPU to enter deeper sleep states.
pub fn enable_deep_sleep() -> std::io::Result<()> {
    for cpu in present_cpus() {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle/state0/disable");
        if Path::new(&path).exists() {
            fs::write(&path, "1")?;
        }
    }
    Ok(())
}

/// Disable deep sleep (keep cores responsive).
/// Writes "0" to state0/disable to enable the shallowest state,
/// preventing the CPU from entering deep sleep.
pub fn disable_deep_sleep() -> std::io::Result<()> {
    for cpu in present_cpus() {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle/state0/disable");
        if Path::new(&path).exists() {
            fs::write(&path, "0")?;
        }
    }
    Ok(())
}

/// Get current C-state residency as a percentage breakdown per state,
/// aggregated across all CPUs.
pub fn cstate_residency() -> Vec<(u32, f64)> {
    let mut state_times: HashMap<u32, u64> = HashMap::new();
    for cpu in present_cpus() {
        let dir = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle");
        if !Path::new(&dir).exists() {
            continue;
        }
        for state_idx in 0..8 {
            let time_path = format!("{dir}/state{state_idx}/time");
            if Path::new(&time_path).exists() {
                if let Ok(time_us) = fs::read_to_string(&time_path) {
                    let time = time_us.trim().parse::<u64>().unwrap_or(0);
                    *state_times.entry(state_idx).or_insert(0) += time;
                }
            } else {
                break;
            }
        }
    }

    let total = state_times.values().sum::<u64>() as f64;
    state_times
        .into_iter()
        .map(|(idx, time)| {
            let pct = if total > 0.0 { time as f64 / total * 100.0 } else { 0.0 };
            (idx, pct)
        })
        .collect()
}

pub fn is_available() -> bool {
    Path::new("/sys/devices/system/cpu/cpu0/cpuidle").exists()
}
