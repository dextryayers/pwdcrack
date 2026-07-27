//! C-state control — idle core deep sleep management

use std::fs;
use std::path::Path;

/// Enable deepest idle state for all cores
pub fn enable_deep_sleep() -> std::io::Result<()> {
    for cpu in 0..128 {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle/state0/disable");
        if Path::new(&path).exists() {
            fs::write(&path, "0")?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Disable deep sleep (keep cores responsive)
pub fn disable_deep_sleep() -> std::io::Result<()> {
    for cpu in 0..128 {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle/state0/disable");
        if Path::new(&path).exists() {
            fs::write(&path, "1")?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Get current C-state residency (percentage of time in each state)
pub fn cstate_residency() -> Vec<(u32, f64)> {
    let mut states = Vec::new();
    for cpu in 0..128 {
        let dir = format!("/sys/devices/system/cpu/cpu{cpu}/cpuidle");
        if !Path::new(&dir).exists() {
            break;
        }
        for state_idx in 0..8 {
            let name_path = format!("{dir}/state{state_idx}/name");
            let time_path = format!("{dir}/state{state_idx}/time");
            if Path::new(&name_path).exists() {
                if let Ok(name) = fs::read_to_string(&name_path) {
                    if let Ok(time_us) = fs::read_to_string(&time_path) {
                        let name = name.trim().to_string();
                        let time = time_us.trim().parse::<u64>().unwrap_or(0);
                        states.push((state_idx, name, time));
                    }
                }
            } else {
                break;
            }
        }
        break; // Only read CPU0 for summary
    }

    let total = states.iter().map(|(_, _, t)| t).sum::<u64>() as f64;
    states
        .into_iter()
        .map(|(idx, _, time)| {
            let pct = if total > 0.0 { time as f64 / total * 100.0 } else { 0.0 };
            (idx, pct)
        })
        .collect()
}

pub fn is_available() -> bool {
    Path::new("/sys/devices/system/cpu/cpu0/cpuidle").exists()
}
