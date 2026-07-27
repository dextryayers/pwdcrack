//! AMD Zen power driver — reads energy counters from hwmon sysfs
//! /sys/class/hwmon/hwmon*/energy*_input
//! Zen 3+ (Ryzen 5000+ / EPYC 7003+) supported

use std::fs;

const HWMON_BASE: &str = "/sys/class/hwmon";

fn find_energy_hwmon() -> Option<String> {
    let dir = fs::read_dir(HWMON_BASE).ok()?;
    for entry in dir.flatten() {
        let name_path = entry.path().join("name");
        let name = fs::read_to_string(&name_path).ok()?;
        let trimmed = name.trim();
        // AMD typically shows "fam17h", "fam19h", "k10temp", "zenpower"
        if trimmed.starts_with("fam1") || trimmed == "k10temp" || trimmed == "zenpower" {
            // Look for energy*_input files
            for sub in fs::read_dir(entry.path()).ok()? {
                let sub_entry = sub.ok()?;
                let fname = sub_entry.file_name();
                let fstr = fname.to_string_lossy();
                if fstr.starts_with("energy") && fstr.ends_with("_input") {
                    return Some(sub_entry.path().to_string_lossy().to_string());
                }
            }
        }
    }
    None
}

pub fn read_energy_uj() -> Option<u64> {
    let path = find_energy_hwmon()?;
    let s = fs::read_to_string(&path).ok()?;
    s.trim().parse::<u64>().ok()
}

pub fn is_available() -> bool {
    find_energy_hwmon().is_some()
}

pub fn calc_watts(energy_uj_prev: u64, energy_uj_curr: u64, delta_secs: f64) -> f64 {
    if delta_secs <= 0.0 {
        return 0.0;
    }
    let delta_uj = if energy_uj_curr >= energy_uj_prev {
        energy_uj_curr - energy_uj_prev
    } else {
        u64::MAX - energy_uj_prev + energy_uj_curr
    };
    (delta_uj as f64 / 1_000_000.0) / delta_secs
}
