//! Intel RAPL (Running Average Power Limit) driver
//!
//! Reads energy counters from MSR or /sys/class/powercap
//! Only available on x86_64 Linux with kernel support

use std::fs;
use std::path::Path;

const RAPL_BASE: &str = "/sys/class/powercap/intel-rapl/intel-rapl:0";

/// Read current energy counter (microjoules)
pub fn read_energy_uj() -> Option<u64> {
    let path = format!("{}/energy_uj", RAPL_BASE);
    fs::read_to_string(&path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Read max energy range (microjoules)
pub fn max_energy_range_uj() -> Option<u64> {
    let path = format!("{}/max_energy_range_uj", RAPL_BASE);
    fs::read_to_string(&path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Read package name
pub fn package_name() -> Option<String> {
    let path = format!("{}/name", RAPL_BASE);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Check if RAPL is available
pub fn is_available() -> bool {
    Path::new(RAPL_BASE).exists()
}

/// Calculate power (watts) from two energy readings and time delta
pub fn calc_watts(energy_uj_prev: u64, energy_uj_curr: u64, delta_secs: f64) -> f64 {
    if delta_secs <= 0.0 { return 0.0; }
    let delta_uj = if energy_uj_curr >= energy_uj_prev {
        energy_uj_curr - energy_uj_prev
    } else {
        // Counter wrapped around
        let max = max_energy_range_uj().unwrap_or(u64::MAX);
        (max - energy_uj_prev) + energy_uj_curr
    };
    (delta_uj as f64 / 1_000_000.0) / delta_secs
}
