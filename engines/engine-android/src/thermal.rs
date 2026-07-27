//! Thermal throttling detection for Android

use std::fs;
use std::path::Path;

const THERMAL_ZONES: &[&str] = &[
    "/sys/class/thermal/thermal_zone0/temp",
    "/sys/class/thermal/thermal_zone1/temp",
    "/sys/class/thermal/thermal_zone2/temp",
];

/// Read current CPU temperature (millidegrees Celsius)
pub fn cpu_temperature_mc() -> Option<u32> {
    for zone in THERMAL_ZONES {
        if Path::new(zone).exists() {
            if let Ok(s) = fs::read_to_string(zone) {
                if let Ok(temp) = s.trim().parse::<u32>() {
                    return Some(temp);
                }
            }
        }
    }
    None
}

/// CPU temperature in Celsius
pub fn cpu_temperature_c() -> Option<f64> {
    cpu_temperature_mc().map(|mc| mc as f64 / 1000.0)
}

/// Check if thermal throttling is needed
pub fn check_thermal_status() -> ThermalStatus {
    match cpu_temperature_c() {
        Some(temp) if temp > 80.0 => ThermalStatus::Critical,
        Some(temp) if temp > 70.0 => ThermalStatus::Hot,
        Some(temp) if temp > 60.0 => ThermalStatus::Warm,
        Some(_) => ThermalStatus::Normal,
        None => ThermalStatus::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalStatus {
    Unknown,
    Normal,
    Warm,
    Hot,
    Critical,
}

impl ThermalStatus {
    pub fn freq_ratio(&self) -> f64 {
        match self {
            ThermalStatus::Unknown | ThermalStatus::Normal => 1.0,
            ThermalStatus::Warm => 0.7,
            ThermalStatus::Hot => 0.4,
            ThermalStatus::Critical => 0.0,
        }
    }

    pub fn action(&self) -> &'static str {
        match self {
            ThermalStatus::Critical => "STOP — temperature critical!",
            ThermalStatus::Hot => "Throttling — reduce threads",
            ThermalStatus::Warm => "Caution — monitor temperature",
            ThermalStatus::Normal => "Normal operation",
            ThermalStatus::Unknown => "No temperature sensor",
        }
    }
}
