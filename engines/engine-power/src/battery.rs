//! Battery monitoring — Android, laptops

use std::fs;

const BATTERY_BASE: &str = "/sys/class/power_supply/BAT0";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerSource {
    Battery,
    AcPower,
    Charging,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryLevel {
    Critical,  // < 10%
    Low,       // 10-30%
    Medium,    // 30-60%
    High,      // 60-100%
    Charging,  // Plugged in
}

impl BatteryLevel {
    /// Recommended freq ratio for this battery level
    pub fn freq_ratio(&self) -> f64 {
        match self {
            BatteryLevel::Critical => 0.0,  // Should pause
            BatteryLevel::Low => 0.2,
            BatteryLevel::Medium => 0.5,
            BatteryLevel::High => 0.8,
            BatteryLevel::Charging => 1.0,
        }
    }
}

/// Get current battery capacity percentage
pub fn battery_capacity() -> Option<u8> {
    let path = format!("{}/capacity", BATTERY_BASE);
    let s = fs::read_to_string(&path).ok()?;
    s.trim().parse().ok()
}

/// Get power source status
pub fn power_source() -> PowerSource {
    let path = format!("{}/status", BATTERY_BASE);
    match fs::read_to_string(&path) {
        Ok(s) => match s.trim() {
            "Discharging" => PowerSource::Battery,
            "Charging" => PowerSource::Charging,
            "Full" => PowerSource::AcPower,
            _ => PowerSource::Unknown,
        },
        Err(_) => PowerSource::Unknown,
    }
}

/// Determine battery level with awareness
pub fn battery_level() -> BatteryLevel {
    if power_source() == PowerSource::Charging || power_source() == PowerSource::AcPower {
        return BatteryLevel::Charging;
    }

    match battery_capacity() {
        Some(cap) if cap < 10 => BatteryLevel::Critical,
        Some(cap) if cap < 30 => BatteryLevel::Low,
        Some(cap) if cap < 60 => BatteryLevel::Medium,
        Some(_) => BatteryLevel::High,
        None => BatteryLevel::Charging,
    }
}
