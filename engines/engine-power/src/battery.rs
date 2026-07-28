//! Battery monitoring — Android, laptops

use std::fs;
use std::path::Path;

fn battery_base() -> Option<String> {
    let bat0 = "/sys/class/power_supply/BAT0";
    if Path::new(bat0).exists() {
        Some(bat0.to_string())
    } else {
        let bat1 = "/sys/class/power_supply/BAT1";
        if Path::new(bat1).exists() {
            Some(bat1.to_string())
        } else {
            None
        }
    }
}

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
    let base = battery_base()?;
    let path = format!("{base}/capacity");
    let s = fs::read_to_string(&path).ok()?;
    s.trim().parse().ok()
}

/// Get power source status
pub fn power_source() -> PowerSource {
    let base = match battery_base() {
        Some(b) => b,
        None => return PowerSource::Unknown,
    };
    let path = format!("{base}/status");
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
