//! GPU power monitoring — NVIDIA NVML / AMD hwmon

use std::fs;
use std::path::Path;

fn find_nvidia_gpu() -> Option<()> {
    for i in 0..8 {
        let path = format!("/sys/class/drm/card{i}/device/gpu_busy_percent");
        if Path::new(&path).exists() {
            return Some(());
        }
    }
    None
}

fn find_amd_gpu_hwmon() -> Option<String> {
    for i in 0..8 {
        let base = format!("/sys/class/drm/card{i}/device/hwmon");
        let dir = fs::read_dir(&base).ok()?;
        for entry in dir.flatten() {
            let name_path = entry.path().join("name");
            if let Ok(name) = fs::read_to_string(&name_path) {
                if name.trim() == "amdgpu" || name.trim() == "radeon" {
                    for sub in fs::read_dir(entry.path()).ok()? {
                        let sub_entry = sub.ok()?;
                        let fname = sub_entry.file_name();
                        let fstr = fname.to_string_lossy();
                        // AMD GPU power: power1_average or power1_input
                        if fstr == "power1_average" || fstr == "power1_input" {
                            return Some(sub_entry.path().to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

pub enum GpuPowerSource {
    Nvidia,
    Amd,
    NotFound,
}

pub fn detect_source() -> GpuPowerSource {
    if find_nvidia_gpu().is_some() {
        GpuPowerSource::Nvidia
    } else if find_amd_gpu_hwmon().is_some() {
        GpuPowerSource::Amd
    } else {
        GpuPowerSource::NotFound
    }
}

/// Read GPU power consumption in microwatts
pub fn read_gpu_power_uw() -> Option<u64> {
    if let Some(path) = find_amd_gpu_hwmon() {
        let s = fs::read_to_string(&path).ok()?;
        return s.trim().parse::<u64>().ok();
    }
    None
}

/// GPU utilization percentage (0-100)
pub fn gpu_busy_percent() -> Option<u8> {
    for i in 0..8 {
        let path = format!("/sys/class/drm/card{i}/device/gpu_busy_percent");
        if Path::new(&path).exists() {
            if let Ok(s) = fs::read_to_string(&path) {
                if let Ok(pct) = s.trim().parse::<u8>() {
                    return Some(pct);
                }
            }
        }
    }
    None
}
