//! engine-fpga — FPGA hash acceleration
//!
//! Components:
//! - Verilog cores: MD5, SHA256, NTLM (fully pipelined)
//! - PCIe DMA communication between host and FPGA
//! - Work scheduler: batch passwords to FPGA, collect results
//! - Power-efficient: FPGA uses 8W vs GPU 450W

pub mod pcie;
pub mod protocol;
pub mod error;

use std::sync::atomic::{AtomicBool, Ordering};

pub struct FpgaDevice {
    pub device_path: String,
    pub core_count: u32,
    pub frequency_mhz: u32,
    connected: AtomicBool,
}

impl FpgaDevice {
    /// Try to detect and initialize FPGA device
    pub fn detect() -> Option<Self> {
        // Try common PCIe FPGA device paths
        let paths = [
            "/dev/fpga0",
            "/dev/xdma0_user",
            "/dev/xdma0_h2c_0",
            "/sys/class/fpga/fpga0",
        ];

        for path in &paths {
            if std::path::Path::new(path).exists() {
                log::info!("FPGA detected at {}", path);
                return Some(FpgaDevice {
                    device_path: path.to_string(),
                    core_count: 4,    // Default cores
                    frequency_mhz: 200, // Default clock
                    connected: AtomicBool::new(true),
                });
            }
        }

        log::info!("No FPGA device found");
        None
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn info(&self) -> String {
        format!(
            "FPGA: {} ({} cores @ {} MHz)",
            self.device_path,
            self.core_count,
            self.frequency_mhz,
        )
    }
}
