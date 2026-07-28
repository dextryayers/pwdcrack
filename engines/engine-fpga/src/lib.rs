//! engine-fpga — FPGA hash acceleration
//!
//! Components:
//! - Verilog cores: MD5, SHA256, NTLM (fully pipelined, 1 hash/cycle)
//! - PCIe DMA communication between host and FPGA
//! - Multi-core scheduler: distribute passwords across FPGA cores
//! - Power-efficient: FPGA uses 8W vs GPU 450W

pub mod pcie;
pub mod protocol;
pub mod error;
pub mod scheduler;

use pcie::PcieDma;
use scheduler::FpgaScheduler;
use error::FpgaResult;

use std::sync::atomic::{AtomicBool, Ordering};

/// Detected FPGA device with driver connection
pub struct FpgaDevice {
    pub device_path: String,
    pub core_count: u32,
    pub frequency_mhz: u32,
    connected: AtomicBool,
    scheduler: Option<FpgaScheduler>,
}

impl FpgaDevice {
    /// Try to detect and initialize FPGA device
    pub fn detect() -> Option<Self> {
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
                    core_count: 4,
                    frequency_mhz: 200,
                    connected: AtomicBool::new(true),
                    scheduler: None,
                });
            }
        }

        log::info!("No FPGA device found");
        None
    }

    /// Initialize DMA and scheduler (call after detect())
    pub fn init(&mut self) -> FpgaResult<()> {
        let dma = PcieDma::open(&self.device_path)?;
        let core_configs = &[
            (protocol::HashType::MD5, 4),
            (protocol::HashType::SHA256, 2),
            (protocol::HashType::NTLM, 2),
        ];
        let scheduler = FpgaScheduler::new(dma, core_configs)?;
        self.scheduler = Some(scheduler);
        log::info!("FPGA initialized: {} cores @ {} MHz", self.core_count, self.frequency_mhz);
        Ok(())
    }

    /// Crack passwords on FPGA — auto-distributes across available cores
    pub fn crack_md5(&mut self, passwords: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler.as_mut().unwrap()
            .crack_batch(protocol::HashType::MD5, passwords)
    }

    /// Crack passwords on FPGA — SHA-256
    pub fn crack_sha256(&mut self, passwords: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler.as_mut().unwrap()
            .crack_batch(protocol::HashType::SHA256, passwords)
    }

    /// Crack passwords on FPGA — NTLM
    pub fn crack_ntlm(&mut self, passwords: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler.as_mut().unwrap()
            .crack_batch(protocol::HashType::NTLM, passwords)
    }

    /// Benchmark FPGA hash cores
    pub fn bench(&mut self, hash_type: protocol::HashType) -> FpgaResult<scheduler::BenchResult> {
        self.scheduler.as_mut().unwrap()
            .bench(hash_type, 1_000_000)
    }

    /// Reset FPGA cores
    pub fn reset(&mut self) -> FpgaResult<()> {
        if let Some(ref mut sched) = self.scheduler {
            sched.reset()?;
        }
        Ok(())
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

impl Drop for FpgaDevice {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}