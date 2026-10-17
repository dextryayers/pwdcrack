//! engine-fpga: FPGA hash acceleration.
//!
//! Components:
//! - SystemVerilog cores under `rtl/`, in whatever state the verification in
//!   `scripts/simulate.sh` reports. Nothing here claims they are correct; the
//!   simulation output is the only evidence.
//! - A PCIe DMA transport for host to device traffic.
//! - A scheduler that splits candidate slots across cores and collects results.
//!
//! # What this crate does not know
//!
//! There is no FPGA in this repository, and no measurement has been taken on
//! one. Three numbers that used to be hardcoded here have been removed because
//! they were invented:
//!
//! - "fully pipelined, 1 hash/cycle" per core. Not read from any RTL, not
//!   simulated, not synthesised.
//! - "FPGA uses 8W vs GPU 450W". No power measurement was taken.
//! - `core_count: 4, frequency_mhz: 200`, which [`FpgaDevice::detect`] assigned to
//!   whatever device node it found. A real card with two cores at 150 MHz would
//!   have been reported as four cores at 200 MHz, and `info` printed that as
//!   fact.
//!
//! [`FpgaDevice::core_count`] and [`FpgaDevice::frequency_mhz`] are now `None`
//! until a device reports them. Filling them in needs a statistics payload in
//! [`protocol`], which does not exist yet; until it does, the honest value is
//! unknown.

pub mod error;
pub mod protocol;
pub mod scheduler;
pub mod transport;

use error::FpgaResult;
use protocol::HashType;
use scheduler::{BenchResult, FpgaScheduler};
use std::sync::atomic::{AtomicBool, Ordering};
use transport::PcieTransport;

/// Device nodes checked by [`FpgaDevice::detect`], in order of preference.
///
/// A node existing means the kernel loaded a driver for it. It does not mean the
/// device speaks this protocol, is the size this crate expects, or is an FPGA at
/// all. The first probe that succeeds at the protocol level is the device this
/// crate talks to; everything before it is a path guess.
const CANDIDATE_NODES: [&str; 4] = [
    "/dev/fpga0",
    "/dev/xdma0_user",
    "/dev/xdma0_h2c_0",
    "/sys/class/fpga/fpga0",
];

/// A detected FPGA device node.
pub struct FpgaDevice {
    pub device_path: String,
    /// Cores in the image, once the device has reported it. `None` means
    /// unknown, not zero.
    pub core_count: Option<u32>,
    /// Core clock in MHz, once the device has reported it. `None` means unknown.
    pub frequency_mhz: Option<u32>,
    connected: AtomicBool,
    scheduler: Option<FpgaScheduler>,
}

impl FpgaDevice {
    /// Looks for a device node and returns a handle if one exists.
    ///
    /// Existence only. Nothing is probed here, so a `Some` result means a path was
    /// found, not that a device is usable. [`FpgaDevice::init`] is where that is
    /// established, and where a wrong node shows up as a protocol failure rather
    /// than as a successful connection.
    pub fn detect() -> Option<Self> {
        for path in CANDIDATE_NODES {
            if std::path::Path::new(path).exists() {
                log::info!("FPGA device node present at {path}");
                return Some(FpgaDevice {
                    device_path: path.to_string(),
                    core_count: None,
                    frequency_mhz: None,
                    connected: AtomicBool::new(true),
                    scheduler: None,
                });
            }
        }

        log::info!("No FPGA device node found in {:?}", CANDIDATE_NODES);
        None
    }

    /// Opens the transport and builds a scheduler.
    ///
    /// The core configuration below is a request, not a discovery. The scheduler
    /// uses it to decide which cores may be given work; if the image disagrees,
    /// the failure shows up as a device error on the first request rather than
    /// being detected here. Reading the real core inventory needs the statistics
    /// payload described at the crate level.
    pub fn init(&mut self) -> FpgaResult<()> {
        let transport = PcieTransport::open(&self.device_path)?;
        let core_configs = &[
            (HashType::Md5, 4),
            (HashType::Sha256, 2),
            (HashType::Ntlm, 2),
        ];
        let scheduler = FpgaScheduler::new(Box::new(transport), core_configs);
        log::info!(
            "FPGA scheduler built for {} with {} configured cores",
            self.device_path,
            scheduler.core_count()
        );
        self.scheduler = Some(scheduler);
        Ok(())
    }

    fn scheduler_mut(&mut self) -> FpgaResult<&mut FpgaScheduler> {
        self.scheduler
            .as_mut()
            .ok_or(error::FpgaError::CoreNotReady)
    }

    /// Verifies candidate slots against MD5 on the device.
    pub fn crack_md5(&mut self, slots: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler_mut()?.crack_batch(HashType::Md5, slots)
    }

    /// Verifies candidate slots against SHA-256 on the device.
    pub fn crack_sha256(&mut self, slots: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler_mut()?.crack_batch(HashType::Sha256, slots)
    }

    /// Verifies candidate slots against NTLM on the device.
    pub fn crack_ntlm(&mut self, slots: &[u8]) -> FpgaResult<Vec<bool>> {
        self.scheduler_mut()?.crack_batch(HashType::Ntlm, slots)
    }

    /// Benchmarks the cores of one hash type.
    pub fn bench(&mut self, hash_type: HashType) -> FpgaResult<BenchResult> {
        self.scheduler_mut()?.bench(hash_type, 1_000_000)
    }

    /// Resets the cores, waiting for the device to confirm.
    pub fn reset(&mut self) -> FpgaResult<()> {
        match self.scheduler.as_mut() {
            Some(sched) => sched.reset(),
            None => Err(error::FpgaError::CoreNotReady),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// A one line description.
    ///
    /// Unknown values are printed as unknown. A number that was never measured
    /// must not appear in output that a user may take as a specification.
    pub fn info(&self) -> String {
        let cores = match self.core_count {
            Some(n) => format!("{n} cores"),
            None => "core count not reported".to_string(),
        };
        let freq = match self.frequency_mhz {
            Some(mhz) => format!("{mhz} MHz"),
            None => "clock not reported".to_string(),
        };
        format!("FPGA: {} ({}, {})", self.device_path, cores, freq)
    }
}

impl Drop for FpgaDevice {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}