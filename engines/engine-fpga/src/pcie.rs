//! PCIe DMA driver — communicate with FPGA via memory-mapped PCIe BAR

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use crate::error::FpgaResult;

/// PCIe DMA channel for host-FPGA communication
pub struct PcieDma {
    /// DMA device file
    file: File,
    /// Maximum transfer size per DMA operation
    max_transfer_size: usize,
}

impl PcieDma {
    /// Open PCIe DMA device
    pub fn open(device_path: &str) -> FpgaResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        Ok(PcieDma {
            file,
            max_transfer_size: 1024 * 1024, // 1MB per DMA
        })
    }

    /// Send data to FPGA (host → FPGA)
    pub fn send(&self, data: &[u8], offset: u64) -> FpgaResult<usize> {
        let written = self.file.write_at(data, offset)?;
        Ok(written)
    }

    /// Receive data from FPGA (FPGA → host)
    pub fn recv(&self, buf: &mut [u8], offset: u64) -> FpgaResult<usize> {
        let read = self.file.read_at(buf, offset)?;
        Ok(read)
    }

    /// Send a command packet to FPGA
    pub fn send_command(&self, cmd: &[u8]) -> FpgaResult<()> {
        self.send(cmd, 0)?;
        Ok(())
    }

    /// Read response from FPGA
    pub fn read_response(&self, buf: &mut [u8]) -> FpgaResult<usize> {
        self.recv(buf, 0)
    }
}
