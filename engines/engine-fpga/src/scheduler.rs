//! FPGA multi-core work scheduler
//!
//! Distributes password batches across available FPGA hash cores,
//! handles load balancing, result collection, and DMA transfers.

use crate::pcie::PcieDma;
use crate::protocol::{self, Command, HashType as FpgaHashType};
use crate::error::FpgaResult;

use std::sync::atomic::{AtomicU32, Ordering};

/// A single FPGA hash core descriptor
#[derive(Debug, Clone)]
pub struct FpgaCore {
    pub id: u32,
    pub hash_type: FpgaHashType,
    pub busy: bool,
    pub throughput: u64,
}

/// Multi-core scheduler that balances work across FPGA cores
pub struct FpgaScheduler {
    dma: PcieDma,
    cores: Vec<FpgaCore>,
    seq_counter: AtomicU32,
    batch_size: usize,
}

impl FpgaScheduler {
    /// Create a new scheduler with given DMA device and core configuration
    pub fn new(dma: PcieDma, core_configs: &[(FpgaHashType, u32)]) -> FpgaResult<Self> {
        let mut cores = Vec::new();
        for (i, &(ht, count)) in core_configs.iter().enumerate() {
            for j in 0..count {
                cores.push(FpgaCore {
                    id: (i as u32) * 100 + j,
                    hash_type: ht,
                    busy: false,
                    throughput: 200_000_000, // 200 MH/s per core at 200MHz
                });
            }
        }

        Ok(FpgaScheduler {
            dma,
            cores,
            seq_counter: AtomicU32::new(1),
            batch_size: 1024, // passwords per batch per core
        })
    }

    /// Crack a batch of passwords on the FPGA
    /// Distributes across all available cores of matching hash type
    pub fn crack_batch(
        &mut self,
        hash_type: FpgaHashType,
        passwords: &[u8],
    ) -> FpgaResult<Vec<bool>> {
        let total = passwords.len() / 64;
        if total == 0 {
            return Ok(Vec::new());
        }

        // Find available cores for this hash type
        let avail_cores: Vec<u32> = self.cores.iter()
            .filter(|c| c.hash_type == hash_type && !c.busy)
            .map(|c| c.id)
            .collect();

        if avail_cores.is_empty() {
            return Err(crate::error::FpgaError::CoreNotReady);
        }

        let cores_count = avail_cores.len();
        let per_core = std::cmp::min(total / cores_count, 32);
        let mut results = vec![false; total];

        for (ci, &core_id) in avail_cores.iter().enumerate() {
            let start = ci * per_core * 64;
            let end = if ci == cores_count - 1 {
                passwords.len()
            } else {
                (ci + 1) * per_core * 64
            };

            if start >= end {
                continue;
            }

            let batch = &passwords[start..end];
            let seq_id = self.seq_counter.fetch_add(1, Ordering::Relaxed);

            // Build command packet
            let packet = protocol::build_crack_packet(seq_id, hash_type, batch);

            // Send to FPGA via DMA
            self.dma.send_command(&packet)?;

            // Read response (poll for completion)
            let mut resp_buf = [0u8; 17];
            self.dma.read_response(&mut resp_buf)?;

            // Parse response
            if let Some(response) = protocol::parse_response(&resp_buf) {
                // Verify CRC by recalculating
                let calc = protocol::crc32(&resp_buf[..13]);
                if calc != response.crc {
                    return Err(crate::error::FpgaError::CrcMismatch);
                }

                // Mark results for this core's portion
                let found_mask = response.found;
                let batch_results = (start / 64)..(end / 64);
                for (i, ri) in batch_results.enumerate() {
                    if i < 32 {
                        results[ri] = (found_mask >> i) & 1 != 0;
                    }
                }
            }
        }

        Ok(results)
    }

    /// Run a benchmark on the FPGA
    pub fn bench(&mut self, hash_type: FpgaHashType, iterations: u64) -> FpgaResult<BenchResult> {
        let start = std::time::Instant::now();

        // Send benchmark command
        let seq_id = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        let mut packet = Vec::with_capacity(16);
        packet.extend_from_slice(&protocol::MAGIC_HOST.to_le_bytes());
        packet.push(Command::Bench as u8);
        packet.extend_from_slice(&seq_id.to_le_bytes());
        packet.push(hash_type as u8);
        packet.extend_from_slice(&iterations.to_le_bytes());
        let crc = protocol::crc32(&packet);
        packet.extend_from_slice(&crc.to_le_bytes());

        self.dma.send_command(&packet)?;

        let mut resp_buf = [0u8; 17];
        self.dma.read_response(&mut resp_buf)?;

        let elapsed = start.elapsed();
        let rate = iterations as f64 / elapsed.as_secs_f64();

        Ok(BenchResult {
            hash_type,
            iterations,
            elapsed,
            rate,
        })
    }

    /// Reset all FPGA cores
    pub fn reset(&mut self) -> FpgaResult<()> {
        let seq_id = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        let mut packet = Vec::with_capacity(12);
        packet.extend_from_slice(&protocol::MAGIC_HOST.to_le_bytes());
        packet.push(Command::Reset as u8);
        packet.extend_from_slice(&seq_id.to_le_bytes());
        let crc = protocol::crc32(&packet);
        packet.extend_from_slice(&crc.to_le_bytes());

        self.dma.send_command(&packet)?;
        Ok(())
    }

    pub fn core_count(&self) -> usize {
        self.cores.len()
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

#[derive(Debug)]
pub struct BenchResult {
    pub hash_type: FpgaHashType,
    pub iterations: u64,
    pub elapsed: std::time::Duration,
    pub rate: f64,
}

impl std::fmt::Display for BenchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rate_str = if self.rate > 1_000_000.0 {
            format!("{:.2} MH/s", self.rate / 1_000_000.0)
        } else if self.rate > 1_000.0 {
            format!("{:.2} KH/s", self.rate / 1_000.0)
        } else {
            format!("{:.0} H/s", self.rate)
        };
        write!(f, "FPGA {:?}: {} in {:?} ({})",
               self.hash_type, self.iterations, self.elapsed, rate_str)
    }
}