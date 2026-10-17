//! FPGA multi-core work scheduler.
//!
//! Distributes candidate slots across the cores of a device image and collects
//! the results.
//!
//! # What changed and why
//!
//! Four defects, none of which a compiler or a unit test of the happy path would
//! have found.
//!
//! **`throughput: 200_000_000` with the comment "200 MH/s per core at 200MHz".**
//! That number was never measured. It was a clock frequency multiplied by an
//! assumed one hash per cycle, stored in a field that nothing ever read. There is
//! no FPGA in this repository to measure it on. The field is gone; a device
//! reports its own measured rate through the `Bench` command and that is the only
//! rate this crate will print.
//!
//! **Three different packet layouts on one wire.** `bench` wrote magic, command,
//! sequence, hash type, iterations. `reset` wrote magic, command, sequence. Only
//! `crack` wrote the documented header with a version. A device cannot parse all
//! three, and the CRC made the mismatch silent rather than obvious, because each
//! packet was self-consistent. Every command now goes through one builder in
//! [`crate::protocol`].
//!
//! **`bench` and `reset` never looked at the reply.** `bench` read a response and
//! discarded it, then computed a rate from wall clock time and reported it. A
//! device that rejected the request, or returned a corrupt frame, or returned a
//! different sequence number all produced a plausible looking throughput number.
//! Both now parse and verify the reply, and `bench` reports a rate only from a
//! reply that passed.
//!
//! **The scheduler took a concrete device handle.** That made P8.3.03 impossible:
//! there is no way to test a scheduler that cannot be constructed without a
//! device node. It now takes a [`Transport`], so the integration test in
//! `tests/scheduler.rs` drives it against a simulated device.
//!
//! # Result attribution
//!
//! A response carries the sequence number of the request it answers, and the
//! scheduler checks it. Matching by position instead would report one batch's
//! matches against another batch's candidates, which is a wrong answer rather
//! than a failure.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::error::{FpgaError, FpgaResult};
use crate::protocol::{self, Command, HashType};
use crate::transport::Transport;

/// Candidate slots one core handles in a single request.
///
/// The response reports matches as a bitmask, and the mask is one bit per slot.
/// At 32 slots the mask fits the `found` field exactly. Going wider would need a
/// wider field and a second packet; going narrower wastes the device.
pub const SLOTS_PER_REQUEST: usize = 32;

/// A core present in the device image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpgaCore {
    pub id: u32,
    pub hash_type: HashType,
    pub busy: bool,
}

/// Splits candidate slots across cores and collects results.
pub struct FpgaScheduler {
    transport: Box<dyn Transport>,
    cores: Vec<FpgaCore>,
    seq_counter: AtomicU32,
}

impl FpgaScheduler {
    /// Creates a scheduler over `transport`.
    ///
    /// `core_configs` lists hash types and how many cores of each the image has.
    /// Core ids are assigned as `group * 100 + index`, which leaves room to add
    /// groups later without renumbering.
    pub fn new(transport: Box<dyn Transport>, core_configs: &[(HashType, u32)]) -> Self {
        let mut cores = Vec::new();
        for (group, &(hash_type, count)) in core_configs.iter().enumerate() {
            for index in 0..count {
                cores.push(FpgaCore {
                    id: group as u32 * 100 + index,
                    hash_type,
                    busy: false,
                });
            }
        }

        FpgaScheduler {
            transport,
            cores,
            seq_counter: AtomicU32::new(1),
        }
    }

    /// Next sequence number, and the same value the device should echo back.
    fn next_seq(&self) -> u32 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Verifies a reply against the request it is supposed to answer.
    fn check_reply(
        reply: &[u8],
        expect_cmd: Command,
        expect_hash: HashType,
        expect_seq: u32,
    ) -> FpgaResult<protocol::Response> {
        let resp = protocol::parse_response(reply)?;
        if resp.cmd != expect_cmd {
            return Err(FpgaError::InvalidPacket(format!(
                "reply carries command {:?} but {:?} was requested",
                resp.cmd, expect_cmd
            )));
        }
        if resp.hash_type != expect_hash {
            return Err(FpgaError::InvalidPacket(format!(
                "reply carries hash type {:?} but {:?} was requested",
                resp.hash_type, expect_hash
            )));
        }
        if resp.seq_id != expect_seq {
            return Err(FpgaError::InvalidPacket(format!(
                "reply carries sequence {} but {expect_seq} was outstanding",
                resp.seq_id
            )));
        }
        Ok(resp)
    }

    /// Submits one request and reads the reply for it.
    fn exchange(&mut self, request: &[u8], cmd: Command, hash: HashType, seq: u32) -> FpgaResult<protocol::Response> {
        self.transport.submit(request)?;
        let reply = self
            .transport
            .poll_completion()?
            .ok_or(FpgaError::Timeout)?;
        Self::check_reply(&reply, cmd, hash, seq)
    }

    /// Cracks a batch of candidate slots across every core of `hash_type`.
    ///
    /// `slots` is a flat buffer of [`protocol::SLOT_LEN`] byte slots. Returns one
    /// bool per slot, true when the device reported a match.
    pub fn crack_batch(&mut self, hash_type: HashType, slots: &[u8]) -> FpgaResult<Vec<bool>> {
        if slots.len() % protocol::SLOT_LEN != 0 {
            return Err(FpgaError::InvalidPacket(format!(
                "{} bytes is not a whole number of {}-byte slots",
                slots.len(),
                protocol::SLOT_LEN
            )));
        }
        let total = slots.len() / protocol::SLOT_LEN;
        if total == 0 {
            return Ok(Vec::new());
        }

        let core_ids: Vec<u32> = self
            .cores
            .iter()
            .filter(|c| c.hash_type == hash_type)
            .map(|c| c.id)
            .collect();
        if core_ids.is_empty() {
            return Err(FpgaError::UnknownCore(format!(
                "no core in the image handles {:?}",
                hash_type
            )));
        }

        let mut results = vec![false; total];

        // Requests are issued in slot order, so the sequence numbers a device
        // echoes are also in slot order. Splitting is done by slot index rather
        // than by byte offset so an empty tail cannot produce a zero length
        // request.
        let mut first_slot = 0usize;
        while first_slot < total {
            let remaining = total - first_slot;
            let request = remaining.min(SLOTS_PER_REQUEST);
            let end_slot = first_slot + request;
            let slice = &slots[first_slot * protocol::SLOT_LEN..end_slot * protocol::SLOT_LEN];

            let seq = self.next_seq();
            let packet = protocol::build_crack_request(seq, hash_type, slice)?;
            let resp = self.exchange(&packet, Command::Crack, hash_type, seq)?;

            // The device reports matches as a bitmask with one bit per slot.
            // A bit beyond the slots sent is ignored rather than trusted.
            for offset in 0..request {
                let slot = first_slot + offset;
                if resp.found & (1u32 << offset) != 0 {
                    results[slot] = true;
                }
            }

            first_slot = end_slot;
        }

        Ok(results)
    }

    /// Runs a benchmark and returns the rate the device reported.
    ///
    /// The rate comes from the reply, not from wall clock timing. A host clock
    /// measures the round trip, which includes DMA setup and host scheduling, and
    /// reporting that as core throughput overstates what the core did. The host
    /// measured round trip is returned separately so the gap between the two is
    /// visible.
    pub fn bench(&mut self, hash_type: HashType, iterations: u64) -> FpgaResult<BenchResult> {
        let seq = self.next_seq();
        let packet = protocol::build_bench_request(seq, hash_type, iterations)?;

        let start = std::time::Instant::now();
        let resp = self.exchange(&packet, Command::Bench, hash_type, seq)?;
        let round_trip = start.elapsed();

        // A well behaved device echoes the iteration count it actually ran in
        // the found field. If it reports a different count, the rate cannot be
        // attributed to the requested work and is not reported at all.
        if resp.found as u64 != iterations {
            return Err(FpgaError::InvalidPacket(format!(
                "device ran {} iterations but {iterations} were requested",
                resp.found
            )));
        }

        Ok(BenchResult {
            hash_type,
            iterations,
            round_trip,
            device_rate: None,
        })
    }

    /// Resets every core, waiting for confirmation.
    ///
    /// The old version sent the packet and returned immediately, so a caller that
    /// reset and then submitted would race the reset. The reply is now required.
    pub fn reset(&mut self) -> FpgaResult<()> {
        let seq = self.next_seq();
        let packet = protocol::build_reset_request(seq);
        self.exchange(&packet, Command::Reset, HashType::Any, seq)?;
        Ok(())
    }

    pub fn cores(&self) -> &[FpgaCore] {
        &self.cores
    }

    pub fn core_count(&self) -> usize {
        self.cores.len()
    }

    pub fn transport_name(&self) -> &str {
        self.transport.name()
    }
}

/// The outcome of a benchmark.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub hash_type: HashType,
    pub iterations: u64,
    /// Time from submitting the request to receiving the verified reply.
    pub round_trip: Duration,
    /// Rate the device reported, in hashes per second.
    ///
    /// `None` until a device reports one. The current response frame has no rate
    /// field, only an iteration count, so nothing may fill this in without one.
    /// Reporting a host timed round trip as a core rate would be a fabricated
    /// measurement.
    pub device_rate: Option<f64>,
}

impl std::fmt::Display for BenchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.device_rate {
            Some(rate) => write!(
                f,
                "FPGA {:?}: {} iterations, round trip {:?}, device rate {}",
                self.hash_type,
                self.iterations,
                self.round_trip,
                format_rate(rate)
            ),
            None => write!(
                f,
                "FPGA {:?}: {} iterations, round trip {:?}, device rate not reported \
                 (no rate field in protocol version {})",
                self.hash_type,
                self.iterations,
                self.round_trip,
                protocol::PROTOCOL_VERSION
            ),
        }
    }
}

fn format_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 {
        format!("{:.2} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.2} KH/s", rate / 1_000.0)
    } else {
        format!("{rate:.0} H/s")
    }
}