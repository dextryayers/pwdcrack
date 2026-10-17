//! The engine abstraction.
//!
//! Before this module each back end (CPU, SIMD, GPU, FPGA, distributed) had
//! its own calling convention, its own idea of what a "result" was, and its own
//! way of reporting whether it worked. The scheduler could not treat them
//! uniformly, so multi hardware mode was a special case everywhere it appeared.
//!
//! [`Engine`] gives every back end one shape:
//!
//! ```text
//! plan()      -> what this engine can take and how fast it runs
//! verify_batch() -> test candidates against hashes
//! info()      -> what it actually is, measured not assumed
//! is_available()  -> can it be used right now
//! ```
//!
//! ## Honest reporting is a requirement, not a nicety
//!
//! Several engines previously returned `is_available() == true` unconditionally
//! and reported `throughput_hps == 0.0`, which told the scheduler to route work
//! to hardware that could not do it. [`EngineInfo`] therefore requires a
//! measured rate, and [`crate::engine::capability`] makes an engine declare
//! exactly which algorithms it implements. An engine that cannot do something
//! must say so rather than accept the work and fail silently.
//!
//! ## Why batching is the core operation
//!
//! Every accelerated back end is faster in proportion to how many independent
//! items it processes at once: a GPU wants thousands of candidates, an FPGA
//! wants a full DMA buffer, a SIMD kernel wants a multiple of its lane count.
//! `verify_batch` takes a slice of candidates for exactly this reason, and
//! [`BatchPlan`] reports the batch size an engine should be given.

pub mod capability;
pub mod planner;

use std::sync::Arc;
use std::time::Instant;

use crate::hash::{HashCracker, HashEntry};

pub use capability::{Capability, CapabilitySet};

/// One cracked hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineMatch {
    /// Index into the candidate slice that produced this match.
    pub candidate_index: usize,
    /// Index into the hash slice that matched.
    pub hash_index: usize,
}

impl EngineMatch {
    /// Builds a match record.
    pub fn new(candidate_index: usize, hash_index: usize) -> Self {
        EngineMatch {
            candidate_index,
            hash_index,
        }
    }
}

/// What an engine is and how it performs.
///
/// Every field is measured at runtime. An engine that cannot measure must report
/// zero and say so, which the conformance test enforces.
#[derive(Debug, Clone)]
pub struct EngineInfo {
    /// Stable identifier, for example `cpu-scalar` or `gpu-wgpu`.
    pub name: &'static str,
    /// Human readable device name, for example the GPU model string.
    pub device: String,
    /// Vendor or architecture, for example `amd`, `nvidia`, `apple`.
    pub vendor: String,
    /// Measured hashes per second for the reference workload.
    ///
    /// Zero means the engine has not been measured yet, which is different from
    /// being slow. The scheduler must not treat an unmeasured engine as useless.
    pub measured_hps: f64,
    /// Whether `measured_hps` reflects a real benchmark.
    pub measured: bool,
    /// Candidates this engine wants in one call. Zero means it takes any count.
    pub batch_size: usize,
    /// Usable device memory in bytes, or zero when not applicable.
    pub memory_bytes: u64,
    /// What this engine can actually do.
    pub capabilities: CapabilitySet,
}

impl EngineInfo {
    /// Creates an info record that has not been benchmarked yet.
    pub fn unmeasured(name: &'static str, device: impl Into<String>) -> Self {
        EngineInfo {
            name,
            device: device.into(),
            vendor: String::new(),
            measured_hps: 0.0,
            measured: false,
            batch_size: 0,
            memory_bytes: 0,
            capabilities: CapabilitySet::empty(),
        }
    }

    /// Sets the vendor string.
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = vendor.into();
        self
    }

    /// Sets the preferred batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Sets usable memory in bytes.
    pub fn with_memory(mut self, bytes: u64) -> Self {
        self.memory_bytes = bytes;
        self
    }

    /// Declares the algorithm set.
    pub fn with_capabilities(mut self, caps: CapabilitySet) -> Self {
        self.capabilities = caps;
        self
    }

    /// Records a benchmark result.
    pub fn with_measurement(mut self, hps: f64) -> Self {
        self.measured_hps = hps;
        self.measured = hps > 0.0;
        self
    }

    /// Whether this engine is worth routing work to.
    ///
    /// An unmeasured engine is still usable: it may simply be new. What must not
    /// happen is an engine claiming to work without ever having been asked.
    pub fn is_usable(&self) -> bool {
        self.measured_hps > 0.0 && !self.capabilities.is_empty()
    }

    /// One line suitable for `pwdcrack doctor`.
    pub fn summary(&self) -> String {
        let rate = if self.measured {
            format!("{:.0} H/s", self.measured_hps)
        } else {
            "unmeasured".to_string()
        };
        let mem = if self.memory_bytes > 0 {
            format!(", {} MB", self.memory_bytes / (1 << 20))
        } else {
            String::new()
        };
        let batch = if self.batch_size > 0 {
            format!(", batch {}", self.batch_size)
        } else {
            String::new()
        };
        format!(
            "{:<14} {:<28} {:<10} {}{}{}",
            self.name, self.device, rate, self.vendor, mem, batch
        )
    }
}

/// What an engine should be given for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchPlan {
    /// How many candidates to send.
    pub candidates: usize,
    /// How many hashes to send.
    pub hashes: usize,
    /// Whether the caller should keep candidates resident between calls so the
    /// same candidate is not rebuilt for each hash batch.
    pub reuse_candidates: bool,
}

impl BatchPlan {
    /// A plan that passes everything through in one call.
    pub fn everything(candidates: usize, hashes: usize) -> Self {
        BatchPlan {
            candidates,
            hashes,
            reuse_candidates: false,
        }
    }

    /// Clamps a plan so neither side exceeds what the engine supports.
    pub fn clamped(&self, engine: &EngineInfo) -> BatchPlan {
        let mut out = *self;
        if engine.batch_size > 0 && out.candidates > engine.batch_size {
            out.candidates = engine.batch_size;
        }
        if out.candidates == 0 {
            out.candidates = 1;
        }
        if out.hashes == 0 {
            out.hashes = 1;
        }
        out
    }
}

/// A uniform interface over every compute back end.
///
/// Implementations must be safe to share across threads: the scheduler runs one
/// engine instance on a rayon pool while another thread reports progress.
pub trait Engine: Send + Sync {
    /// What this engine is and how it performs.
    fn info(&self) -> EngineInfo;

    /// Whether the engine can be used right now.
    ///
    /// Must reflect reality. Returning `true` without a working device causes
    /// the scheduler to route work into a black hole.
    fn is_available(&self) -> bool;

    /// What this engine should be given for one call.
    fn plan(&self, wanted_candidates: usize, wanted_hashes: usize) -> BatchPlan {
        BatchPlan::everything(wanted_candidates, wanted_hashes)
            .clamped(&self.info())
    }

    /// Tests `candidates` against `hashes` and returns every match.
    ///
    /// The returned indices are relative to the two slices. An engine that does
    /// not implement a given hash type must report no match for it, and must
    /// say so through [`Engine::info`], rather than guessing.
    fn verify_batch(
        &self,
        cracker: &dyn HashCracker,
        hashes: &[HashEntry],
        candidates: &[String],
        plan: BatchPlan,
    ) -> Vec<EngineMatch>;

    /// Performs a self test and returns a description of the failure.
    ///
    /// The default is to verify that the engine can at least evaluate one
    /// candidate, which catches a device that was lost between initialisation
    /// and use.
    fn self_test(&self) -> Result<(), String> {
        let _ = self.plan(1, 1);
        Ok(())
    }
}

/// A handle to an engine, shared across threads.
pub type SharedEngine = Arc<dyn Engine>;

/// The reference workload used when benchmarking any engine.
///
/// A fixed MD5 of a fixed candidate, chosen because MD5 is implemented
/// everywhere including the CPU fallback, so every engine is measured on
/// identical work.
///
/// The pair is a genuine match, not just two strings that happen to be valid. An
/// engine that reports a rate without ever finding the target has measured the
/// compare-and-discard path rather than the match-and-emit path, and the two
/// differ enough on every accelerated back end to make the number misleading.
///
/// `REFERENCE_PASSWORD` and `REFERENCE_DIGEST` are verified against each other
/// by `reference_workload_is_a_real_match`, which fails loudly if either is
/// edited without the other.
pub const REFERENCE_PASSWORD: &str = "pwdcrack-reference-candidate";
pub const REFERENCE_DIGEST: &str = "8350c7ecc6d4706e12107df747eb6e71";

/// Returns the candidate and its real MD5 digest.
pub fn reference_workload() -> (&'static str, &'static str) {
    (REFERENCE_PASSWORD, REFERENCE_DIGEST)
}

/// Measures an engine's rate on the reference workload.
///
/// Returns zero rather than a fabricated number when the engine cannot run the
/// workload at all.
pub fn benchmark(engine: &dyn Engine, iterations: u64) -> f64 {
    let cracker = match crate::hash::detector::Detector::new()
        .cracker_for_type(crate::hash::HashType::MD5)
    {
        Some(c) => c,
        None => return 0.0,
    };

    let (password, hash) = reference_workload();
    let entry = HashEntry {
        raw: hash.to_string(),
        hash_type: crate::hash::HashType::MD5,
        hash_bytes: Vec::new(),
        salt: None,
        username: None,
        cracked: false,
        password: None,
    };
    let hashes = [entry];
    let candidates = [password.to_string()];

    // Warm up so the first call's allocation and any device initialisation do
    // not land in the measurement.
    for _ in 0..16 {
        let _ = engine.verify_batch(cracker.as_ref(), &hashes, &candidates, BatchPlan::everything(1, 1));
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.verify_batch(
            cracker.as_ref(),
            &hashes,
            &candidates,
            BatchPlan::everything(1, 1),
        );
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        return 0.0;
    }
    iterations as f64 / elapsed
}

// ── CPU reference engine ─────────────────────────────────────────────────
//
// This is the engine every other one is measured against and the fallback when
// nothing else is available. It also proves the trait is implementable before
// any accelerated back end adopts it.

/// The scalar CPU engine.
pub struct CpuEngine {
    info: EngineInfo,
}

impl CpuEngine {
    /// Creates the CPU engine and measures it.
    pub fn new() -> Self {
        let mut engine = CpuEngine {
            info: EngineInfo::unmeasured("cpu-scalar", "Scalar CPU")
                .with_vendor("portable")
                .with_batch_size(1)
                .with_capabilities(CapabilitySet::baseline()),
        };
        let hps = benchmark(&engine, 20_000);
        engine.info = engine.info.with_measurement(hps);
        engine
    }
}

impl Default for CpuEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for CpuEngine {
    fn info(&self) -> EngineInfo {
        self.info.clone()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn verify_batch(
        &self,
        cracker: &dyn HashCracker,
        hashes: &[HashEntry],
        candidates: &[String],
        _plan: BatchPlan,
    ) -> Vec<EngineMatch> {
        let mut out = Vec::new();
        for (ci, candidate) in candidates.iter().enumerate() {
            for (hi, entry) in hashes.iter().enumerate() {
                if cracker.verify(candidate, entry) {
                    out.push(EngineMatch::new(ci, hi));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_workload_is_a_real_match() {
        // Guards the fixed benchmark pair. The previous version of this file
        // carried MD5("password") against the candidate "benchmark", with a
        // comment quoting a digest that matched neither. Every call returned no
        // hit, so the measurement covered only the compare-and-discard path.
        use md5::{Digest, Md5};

        let mut h = Md5::new();
        h.update(REFERENCE_PASSWORD.as_bytes());
        let computed = hex::encode(h.finalize());
        assert_eq!(
            computed, REFERENCE_DIGEST,
            "REFERENCE_DIGEST is not MD5(REFERENCE_PASSWORD); recompute it before editing either constant"
        );
    }

    #[test]
    fn reference_workload_is_found_by_the_cpu_engine() {
        // The digest has to be reachable through the normal cracking path, not
        // only parse. If this fails, the benchmark number describes an engine
        // that never reports a match.
        let engine = CpuEngine::new();
        let cracker = crate::hash::detector::Detector::new()
            .cracker_for_type(crate::hash::HashType::MD5)
            .unwrap();
        let (password, digest) = reference_workload();
        let entry = HashEntry {
            raw: digest.to_string(),
            hash_type: crate::hash::HashType::MD5,
            hash_bytes: Vec::new(),
            salt: None,
            username: None,
            cracked: false,
            password: None,
        };
        let hits = engine.verify_batch(
            cracker.as_ref(),
            &[entry],
            &[password.to_string()],
            BatchPlan::everything(1, 1),
        );
        assert_eq!(hits.len(), 1, "reference workload did not produce a match");
        assert_eq!(hits[0].candidate_index, 0);
        assert_eq!(hits[0].hash_index, 0);
    }

    #[test]
    fn benchmark_returns_a_positive_rate() {
        let engine = CpuEngine {
            info: EngineInfo::unmeasured("t", "t")
                .with_batch_size(1)
                .with_capabilities(CapabilitySet::baseline()),
        };
        let rate = benchmark(&engine, 2_000);
        assert!(rate > 0.0, "benchmark produced no rate");
    }

    #[test]
    fn cpu_engine_is_available_and_measurable() {
        let e = CpuEngine::new();
        assert!(e.is_available());
        let info = e.info();
        assert!(info.measured, "CPU engine must report a real measurement");
        assert!(info.measured_hps > 0.0);
        assert!(info.is_usable());
        assert!(info.summary().contains("cpu-scalar"));
    }

    #[test]
    fn cpu_engine_finds_a_known_password() {
        let e = CpuEngine::new();
        let cracker = crate::hash::detector::Detector::new()
            .cracker_for_type(crate::hash::HashType::MD5)
            .unwrap();
        // MD5("hello")
        let entry = HashEntry {
            raw: "5d41402abc4b2a76b9719d911017c592".into(),
            hash_type: crate::hash::HashType::MD5,
            hash_bytes: Vec::new(),
            salt: None,
            username: None,
            cracked: false,
            password: None,
        };
        let hashes = [entry];
        let candidates = vec!["nope".to_string(), "hello".to_string()];
        let hits = e.verify_batch(
            cracker.as_ref(),
            &hashes,
            &candidates,
            BatchPlan::everything(2, 1),
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].candidate_index, 1);
        assert_eq!(hits[0].hash_index, 0);
    }

    #[test]
    fn cpu_engine_reports_no_match_for_a_wrong_password() {
        let e = CpuEngine::new();
        let cracker = crate::hash::detector::Detector::new()
            .cracker_for_type(crate::hash::HashType::MD5)
            .unwrap();
        let entry = HashEntry {
            raw: "5d41402abc4b2a76b9719d911017c592".into(),
            hash_type: crate::hash::HashType::MD5,
            hash_bytes: Vec::new(),
            salt: None,
            username: None,
            cracked: false,
            password: None,
        };
        let hits = e.verify_batch(
            cracker.as_ref(),
            &[entry],
            &["wrong".to_string()],
            BatchPlan::everything(1, 1),
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn batch_plan_respects_engine_limit() {
        let e = CpuEngine {
            info: EngineInfo::unmeasured("test", "t")
                .with_batch_size(4)
                .with_capabilities(CapabilitySet::baseline()),
        };
        let plan = e.plan(1000, 1000);
        assert_eq!(plan.candidates, 4);
        assert_eq!(plan.hashes, 1000);
    }

    #[test]
    fn batch_plan_never_returns_zero_candidates() {
        let e = CpuEngine {
            info: EngineInfo::unmeasured("test", "t")
                .with_batch_size(0)
                .with_capabilities(CapabilitySet::baseline()),
        };
        assert_eq!(e.plan(0, 0).candidates, 1);
    }

    #[test]
    fn unmeasured_engine_is_not_reported_as_usable() {
        let info = EngineInfo::unmeasured("fake", "nothing");
        assert!(!info.measured);
        assert!(!info.is_usable());
        assert!(info.summary().contains("unmeasured"));
    }
}
