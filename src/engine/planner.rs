//! Work planning and result merging for multi engine execution.
//!
//! ## How the split works
//!
//! Each candidate range is divided into chunks sized to the engine's declared
//! batch. Every engine gets chunks in proportion to its measured throughput, so
//! a fast GPU receives more work than a slow FPGA and neither sits idle. Slow
//! engines start first: a bcrypt run on an FPGA takes minutes per chunk, so
//! giving it the first chunks removes the tail latency a CPU would otherwise
//! absorb at the end.
//!
//! ## Why chunks carry an engine assignment
//!
//! [`Chunk`] records which engine owns it. That makes a resumed run replay the
//! same assignment, which is what lets [`crate::attack::session`] guarantee that
//! a resumed run and an uninterrupted run test the same candidates against the
//! same engines. Without that guarantee the differential test between the two is
//! meaningless.

use std::collections::HashSet;
use std::sync::Arc;

use crate::engine::{Capability, EngineInfo, SharedEngine};

/// One unit of work: a candidate index range for one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// First candidate index, inclusive.
    pub start: u64,
    /// Last candidate index, exclusive.
    pub end: u64,
    /// Index into the plan's engine list.
    pub engine: usize,
}

impl Chunk {
    /// How many candidates this chunk covers.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the chunk is empty.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// One match found while executing a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMatch {
    /// Candidate index.
    pub candidate: u64,
    /// Hash index.
    pub hash: usize,
    /// Which engine found it, for reporting and for the resume record.
    pub engine: usize,
    /// Engine name, captured so a result survives the engine list being
    /// dropped.
    pub engine_name: &'static str,
}

/// A complete work plan.
///
/// Deliberately not `Debug`: `Arc<dyn Engine>` has no `Debug` bound and adding
/// one to the trait would force every engine to format itself, which no engine
/// needs. Use [`Plan::describe`] for a printable form.
#[derive(Clone)]
pub struct Plan {
    /// Total candidates the plan covers.
    pub total: u64,
    /// Chunk list, in execution order.
    pub chunks: Vec<Chunk>,
    /// Engines used, indexed by `Chunk::engine`.
    pub engines: Vec<Arc<dyn crate::engine::Engine>>,
    /// Capabilities the run needs. An engine lacking one is not assigned work.
    pub required: Vec<Capability>,
}

impl Plan {
    /// Whether the plan has any work at all.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Total candidates across all chunks, for reporting.
    pub fn planned_candidates(&self) -> u64 {
        self.chunks.iter().map(|c| c.len()).sum()
    }

    /// Printable form for `doctor` and error messages.
    pub fn describe(&self) -> String {
        let mut s = format!(
            "plan over {} candidates in {} chunks across {} engine(s)",
            self.total,
            self.chunks.len(),
            self.engines.len()
        );
        for (name, count) in self.per_engine() {
            s.push_str(&format!("\n  {name}: {count} candidates"));
        }
        s
    }

    /// Per engine candidate totals, for the run summary.
    pub fn per_engine(&self) -> Vec<(String, u64)> {
        let mut totals = vec![0u64; self.engines.len()];
        for c in &self.chunks {
            if let Some(t) = totals.get_mut(c.engine) {
                *t += c.len();
            }
        }
        self.engines
            .iter()
            .enumerate()
            .map(|(i, e)| (e.info().name.to_string(), totals[i]))
            .collect()
    }
}

/// Builds a work plan over `total` candidates.
///
/// `engines` is filtered to those that are available and that declare every
/// capability in `required`. An engine missing one capability is dropped
/// entirely rather than given work it cannot finish, which is the point of the
/// capability set.
///
/// Returns `None` when no engine qualifies, so the caller can fall back rather
/// than silently doing nothing.
pub fn build(
    engines: &[SharedEngine],
    total: u64,
    required: &[Capability],
) -> Option<Plan> {
    // Filter to usable engines that satisfy the requirement set.
    let mut usable: Vec<SharedEngine> = engines
        .iter()
        .filter(|e| e.is_available())
        .filter(|e| {
            let info = e.info();
            required.iter().all(|c| info.capabilities.contains(*c))
        })
        .cloned()
        .collect();

    if usable.is_empty() {
        return None;
    }

    // Sort slowest first so the long pole starts immediately.
    usable.sort_by(|a, b| {
        let ra = a.info().measured_hps;
        let rb = b.info().measured_hps;
        // Unmeasured engines (rate 0) sort first: they are the ones most likely
        // to be a surprise later, so give them the early chunks.
        ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Assign candidate counts proportional to measured rate.
    let rates: Vec<f64> = usable.iter().map(|e| e.info().measured_hps.max(0.0)).collect();
    let rate_sum: f64 = rates.iter().sum();

    let mut chunks: Vec<Chunk> = Vec::new();
    if rate_sum <= 0.0 {
        // No usable rates. Give everything to the first engine rather than
        // refusing to run; a single engine always makes forward progress.
        chunks.push(Chunk { start: 0, end: total, engine: 0 });
    } else {
        // Build a contiguous partition so every candidate is covered exactly
        // once, with no overlap and no gaps.
        let mut cursor: u64 = 0;
        for (i, engine) in usable.iter().enumerate() {
            let share = (rates[i] / rate_sum) * total as f64;
            let mut end = cursor + share.round() as u64;
            if i == usable.len() - 1 {
                end = total; // last engine absorbs rounding drift
            }
            end = end.min(total);
            if end > cursor {
                // Chunk size honours the engine's batch preference where it has
                // one, so a GPU gets large dispatches and a scalar engine gets
                // small ones.
                let batch = {
                    let b = engine.info().batch_size;
                    if b == 0 { 65_536 } else { b as u64 }
                };
                let mut s = cursor;
                while s < end {
                    let e = (s + batch).min(end);
                    chunks.push(Chunk { start: s, end: e, engine: i });
                    s = e;
                }
                cursor = end;
            }
        }
        // If rounding left the last engine with nothing, append a final chunk.
        if cursor < total && !usable.is_empty() {
            chunks.push(Chunk {
                start: cursor,
                end: total,
                engine: usable.len() - 1,
            });
        }
    }

    Some(Plan {
        total,
        chunks,
        engines: usable,
        required: required.to_vec(),
    })
}

/// Merges matches from parallel execution into a stable, deduplicated list.
///
/// Two engines can report the same candidate if a duplicate falls on a chunk
/// boundary, so results are deduplicated on `(candidate, hash)`. The output is
/// sorted by candidate then hash so a run produces the same order regardless of
/// which engine finished first. Deterministic output matters because these
/// results are written to the potfile and compared across runs in tests.
pub fn merge(raw: Vec<PlannedMatch>) -> Vec<PlannedMatch> {
    let mut seen: HashSet<(u64, usize)> = HashSet::with_capacity(raw.len());
    let mut out: Vec<PlannedMatch> = Vec::with_capacity(raw.len());
    for m in raw {
        if seen.insert((m.candidate, m.hash)) {
            out.push(m);
        }
    }
    out.sort_by(|a, b| {
        a.candidate
            .cmp(&b.candidate)
            .then(a.hash.cmp(&b.hash))
            .then_with(|| a.engine_name.cmp(b.engine_name))
    });
    out
}

/// Picks the fastest engine that can handle the requirement set.
///
/// This is the common case: one engine does the work. The planner above is only
/// needed when the user explicitly requests a hybrid run.
pub fn fastest_suitable(
    engines: &[SharedEngine],
    required: &[Capability],
) -> Option<SharedEngine> {
    engines
        .iter()
        .filter(|e| e.is_available())
        .filter(|e| {
            let info = e.info();
            required.iter().all(|c| info.capabilities.contains(*c))
        })
        .max_by(|a, b| {
            let ra = a.info().measured_hps;
            let rb = b.info().measured_hps;
            ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// Human readable summary of every engine, for `pwdcrack doctor`.
pub fn describe_all(engines: &[SharedEngine]) -> Vec<EngineInfo> {
    engines.iter().map(|e| e.info()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{CpuEngine, EngineInfo, CapabilitySet};
    use std::sync::atomic::{AtomicU64, Ordering};

    // A fake engine so planning can be tested without real hardware.
    struct FakeEngine {
        info: EngineInfo,
        found: AtomicU64,
    }

    impl FakeEngine {
        fn new(name: &'static str, hps: f64, batch: usize, caps: CapabilitySet) -> Arc<dyn crate::engine::Engine> {
            Arc::new(FakeEngine {
                info: EngineInfo::unmeasured(name, name)
                    .with_vendor("fake")
                    .with_batch_size(batch)
                    .with_capabilities(caps)
                    .with_measurement(hps),
                found: AtomicU64::new(0),
            })
        }
    }

    impl crate::engine::Engine for FakeEngine {
        fn info(&self) -> EngineInfo { self.info.clone() }
        fn is_available(&self) -> bool { true }
        fn verify_batch(
            &self,
            _c: &dyn crate::hash::HashCracker,
            _h: &[crate::hash::HashEntry],
            candidates: &[String],
            _plan: crate::engine::BatchPlan,
        ) -> Vec<crate::engine::EngineMatch> {
            self.found.fetch_add(candidates.len() as u64, Ordering::Relaxed);
            Vec::new()
        }
    }

    #[test]
    fn single_engine_covers_every_candidate_exactly_once() {
        let e = FakeEngine::new("solo", 1000.0, 100, CapabilitySet::all());
        let plan = build(&[e], 1000, &[]).unwrap();
        assert_eq!(plan.planned_candidates(), 1000);
        // Contiguous, no gaps, no overlap.
        let mut expect = 0;
        for c in &plan.chunks {
            assert_eq!(c.start, expect);
            expect = c.end;
        }
        assert_eq!(expect, 1000);
    }

    #[test]
    fn two_engines_partition_without_overlap_or_gaps() {
        let a = FakeEngine::new("slow", 1000.0, 10, CapabilitySet::all());
        let b = FakeEngine::new("fast", 3000.0, 10, CapabilitySet::all());
        let plan = build(&[a, b], 1000, &[]).unwrap();
        assert_eq!(plan.planned_candidates(), 1000);
        let mut expect = 0;
        for c in &plan.chunks {
            assert_eq!(c.start, expect, "gap or overlap at chunk {:?}", c);
            expect = c.end;
        }
        assert_eq!(expect, 1000);
    }

    #[test]
    fn work_is_split_by_measured_rate() {
        // A 3:1 fast:slow ratio should give the fast engine about three
        // quarters of the work.
        let slow = FakeEngine::new("slow", 1000.0, 1, CapabilitySet::all());
        let fast = FakeEngine::new("fast", 3000.0, 1, CapabilitySet::all());
        let plan = build(&[slow, fast], 1000, &[]).unwrap();
        let per: Vec<u64> = plan.per_engine().into_iter().map(|(_, c)| c).collect();
        let total: u64 = per.iter().sum();
        assert_eq!(total, 1000);
        assert!(per[0] < per[1], "fast engine should get more work: {per:?}");
        // Roughly 250 slow, 750 fast.
        assert!((per[0] as i64 - 250).abs() < 40, "slow share {} off", per[0]);
    }

    #[test]
    fn engine_missing_a_capability_is_excluded() {
        let no_gpu = {
            let mut c = CapabilitySet::baseline();
            c.remove(Capability::Blake);
            FakeEngine::new("limited", 5000.0, 10, c)
        };
        let plan = build(&[no_gpu], 100, &[Capability::Blake]);
        assert!(plan.is_none(), "engine without the capability must not be used");
    }

    #[test]
    fn no_engines_yields_none() {
        assert!(build(&[], 100, &[]).is_none());
    }

    #[test]
    fn zero_total_yields_no_chunks() {
        let e = FakeEngine::new("solo", 1000.0, 10, CapabilitySet::all());
        let plan = build(&[e], 0, &[]).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn merge_deduplicates_and_sorts() {
        let raw = vec![
            PlannedMatch { candidate: 5, hash: 1, engine: 0, engine_name: "a" },
            PlannedMatch { candidate: 5, hash: 1, engine: 1, engine_name: "b" },
            PlannedMatch { candidate: 2, hash: 0, engine: 0, engine_name: "a" },
            PlannedMatch { candidate: 5, hash: 0, engine: 0, engine_name: "a" },
        ];
        let merged = merge(raw);
        assert_eq!(merged.len(), 3, "the duplicate (5,1) must collapse");
        assert_eq!(merged[0].candidate, 2);
        assert_eq!(merged[1].hash, 0);
        assert_eq!(merged[2].hash, 1);
    }

    #[test]
    fn merge_is_deterministic_regardless_of_input_order() {
        let mk = |cands: &[u64]| -> Vec<PlannedMatch> {
            cands.iter().map(|c| PlannedMatch {
                candidate: *c, hash: 0, engine: 0, engine_name: "x",
            }).collect()
        };
        let a = merge(mk(&[3, 1, 2]));
        let b = merge(mk(&[1, 2, 3]));
        assert_eq!(a, b);
    }

    #[test]
    fn fastest_suitable_picks_the_highest_rate() {
        let slow = FakeEngine::new("slow", 100.0, 1, CapabilitySet::all());
        let fast = FakeEngine::new("fast", 900.0, 1, CapabilitySet::all());
        let picked = fastest_suitable(&[slow, fast], &[]).unwrap();
        assert_eq!(picked.info().name, "fast");
    }

    #[test]
    fn fastest_suitable_returns_none_when_capability_missing() {
        let mut caps = CapabilitySet::all();
        caps.remove(Capability::Argon2);
        let e = FakeEngine::new("noargon2", 900.0, 1, caps);
        assert!(fastest_suitable(&[e], &[Capability::Argon2]).is_none());
    }

    #[test]
    fn describe_all_returns_one_info_per_engine() {
        let e = FakeEngine::new("x", 1.0, 1, CapabilitySet::all());
        let infos = describe_all(&[e]);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "x");
    }
}
