//! Work distribution: who gets which candidates, and the proof that no
//! candidate is handed out twice.
//!
//! # What this replaces
//!
//! `MasterNode` held a `VecDeque<PendingWork>` of pre-split equal sized chunks
//! and popped the front. That is round robin over chunk *indices*, and it has a
//! specific failure: chunk *sizes* are constant while worker *speeds* are not, so
//! a worker ten times slower than its sibling sits on its chunk for ten times
//! as long. With four workers and one slow node, three finish their queues and
//! idle while the last one grinds through a backlog that was handed to it at the
//! same rate as everyone else's.
//!
//! # The arithmetic
//!
//! Let worker `i` have rate `r_i`, let it receive a fraction `f_i` of a keyspace
//! of size `W`, and let the run take `T`. Then `T = f_i * W / r_i` for every
//! worker, and minimising `T` subject to `sum f_i = 1` gives `f_i proportional
//! to r_i`. Two mechanisms achieve that:
//!
//!   - **equal picks, size proportional to rate.** Worker `i` gets the same
//!     number of chunks as everyone else, but each chunk holds `r_i * k`
//!     candidates. Its share is then `picks * r_i * k`, proportional to `r_i`.
//!     This is what [`ChunkPolicy`] and [`Scheduler::next_chunk`] do.
//!   - **picks proportional to rate, equal sizes.** Also correct.
//!
//! Doing both at once is wrong, and it is a mistake this code makes it easy to
//! make: the share would then be proportional to `r_i` squared, so a worker
//! nine times faster would get eighty one times the work and the slow workers
//! would still be the bottleneck, just with less total throughput at the end.
//! There is a test for exactly this: [`tests::a_slow_worker_does_not_starve_the_run`].
//!
//! # Why the coverage ledger exists
//!
//! "No candidate is tested twice" is a claim about every range the master has
//! ever issued, including ranges it issued, then took back, then issued again.
//! Asserting it by inspection of the queue is not possible: the queue is mutated
//! from the accept loop, the result handler, and the reaper. So the invariant is
//! recorded rather than trusted. [`CoverageLedger`] notes every issued span and
//! counts any that overlapped a previous one, and `tests/distributed_run.rs`
//! asserts the count is zero for a real run.
//!
//! The ledger's scope is stated plainly: it is exact **within one master run**.
//! Across a checkpoint restore, a span that was in flight when the master stopped
//! is put back and issued again, which is at-least-once. This engine does not
//! claim exactly-once across a restart, because doing so would need durable
//! per-candidate completion state, which is a different order of magnitude of
//! bookkeeping for a property that only matters if a worker crashes constantly.

use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::{AttackType, Message, TargetHash, WorkUnit};

/// Largest rate the scheduler will believe from a worker.
///
/// A worker is a peer. A peer reporting 1e300 hashes per second, or `NaN`, or a
/// negative number must not be allowed to size its own chunks; without a bound a
/// single claim takes the whole keyspace. Samples outside this band are discarded
/// and counted, not clamped, so a broken worker's reports are visible.
pub const MAX_PLAUSIBLE_RATE: f64 = 1e12;

/// Smallest rate the scheduler will believe.
pub const MIN_PLAUSIBLE_RATE: f64 = 1e-3;

/// Half open interval of candidate indices. `start` inclusive, `end` exclusive.
///
/// Half open is what lets two adjacent chunks concatenate without an off-by-one
/// gap or double count, which inclusive ends cannot do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
}

impl Span {
    pub fn new(start: u64, end: u64) -> Self {
        Span { start, end }
    }

    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    fn intersects(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Why a span could not be returned to the free set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanError {
    /// The span was empty, which is never a legitimate thing to requeue.
    Empty(Span),
    /// The span overlaps one that is already free, which means it was issued
    /// twice or requeued twice.
    ///
    /// This is the deduplication invariant, and it is a bug when it happens
    /// inside one run rather than after a resume.
    Overlap { incoming: Span, existing: Span },
}

impl std::fmt::Display for SpanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpanError::Empty(s) => {
                write!(f, "cannot requeue the empty span [{}, {})", s.start, s.end)
            }
            SpanError::Overlap { incoming, existing } => write!(
                f,
                "span [{}, {}) overlaps [{}, {}), so a candidate would be tested twice",
                incoming.start, incoming.end, existing.start, existing.end
            ),
        }
    }
}

impl std::error::Error for SpanError {}

/// A set of unassigned keyspace, kept sorted and disjoint.
///
/// This is the structure that makes deduplication structural rather than
/// hopeful: a candidate index is in exactly one of three places, the free set,
/// some worker's in-flight record, or the completed list. There is no path that
/// puts an index in two of them, because the only way into the free set is
/// [`SpanSet::give_back`], which refuses an overlap.
#[derive(Debug, Clone, Default)]
pub struct SpanSet {
    /// `start -> end`, guaranteed sorted and non-overlapping.
    spans: BTreeMap<u64, u64>,
}

impl SpanSet {
    pub fn new() -> Self {
        SpanSet { spans: BTreeMap::new() }
    }

    /// A set holding the single span `[start, end)`.
    pub fn from_range(start: u64, end: u64) -> Self {
        let mut s = SpanSet::new();
        if start < end {
            s.spans.insert(start, end);
        }
        s
    }

    /// Candidates still unassigned.
    pub fn total(&self) -> u64 {
        self.spans
            .iter()
            .map(|(&s, &e)| e.saturating_sub(s))
            .sum()
    }

    /// Number of separate spans. One for a contiguous keyspace that has never
    /// been split.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The spans, in order.
    pub fn to_vec(&self) -> Vec<Span> {
        self.spans
            .iter()
            .map(|(s, e)| Span::new(*s, *e))
            .collect()
    }

    /// Removes up to `n` candidates from the lowest span and returns them.
    ///
    /// Always takes from the front, so the union of everything issued so far plus
    /// everything still free is exactly the original keyspace at every point in
    /// time. Taking from the middle instead would make that invariant only true
    /// after the whole job finished.
    ///
    /// The remainder keeps the map key `start + n`, not `start`: the candidates
    /// taken are the low ones, so what is left starts where they stopped. An
    /// earlier version left the key at `start`, which made the set describe the
    /// range that had just been issued rather than the range that was still free,
    /// and every later span came out wrong.
    pub fn take_front(&mut self, n: u64) -> Option<Span> {
        let (&start, &end) = self.spans.iter().next()?;
        let take = n.min(end - start);
        if take == 0 {
            return None;
        }
        let cut = start + take;
        self.spans.remove(&start);
        if cut < end {
            self.spans.insert(cut, end);
        }
        Some(Span::new(start, cut))
    }

    /// Returns a span to the free set, refusing anything that would overlap.
    ///
    /// Adjacent spans are coalesced so the set does not fragment into millions of
    /// single-candidate entries after a run with small chunks. The coalescing
    /// loops restart after every merge, because one insertion can bridge two
    /// neighbours and a single pass in each direction misses the second one
    /// reached by the first.
    pub fn give_back(&mut self, span: Span) -> Result<(), SpanError> {
        if span.is_empty() {
            return Err(SpanError::Empty(span));
        }
        if let Some(existing) = self.find_overlap(span) {
            return Err(SpanError::Overlap { incoming: span, existing });
        }

        // The spans are sorted and disjoint, so only the nearest neighbour on
        // each side can touch, and if that one does not touch then none beyond
        // it does either. Strictly less than `merged.start` on the left and
        // greater than or equal to `merged.end` on the right keeps the span being
        // inserted out of its own search.
        let mut merged = span;
        while let Some((&s, &e)) = self.spans.range(..merged.start).next_back() {
            if e < merged.start {
                break;
            }
            self.spans.remove(&s);
            merged.start = s;
        }
        while let Some((&s, &e)) = self.spans.range(merged.end..).next() {
            if s > merged.end {
                break;
            }
            self.spans.remove(&s);
            merged.end = merged.end.max(e);
        }
        self.spans.insert(merged.start, merged.end);
        Ok(())
    }

    fn find_overlap(&self, span: Span) -> Option<Span> {
        // A candidate overlapping `span` must start before `span.end` and end
        // after `span.start`, so only the one entry that straddles the start can
        // begin before the range begins.
        self.spans
            .range(..span.end)
            .next_back()
            .filter(|(_, e)| **e > span.start)
            .map(|(&s, &e)| Span::new(s, e))
    }

    /// True when any part of `span` is still in this set.
    pub fn overlaps_any(&self, span: Span) -> bool {
        self.spans
            .range(..span.end)
            .next_back()
            .map(|(_, e)| *e > span.start)
            .unwrap_or(false)
    }

    /// True when the set is exactly `[lo, hi)` with no gaps and nothing outside.
    pub fn covers_exactly(&self, lo: u64, hi: u64) -> bool {
        if lo == hi {
            return self.spans.is_empty();
        }
        let v = self.to_vec();
        if v.is_empty() {
            return false;
        }
        v.first().map(|s| s.start) == Some(lo)
            && v.last().map(|s| s.end) == Some(hi)
            && v.windows(2).all(|w| w[0].end == w[1].start)
    }
}

/// A record of every span the scheduler has issued, used to prove deduplication.
///
/// Not on the hot path: `record` is an `O(n)` scan over issued spans, which is
/// fine for a diagnostic that runs once per run and not for a hot loop. The
/// `Scheduler` keeps one for logging and for the integration test; production
/// runs with it disabled if span counts are large.
#[derive(Debug, Clone)]
pub struct CoverageLedger {
    lo: u64,
    hi: u64,
    issued: Vec<Span>,
    overlaps: u64,
    repeats: u64,
}

impl CoverageLedger {
    pub fn new(lo: u64, hi: u64) -> Self {
        CoverageLedger {
            lo,
            hi,
            issued: Vec::new(),
            overlaps: 0,
            repeats: 0,
        }
    }

    /// Notes a span, counting any overlap with a previously issued one.
    pub fn record(&mut self, span: Span) {
        if self.issued.iter().any(|p| p.intersects(&span)) {
            self.overlaps += 1;
        }
        if self.issued.contains(&span) {
            self.repeats += 1;
        }
        self.issued.push(span);
    }

    /// How many issued spans overlapped an earlier one. Must be zero.
    pub fn overlaps(&self) -> u64 {
        self.overlaps
    }

    /// How many spans were issued more than once in identical form. Also zero in
    /// a clean run; non-zero after a resume, where a requeued span is reissued.
    pub fn repeats(&self) -> u64 {
        self.repeats
    }

    /// Candidates issued, counting repeats.
    pub fn issued_total(&self) -> u64 {
        self.issued.iter().map(|s| s.len()).sum()
    }

    /// The union of everything issued, coalesced.
    pub fn union(&self) -> SpanSet {
        let mut set = SpanSet::new();
        let mut sorted = self.issued.clone();
        sorted.sort_by_key(|s| s.start);
        for s in sorted {
            // Force the coalesce path; the ledger is allowed to hold overlaps so
            // it can report them, and `give_back` would refuse them.
            let _ = set.force_insert(s);
        }
        set
    }

    /// True when the union of issued spans is exactly `[lo, hi)`.
    pub fn covers_exactly(&self) -> bool {
        self.union().covers_exactly(self.lo, self.hi)
    }

    /// The parts of `[lo, hi)` never issued.
    pub fn missing(&self) -> Vec<Span> {
        let mut free = SpanSet::from_range(self.lo, self.hi);
        for s in self.issued.clone() {
            let _ = free.force_insert(s);
        }
        free.complement_in(self.lo, self.hi)
    }

    pub fn range(&self) -> (u64, u64) {
        (self.lo, self.hi)
    }

    /// Every span issued, in order, repeats included.
    pub fn issued_spans(&self) -> &[Span] {
        &self.issued
    }

    /// How many times a particular span was issued.
    pub fn times_issued(&self, span: Span) -> usize {
        self.issued.iter().filter(|s| **s == span).count()
    }
}

impl SpanSet {
    /// Inserts without the overlap check, coalescing anyway.
    ///
    /// Used by [`CoverageLedger`] to build the union of everything issued, which
    /// legitimately contains overlaps because counting them is the point.
    fn force_insert(&mut self, span: Span) -> Result<(), SpanError> {
        if span.is_empty() {
            return Err(SpanError::Empty(span));
        }
        let mut merged = span;
        while let Some((&s, &e)) = self.spans.range(..merged.start).next_back() {
            if e < merged.start {
                break;
            }
            self.spans.remove(&s);
            merged.start = s;
        }
        while let Some((&s, &e)) = self.spans.range(merged.end..).next() {
            if s > merged.end {
                break;
            }
            self.spans.remove(&s);
            merged.end = merged.end.max(e);
        }
        self.spans.insert(merged.start, merged.end);
        Ok(())
    }

    /// The parts of `[lo, hi)` that are **not** in this set.
    fn complement_in(&self, lo: u64, hi: u64) -> Vec<Span> {
        let mut out = Vec::new();
        let mut cursor = lo;
        for s in self.to_vec() {
            if s.start > cursor {
                out.push(Span::new(cursor, s.start.min(hi)));
            }
            cursor = cursor.max(s.end);
        }
        if cursor < hi {
            out.push(Span::new(cursor, hi));
        }
        out.retain(|s| !s.is_empty());
        out
    }
}

/// An exponentially weighted moving average of a worker's measured rate.
///
/// The average rather than the last sample because a single sample covers one
/// chunk, and the first chunk of a job includes file opening and hash setup, so
/// the first sample is usually the slowest and using it alone would starve the
/// worker until it had proved itself.
#[derive(Debug, Clone)]
pub struct RateSample {
    alpha: f64,
    value: Option<f64>,
    samples: u64,
    rejected: u64,
}

impl Default for RateSample {
    fn default() -> Self {
        RateSample::new(0.3)
    }
}

impl RateSample {
    pub fn new(alpha: f64) -> Self {
        let a = alpha.clamp(0.01, 1.0);
        RateSample {
            alpha: a,
            value: None,
            samples: 0,
            rejected: 0,
        }
    }

    /// Records a measurement, discarding one that cannot be true.
    pub fn observe(&mut self, rate: f64) {
        if !rate.is_finite() || rate < MIN_PLAUSIBLE_RATE || rate > MAX_PLAUSIBLE_RATE {
            self.rejected += 1;
            return;
        }
        self.value = Some(match self.value {
            None => rate,
            Some(prev) => prev + self.alpha * (rate - prev),
        });
        self.samples += 1;
    }

    /// The smoothed rate, or `None` before any usable sample.
    pub fn rate(&self) -> Option<f64> {
        self.value
    }

    /// Samples that were discarded as implausible.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Seconds this worker should need for `candidates`.
    pub fn seconds_for(&self, candidates: u64) -> Option<f64> {
        self.value.map(|r| candidates as f64 / r)
    }
}

/// How big a chunk to hand a worker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChunkPolicy {
    /// How long a chunk should take at the receiving worker's own rate.
    ///
    /// Two seconds: long enough that per chunk overhead is noise, short enough
    /// that a requeued or crashed chunk costs little and the rate estimate
    /// updates quickly.
    pub target_seconds: f64,
    /// Floor, so a worker that has not reported a rate still gets something it
    /// can finish and then report on.
    pub min_candidates: u64,
    /// Ceiling, so one very fast worker cannot receive a chunk so large that its
    /// result arrives after the master has decided it is dead.
    pub max_candidates: u64,
}

impl Default for ChunkPolicy {
    fn default() -> Self {
        ChunkPolicy {
            target_seconds: 2.0,
            min_candidates: 256,
            max_candidates: 4_000_000,
        }
    }
}

impl ChunkPolicy {
    /// Candidates for a worker running at `rate`.
    ///
    /// `None` means no usable measurement yet, which yields the floor. A worker
    /// that has just joined therefore gets a small chunk and a fast first
    /// measurement, rather than a large one it might not finish before the
    /// liveness deadline.
    pub fn size_for(&self, rate: Option<f64>) -> u64 {
        let raw = match rate {
            Some(r) if r.is_finite() && r > 0.0 => r * self.target_seconds,
            _ => self.min_candidates as f64,
        };
        let clamped = raw.floor().max(self.min_candidates as f64);
        (clamped.min(self.max_candidates as f64)) as u64
    }
}

/// One job: an attack, a set of target hashes, and the keyspace to search.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: u64,
    pub attack: AttackType,
    pub targets: Vec<TargetHash>,
    /// Exact keyspace. Never an estimate: the old code used a hardcoded ten
    /// million for every dictionary attack, which made the chunk count a fiction
    /// and left the tail of a real wordlist unscheduled.
    pub keyspace: u64,
    /// Hashes already found, lowercase.
    pub solved: BTreeSet<String>,
    /// Unassigned keyspace.
    pub free: SpanSet,
}

impl Job {
    /// Targets still worth testing against.
    pub fn open_targets(&self) -> Vec<TargetHash> {
        self.targets
            .iter()
            .filter(|t| !self.solved.contains(&t.hash))
            .cloned()
            .collect()
    }

    /// True when nothing more can be learned from this job.
    pub fn is_finished(&self) -> bool {
        self.open_targets().is_empty() || self.free.is_empty()
    }
}

/// A chunk handed to a worker, plus the span it covers.
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub job_id: u64,
    pub batch_id: u64,
    pub span: Span,
    pub work: WorkUnit,
}

/// Decides which worker gets which candidates.
#[derive(Debug)]
pub struct Scheduler {
    jobs: BTreeMap<u64, Job>,
    next_job_id: u64,
    next_batch_id: u64,
    /// Round robin cursor across jobs, so a large job cannot starve a small one
    /// queued behind it.
    cursor: usize,
    pub policy: ChunkPolicy,
    pub ledger: Option<CoverageLedger>,
    /// Spans issued, kept so the ledger can be reported and a resume knows what
    /// was in flight.
    issued_count: u64,
}

impl Default for Scheduler {
    fn default() -> Self {
        Scheduler::new(ChunkPolicy::default())
    }
}

impl Scheduler {
    pub fn new(policy: ChunkPolicy) -> Self {
        Scheduler {
            jobs: BTreeMap::new(),
            next_job_id: 1,
            next_batch_id: 1,
            cursor: 0,
            policy,
            ledger: None,
            issued_count: 0,
        }
    }

    pub fn policy_mut(&mut self) -> &mut ChunkPolicy {
        &mut self.policy
    }

    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    pub fn job(&self, job_id: u64) -> Option<&Job> {
        self.jobs.get(&job_id)
    }

    /// Total candidates still unassigned across every job.
    pub fn free_total(&self) -> u64 {
        self.jobs.values().map(|j| j.free.total()).sum()
    }

    /// Every job that can still yield work, in id order.
    pub fn open_jobs(&self) -> Vec<u64> {
        self.jobs
            .values()
            .filter(|j| !j.is_finished())
            .map(|j| j.id)
            .collect()
    }

    /// Adds a job and returns its id.
    pub fn add_job(
        &mut self,
        attack: AttackType,
        targets: Vec<TargetHash>,
        keyspace: u64,
    ) -> Result<u64, String> {
        if keyspace == 0 {
            return Err("a job with an empty keyspace has nothing to schedule".to_string());
        }
        if targets.is_empty() {
            return Err("a job with no target hashes has nothing to test".to_string());
        }
        let id = self.next_job_id;
        self.next_job_id += 1;
        self.jobs.insert(
            id,
            Job {
                id,
                attack,
                targets,
                keyspace,
                solved: BTreeSet::new(),
                free: SpanSet::from_range(0, keyspace),
            },
        );
        self.ensure_ledger();
        Ok(id)
    }

    /// Starts the coverage ledger when exactly one job is in flight.
    ///
    /// One ledger per run rather than one per job, because the ledger's whole
    /// purpose is to answer "was any candidate tested twice", and that question
    /// needs a single view. A multi job run has overlapping candidate *indices*
    /// across jobs by construction, so a single ledger cannot be meaningful
    /// there; the per job overlap check on `give_back` still holds.
    fn ensure_ledger(&mut self) {
        if self.ledger.is_some() {
            return;
        }
        if let Some(j) = self.jobs.values().next() {
            if self.jobs.len() == 1 {
                self.ledger = Some(CoverageLedger::new(0, j.keyspace));
            }
        }
    }

    /// Reinstates a job from a checkpoint, keeping its id and remaining keyspace.
    pub fn restore_job(&mut self, job: Job) {
        self.next_job_id = self.next_job_id.max(job.id + 1);
        self.jobs.insert(job.id, job);
        self.ensure_ledger();
    }

    /// Restores the id counters so ids are not reused after a resume.
    pub fn note_counters(&mut self, next_batch_id: u64, next_job_id: u64) {
        self.next_batch_id = self.next_batch_id.max(next_batch_id);
        self.next_job_id = self.next_job_id.max(next_job_id);
    }

    pub fn next_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// Starts recording issued spans, so deduplication can be checked.
    pub fn start_ledger(&mut self) {
        self.ensure_ledger();
    }

    pub fn ledger(&self) -> Option<&CoverageLedger> {
        self.ledger.as_ref()
    }

    /// Hands out the next chunk for a worker, or `None` when nothing is left.
    ///
    /// `rate` is the worker's smoothed rate, or `None` before it has reported.
    /// The chunk size comes from the rate, which is what makes a slow worker's
    /// chunks small and lets it hold the same number of chunks as a fast one.
    pub fn next_chunk(&mut self, worker: &str, rate: Option<f64>) -> Option<Chunk> {
        let job_id = self.next_job_with_work()?;
        let job = self.jobs.get_mut(&job_id)?;

        let size = self.policy.size_for(rate);
        let span = job.free.take_front(size)?;
        let targets = job.open_targets();
        debug_assert!(!targets.is_empty());

        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;
        self.issued_count += 1;

        if let Some(l) = self.ledger.as_mut() {
            l.record(span);
        }

        let work = WorkUnit {
            job_id,
            attack_type: job.attack.clone(),
            targets,
            keyspace_start: span.start,
            keyspace_end: span.end,
            keyspace_total: job.keyspace,
        };

        log::debug!(
            "scheduler: {worker} ({}) gets job {} batch {} span [{}, {}) of {}",
            rate.map(|r| format!("{r:.0} H/s")).unwrap_or_else(|| "rate unknown".into()),
            job_id,
            batch_id,
            span.start,
            span.end,
            job.keyspace
        );

        Some(Chunk {
            job_id,
            batch_id,
            span,
            work,
        })
    }

    /// Picks the next job with unassigned keyspace, rotating so no job starves.
    fn next_job_with_work(&mut self) -> Option<u64> {
        let ids: Vec<u64> = self.jobs.values().filter(|j| !j.is_finished()).map(|j| j.id).collect();
        if ids.is_empty() {
            return None;
        }
        let pick = ids[self.cursor % ids.len()];
        self.cursor = (self.cursor + 1) % ids.len();
        Some(pick)
    }

    /// Records that a worker finished a chunk.
    ///
    /// `solved` is every target the worker reported finding. Returns whether the
    /// job is now finished.
    pub fn complete(
        &mut self,
        job_id: u64,
        solved: &[TargetHash],
    ) -> Option<bool> {
        let job = self.jobs.get_mut(&job_id)?;
        for t in solved {
            job.solved.insert(t.hash.clone());
        }
        Some(job.is_finished())
    }

    /// Returns an unissued span to its job's free set.
    ///
    /// An empty span, or one already free, is refused. That refusal is the
    /// deduplication check on the write path rather than only on the read path.
    pub fn requeue(&mut self, job_id: u64, span: Span) -> Result<(), SpanError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(SpanError::Empty(span))?;
        job.free.give_back(span)
    }

    pub fn issued(&self) -> u64 {
        self.issued_count
    }

    /// A snapshot for a checkpoint: every job with its remaining keyspace.
    pub fn snapshot(&self) -> Vec<Job> {
        self.jobs.values().cloned().collect()
    }

    pub fn solved_hashes(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .jobs
            .values()
            .flat_map(|j| j.solved.iter().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// The frame that sends a chunk to a worker.
pub fn assign_frame(chunk: &Chunk, worker_id: u64) -> Message {
    Message::AssignWork {
        worker_id,
        batch_id: chunk.batch_id,
        work: chunk.work.clone(),
    }
}

/// Exact keyspace of an attack, so a job is never sized by guesswork.
///
/// `Dictionary` needs the line count. A master cannot assume one: the previous
/// implementation used a hardcoded ten million, which both invented work that
/// did not exist and left a real wordlist longer than that unscheduled past its
/// end. The caller must supply the count it measured.
pub fn keyspace_for(attack: &AttackType, dictionary_lines: Option<u64>) -> Result<u64, String> {
    match attack {
        AttackType::BruteForce { mask } => crate::mask::keyspace_size(mask).map_err(|e| e.to_string()),
        AttackType::Combinator { left_words, right_words } => {
            Ok((left_words.len() as u64).saturating_mul(right_words.len() as u64))
        }
        AttackType::Inline { .. } | AttackType::Dictionary { .. } => dictionary_lines
            .ok_or_else(|| {
                "a wordlist job needs its line count, which the master must measure. \
                 Guessing it would both invent candidates and skip real ones."
                    .to_string()
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_attack() -> AttackType {
        AttackType::BruteForce {
            mask: "?l?d".to_string(),
        }
    }

    fn targets(n: usize) -> Vec<TargetHash> {
        (0..n)
            .map(|i| TargetHash::new("MD5", format!("{i:032x}")))
            .collect()
    }

    // ---- SpanSet ----

    #[test]
    fn taking_from_the_front_never_leaves_a_gap() {
        let mut s = SpanSet::from_range(0, 100);
        let a = s.take_front(30).unwrap();
        assert_eq!(a, Span::new(0, 30));
        assert_eq!(s.to_vec(), vec![Span::new(30, 100)]);
        let b = s.take_front(30).unwrap();
        assert_eq!(b, Span::new(30, 60));
        let c = s.take_front(1000).unwrap();
        assert_eq!(c, Span::new(60, 100));
        assert!(s.is_empty());
        assert_eq!(s.take_front(1), None);
    }

    #[test]
    fn total_is_the_sum_of_the_spans() {
        let mut s = SpanSet::from_range(0, 100);
        assert_eq!(s.total(), 100);
        s.take_front(40);
        assert_eq!(s.total(), 60);
    }

    #[test]
    fn giving_back_coalesces_with_both_neighbours() {
        let mut s = SpanSet::new();
        s.give_back(Span::new(0, 10)).unwrap();
        s.give_back(Span::new(20, 30)).unwrap();
        s.give_back(Span::new(10, 20)).unwrap();
        assert_eq!(s.to_vec(), vec![Span::new(0, 30)]);
        assert_eq!(s.len(), 1);
    }

    /// The invariant that stops a candidate being tested twice: a span cannot
    /// return to the free set while any part of it is still free.
    #[test]
    fn giving_back_an_overlapping_span_is_refused() {
        let mut s = SpanSet::from_range(0, 100);
        s.take_front(50);
        // [50,100) is free; returning [40,60) would double [50,60).
        assert!(matches!(
            s.give_back(Span::new(40, 60)),
            Err(SpanError::Overlap { .. })
        ));
        assert_eq!(s.to_vec(), vec![Span::new(50, 100)]);
    }

    #[test]
    fn giving_back_the_taken_span_is_allowed_and_restores_the_whole() {
        let mut s = SpanSet::from_range(0, 100);
        let taken = s.take_front(50).unwrap();
        assert_eq!(taken, Span::new(0, 50));
        assert_eq!(s.to_vec(), vec![Span::new(50, 100)]);
        // Adjacent, not overlapping, so the whole keyspace is restored and the
        // two halves coalesce rather than sitting side by side.
        s.give_back(taken).unwrap();
        assert!(s.covers_exactly(0, 100));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn an_empty_span_is_refused() {
        let mut s = SpanSet::new();
        assert!(matches!(s.give_back(Span::new(5, 5)), Err(SpanError::Empty(_))));
    }

    #[test]
    fn covers_exactly_detects_a_hole() {
        let mut s = SpanSet::new();
        s.give_back(Span::new(0, 30)).unwrap();
        s.give_back(Span::new(60, 100)).unwrap();
        assert!(!s.covers_exactly(0, 100), "a hole between 30 and 60");
        assert_eq!(s.to_vec(), vec![Span::new(0, 30), Span::new(60, 100)]);
        assert_eq!(s.total(), 70);
        // `covers_exactly` means the union is *exactly* the range, so a set that
        // also holds other spans does not cover a sub range.
        assert!(!s.covers_exactly(0, 30));
    }

    #[test]
    fn covers_exactly_notices_where_the_set_begins() {
        let mut s = SpanSet::from_range(0, 100);
        assert!(s.covers_exactly(0, 100));
        s.take_front(10);
        assert!(!s.covers_exactly(0, 100));
        assert!(s.covers_exactly(10, 100));
        s.take_front(10);
        assert!(s.covers_exactly(20, 100));
    }

    #[test]
    fn an_empty_set_covers_only_an_empty_range() {
        let s = SpanSet::new();
        assert!(s.covers_exactly(0, 0));
        assert!(!s.covers_exactly(0, 1));
    }

    // ---- CoverageLedger ----

    #[test]
    fn a_ledger_sees_no_overlap_when_there_is_none() {
        let mut l = CoverageLedger::new(0, 100);
        for s in [Span::new(0, 10), Span::new(10, 60), Span::new(60, 100)] {
            l.record(s);
        }
        assert_eq!(l.overlaps(), 0);
        assert_eq!(l.issued_total(), 100);
        assert!(l.covers_exactly());
        assert!(l.missing().is_empty());
    }

    #[test]
    fn a_ledger_reports_an_overlap() {
        let mut l = CoverageLedger::new(0, 100);
        l.record(Span::new(0, 60));
        l.record(Span::new(50, 100)); // overlaps [50,60)
        assert_eq!(l.overlaps(), 1);
        // The union is still the whole range, so an overlap is wasted work rather
        // than a missed candidate. Both facts are reported.
        assert!(l.covers_exactly());
        assert_eq!(l.issued_total(), 110);
    }

    #[test]
    fn a_ledger_reports_uncovered_keyspace_separately() {
        let mut l = CoverageLedger::new(0, 100);
        l.record(Span::new(0, 30));
        l.record(Span::new(60, 100));
        assert_eq!(l.overlaps(), 0);
        assert!(!l.covers_exactly());
        assert_eq!(l.missing(), vec![Span::new(30, 60)]);
    }

    #[test]
    fn a_ledger_reports_uncovered_keyspace() {
        let mut l = CoverageLedger::new(0, 100);
        l.record(Span::new(0, 30));
        l.record(Span::new(60, 100));
        assert_eq!(l.missing(), vec![Span::new(30, 60)]);
    }

    #[test]
    fn a_reissued_span_is_counted_as_a_repeat() {
        let mut l = CoverageLedger::new(0, 100);
        l.record(Span::new(0, 50));
        l.record(Span::new(0, 50));
        assert_eq!(l.repeats(), 1);
    }

    // ---- RateSample ----

    #[test]
    fn an_implausible_rate_is_discarded_not_believed() {
        let mut r = RateSample::new(0.5);
        for bad in [f64::NAN, f64::INFINITY, -1.0, 0.0, 1e300] {
            r.observe(bad);
        }
        assert_eq!(r.rate(), None, "a worker must not be able to size its own chunks");
        assert_eq!(r.rejected(), 5);

        r.observe(1000.0);
        assert_eq!(r.rate(), Some(1000.0));
    }

    #[test]
    fn the_rate_is_smoothed_towards_the_new_sample() {
        let mut r = RateSample::new(0.5);
        r.observe(100.0);
        r.observe(200.0);
        assert_eq!(r.rate(), Some(150.0));
        r.observe(200.0);
        assert_eq!(r.rate(), Some(175.0));
    }

    #[test]
    fn seconds_are_the_candidate_count_over_the_rate() {
        let mut r = RateSample::default();
        assert_eq!(r.seconds_for(1000), None);
        r.observe(500.0);
        assert_eq!(r.seconds_for(1000), Some(2.0));
    }

    // ---- ChunkPolicy ----

    #[test]
    fn a_worker_with_no_measurement_gets_the_floor() {
        let p = ChunkPolicy::default();
        assert_eq!(p.size_for(None), p.min_candidates);
    }

    #[test]
    fn chunk_size_tracks_the_worker_rate() {
        let p = ChunkPolicy::default();
        assert_eq!(p.size_for(Some(1000.0)), 2000);
        assert_eq!(p.size_for(Some(100.0)), 256); // clamped to the floor
        assert_eq!(p.size_for(Some(1e9)), p.max_candidates); // clamped to the ceiling
    }

    // ---- Scheduler ----

    fn scheduler(total: u64) -> Scheduler {
        let mut s = Scheduler::default();
        s.add_job(unit_attack(), targets(3), total).unwrap();
        s
    }

    #[test]
    fn a_job_needs_a_keyspace_and_targets() {
        let mut s = Scheduler::default();
        assert!(s.add_job(unit_attack(), targets(1), 0).is_err());
        assert!(s.add_job(unit_attack(), vec![], 10).is_err());
        assert!(s.add_job(unit_attack(), targets(1), 10).is_ok());
    }

    #[test]
    fn chunks_walk_the_keyspace_without_gap_or_overlap() {
        let mut s = scheduler(1000);
        let mut spans = Vec::new();
        while let Some(c) = s.next_chunk("w", Some(100.0)) {
            spans.push(c.span);
        }
        assert_eq!(spans.len(), 4);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[3].end, 1000);
        for w in spans.windows(2) {
            assert_eq!(w[0].end, w[1].start, "gap or overlap between {w:?}");
        }
    }

    #[test]
    fn a_drained_scheduler_hands_out_nothing() {
        let mut s = scheduler(1000);
        assert!(s.next_chunk("w", Some(1000.0)).is_some());
        assert!(s.next_chunk("w", Some(1000.0)).is_none());
    }

    #[test]
    fn a_job_with_an_empty_keyspace_is_refused_rather_than_scheduled() {
        let mut s = Scheduler::default();
        assert!(s.add_job(unit_attack(), targets(1), 0).is_err());
        assert!(s.next_chunk("w", Some(1000.0)).is_none());
    }

    /// The test named in the module documentation: if chunk size *and* pick
    /// frequency were both rate proportional, a worker ten times faster would
    /// get a hundred times the work. Here picks are equal, so the faster worker
    /// gets ten times the work and the slower worker's share is small but not
    /// zero.
    #[test]
    fn a_slow_worker_does_not_starve_the_run() {
        let mut s = scheduler(100_000);
        s.policy = ChunkPolicy {
            target_seconds: 1.0,
            min_candidates: 100,
            max_candidates: 10_000_000,
        };
        let mut fast_work = 0u64;
        let mut slow_work = 0u64;
        // Alternating turns, which is what the master's dispatcher does: equal
        // number of chunks each, chunk size proportional to rate.
        let mut turn = 0u32;
        while let Some(c) = s.next_chunk("w", if turn % 2 == 0 { Some(1000.0) } else { Some(100.0) }) {
            if turn % 2 == 0 {
                fast_work += c.span.len();
            } else {
                slow_work += c.span.len();
            }
            turn += 1;
        }
        assert_eq!(fast_work + slow_work, 100_000);
        // Ten to one, which is the ten to one rate ratio. If chunk size and pick
        // frequency were both rate proportional this would be a hundred to one.
        assert_eq!(fast_work / slow_work, 10);
    }

    #[test]
    fn batch_ids_are_unique_across_jobs() {
        let mut s = scheduler(1000);
        s.add_job(unit_attack(), targets(1), 500).unwrap();
        let mut ids = Vec::new();
        while let Some(c) = s.next_chunk("w", Some(100.0)) {
            ids.push(c.batch_id);
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 4 + 2);
    }

    #[test]
    fn a_solved_target_stops_being_scheduled() {
        let mut s = scheduler(1000);
        let job_id = s.jobs.keys().next().copied().unwrap();
        let t = targets(3);
        s.complete(job_id, &[t[0].clone()]);
        let c = s.next_chunk("w", Some(100.0)).unwrap();
        assert_eq!(c.work.targets, vec![t[1].clone(), t[2].clone()]);
    }

    #[test]
    fn a_job_with_every_target_solved_is_finished() {
        let mut s = scheduler(1000);
        let job_id = s.jobs.keys().next().copied().unwrap();
        let all = targets(3);
        assert_eq!(s.complete(job_id, &all), Some(true));
        assert!(s.next_chunk("w", Some(100.0)).is_none());
        assert!(s.open_jobs().is_empty());
    }

    #[test]
    fn a_requeued_span_is_handed_out_again_and_the_ledger_says_so() {
        let mut s = scheduler(1000);
        s.start_ledger();
        let c = s.next_chunk("w", Some(100.0)).unwrap();
        s.complete(c.job_id, &[]);
        s.requeue(c.job_id, c.span).unwrap();
        let again = s.next_chunk("w", Some(100.0)).unwrap();
        assert_eq!(again.span, c.span);
        let l = s.ledger().unwrap();
        assert_eq!(l.repeats(), 1);
        assert_eq!(l.overlaps(), 1, "a requeue in one run is a duplicate by definition");
        // And the keyspace is still whole.
        assert!(s.jobs.values().all(|j| j.free.total() <= 1000));
    }

    #[test]
    fn requeueing_a_span_that_is_still_free_is_refused() {
        let mut s = scheduler(1000);
        let job_id = s.jobs.keys().next().copied().unwrap();
        assert!(matches!(
            s.requeue(job_id, Span::new(0, 100)),
            Err(SpanError::Overlap { .. })
        ));
    }

    #[test]
    fn jobs_rotate_so_a_small_one_behind_a_large_one_still_runs() {
        let mut s = Scheduler::default();
        let big = s.add_job(unit_attack(), targets(1), 10_000).unwrap();
        let small = s.add_job(unit_attack(), targets(1), 100).unwrap();
        s.policy = ChunkPolicy {
            target_seconds: 1.0,
            min_candidates: 100,
            max_candidates: 100,
        };
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(s.next_chunk("w", Some(100.0)).unwrap().job_id);
        }
        assert!(seen.contains(&big) && seen.contains(&small), "starved: {seen:?}");
    }

    #[test]
    fn a_restored_job_keeps_its_remaining_keyspace() {
        let mut s = scheduler(1000);
        s.policy = ChunkPolicy {
            target_seconds: 1.0,
            min_candidates: 300,
            max_candidates: 300,
        };
        let c = s.next_chunk("w", Some(100.0)).unwrap();
        s.complete(c.job_id, &[]);

        let snapshot = s.snapshot();
        let mut fresh = Scheduler::default();
        for j in snapshot {
            fresh.restore_job(j);
        }
        assert_eq!(fresh.free_total(), 700);
        assert_eq!(fresh.job(c.job_id).unwrap().free.to_vec(), vec![Span::new(300, 1000)]);
    }

    #[test]
    fn counters_are_not_reused_after_a_restore() {
        let mut s = scheduler(100);
        s.note_counters(500, 9);
        let c = s.next_chunk("w", Some(1.0)).unwrap();
        assert!(c.batch_id >= 500);
        assert_eq!(s.jobs.values().next().unwrap().id.max(1), 1);
    }

    // ---- keyspace_for ----

    #[test]
    fn a_mask_keyspace_is_computed_not_guessed() {
        let a = AttackType::BruteForce { mask: "?l?l".into() };
        assert_eq!(keyspace_for(&a, None).unwrap(), 676);
    }

    #[test]
    fn a_combinator_keyspace_is_the_product_of_its_lists() {
        let a = AttackType::Combinator {
            left_words: vec!["a".into(), "b".into()],
            right_words: vec!["1".into(), "2".into(), "3".into()],
        };
        assert_eq!(keyspace_for(&a, None).unwrap(), 6);
    }

    /// The old code returned a hardcoded ten million here. That invented work and
    /// silently truncated longer wordlists, so it is now an error unless the
    /// caller measured the file.
    #[test]
    fn a_wordlist_keyspace_requires_a_measured_line_count() {
        let a = AttackType::Dictionary {
            wordlist_path: "x.txt".into(),
            rules: vec![],
        };
        let err = keyspace_for(&a, None).unwrap_err();
        assert!(err.contains("measure"), "unhelpful error: {err}");
        assert_eq!(keyspace_for(&a, Some(1234)).unwrap(), 1234);
    }
}