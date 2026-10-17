//! Heartbeat deadlines, exponential backoff, and declaring a worker dead.
//!
//! # What this replaces
//!
//! `master.rs` requeued work for any worker whose `last_heartbeat` was older
//! than thirty seconds, checked by a fifteen second interval task. Two problems:
//!
//!   - **Not three missed heartbeats.** Thirty seconds is a magic constant that
//!     happens to be near three times the five second default, so a change to
//!     `heartbeat_secs` silently changed the tolerance. Worse, "thirty seconds
//!     since the last byte" is not the same as "three missed heartbeats": a
//!     worker that is streaming results steadily never updates
//!     `last_heartbeat` at all, because only `Heartbeat` touches it, so a busy
//!     healthy worker looked identical to a dead one.
//!   - **No backoff.** The master sent nothing, so a worker that lost the master
//!     kept beating into a dead socket at full rate, and one that was merely slow
//!     had no signal to reduce its own heartbeat cost.
//!
//! # The model
//!
//! A worker is alive if any frame from it arrived within one heartbeat interval.
//! [`WorkerLiveness::sweep`] counts consecutive missed deadlines and declares
//! the worker dead on the third, which is the plan's rule and is written as a
//! rule rather than as a duration. Every time is passed in as an `Instant`
//! rather than read from the clock, so the deadlines are tested without sleeping.
//!
//! The backoff is the master telling the worker how long to wait
//! ([`crate::protocol::Message::HeartbeatAck`]). It doubles per missed deadline
//! and resets to the base interval on the first frame that arrives. The master is
//! the side that decides when a worker is dead, so it is the side that owns the
//! schedule.

use std::time::{Duration, Instant};

/// How many consecutive missed heartbeats make a worker dead.
///
/// Three, from the plan. Exposed as a constant rather than a literal so the
/// rule and the code that implements it cannot drift.
pub const MAX_MISSED_HEARTBEATS: u32 = 3;

/// Ceiling on the backoff period.
///
/// A worker whose heartbeats are being missed but which keeps talking on the
/// same connection still gets acknowledged; backing off without limit would turn
/// a brief network blip into a partition.
pub const MAX_BACKOFF_SECS: u64 = 60;

/// One worker's liveness state.
#[derive(Debug, Clone)]
pub struct WorkerLiveness {
    /// The base heartbeat period the master asks for.
    pub interval: Duration,
    /// When the master last heard anything at all from this worker.
    pub last_seen: Instant,
    /// Consecutive deadlines passed with nothing received.
    pub missed: u32,
    /// Deadlines passed since the last frame, for the log line.
    pub last_swept: Instant,
}

/// What a sweep concluded about a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Alive and behaving.
    Alive { missed: u32 },
    /// Alive, but has missed at least one deadline.
    Late { missed: u32 },
    /// Three consecutive deadlines passed. The caller requeues its work.
    Dead { missed: u32 },
}

impl WorkerLiveness {
    pub fn new(interval: Duration, now: Instant) -> Self {
        WorkerLiveness {
            interval,
            last_seen: now,
            missed: 0,
            last_swept: now,
        }
    }

    /// Records that a frame arrived from this worker.
    ///
    /// Resets the missed count and the backoff. Called for *any* frame, not just
    /// a heartbeat, which is the fix for the busy worker looking dead: a worker
    /// streaming results is the healthiest worker there is.
    pub fn seen(&mut self, now: Instant) {
        self.last_seen = now;
        self.missed = 0;
    }

    /// How long the worker should wait before its next heartbeat.
    ///
    /// `interval * 2^missed`, capped. Doubling from the base rather than from the
    /// last value keeps the schedule a function of the miss count, so it cannot
    /// drift upward over a long run.
    pub fn backoff(&self) -> Duration {
        let shift = self.missed.min(16);
        let secs = self
            .interval
            .as_secs()
            .saturating_mul(1u64 << shift)
            .max(1)
            .min(MAX_BACKOFF_SECS);
        Duration::from_secs(secs)
    }

    /// The deadline after which one more heartbeat is considered missed.
    fn deadline(&self) -> Instant {
        self.last_seen + self.interval
    }

    /// Checks the deadline and advances the miss count.
    ///
    /// `interval()` is the sweep period, so this is not called more often than
    /// once per interval and a worker is not declared dead by a fast loop.
    pub fn sweep(&mut self, now: Instant) -> Liveness {
        // Count every deadline that has passed since the last sweep, not just
        // one. A sweep that runs after a long pause should reflect the pause,
        // otherwise a master blocked for a minute would then take three more
        // sweeps to notice a dead worker.
        while self.missed < MAX_MISSED_HEARTBEATS
            && now >= self.deadline().checked_add(self.interval * u32::from(self.missed)).unwrap_or(self.deadline())
        {
            self.missed += 1;
        }
        self.last_swept = now;

        if self.missed >= MAX_MISSED_HEARTBEATS {
            Liveness::Dead { missed: self.missed }
        } else if self.missed > 0 {
            Liveness::Late { missed: self.missed }
        } else {
            Liveness::Alive { missed: 0 }
        }
    }

    /// True when the worker has never been seen at all, which is different from
    /// having gone away after working.
    pub fn is_new(&self) -> bool {
        self.missed == 0 && self.last_seen == self.last_swept
    }
}

/// Milliseconds since the Unix epoch, for `HeartbeatAck`.
///
/// Uses the system clock rather than `Instant` because the point is to let a
/// worker notice clock skew against the master, which a monotonic counter could
/// not show.
pub fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_secs(5);

    #[test]
    fn a_fresh_worker_is_alive() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.sweep(t0 + Duration::from_secs(1)), Liveness::Alive { missed: 0 });
    }

    /// The plan's rule, written as a rule: three consecutive missed heartbeats.
    ///
    /// Deadlines fall at one, two and three intervals after the last frame, so
    /// with a five second heartbeat a worker is declared dead fifteen seconds
    /// after it was last heard from. The rule is stated in heartbeats rather than
    /// in seconds so that changing `heartbeat_secs` changes the tolerance
    /// deliberately instead of silently.
    #[test]
    fn three_missed_heartbeats_make_a_worker_dead() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.sweep(t0 + BASE), Liveness::Late { missed: 1 });
        assert_eq!(l.sweep(t0 + BASE * 2), Liveness::Late { missed: 2 });
        assert_eq!(
            l.sweep(t0 + BASE * 3),
            Liveness::Dead { missed: 3 },
            "the third missed heartbeat declares it dead"
        );
    }

    #[test]
    fn a_worker_still_missing_stays_dead() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.sweep(t0 + BASE * 10), Liveness::Dead { missed: 3 });
    }

    /// The bug the module note describes: a worker streaming results never sent
    /// a heartbeat, so only `Heartbeat` updated the timestamp and the busy worker
    /// looked dead.
    #[test]
    fn any_frame_counts_as_liveness() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.sweep(t0 + BASE * 2), Liveness::Late { missed: 2 });
        l.seen(t0 + BASE * 2);
        assert_eq!(l.missed, 0);
        assert_eq!(
            l.sweep(t0 + BASE * 2 + BASE / 2),
            Liveness::Alive { missed: 0 }
        );
        // And the next deadline is measured from the frame, not from the sweep.
        assert_eq!(l.sweep(t0 + BASE * 3), Liveness::Late { missed: 1 });
    }

    #[test]
    fn the_backoff_doubles_per_missed_deadline_and_resets() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.backoff(), Duration::from_secs(5));
        assert_eq!(l.sweep(t0 + BASE), Liveness::Late { missed: 1 });
        assert_eq!(l.backoff(), Duration::from_secs(10));
        assert_eq!(l.sweep(t0 + BASE * 2), Liveness::Late { missed: 2 });
        assert_eq!(l.backoff(), Duration::from_secs(20));
        l.seen(t0 + BASE * 2);
        assert_eq!(l.backoff(), Duration::from_secs(5), "a frame resets the schedule");
    }

    #[test]
    fn the_backoff_is_capped() {
        let t0 = Instant::now();
        // A ten second base reaches the cap at the third miss; a five second one
        // never does, because the worker is declared dead first.
        let mut l = WorkerLiveness::new(Duration::from_secs(10), t0);
        for _ in 0..MAX_MISSED_HEARTBEATS {
            l.missed += 1;
        }
        assert_eq!(l.backoff(), Duration::from_secs(80).min(Duration::from_secs(MAX_BACKOFF_SECS)));
        assert_eq!(l.backoff(), Duration::from_secs(MAX_BACKOFF_SECS));
    }

    /// A sweep after a long pause counts every deadline that passed, not one. A
    /// master that was busy for a minute should not then need three more sweeps
    /// to notice a worker is gone.
    #[test]
    fn a_long_pause_counts_every_missed_deadline() {
        let t0 = Instant::now();
        let mut l = WorkerLiveness::new(BASE, t0);
        assert_eq!(l.sweep(t0 + Duration::from_secs(60)), Liveness::Dead { missed: 3 });
    }

    #[test]
    fn a_shorter_interval_deadline_moves_with_it() {
        let t0 = Instant::now();
        let mut fast = WorkerLiveness::new(Duration::from_secs(1), t0);
        let mut slow = WorkerLiveness::new(Duration::from_secs(10), t0);
        assert_eq!(fast.sweep(t0 + Duration::from_secs(4)), Liveness::Dead { missed: 3 });
        assert_eq!(slow.sweep(t0 + Duration::from_secs(4)), Liveness::Alive { missed: 0 });
    }

    #[test]
    fn epoch_millis_is_after_2020() {
        assert!(
            epoch_millis() > 1_577_836_800_000,
            "system clock is before 2020"
        );
    }
}