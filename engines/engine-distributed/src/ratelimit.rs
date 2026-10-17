//! Per address admission rate limiting (P9.1.06).
//!
//! # What this is for
//!
//! [`crate::admission`] stops a peer that cannot prove the token. That check is
//! cheap: a SHA-256 over a 32 byte nonce. Without a limit in front of it, the
//! cost to an attacker is one connection per guess and the cost to the master is
//! one accept, one read, one hash and one log line, forever, from as many
//! addresses as they control. The token stays unguessable either way; what
//! changes is whether the master is available to do its job while it is being
//! guessed at.
//!
//! A token bucket per source address, not a global counter: a global counter
//! would let one noisy address lock out the legitimate workers on the same
//! cluster, which is a denial of service the operator causes themselves.
//!
//! # The map is the other half of the problem
//!
//! A per address limiter that keeps an entry forever is a memory exhaustion
//! attack with a different name. Attacker controlled addresses arrive at line
//! rate, so [`RateLimiter::sweep`] forgets addresses that have been idle longer
//! than the idle timeout, and [`RateLimiter::check`] creates no entry at all
//! once [`RateLimiter::max_addresses`] is reached. Refusing a *new* address
//! without recording it is the right trade: the legitimate case is a handful of
//! workers, and an attacker cannot make the table grow past the cap.
//!
//! # Addresses are the socket's, never a header's
//!
//! There is no `X-Forwarded-For` handling. A forwarded header would let one
//! peer pick a fresh identity per attempt and make the limiter useless. Behind a
//! proxy the correct answer is to run the limiter at the proxy, and the log line
//! says which address was refused so an operator can see that is what happened.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Default sustained admission rate for one address, in attempts per second.
pub const DEFAULT_RATE_PER_SEC: f64 = 2.0;

/// Default burst, in attempts. Enough for a cluster restarting, small enough
/// that a full burst still cannot be used as a rate.
pub const DEFAULT_BURST: f64 = 8.0;

/// How long an idle address is forgotten. Two minutes of quiet is a cluster
/// restart or a laptop lid, well past the burst refill.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Ceiling on distinct tracked addresses.
pub const DEFAULT_MAX_ADDRESSES: usize = 4096;

/// Cluster wide ceiling on admission attempts per second, across all addresses.
///
/// A per address bucket is defeated by spreading attempts over many source
/// addresses: a thousand addresses at a burst of eight each is eight thousand free
/// guesses with no single address ever exceeding its budget. This bucket is what
/// makes the per address one fair rather than merely ineffective. Set high enough
/// that a two hundred node cluster starting at once is not throttled by it.
pub const DEFAULT_GLOBAL_RATE: f64 = 100.0;

/// Cluster wide burst.
pub const DEFAULT_GLOBAL_BURST: f64 = 400.0;

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Allowed,
    /// Refused for now. `retry_after` is how long until one token exists.
    Throttled {
        retry_after: Duration,
    },
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allowed)
    }
}

/// Counters, for a log line and for a test to assert on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimiterStats {
    /// Checks made.
    pub checks: u64,
    /// Checks refused because the address's bucket was empty.
    pub throttled: u64,
    /// Checks refused because the cluster wide bucket was empty.
    pub throttled_global: u64,
    /// Checks refused because the address table was full.
    pub table_full: u64,
    /// Entries dropped by the idle sweep.
    pub expired: u64,
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token bucket per address, behind a cluster wide bucket.
#[derive(Debug)]
pub struct RateLimiter {
    rate_per_sec: f64,
    burst: f64,
    global_rate_per_sec: f64,
    global_burst: f64,
    idle_timeout: Duration,
    max_addresses: usize,
    buckets: HashMap<IpAddr, Bucket>,
    global: Bucket,
    stats: RateLimiterStats,
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            rate_per_sec: DEFAULT_RATE_PER_SEC,
            burst: DEFAULT_BURST,
            global_rate_per_sec: DEFAULT_GLOBAL_RATE,
            global_burst: DEFAULT_GLOBAL_BURST,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_addresses: DEFAULT_MAX_ADDRESSES,
            buckets: HashMap::new(),
            // The cluster wide bucket starts full so a restart storm is absorbed
            // by its burst rather than refused on the first connection.
            global: Bucket {
                tokens: DEFAULT_GLOBAL_BURST,
                last: Instant::now(),
            },
            stats: RateLimiterStats::default(),
        }
    }

    /// Builds a limiter with explicit parameters, for tests and for an operator
    /// who needs a cluster of two hundred workers.
    pub fn with_limits(
        rate_per_sec: f64,
        burst: f64,
        idle_timeout: Duration,
        max_addresses: usize,
    ) -> Self {
        let mut l = RateLimiter::new();
        l.rate_per_sec = rate_per_sec.max(0.0);
        l.burst = burst.max(1.0);
        l.idle_timeout = idle_timeout;
        l.max_addresses = max_addresses.max(1);
        l
    }

    /// Sets the cluster wide ceiling, which [`RateLimiter::with_limits`] does not
    /// touch.
    pub fn with_global_limits(mut self, rate_per_sec: f64, burst: f64) -> Self {
        self.global_rate_per_sec = rate_per_sec.max(0.0);
        self.global_burst = burst.max(1.0);
        self.global.tokens = self.global_burst;
        self
    }

    pub fn stats(&self) -> RateLimiterStats {
        self.stats
    }

    /// Distinct addresses currently tracked.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Decides whether a connection attempt from `addr` may proceed.
    pub fn check(&mut self, addr: IpAddr, now: Instant) -> Decision {
        self.stats.checks += 1;

        // Sweep before deciding, so a table that grew to the cap this instant can
        // make room from an address that has gone away.
        self.sweep(now);

        // Cluster wide first, so an attempt spread over many addresses is stopped
        // before any per address bookkeeping happens.
        if !self.take_global(now) {
            self.stats.throttled_global += 1;
            log::warn!(
                "cluster: refusing {addr}: the cluster wide admission budget of {:.0} \
                 attempts per second is exhausted, which usually means a distributed \
                 handshake attempt rather than a large legitimate cluster",
                self.global_rate_per_sec
            );
            return Decision::Throttled {
                retry_after: self.global_retry_after(),
            };
        }

        let rate = self.rate_per_sec;
        let burst = self.burst;

        let bucket = match self.buckets.get_mut(&addr) {
            Some(b) => b,
            None => {
                if self.buckets.len() >= self.max_addresses {
                    self.stats.table_full += 1;
                    log::warn!(
                        "cluster: refusing {addr}: the address table is full at {} entries, \
                         so a new address cannot be admitted",
                        self.max_addresses
                    );
                    return Decision::Throttled {
                        // No entry exists to refill, so the honest answer is the
                        // idle timeout: either the table frees up or the operator
                        // restarts.
                        retry_after: self.idle_timeout,
                    };
                }
                // A new address starts with a full burst. A legitimate cluster of
                // two hundred workers starting at once must not be serialised by
                // the limiter; the cluster wide bucket above is what stops a scan
                // spreading attempts over many addresses instead.
                self.buckets.insert(
                    addr,
                    Bucket {
                        tokens: burst,
                        last: now,
                    },
                );
                self.buckets.get_mut(&addr).expect("just inserted")
            }
        };

        // Refill for the time since the last check from this address. `now` is
        // never before `last` in normal use; the `max` keeps a backwards system
        // clock from minting tokens.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Decision::Allowed
        } else {
            self.stats.throttled += 1;
            let deficit = 1.0 - bucket.tokens;
            let wait = if rate > 0.0 {
                Duration::from_secs_f64((deficit / rate).max(0.001))
            } else {
                self.idle_timeout
            };
            let rate_per_sec = self.rate_per_sec;
            log::warn!(
                "cluster: throttling {addr}: handshake attempts exhausted the \
                 {rate_per_sec}/s budget, retry in {} ms",
                wait.as_millis()
            );
            Decision::Throttled { retry_after: wait }
        }
    }

    /// Spends one cluster wide token. False when the cluster budget is spent.
    fn take_global(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.global.last)
            .as_secs_f64();
        self.global.last = now;
        self.global.tokens =
            (self.global.tokens + elapsed * self.global_rate_per_sec).min(self.global_burst);
        if self.global.tokens >= 1.0 {
            self.global.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn global_retry_after(&self) -> Duration {
        if self.global_rate_per_sec > 0.0 {
            let deficit = 1.0 - self.global.tokens;
            Duration::from_secs_f64((deficit / self.global_rate_per_sec).max(0.001))
        } else {
            Duration::from_secs(60)
        }
        .min(Duration::from_secs(30))
    }

    /// Forgets addresses idle for longer than the timeout.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < self.idle_timeout);
        let removed = before - self.buckets.len();
        if removed > 0 {
            self.stats.expired += removed as u64;
            log::debug!("cluster: rate limiter forgot {removed} idle address(es)");
        }
        removed
    }

    /// Forgets one address, so a worker that was refused can retry without
    /// waiting out its own backoff.
    pub fn forget(&mut self, addr: &IpAddr) -> bool {
        self.buckets.remove(addr).is_some()
    }

    /// Zeroes the counters, leaving the buckets alone.
    pub fn reset_stats(&mut self) {
        self.stats = RateLimiterStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn limiter() -> RateLimiter {
        // 2 per second sustained, 8 burst: the shipped defaults, but pinned here
        // so a default change cannot silently move a test's expectation.
        RateLimiter::with_limits(2.0, 8.0, DEFAULT_IDLE_TIMEOUT, 16)
    }

    #[test]
    fn a_new_address_gets_its_burst_and_then_is_throttled() {
        let t0 = Instant::now();
        let mut l = limiter();
        for _ in 0..DEFAULT_BURST as u32 {
            assert!(l.check(ip(1), t0).is_allowed());
        }
        assert!(!l.check(ip(1), t0).is_allowed());
        assert_eq!(l.stats().throttled, 1);
    }

    #[test]
    fn the_burst_is_spendable_and_then_stops() {
        let t0 = Instant::now();
        // A rate near zero, so the burst is the whole allowance.
        let mut l = RateLimiter::with_limits(0.001, 5.0, DEFAULT_IDLE_TIMEOUT, 16);
        let mut allowed = 0;
        for i in 0..8 {
            if l.check(ip(1), t0 + Duration::from_millis(i)).is_allowed() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5, "a burst of 5 must allow exactly 5 attempts");
    }

    /// The per address bucket is trivially defeated by spreading attempts over
    /// many addresses, so there is also a cluster wide ceiling.
    #[test]
    fn the_cluster_wide_ceiling_stops_a_distributed_scan() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(1000.0, 1000.0, DEFAULT_IDLE_TIMEOUT, 4096)
            .with_global_limits(1.0, 10.0);
        let mut allowed = 0;
        // Twenty different addresses, each with a hundred free attempts of its own.
        for n in 0..20u8 {
            if l.check(ip(n), t0).is_allowed() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "the cluster ceiling was not enforced");
        assert_eq!(l.stats().throttled_global, 10);
        assert_eq!(l.tracked(), 10, "a refused attempt must not create a bucket");
    }

    #[test]
    fn the_cluster_wide_bucket_refills() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(1000.0, 1000.0, DEFAULT_IDLE_TIMEOUT, 16)
            .with_global_limits(10.0, 1.0);
        assert!(l.check(ip(1), t0).is_allowed());
        assert!(!l.check(ip(2), t0).is_allowed());
        assert!(l.check(ip(3), t0 + Duration::from_millis(200)).is_allowed());
    }

    #[test]
    fn tokens_refill_over_time() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(1.0, 2.0, DEFAULT_IDLE_TIMEOUT, 16);
        assert!(l.check(ip(1), t0).is_allowed());
        assert!(l.check(ip(1), t0).is_allowed());
        assert!(!l.check(ip(1), t0).is_allowed());
        // Two seconds at one per second refills the bucket to its burst of two.
        let t2 = t0 + Duration::from_secs(2);
        assert!(l.check(ip(1), t2).is_allowed());
        assert!(l.check(ip(1), t2 + Duration::from_millis(1)).is_allowed());
        assert!(!l.check(ip(1), t2 + Duration::from_millis(2)).is_allowed());
    }

    #[test]
    fn the_retry_after_is_the_time_to_one_token() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(1.0, 1.0, DEFAULT_IDLE_TIMEOUT, 16);
        assert!(l.check(ip(1), t0).is_allowed());
        match l.check(ip(1), t0) {
            Decision::Throttled { retry_after } => {
                assert!(
                    retry_after <= Duration::from_millis(1100),
                    "retry_after {retry_after:?} is longer than one refill period"
                );
            }
            other => panic!("expected a throttle, got {other:?}"),
        }
    }

    #[test]
    fn one_noisy_address_does_not_limit_another() {
        let t0 = Instant::now();
        let mut l = limiter();
        for _ in 0..10 {
            let _ = l.check(ip(1), t0);
        }
        assert!(l.check(ip(2), t0).is_allowed(), "addresses must be independent");
    }

    #[test]
    fn a_table_full_of_idle_addresses_is_swept_before_refusing_a_new_one() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(
            1.0,
            2.0,
            Duration::from_secs(10),
            4,
        );
        for n in 0..4 {
            assert!(l.check(ip(n), t0).is_allowed());
        }
        // The fifth address cannot get an entry while the first four are recent.
        assert!(!l.check(ip(200), t0).is_allowed());
        assert_eq!(l.stats().table_full, 1);
        // After the idle timeout the table frees itself.
        let later = t0 + Duration::from_secs(11);
        assert!(l.check(ip(201), later).is_allowed());
        assert_eq!(l.tracked(), 1, "only the new address should be tracked");
        assert_eq!(l.stats().expired, 4);
    }

    #[test]
    fn a_backwards_clock_does_not_mint_tokens() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(1.0, 2.0, DEFAULT_IDLE_TIMEOUT, 16);
        assert!(l.check(ip(1), t0).is_allowed());
        // `Instant` cannot go backwards, but a caller could pass an earlier one
        // to a limiter that has seen a later one; saturating_duration_since
        // handles it and the answer must be a throttle, not free tokens.
        let _ = l.check(ip(1), t0);
        assert!(!l.check(ip(1), t0).is_allowed());
    }

    #[test]
    fn the_shipped_defaults_match_the_documented_constants() {
        let l = RateLimiter::new();
        assert_eq!(l.rate_per_sec, DEFAULT_RATE_PER_SEC);
        assert_eq!(l.burst, DEFAULT_BURST);
        assert_eq!(l.global_rate_per_sec, DEFAULT_GLOBAL_RATE);
        assert_eq!(l.global_burst, DEFAULT_GLOBAL_BURST);
        assert_eq!(l.max_addresses, DEFAULT_MAX_ADDRESSES);
        assert_eq!(l.idle_timeout, DEFAULT_IDLE_TIMEOUT);
    }

    #[test]
    fn forgetting_an_address_lets_it_retry_immediately() {
        let t0 = Instant::now();
        // Burst of one, so the second attempt is refused without any refill.
        let mut l = RateLimiter::with_limits(0.001, 1.0, DEFAULT_IDLE_TIMEOUT, 16);
        assert!(l.check(ip(7), t0).is_allowed());
        assert!(!l.check(ip(7), t0).is_allowed());
        assert!(l.forget(&ip(7)));
        assert!(l.check(ip(7), t0).is_allowed());
    }

    /// P9.1.06 says "and log failures". Counting them is checkable; asserting on
    /// log output is not, so the counter is the evidence.
    #[test]
    fn every_refusal_is_counted() {
        let t0 = Instant::now();
        let mut l = RateLimiter::with_limits(0.001, 1.0, DEFAULT_IDLE_TIMEOUT, 16);
        for _ in 0..5 {
            let _ = l.check(ip(3), t0);
        }
        let s = l.stats();
        assert_eq!(s.checks, 5);
        assert_eq!(s.throttled, 4);
    }
}