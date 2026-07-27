//! Power statistics collector — tracks energy, power, efficiency

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct PowerStats {
    energy_uj: AtomicU64,
    current_watts: AtomicU64,
    total_hashes: AtomicU64,
    joules_per_hash: AtomicU64,
    start: Instant,
    last_sample: std::sync::Mutex<SamplePoint>,
}

#[derive(Debug, Clone)]
struct SamplePoint {
    time: Instant,
    energy_uj: u64,
}

impl PowerStats {
    pub fn new() -> Self {
        PowerStats {
            energy_uj: AtomicU64::new(0),
            current_watts: AtomicU64::new(0),
            total_hashes: AtomicU64::new(0),
            joules_per_hash: AtomicU64::new(0),
            start: Instant::now(),
            last_sample: std::sync::Mutex::new(SamplePoint {
                time: Instant::now(),
                energy_uj: 0,
            }),
        }
    }

    pub fn record_hashes(&self, count: u64) {
        self.total_hashes.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_energy(&self, energy_uj: u64) {
        self.energy_uj.store(energy_uj, Ordering::Relaxed);
        let mut last = self.last_sample.lock().unwrap();
        let now = Instant::now();
        let delta_secs = now.duration_since(last.time).as_secs_f64();
        if delta_secs > 0.05 {
            let delta_uj = if energy_uj >= last.energy_uj {
                energy_uj - last.energy_uj
            } else {
                u64::MAX - last.energy_uj + energy_uj
            };
            let watts = (delta_uj as f64 / 1_000_000.0) / delta_secs;
            self.current_watts.store(watts as u64, Ordering::Relaxed);
            *last = SamplePoint {
                time: now,
                energy_uj,
            };
        }
        self.update_joules_per_hash();
    }

    fn update_joules_per_hash(&self) {
        let total_h = self.total_hashes.load(Ordering::Relaxed);
        if total_h > 0 {
            let joules = self.energy_uj.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            let jph = (joules / total_h as f64 * 1_000_000.0) as u64;
            self.joules_per_hash.store(jph, Ordering::Relaxed);
        }
    }

    pub fn total_energy_j(&self) -> f64 {
        self.energy_uj.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn current_watts(&self) -> f64 {
        self.current_watts.load(Ordering::Relaxed) as f64
    }

    pub fn hashes_per_watt(&self) -> f64 {
        let watts = self.current_watts();
        if watts > 0.0 {
            let hps = self.hashes_per_second();
            hps / watts
        } else {
            0.0
        }
    }

    pub fn hashes_per_second(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_hashes.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    pub fn report(&self) -> String {
        format!(
            "⚡ {:.1}W | {:.3} J/hash | {:.0} H/s | {:.0} H/W | {:.1}s elapsed",
            self.current_watts(),
            self.total_energy_j() / self.total_hashes.load(Ordering::Relaxed).max(1) as f64,
            self.hashes_per_second(),
            self.hashes_per_watt(),
            self.elapsed_secs(),
        )
    }
}
