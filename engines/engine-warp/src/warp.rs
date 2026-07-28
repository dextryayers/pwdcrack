use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub struct WarpScheduler {
    active_threads: Arc<AtomicU64>,
    terminated: Arc<AtomicBool>,
    warp_size: u32,
}

impl WarpScheduler {
    pub fn new() -> Self {
        Self {
            active_threads: Arc::new(AtomicU64::new(0)),
            terminated: Arc::new(AtomicBool::new(false)),
            warp_size: 32,
        }
    }

    pub fn warp_size(&self) -> u32 { self.warp_size }

    pub fn launch_warp<F>(&self, f: F) where F: Fn(u32) + Send + 'static {
        self.active_threads.fetch_add(1, Ordering::Relaxed);
        let terminated = Arc::clone(&self.terminated);
        let counter = Arc::clone(&self.active_threads);
        std::thread::spawn(move || {
            for tid in 0..32 {
                if terminated.load(Ordering::Relaxed) { break; }
                f(tid);
            }
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }

    pub fn synchronize(&self) {
        while self.active_threads.load(Ordering::Relaxed) > 0 {
            std::thread::yield_now();
        }
    }

    pub fn terminate(&self) {
        self.terminated.store(true, Ordering::Relaxed);
    }
}
