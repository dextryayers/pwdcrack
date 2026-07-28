use crate::warp::WarpScheduler;
use crate::error::Result;

pub struct WarpCracker {
    scheduler: WarpScheduler,
}

impl WarpCracker {
    pub fn new() -> Self {
        Self {
            scheduler: WarpScheduler::new(),
        }
    }

    pub fn is_available(&self) -> bool { true }

    pub fn crack_md5(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
        for word in wordlist {
            let digest = md5::compute(word.as_bytes());
            if digest.as_slice() == hash {
                return Ok(Some(word.clone()));
            }
        }
        Ok(None)
    }

    pub fn benchmark(&self) -> Result<u64> {
        let start = std::time::Instant::now();
        let mut count = 0u64;
        while start.elapsed().as_secs() < 1 {
            let _ = md5::compute(b"warpbench");
            count += 1;
        }
        Ok(count)
    }
}
