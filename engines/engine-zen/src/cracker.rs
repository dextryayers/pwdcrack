use crate::arch::ZenArch;
use crate::dispatch::ZenDispatch;
use crate::error::Result;

pub struct ZenCracker {
    arch: ZenArch,
    dispatch: ZenDispatch,
}

impl ZenCracker {
    pub fn new() -> Self {
        let arch = ZenArch::detect();
        let dispatch = ZenDispatch::new(&arch);
        Self { arch, dispatch }
    }

    pub fn is_available(&self) -> bool {
        self.arch.supports_avx2() || self.arch.supports_avx512()
    }

    pub fn dispatch_level(&self) -> &str {
        self.dispatch.level_name()
    }

    pub fn crack_md5(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
        for word in wordlist {
            let digest = md5::compute(word.as_bytes());
            if digest.as_slice() == hash {
                return Ok(Some(word.clone()));
            }
        }
        Ok(None)
    }

    pub fn crack_sha256(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
        for word in wordlist {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(word.as_bytes());
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
            let _ = md5::compute(b"zenbench");
            count += 1;
        }
        Ok(count)
    }
}
