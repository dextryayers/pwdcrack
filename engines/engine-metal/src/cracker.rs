use crate::device::MetalDevice;
use crate::error::Result;

pub struct MetalCracker {
    device: Option<MetalDevice>,
}

impl MetalCracker {
    pub fn new() -> Self {
        let devices = MetalDevice::detect_all();
        Self {
            device: devices.into_iter().next(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.device.is_some()
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

    pub fn device_name(&self) -> &str {
        self.device.as_ref().map(|d| d.name.as_str()).unwrap_or("none")
    }

    pub fn benchmark(&self) -> Result<u64> {
        let start = std::time::Instant::now();
        let mut count = 0u64;
        while start.elapsed().as_secs() < 1 {
            let _ = md5::compute(b"benchmark");
            count += 1;
        }
        Ok(count)
    }
}
