use crate::device::XpuDevice;
use crate::kernel::XpuKernel;
use crate::error::Result;

pub struct XpuCracker {
    device: Option<XpuDevice>,
}

impl XpuCracker {
    pub fn new() -> Self {
        let devices = XpuDevice::detect();
        Self {
            device: devices.into_iter().next(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.device.as_ref().map(|d| d.is_available()).unwrap_or(false)
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

    pub fn benchmark(&self) -> Result<u64> {
        let start = std::time::Instant::now();
        let mut count = 0u64;
        while start.elapsed().as_secs() < 1 {
            let _ = md5::compute(b"xpubenchn");
            count += 1;
        }
        Ok(count)
    }
}
