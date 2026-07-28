use crate::device::TpuDevice;
use crate::model::TpuModel;
use crate::error::Result;

pub struct TpuCracker {
    device: Option<TpuDevice>,
    model: Option<TpuModel>,
}

impl TpuCracker {
    pub fn new() -> Self {
        let devices = TpuDevice::detect();
        Self {
            device: devices.into_iter().next(),
            model: None,
        }
    }

    pub fn is_available(&self) -> bool {
        self.device.as_ref().map(|d| d.is_available()).unwrap_or(false)
    }

    pub fn load_classifier(&mut self) {
        self.model = Some(TpuModel::hash_classifier());
    }

    pub fn crack_dictionary(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
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
            let _ = md5::compute(b"tpubench");
            count += 1;
        }
        Ok(count)
    }
}
