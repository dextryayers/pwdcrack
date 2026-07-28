use crate::dsp::DspDevice;
use crate::error::Result;

pub struct DspCracker {
    device: DspDevice,
}

impl DspCracker {
    pub fn new(device: DspDevice) -> Self {
        Self { device }
    }

    pub fn name(&self) -> &str {
        &self.device.name
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

    pub fn crack_sha1(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
        for word in wordlist {
            use sha1::Digest;
            let digest = sha1::Sha1::digest(word.as_bytes());
            if digest.as_slice() == hash {
                return Ok(Some(word.clone()));
            }
        }
        Ok(None)
    }

    pub fn benchmark(&self) -> Result<u64> {
        let start = std::time::Instant::now();
        let data = b"benchmark_test_data";
        let mut count = 0u64;
        while start.elapsed().as_secs() < 1 {
            let _ = md5::compute(data);
            count += 1;
        }
        Ok(count)
    }
}
