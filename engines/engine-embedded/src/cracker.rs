use crate::neon::NeonEngine;
use crate::mve::MveEngine;
use crate::error::Result;

pub struct EmbeddedCracker {
    neon: Option<NeonEngine>,
    mve: Option<MveEngine>,
}

impl EmbeddedCracker {
    pub fn new() -> Self {
        let neon = NeonEngine::detect();
        let mve = MveEngine::detect();
        Self {
            neon: if neon.is_available() { Some(neon) } else { None },
            mve: if mve.is_available() { Some(mve) } else { None },
        }
    }

    pub fn is_available(&self) -> bool {
        self.neon.is_some() || self.mve.is_some()
    }

    pub fn crack_ntlm(&self, hash: &[u8], target: &[String]) -> Result<Option<String>> {
        for word in target {
            let utf16: Vec<u16> = word.encode_utf16().collect();
            let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            use md4::Digest;
            let digest = md4::Md4::digest(&bytes);
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
            let _ = md5::compute(b"test");
            count += 1;
        }
        Ok(count)
    }
}
