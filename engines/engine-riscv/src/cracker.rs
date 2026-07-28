use crate::vector::RiscvVector;
use crate::intrinsic::RiscvIntrinsic;
use crate::error::Result;

pub struct RiscvCracker {
    vector: Option<RiscvVector>,
    intrinsic: Option<RiscvIntrinsic>,
}

impl RiscvCracker {
    pub fn new() -> Self {
        let vector = RiscvVector::detect();
        let intrinsic = RiscvIntrinsic::detect();
        Self {
            vector: if vector.is_available() { Some(vector) } else { None },
            intrinsic: if intrinsic.is_available() { Some(intrinsic) } else { None },
        }
    }

    pub fn is_available(&self) -> bool {
        self.vector.is_some() || self.intrinsic.is_some()
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
            let _ = md5::compute(b"riscvbench");
            count += 1;
        }
        Ok(count)
    }
}
