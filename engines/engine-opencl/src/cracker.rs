use crate::{OpenclEngine, error::OpenclError, kernel};

pub struct OpenclCracker {
    engine: OpenclEngine,
}

impl OpenclCracker {
    pub fn new(engine: OpenclEngine) -> Self {
        OpenclCracker { engine }
    }

    pub fn engine(&self) -> &OpenclEngine { &self.engine }

    pub fn crack_md5(&self, _candidates: &[u8], _target_hex: &str) -> Result<Vec<bool>, OpenclError> {
        Err(OpenclError::NotEnabled)
    }
}
