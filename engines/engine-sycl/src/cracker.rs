use crate::SyclEngine;

pub struct SyclCracker {
    engine: SyclEngine,
}

impl SyclCracker {
    pub fn new(engine: SyclEngine) -> Self {
        SyclCracker { engine }
    }
    pub fn engine(&self) -> &SyclEngine { &self.engine }
}
