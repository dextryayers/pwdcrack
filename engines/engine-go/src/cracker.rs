use crate::GoEngine;

pub struct GoCracker {
    engine: GoEngine,
}

impl GoCracker {
    pub fn new(engine: GoEngine) -> Self {
        GoCracker { engine }
    }
    pub fn engine(&self) -> &GoEngine { &self.engine }
}
