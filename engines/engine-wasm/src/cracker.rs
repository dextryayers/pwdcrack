use crate::WasmEngine;

pub struct WasmCracker {
    engine: WasmEngine,
}

impl WasmCracker {
    pub fn new(engine: WasmEngine) -> Self {
        WasmCracker { engine }
    }
    pub fn engine(&self) -> &WasmEngine { &self.engine }
}
