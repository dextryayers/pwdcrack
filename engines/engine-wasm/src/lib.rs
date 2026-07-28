pub mod runtime;
pub mod cracker;
pub mod error;

use log;

pub struct WasmEngine {
    pub initialized: bool,
    pub engine: Option<String>,
}

impl WasmEngine {
    pub fn init() -> Option<Self> {
        runtime::init_wasm()
    }
    pub fn info(&self) -> String {
        format!("WASM: {}",
            if self.initialized { "wasmtime runtime initialized" } else { "not available" },
        )
    }
}
