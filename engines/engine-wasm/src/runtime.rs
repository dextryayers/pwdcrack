use crate::WasmEngine;

pub fn init_wasm() -> Option<WasmEngine> {
    #[cfg(feature = "wasm")] {
        let engine = wasmtime::Engine::default();
        log::info!("WASM: wasmtime runtime initialized");
        Some(WasmEngine { initialized: true, engine: Some("wasmtime 25".into()) })
    }
    #[cfg(not(feature = "wasm"))] {
        log::info!("WASM: engine requires wasm feature (not enabled)");
        None
    }
}
