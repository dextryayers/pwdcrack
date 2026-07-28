use thiserror::Error;

#[derive(Error, Debug)]
pub enum WasmError {
    #[error("WASM runtime initialization failed: {0}")] InitFailed(String),
    #[error("WASM module compilation failed: {0}")] CompileFailed(String),
    #[error("WASM function not found: {0}")] FunctionNotFound(String),
    #[error("WASM trap during execution: {0}")] Trap(String),
    #[error("WASM not available (feature not enabled)")] NotAvailable,
}
