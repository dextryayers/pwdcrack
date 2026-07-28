use thiserror::Error;

#[derive(Error, Debug)]
pub enum JuliaError {
    #[error("Julia runtime not initialized")] NotInitialized,
    #[error("Julia evaluation failed: {0}")] EvalFailed(String),
    #[error("Julia not available (feature not enabled)")] NotAvailable,
    #[error("Julia exception: {0}")] JuliaException(String),
}
