use thiserror::Error;

#[derive(Error, Debug)]
pub enum GoError {
    #[error("Go shared library not found: {0}")] LibraryNotFound(String),
    #[error("Go symbol not found: {0}")] SymbolNotFound(String),
    #[error("Go engine not loaded")] NotLoaded,
    #[error("Go engine not available (feature not enabled)")] NotAvailable,
}
