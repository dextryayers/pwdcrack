use crate::error::JuliaError;

pub fn eval_hash_julia(_password: &str, _hash_type: &str) -> Result<String, JuliaError> {
    Err(JuliaError::NotAvailable)
}

pub fn call_cracker(_password: &str, _target_hex: &str, _algo: &str) -> Result<bool, JuliaError> {
    Err(JuliaError::NotAvailable)
}
