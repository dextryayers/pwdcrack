//! Core library for pwdcrack: a high-performance password hash cracker.
//!
//! This crate provides hash parsing, identification, and cracking
//! algorithms for a wide range of hash formats (MD5, SHA, NTLM, bcrypt,
//! Argon2, scrypt, Unix crypt variants, and more). It also implements
//! dictionary, combinator, and brute-force attack modes with rule-based
//! word mangling.

/// The version of this library.
///
/// Wrappers need to report the version of the code they are wrapping, not their
/// own. Three of them previously hardcoded a string: `engine-bridge` said
/// "1.1.0" while the crate was 1.2.0, the Python module reported the bridge
/// crate's 0.1.0, and the wheel metadata said 1.2.0. Three answers to "what
/// version is this" is one too many.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod hash;
pub mod attack;
pub mod engine;
pub mod potfile;

#[cfg(feature = "engine-web")]
pub mod webexec;

#[cfg(test)]
mod tests;
