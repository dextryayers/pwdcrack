//! Core library for pwdcrack — a high-performance password hash cracker.
//!
//! This crate provides hash parsing, identification, and cracking
//! algorithms for a wide range of hash formats (MD5, SHA, NTLM, bcrypt,
//! Argon2, scrypt, Unix crypt variants, and more). It also implements
//! dictionary, combinator, and brute-force attack modes with rule-based
//! word mangling.

pub mod hash;
pub mod attack;
pub mod potfile;

#[cfg(test)]
mod tests;
