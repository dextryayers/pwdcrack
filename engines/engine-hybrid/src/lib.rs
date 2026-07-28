//! Hybrid CPU+GPU scheduler and load balancer engine for pwdcrack.
//!
//! Provides work scheduling, load balancing, and resource monitoring.

pub mod scheduler;
pub mod balancer;
pub mod monitor;
pub mod error;
