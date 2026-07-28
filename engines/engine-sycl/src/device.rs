use crate::SyclEngine;

pub fn init_sycl() -> Option<SyclEngine> {
    log::info!("SYCL: engine requires Intel SYCL runtime (not yet available in Rust)");
    None
}
