# pwdcrack — Universal Architecture (All Tiers, All Platforms)

## Design Principle

```
"Every hash, every device, every watt — from 32-bit ARM to 512-core GPU farm"
```

| Platform | Binary | SIMD | GPU | RAM | Target |
|----------|--------|------|-----|-----|--------|
| Android (Termux) | 32/64-bit ARM | NEON | — | 512MB+ | Dictionary |
| Raspberry Pi 3+ | 64-bit ARM | NEON | — | 1GB+ | Dictionary/Brute |
| x86 32-bit (Pentium 4) | 32-bit | SSE2 | — | 512MB+ | Dictionary |
| x86_64 (Core 2 Duo) | 64-bit | SSSE3 | — | 2GB+ | Dictionary/Brute |
| x86_64 (Haswell) | 64-bit | AVX2 | iGPU | 8GB+ | + Mask/Combo |
| x86_64 (Zen 4) | 64-bit | AVX-512 | dGPU | 32GB+ | + GPU/FPGA |
| Multi-node cluster | 64-bit | All | All | All | Distributed |

---

## 1. HARDWARE TIER SYSTEM

### 1.1 Tier Classification

```rust
#[derive(Debug, Clone)]
pub enum HardwareTier {
    /// Tier 1: Low-end — 32-bit, no SIMD, <1GB RAM, single core
    /// Pentium 4, Celeron, Atom, ARM Cortex-A53, old Android phones
    LowEnd {
        bits: u32,          // 32 or 64
        simd: SimdLevel,    // Scalar, Neon, Sse2
        cores: usize,       // 1-4
        ram_mb: u64,        // MB
    },
    
    /// Tier 2: Mid-range — 64-bit, SSE4.2/AVX/NEON, 4-8 cores, 2-8GB RAM
    /// Core i5 gen 3-8, Ryzen 3/5, Raspberry Pi 5, Snapdragon 8xx
    MidRange {
        bits: u32,
        simd: SimdLevel,    // Sse42, Avx2, Neon
        cores: usize,       // 4-8
        ram_mb: u64,        // 2048-8192
        gpu: GpuTier,
    },
    
    /// Tier 3: High-end — AVX-512/VAES/SVE, 16+ cores, >16GB RAM, dGPU
    /// Core i9/Ryzen 9, Apple M-series, RTX 4090, Xilinx FPGA
    HighEnd {
        bits: u32,
        simd: SimdLevel,    // Avx512, Vaes, Sve
        cores: usize,       // 16-128
        ram_mb: u64,        // 16384+
        gpu: GpuTier,
        fpga: bool,
        power_budget_w: Option<f64>,
    },
    
    /// Custom: User-specified constraints
    Custom {
        max_threads: usize,
        max_ram_mb: u64,
        simd: SimdLevel,
        gpu: bool,
        power_budget_w: Option<f64>,
        work_dir: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdLevel {
    Scalar,   // No SIMD — any platform
    Sse2,     // x86 baseline (Pentium 4+, all x86_64)
    Ssse3,    // Core 2 Duo+
    Sse42,    // Nehalem+ (2008+)
    Avx2,     // Haswell+ (2013+), Zen+ (2017+)
    Avx512,   // Skylake-X (2017+), Ice Lake (2019+), Zen 4 (2022+)
    Vaes,     // AVX-512 + AES (Ice Lake+)
    Neon64,   // ARMv8 AArch64 NEON (all 64-bit ARM)
    Neon32,   // ARMv7 NEON (32-bit ARM)
    Sve,      // ARM Scalable Vector Extension (SVE/SVE2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuTier {
    None,           // No GPU compute
    Integrated,     // Intel UHD, AMD Vega iGPU, Apple M-series
    Discrete,       // NVIDIA RTX, AMD Radeon, Intel Arc
    MultiGpu,       // Multiple discrete GPUs
}
```

### 1.2 Auto-Detection Logic

```rust
/// Automatically classify hardware at startup
impl HardwareTier {
    pub fn detect() -> Self {
        let bits = if cfg!(target_pointer_width = "64") { 64 } else { 32 };
        let simd = Self::detect_simd();
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let ram_mb = Self::detect_ram_mb();
        let gpu = Self::detect_gpu();

        // Score-based tier assignment
        let score = Self::compute_tier_score(simd, cores, ram_mb, gpu);

        if score < 10 {
            HardwareTier::LowEnd { bits, simd, cores, ram_mb }
        } else if score < 50 {
            let gpu_tier = if gpu { GpuTier::Integrated } else { GpuTier::None };
            HardwareTier::MidRange { bits, simd, cores, ram_mb, gpu: gpu_tier }
        } else {
            let fpga = Self::detect_fpga();
            HardwareTier::HighEnd {
                bits, simd, cores, ram_mb,
                gpu: if gpu { GpuTier::Discrete } else { GpuTier::None },
                fpga,
                power_budget_w: None,
            }
        }
    }

    fn detect_simd() -> SimdLevel {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("vaes") {
                return SimdLevel::Vaes;
            }
            if is_x86_feature_detected!("avx512f") {
                return SimdLevel::Avx512;
            }
            if is_x86_feature_detected!("avx2") {
                return SimdLevel::Avx2;
            }
            if is_x86_feature_detected!("sse4.2") {
                return SimdLevel::Sse42;
            }
            if is_x86_feature_detected!("sse2") {
                return SimdLevel::Sse2;
            }
            SimdLevel::Scalar
        }
        #[cfg(target_arch = "aarch64")]
        {
            // All AArch64 has NEON
            SimdLevel::Neon64
        }
        #[cfg(target_arch = "arm")]
        {
            if cfg!(target_feature = "neon") {
                SimdLevel::Neon32
            } else {
                SimdLevel::Scalar
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        {
            SimdLevel::Scalar
        }
    }

    fn detect_ram_mb() -> u64 {
        // Cross-platform RAM detection
        #[cfg(target_os = "linux")]
        {
            // /proc/meminfo or sysconf
            if let Ok(info) = std::fs::read_to_string("/proc/meminfo") {
                if let Some(line) = info.lines().find(|l| l.starts_with("MemTotal:")) {
                    let kb: u64 = line.split_whitespace()
                        .nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    return kb / 1024;
                }
            }
        }
        #[cfg(target_os = "android")]
        {
            // Android via Termux: same /proc/meminfo
            if let Ok(info) = std::fs::read_to_string("/proc/meminfo") {
                if let Some(line) = info.lines().find(|l| l.starts_with("MemTotal:")) {
                    let kb: u64 = line.split_whitespace()
                        .nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    return kb / 1024;
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            // sysctl hw.memsize
            if let Ok(out) = std::process::Command::new("sysctl")
                .arg("-n").arg("hw.memsize").output()
            {
                if let Ok(bytes) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() {
                    return bytes / 1024 / 1024;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Use GlobalMemoryStatusEx via winapi
            // Fallback to reasonable default
        }
        1024 // Fallback: assume 1GB
    }

    fn detect_gpu() -> bool {
        // Check for Vulkan support (wgpu)
        // On low-end/Android: always false
        // On mid-range: check for integrated GPU
        // On high-end: check for discrete GPU
        #[cfg(feature = "gpu")]
        {
            pollster::block_on(check_vulkan_device())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "gpu"))]
        {
            false
        }
    }

    fn compute_tier_score(simd: SimdLevel, cores: usize, ram_mb: u64, gpu: bool) -> u32 {
        let mut score = 0u32;
        score += match simd {
            SimdLevel::Scalar => 0,
            SimdLevel::Neon32 | SimdLevel::Sse2 => 2,
            SimdLevel::Ssse3 => 3,
            SimdLevel::Sse42 => 5,
            SimdLevel::Neon64 => 6,
            SimdLevel::Avx2 => 10,
            SimdLevel::Avx512 => 15,
            SimdLevel::Vaes => 20,
            SimdLevel::Sve => 18,
        };
        score += (cores as u32).min(32) * 2;
        score += (ram_mb / 512).min(64) as u32;
        score += if gpu { 20 } else { 0 };
        score
    }
}
```

### 1.3 Adaptive Configuration Per Tier

```rust
impl HardwareTier {
    /// Optimal config for current hardware
    pub fn recommend_config(&self) -> CrackingConfig {
        match self {
            HardwareTier::LowEnd { bits, simd, cores, ram_mb } => {
                CrackingConfig {
                    // Limmited threads (1-2)
                    max_threads: (*cores).min(2),
                    // Small batch size to fit in cache
                    batch_size: 64,
                    // No GPU, no FPGA
                    use_gpu: false,
                    use_fpga: false,
                    // Scalar or basic SIMD
                    simd: *simd,
                    // Small arena (64KB per thread)
                    arena_size: 64 * 1024,
                    // No huge pages (32-bit may not support)
                    huge_pages: false,
                    // Minimal prefetch distance
                    prefetch_distance: 4,
                    // Limit wordlist size to available RAM / 4
                    max_wordlist_mb: (*ram_mb / 4) as usize,
                    // Use simple progress bar (no rich UI)
                    progress_bar: ProgressStyle::Simple,
                    // No power management (no RAPL support on old HW)
                    power_management: PowerMode::Disabled,
                    // Memory-map whole file if possible
                    io_mode: if *ram_mb > 512 { IoMode::Mmap } else { IoMode::Stream },
                }
            }

            HardwareTier::MidRange { bits, simd, cores, ram_mb, gpu } => {
                CrackingConfig {
                    max_threads: *cores,
                    batch_size: 256,
                    use_gpu: *gpu != GpuTier::None,
                    use_fpga: false,
                    simd: *simd,
                    arena_size: 256 * 1024,           // 256KB per thread
                    huge_pages: *bits == 64,
                    prefetch_distance: 8,
                    max_wordlist_mb: (*ram_mb / 2) as usize,
                    progress_bar: ProgressStyle::Rich,
                    power_management: if *bits == 64 {
                        PowerMode::Basic
                    } else {
                        PowerMode::Disabled
                    },
                    io_mode: IoMode::Mmap,
                }
            }

            HardwareTier::HighEnd { bits, simd, cores, ram_mb, gpu, fpga, power_budget_w } => {
                CrackingConfig {
                    max_threads: *cores,
                    batch_size: 1024,
                    use_gpu: *gpu != GpuTier::None,
                    use_fpga: *fpga,
                    simd: *simd,
                    arena_size: 1024 * 1024,          // 1MB per thread
                    huge_pages: true,
                    prefetch_distance: 16,
                    max_wordlist_mb: (*ram_mb) as usize,
                    progress_bar: ProgressStyle::Rich,
                    power_management: match power_budget_w {
                        Some(w) => PowerMode::Budget(*w),
                        None => PowerMode::Aggressive,
                    },
                    io_mode: IoMode::Mmap,
                }
            }

            HardwareTier::Custom { max_threads, max_ram_mb, simd, gpu, power_budget_w, work_dir } => {
                CrackingConfig {
                    max_threads: *max_threads,
                    batch_size: 256,
                    use_gpu: *gpu,
                    use_fpga: false,
                    simd: *simd,
                    arena_size: 256 * 1024,
                    huge_pages: cfg!(target_pointer_width = "64"),
                    prefetch_distance: 8,
                    max_wordlist_mb: *max_ram_mb as usize,
                    progress_bar: ProgressStyle::Rich,
                    power_management: match power_budget_w {
                        Some(w) => PowerMode::Budget(*w),
                        None => PowerMode::Basic,
                    },
                    io_mode: IoMode::Mmap,
                }
            }
        }
    }
}
```

---

## 2. PLATFORM ABSTRACTION LAYER

### 2.1 Feature Gates Per Tier

```rust
// === BUILD TIME: Cargo.toml features ===
//
// [features]
// default = ["tier-auto"]
// tier-auto     = []
// tier-low      = ["simd-scalar"]
// tier-mid      = ["simd-avx2", "mmap", "gpu-igpu"]
// tier-high     = ["simd-avx512", "mmap", "gpu-dgpu", "fpga", "huge-pages", "power-rapl"]
//
// simd-scalar   = []
// simd-sse2     = []
// simd-sse42    = []
// simd-avx2     = []
// simd-avx512   = []
// simd-neon     = []
// simd-neon64   = []
// simd-sve      = []
//
// gpu           = ["wgpu"]           # Any GPU support
// gpu-igpu      = ["gpu"]            # Integrated GPU only
// gpu-dgpu      = ["gpu"]            # Discrete GPU
//
// fpga          = []
// mmap          = []
// huge-pages    = ["mmap"]
// power-rapl    = []
// power-amd     = []

#[cfg(feature = "simd-avx2")]
fn md5_verify_batch_avx2(input: &[u8; 64], hash: &[u8; 16]) -> bool {
    // 8-way AVX2 MD5
}

#[cfg(any(feature = "simd-neon64", feature = "simd-neon"))]
fn md5_verify_batch_neon(input: &[u8; 64], hash: &[u8; 16]) -> bool {
    // 4-way NEON MD5 (ARM)
}

#[cfg(not(any(
    feature = "simd-avx2",
    feature = "simd-avx512",
    feature = "simd-neon64",
    feature = "simd-neon",
)))]
fn md5_verify_batch_scalar(input: &[u8; 64], hash: &[u8; 16]) -> bool {
    // Scalar MD5 — works on ALL platforms
}
```

### 2.2 Runtime SIMD Dispatcher

```rust
/// Pick the best SIMD path at runtime
/// Falls back gracefully on all platforms

#[inline(always)]
pub fn hash_verify_batch(hash_type: HashType, passwords: &[Password], targets: &[HashDigest]) -> Vec<bool> {
    let simd = CURRENT_SIMD_LEVEL.load(Ordering::Relaxed);

    match (hash_type, simd) {
        (MD5, SimdLevel::Vaes)      => md5_verify_avx512_vaes(passwords, targets),
        (MD5, SimdLevel::Avx512)    => md5_verify_avx512(passwords, targets),
        (MD5, SimdLevel::Avx2)      => md5_verify_avx2(passwords, targets),
        (MD5, SimdLevel::Neon64)    => md5_verify_neon64(passwords, targets),
        (MD5, SimdLevel::Sse42)     => md5_verify_sse42(passwords, targets),
        (MD5, _)                    => md5_verify_scalar(passwords, targets),

        (SHA256, SimdLevel::Vaes)   => sha256_verify_avx512_vaes(passwords, targets),
        (SHA256, SimdLevel::Avx2)   => sha256_verify_avx2(passwords, targets),
        (SHA256, SimdLevel::Neon64) => sha256_verify_neon64(passwords, targets),
        (SHA256, _)                 => sha256_verify_scalar(passwords, targets),

        // ... other hash types

        _ => {
            // Fallback: scalar, works on ALL platforms including 32-bit ARM
            verify_scalar_fallback(hash_type, passwords, targets)
        }
    }
}

static CURRENT_SIMD_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Initialize SIMD dispatcher — call once at startup
pub fn init_simd_detection() {
    let level = HardwareTier::detect_simd();
    CURRENT_SIMD_LEVEL.store(level as u8, Ordering::Relaxed);

    log::info!("SIMD level: {:?} (detected)", level);
}
```

### 2.3 Platform-Specific Modules

```rust
// ─── Memory ───

#[cfg(any(target_os = "linux", target_os = "android"))]
mod memory_impl {
    pub fn lock_into_ram(addr: *const u8, len: usize) -> bool {
        unsafe { libc::mlock(addr as *const _, len) == 0 }
    }

    pub fn alloc_huge_pages(size: usize) -> Option<*mut u8> {
        // mmap with MAP_HUGETLB or /dev/hugepages
        #[cfg(feature = "huge-pages")]
        {
            // Only available on 64-bit Linux with kernel support
            // Not available on 32-bit or Android
        }
        None
    }

    pub fn get_ram_info() -> (u64, u64) { // (total, available) in MB
        // Read /proc/meminfo
    }
}

#[cfg(target_os = "windows")]
mod memory_impl {
    pub fn lock_into_ram(addr: *const u8, len: usize) -> bool {
        // VirtualLock
        unsafe {
            windows::System::Memory::VirtualLock(addr as _, len).is_ok()
        }
    }
}

#[cfg(target_os = "macos")]
mod memory_impl {
    pub fn lock_into_ram(addr: *const u8, len: usize) -> bool {
        // mlock on macOS
        unsafe { libc::mlock(addr as *const _, len) == 0 }
    }
}

// ─── Filesystem (Wordlist Access) ───

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
))]
mod io_impl {
    pub fn map_wordlist(path: &str) -> Result<Mmap, IoError> {
        // Standard mmap — works on all Unix-like systems
        // Including Android/Termux
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len() as usize;
        let map = unsafe { Mmap::map(&file)? };
        Ok(map)
    }

    pub fn read_stream(path: &str) -> Result<BufReader<File>, IoError> {
        // Fallback when mmap fails (old kernel, 32-bit, low RAM)
        let file = std::fs::File::open(path)?;
        Ok(BufReader::with_capacity(64 * 1024, file))
    }
}

#[cfg(target_os = "windows")]
mod io_impl {
    pub fn map_wordlist(path: &str) -> Result<Mmap, IoError> {
        // CreateFileMapping + MapViewOfFile
    }
}

// ─── Power Management ───

#[cfg(all(feature = "power-rapl", target_os = "linux"))]
mod power_impl {
    pub fn read_energy_counter() -> u64 {
        // /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj
        // Only on x86_64 Linux with RAPL support
        // NOT available on: 32-bit, ARM, Android, macOS, Windows
        std::fs::read_to_string(
            "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"
        ).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
    }
}

#[cfg(not(all(feature = "power-rapl", target_os = "linux")))]
mod power_impl {
    pub fn read_energy_counter() -> u64 {
        // No power monitoring available
        // All platforms: 32-bit, ARM, Android, etc.
        0
    }
}

// ─── Platform Info ───

pub fn platform_info() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        bits: if cfg!(target_pointer_width = "64") { 64 } else { 32 },
        endian: if cfg!(target_endian = "little") { "little" } else { "big" },
        simd: HardwareTier::detect_simd(),
        cores: std::thread::available_parallelism()
            .map(|n| n.get()).unwrap_or(1),
        ram_mb: HardwareTier::detect_ram_mb(),
        android: cfg!(target_os = "android"),
        termux: std::env::var("TERMUX_VERSION").is_ok(),
    }
}
```

---

## 3. BUILD SYSTEM: CROSS-PLATFORM COMPILATION

### 3.1 Cargo.toml Feature Matrix

```toml
[package]
name = "pwdcrack"
version = "0.2.0"
edition = "2024"
description = "Universal password cracker — all hardware, all platforms"

[features]
# === Auto Tier (default) ===
default = ["tier-auto"]
tier-auto = []

# === Manual Tiers ===
tier-low   = ["simd-scalar", "io-stream"]
tier-mid   = ["simd-detect", "mmap", "progress-rich"]
tier-high  = ["simd-detect", "mmap", "huge-pages", "gpu", "power", "fpga"]

# === SIMD (mutually exclusive feature groups) ===
simd-scalar = []
simd-sse2   = ["simd-scalar"]     # Baseline x86
simd-avx2   = ["simd-sse2"]       # Mid-range x86
simd-avx512 = ["simd-avx2"]       # High-end x86
simd-neon32 = ["simd-scalar"]     # 32-bit ARM
simd-neon64 = ["simd-scalar"]     # 64-bit ARM (all have NEON)
simd-sve    = ["simd-neon64"]     # High-end ARM

# Auto-detect SIMD at build time
simd-detect = []

# === GPU ===
gpu         = ["wgpu", "naga", "naga_oil"]
gpu-low     = ["gpu"]   # iGPU, lower batch size
gpu-high    = ["gpu"]   # dGPU, large batch

# === FPGA ===
fpga        = []

# === Power Management ===
power       = []
power-rapl  = ["power"]    # Intel RAPL (x86_64 Linux only)
power-amd   = ["power"]    # AMD Zen (x86_64 Linux only)

# === I/O ===
mmap        = []
io-stream   = []
huge-pages  = ["mmap"]

# === Progress ===
progress-simple = []
progress-rich   = ["indicatif"]

[dependencies]
# Core
rayon = { version = "1", optional = true }
crossbeam = "0.8"

# GPU
wgpu = { version = "22", optional = true }
naga = { version = "20", optional = true }
naga_oil = { version = "0.16", optional = true }

# Progress
indicatif = { version = "0.17", optional = true }

# CLI
clap = { version = "4", features = ["derive"] }

# Hash (always included — pure Rust)
md-5 = "0.10"
sha1 = "0.10"
sha2 = "0.10"
sha3 = "0.10"
blake2 = "0.10"
ripemd = "0.1"
md4 = "0.10"
bcrypt = "0.16"
argon2 = "0.5"
scrypt = "0.11"

# Serialization
serde = { version = "1", features = ["derive"] }
bincode = "2"

# Logging
log = "0.4"

# Platform-specific
[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"

[target.'cfg(target_os = "android")'.dependencies]
libc = "0.2"

[target.'cfg(target_os = "windows")'.dependencies.windows]
version = "0.58"
features = ["System_Memory", "Storage_FileSystem"]
```

### 3.2 Cross-Compilation Script

```bash
#!/bin/bash
# scripts/build-all.sh
# Build pwdcrack for ALL platforms

set -euo pipefail
BUILD_DIR="target/release"

echo "=== Building pwdcrack for all platforms ==="

# === 1. x86_64 Linux (Universal) ===
echo "--- x86_64 Linux ---"
cargo build --release --target x86_64-unknown-linux-gnu

# === 2. x86_64 with AVX-512 (High-end) ===
echo "--- x86_64 Linux (AVX-512) ---"
RUSTFLAGS="-C target-feature=+avx512f,+avx512bw,+vaes" \
    cargo build --release --target x86_64-unknown-linux-gnu \
    --features tier-high -p pwdcrack-core

# === 3. x86_64 with AVX2 (Mid-range) ===
echo "--- x86_64 Linux (AVX2) ---"
RUSTFLAGS="-C target-feature=+avx2" \
    cargo build --release --target x86_64-unknown-linux-gnu \
    --features tier-mid -p pwdcrack-core

# === 4. 32-bit x86 Linux (Low-end) ===
echo "--- i686 Linux (32-bit) ---"
rustup target add i686-unknown-linux-gnu
cargo build --release --target i686-unknown-linux-gnu \
    --features tier-low

# === 5. aarch64 Linux (Raspberry Pi 3/4/5) ===
echo "--- aarch64 Linux (ARM64) ---"
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu \
    --features tier-mid

# === 6. ARMv7 Linux (Raspberry Pi 2, 32-bit) ===
echo "--- armv7 Linux (ARM32) ---"
rustup target add armv7-unknown-linux-gnueabihf
cargo build --release --target armv7-unknown-linux-gnueabihf \
    --features tier-low

# === 7. Android aarch64 (Termux, modern phones) ===
echo "--- Android aarch64 (Termux) ---"
rustup target add aarch64-linux-android
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang \
    cargo build --release --target aarch64-linux-android \
    --features tier-mid

# === 8. Android ARMv7 (older phones, 32-bit) ===
echo "--- Android armv7 (Termux, 32-bit) ---"
rustup target add armv7-linux-androideabi
CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi21-clang \
    cargo build --release --target armv7-linux-androideabi \
    --features tier-low

# === 9. x86_64 macOS (Apple Intel) ===
echo "--- x86_64 macOS ---"
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin \
    --features tier-mid

# === 10. aarch64 macOS (Apple Silicon) ===
echo "--- aarch64 macOS (M1/M2/M3) ---"
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin \
    --features tier-high

# === 11. x86_64 Windows ===
echo "--- x86_64 Windows ---"
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu \
    --features tier-mid

# === 12. Gather binaries ===
echo ""
echo "=== Output ==="
echo "Binary sizes (stripped):"
find target -name "pwdcrack*" -type f -executable 2>/dev/null | while read f; do
    size=$(du -h "$f" | cut -f1)
    echo "  $size  $f"
done
```

### 3.3 Cross-compilation Targets Summary

```
┌──────────────────────────────────┬──────────┬──────────────────────┬────────────┐
│ Target                           │ Arch     │ Feature Set         │ Linker     │
├──────────────────────────────────┼──────────┼──────────────────────┼────────────┤
│ x86_64-unknown-linux-gnu         │ x86_64   │ tier-high (auto)    │ gcc/lld    │
│ x86_64-unknown-linux-gnu (AVX2)  │ x86_64   │ tier-mid (forced)   │ gcc/lld    │
│ i686-unknown-linux-gnu           │ x86 32   │ tier-low            │ gcc/lld    │
│ aarch64-unknown-linux-gnu        │ ARM64    │ tier-mid            │ gcc/lld    │
│ armv7-unknown-linux-gnueabihf    │ ARM32    │ tier-low            │ gcc/lld    │
│ aarch64-linux-android            │ ARM64    │ tier-mid            │ android-ndk│
│ armv7-linux-androideabi          │ ARM32    │ tier-low            │ android-ndk│
│ x86_64-apple-darwin              │ x86_64   │ tier-mid            │ ld64       │
│ aarch64-apple-darwin             │ ARM64    │ tier-high           │ ld64       │
│ x86_64-pc-windows-gnu            │ x86_64   │ tier-mid            │ lld        │
│ i686-pc-windows-gnu              │ x86 32   │ tier-low            │ lld        │
└──────────────────────────────────┴──────────┴──────────────────────┴────────────┘
```

---

## 4. MEMORY MANAGEMENT PER TIER

### 4.1 Adaptive Memory Strategy

```
┌────────────────┬──────────┬───────────┬───────────┬──────────┐
│ Component      │ Low-End  │ Mid-Range │ High-End  │ Android  │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Wordlist       │ Stream   │ mmap      │ mmap      │ Mmap or  │
│                │ (64KB    │ (Map)     │ (Huge 2MB │ Stream   │
│                │  buffer) │           │  pages)   │ based on │
│                │          │           │           │ RAM      │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Arena/thread   │ 16KB     │ 64KB      │ 1MB       │ 32KB     │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Batch size     │ 8        │ 64        │ 1024      │ 32       │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Hash cache     │ None     │ 512KB     │ 8MB       │ 128KB    │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Potfile buffer │ 1KB      │ 8KB       │ 64KB      │ 2KB      │
├────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Max wordlist   │ 128MB    │ 2GB       │ Unlimited │ 256MB    │
│ (stream chunk) │          │           │           │          │
└────────────────┴──────────┴───────────┴───────────┴──────────┘
```

### 4.2 Auto-Config From Available RAM

```rust
pub fn configure_memory(ram_mb: u64, is_32bit: bool) -> MemoryConfig {
    // 32-bit limitation: max ~3GB addressable
    // Android: limited by cgroup/memory limit
    // Low-RAM: use streaming I/O instead of mmap

    let max_wordlist_mb = if is_32bit {
        // 32-bit address space: max 3GB user space
        // Reserve 1GB for process, use max 2GB for wordlist
        ram_mb.min(2048).saturating_sub(512)
    } else {
        // 64-bit: use up to 75% of RAM
        (ram_mb * 3 / 4) as usize
    };

    // Streaming threshold: below 512MB, don't mmap
    let io_mode = if ram_mb < 512 || is_32bit {
        IoMode::Stream
    } else {
        IoMode::Mmap
    };

    // Batch size: fit in L2 cache (typical: 256KB-1MB)
    // Lower batch for low-RAM to reduce memory pressure
    let batch_size = match ram_mb {
        r if r < 256 => 8,
        r if r < 512 => 16,
        r if r < 1024 => 32,
        r if r < 4096 => 64,
        _ => 256,
    };

    MemoryConfig {
        io_mode,
        batch_size,
        max_wordlist_mb,
        arena_size: (batch_size * 64).max(16 * 1024), // 64 bytes per candidate
        potfile_buffer: batch_size * 8,
    }
}
```

---

## 5. RUNTIME ADAPTATION

### 5.1 Startup Sequence

```rust
fn main() {
    // 1. Detect hardware tier
    let tier = HardwareTier::detect();

    // 2. Print platform info
    println!("🚀 pwdcrack v{}", env!("CARGO_PKG_VERSION"));
    println!("   Platform: {} ({}-bit)", std::env::consts::ARCH, 
             if cfg!(target_pointer_width = "64") { "64" } else { "32" });
    println!("   OS: {}", std::env::consts::OS);
    println!("   Tier: {:?}", tier.name());
    println!("   SIMD: {:?}", tier.simd());
    println!("   Cores: {}", tier.cores());
    println!("   RAM: {} MB", tier.ram_mb());

    #[cfg(target_os = "android")]
    println!("   Mode: Android (Termux)");

    // 3. Apply auto-config
    let config = tier.recommend_config();
    apply_config(config);

    // 4. Initialize SIMD dispatch
    init_simd_detection();

    // 5. Print available backends
    let gpu_status = if config.use_gpu { "✅ Available" } else { "❌ Not available" };
    println!("   GPU: {}", gpu_status);
    println!("   SIMD: {:?}", CURRENT_SIMD_LEVEL.load(Ordering::Relaxed));
    println!();

    // 6. Parse CLI args
    let args = Cli::parse();

    // 7. Run attack
    run(args);
}
```

### 5.2 Tier-Specific Output

```
=== Tier 1: Low-end (32-bit ARM, 512MB RAM) ===

🚀 pwdcrack v0.2.0
   Platform: arm (32-bit)
   OS: android
   Tier: Low-End
   SIMD: Neon32
   Cores: 4
   RAM: 492 MB
   GPU: ❌ Not available
   SIMD: Neon32

[*] Running in low-memory mode (streaming I/O)
[*] Batch size: 16 passwords at a time
[*] Arena: 16KB per thread
[*] Wordlist limit: 128MB

=== Tier 3: High-end (x86_64, RTX 4090, 64GB RAM) ===

🚀 pwdcrack v0.2.0
   Platform: x86_64 (64-bit)
   OS: linux
   Tier: High-End
   SIMD: AVX-512 + VAES
   Cores: 32
   RAM: 64384 MB
   GPU: ✅ NVIDIA RTX 4090 (via wgpu/Vulkan)
   FPGA: ✅ Xilinx XCKU060

[*] Running in high-performance mode
[*] GPU backend: Vulkan (wgpu)
[*] FPGA: 4x bcrypt cores @ 200MHz
[*] Power budget: 450W (auto)
[*] Huge pages: 2MB (enabled)
[*] Batch size: 1024 passwords
```

### 5.3 Graceful Degradation

```rust
/// When a feature is requested but not available:
/// Never crash — always fall back to slower path

impl DictionaryAttack {
    fn run(&self, config: &CrackingConfig) -> Result<Vec<CrackResult>> {
        match config.io_mode {
            IoMode::Mmap => {
                match self.try_mmap_wordlist() {
                    Ok(map) => self.crack_mmap(map, config),
                    Err(_) => {
                        // Fallback: stream instead
                        log::warn!("mmap failed, falling back to streaming I/O");
                        self.crack_stream(config)
                    }
                }
            }
            IoMode::Stream => self.crack_stream(config),
        }
    }
}

impl GpuBackend {
    fn crack(&self, batch: &[Password], config: &CrackingConfig) -> Vec<CrackResult> {
        match self.try_gpu_crack(batch) {
            Ok(results) => results,
            Err(GpuError::OutOfMemory) => {
                // GPU ran out of memory — split batch
                log::warn!("GPU OOM, splitting batch");
                let mid = batch.len() / 2;
                let mut results = self.crack(&batch[..mid], config);
                results.extend(self.crack(&batch[mid..], config));
                results
            }
            Err(GpuError::DeviceLost) => {
                // GPU crashed — fall back to CPU
                log::warn!("GPU device lost, falling back to CPU");
                self.cpu_fallback.crack(batch, config)
            }
            Err(GpuError::Unsupported) => {
                // GPU doesn't support this hash type
                log::warn!("GPU doesn't support this hash, using CPU");
                self.cpu_fallback.crack(batch, config)
            }
        }
    }
}
```

---

## 6. TARGET PERFORMANCE BY TIER

### 6.1 Dictionary Attack (rockyou.txt, 14M words, NTLM)

```
┌──────────────────────┬────────┬──────────┬──────────┬─────────────────────────┐
│ Device               │ Tier   │ Time     │ Rate     │ Power                   │
├──────────────────────┼────────┼──────────┼──────────┼─────────────────────────┤
│ Pentium 4 (32-bit)   │ Low    │ 12 min   │ 19 KH/s  │ 50W                     │
│ Raspberry Pi 4 (ARM) │ Low    │ 4 min    │ 58 KH/s  │ 7W (idle: 3W)           │
│ Android (SDM865)     │ Mid    │ 1.5 min  │ 155 KH/s │ 3W (battery efficient)  │
│ Core i5-12400        │ Mid    │ 8 sec    │ 1.7 MH/s │ 65W                     │
│ Ryzen 9 7950X        │ High   │ 1.5 sec  │ 9.3 MH/s │ 170W                    │
│ RTX 4090 (GPU)       │ High   │ 0.07 sec │ 80 GH/s  │ 450W                    │
│ FPGA XCKU060         │ High   │ 0.2 sec  │ 2.6 GH/s │ 8W (ultra efficient)    │
│ 10× RTX 4090         │ Dist   │ 0.007s   │ 850 GH/s │ 5000W                   │
└──────────────────────┴────────┴──────────┴──────────┴─────────────────────────┘
```

### 6.2 Brute-Force (8-char lowercase, 26^8 = 208B keys, MD5)

```
┌──────────────────────┬────────┬──────────┬──────────┬─────────────────────────┐
│ Device               │ Tier   │ Time     │ Rate     │ Notes                   │
├──────────────────────┼────────┼──────────┼──────────┼─────────────────────────┤
│ Pentium 4            │ Low    │ 127 days │ 19 KH/s  │ Not practical           │
│ Raspberry Pi 4       │ Low    │ 41 days  │ 58 KH/s  │ Not practical           │
│ Android (SDM865)     │ Mid    │ 15 days  │ 155 KH/s │ Battery: 2h runtime     │
│ Core i5-12400        │ Mid    │ 1.4 days │ 1.7 MH/s │ Possible with rules     │
│ Ryzen 9 7950X        │ High   │ 6.2 hrs  │ 9.3 MH/s │ Mask attack feasible    │
│ RTX 4090 (GPU)       │ High   │ 2.5 sec  │ 85 GH/s  │ Instant!                │
│ FPGA XCKU060         │ High   │ 80 sec   │ 2.6 GH/s │ Very efficient          │
└──────────────────────┴────────┴──────────┴──────────┴─────────────────────────┘
```

### 6.3 bcrypt (cost=10 — 1024 rounds)

```
┌──────────────────────┬────────┬──────────┬──────────┬─────────────────────────┐
│ Device               │ Tier   │ Time     │ Rate     │ Energy per hash         │
├──────────────────────┼────────┼──────────┼──────────┼─────────────────────────┤
│ Pentium 4            │ Low    │ 0.2 H/s  │ 0.2 H/s  │ 250 J                   │
│ Raspberry Pi 4       │ Low    │ 0.5 H/s  │ 0.5 H/s  │ 14 J                    │
│ Android (SDM865)     │ Mid    │ 1.2 H/s  │ 1.2 H/s  │ 2.5 J (battery: 5000h)  │
│ Core i5-12400        │ Mid    │ 25 H/s   │ 25 H/s   │ 2.6 J                   │
│ Ryzen 9 7950X        │ High   │ 160 H/s  │ 160 H/s  │ 1.1 J                   │
│ RTX 4090 (GPU)       │ High   │ 5.5 KH/s │ 5.5 KH/s │ 0.08 J                  │
└──────────────────────┴────────┴──────────┴──────────┴─────────────────────────┘
```

---

## 7. FUTURE: DISTRIBUTED (Tier 4)

```
┌──────────────────┬──────────────────┬──────────────────┐
│   Master Node    │  Worker Node 1   │  Worker Node 2   │
│  ┌────────────┐  │  ┌────────────┐  │  ┌────────────┐  │
│  │ Scheduler  │  │  │ CPU(16C)   │  │  │ CPU(4C)    │  │
│  │ DB         │  │  │ GPU(RTX)   │  │  │ FPGA       │  │
│  │ API        │  │  │ 500W       │  │  │ 15W        │  │
│  └────────────┘  │  └────────────┘  │  └────────────┘  │
└──────────────────┴──────────────────┴──────────────────┘
                         │                    │
                         └──── LAN (TCP) ─────┘

Tier-aware dispatching:
  • bcrypt work → GPU workers (best hash/watt)
  • MD5/NTLM → FPGA workers (lowest power)
  • Rules/mutation → CPU workers (branch-heavy)
  • Low-end workers → dictionary attack (streaming)

Protocol: Cap'n Proto over TCP (zero-copy serialization)
```

---

## 8. QUICK START PER PLATFORM

### Android (Termux)

```bash
# Install Termux from F-Droid
pkg install rust binutils python
git clone https://github.com/your/pwdcrack
cd pwdcrack

# Build for ARM64 with NEON
cargo build --release --target aarch64-linux-android \
    --features tier-mid

# Or install pre-built binary
pkg install pwdcrack

# Run (auto-detects hardware)
pwdcrack dictionary hashes.txt /sdcard/wordlist.txt
```

### Raspberry Pi (32-bit)

```bash
cargo build --release --target armv7-unknown-linux-gnueabihf \
    --features tier-low
```

### Old x86 (32-bit, Pentium 4)

```bash
cargo build --release --target i686-unknown-linux-gnu \
    --features tier-low
```

### Modern Gaming PC

```bash
cargo build --release --features tier-high
```

### Everything Auto

```bash
cargo build --release --features tier-auto  # Default
./pwdcrack                                   # Auto-detect everything
```


---

## 9. PROJECT MAP — ENGINE FOLDER STRUCTURE

Seluruh engine dan komponen dipisahkan dalam folder-folder independen di luar `src/`. Masing-masing engine bisa dikerjakan, di-test, dan di-compile sendiri-sendiri.

```
pwdcrack/
│
├── src/                              # ◄ RUST CORE ENGINE (existing)
│   ├── main.rs                       # Entry point, CLI dispatch
│   ├── lib.rs                        # Shared library (libcrack-core)
│   ├── cli/                          # Argument parser
│   ├── hash/                         # Hash verification (19 types)
│   ├── attack/                       # Dictionary, brute, combinator
│   │   └── rules/                    # Rule engine (JTR/Hashcat)
│   ├── potfile.rs                    # Potfile I/O
│   └── util/                         # Utilities
│
├── engines/                          # ◄ ALL ENGINES (external from src/)
│   │
│   ├── engine-simd/                  # CPU: SIMD optimization
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── x86/
│   │       │   ├── sse2.rs
│   │       │   ├── avx2.rs
│   │       │   └── avx512.rs
│   │       └── arm/
│   │           ├── neon.rs
│   │           └── sve.rs
│   │
│   ├── engine-gpu/                   # GPU: wgpu/Vulkan/Metal/DX12
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── device.rs             # GPU device detection + selection
│   │   │   ├── pipeline.rs           # Compute pipeline builder
│   │   │   ├── buffer.rs             # GPU buffer pool (pinned memory)
│   │   │   └── shaders/              # WGSL compute shaders
│   │   │       ├── md5.wgsl
│   │   │       ├── sha1.wgsl
│   │   │       ├── sha256.wgsl
│   │   │       ├── ntlm.wgsl
│   │   │       └── bcrypt.wgsl
│   │   └── build.rs                  # Shader compilation
│   │
│   ├── engine-fpga/                  # FPGA: Verilog cores + Rust driver
│   │   ├── rtl/                      # Verilog/SystemVerilog source
│   │   │   ├── cores/
│   │   │   │   ├── md5_core.sv
│   │   │   │   ├── sha256_core.sv
│   │   │   │   └── ntlm_core.sv
│   │   │   ├── common/
│   │   │   │   ├── fifo.sv
│   │   │   │   └── pipeline.sv
│   │   │   └── top.sv               # Top-level module
│   │   ├── src/                      # Rust FPGA driver
│   │   │   ├── lib.rs
│   │   │   ├── pcie.rs              # PCIe DMA communication
│   │   │   └── protocol.rs          # Host-FPGA command protocol
│   │   ├── scripts/
│   │   │   ├── build.tcl            # Vivado synthesis script
│   │   │   ├── program.tcl          # Bitstream programmer
│   │   │   └── simulate.tcl         # Simulation script
│   │   ├── sim/                      # Verilog testbenches
│   │   │   ├── md5_tb.sv
│   │   │   └── sha256_tb.sv
│   │   └── constraints/
│   │       └── pwdcrack.xdc         # Timing constraints
│   │
│   ├── engine-jit/                   # JIT compilation (Cranelift)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── mask_compiler.rs     # Mask → native SIMD code
│   │       ├── rule_compiler.rs     # Rule → native code
│   │       └── ir.rs                # Intermediate representation
│   │
│   ├── engine-power/                 # Power management
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── rapl.rs              # Intel RAPL driver
│   │       ├── amd.rs               # AMD Zen power
│   │       ├── governor.rs          # Frequency scaling
│   │       └── scheduler.rs         # Power-aware work distribution
│   │
│   ├── engine-distributed/           # Distributed cracking
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── master.rs            # Master node
│   │       ├── worker.rs            # Worker node
│   │       ├── protocol.rs          # Network protocol
│   │       └── discovery.rs         # mDNS node discovery
│   │
│   ├── engine-web/                   # Web dashboard (Rust backend)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs            # Actix-web/FastAPI-like server
│   │       ├── routes.rs            # API endpoints
│   │       ├── websocket.rs         # Real-time progress
│   │       └── static/              # HTML/CSS/JS frontend
│   │
│   ├── engine-android/               # Android-specific glue
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── termux.rs            # Termux env detection
│   │       ├── battery.rs           # Battery-aware scheduling
│   │       └── saf.rs              # Storage Access Framework
│   │
│   └── engine-bridge/                # FFI bridges ke bahasa lain
│       ├── src/
│       │   ├── lib.rs               # C FFI exports
│       │   ├── python.rs            # PyO3 bindings
│       │   └── c_api.rs             # Plain C API
│       ├── python/                   # Python wrapper
│       │   ├── pwdcrack/
│       │   │   ├── __init__.py
│       │   │   └── _native.pyi
│       │   └── setup.py
│       └── perl/                     # Perl XS wrapper
│           ├── libpwdcrack.xs
│           └── Makefile.PL
│
├── scripts/                          # Build + CI scripts
│   ├── build-all.sh                  # Build semua target
│   ├── build-android.sh              # Cross-compile untuk Android
│   ├── test-all.sh                   # Test semua engine
│   ├── bench-all.sh                  # Benchmark semua tier
│   ├── package.sh                    # Package release
│   ├── docker-build.sh               # Docker image
│   └── cross-compile/                # Cross-compilation helpers
│       ├── android-ndk.sh
│       └── termux-env.sh
│
├── docker/                           # Docker environments
│   ├── Dockerfile.low                # Alpine: 32-bit, 64MB RAM
│   ├── Dockerfile.mid                # Debian: 4-core, 4GB RAM
│   ├── Dockerfile.high               # Ubuntu: GPU + FPGA passthrough
│   ├── Dockerfile.android            # Termux cross-compile env
│   └── docker-compose.yml            # Distributed cluster
│
├── configs/                          # Configuration templates
│   ├── pwdcrack.low.toml            # Config untuk low-end
│   ├── pwdcrack.mid.toml            # Config untuk mid-range
│   ├── pwdcrack.high.toml           # Config untuk high-end
│   ├── pwdcrack.android.toml        # Config untuk Android
│   └── pwdcrack.dist.toml           # Config untuk distributed
│
├── rules/                            # Rule files (JTR/Hashcat format)
│   ├── best64.rule                   # Top 64 rules
│   ├── d3ad0ne.rule                  # d3ad0ne's rules
│   └── generated/                    # Auto-generated rules
│
├── wordlists/                        # Wordlist helpers
│   └── download.sh                   # Download common wordlists
│
├── tests/                            # Integration tests
│   ├── test_vectors/                 # Known hash:password pairs
│   │   ├── md5.txt
│   │   ├── ntlm.txt
│   │   ├── sha256.txt
│   │   ├── bcrypt.txt
│   │   └── ...
│   ├── test_vectors_gen.py           # Generate test vectors
│   └── cross_platform/               # Platform-specific tests
│       ├── test_android.sh
│       └── test_32bit.sh
│
├── benchmarks/                       # Benchmark results
│   ├── results/                      # Historical benchmark data
│   └── compare.py                    # Compare results across runs
│
├── docs/                             # Documentation
│   ├── architecture.md               # This file
│   ├── api.md                        # API documentation
│   ├── tier-low.md                   # Low-end setup guide
│   ├── tier-mid.md                   # Mid-range setup guide
│   ├── tier-high.md                  # High-end setup guide
│   ├── android.md                    # Android/Termux guide
│   └── distributed.md               # Distributed setup guide
│
├── Cargo.toml                        # Workspace root
├── Cargo.lock
├── Makefile                          # Top-level build commands
└── README.md                         # Project overview
```


---

## 10. IMPLEMENTATION ROADMAP — DETAILED PHASES

### Phase Mapping

```
Phase 0 [DONE]     ████████████████████████████████████  Rust Core (existing)
Phase 1 [2 bulan]  ████████████████████░░░░░░░░░░░░░░░░  Auto-Tier + SIMD Engine
Phase 2 [2 bulan]  ████████████████████████████░░░░░░░░  GPU Engine (wgpu)
Phase 3 [1 bulan]  ████████████████████████████████░░░░  JIT Engine
Phase 4 [1 bulan]  ████████████████████████████████████  Power Engine
Phase 5 [1 bulan]  ████████████████████████████████████  Android/Termux
Phase 6 [2 bulan]  ████████████████████████████████████  FPGA Engine
Phase 7 [1 bulan]  ████████████████████████████████████  Bridge (Python/Perl)
Phase 8 [1 bulan]  ████████████████████████████████████  Distributed
Phase 9 [1 bulan]  ████████████████████████████████████  Web Dashboard
Phase10[1 bulan]   ████████████████████████████████████  Polish + Release
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total: ~13 bulan
```


### PHASE 0: FOUNDATION (DONE) — Rust Core Engine

**Status:** ✅ SELESAI

**Folder:** `src/`

**Deliverables:**
- ✅ Hash verification (MD5, SHA1/256/512, SHA3, BLAKE2, RIPEMD, NTLM, LM, bcrypt, Argon2, scrypt, Unix crypt)
- ✅ Dictionary attack (wordlist + rules)
- ✅ Brute-force attack (mask)
- ✅ Combinator attack
- ✅ Rule engine (JTR/Hashcat compatible)
- ✅ Multi-threading (rayon)
- ✅ Potfile save/load
- ✅ Benchmark mode
- ✅ Hash auto-detection
- ✅ CLI argument parser (clap)

**File count:** 17 source files
**Tests:** 7 unit tests (rules engine)
**Performance:** MD5 ~2M H/s (debug), ~20M H/s (release, 16-core)


### PHASE 1: AUTO-TIER + SIMD ENGINE (Month 1-2)

**Folder:** `engines/engine-simd/`
**Dependency:** Phase 0 (Rust Core)

#### Objectives
1. Hardware auto-detection system (CPUID, RAM, platform)
2. SIMD-accelerated hash verification (AVX2, AVX-512, NEON)
3. Graceful fallback: AVX-512 → AVX2 → SSE → Scalar
4. Adaptive memory management per tier
5. Cross-compilation for 12 targets

#### Task Breakdown

```
Month 1 — Auto-Tier Detection
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 1-2: Hardware Detection
  [ ] Implement HardwareTier::detect()
  [ ] CPUID-based SIMD level detection
      • x86: CPUID leaf 1 → SSE2, leaf 7 → AVX2/AVX-512
      • ARM: /proc/cpuinfo features, aux vector HWCAP
  [ ] Cross-platform RAM detection
      • Linux: /proc/meminfo
      • macOS: sysctl hw.memsize
      • Windows: GlobalMemoryStatusEx
      • Android: /proc/meminfo (Termux)
  [ ] GPU detection via wgpu adapter query
  [ ] FPGA detection (PCIe vendor/device ID)
  [ ] Power monitoring capability check
      • Intel: /sys/class/powercap/intel-rapl
      • AMD: /sys/class/hwmon/hwmon*/energy*_input
  [ ] Platform info collector
  [ ] Unit tests for detection on all platforms

Week 3-4: Adaptive Config
  [ ] CrackingConfig generator per tier
  [ ] Memory config: arena size, batch size, I/O mode
  [ ] Thread config: NUMA-aware pinning
  [ ] Power config: budget, governor, C-state
  [ ] Wordlist loading strategy (mmap vs stream)
  [ ] Config file support (TOML)
  [ ] Override system (CLI flag override auto-detect)
  [ ] Graceful degradation tests:
      • 32-bit address space limit
      • Low RAM (128MB simulated)
      • No SIMD fallback

Month 2 — SIMD Hash Engine
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 5-6: x86 SIMD
  [ ] SSE2 MD5 (2-way)
  [ ] SSE4.2 MD5 (4-way)
  [ ] AVX2 MD5 (8-way)
  [ ] AVX-512 MD5 (16-way)
  [ ] AVX2 SHA-1 (8-way)
  [ ] AVX2 SHA-256 (8-way)
  [ ] AVX-512 VAES SHA-256 (16-way)
  [ ] SSE2/AVX2 NTLM (8-way)
  [ ] SIMD autodetect + dispatch layer
  [ ] Benchmarks: scalar vs SSE vs AVX2 vs AVX-512

Week 7-8: ARM SIMD + Testing
  [ ] NEON MD5 (4-way, ARMv7/v8)
  [ ] NEON SHA-1 (4-way)
  [ ] NEON SHA-256 (4-way)
  [ ] SVE MD5 (variable width)
  [ ] Cross-platform CI pipeline
  [ ] 32-bit x86 build test
  [ ] 32-bit ARM build test
  [ ] 64-bit ARM build test (RPi, Android)
  [ ] Regression tests against known test vectors
```

**Deliverables Phase 1:**
- `engines/engine-simd/` — SIMD library
- `src/core/tier.rs` — Auto-tier detection
- `src/core/config.rs` — Adaptive config
- Cross-compile scripts for 12 targets

**Milestone:** `v0.2.0 — "Auto-Tier"`

**Test Vectors:**
```bash
# Verify SIMD correctness on all platforms
pwdcrack test vectors/md5.txt     # Must match across SSE/AVX/NEON
pwdcrack test vectors/ntlm.txt
pwdcrack test vectors/sha256.txt
pwdcrack test vectors/bcrypt.txt
```

**Acceptance Criteria:**
- [ ] Auto-detect Pentium 4 → SSE2 scalar (low tier)
- [ ] Auto-detect RPi 4 → NEON 64 (mid tier)
- [ ] Auto-detect Ryzen 9 → AVX2 (high tier)
- [ ] Auto-detect Ice Lake → AVX-512 + VAES (high tier)
- [ ] SIMD 8x faster than scalar on AVX2
- [ ] Zero crashes on 32-bit ARM (RPi 2, Android)
- [ ] Graceful fallback when SIMD feature missing


### PHASE 2: GPU ENGINE (Month 3-4)

**Folder:** `engines/engine-gpu/`
**Dependency:** Phase 1 (SIMD + Tier)
**Blocking:** Requires wgpu 22+, Vulkan 1.2+ driver

#### Objectives
1. GPU compute via wgpu (Vulkan/Metal/DX12) — pure Rust, no C
2. Hash compute shaders: MD5, SHA1, SHA256, NTLM, bcrypt
3. Automatic GPU selection (iGPU vs dGPU)
4. Host-GPU buffer management (pinned memory, async)
5. Hybrid CPU+GPU scheduler with work stealing
6. Graceful fallback when no GPU available

#### Task Breakdown

```
Month 3 — GPU Pipeline
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 9-10: Foundation
  [ ] wgpu device + adapter initialization
  [ ] GPU capability query:
      • Compute shader support
      • Storage buffer max size
      • Workgroup size limits
      • Dedicated vs integrated GPU detection
  [ ] Multi-GPU enumeration
  [ ] Buffer pool with pinned host memory
  [ ] Async fence + semaphore synchronization
  [ ] GPU info display (name, driver, VRAM)
  [ ] Fallback: no GPU → CPU SIMD

Week 11-12: Compute Shaders
  [ ] WGSL MD5 compute shader
      • 64 passwords per workgroup
      • Unrolled rounds (constant-time)
      • Target hash comparison in shader
  [ ] WGSL SHA-1 compute shader
  [ ] WGSL SHA-256 compute shader
  [ ] WGSL NTLM compute shader (MD4 + UTF16-LE)
  [ ] Shader compilation pipeline (naga)
  [ ] Pipeline cache (avoid recompilation)
  [ ] Unit tests: GPU vs CPU result match

Month 4 — GPU Scheduler
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 13-14: Batch Processing
  [ ] Batch submission: queue multiple dispatches
  [ ] Asynchronous result readback
  [ ] Chunked processing for large keyspaces
  [ ] GPU memory management (avoid OOM)
  [ ] Multi-GPU work distribution
      • Split keyspace across GPUs
      • Merge results
  [ ] GPU-CPU hybrid scheduling
      • bcrypt/Argon2 → GPU (parallel friendly)
      • Rules/mutation → CPU (branch-heavy)
  [ ] Auto batch-size tuning

Week 15-16: bcrypt Shader + Polish
  [ ] WGSL bcrypt compute shader
      • Blowfish key schedule (4KB S-boxes)
      • Salt expansion
      • 2^cost rounds
  [ ] GPU benchmark mode
  [ ] Per-GPU performance tracking
  [ ] Cross-GPU result consistency test
  [ ] Integration test: crack known hashes
  [ ] Documentation: GPU requirements per tier
```

**Deliverables Phase 2:**
- `engines/engine-gpu/` — Full GPU engine
- WGSL shaders for MD5, SHA1, SHA256, NTLM, bcrypt
- Hybrid CPU+GPU scheduler
- Multi-GPU support

**Milestone:** `v0.3.0 — "GPU Boost"`

**GPU Requirements Per Tier:**
```
Tier 2 (Mid):  Integrated GPU (Intel Iris, AMD Vega, Apple M1)
               → MD5: ~500 MH/s, limited VRAM
               → Batches: 16K passwords

Tier 3 (High): Discrete GPU (RTX 4090, Radeon 7900 XTX)
               → MD5: ~85 GH/s, 24GB VRAM
               → Batches: 1M passwords
```

**Acceptance Criteria:**
- [ ] GPU MD5 matches CPU MD5 for all test vectors
- [ ] Auto-detect no-GPU → CPU fallback silently
- [ ] Multi-GPU: 2× GPUs = 2× throughput
- [ ] GPU crash → resume on CPU (no data loss)
- [ ] bcrypt GPU: 5.5 KH/s on RTX 4090 (cost 10)
- [ ] Vulkan, Metal, DX12 all work


### PHASE 3: JIT ENGINE (Month 5)

**Folder:** `engines/engine-jit/`
**Dependency:** Phase 1 (SIMD)
**Note:** Cranelift JIT for runtime code generation

#### Objectives
1. Compile mask patterns to native SIMD code at runtime
2. Compile rule chains to native code (bypass interpreter)
3. Hot/cold splitting: hot rules → JIT, cold → interpreted
4. Self-modifying code for tight loops

#### Task Breakdown

```
Month 5 — JIT Compilation
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 17-18: Mask JIT
  [ ] Cranelift JIT initialization
  [ ] Intermediate Representation (IR) for mask ops
  [ ] Mask → IR compiler:
      "?l?l?d" → loop a-z, a-z, 0-9 with SIMD
  [ ] IR → native code (Cranelift backend)
  [ ] JIT cache: avoid recompiling same mask
  [ ] Memory management: JIT arena
  [ ] Benchmark: interpreted vs JIT mask

Week 19-20: Rule JIT
  [ ] IR for rule operations
  [ ] Rule chain → IR compiler
      "l r $1 $2 $3" → lowercase + reverse + append
  [ ] Conditional branch optimization
  [ ] Hot rule profiling (count executions)
  [ ] Hot/cold threshold (JIT after N executions)
  [ ] Cold fallback: interpreted engine (existing)
  [ ] Integration with dictionary attack
  [ ] Tests: JIT output matches interpreted output
```

**Deliverables Phase 3:**
- `engines/engine-jit/` — JIT library
- Mask compiler: pattern → native SIMD
- Rule compiler: chain → native code

**Milestone:** `v0.4.0 — "JIT Turbo"`

**Performance Target:**
```
Mask expansion: 5-10× faster than interpreted
Rule application: 3-5× faster than interpreted
```

**Acceptance Criteria:**
- [ ] JIT output byte-identical to interpreted output
- [ ] JIT mask 5× faster than interpreter (benchmark)
- [ ] JIT rules 3× faster than interpreter
- [ ] Graceful fallback if JIT fails (use interpreter)
- [ ] No memory leak from JIT arena


### PHASE 4: POWER ENGINE (Month 6)

**Folder:** `engines/engine-power/`
**Dependency:** Phase 1 (Tier detection)

#### Objectives
1. Real-time power monitoring (Intel RAPL, AMD Zen)
2. Dynamic frequency scaling based on workload
3. Battery-aware mode (Android, laptops)
4. Power budget enforcement
5. Idle detection + deep sleep (C10)

#### Task Breakdown

```
Month 6 — Power Management
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 21-22: Power Monitoring
  [ ] Intel RAPL driver
      • /sys/class/powercap/intel-rapl/*/energy_uj
      • Package, core, uncore, DRAM domains
      • Sample rate: 1ms
  [ ] AMD Zen power driver
      • /sys/class/hwmon/hwmon*/energy*_input
      • CPU + SoC power
  [ ] GPU power (NVIDIA NVML via Rust bindings)
  [ ] GPU power (AMD via sysfs hwmon)
  [ ] Android battery monitoring
      • /sys/class/power_supply/battery/
      • current_now, voltage_now, capacity
  [ ] Power stats collector
      • Watts per hash
      • Joules per hash
      • Hash per watt (HPW)

Week 23-24: Power Governor
  [ ] Workload classification:
      • Compute-bound (bcrypt, Argon2) → high freq
      • Memory-bound (dictionary) → low freq
      • GPU offload → CPU sleep
      • Mixed → balanced
  [ ] Userspace frequency scaling
      • /sys/devices/system/cpu/cpu*/cpufreq/scaling_setspeed
  [ ] C-state control
      • Idle core → C6/C10 deep sleep
      • Wake on work arrival
  [ ] Power budget enforcement
      • User sets max watts (e.g., --power-budget 65W)
      • Governor throttles when exceeded
  [ ] Battery-aware mode
      • Detect battery vs AC power
      • Battery: limit to 15W, prefer efficient hashes
      • AC: max performance
  [ ] Power efficiency report
      • Hashes per watt for each hash type
      • Energy cost estimation ($ per hash)
```

**Deliverables Phase 4:**
- `engines/engine-power/` — Power management library
- Real-time power display in CLI
- Battery-aware mode for laptops/Android

**Milestone:** `v0.5.0 — "Power Saver"`

**Power Efficiency Targets:**
```
┌──────────────┬─────────────┬──────────────────────┐
│ Scenario     │ Without     │ With Power Engine    │
├──────────────┼─────────────┼──────────────────────┤
│ Dict attack  │ 180W @ 45M  │ 80W @ 43M H/s        │
│ (desktop)    │ H/s NTLM    │ (56% power saved)    │
├──────────────┼─────────────┼──────────────────────┤
│ Brute MD5    │ 500W @ 85G  │ 500W @ 85G H/s       │
│ (RTX 4090)   │ H/s         │ (GPU full speed)     │
├──────────────┼─────────────┼──────────────────────┤
│ Android      │ 3W @ 30 min │ 1.5W @ 2 hours       │
│ (battery)    │             │ (4× battery life)    │
└──────────────┴─────────────┴──────────────────────┘
```

**Acceptance Criteria:**
- [ ] RAPL monitoring works on Intel (Haswell+)
- [ ] AMD power works on Zen 3+
- [ ] Memory-bound attack uses 40% less power
- [ ] Battery mode: 2+ hours continuous cracking
- [ ] Power budget: never exceed user limit
- [ ] Graceful: no RAPL → no power features (Android, ARM)


### PHASE 5: ANDROID / TERMUX (Month 7)

**Folder:** `engines/engine-android/`
**Dependency:** Phase 1 (Tier), Phase 4 (Power)

#### Objectives
1. First-class Android/Termux support
2. NEON SIMD for ARM64/ARM32
3. Battery-aware cracking (pause on low battery)
4. Storage Access Framework (SAF) for file access
5. Termux-specific optimizations (bionic libc, limited RAM)

#### Task Breakdown

```
Month 7 — Android/Termux
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 25-26: Android Runtime
  [ ] Termux environment detection
      • TERMUX_VERSION env var
      • /data/data/com.termux/files/usr prefix
  [ ] bionic libc compatibility
      • No glibc-specific features
      • Use libc crate with bionic support
  [ ] ARM64 NEON SIMD path (from Phase 1)
  [ ] ARM32 NEON SIMD path (older devices)
  [ ] Limited RAM handling (512MB - 4GB)
      • Aggressive streaming I/O (no mmap on low RAM)
      • Tiny batch sizes (8-32 passwords)
      • Minimal arena (16KB per thread)
  [ ] Storage Access Framework (SAF)
      • /sdcard access via content:// URIs
      • open SAF URIs via FUSE or cp hack
  [ ] Android notification on crack found

Week 27-28: Battery Optimization
  [ ] Battery monitoring
      • /sys/class/power_supply/battery/capacity
      • /sys/class/power_supply/battery/status
  [ ] Battery modes:
      • >50%: normal cracking
      • 20-50%: slow mode (single thread, freq cap)
      • <20%: pause, save session
      • Charging: full speed
  [ ] Thermal throttling detection
      • /sys/class/thermal/thermal_zone*/temp
      • If >60°C: reduce threads, lower freq
      • If >80°C: pause until cool
  [ ] Background service (no-gui mode)
  [ ] Session save/restore on battery death
  [ ] Documentation: Termux installation guide
  [ ] Pre-built binaries for Termux (via GitHub releases)
```

**Deliverables Phase 5:**
- `engines/engine-android/` — Android glue
- Pre-built ARM64 + ARM32 binaries
- Termux install script (`curl | bash`)
- Battery-safe cracking profiles

**Milestone:** `v0.6.0 — "Android Ready"`

**Target Devices:**
```
┌──────────────────────┬─────────┬──────────┬──────────┐
│ Device               │ Arch    │ SIMD     │ Expected │
│                      │         │          │ NTLM/s   │
├──────────────────────┼─────────┼──────────┼──────────┤
│ Xiaomi Redmi 9A      │ ARM64   │ NEON     │ 65 KH/s  │
│ (Helio G25, 2.0GHz)  │         │          │          │
├──────────────────────┼─────────┼──────────┼──────────┤
│ Samsung S23 Ultra    │ ARM64   │ NEON+SVE │ 280 KH/s │
│ (Snapdragon 8 Gen 2) │         │          │          │
├──────────────────────┼─────────┼──────────┼──────────┤
│ Raspberry Pi 5       │ ARM64   │ NEON     │ 85 KH/s  │
│ (Cortex-A76, 2.4GHz) │         │          │          │
├──────────────────────┼─────────┼──────────┼──────────┤
│ Raspberry Pi 3       │ ARM32   │ NEON     │ 22 KH/s  │
│ (Cortex-A53, 1.2GHz) │         │          │          │
└──────────────────────┴─────────┴──────────┴──────────┘
```

**Acceptance Criteria:**
- [ ] Runs on Termux (Android 10+) without root
- [ ] NEON SIMD active on all ARM64 devices
- [ ] Battery <20%: auto-pause with session save
- [ ] Thermal >80°C: auto-pause, resume when cool
- [ ] 32-bit ARM (RPi 2, old Android) works
- [ ] SAF file access works (/sdcard/Downloads/)
- [ ] Pre-built APK/termux package available


### PHASE 6: FPGA ENGINE (Month 8-9)

**Folder:** `engines/engine-fpga/`
**Dependency:** Phase 1 (Tier), Phase 4 (Power)
**Note:** Requires FPGA board (Xilinx, Intel, or Lattice)

#### Objectives
1. Verilog hash cores: MD5, SHA256, NTLM (fully pipelined)
2. PCIe DMA communication between host and FPGA
3. Work scheduler: batch passwords to FPGA, collect results
4. Power-efficient: FPGA uses 8W vs GPU 450W

#### Task Breakdown

```
Month 8 — Verilog Cores
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 29-30: MD5 Core
  [ ] MD5 algorithm study + microarchitecture design
  [ ] Fully pipelined MD5 (1 hash/cycle after latency)
      • 64 stages, each doing one round
      • Clock: 200MHz on Xilinx KU060
      • Throughput: 200M H/s per core
  [ ] Write Verilog: md5_core.sv
      • Input: 512-bit message block
      • Output: 128-bit digest
      • Handshake: valid/ready protocol
  [ ] Simulation testbench
  [ ] Match against Rust MD5 (1000 random vectors)

Week 31-32: SHA256 + NTLM Cores
  [ ] SHA-256 pipelined core (64 stages)
  [ ] NTLM core = MD4 + UTF16-LE encoder
  [ ] Common modules:
      • fifo.sv — sync/async FIFO
      • pipeline_stage.sv — generic pipeline FF
      • clock_crossing.sv — CDC synchronizer
      • valid_ready.sv — handshake protocol
  [ ] Multiple core instantiation (4× MD5, 2× SHA256)
  [ ] Resource estimation:
      • LUT, FF, BRAM, DSP usage
      • Expected frequency
  [ ] Simulation: all cores together

Month 9 — Host Integration
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 33-34: PCIe + Scheduler
  [ ] PCIe DMA wrapper (AXI4-based)
  [ ] Host-FPGA command protocol
      • Command: hash_type, count, passwords
      • Response: match bitmap
  [ ] Rust FPGA driver (mmap /dev/fpga*)
      • engnes/engine-fpga/src/pcie.rs
  [ ] Multi-core scheduler
      • Distribute passwords to available cores
      • Load balancing
  [ ] Buffer management: DMA to/from FPGA
  [ ] Bitstream build script (Vivado)
  [ ] Timing closure (200MHz target)

Week 35-36: Integration + Testing
  [ ] FPGA benchmark mode
  [ ] Hybrid CPU+FPGA scheduler
      • FPGA: MD5, SHA256, NTLM (high throughput)
      • CPU: bcrypt, Argon2, rules (branch-heavy)
  [ ] Power measurement: FPGA vs CPU vs GPU
  [ ] Integration test: crack known hashes with FPGA
  [ ] Documentation: supported FPGA boards
  [ ] Build automation: all FPGAs
```

**Deliverables Phase 6:**
- `engines/engine-fpga/` — Full FPGA engine
- Verilog cores: MD5, SHA256, NTLM
- PCIe DMA driver (Rust)
- Vivado build scripts
- Bitstream files for supported boards

**Milestone:** `v0.7.0 — "FPGA Power"`

**Supported FPGA Boards:**
```
┌──────────────────────┬──────────┬──────────┬──────────────┐
│ Board                │ Cores    │ Through- │ Power        │
│                      │          │ put MD5  │              │
├──────────────────────┼──────────┼──────────┼──────────────┤
│ Xilinx XCKU060       │ 4× MD5   │ 800 MH/s │ 8W           │
│                      │ 2× SHA256│ 400 MH/s │              │
├──────────────────────┼──────────┼──────────┼──────────────┤
│ Xilinx XCVU9P        │ 16× MD5  │ 3.2 GH/s │ 35W          │
│                      │ 8× SHA256│ 1.6 GH/s │              │
├──────────────────────┼──────────┼──────────┼──────────────┤
│ Intel Agilex 7       │ 8× MD5   │ 1.6 GH/s │ 15W          │
│                      │ 4× SHA256│ 800 MH/s │              │
├──────────────────────┼──────────┼──────────┼──────────────┤
│ Lattice CertusPro-NX │ 2× MD5   │ 400 MH/s │ 2W           │
│                      │ —        │ —        │ (ultra-low)  │
└──────────────────────┴──────────┴──────────┴──────────────┘
```

**Efficiency Comparison (MD5):**
```
CPU (Ryzen 9):   9 MH/s/W   (170W for 1.5 GH/s)
GPU (RTX 4090):  190 MH/s/W (450W for 85 GH/s)
FPGA (XCKU060):  100 MH/s/W (8W for 800 MH/s)
  → FPGA 10× more efficient than CPU
  → FPGA 0.5× GPU (but 56× less power)
```

**Acceptance Criteria:**
- [ ] All test vectors match between FPGA and CPU
- [ ] PCIe DMA works (no data corruption)
- [ ] Auto-detect FPGA at startup
- [ ] No FPGA → CPU fallback
- [ ] 200MHz timing closure on KU060
- [ ] <10W power for KU060 board


### PHASE 7: BRIDGE ENGINE (Month 10)

**Folder:** `engines/engine-bridge/`
**Dependency:** Phase 0 (Rust Core)

#### Objectives
1. C FFI exports for all core functions
2. Python bindings (PyO3) for scripting
3. Perl XS bindings for text processing
4. Python CLI wrapper (rich CLI, distributed orchestration)

#### Task Breakdown

```
Month 10 — Language Bridges
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 37-38: C FFI + Python
  [ ] C API design (engines/engine-bridge/src/c_api.rs)
      • crack_init(), crack_shutdown()
      • hash_load_file(), hash_load_buffer()
      • attack_dictionary(), attack_bruteforce(), attack_combinator()
      • crack_get_result(), crack_stats()
  [ ] FFI safety: no unwind across boundary
  [ ] Error handling: return codes, never panic
  [ ] Python bindings via PyO3
      • engnes/engine-bridge/python/pwdcrack/
      • Native Python module (maturin build)
      • Type stubs (.pyi)
  [ ] Python CLI wrapper (Click + Rich)
      • pwdcrack command → Rust binary or Python
      • Rich progress bars, tables, live display
  [ ] Python packaging (setup.py, pyproject.toml)
  [ ] Tests: Python ↔ Rust roundtrip

Week 39-40: Perl + Documentation
  [ ] Perl XS bindings
      • engnes/engine-bridge/perl/
      • Hash format detection (regex)
      • Wordlist transformation
      • Rule conversion (John ↔ Hashcat)
  [ ] Perl packaging (Makefile.PL)
  [ ] API documentation (docs/api.md)
  [ ] Python examples: custom attack scripts
  [ ] Perl examples: one-liner utilities
  [ ] FFI benchmark (Python calling Rust)
```

**Deliverables Phase 7:**
- `engines/engine-bridge/` — FFI + Python + Perl
- `libcrack-core.so` — Shared library
- `pwdcrack` Python package (pip installable)
- `pwdcrack` Perl module (cpan installable)

**Milestone:** `v0.8.0 — "Polyglot"`

**API Example (Python):**
```python
import pwdcrack

# Initialize engine
pwdcrack.init()

# Load hashes
hashes = pwdcrack.load_file("hashes.txt")

# Dictionary attack
for result in pwdcrack.attack_dictionary("rockyou.txt"):
    print(f"{result.hash}:{result.password}")

# Custom: mutate wordlist in Python, verify in Rust
for word in my_wordlist:
    for mutated in [word, word.upper(), word + "123"]:
        if pwdcrack.verify_one(mutated, target_hash):
            print(f"Found: {mutated}")
```

**Acceptance Criteria:**
- [ ] C API callable from any language (C, C++, Go, Zig)
- [ ] Python pip package works (pip install pwdcrack)
- [ ] PyO3 function calls <1µs overhead
- [ ] Python ↔ Rust result consistency
- [ ] Perl module installable via cpan
- [ ] No segfaults from FFI misuse


### PHASE 8: DISTRIBUTED ENGINE (Month 11)

**Folder:** `engines/engine-distributed/`
**Dependency:** Phase 1-2 (Core + GPU)

#### Objectives
1. Master-worker architecture over TCP
2. Dynamic node discovery (mDNS)
3. Tier-aware work distribution
4. Checkpoint/resume per node
5. Power-aware: suspend workers when idle

#### Task Breakdown

```
Month 11 — Distributed Cracking
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 41-42: Master-Worker Protocol
  [ ] ZeroMQ (zmq) or custom TCP protocol
  [ ] Master node:
      • Keyspace partitioning
      • Work distribution
      • Result collection + dedup
      • Worker heartbeat monitoring
  [ ] Worker node:
      • Batch processing
      • Result reporting
      • Heartbeat
      • Checkpoint save
  [ ] Session persistence (master crash recovery)
  [ ] Load balancing: slow worker → less work
  [ ] Network bandwidth optimization

Week 43-44: Discovery + Scaling
  [ ] mDNS/DNS-SD node discovery
  [ ] Tier-aware dispatching:
      • bcrypt → GPU workers (best hash/watt)
      • MD5 → FPGA workers (lowest power)
      • Dictionary → CPU workers (memory-bound)
      • Low-end → dictionary only (streaming)
  [ ] Dynamic add/remove workers
  [ ] Power-aware: suspend idle workers
  [ ] End-to-end test: 3-node cluster
  [ ] Documentation: cluster setup guide
```

**Deliverables Phase 8:**
- `engines/engine-distributed/` — Full distributed engine
- Master node binary
- Worker node binary
- Docker Compose for cluster

**Milestone:** `v0.9.0 — "Cluster Mode"`

**Distributed Performance:**
```
10 nodes × (Ryzen 9 + RTX 4090):
  MD5 brute:    850 GH/s total (10× single node)
  NTLM dict:    800 GH/s total
  SHA-256:      250 GH/s total
  bcrypt (c10): 55 KH/s total
```

**Acceptance Criteria:**
- [ ] 2× nodes = 2× throughput (linear scaling)
- [ ] Worker crash → work redistributed (no data loss)
- [ ] Master crash → session resume from checkpoint
- [ ] Auto-discover workers on LAN
- [ ] Low-end worker automatically gets dictionary tasks
- [ ] GPU worker automatically gets GPU-friendly hashes


### PHASE 9: WEB DASHBOARD (Month 12)

**Folder:** `engines/engine-web/`
**Dependency:** Phase 2 (GPU), Phase 8 (Distributed)

#### Objectives
1. Real-time web dashboard (FastAPI-style, pure Rust)
2. Live progress: hashes/sec, cracked count, ETA
3. Session management: start, pause, resume, stop
4. Cluster monitoring: all nodes in one view
5. Power/thermal graphs

#### Task Breakdown

```
Month 12 — Web Dashboard
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 45-46: Backend
  [ ] HTTP server (actix-web or axum)
  [ ] REST API:
      • GET  /api/status — current attack status
      • GET  /api/stats — hashes/sec, cracked, ETA
      • POST /api/attack/start — start attack
      • POST /api/attack/pause — pause
      • POST /api/attack/stop — stop
      • GET  /api/nodes — cluster node list
      • GET  /api/power — power consumption
      • GET  /api/results — cracked passwords
  [ ] WebSocket: real-time push updates
  [ ] Session CRUD (save/load/resume)
  [ ] Authentication (optional, token-based)

Week 47-48: Frontend
  [ ] Single-page app (React/Svelte/Vanilla JS)
  [ ] Dashboard overview:
      • Speed gauge (H/s, trend graph)
      • Cracking progress bar
      • Cracked count with timeline
      • Power consumption (watts, J/hash)
      • Hardware utilization (CPU/GPU/FPGA)
  [ ] Node list with per-node stats
  [ ] Attack configuration page
  [ ] Results table with search/export
  [ ] Dark/light theme
  [ ] Mobile-responsive (Android browser)
  [ ] Embedded in pwdcrack binary (no separate server)
```

**Deliverables Phase 9:**
- `engines/engine-web/` — Web dashboard
- Binary: `pwdcrack web --port 8080`
- REST API + WebSocket
- Responsive SPA frontend

**Milestone:** `v0.10.0 — "Web Commander"`


### PHASE 10: POLISH + RELEASE (Month 13)

**Folder:** Root + `docs/`
**Dependency:** All previous phases

#### Objectives
1. Integration testing across all tiers
2. Performance optimization pass
3. Documentation complete
4. CI/CD pipeline mature
5. Package for all platforms
6. v1.0.0 release

#### Task Breakdown

```
Month 13 — Polish & v1.0.0
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

Week 49-50: Integration Testing
  [ ] Full regression test suite
      • All 19 hash types × all attack modes
      • All SIMD code paths
      • GPU (if available)
      • FPGA (if available)
      • 32-bit and 64-bit builds
  [ ] Cross-platform testing:
      • x86_64 Linux (native)
      • i686 Linux (32-bit Docker)
      • aarch64 Linux (RPi, Docker)
      • armv7 Linux (RPi 32-bit, Docker)
      • Android (Termux emulator or device)
      • macOS (Intel + Apple Silicon)
      • Windows (x86_64)
  [ ] Performance regression check
      • Compare against Phase 0 baseline
      • Ensure no regression

Week 51-52: Polish + Release
  [ ] Documentation complete
  [ ] man pages
  [ ] GitHub release workflow
  [ ] Pre-built binaries for all platforms
  [ ] Docker images (low/mid/high/android)
  [ ] Homebrew formula (macOS)
  [ ] apt repository (Linux)
  [ ] Termux package (Android)
  [ ] v1.0.0 release
```

**Deliverables Phase 10:**
- v1.0.0 release
- Pre-built binaries for all targets
- Docker images
- Package manager entries
- Complete documentation

**Milestone:** `v1.0.0 — "Universal"`


---

## 11. DEPENDENCY GRAPH

```
Phase 0 (Rust Core) ─────────────────────────────────────────────────────┐
    │                                                                     │
    ├──► Phase 1 (Auto-Tier + SIMD) ───────┐                             │
    │          │                            │                             │
    │          ├──► Phase 2 (GPU) ───────┐  │                             │
    │          │         │                │  │                             │
    │          │         ├──► Phase 6    │  │                             │
    │          │         │   (FPGA)      │  │                             │
    │          │         │                │  │                             │
    │          │         └──► Phase 8    │  │                             │
    │          │              (Dist)     │  │                             │
    │          │                          │  │                             │
    │          ├──► Phase 3 (JIT) ────────┘  │                             │
    │          │                              │                             │
    │          ├──► Phase 4 (Power) ──────┐  │                             │
    │          │          │                │  │                             │
    │          │          └──► Phase 5    │  │                             │
    │          │               (Android)  │  │                             │
    │          │                          │  │                             │
    │          └──► Phase 7 (Bridge) ────────┘                             │
    │               │                                                      │
    │               └──► Python + Perl wrappers                            │
    │                                                                      │
    └──► Phase 9 (Web Dashboard) ─── depends on Phase 2 + 8               │
                                                                          │
    Phase 10 (Polish + Release) ◄── depends on ALL phases                │
                                                                          │
    ┌─────────────────────────────────────────────────────────────────────┘
    │
    ▼
  v1.0.0
```

**Parallelizable Tracks:**
```
Track A: Phase 2 (GPU) → Phase 6 (FPGA) → Phase 8 (Distributed)
Track B: Phase 3 (JIT)
Track C: Phase 4 (Power) → Phase 5 (Android)
Track D: Phase 7 (Bridge)

Tracks A-D can be worked in parallel after Phase 1 completes.
Estimated: 8 months (parallel) = 13 months (serial)
```


## 12. TESTING STRATEGY PER PHASE

```
┌────────────────────┬──────────────────────────────────────────────────┐
│ Phase              │ Testing Strategy                                 │
├────────────────────┼──────────────────────────────────────────────────┤
│ 0. Rust Core       │ ✅ 7 unit tests (rules engine)                   │
│                    │ Manual: dictionary, brute, combinator            │
├────────────────────┼──────────────────────────────────────────────────┤
│ 1. Auto-Tier+SIMD  │ [ ] Test vectors: 1000 known hash:password       │
│                    │ [ ] SIMD output == scalar output                 │
│                    │ [ ] Cross-SIMD consistency                       │
│                    │ [ ] 32-bit vs 64-bit consistency                 │
│                    │ [ ] Auto-tier detection unit tests               │
├────────────────────┼──────────────────────────────────────────────────┤
│ 2. GPU             │ [ ] GPU output == CPU output (test vectors)      │
│                    │ [ ] Multi-GPU result merge                       │
│                    │ [ ] GPU crash → CPU fallback                     │
│                    │ [ ] No GPU → graceful skip                       │
├────────────────────┼──────────────────────────────────────────────────┤
│ 3. JIT             │ [ ] JIT output == interpreter output             │
│                    │ [ ] 100 random rules tested                      │
│                    │ [ ] Memory leak check (valgrind)                 │
├────────────────────┼──────────────────────────────────────────────────┤
│ 4. Power           │ [ ] RAPL read test (Intel)                       │
│                    │ [ ] Power budget enforcement test                │
│                    │ [ ] Battery mode test (simulated)                │
├────────────────────┼──────────────────────────────────────────────────┤
│ 5. Android         │ [ ] Termux install test                          │
│                    │ [ ] Battery drain test (real device)             │
│                    │ [ ] NEON output == scalar test                   │
│                    │ [ ] Thermal throttle test                        │
├────────────────────┼──────────────────────────────────────────────────┤
│ 6. FPGA            │ [ ] Test vectors: FPGA == CPU                    │
│                    │ [ ] PCIe DMA loopback test                       │
│                    │ [ ] Timing closure check (synth)                 │
│                    │ [ ] Resource utilization check                   │
├────────────────────┼──────────────────────────────────────────────────┤
│ 7. Bridge          │ [ ] Python ↔ Rust roundtrip                      │
│                    │ [ ] C API test suite                             │
│                    │ [ ] Perl module test                             │
│                    │ [ ] FFI safety (no unwind)                       │
├────────────────────┼──────────────────────────────────────────────────┤
│ 8. Distributed     │ [ ] 2-node cluster test                          │
│                    │ [ ] Linear scaling test (N nodes = N× perf)      │
│                    │ [ ] Worker crash recovery                        │
│                    │ [ ] Master crash recovery                        │
├────────────────────┼──────────────────────────────────────────────────┤
│ 9. Web Dashboard   │ [ ] REST API integration test                    │
│                    │ [ ] WebSocket real-time test                     │
│                    │ [ ] Frontend E2E test (Playwright)               │
├────────────────────┼──────────────────────────────────────────────────┤
│ 10. Polish+Release │ [ ] All-platform regression                      │
│                    │ [ ] Performance regression (benchmark suite)     │
│                    │ [ ] Security audit (no hardcoded secrets)        │
└────────────────────┴──────────────────────────────────────────────────┘
```


## 13. VERSION ROADMAP

```
v0.1.0  ─── Phase 0  ─── Rust Core (existing)                  [DONE]
v0.2.0  ─── Phase 1  ─── Auto-Tier + SIMD                      [Month 2]
v0.3.0  ─── Phase 2  ─── GPU Boost (wgpu)                      [Month 4]
v0.4.0  ─── Phase 3  ─── JIT Turbo (Cranelift)                 [Month 5]
v0.5.0  ─── Phase 4  ─── Power Saver (RAPL+Governor)           [Month 6]
v0.6.0  ─── Phase 5  ─── Android Ready (Termux)                [Month 7]
v0.7.0  ─── Phase 6  ─── FPGA Power (Verilog + PCIe)           [Month 9]
v0.8.0  ─── Phase 7  ─── Polyglot (Python + Perl + C FFI)      [Month 10]
v0.9.0  ─── Phase 8  ─── Cluster Mode (Distributed)            [Month 11]
v0.10.0 ─── Phase 9  ─── Web Commander (Dashboard)             [Month 12]
v1.0.0  ─── Phase 10 ─── Universal Release                     [Month 13]
```


## 14. QUICK-START BY PHASE

```bash
# === PHASE 0 (CURRENT) ===
git checkout main
cargo run --release -- dictionary hashes.txt wordlist.txt
cargo test

# === PHASE 1: Auto-Tier ===
git checkout phase-1-auto-tier
cargo run --release -- --detect          # Show hardware info
cargo run --release -- --tier low        # Force low-end mode
cargo test --features simd-avx2
cargo test --features simd-neon64

# === PHASE 2: GPU ===
git checkout phase-2-gpu
cargo run --release -- --gpu benchmark md5
cargo run --release -- --gpu dictionary hashes.txt wordlist.txt

# === PHASE 3: JIT ===
git checkout phase-3-jit
cargo bench -- jit                       # JIT vs interpreter
cargo run --release -- mask "?l?l?d?d" --jit

# === PHASE 4: Power ===
git checkout phase-4-power
cargo run --release -- --power-budget 65W dictionary hashes.txt words.txt
cargo run --release -- --battery         # Laptop mode

# === PHASE 5: Android ===
git checkout phase-5-android
cargo build --target aarch64-linux-android --features tier-mid
# Push to phone, run in Termux

# === PHASE 6: FPGA ===
git checkout phase-6-fpga
cd engines/engine-fpga
vivado -mode batch -source scripts/build.tcl
cargo run --release -- --fpga benchmark md5

# === PHASE 7: Bridge ===
git checkout phase-7-bridge
cd engines/engine-bridge/python
pip install .
python -c "import pwdcrack; print(pwdcrack.detect_tier())"

# === PHASE 8: Distributed ===
git checkout phase-8-distributed
cargo run --release --bin master -- --bind 0.0.0.0:5555 &
cargo run --release --bin worker -- --connect 192.168.1.100:5555

# === PHASE 9: Web ===
git checkout phase-9-web
cargo run --release -- web --port 8080
# Open http://localhost:8080

# === PHASE 10: v1.0.0 ===
git checkout main
./scripts/build-all.sh
./scripts/test-all.sh
./scripts/package.sh
```
