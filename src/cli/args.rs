use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "pwdcrack",
    about = "🏴 Universal password cracker — CPU / GPU / FPGA / Distributed / Web dashboard",
    long_about = "\
pwdcrack is a high-performance password hash cracker written in Rust.

It supports 21+ hash formats (MD5, SHA family, NTLM, bcrypt, Argon2,
scrypt, Unix crypt variants, and more) with three attack modes:
dictionary (+ rule-based mangling), combinator, and brute-force/mask.

Hardware engines (optional):
  SIMD  → auto-detected (SSE2, AVX2, AVX-512, NEON, SVE)
  GPU   → Vulkan via wgpu
  FPGA  → PCIe DMA
  JIT   → Cranelift JIT for mask/rule acceleration
  Power → RAPL / AMD hwmon power budgeting
  Distributed → multi-node TCP cluster
  Web   → real-time dashboard with WebSocket stats",
    version = "0.1.0",
    author = "pwdcrack team",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short = 'T', long, global = true, help = "Number of threads (default: all available)")]
    pub threads: Option<usize>,

    #[arg(short = 'p', long, global = true, default_value = "pwdcrack.pot", help = "Potfile path for save/load cracked hashes")]
    pub potfile: String,

    #[arg(short = 'q', long, global = true, help = "Quiet mode — no progress bar, minimal output")]
    pub quiet: bool,

    #[arg(long, global = true, default_value = "0", help = "Power budget in watts (0 = unlimited). Requires engine-power feature")]
    pub power_budget: f64,

    #[arg(long, global = true, help = "Android battery-safe mode (auto-pause on low battery / thermal)")]
    pub battery_safe: bool,

    #[arg(short = 'o', long, global = true, help = "Save cracked results to a file instead of stdout")]
    pub output: Option<String>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text, help = "Output format: text, json, csv")]
    pub format: OutputFormat,

    #[arg(long, global = true, help = "Skip hashes already present in potfile")]
    pub skip_cracked: bool,

    #[arg(long, global = true, help = "Enable GPU engine (requires engine-gpu feature)")]
    pub gpu: bool,

    #[arg(long, global = true, help = "Enable distributed mode (requires engine-distributed feature)")]
    pub distributed: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Dictionary attack — tries each word from a wordlist, with optional rule-based mangling
    ///
    /// Reads a wordlist file line by line and hashes each word using the
    /// detected hash type. If a rules file is given, each word is also
    /// mangled with every rule before hashing.
    Dictionary {
        /// Hash file — one hash per line, or user:hash format (e.g. admin:5d41402abc...)
        hash_file: String,
        /// Wordlist file — one candidate per line
        wordlist: String,
        /// Rules file — John/Hashcat-compatible rule file
        #[arg(short = 'r', long)]
        rules: Option<String>,
        /// Only run this many candidates (for testing)
        #[arg(long)]
        limit: Option<u64>,
        /// Save / resume session file
        #[arg(long)]
        session: Option<String>,
    },

    /// Brute-force attack — enumerate all combinations of a mask pattern
    ///
    /// Mask placeholders:
    ///   ?l  → lowercase (a-z)
    ///   ?u  → uppercase (A-Z)
    ///   ?d  → digit (0-9)
    ///   ?s  → special (!@#$...)
    ///   ?a  → all printable ASCII
    ///   ?h  → lowercase hex (0-9 a-f)
    ///   ?H  → uppercase hex (0-9 A-F)
    ///   ?b  → all bytes 0x00-0xff
    ///   ?1-?4 → custom charsets (via -1/-2/-3/-4)
    ///
    /// Examples:
    ///   ?l?l?l?l?l?l?l?l   →  8 lowercase letters
    ///   ?u?l?l?l?d?d?d?d   →  Capital + 3 lower + 4 digits
    ///   ?d?d?d?d?d?d        →  6-digit PIN
    ///   ?1?1?1?2?2?d?d?d    →  custom C1 + C2 + 3 digits
    BruteForce {
        /// Hash file
        hash_file: String,
        /// Mask pattern (see help for placeholders)
        mask: String,
        #[arg(short = '1', long, help = "Custom charset for ?1 placeholder")]
        charset1: Option<String>,
        #[arg(short = '2', long, help = "Custom charset for ?2 placeholder")]
        charset2: Option<String>,
        #[arg(short = '3', long, help = "Custom charset for ?3 placeholder")]
        charset3: Option<String>,
        #[arg(short = '4', long, help = "Custom charset for ?4 placeholder")]
        charset4: Option<String>,
        /// Minimum password length (increment mask length)
        #[arg(long, default_value_t = 1)]
        min_length: usize,
        /// Maximum password length
        #[arg(long)]
        max_length: Option<usize>,
        /// Only run this many candidates (for testing)
        #[arg(long)]
        limit: Option<u64>,
        /// Save / resume session file
        #[arg(long)]
        session: Option<String>,
    },

    /// Combinator attack — concatenates words from two wordlists
    ///
    /// Every word from wordlist1 is concatenated with every word from
    /// wordlist2 (wordlist1 + wordlist2). The result is hashed and
    /// compared against the target hashes.
    Combinator {
        /// Hash file
        hash_file: String,
        /// Left wordlist (first half of combined words)
        wordlist1: String,
        /// Right wordlist (second half)
        wordlist2: String,
        /// Only run this many combinations (for testing)
        #[arg(long)]
        limit: Option<u64>,
        /// Save / resume session file
        #[arg(long)]
        session: Option<String>,
    },

    /// Identify hash types in a file — shows count per type
    Identify {
        /// Hash file to analyze
        hash_file: String,
        /// Show full details for each hash (type, length, etc.)
        #[arg(short = 'v', long)]
        verbose: bool,
    },

    /// Compute hash of a password (useful for testing / verification)
    Hash {
        /// Password to hash
        password: String,
        /// Hash type (e.g. md5, sha256, ntlm, bcrypt). Default: auto-detect from hash format
        #[arg(short = 't', long, default_value = "md5")]
        hash_type: String,
    },

    /// Verify a password against a hash
    Verify {
        /// Hash string
        hash: String,
        /// Password to test
        password: String,
    },

    /// List all supported hash types with details
    List {
        /// Show all details (bit length, example hash, etc.)
        #[arg(short = 'v', long)]
        verbose: bool,
        /// Filter by search term (e.g. "sha", "bcrypt", "unix")
        filter: Option<String>,
    },

    /// Dry-run: generate mask candidates without cracking
    Mask {
        /// Mask pattern (same placeholders as brute-force)
        mask: String,
        #[arg(short = '1', long)]
        charset1: Option<String>,
        #[arg(short = '2', long)]
        charset2: Option<String>,
        #[arg(short = '3', long)]
        charset3: Option<String>,
        #[arg(short = '4', long)]
        charset4: Option<String>,
        /// Number of candidates to show
        #[arg(long, default_value_t = 20)]
        count: usize,
        /// Start offset
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },

    /// Benchmark hash verification throughput
    Benchmark {
        /// Hash type to benchmark (e.g. md5, sha256, ntlm, bcrypt, all)
        #[arg(default_value = "all")]
        hash_type: String,
        /// Number of iterations per cracker
        #[arg(long, default_value_t = 100_000)]
        iterations: u64,
    },

    /// Show cracked passwords from potfile
    Show {
        /// Potfile path (default: pwdcrack.pot)
        #[arg(default_value = "pwdcrack.pot")]
        potfile: String,
        /// Show hash type alongside password
        #[arg(short = 't', long)]
        show_type: bool,
        /// Show only statistics (count summary)
        #[arg(short = 's', long)]
        stats: bool,
    },

    /// Suggest the best attack approach for a hash type
    Suggest {
        /// Hash string to analyze
        hash: String,
    },
}
