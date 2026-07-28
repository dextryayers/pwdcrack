use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "pwdcrack",
    about = "🏴 Universal password cracker — CPU / GPU / FPGA / Distributed / Web",
    long_about = "\
pwdcrack — high-performance hash cracker written in Rust.

SUPPORTED HASHES
  MD5, SHA-1/224/256/384/512, SHA3-512, BLAKE2B-256/512,
  RIPEMD-160, NTLM, LM, bcrypt, Argon2i/d/id, scrypt,
  MD5Crypt, SHA256Crypt, SHA512Crypt, Unix DES/BF/BSDi

ATTACK MODES
  dictionary   wordlist + rule-based mangling (John/Hashcat rules)
  brute-force  mask-based enumeration with custom charsets
  combinator   concatenate words from two wordlists

HARDWARE ENGINES (optional features)
  SIMD   SSE2 / AVX2 / AVX-512 / NEON / SVE (auto-detected)
  GPU    Vulkan compute via wgpu
  FPGA   PCIe DMA acceleration
  JIT    Cranelift JIT for mask/rule speedup
  Power  RAPL / AMD hwmon power capping
  Dist   multi-node TCP cluster cracking
  Web    real-time dashboard + WebSocket stats",
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
    /// Dictionary attack — wordlist + rule-based mangling
    ///
    /// Reads a wordlist file line by line, applies optional hashcat/John
    /// rules to mangle each word, and compares against target hashes.
    ///
    /// Example: pwdcrack dictionary hashes.txt rockyou.txt -r rules.rule
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

    /// Brute-force / Mask attack — enumerate mask patterns
    ///
    /// Mask characters:
    ///   ?l lowercase     ?u uppercase     ?d digit
    ///   ?s specials      ?a all printable ?h hex lower
    ///   ?H hex upper     ?b all bytes     ?1-?4 custom
    ///
    /// Examples:
    ///   ?l?l?l?l?l?l?l?l   8 lowercase        (26⁸ combos)
    ///   ?u?l?l?l?d?d?d?d   Capital+3l+4d      (26⁴·10⁴)
    ///   ?d?d?d?d?d?d        6-digit PIN        (10⁶)
    ///   ?1?1?1?2?2?d?d?d    custom + digits
    ///
    ///   pwdcrack brute-force hashes.txt ?l?l?l?l?l?l
    ///   pwdcrack brute-force hashes.txt ?1?1?d?d?d -1 abcdef
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

    /// Combinator attack — concatenate pairs from two wordlists
    ///
    /// For every word A from wordlist1 and word B from wordlist2,
    /// hashes A+B and compares against targets. Produces N·M candidates.
    ///
    /// Example: pwdcrack combinator hashes.txt left.txt right.txt
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

    /// Identify hash types — scan a file and classify hashes
    ///
    /// Reads a hash file and detects each hash type based on format/length.
    /// Shows count per type with optional per-hash details.
    ///
    /// Examples: pwdcrack identify hashes.txt, pwdcrack identify hashes.txt -v
    Identify {
        hash_file: String,
        #[arg(short = 'v', long, help = "Show per-hash details (type, length, charset)")]
        verbose: bool,
    },

    /// Hash a password — compute a hash for testing
    ///
    /// Computes a hash for the given password using the specified algorithm.
    /// Useful for preparing test hashes or verifying format compatibility.
    ///
    /// Examples: pwdcrack hash mypassword -t sha256, pwdcrack hash mypassword -t ntlm
    Hash {
        password: String,
        #[arg(short = 't', long, default_value = "md5", help = "Hash algorithm: md5, sha1, sha256, sha512, sha3, ntlm, blake2b, ripemd160, ...")]
        hash_type: String,
    },

    /// Verify a password against a hash
    ///
    /// Checks whether the given password produces the given hash.
    /// Auto-detects hash type from the hash format/length.
    ///
    /// Example: pwdcrack verify 5d41402abc4b2a76b9719d911017c592 hello
    Verify {
        /// Target hash to verify against
        hash: String,
        /// Password to test
        password: String,
    },

    /// List supported hash types with details
    ///
    /// Shows all supported hash algorithms with bit length, category,
    /// and an example hash. Use -v for full details. Optionally filter by name.
    ///
    /// Examples: pwdcrack list, pwdcrack list sha, pwdcrack list -v
    List {
        #[arg(short = 'v', long, help = "Show full details (bits, example hash, category)")]
        verbose: bool,
        #[arg(help = "Optional filter term (e.g. sha, bcrypt, unix, nt)")]
        filter: Option<String>,
    },

    /// Dry-run mask — preview mask candidates
    ///
    /// Generates sample candidates for a mask pattern without actually
    /// cracking. Useful for testing mask syntax and counting keyspace.
    ///
    /// Examples: pwdcrack mask ?l?l?l?l?l?l, pwdcrack mask ?d?d?d?d -1 abc --count 5
    Mask {
        mask: String,
        #[arg(short = '1', long, help = "Custom charset for ?1 placeholder")]
        charset1: Option<String>,
        #[arg(short = '2', long, help = "Custom charset for ?2 placeholder")]
        charset2: Option<String>,
        #[arg(short = '3', long, help = "Custom charset for ?3 placeholder")]
        charset3: Option<String>,
        #[arg(short = '4', long, help = "Custom charset for ?4 placeholder")]
        charset4: Option<String>,
        #[arg(long, default_value_t = 20, help = "Number of candidates to show (max 100)")]
        count: usize,
        #[arg(long, default_value_t = 0, help = "Start index offset into keyspace")]
        offset: u64,
    },

    /// Benchmark — measure hash throughput
    ///
    /// Runs a benchmark for one or all hash types and reports
    /// hashes-per-second. Useful for comparing hardware performance.
    ///
    /// Examples: pwdcrack benchmark md5 --iterations 500000, pwdcrack benchmark all
    Benchmark {
        #[arg(default_value = "all", help = "Hash type to benchmark (or 'all' for all types)")]
        hash_type: String,
        #[arg(long, default_value_t = 100_000, help = "Hash iterations per cracker")]
        iterations: u64,
    },

    /// Show cracked passwords from potfile
    ///
    /// Reads the potfile and displays recovered passwords.
    /// Use -t to show hash types, -s for a summary count.
    ///
    /// Examples: pwdcrack show, pwdcrack show -t, pwdcrack show -s
    Show {
        #[arg(default_value = "pwdcrack.pot", help = "Potfile path to read")]
        potfile: String,
        #[arg(short = 't', long, help = "Show hash type alongside password")]
        show_type: bool,
        #[arg(short = 's', long, help = "Show only statistics (count, types)")]
        stats: bool,
    },

    /// Suggest attack strategy for a hash type
    ///
    /// Analyzes the given hash and suggests the most effective
    /// cracking approach (mask pattern, wordlist, rules, etc.).
    ///
    /// Examples: pwdcrack suggest '$2y$10$...', pwdcrack suggest '5d41402abc4b2a76b9719d911017c592'
    Suggest {
        #[arg(help = "Hash string to analyze for attack strategy")]
        hash: String,
    },
}
