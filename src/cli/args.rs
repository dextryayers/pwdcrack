use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "pwdcrack",
    display_name = "pwdcrack",
    version = "1.2.0",
    author = "Hanif Abdur - AniipID",
    about = "Universal password hash recovery toolkit: 350+ hash types, CPU/GPU acceleration, low-end to HPC",
    long_about = "\
Professional-grade hash recovery suite supporting 350+ hash types across all major
algorithm families: MDx, SHA-1/2/3, BLAKE2/3, RIPEMD, Whirlpool, Streebog,
GOST, Tiger, JH, Skein, Shabal, Snefru, SM3, HAS-160, Argon2, bcrypt, and more.

Cracking engines: dictionary (rule-based mangling), brute-force mask, combinator,
PRINCE, toggle-case, substitution, and hybrid attacks with auto-tier performance.

Optimized for all hardware tiers, from embedded/low-end devices to HPC clusters,
with auto-detected SIMD (SSE2/AVX2/AVX-512/NEON/SVE) and GPU acceleration.",
    after_help = "\
Examples:
  pwdcrack dictionary hashes.txt rockyou.txt -r best64.rule
  pwdcrack brute-force hashes.txt ?u?l?l?l?l?d?d
  pwdcrack identify hashes.txt -v
  pwdcrack show -t

Run 'pwdcrack <COMMAND> --help' for the options of a specific command.
Copyright (c) 2026 Hanif Abdur - AniipID",
    help_template = "\
{name} v{version}

{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    // ---- Performance ----

    #[arg(short = 'T', long, global = true, help_heading = "Performance", help = "Number of threads (default: all available)")]
    pub threads: Option<usize>,

    #[arg(long, global = true, value_enum, help_heading = "Performance", help = "Force a hardware tier instead of auto-detection")]
    pub tier: Option<Tier>,

    #[arg(long, global = true, help_heading = "Performance", help = "Low-memory mode: reduce buffer sizes for low-end/embedded devices")]
    pub low_mem: bool,

    #[arg(long = "disable-simd", global = true, help_heading = "Performance", help = "Disable SIMD auto-detection")]
    pub disable_simd: bool,

    // ---- Engines ----

    #[arg(long, global = true, help_heading = "Engines", help = "Enable GPU acceleration (requires engine-gpu feature)")]
    pub gpu: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable FPGA acceleration (requires engine-fpga feature)")]
    pub fpga: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable Apple Metal acceleration (requires engine-metal feature)")]
    pub metal: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable Google TPU acceleration (requires engine-tpu feature)")]
    pub tpu: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable hybrid CPU+GPU+FPGA scheduler (requires engine-hybrid feature)")]
    pub hybrid: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable tensor/ONNX acceleration (requires engine-tensor feature)")]
    pub tensor: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable Intel XPU/oneAPI (requires engine-xpu feature)")]
    pub xpu: bool,

    #[arg(long, global = true, help_heading = "Engines", help = "Enable distributed mode (requires engine-distributed feature)")]
    pub distributed: bool,

    /// Address the cluster master listens on.
    ///
    /// Defaults to 127.0.0.1. Any other address is reachable from the network,
    /// so it is refused unless it is passed explicitly, and it is refused again
    /// without `--token`. See `engine_distributed::netpolicy`.
    #[arg(long, global = true, value_name = "ADDR", help_heading = "Engines", help = "Address for the cluster master to listen on (default 127.0.0.1:5555). A non-loopback address must be given explicitly and requires --token")]
    pub bind: Option<String>,

    /// Address of the master, for a worker node.
    #[arg(long, global = true, value_name = "ADDR", help_heading = "Engines", help = "Master address for a worker node")]
    pub master: Option<String>,

    /// Shared secret for cluster authentication.
    ///
    /// Can also come from PWDCRACK_CLUSTER_TOKEN, which keeps it out of the
    /// process list where every other user on the machine can read it.
    #[arg(long, global = true, value_name = "TOKEN", help_heading = "Engines", help = "Shared token for cluster authentication. Prefer the PWDCRACK_CLUSTER_TOKEN environment variable, which keeps it out of the process list")]
    pub token: Option<String>,

    /// Confirms a non-loopback bind address.
    ///
    /// Kept separate from `--bind` so that exposing a port is a second, distinct
    /// act rather than a side effect of naming an address.
    #[arg(long, global = true, help_heading = "Engines", help = "Confirm that --bind may use a non-loopback address. Required in addition to --token")]
    pub allow_exposed_bind: bool,

    /// Directory a worker will read wordlists from.
    ///
    /// Repeatable. A worker refuses every dictionary unit unless at least one is
    /// given: the master chooses which file inside these directories is opened,
    /// and cannot widen the grant. Without this flag a worker ignores dictionary
    /// work entirely rather than opening whatever path the master names.
    #[arg(long, global = true, value_name = "DIR", help_heading = "Engines", help = "Directory a worker may read wordlists from. Repeatable. Without it a worker refuses all dictionary work rather than opening any path the master names")]
    pub wordlist_dir: Vec<String>,

    // ---- Power & monitoring ----

    #[arg(long, global = true, default_value = "0", help_heading = "Power & monitoring", help = "Power budget in watts (0 = unlimited; requires engine-power feature)")]
    pub power_budget: f64,

    #[arg(long, global = true, help_heading = "Power & monitoring", help = "Android battery-safe mode (auto-pause on low battery / thermal)")]
    pub battery_safe: bool,

    #[arg(long, global = true, help_heading = "Power & monitoring", help = "Enable hardware monitoring (temperature, power, utilization)")]
    pub hwmon: bool,

    // ---- Output ----

    #[arg(short = 'o', long, global = true, help_heading = "Output", help = "Save cracked results to a file instead of stdout")]
    pub output: Option<String>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text, help_heading = "Output", help = "Output format for cracked results")]
    pub format: OutputFormat,

    #[arg(short = 'q', long, global = true, help_heading = "Output", help = "Quiet mode: no progress bar, minimal output")]
    pub quiet: bool,

    #[arg(long, global = true, help_heading = "Output", help = "Disable colored output")]
    pub no_color: bool,

    #[arg(long, global = true, help_heading = "Output", help = "Enable verbose logging")]
    pub verbose: bool,

    // ---- Session & state ----

    #[arg(short = 'p', long, global = true, default_value = "pwdcrack.pot", help_heading = "Session & state", help = "Potfile path for save/load cracked hashes")]
    pub potfile: String,

    // Long form only, no short flag.
    //
    // `-r` is already taken by `Dictionary.rules` and by the `Rules` subcommand
    // positional. Giving this global flag the same short form made clap abort
    // at startup in debug builds with:
    //   "Short option names must be unique for each argument,
    //    but '-r' is in use by both 'rules' and 'rules_file'"
    // which happens in `_build_self` before any subcommand is even reached.
    // Removing the short form keeps every documented invocation working, since
    // every documented form of this flag is `--rules-file`.
    #[arg(long, global = true, help_heading = "Session & state", help = "Global rules file for all applicable attacks")]
    pub rules_file: Option<String>,

    #[arg(long, global = true, help_heading = "Session & state", help = "Skip hashes that are already present in the potfile")]
    pub skip_cracked: bool,

    #[arg(long, global = true, help_heading = "Session & state", help = "Batch mode: suppress interactive prompts")]
    pub batch: bool,

    #[arg(long, global = true, help_heading = "Session & state", help = "Resume from last session checkpoint")]
    pub resume: bool,
}

impl Cli {
    /// Parse command-line arguments.
    ///
    /// Same behavior as `Cli::parse()`, with `-h/--help` and `-V/--version`
    /// shown under the "General" help group instead of the default section.
    pub fn parse_args() -> Self {
        let mut cmd = <Self as clap::CommandFactory>::command();
        cmd.build();
        let cmd = cmd
            .mut_arg("help", |a| a.help_heading("General"))
            .mut_arg("version", |a| a.help_heading("General"));
        <Self as clap::FromArgMatches>::from_arg_matches(&cmd.get_matches())
            .unwrap_or_else(|err| err.exit())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Low,
    Mid,
    High,
    Auto,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Dictionary attack: wordlist + rule-based mangling
    ///
    /// Reads a wordlist file line by line, applies optional hashcat/John
    /// rules to mangle each word, and compares against target hashes.
    ///
    /// Example: pwdcrack dictionary hashes.txt rockyou.txt -r rules.rule
    Dictionary {
        /// Hash file (one hash per line, or user:hash format, e.g. admin:5d41402abc...)
        hash_file: String,
        /// Wordlist file (one candidate per line)
        wordlist: String,
        /// Rules file (John/Hashcat-compatible syntax)
        #[arg(short = 'r', long)]
        rules: Option<String>,
        /// Only run this many candidates (for testing)
        #[arg(long)]
        limit: Option<u64>,
        /// Save / resume session file
        #[arg(long)]
        session: Option<String>,
    },

    /// Brute-force / Mask attack: enumerate mask patterns
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

    /// Combinator attack: concatenate pairs from two wordlists
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

    /// Identify hash types: scan a file and classify hashes
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

    /// Hash a password: compute a hash for testing
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

    /// Dry-run mask: preview mask candidates
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

    /// Benchmark: measure hash throughput
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

    /// PRINCE attack: probability-based word generation
    ///
    /// Uses the PRINCE algorithm to generate password candidates
    /// from a wordlist based on probability. Efficient for targeted
    /// attacks where the password follows common patterns.
    ///
    /// Example: pwdcrack prince hashes.txt wordlist.txt
    Prince {
        /// Hash file containing target hashes
        hash_file: String,
        /// Wordlist for PRINCE candidate generation
        wordlist: String,
        /// Minimum password length
        #[arg(long, default_value_t = 1)]
        min_length: usize,
        /// Maximum password length
        #[arg(long, default_value_t = 32)]
        max_length: usize,
        /// Only test this many candidates
        #[arg(long)]
        limit: Option<u64>,
        /// Save/resume session
        #[arg(long)]
        session: Option<String>,
    },

    /// Toggle-case attack: case variants of dictionary words
    ///
    /// For each word in the list, tries all case permutations
    /// at toggle points. Effective against simple capitalization.
    ///
    /// Example: pwdcrack toggle-case hashes.txt wordlist.txt
    ToggleCase {
        /// Hash file containing target hashes
        hash_file: String,
        /// Base wordlist
        wordlist: String,
        /// Maximum toggle points per word
        #[arg(long, default_value_t = 4)]
        max_toggle: usize,
        /// Only test this many candidates per word
        #[arg(long)]
        limit: Option<u64>,
    },

    /// Substitution attack: leet/character substitution
    ///
    /// Applies common character substitutions to dictionary words
    /// (e.g. a→@, e→3, o→0, s→$). Multiple substitution sets available.
    ///
    /// Example: pwdcrack substitute hashes.txt wordlist.txt
    Substitute {
        /// Hash file containing target hashes
        hash_file: String,
        /// Base wordlist
        wordlist: String,
        /// Substitution level 1-3 (default: 2)
        #[arg(long, default_value_t = 2)]
        level: u8,
        /// Only test this many candidates per word
        #[arg(long)]
        limit: Option<u64>,
    },

    /// Apply rules to a wordlist: dry-run rule engine
    ///
    /// Reads a wordlist and rule file, applies the rules, and
    /// writes the resulting candidates. Useful for testing rules.
    ///
    /// Example: pwdcrack rules rockyou.txt rules.rule -o output.txt
    Rules {
        /// Input wordlist
        wordlist: String,
        /// Rules file (John/Hashcat syntax)
        rules_file: String,
        /// Output file for generated candidates
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Only generate this many candidates
        #[arg(long)]
        limit: Option<u64>,
    },

    /// Show potfile statistics: breakdown, charts, trends
    ///
    /// Analyzes the potfile and shows cracking statistics:
    /// cracked vs remaining, hash type breakdown, timing info.
    ///
    /// Example: pwdcrack stats, pwdcrack stats -v
    Stats {
        #[arg(default_value = "pwdcrack.pot", help = "Potfile path to analyze")]
        potfile: String,
        #[arg(short = 'v', long, help = "Show detailed statistics")]
        verbose: bool,
        #[arg(long, help = "Show breakdown by hash length/complexity")]
        by_complexity: bool,
    },

    /// Expand a mask pattern: show all matching candidates
    ///
    /// Fully expands a mask pattern to show all possible passwords.
    /// WARNING: large keyspaces may produce massive output.
    ///
    /// Example: pwdcrack expand ?d?d?d -l 10
    Expand {
        /// Mask pattern to expand (max 4 chars for safety)
        mask: String,
        #[arg(short = '1', long, help = "Custom charset for ?1")]
        charset1: Option<String>,
        #[arg(short = '2', long, help = "Custom charset for ?2")]
        charset2: Option<String>,
        #[arg(short = '3', long, help = "Custom charset for ?3")]
        charset3: Option<String>,
        #[arg(short = '4', long, help = "Custom charset for ?4")]
        charset4: Option<String>,
        /// Maximum candidates to show
        #[arg(long, default_value_t = 10000)]
        limit: u64,
    },

    /// Check/validate a hash file: syntax, format, uniqueness
    ///
    /// Validates all hashes in a file for correct format and length.
    /// Reports invalid entries and duplicate detection.
    ///
    /// Example: pwdcrack check hashes.txt
    Check {
        /// Hash file to validate
        hash_file: String,
        #[arg(short = 'v', long, help = "Show details for each hash")]
        verbose: bool,
        #[arg(long, help = "Remove invalid hashes and write cleaned file")]
        clean: bool,
    },
}
