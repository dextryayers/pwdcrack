use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "pwdcrack", about = "High-performance password cracker in Rust", version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Number of threads to use (default: all available)
    #[arg(short = 'T', long, global = true)]
    pub threads: Option<usize>,

    /// Potfile to save/load cracked hashes
    #[arg(short = 'p', long, global = true, default_value = "pwdcrack.pot")]
    pub potfile: String,

    /// Show cracked passwords at the end
    #[arg(short = 's', long, global = true)]
    pub show: bool,

    /// Left/Right separator for user:hash format
    #[arg(long, global = true, default_value = ":")]
    pub separator: String,

    /// Quiet mode (no progress bar)
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Dictionary attack with optional rules
    Dictionary {
        /// Hash file (one hash per line, or user:hash format)
        hash_file: String,
        /// Wordlist file
        wordlist: String,
        /// Rules file (John/Hashcat format)
        #[arg(short = 'r', long)]
        rules: Option<String>,
        /// Skip words with same length as the hash (likely already plaintext)
        #[arg(long)]
        skip_self: bool,
    },
    /// Brute-force / Mask attack
    BruteForce {
        /// Hash file
        hash_file: String,
        /// Mask pattern (?l, ?u, ?d, ?s, ?a, ?h, ?H, ?b)
        /// Example: ?l?l?l?d?d for 3 lowercase + 2 digits
        mask: String,
        /// Custom charset for ?1-?4
        #[arg(short = '1', long)]
        charset1: Option<String>,
        #[arg(short = '2', long)]
        charset2: Option<String>,
        #[arg(short = '3', long)]
        charset3: Option<String>,
        #[arg(short = '4', long)]
        charset4: Option<String>,
    },
    /// Combinator attack (combine words from two wordlists)
    Combinator {
        /// Hash file
        hash_file: String,
        /// Left wordlist
        wordlist1: String,
        /// Right wordlist
        wordlist2: String,
    },
    /// Identify hash types in a file
    Identify {
        /// Hash file to analyze
        hash_file: String,
    },
    /// Run benchmark
    Benchmark {
        /// Hash type to benchmark
        #[arg(default_value = "all")]
        hash_type: String,
    },
    /// Show cracked passwords from potfile
    Show {
        /// Potfile path
        #[arg(default_value = "pwdcrack.pot")]
        potfile: String,
        /// Also show hash type
        #[arg(short = 't', long)]
        show_type: bool,
    },
}
