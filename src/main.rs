mod cli;

use clap::Parser;
use cli::{Cli, args::{Commands, OutputFormat}};
use pwdcrack::hash::{HashCracker, HashEntry, HashType};
use pwdcrack::hash::detector::Detector;
use pwdcrack::attack::CrackResult;
use pwdcrack::potfile::Potfile;

#[cfg(feature = "engine-power")]
use std::sync::Arc;

fn main() {
    env_logger::init();
    let args = Cli::parse();
    let detector = Detector::new();
    let threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();

    #[cfg(feature = "engine-power")]
    let _power_mgr = if args.power_budget > 0.0 || args.battery_safe {
        let pm = Arc::new(engine_power::PowerManager::new(args.power_budget));
        if args.battery_safe {
            let _ = std::thread::spawn({
                let pm = Arc::clone(&pm);
                move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    pm.sample();
                    let workload = pm.current_workload();
                    engine_power::governor::apply_workload_policy(workload);
                }
            });
            log::info!("Battery-safe mode active");
        }
        if args.power_budget > 0.0 {
            log::info!("Power budget: {}W", args.power_budget);
        }
        Some(pm)
    } else {
        None
    };

    #[cfg(feature = "engine-android")]
    let mut _android_engine = {
        let mut ae = engine_android::AndroidEngine::new();
        ae.init();
        log::info!("Android: {}", ae.info());
        if ae.should_throttle() {
            log::warn!("Android throttling: {:?}", ae.throttle_reason());
        }
        ae
    };

    let _cmd_result = match &args.command {
        Commands::Identify { hash_file, verbose } => cmd_identify(&detector, hash_file, *verbose),
        Commands::Dictionary { hash_file, wordlist, rules, limit, session } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::MemoryBound);
            }
            cmd_dictionary(&detector, hash_file, wordlist, rules.as_deref(), threads, &args, *limit, session.as_deref())
        }
        Commands::BruteForce { hash_file, mask, charset1, charset2, charset3, charset4, min_length, max_length, limit, session } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::ComputeBound);
            }
            cmd_bruteforce(&detector, hash_file, mask, &[charset1.clone(), charset2.clone(), charset3.clone(), charset4.clone()], threads, &args, *min_length, *max_length, *limit, session.as_deref())
        }
        Commands::Combinator { hash_file, wordlist1, wordlist2, limit, session } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::Mixed);
            }
            cmd_combinator(&detector, hash_file, wordlist1, wordlist2, threads, &args, *limit, session.as_deref())
        }
        Commands::Benchmark { hash_type, iterations } => cmd_benchmark(&detector, hash_type, threads, args.quiet, *iterations),
        Commands::Show { potfile, show_type, stats } => cmd_show(potfile, *show_type, *stats),
        Commands::Hash { password, hash_type } => cmd_hash(password, hash_type),
        Commands::Verify { hash, password } => cmd_verify(&detector, hash, password),
        Commands::List { verbose, filter } => cmd_list(*verbose, filter.as_deref()),
        Commands::Mask { mask, charset1, charset2, charset3, charset4, count, offset } => cmd_mask(mask, &[charset1.clone(), charset2.clone(), charset3.clone(), charset4.clone()], *count, *offset),
        Commands::Suggest { hash } => cmd_suggest(&detector, hash),
    };

    #[cfg(feature = "engine-android")]
    _android_engine.shutdown();
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn load_hashes(detector: &Detector, path: &str) -> Vec<(Box<dyn HashCracker>, HashEntry)> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("[!] Failed to read hash file: {}", e);
        std::process::exit(1);
    });

    let mut results = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        match detector.detect(trimmed) {
            Some((cracker, entry)) => results.push((cracker, entry)),
            None => eprintln!("[!] Unknown hash format: {}", trimmed),
        }
    }

    if results.is_empty() {
        eprintln!("[!] No valid hashes found in {}", path);
        std::process::exit(1);
    }
    results
}

fn filter_uncracked(args: &Cli, hashes: &mut Vec<HashEntry>) {
    if !args.skip_cracked { return; }
    let potfile = Potfile::new(&args.potfile);
    let cracked_map: std::collections::HashSet<String> = potfile.entries()
        .into_iter()
        .map(|(h, _)| h)
        .collect();
    hashes.retain(|h| !cracked_map.contains(&h.raw));
}

fn emit_results(results: &[CrackResult], args: &Cli, potfile: &Potfile) {
    if results.is_empty() {
        eprintln!("[-] No passwords cracked.");
        return;
    }

    match args.format {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = results.iter().map(|r| {
                serde_json::json!({
                    "hash": r.original,
                    "type": r.hash_type,
                    "password": r.password,
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        OutputFormat::Csv => {
            println!("hash,type,password");
            for r in results {
                let pw = r.password.as_deref().unwrap_or("");
                println!("{},{},{}", r.original, r.hash_type, pw);
            }
        }
        OutputFormat::Text => {
            println!("\nCracked passwords:");
            println!("{:-<60}", "");
            for r in results {
                if let Some(ref pw) = r.password {
                    println!("  {}  →  {}  [{}]", r.original, pw, r.hash_type);
                }
            }
        }
    }

    // Always save to potfile
    for r in results {
        if let Some(ref pw) = r.password {
            potfile.save(&r.original, pw);
        }
    }

    // Also write output file if requested
    if let Some(ref path) = args.output {
        let content: String = match args.format {
            OutputFormat::Text => results.iter()
                .filter_map(|r| r.password.as_ref().map(|pw| format!("{}:{}\n", r.original, pw)))
                .collect(),
            OutputFormat::Json => {
                let json: Vec<serde_json::Value> = results.iter().map(|r| {
                    serde_json::json!({"hash": r.original, "type": r.hash_type, "password": r.password})
                }).collect();
                serde_json::to_string_pretty(&json).unwrap()
            }
            OutputFormat::Csv => {
                let mut s = String::from("hash,type,password\n");
                for r in results {
                    let pw = r.password.as_deref().unwrap_or("");
                    s.push_str(&format!("{},{},{}\n", r.original, r.hash_type, pw));
                }
                s
            }
        };
        std::fs::write(path, content).unwrap_or_else(|e| {
            eprintln!("[!] Failed to write output file: {}", e);
        });
    }
}

// ── Commands ─────────────────────────────────────────────────────────────

fn cmd_identify(detector: &Detector, path: &str, verbose: bool) {
    let results = detector.identify(path);
    if results.is_empty() {
        eprintln!("[!] No hashes found in {}", path);
        return;
    }
    println!("Hash identification for {}:", path);
    println!("{:-<60}", "");

    if verbose {
        for (i, (hash, ht)) in results.iter().enumerate() {
            println!("  {:<4} {:20} {:40}", i + 1, ht.name(), hash);
        }
        println!("{:-<60}", "");
    } else {
        let mut by_type: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();
        for (hash, ht) in &results {
            let e = by_type.entry(ht.name().to_string()).or_insert((0usize, 0usize));
            (*e).0 += 1;
            (*e).1 = (*e).1.max(hash.len());
        }
        for (name, (count, max_len)) in &by_type {
            println!("  {:20} : {:>6} hashes  (max length: {})", name, count, max_len);
        }
        println!("{:-<60}", "");
    }
    println!("  Total: {} hashes", results.len());
}

fn cmd_dictionary(detector: &Detector, hash_file: &str, wordlist: &str, rules: Option<&str>, threads: usize, args: &Cli, _limit: Option<u64>, _session: Option<&str>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked (use --skip-cracked to skip, or remove potfile)");
        return;
    }

    let cracker = &loaded[0].0;

    eprintln!("[*] Dictionary attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Wordlist  : {}", wordlist);
    if let Some(r) = rules {
        eprintln!("[*] Rules     : {}", r);
    }
    eprintln!("[*] Threads   : {}", threads);

    let results = pwdcrack::attack::dictionary::run_dictionary(
        &mut hashes, cracker.as_ref(), wordlist, rules, threads, args.quiet,
    );

    emit_results(&results, args, &potfile);
}

fn cmd_bruteforce(detector: &Detector, hash_file: &str, mask: &str, charsets: &[Option<String>], threads: usize, args: &Cli, _min_length: usize, _max_length: Option<usize>, _limit: Option<u64>, _session: Option<&str>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked");
        return;
    }

    let cracker = &loaded[0].0;

    eprintln!("[*] Brute-force attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Mask      : {}", mask);
    eprintln!("[*] Threads   : {}", threads);

    let results = pwdcrack::attack::brute::run_bruteforce(
        &mut hashes, cracker.as_ref(), mask, charsets, threads, args.quiet,
    );

    emit_results(&results, args, &potfile);
}

fn cmd_combinator(detector: &Detector, hash_file: &str, wl1: &str, wl2: &str, threads: usize, args: &Cli, _limit: Option<u64>, _session: Option<&str>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked");
        return;
    }

    let cracker = &loaded[0].0;

    eprintln!("[*] Combinator attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Wordlist1 : {}", wl1);
    eprintln!("[*] Wordlist2 : {}", wl2);
    eprintln!("[*] Threads   : {}", threads);

    let results = pwdcrack::attack::combinator::run_combinator(
        &mut hashes, cracker.as_ref(), wl1, wl2, threads, args.quiet,
    );

    emit_results(&results, args, &potfile);
}

fn cmd_benchmark(detector: &Detector, hash_type: &str, threads: usize, _quiet: bool, iterations: u64) {
    use std::time::Instant;

    let crackers = detector.crackers();
    let to_bench: Vec<&dyn HashCracker> = if hash_type == "all" {
        crackers.iter().map(|b| b.as_ref()).collect()
    } else {
        let mut found = Vec::new();
        for c in crackers.iter() {
            if c.name().to_lowercase().contains(&hash_type.to_lowercase()) {
                found.push(c.as_ref());
            }
        }
        if found.is_empty() {
            eprintln!("[!] Unknown hash type: {}", hash_type);
            eprintln!("    Run 'pwdcrack list' to see all supported types");
            return;
        }
        found
    };

    let iterations = iterations.max(100);

    println!("Benchmark ({} threads):", threads);
    println!("{:=<60}", "");
    println!("{:<20} {:>15} {:>15}", "Algorithm", "Speed", "Time/hash");
    println!("{:-<60}", "");

    for cracker in &to_bench {
        let test_pass = "benchmark_test_password123!";
        let test_hash = generate_test_hash(*cracker, test_pass);

        let entry = HashEntry {
            raw: test_hash,
            hash_type: cracker.hash_type(),
            hash_bytes: Vec::new(),
            salt: None,
            username: None,
            cracked: false,
            password: None,
        };

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = cracker.verify(test_pass, &entry);
        }
        let elapsed = start.elapsed();
        let per_sec = iterations as f64 / elapsed.as_secs_f64();
        let per_hash_ns = elapsed.as_nanos() as f64 / iterations as f64;

        let speed_str = if per_sec > 1_000_000.0 {
            format!("{:>8.2} M/s", per_sec / 1_000_000.0)
        } else if per_sec > 1_000.0 {
            format!("{:>8.2} K/s", per_sec / 1_000.0)
        } else {
            format!("{:>8.0}  /s", per_sec)
        };

        let time_str = if per_hash_ns > 1_000_000.0 {
            format!("{:>7.2} ms", per_hash_ns / 1_000_000.0)
        } else if per_hash_ns > 1_000.0 {
            format!("{:>7.2} µs", per_hash_ns / 1_000.0)
        } else {
            format!("{:>7.0} ns", per_hash_ns)
        };

        println!("{:<20} {} {}", cracker.name(), speed_str, time_str);
    }
    println!("{:=<60}", "");
}

fn generate_test_hash(cracker: &dyn HashCracker, password: &str) -> String {
    use md5::Md5;
    use sha2::{Sha256, Sha512, Digest};

    match cracker.hash_type() {
        HashType::MD5 => {
            let mut h = Md5::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA224 => {
            let mut h = sha2::Sha224::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA1 => {
            let mut h = sha1::Sha1::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA256 => {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA384 => {
            let mut h = sha2::Sha384::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA512 => {
            let mut h = Sha512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::SHA3512 => {
            let mut h = sha3::Sha3_512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::BLAKE2B256 => {
            let mut h = blake2::Blake2s256::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::BLAKE2B512 => {
            let mut h = blake2::Blake2b512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::RIPEMD160 => {
            let mut h = ripemd::Ripemd160::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        HashType::NTLM => {
            use md4::Md4;
            use md4::Digest;
            let utf16: Vec<u8> = password.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut h = Md4::new();
            h.update(&utf16);
            hex::encode(h.finalize())
        }
        HashType::BCrypt | HashType::BCryptA => {
            bcrypt::hash(password, 4).unwrap()
        }
        _ => password.to_string(),
    }
}

fn cmd_show(potfile_path: &str, show_type: bool, stats_only: bool) {
    let potfile = Potfile::new(potfile_path);
    let entries = potfile.entries();

    if entries.is_empty() {
        eprintln!("[!] No entries in potfile: {}", potfile_path);
        return;
    }

    if stats_only {
        println!("Potfile: {}", potfile_path);
        println!("{:-<40}", "");
        println!("  Entries : {}", entries.len());
        println!("  File    : {}", potfile_path);
        return;
    }

    let detector = Detector::new();
    println!("Cracked passwords ({})", entries.len());
    println!("{:-<60}", "");

    let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (hash, password) in &entries {
        let t = if show_type {
            if let Some((cracker, _)) = detector.detect(hash) {
                *by_type.entry(cracker.name().to_string()).or_insert(0)
                    += 1;
                Some(cracker.name().to_string())
            } else {
                None
            }
        } else {
            None
        };
        match t {
            Some(ty) => println!("  {}  →  {}  [{}]", hash, password, ty),
            None => println!("  {}  →  {}", hash, password),
        }
    }

    if show_type {
        println!("{}", "");
        println!("Breakdown by type:");
        for (t, c) in &by_type {
            println!("  {}: {}", t, c);
        }
    }
}

fn cmd_hash(password: &str, hash_type: &str) {
    use md5::Md5 as Md5Core;
    use sha2::{Sha224, Sha256, Sha384, Sha512, Digest};

    let result = match hash_type.to_lowercase().as_str() {
        "md5" | "md-5" => {
            let mut h = Md5Core::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha1" | "sha-1" => {
            let mut h = sha1::Sha1::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha224" | "sha-224" => {
            let mut h = Sha224::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha256" | "sha-256" => {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha384" | "sha-384" => {
            let mut h = Sha384::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha512" | "sha-512" => {
            let mut h = Sha512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "sha3" | "sha3-512" => {
            let mut h = sha3::Sha3_512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "blake2b" | "blake2b-256" => {
            let mut h = blake2::Blake2s256::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "blake2b-512" => {
            let mut h = blake2::Blake2b512::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "ripemd160" | "ripemd-160" => {
            let mut h = ripemd::Ripemd160::new();
            h.update(password.as_bytes());
            hex::encode(h.finalize())
        }
        "ntlm" => {
            use md4::Md4;
            let utf16: Vec<u8> = password.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut h = Md4::new();
            h.update(&utf16);
            hex::encode(h.finalize())
        }
        "bcrypt" => bcrypt::hash(password, 10).unwrap(),
        _ => {
            eprintln!("[!] Unknown hash type: {}", hash_type);
            eprintln!("    Run 'pwdcrack list' to see supported types");
            return;
        }
    };
    println!("{}", result);
}

fn cmd_verify(detector: &Detector, hash: &str, password: &str) {
    match detector.detect(hash) {
        Some((cracker, entry)) => {
            let result = cracker.verify(password, &entry);
            if result {
                println!("✓  Password matches!");
            } else {
                println!("✗  Password does NOT match");
            }
        }
        None => {
            eprintln!("[!] Unknown hash format: {}", hash);
        }
    }
}

fn cmd_list(verbose: bool, filter: Option<&str>) {
    let types = [
        ("MD5", HashType::MD5, "5d41402abc4b2a76b9719d911017c592", 128, "Raw hex"),
        ("MD5 Crypt", HashType::MD5Crypt, "$1$salt$...", 0, "Unix crypt"),
        ("SHA-1", HashType::SHA1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", 160, "Raw hex"),
        ("SHA-224", HashType::SHA224, "<56 hex chars>", 224, "Raw hex"),
        ("SHA-256", HashType::SHA256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 256, "Raw hex"),
        ("SHA-256 Crypt", HashType::SHA256Crypt, "$5$rounds=5000$salt$...", 256, "Unix crypt"),
        ("SHA-384", HashType::SHA384, "<96 hex chars>", 384, "Raw hex"),
        ("SHA-512", HashType::SHA512, "<128 hex chars>", 512, "Raw hex"),
        ("SHA-512 Crypt", HashType::SHA512Crypt, "$6$rounds=5000$salt$...", 512, "Unix crypt"),
        ("SHA3-512", HashType::SHA3512, "<128 hex chars>", 512, "Raw hex"),
        ("BLAKE2b-256", HashType::BLAKE2B256, "<64 hex chars>", 256, "Raw hex"),
        ("BLAKE2b-512", HashType::BLAKE2B512, "<128 hex chars>", 512, "Raw hex"),
        ("RIPEMD-160", HashType::RIPEMD160, "<40 hex chars>", 160, "Raw hex"),
        ("NTLM", HashType::NTLM, "$NT$066ddfd4ef0e9cd7c256fe77191ef43c", 128, "NT hash"),
        ("LM", HashType::LM, "<32 uppercase hex>", 64, "LAN Manager"),
        ("bcrypt", HashType::BCrypt, "$2b$10$...", 0, "Blowfish"),
        ("bcrypt ($2a$)", HashType::BCryptA, "$2a$10$...", 0, "Blowfish"),
        ("Argon2i", HashType::Argon2i, "$argon2i$v=19$...", 0, "Memory-hard"),
        ("Argon2d", HashType::Argon2d, "$argon2d$v=19$...", 0, "Memory-hard"),
        ("Argon2id", HashType::Argon2id, "$argon2id$v=19$...", 0, "Memory-hard"),
        ("scrypt", HashType::Scrypt, "$scrypt$ln=10$...", 0, "Memory-hard"),
        ("Unknown", HashType::Unknown, "—", 0, "Fallback"),
    ];

    let filtered = match filter {
        Some(f) => {
            let f = f.to_lowercase();
            types.iter().filter(|(n, _, _, _, _)| n.to_lowercase().contains(&f)).collect::<Vec<_>>()
        }
        None => types.iter().collect(),
    };

    let n = filtered.len();
    if n == 0 {
        eprintln!("[!] No hash types matched '{}'", filter.unwrap());
        return;
    }

    if verbose {
        println!("{:<4} {:<20} {:>8} {:<12} {}", "#", "Algorithm", "Bits", "Category", "Example");
        println!("{:=<80}", "");
        for (i, (name, _, example, bits, cat)) in filtered.iter().enumerate() {
            let bits_str = if *bits > 0 { format!("{}", bits) } else { String::from("—") };
            let ex = if example.len() > 30 {
                format!("{}...", &example[..30])
            } else {
                example.to_string()
            };
            println!("{:<4} {:<20} {:>8} {:<12} {}", i + 1, name, bits_str, cat, ex);
        }
    } else {
        println!("Supported hash types:");
        println!("{:=<50}", "");
        for (name, _, _, _, cat) in &filtered {
            println!("  {:<20}  ({})", name, cat);
        }
    }
    println!("{:=<50}", "");
    println!("  {} type(s) shown", n);
}

fn cmd_mask(mask: &str, charsets: &[Option<String>], count: usize, offset: u64) {
    use pwdcrack::attack::brute::{parse_mask, total_combinations, index_to_password};
    let custom_slices: Vec<&[u8]> = charsets.iter()
        .filter_map(|c| c.as_ref().map(|s| s.as_bytes()))
        .collect();
    let parsed = parse_mask(mask);
    let total = total_combinations(&parsed, &custom_slices);
    println!("Mask: {}", mask);
    println!("Keyspace: {} ({:.2} billion)", total, total as f64 / 1_000_000_000.0);
    println!("");
    println!("Sample candidates (offset={}, count={}):", offset, count);
    println!("{:=<40}", "");

    let limit = count.min(100);
    for i in 0..limit {
        let idx = offset + i as u64;
        if idx >= total { break; }
        let pw = index_to_password(idx, &parsed, &custom_slices);
        println!("  {:<8} {}", idx, pw);
    }
    println!("{:=<40}", "");
}

fn cmd_suggest(detector: &Detector, hash: &str) {
    match detector.detect(hash) {
        Some((cracker, entry)) => {
            let ht = cracker.hash_type();
            println!("Hash  : {}", hash);
            println!("Type  : {}", cracker.name());
            println!("Bits  : {}", ht.bit_length().map(|b| b.to_string()).unwrap_or("N/A".into()));

            println!("\nSuggested attacks:");
            println!("{:=<60}", "");

            match ht {
                HashType::MD5 | HashType::SHA1 | HashType::SHA224
                | HashType::SHA256 | HashType::SHA384 | HashType::SHA512
                | HashType::SHA3512 | HashType::BLAKE2B256 | HashType::BLAKE2B512
                | HashType::RIPEMD160 | HashType::NTLM => {
                    let speed = match ht {
                        HashType::BCrypt | HashType::BCryptA => "~1 K/s",
                        _ => "> 1 M/s",
                    };
                    let bits = ht.bit_length().unwrap_or(0);
                    println!("  🏆  Dictionary + rules    (fast: {})", speed);
                    println!("  🥈  Brute-force mask       (8-char lower: {} combos)", "26^8 = 208B");
                    println!("  🥉  Combinator             (if two wordlists available)");
                    println!("");
                    if bits <= 128 {
                        println!("  ⚡  This hash is fast — susceptible to GPU/FPGA acceleration");
                    }
                    if bits >= 256 {
                        println!("  🔒  This hash is slow — dictionary + rules is most efficient");
                    }
                }
                HashType::BCrypt | HashType::BCryptA => {
                    println!("  🏆  Dictionary + rules    (bcrypt is intentionally slow)");
                    println!("  🥈  Small brute-force     (up to 6 characters)");
                    println!("");
                    println!("  ⚠  bcrypt is resistant to GPU acceleration");
                    println!("  ⚠  Focus on dictionary with good rules");
                }
                HashType::Argon2i | HashType::Argon2d | HashType::Argon2id | HashType::Scrypt => {
                    println!("  🏆  Dictionary + rules    (memory-hard, very slow to brute-force)");
                    println!("");
                    println!("  ⚠  Memory-hard hash — GPU resistance is high");
                    println!("  ⚠  Best approach: targeted dictionary with context-aware rules");
                }
                _ => {
                    println!("  🏆  Dictionary + rules");
                    println!("  🥈  Brute-force mask");
                    println!("  🥉  Combinator");
                }
            }

            // Print hash details
            if let Some(ref salt) = entry.salt {
                println!("\nSalt: {}", salt);
            }
            if let Some(ref username) = entry.username {
                println!("Username: {}", username);
            }
        }
        None => {
            eprintln!("[!] Unknown hash format: {}", hash);
            eprintln!("    Run 'pwdcrack list' to see supported types");
        }
    }
}
