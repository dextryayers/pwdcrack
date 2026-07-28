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

    // ── Engine init ──
    #[cfg(feature = "engine-simd")]
    {
        engine_simd::init();
        log::info!("SIMD: {:?}", engine_simd::current_level());
    }

    #[cfg(feature = "engine-gpu")]
    let _gpu_engine = if args.gpu {
        match pollster::block_on(engine_gpu::GpuEngine::init()) {
            Some(gpu) => {
                log::info!("GPU: {}", gpu.info());
                Some(std::sync::Arc::new(gpu))
            }
            None => {
                log::warn!("GPU: no compatible device found");
                None
            }
        }
    } else { None };

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

    #[cfg(feature = "engine-distributed")]
    let _dist_engine = if args.distributed {
        Some(engine_distributed::DistributedNode::new("0.0.0.0:0"))
    } else { None };

    #[cfg(feature = "engine-tpu")]
    let _tpu_engine = {
        log::info!("TPU: engine available");
        engine_tpu::device::probe();
        Some(())
    };
    #[cfg(not(feature = "engine-tpu"))]
    let _tpu_engine = None::<()>;

    #[cfg(feature = "engine-riscv")]
    let _riscv_engine = {
        log::info!("RISC-V: vector extension detected");
        engine_riscv::vector::probe();
        Some(())
    };
    #[cfg(not(feature = "engine-riscv"))]
    let _riscv_engine = None::<()>;

    #[cfg(feature = "engine-metal")]
    let _metal_engine = {
        log::info!("Metal: GPU acceleration available");
        engine_metal::device::probe();
        Some(())
    };
    #[cfg(not(feature = "engine-metal"))]
    let _metal_engine = None::<()>;

    #[cfg(feature = "engine-hybrid")]
    let _hybrid_scheduler = {
        let hs = engine_hybrid::scheduler::HybridScheduler::new();
        log::info!("Hybrid: scheduler initialized");
        Some(hs)
    };
    #[cfg(not(feature = "engine-hybrid"))]
    let _hybrid_scheduler = None::<()>;

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
        Commands::Prince { hash_file, wordlist, min_length, max_length, limit, session } => {
            cmd_prince(&detector, hash_file, wordlist, threads, &args, *min_length, *max_length, *limit, session.as_deref())
        }
        Commands::ToggleCase { hash_file, wordlist, max_toggle, limit } => {
            cmd_toggle_case(&detector, hash_file, wordlist, threads, &args, *max_toggle, *limit)
        }
        Commands::Substitute { hash_file, wordlist, level, limit } => {
            cmd_substitute(&detector, hash_file, wordlist, threads, &args, *level, *limit)
        }
        Commands::Rules { wordlist, rules_file, output, limit } => {
            cmd_rules(wordlist, rules_file, output.as_deref(), *limit)
        }
        Commands::Stats { potfile, verbose, by_complexity } => {
            cmd_stats(potfile, *verbose, *by_complexity)
        }
        Commands::Expand { mask, charset1, charset2, charset3, charset4, limit } => {
            cmd_expand(mask, &[charset1.clone(), charset2.clone(), charset3.clone(), charset4.clone()], *limit)
        }
        Commands::Check { hash_file, verbose, clean } => {
            cmd_check(&detector, hash_file, *verbose, *clean)
        }
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
        ("SHA-512/224", HashType::SHA512_224, "<56 hex chars>", 224, "Raw hex"),
        ("SHA-512/256", HashType::SHA512_256, "<64 hex chars>", 256, "Raw hex"),
        ("SHA-512 Crypt", HashType::SHA512Crypt, "$6$rounds=5000$salt$...", 512, "Unix crypt"),
        ("SHA3-224", HashType::SHA3224, "<56 hex chars>", 224, "Raw hex"),
        ("SHA3-256", HashType::SHA3256, "<64 hex chars>", 256, "Raw hex"),
        ("SHA3-384", HashType::SHA3384, "<96 hex chars>", 384, "Raw hex"),
        ("SHA3-512", HashType::SHA3512, "<128 hex chars>", 512, "Raw hex"),
        ("MD4", HashType::MD4, "<32 hex chars>", 128, "Raw hex"),
        ("Whirlpool", HashType::WHIRLPOOL, "<128 hex chars>", 512, "Raw hex"),
        ("Streebog-256", HashType::STREEBOG256, "<64 hex chars>", 256, "Raw hex"),
        ("Streebog-512", HashType::STREEBOG512, "<128 hex chars>", 512, "Raw hex"),
        ("Tiger-192", HashType::TIGER192, "<48 hex chars>", 192, "Raw hex"),
        ("JH-224", HashType::JH224, "<56 hex chars>", 224, "Raw hex"),
        ("JH-256", HashType::JH256, "<64 hex chars>", 256, "Raw hex"),
        ("JH-384", HashType::JH384, "<96 hex chars>", 384, "Raw hex"),
        ("JH-512", HashType::JH512, "<128 hex chars>", 512, "Raw hex"),
        ("Skein-256", HashType::SKEIN256, "<64 hex chars>", 256, "Raw hex"),
        ("Skein-512", HashType::SKEIN512, "<128 hex chars>", 512, "Raw hex"),
        ("Shabal-192", HashType::SHABAL192, "<48 hex chars>", 192, "Raw hex"),
        ("Shabal-224", HashType::SHABAL224, "<56 hex chars>", 224, "Raw hex"),
        ("Shabal-256", HashType::SHABAL256, "<64 hex chars>", 256, "Raw hex"),
        ("Shabal-384", HashType::SHABAL384, "<96 hex chars>", 384, "Raw hex"),
        ("Shabal-512", HashType::SHABAL512, "<128 hex chars>", 512, "Raw hex"),
        ("GOST94-256", HashType::GOST94256, "<64 hex chars>", 256, "Raw hex"),
        ("GOST94-512", HashType::GOST94512, "<128 hex chars>", 512, "Raw hex"),
        ("BLAKE2b-256", HashType::BLAKE2B256, "<64 hex chars>", 256, "Raw hex"),
        ("BLAKE2s-256", HashType::BLAKE2S256, "<64 hex chars>", 256, "Raw hex"),
        ("BLAKE2b-512", HashType::BLAKE2B512, "<128 hex chars>", 512, "Raw hex"),
        ("BLAKE2b-384", HashType::BLAKE2B384, "<96 hex chars>", 384, "Raw hex"),
        ("BLAKE2b-224", HashType::BLAKE2B224, "<56 hex chars>", 224, "Raw hex"),
        ("BLAKE2b-160", HashType::BLAKE2B160, "<40 hex chars>", 160, "Raw hex"),
        ("BLAKE2s-128", HashType::BLAKE2S128, "<32 hex chars>", 128, "Raw hex"),
        ("BLAKE2s-160", HashType::BLAKE2S160, "<40 hex chars>", 160, "Raw hex"),
        ("BLAKE3-256", HashType::BLAKE3256, "<64 hex chars>", 256, "Raw hex"),
        ("CRC32", HashType::CRC32, "<8 hex chars>", 32, "Checksum"),
        ("CRC64", HashType::CRC64, "<16 hex chars>", 64, "Checksum"),
        ("MD2", HashType::MD2, "<32 hex chars>", 128, "Raw hex"),
        ("RIPEMD-128", HashType::RIPEMD128, "<32 hex chars>", 128, "Raw hex"),
        ("RIPEMD-160", HashType::RIPEMD160, "<40 hex chars>", 160, "Raw hex"),
        ("RIPEMD-256", HashType::RIPEMD256, "<64 hex chars>", 256, "Raw hex"),
        ("RIPEMD-320", HashType::RIPEMD320, "<80 hex chars>", 320, "Raw hex"),
        ("Apache MD5", HashType::APR1MD5, "$apr1$...", 0, "Application"),
        ("PHPass", HashType::PHPASS, "$P$...", 128, "Application"),
        ("Drupal 7", HashType::DRUPAL7, "$S$...", 512, "Application"),
        ("osCommerce", HashType::OSCOMMERCE, "<32hex>:<salt>", 128, "Application"),
        ("MySQL 4.1+", HashType::MYSQL41, "*HEX...", 0, "Application"),
        ("PostgreSQL MD5", HashType::POSTGRESQL, "md5...", 0, "Application"),
        ("Oracle 10g", HashType::ORACLE10G, "<40hex>:user", 160, "Application"),
        ("Oracle 11g/12c", HashType::ORACLE11G, "<128hex>:<salt>", 512, "Application"),
        ("MSSQL 2005", HashType::MSSQL2005, "<64hex>:<salt>", 256, "Application"),
        ("MSSQL 2012", HashType::MSSQL2012, "<128hex>:<salt>", 512, "Application"),
        ("vBulletin 3/4", HashType::VBULLETIN3, "<32hex>:<salt>", 128, "Application"),
        ("vBulletin 5", HashType::VBULLETIN5, "<64hex>:<salt>", 256, "Application"),
        ("SMF 1/2", HashType::SMF, "<40hex>:user", 160, "Application"),
        ("IPB 2 / MyBB", HashType::IPB2, "<32hex>:<salt>", 128, "Application"),
        ("IPB 3+", HashType::IPB3, "<64hex>:<salt>", 256, "Application"),
        ("MediaWiki", HashType::MEDIAWIKI, ":<salt>:<32hex>", 128, "Application"),
        ("Cisco PIX", HashType::CISCOPIX, "02...", 64, "Application"),
        ("Cisco Type 5", HashType::CISCO5, "$5$...", 0, "Application"),
        ("HMAC-SHA1", HashType::HMACSHA1, "<40hex>", 160, "Application"),
        ("HMAC-SHA256", HashType::HMACSHA256, "<64hex>", 256, "Application"),
        ("HMAC-MD5", HashType::HMACMD5, "<32hex>", 128, "Application"),
        ("HMAC-SHA512", HashType::HMACSHA512, "<128hex>", 512, "Application"),
        ("HMAC-SHA224", HashType::HMACSHA224, "<56hex>", 224, "Application"),
        ("HMAC-SHA384", HashType::HMACSHA384, "<96hex>", 384, "Application"),
        ("HMAC-RIPEMD160", HashType::HMACRIPEMD160, "<40hex>", 160, "Application"),
        ("PBKDF2-SHA256", HashType::PBKDF2SHA256, "<64hex>:salt", 256, "Application"),
        ("PBKDF2-SHA512", HashType::PBKDF2SHA512, "<128hex>:salt", 512, "Application"),
        ("PBKDF2-SHA1", HashType::PBKDF2SHA1, "<40hex>:salt", 160, "Application"),
        ("DCC1", HashType::DCC1, "<32hex>:user", 128, "Application"),
        ("DCC2", HashType::DCC2, "<32hex>:user", 128, "Application"),
        ("NTLMv2", HashType::NTLMV2, "<user>:<domain>:<32hex>", 128, "Application"),
        ("Salted MD5", HashType::SALTEDMD5, "<32hex>:<salt>", 128, "Application"),
        ("Salted SHA-1", HashType::SALTEDSHA1, "<40hex>:<salt>", 160, "Application"),
        ("Salted SHA-256", HashType::SALTEDSHA256, "<64hex>:<salt>", 256, "Application"),
        ("Salted SHA-384", HashType::SALTEDSHA384, "<96hex>:<salt>", 384, "Application"),
        ("Salted SHA-512", HashType::SALTEDSHA512, "<128hex>:<salt>", 512, "Application"),
        ("Double MD5", HashType::DOUBLEMD5, "<32hex>", 128, "Application"),
        ("Double SHA-1", HashType::DOUBLESHA1, "<40hex>", 160, "Application"),
        ("Double SHA-256", HashType::DOUBLESHA256, "<64hex>", 256, "Application"),
        ("{SHA}", HashType::SHA1DASH, "{SHA}base64...", 160, "Application"),
        ("SSHA-1", HashType::SSHA1, "{SSHA}base64...", 160, "Application"),
        ("SSHA-256", HashType::SSHA256, "{SSHA256}base64...", 256, "Application"),
        ("HMAC-SHA512/224", HashType::HMACSHA512_224, "<hash>:<salt>", 224, "HMAC"),
        ("HMAC-SHA512/256", HashType::HMACSHA512_256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-SHA3-224", HashType::HMACSHA3224, "<hash>:<salt>", 224, "HMAC"),
        ("HMAC-SHA3-256", HashType::HMACSHA3256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-SHA3-384", HashType::HMACSHA3384, "<hash>:<salt>", 384, "HMAC"),
        ("HMAC-SHA3-512", HashType::HMACSHA3512, "<hash>:<salt>", 512, "HMAC"),
        ("HMAC-BLAKE2b-256", HashType::HMACBLAKE2B256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-BLAKE2s-256", HashType::HMACBLAKE2S256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-BLAKE2b-512", HashType::HMACBLAKE2B512, "<hash>:<salt>", 512, "HMAC"),
        ("HMAC-RIPEMD128", HashType::HMACRIPEMD128, "<hash>:<salt>", 128, "HMAC"),
        ("HMAC-RIPEMD256", HashType::HMACRIPEMD256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-RIPEMD320", HashType::HMACRIPEMD320, "<hash>:<salt>", 320, "HMAC"),
        ("HMAC-Whirlpool", HashType::HMACWHIRLPOOL, "<hash>:<salt>", 512, "HMAC"),
        ("HMAC-Streebog-256", HashType::HMACSTREEBOG256, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-Streebog-512", HashType::HMACSTREEBOG512, "<hash>:<salt>", 512, "HMAC"),
        ("PBKDF2-SHA384", HashType::PBKDF2SHA384, "<hash>:<iter>:<salt>", 0, "PBKDF2"),
        ("PBKDF2-SHA224", HashType::PBKDF2SHA224, "<hash>:<iter>:<salt>", 0, "PBKDF2"),
        ("Salted SHA-224", HashType::SALTEDSHA224, "<hash>:<salt>", 224, "Application"),
        ("Triple MD5", HashType::TRIPLEMD5, "<32 hex>", 128, "Application"),
        ("MD5 Half", HashType::MD5HALF, "<16 hex>", 64, "Application"),
        ("CRC-8/ITU", HashType::CRC8ITU, "<2 hex chars>", 8, "Checksum"),
        ("CRC-16/CCITT", HashType::CRC16CCITT, "<4 hex chars>", 16, "Checksum"),
        ("CRC-16/MODBUS", HashType::CRC16MODBUS, "<4 hex chars>", 16, "Checksum"),
        ("CRC-32/BZIP2", HashType::CRC32BZIP2, "<8 hex chars>", 32, "Checksum"),
        ("CRC-32/MPEG-2", HashType::CRC32MPEG2, "<8 hex chars>", 32, "Checksum"),
        ("CRC-64/ECMA-182", HashType::CRC64ECMA, "<16 hex chars>", 64, "Checksum"),
        ("NTLMv1", HashType::NTLMV1, "<challenge>:<response>", 128, "NT hash"),
        ("CRAM-MD5", HashType::CRAMMD5, "<challenge> <digest>", 128, "Application"),
        ("PLAINTEXT", HashType::PLAINTEXT, "<password>", 0, "Application"),
        ("CRC-24", HashType::CRC24, "<6 hex chars>", 24, "Checksum"),
        ("MySQL 3.21", HashType::MYSQL321, "<16 hex chars>", 64, "Database"),
        ("Oracle 7", HashType::ORACLE7, "O$...", 0, "Database"),
        ("Snefru-128", HashType::SNEFRU128, "<32 hex chars>", 128, "Hash"),
        ("Snefru-256", HashType::SNEFRU256, "<64 hex chars>", 256, "Hash"),
        ("Salted SHA3-256", HashType::SALTEDSHA3256, "<hash>:<salt>", 256, "Application"),
        ("Salted SHA3-512", HashType::SALTEDSHA3512, "<hash>:<salt>", 512, "Application"),
        ("HMAC-GOST94", HashType::HMACGOST94, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-Tiger", HashType::HMACTIGER, "<hash>:<salt>", 192, "HMAC"),
        ("CRC8", HashType::CRC8, "<2 hex chars>", 8, "Checksum"),
        ("CRC16", HashType::CRC16, "<4 hex chars>", 16, "Checksum"),
        ("CRC32C", HashType::CRC32C, "<8 hex chars>", 32, "Checksum"),
        ("Adler-32", HashType::ADLER32, "<8 hex chars>", 32, "Checksum"),
        ("Sun MD5", HashType::SUNMD5, "$md5$...", 0, "Application"),
        ("BSDi Crypt", HashType::BSDICRYPT, "_...", 0, "Application"),
        ("macOS PBKDF2", HashType::MACOSPBKDF2, "$ml$...", 0, "Application"),
        ("NTLM", HashType::NTLM, "$NT$066ddfd4ef0e9cd7c256fe77191ef43c", 128, "NT hash"),
        ("LM", HashType::LM, "<32 uppercase hex>", 64, "LAN Manager"),
        ("bcrypt", HashType::BCrypt, "$2b$10$...", 0, "Blowfish"),
        ("bcrypt ($2a$)", HashType::BCryptA, "$2a$10$...", 0, "Blowfish"),
        ("Argon2i", HashType::Argon2i, "$argon2i$v=19$...", 0, "Memory-hard"),
        ("Argon2d", HashType::Argon2d, "$argon2d$v=19$...", 0, "Memory-hard"),
        ("Argon2id", HashType::Argon2id, "$argon2id$v=19$...", 0, "Memory-hard"),
        ("scrypt", HashType::Scrypt, "$scrypt$ln=10$...", 0, "Memory-hard"),
        ("LM CHAPv2", HashType::LMCHAPV2, "<user>:<challenge>:<48hex>", 128, "NT hash"),
        ("DCC3", HashType::DCC3, "<32hex>:<user>", 128, "Application"),
        ("SAP CODVN B", HashType::SAPCODVNB, "SAPB...", 0, "Application"),
        ("SAP CODVN F/G", HashType::SAPCODVNFG, "SAPF.../SAPG...", 0, "Application"),
        ("EPi", HashType::EPI, "<32hex>:<salt>", 128, "Application"),
        ("PunBB", HashType::PUNBB, "<40hex>:<salt>", 160, "Application"),
        ("NSLDAP", HashType::NSLDAP, "<40hex>:<salt>", 160, "Application"),
        ("Lotus Notes", HashType::LOTUSNOTES, "<16hex>:<salt>", 0, "Application"),
        ("Challenge", HashType::CHALLENGE, "<challenge>$<32hex>", 128, "Application"),
        ("GOST94 HMAC", HashType::GOST94HMAC, "<hash>:<salt>", 256, "HMAC"),
        ("HMAC-BLAKE2b-224", HashType::HMACBLAKE2B224, "<hash>:<salt>", 224, "HMAC"),
        ("HMAC-BLAKE2b-384", HashType::HMACBLAKE2B384, "<hash>:<salt>", 384, "HMAC"),
        ("SHA-256 Crypt ($rounds$)", HashType::SHA256CRYPTROUNDS, "$rounds=...", 256, "Application"),
        ("HMAC-SHA1 (username)", HashType::HMACSHA1USER, "<hash>:<user>:<salt>", 160, "HMAC"),
        ("SKIP32", HashType::SKIP32, "<8 hex chars>", 32, "Checksum"),
        ("xxHash32", HashType::XXHASH32, "<8 hex chars>", 32, "Checksum"),
        ("SM3", HashType::SM3, "<64 hex chars>", 256, "Raw hex"),
        ("HAS-160", HashType::HAS160, "<40 hex chars>", 160, "Raw hex"),
        ("Groestl-224", HashType::Groestl224, "<56 hex chars>", 224, "Raw hex"),
        ("Groestl-256", HashType::Groestl256, "<64 hex chars>", 256, "Raw hex"),
        ("Groestl-384", HashType::Groestl384, "<96 hex chars>", 384, "Raw hex"),
        ("Groestl-512", HashType::Groestl512, "<128 hex chars>", 512, "Raw hex"),
        ("BMW-224", HashType::BMW224, "<56 hex chars>", 224, "Raw hex"),
        ("BMW-256", HashType::BMW256, "<64 hex chars>", 256, "Raw hex"),
        ("BMW-384", HashType::BMW384, "<96 hex chars>", 384, "Raw hex"),
        ("BMW-512", HashType::BMW512, "<128 hex chars>", 512, "Raw hex"),
        ("Echo-224", HashType::Echo224, "<56 hex chars>", 224, "Raw hex"),
        ("Echo-256", HashType::Echo256, "<64 hex chars>", 256, "Raw hex"),
        ("Echo-384", HashType::Echo384, "<96 hex chars>", 384, "Raw hex"),
        ("Echo-512", HashType::Echo512, "<128 hex chars>", 512, "Raw hex"),
        ("SHAvite-3-224", HashType::Shavite2224, "<56 hex chars>", 224, "Raw hex"),
        ("SHAvite-3-256", HashType::Shavite2256, "<64 hex chars>", 256, "Raw hex"),
        ("SHAvite-3-384", HashType::Shavite2384, "<96 hex chars>", 384, "Raw hex"),
        ("SHAvite-3-512", HashType::Shavite2512, "<128 hex chars>", 512, "Raw hex"),
        ("SIMD-224", HashType::SIMD224, "<56 hex chars>", 224, "Raw hex"),
        ("SIMD-256", HashType::SIMD256, "<64 hex chars>", 256, "Raw hex"),
        ("SIMD-384", HashType::SIMD384, "<96 hex chars>", 384, "Raw hex"),
        ("SIMD-512", HashType::SIMD512, "<128 hex chars>", 512, "Raw hex"),
        ("Luffa-224", HashType::Luffa224, "<56 hex chars>", 224, "Raw hex"),
        ("Luffa-256", HashType::Luffa256, "<64 hex chars>", 256, "Raw hex"),
        ("Luffa-384", HashType::Luffa384, "<96 hex chars>", 384, "Raw hex"),
        ("Luffa-512", HashType::Luffa512, "<128 hex chars>", 512, "Raw hex"),
        ("CubeHash-224", HashType::CubeHash224, "<56 hex chars>", 224, "Raw hex"),
        ("CubeHash-256", HashType::CubeHash256, "<64 hex chars>", 256, "Raw hex"),
        ("CubeHash-384", HashType::CubeHash384, "<96 hex chars>", 384, "Raw hex"),
        ("CubeHash-512", HashType::CubeHash512, "<128 hex chars>", 512, "Raw hex"),
        ("Fugue-224", HashType::Fugue224, "<56 hex chars>", 224, "Raw hex"),
        ("Fugue-256", HashType::Fugue256, "<64 hex chars>", 256, "Raw hex"),
        ("Fugue-384", HashType::Fugue384, "<96 hex chars>", 384, "Raw hex"),
        ("Fugue-512", HashType::Fugue512, "<128 hex chars>", 512, "Raw hex"),
        ("Hamsi-224", HashType::Hamsi224, "<56 hex chars>", 224, "Raw hex"),
        ("Hamsi-256", HashType::Hamsi256, "<64 hex chars>", 256, "Raw hex"),
        ("Hamsi-384", HashType::Hamsi384, "<96 hex chars>", 384, "Raw hex"),
        ("Hamsi-512", HashType::Hamsi512, "<128 hex chars>", 512, "Raw hex"),
        ("Panama-128", HashType::Panama128, "<32 hex chars>", 128, "Raw hex"),
        ("RadioGatún-32", HashType::RadioGatun32, "<8 hex chars>", 32, "Raw hex"),
        ("RadioGatún-64", HashType::RadioGatun64, "<16 hex chars>", 64, "Raw hex"),
        ("Haval-128", HashType::Haval128, "<32 hex chars>", 128, "Raw hex"),
        ("Haval-160", HashType::Haval160, "<40 hex chars>", 160, "Raw hex"),
        ("Haval-192", HashType::Haval192, "<48 hex chars>", 192, "Raw hex"),
        ("Haval-224", HashType::Haval224, "<56 hex chars>", 224, "Raw hex"),
        ("Haval-256", HashType::Haval256, "<64 hex chars>", 256, "Raw hex"),
        ("FSB-160", HashType::FSB160, "<40 hex chars>", 160, "Raw hex"),
        ("FSB-224", HashType::FSB224, "<56 hex chars>", 224, "Raw hex"),
        ("FSB-256", HashType::FSB256, "<64 hex chars>", 256, "Raw hex"),
        ("FSB-384", HashType::FSB384, "<96 hex chars>", 384, "Raw hex"),
        ("FSB-512", HashType::FSB512, "<128 hex chars>", 512, "Raw hex"),
        ("ECOH-128", HashType::ECOH128, "<32 hex chars>", 128, "Raw hex"),
        ("ECOH-192", HashType::ECOH192, "<48 hex chars>", 192, "Raw hex"),
        ("ECOH-256", HashType::ECOH256, "<64 hex chars>", 256, "Raw hex"),
        ("CRC-10", HashType::CRC10, "<3 hex chars>", 10, "Checksum"),
        ("CRC-11", HashType::CRC11, "<3 hex chars>", 11, "Checksum"),
        ("CRC-12", HashType::CRC12, "<3 hex chars>", 12, "Checksum"),
        ("CRC-13", HashType::CRC13, "<4 hex chars>", 13, "Checksum"),
        ("CRC-14", HashType::CRC14, "<4 hex chars>", 14, "Checksum"),
        ("CRC-15", HashType::CRC15, "<4 hex chars>", 15, "Checksum"),
        ("CRC-17", HashType::CRC17, "<5 hex chars>", 17, "Checksum"),
        ("CRC-21", HashType::CRC21, "<6 hex chars>", 21, "Checksum"),
        ("CRC-24C", HashType::CRC24C, "<6 hex chars>", 24, "Checksum"),
        ("CRC-30", HashType::CRC30, "<8 hex chars>", 30, "Checksum"),
        ("CRC-31", HashType::CRC31, "<8 hex chars>", 31, "Checksum"),
        ("CRC-40", HashType::CRC40, "<10 hex chars>", 40, "Checksum"),
        ("CRC-82", HashType::CRC82, "<21 hex chars>", 82, "Checksum"),
        ("CRC-DNP", HashType::CRCDNP, "<6 hex chars>", 24, "Checksum"),
        ("CRC-JAM", HashType::CRCJAM, "<8 hex chars>", 32, "Checksum"),
        ("Fletcher-4", HashType::Fletcher4, "<1 hex chars>", 4, "Checksum"),
        ("Fletcher-8", HashType::Fletcher8, "<2 hex chars>", 8, "Checksum"),
        ("Fletcher-16", HashType::Fletcher16, "<4 hex chars>", 16, "Checksum"),
        ("Fletcher-32", HashType::Fletcher32, "<8 hex chars>", 32, "Checksum"),
        ("XOR-8", HashType::XOR8, "<2 hex chars>", 8, "Checksum"),
        ("Sum-8", HashType::Sum8, "<2 hex chars>", 8, "Checksum"),
        ("Sum-16", HashType::Sum16, "<4 hex chars>", 16, "Checksum"),
        ("Sum-24", HashType::Sum24, "<6 hex chars>", 24, "Checksum"),
        ("Sum-32", HashType::Sum32, "<8 hex chars>", 32, "Checksum"),
        ("Sum-64", HashType::Sum64, "<16 hex chars>", 64, "Checksum"),
        ("Django MD5", HashType::DjangoMD5, "<salt>$<32hex>", 128, "Application"),
        ("Django SHA-256", HashType::DjangoSHA256, "$<iter>$<salt>$<64hex>", 256, "Application"),
        ("Django PBKDF2", HashType::DjangoPBKDF2, "pbkdf2_sha256$<iter>$<salt>$<hash>", 0, "Application"),
        ("Joomla MD5", HashType::JoomlaMD5, "<32hex>:<salt>", 128, "Application"),
        ("Joomla SHA-256", HashType::JoomlaSHA256, "<64hex>:<salt>", 256, "Application"),
        ("Drupal 8", HashType::Drupal8, "$S$...", 256, "Application"),
        ("XenForo", HashType::XenForo, "<40hex>:<salt>", 160, "Application"),
        ("Woltlab", HashType::Woltlab, "<40hex>:<salt>", 160, "Application"),
        ("MyBB 1.x", HashType::MyBBHash, "<32hex>:<salt>", 128, "Application"),
        ("Vanilla", HashType::Vanilla, "<32hex>:<salt>", 128, "Application"),
        ("FluxBB", HashType::FluxBB, "<32hex>:<salt>", 128, "Application"),
        ("CakePHP", HashType::CakePHP, "<32hex>:<salt>", 128, "Application"),
        ("CodeIgniter", HashType::CodeIgniter, "<32hex>:<salt>", 128, "Application"),
        ("Laravel bcrypt", HashType::LaravelBCrypt, "$2y$...", 0, "Application"),
        ("Magento", HashType::Magento, "<32hex>:<salt>", 128, "Application"),
        ("MODX", HashType::MODX, "<32hex>:<salt>", 128, "Application"),
        ("Moodle", HashType::Moodle, "<32hex>:<salt>", 128, "Application"),
        ("PrestaShop", HashType::PrestaShop, "<32hex>:<salt>", 128, "Application"),
        ("TYPO3", HashType::TYPO3, "<32hex>:<salt>", 128, "Application"),
        ("Umbraco", HashType::Umbraco, "<32hex>:<salt>", 128, "Application"),
        ("WHMCS", HashType::WHMCS, "<32hex>:<salt>", 128, "Application"),
        ("Zikula", HashType::Zikula, "<32hex>:<salt>", 128, "Application"),
        ("Elgg", HashType::Elgg, "<32hex>:<salt>", 128, "Application"),
        ("WordPress PHPass", HashType::WordPressPHPass, "$P$...", 128, "Application"),
        ("PHP Hash", HashType::PHPHash, "<hash>:<salt>", 0, "Application"),
        ("Oracle 8", HashType::Oracle8, "<16 hex chars>", 64, "Database"),
        ("Oracle 9", HashType::Oracle9, "<16 hex chars>", 64, "Database"),
        ("Oracle 12c", HashType::Oracle12c, "T_HASH<128hex>", 512, "Database"),
        ("IBM DB2", HashType::IBMDB2, "<32 hex chars>", 128, "Database"),
        ("Progress", HashType::Progress, "<16 hex chars>", 64, "Database"),
        ("Sybase", HashType::Sybase, "<32 hex chars>", 128, "Database"),
        ("Teradata", HashType::Teradata, "<16 hex chars>", 64, "Database"),
        ("MSSQL 2000", HashType::MSSQL2000, "<44 hex chars>", 0, "Database"),
        ("MSSQL 2008", HashType::MSSQL2008, "<32 hex chars>", 0, "Database"),
        ("MSSQL 2017", HashType::MSSQL2017, "<64 hex chars>", 0, "Database"),
        ("MySQL 5", HashType::MySQL5, "*<40hex>", 256, "Database"),
        ("MySQL 8", HashType::MySQL8, "$A$...", 256, "Database"),
        ("PostgreSQL SCRAM", HashType::PostgreSQLSCRAM, "SCRAM-SHA-256$...", 0, "Database"),
        ("MongoDB", HashType::MongoDB, "<32 hex chars>", 128, "Database"),
        ("Redis", HashType::Redis, "<32 hex chars>", 128, "Database"),
        ("RavenDB", HashType::RavenDB, "<64 hex chars>", 0, "Database"),
        ("CouchDB", HashType::CouchDB, "<16 hex chars>", 0, "Database"),
        ("Cisco Type 7", HashType::CiscoType7, "<encrypted>", 0, "Enterprise"),
        ("Juniper", HashType::Juniper, "$9$...", 0, "Enterprise"),
        ("Huawei", HashType::Huawei, "<32 hex chars>", 0, "Enterprise"),
        ("Nokia", HashType::Nokia, "<16 hex chars>", 0, "Enterprise"),
        ("Alcatel", HashType::Alcatel, "<32 hex chars>", 0, "Enterprise"),
        ("ZTE", HashType::ZTE, "<32 hex chars>", 0, "Enterprise"),
        ("Ericsson", HashType::Ericsson, "<32 hex chars>", 0, "Enterprise"),
        ("SNMP", HashType::SNMP, "<community string>", 0, "Enterprise"),
        ("RADIUS CHAP", HashType::RADIUSCHAP, "<user>:<challenge>:<32hex>", 128, "Enterprise"),
        ("Kerberos 5", HashType::Kerberos5, "$krb5$...", 0, "Enterprise"),
        ("AFS", HashType::AFS, "<16 hex chars>", 0, "Enterprise"),
        ("DPAPI", HashType::DPAPI, "<encoded>", 0, "Enterprise"),
        ("BitLocker", HashType::BitLocker, "<recovery>", 0, "Enterprise"),
        ("TrueCrypt", HashType::TrueCrypt, "<volume>", 0, "Enterprise"),
        ("FileVault", HashType::FileVault, "<recovery>", 0, "Enterprise"),
        ("LUKS", HashType::LUKS, "<header>", 0, "Enterprise"),
        ("VeraCrypt", HashType::VeraCrypt, "<volume>", 0, "Enterprise"),
        ("Windows Hello", HashType::WindowsHello, "<PIN hash>", 0, "Enterprise"),
        ("X11", HashType::X11, "<64 hex chars>", 256, "Blockchain"),
        ("X13", HashType::X13, "<64 hex chars>", 256, "Blockchain"),
        ("X15", HashType::X15, "<64 hex chars>", 256, "Blockchain"),
        ("X17", HashType::X17, "<64 hex chars>", 256, "Blockchain"),
        ("Quark", HashType::Quark, "<64 hex chars>", 256, "Blockchain"),
        ("NeoScrypt", HashType::Neoscrypt, "<64 hex chars>", 256, "Blockchain"),
        ("Lyra2RE", HashType::Lyra2RE, "<64 hex chars>", 256, "Blockchain"),
        ("yescrypt", HashType::Yescrypt, "<64 hex chars>", 256, "Blockchain"),
        ("scrypt-N", HashType::ScryptN, "<64 hex chars>", 256, "Blockchain"),
        ("scrypt-J", HashType::ScryptJ, "<64 hex chars>", 256, "Blockchain"),
        ("Bitcoin", HashType::Bitcoin, "<64 hex chars>", 256, "Blockchain"),
        ("Ethereum", HashType::Ethereum, "<40 hex chars>", 160, "Blockchain"),
        ("Litecoin", HashType::Litecoin, "<64 hex chars>", 256, "Blockchain"),
        ("Dogecoin", HashType::Dogecoin, "<64 hex chars>", 256, "Blockchain"),
        ("Ripple", HashType::Ripple, "<64 hex chars>", 256, "Blockchain"),
        ("Monero", HashType::Monero, "<64 hex chars>", 256, "Blockchain"),
        ("Dash", HashType::Dash, "<64 hex chars>", 256, "Blockchain"),
        ("Zcash", HashType::Zcash, "<64 hex chars>", 256, "Blockchain"),
        ("Namecoin", HashType::Namecoin, "<64 hex chars>", 256, "Blockchain"),
        ("Peercoin", HashType::Peercoin, "<64 hex chars>", 256, "Blockchain"),
        ("DES Crypt", HashType::DESCrypt, "<13 chars>", 64, "Legacy"),
        ("BSD Auth", HashType::BSDAuth, "_<20+ chars>", 0, "Legacy"),
        ("MD5 Crypt APR", HashType::MD5CryptAPR, "$apr1$...", 0, "Legacy"),
        ("Blowfish OpenBSD", HashType::BlowfishOpenBSD, "$2a$...", 0, "Legacy"),
        ("Linux Overflow", HashType::LinuxOverflow, "<overflow hash>", 0, "Legacy"),
        ("Unix Old", HashType::UnixOld, "<13 DES chars>", 64, "Legacy"),
        ("DES BSDi", HashType::DESBSDi, "_<20+ chars>", 64, "Legacy"),
        ("HP Managed", HashType::HPManaged, "<32 hex chars>", 128, "Legacy"),
        ("SNEFRU-128 Legacy", HashType::SNEFRU128Legacy, "<32 hex chars>", 128, "Legacy"),
        ("HMAC-SHA256-128", HashType::HMACSHA256_128, "<32 hex chars>", 128, "HMAC"),
        ("HMAC-SHA1-96", HashType::HMACSHA1_96, "<24 hex chars>", 96, "HMAC"),
        ("GPG", HashType::GPG, "-----BEGIN PGP...", 0, "Encryption"),
        ("PGP S2K", HashType::PGPS2K, "<salt>:<hash>", 0, "Encryption"),
        ("Lotus Notes 5", HashType::LotusNotes5, "<hex>:<salt>", 0, "Application"),
        ("MSSQL Old", HashType::MSSQLOld, "<hex>:<salt>", 0, "Database"),
        ("MySQL Old", HashType::MySQLOld1, "<16 hex chars>", 64, "Database"),
        ("PostgreSQL SCRAM-SHA-256", HashType::PostgreSQLSCRAMSHA256, "SCRAM-SHA-256$...", 256, "Database"),
        ("FreeRADIUS MD5", HashType::FreeRADIUSMD5, "<32 hex chars>", 128, "Application"),
        ("OpenVPN MD5", HashType::OpenVPNMD5, "<32 hex chars>", 128, "Application"),
        ("Digest-MD5", HashType::DigestMD5, "<32 hex chars>", 128, "Application"),
        ("AWS4-HMAC-SHA256", HashType::AWS4HMACSHA256, "<64 hex chars>", 256, "HMAC"),
        ("Ethereum Wallet", HashType::EthereumWallet, "0x...", 0, "Blockchain"),
        ("Ripple Wallet", HashType::RippleWallet, "r...", 0, "Blockchain"),
        ("Stellar", HashType::Stellar, "G...", 0, "Blockchain"),
        ("Cardano", HashType::Cardano, "addr...", 0, "Blockchain"),
        ("Polkadot", HashType::Polkadot, "1...", 0, "Blockchain"),
        ("Solana", HashType::Solana, "sol...", 0, "Blockchain"),
        ("WPA PBKDF2", HashType::WPAPBKDF2, "<64 hex chars>", 256, "WiFi"),
        ("WPA2 PMKID", HashType::WPA2PMKID, "<prefix>:<64 hex>", 256, "WiFi"),
        ("WPA3 SAE", HashType::WPA3SAE, "<64 hex chars>", 256, "WiFi"),
        ("iSCSI CHAP", HashType::iSCSI_CHAP, "<32 hex chars>", 128, "Application"),
        ("Python MD5", HashType::PythonMD5, "<32 hex chars>", 128, "Application"),
        ("RabbitMQ MD5", HashType::RabbitMQMD5, "<32 hex chars>", 128, "Application"),
        ("Redis MD5", HashType::RedisMD5, "<32 hex chars>", 128, "Application"),
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

// ── New Attack Commands ──────────────────────────────────────────────────

fn cmd_prince(detector: &Detector, hash_file: &str, wordlist: &str, _threads: usize, args: &Cli, _min_length: usize, _max_length: usize, _limit: Option<u64>, _session: Option<&str>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);
    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked"); return;
    }
    let cracker = &loaded[0].0;
    eprintln!("[*] PRINCE attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Wordlist  : {}", wordlist);
    let results = pwdcrack::attack::prince::run_prince(&mut hashes, cracker.as_ref(), wordlist, args.quiet);
    emit_results(&results, args, &potfile);
}

fn cmd_toggle_case(detector: &Detector, hash_file: &str, wordlist: &str, _threads: usize, args: &Cli, _max_toggle: usize, _limit: Option<u64>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);
    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked"); return;
    }
    let cracker = &loaded[0].0;
    eprintln!("[*] Toggle-case attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Wordlist  : {}", wordlist);
    let results = pwdcrack::attack::toggle::run_toggle(&mut hashes, cracker.as_ref(), wordlist, args.quiet);
    emit_results(&results, args, &potfile);
}

fn cmd_substitute(detector: &Detector, hash_file: &str, wordlist: &str, _threads: usize, args: &Cli, _level: u8, _limit: Option<u64>) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);
    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    filter_uncracked(args, &mut hashes);
    if hashes.is_empty() {
        eprintln!("[!] All hashes already cracked"); return;
    }
    let cracker = &loaded[0].0;
    eprintln!("[*] Substitution attack");
    eprintln!("[*] Hash type : {}", cracker.name());
    eprintln!("[*] Target    : {} hashes", hashes.len());
    eprintln!("[*] Wordlist  : {}", wordlist);
    let results = pwdcrack::attack::substitute::run_substitute(&mut hashes, cracker.as_ref(), wordlist, args.quiet);
    emit_results(&results, args, &potfile);
}

fn cmd_rules(wordlist: &str, rules_file: &str, output: Option<&str>, _limit: Option<u64>) {
    use std::io::{BufRead, Write};
    let rules_content = std::fs::read_to_string(rules_file).unwrap_or_else(|e| {
        eprintln!("[!] Failed to read rules file: {}", e); std::process::exit(1);
    });
    let rules: Vec<&str> = rules_content.lines().collect();
    let file = std::fs::File::open(wordlist).unwrap_or_else(|e| {
        eprintln!("[!] Failed to open wordlist: {}", e); std::process::exit(1);
    });
    let reader = std::io::BufReader::new(file);
    let mut out: Box<dyn Write> = match output {
        Some(path) => Box::new(std::fs::File::create(path).unwrap()),
        None => Box::new(std::io::stdout()),
    };
    for line in reader.lines() {
        let word = line.unwrap_or_default();
        for rule in &rules {
            let _ = writeln!(out, "{}:{}", rule, word);
        }
    }
    eprintln!("[*] Rules applied: {} rules × wordlist", rules.len());
}

fn cmd_stats(potfile_path: &str, _verbose: bool, _by_complexity: bool) {
    let potfile = Potfile::new(potfile_path);
    let entries = potfile.entries();
    println!("Potfile statistics: {}", potfile_path);
    println!("{:=<50}", "");
    println!("  Total entries  : {}", entries.len());
    if entries.is_empty() { return; }
    let _: Vec<_> = entries.iter().map(|(h, p)| {
        println!("  {}  →  {}", h, p);
    }).collect();
    println!("{:=<50}", "");
}

fn cmd_expand(mask: &str, charsets: &[Option<String>], limit: u64) {
    use pwdcrack::attack::brute::{parse_mask, index_to_password, total_combinations};
    let custom_slices: Vec<&[u8]> = charsets.iter()
        .filter_map(|c| c.as_ref().map(|s| s.as_bytes()))
        .collect();
    let parsed = parse_mask(mask);
    let total = total_combinations(&parsed, &custom_slices);
    let show = limit.min(total).min(1_000_000);
    eprintln!("Mask: {}  (keyspace: {}, showing {})", mask, total, show);
    for i in 0..show {
        println!("{}", index_to_password(i, &parsed, &custom_slices));
    }
}

fn cmd_check(detector: &Detector, hash_file: &str, _verbose: bool, clean: bool) {
    let content = match std::fs::read_to_string(hash_file) {
        Ok(s) => s,
        Err(e) => { eprintln!("[!] Failed to read: {}", e); return; }
    };
    let mut valid = 0u32;
    let mut invalid = 0u32;
    let mut cleaned = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if let Some((_, _)) = detector.detect(trimmed) {
            valid += 1;
            cleaned.push_str(line);
            cleaned.push('\n');
        } else {
            invalid += 1;
            eprintln!("[!] Invalid: {}", trimmed);
        }
    }
    println!("  Valid: {}  Invalid: {}", valid, invalid);
    if clean && invalid > 0 {
        let cleaned_path = format!("{}.clean", hash_file);
        std::fs::write(&cleaned_path, &cleaned).unwrap_or_else(|e| {
            eprintln!("[!] Failed to write cleaned file: {}", e);
        });
        println!("  Cleaned file written: {}", cleaned_path);
    }
}

fn cmd_suggest(detector: &Detector, hash: &str) {
    match detector.detect(hash) {
        Some((cracker, entry)) => {
            let ht = cracker.hash_type();
            let bits = ht.bit_length().unwrap_or(0);
            println!("Hash  : {}", hash);
            println!("Type  : {} ({} bit)", cracker.name(), if bits > 0 { bits.to_string() } else { "var".into() });

            println!("\n⚡ Suggested attacks:");
            println!("{:=<60}", "");

            let is_slow = matches!(ht, HashType::BCrypt | HashType::BCryptA
                | HashType::Argon2i | HashType::Argon2d | HashType::Argon2id | HashType::Scrypt
                | HashType::PBKDF2SHA256 | HashType::PBKDF2SHA512 | HashType::PBKDF2SHA1
                | HashType::PBKDF2SHA384 | HashType::PBKDF2SHA224
                | HashType::PHPASS | HashType::DRUPAL7 | HashType::MACOSPBKDF2
                | HashType::SUNMD5 | HashType::BSDICRYPT
                | HashType::HMACSHA256 | HashType::HMACSHA512 | HashType::HMACSHA1 | HashType::HMACMD5
                | HashType::HMACSHA224 | HashType::HMACSHA384 | HashType::HMACRIPEMD160
                | HashType::HMACSHA512_224 | HashType::HMACSHA512_256
                | HashType::HMACSHA3224 | HashType::HMACSHA3256 | HashType::HMACSHA3384 | HashType::HMACSHA3512
                | HashType::HMACBLAKE2B256 | HashType::HMACBLAKE2S256 | HashType::HMACBLAKE2B512
                | HashType::HMACRIPEMD128 | HashType::HMACRIPEMD256 | HashType::HMACRIPEMD320
                | HashType::HMACWHIRLPOOL | HashType::HMACSTREEBOG256 | HashType::HMACSTREEBOG512
                | HashType::HMACGOST94 | HashType::HMACTIGER | HashType::GOST94HMAC
                | HashType::HMACBLAKE2B224 | HashType::HMACBLAKE2B384);
            let is_medium = matches!(ht, HashType::SHA512 | HashType::SHA384
                | HashType::SHA256 | HashType::SHA512Crypt
                | HashType::SHA3512 | HashType::WHIRLPOOL
                | HashType::STREEBOG512 | HashType::STREEBOG256
                | HashType::JH512 | HashType::JH384 | HashType::SKEIN512
                | HashType::SHABAL512 | HashType::BLAKE2B512 | HashType::BLAKE2B384
                | HashType::SALTEDSHA512 | HashType::SALTEDSHA384 | HashType::SALTEDSHA256
                | HashType::SSHA256 | HashType::SSHA1 | HashType::SHA256CRYPTROUNDS
                | HashType::SALTEDSHA3512 | HashType::SALTEDSHA3256
                | HashType::PBKDF2SHA384 | HashType::PBKDF2SHA224);
            let is_fast = !is_slow && !is_medium;
            let has_gpu_accel = matches!(ht, HashType::MD5 | HashType::NTLM
                | HashType::SHA1 | HashType::SHA256 | HashType::SHA224
                | HashType::MD4 | HashType::MD2
                | HashType::CRC32 | HashType::CRC64 | HashType::CRC16 | HashType::CRC32C
                | HashType::CRC8 | HashType::CRC8ITU | HashType::CRC16CCITT | HashType::CRC16MODBUS
                | HashType::CRC32BZIP2 | HashType::CRC32MPEG2 | HashType::CRC64ECMA | HashType::CRC24
                | HashType::ADLER32 | HashType::XXHASH32
                | HashType::LM | HashType::NTLMV1
                | HashType::DOUBLEMD5 | HashType::DOUBLESHA1 | HashType::DOUBLESHA256
                | HashType::TRIPLEMD5 | HashType::MD5HALF
                | HashType::MYSQL41 | HashType::MYSQL321
                | HashType::POSTGRESQL | HashType::OSCOMMERCE | HashType::VBULLETIN3 | HashType::VBULLETIN5
                | HashType::SMF | HashType::IPB2 | HashType::IPB3);

            let speed_str = if is_slow {
                if matches!(ht, HashType::BCrypt | HashType::BCryptA) { "~1 K/s" }
                else if matches!(ht, HashType::Argon2i | HashType::Argon2d | HashType::Argon2id | HashType::Scrypt) { "~100 H/s" }
                else { "~10 K/s" }
            } else if is_medium { "~500 K/s" } else { "> 10 M/s" };

            println!("  🏆  Dictionary + rules    ({})", speed_str);
            if is_fast && bits <= 128 {
                println!("  🥈  Brute-force mask       (up to 8 chars recommended)");
                println!("  🥉  Combinator             (if two wordlists available)");
            } else if is_fast && bits > 128 && bits <= 256 {
                println!("  🥈  Brute-force mask       (up to 6 chars recommended)");
            }
            if has_gpu_accel {
                println!("  ⚡  GPU/FPGA/Warp acceleration supported");
            }
            if is_slow {
                println!("  🔒  Slow/iterated hash — GPU resistance is high, focus on targeted dictionary");
            }
            if bits >= 256 && !is_fast {
                println!("  🔒  256+ bit — dictionary + rules is most efficient per watt");
            }

            // Domain-specific advice
            if matches!(ht, HashType::NTLM | HashType::LM | HashType::NTLMV1 | HashType::NTLMV2
                | HashType::DCC1 | HashType::DCC2 | HashType::DCC3) {
                println!("  💻  Windows credential — try patterns: P@ssw0rd, Welcome1, Admin123");
            }
            if matches!(ht, HashType::MD5Crypt | HashType::SHA256Crypt | HashType::SHA512Crypt
                | HashType::SHA256CRYPTROUNDS) {
                println!("  🐧  Unix shadow — try Linux patterns: seasonal + year + special");
            }
            if matches!(ht, HashType::PHPASS | HashType::DRUPAL7 | HashType::EPI
                | HashType::PUNBB | HashType::IPB2 | HashType::IPB3 | HashType::VBULLETIN3
                | HashType::VBULLETIN5 | HashType::SMF | HashType::MEDIAWIKI) {
                println!("  🌐  CMS/Forum — try site-related keywords + common passwords");
            }
            if matches!(ht, HashType::MYSQL41 | HashType::MYSQL321 | HashType::POSTGRESQL
                | HashType::ORACLE10G | HashType::ORACLE11G | HashType::ORACLE7
                | HashType::MSSQL2005 | HashType::MSSQL2012) {
                println!("  🗄️   Database — try admin/service account patterns");
            }
            if matches!(ht, HashType::SAPCODVNB | HashType::SAPCODVNFG) {
                println!("  🏢  SAP — try default SAP* passwords, company-related terms");
            }
            if matches!(ht, HashType::LOTUSNOTES | HashType::NSLDAP) {
                println!("  📧  Enterprise — try organizational patterns,季节+year");
            }
            if matches!(ht, HashType::SKIP32 | HashType::XXHASH32 | HashType::CRC24) {
                println!("  🔧  Checksum/Light — NOT a cryptographic hash, trivial to invert");
            }
            if matches!(ht, HashType::PLAINTEXT | HashType::CHALLENGE | HashType::CRAMMD5) {
                println!("  🪪  Identity/Challenge — password == raw or derived from challenge");
            }
            if matches!(ht, HashType::SNEFRU128 | HashType::SNEFRU256 | HashType::GOST94256 | HashType::GOST94512) {
                println!("  📜  Legacy hash — limited cracking resources available");
            }

            if let Some(ref salt) = entry.salt {
                println!("\n  Salt: {}", salt);
            }
            if let Some(ref username) = entry.username {
                println!("  User: {}", username);
            }
            println!("{:=<60}", "");
            println!("  For GPU acceleration: pwdcrack --gpu <command>");
            println!("  For FPGA:           pwdcrack --fpga <command>");
        }
        None => {
            eprintln!("[!] Unknown hash format: {}", hash);
            eprintln!("    Run 'pwdcrack list' to see supported types");
        }
    }
}
