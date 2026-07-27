mod cli;
mod hash;
mod attack;
mod potfile;

use clap::Parser;
use cli::{Cli};
use cli::args::Commands;
use hash::{HashCracker, HashEntry, HashType};
use hash::detector::Detector;
use attack::CrackResult;
use potfile::Potfile;

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

    match &args.command {
        Commands::Identify { hash_file } => cmd_identify(&detector, hash_file),
        Commands::Dictionary { hash_file, wordlist, rules, skip_self: _ } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::MemoryBound);
            }
            cmd_dictionary(&detector, hash_file, wordlist, rules.as_deref(), threads, &args);
        }
        Commands::BruteForce { hash_file, mask, charset1, charset2, charset3, charset4 } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::ComputeBound);
            }
            cmd_bruteforce(&detector, hash_file, mask, &[charset1.clone(), charset2.clone(), charset3.clone(), charset4.clone()], threads, &args);
        }
        Commands::Combinator { hash_file, wordlist1, wordlist2 } => {
            #[cfg(feature = "engine-power")]
            if let Some(ref pm) = _power_mgr {
                pm.set_workload(engine_power::WorkloadType::Mixed);
            }
            cmd_combinator(&detector, hash_file, wordlist1, wordlist2, threads, &args);
        }
        Commands::Benchmark { hash_type } => cmd_benchmark(&detector, hash_type, threads, args.quiet),
        Commands::Show { potfile, show_type } => cmd_show(potfile, *show_type),
    }

    #[cfg(feature = "engine-android")]
    _android_engine.shutdown();
}

fn load_hashes(detector: &Detector, path: &str) -> Vec<(Box<dyn HashCracker>, HashEntry)> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("[!] Failed to read hash file: {}", e);
        std::process::exit(1);
    });

    let mut results = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match detector.detect(trimmed) {
            Some((cracker, entry)) => results.push((cracker, entry)),
            None => {
                eprintln!("[!] Unknown hash format: {}", trimmed);
            }
        }
    }

    if results.is_empty() {
        eprintln!("[!] No valid hashes found in {}", path);
        std::process::exit(1);
    }

    results
}

fn cmd_identify(detector: &Detector, path: &str) {
    let results = detector.identify(path);
    if results.is_empty() {
        eprintln!("[!] No hashes found in {}", path);
        return;
    }
    println!("Hash identification for {}:", path);
    println!("{:-<60}", "");
    let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, ht) in &results {
        *by_type.entry(ht.name().to_string()).or_insert(0) += 1;
    }
    for (name, count) in &by_type {
        println!("  {:20} : {}", name, count);
    }
    println!("{:-<60}", "");
    println!("  Total: {} hashes", results.len());
}

fn cmd_dictionary(detector: &Detector, hash_file: &str, wordlist: &str, rules: Option<&str>, threads: usize, args: &Cli) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &loaded[0].0;

    eprintln!("[*] Starting dictionary attack");
    eprintln!("[*] Hash type: {}", cracker.name());
    eprintln!("[*] Threads: {}", threads);

    let results = attack::dictionary::run_dictionary(
        &mut hashes, cracker.as_ref(), wordlist, rules, threads, args.quiet,
    );

    print_results(&results, &potfile);
}

fn cmd_bruteforce(detector: &Detector, hash_file: &str, mask: &str, charsets: &[Option<String>], threads: usize, args: &Cli) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &loaded[0].0;

    eprintln!("[*] Starting brute-force attack");
    eprintln!("[*] Hash type: {}", cracker.name());
    eprintln!("[*] Mask: {}", mask);

    let results = attack::brute::run_bruteforce(
        &mut hashes, cracker.as_ref(), mask, charsets, threads, args.quiet,
    );

    print_results(&results, &potfile);
}

fn cmd_combinator(detector: &Detector, hash_file: &str, wl1: &str, wl2: &str, threads: usize, args: &Cli) {
    let potfile = Potfile::new(&args.potfile);
    let loaded = load_hashes(detector, hash_file);

    let mut hashes: Vec<HashEntry> = loaded.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &loaded[0].0;

    eprintln!("[*] Starting combinator attack");
    eprintln!("[*] Hash type: {}", cracker.name());

    let results = attack::combinator::run_combinator(
        &mut hashes, cracker.as_ref(), wl1, wl2, threads, args.quiet,
    );

    print_results(&results, &potfile);
}

fn cmd_benchmark(detector: &Detector, hash_type: &str, threads: usize, _quiet: bool) {
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
            return;
        }
        found
    };

    println!("Benchmark ({} threads):", threads);
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

        let iterations = 100_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = cracker.verify(test_pass, &entry);
        }
        let elapsed = start.elapsed();
        let per_sec = iterations as f64 / elapsed.as_secs_f64();
        println!("  {:20} : {:>8.0} H/s", cracker.name(), per_sec);

        // SIMD batch verify benchmark
        #[cfg(feature = "engine-simd")]
        {
            let batch_passwords: Vec<&[u8]> = (0..1000).map(|_| test_pass.as_bytes()).collect();
            let batch_targets: Vec<&str> = (0..1000).map(|_| test_hash.as_str()).collect();
            let bstart = Instant::now();
            let simd_results = engine_simd::dispatch::sha256_batch_verify(
                &batch_passwords, &batch_targets,
            );
            let belapsed = bstart.elapsed();
            if simd_results.len() == 1000 {
                let bps = 1000.0 / belapsed.as_secs_f64();
                println!("  {:20} : {:>8.0} H/s (SIMD batch)", cracker.name(), bps);
            }
        }
    }
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
        HashType::SHA512 => {
            let mut h = Sha512::new();
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

fn cmd_show(potfile_path: &str, show_type: bool) {
    let potfile = Potfile::new(potfile_path);
    let entries = potfile.entries();

    if entries.is_empty() {
        eprintln!("[!] No entries in potfile: {}", potfile_path);
        return;
    }

    println!("Cracked passwords:");
    println!("{:-<60}", "");
    for (hash, password) in &entries {
        if show_type {
            let detector = Detector::new();
            if let Some((cracker, _)) = detector.detect(hash) {
                println!("{}:{} [{}]", hash, password, cracker.name());
                continue;
            }
        }
        println!("{}:{}", hash, password);
    }
}

fn print_results(results: &[CrackResult], potfile: &Potfile) {
    if results.is_empty() {
        eprintln!("[-] No passwords cracked.");
        return;
    }

    println!("\nCracked passwords:");
    println!("{:-<60}", "");
    for r in results {
        if let Some(ref pw) = r.password {
            println!("{}:{} [{}]", r.original, pw, r.hash_type);
            potfile.save(&r.original, pw);
        }
    }
}
