use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Benchmark hash verification throughput for raw MD5, SHA1, SHA256, NTLM.
/// This measures how many hashes per second the core library can verify.

fn bench_md5_verify(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();
    let (_cracker, entry) = d.detect("5d41402abc4b2a76b9719d911017c592").unwrap();

    c.bench_function("md5_verify", |b| {
        b.iter(|| {
            black_box(_cracker.verify(black_box("hello"), black_box(&entry)));
        })
    });
}

fn bench_sha1_verify(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();
    let (_cracker, entry) = d.detect("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();

    c.bench_function("sha1_verify", |b| {
        b.iter(|| {
            black_box(_cracker.verify(black_box("hello"), black_box(&entry)));
        })
    });
}

fn bench_sha256_verify(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();
    let h = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let (_cracker, entry) = d.detect(h).unwrap();

    c.bench_function("sha256_verify", |b| {
        b.iter(|| {
            black_box(_cracker.verify(black_box("hello"), black_box(&entry)));
        })
    });
}

fn bench_ntlm_verify(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();
    let (_cracker, entry) = d.detect("$NT$066ddfd4ef0e9cd7c256fe77191ef43c").unwrap();

    c.bench_function("ntlm_verify", |b| {
        b.iter(|| {
            black_box(_cracker.verify(black_box("hello"), black_box(&entry)));
        })
    });
}

fn bench_bcrypt_verify(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();
    let h = "$2b$04$2WYyN.eiXbyOO340HLSZYOh7.Nag8klMznoYg9ishyhAaURBnrgPi";
    let (_cracker, entry) = d.detect(h).unwrap();

    c.bench_function("bcrypt_verify_cost4", |b| {
        b.iter(|| {
            black_box(_cracker.verify(black_box("password"), black_box(&entry)));
        })
    });
}

fn bench_detect_hash(c: &mut Criterion) {
    let d = pwdcrack::hash::detector::Detector::new();

    c.bench_function("detect_md5", |b| {
        b.iter(|| {
            black_box(d.detect(black_box("5d41402abc4b2a76b9719d911017c592")));
        })
    });

    c.bench_function("detect_sha256", |b| {
        b.iter(|| {
            let h = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
            black_box(d.detect(black_box(h)));
        })
    });
}

criterion_group!(
    benches,
    bench_md5_verify,
    bench_sha1_verify,
    bench_sha256_verify,
    bench_ntlm_verify,
    bench_bcrypt_verify,
    bench_detect_hash,
);
criterion_main!(benches);
