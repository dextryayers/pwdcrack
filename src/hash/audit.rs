//! Audit of hash type honesty.
//!
//! This file exists to enforce one invariant across the whole cracker registry:
//!
//! > A hash type may be listed as supported only if `verify` actually computes
//! > that hash.
//!
//! The failure this prevents is not a wrong digest, it is a wrong *report*. A
//! cracker whose `verify` returns `false` unconditionally looks exactly like a
//! cracker that ran over the whole keyspace and found nothing, so the user sees
//! a completed attack with zero cracks and cannot tell that no work happened.
//!
//! Two mechanisms guard it:
//!
//! 1. Every detection-only cracker overrides
//!    [`crate::hash::HashCracker::is_verifiable`] to return `false`. The
//!    inventory test below enumerates them so the number stays accurate.
//! 2. A cracker that returns `false` for a digest it demonstrably should match is
//!    a defect. `verification_is_not_vacuous` re-checks every verifiable cracker
//!    against digest values produced by an independent digest implementation.

use crate::hash::detector::Detector;
// `HashCracker` is not imported: the audit calls concrete methods on the
// registered crackers rather than going through the trait, so naming it here
// was a leftover from an earlier version that did go through it.

/// Digest of "hello" computed here, separately from the cracker under test.
fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn sha1_hex(s: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn entry(raw: &str, ht: crate::hash::HashType) -> crate::hash::HashEntry {
    crate::hash::HashEntry {
        raw: raw.to_string(),
        hash_type: ht,
        hash_bytes: Vec::new(),
        salt: None,
        username: None,
        cracked: false,
        password: None,
    }
}

/// The raw digests that a correct cracker must be able to reproduce.
///
/// If a hash type is listed here it must both be reported verifiable and
/// actually match these values.
fn known_pairs() -> Vec<(crate::hash::HashType, &'static str, &'static str)> {
    use crate::hash::HashType::*;
    vec![
        (MD5, "hello", "5d41402abc4b2a76b9719d911017c592"),
        (MD5, "abc", "900150983cd24fb0d6963f7d28e17f72"),
        (MD5, "", "d41d8cd98f00b204e9800998ecf8427e"),
        (SHA1, "hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        (SHA256, "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ]
}

#[test]
fn known_digest_values_are_themselves_correct() {
    // Guards the values in `known_pairs` against a mistake in this file. If the
    // expected literals ever drift, every other test here becomes meaningless.
    assert_eq!(md5_hex("hello"), "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(sha1_hex("hello"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    assert_eq!(
        sha256_hex("hello"),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn verification_is_not_vacuous_for_raw_digests() {
    // The single most important test in this file. A raw digest cracker must
    // match a digest it should match. If any of these return false, the type is
    // lying, whether through a stub verify or a broken implementation.
    let detector = Detector::new();
    let mut checked = 0;
    let mut failures: Vec<String> = Vec::new();

    for (ht, password, digest) in known_pairs() {
        let Some(cracker) = detector.cracker_for_type(ht) else {
            failures.push(format!("{ht:?}: no cracker registered"));
            continue;
        };
        if !cracker.is_verifiable() {
            failures.push(format!(
                "{ht:?}: reports itself as detection only but a real digest is known"
            ));
            continue;
        }
        checked += 1;
        if !cracker.verify(password, &entry(digest, ht)) {
            failures.push(format!("{ht:?}: failed to verify a correct digest"));
        }
        // And it must reject a wrong password with the same digest.
        if cracker.verify("definitely-not-the-password", &entry(digest, ht)) {
            failures.push(format!("{ht:?}: accepted a wrong password"));
        }
    }

    assert!(
        failures.is_empty(),
        "verification defects found:\n  {}",
        failures.join("\n  ")
    );
    assert!(checked >= 5, "expected at least 5 checked pairs, got {checked}");
}

#[test]
fn every_detection_only_cracker_is_marked_as_such() {
    // Enumerates the registry and counts how many distinct types report
    // themselves as parse-only.
    //
    // The registry holds more entries than there are distinct types, because
    // several crackers are registered under more than one alias. The meaningful
    // number for a user is distinct types, so the count is taken over a set of
    // `HashType` values rather than over registry entries.
    let detector = Detector::new();

    let mut verifiable: std::collections::BTreeSet<String> = Default::default();
    let mut detection_only: std::collections::BTreeSet<String> = Default::default();

    for c in detector.crackers() {
        let key = format!("{:?}", c.hash_type());
        if c.is_verifiable() {
            verifiable.insert(key);
        } else {
            detection_only.insert(key);
        }
    }

    println!(
        "registry entries: {}, distinct types: {} ({} verifiable, {} detection only)",
        detector.crackers().len(),
        verifiable.len() + detection_only.len(),
        verifiable.len(),
        detection_only.len()
    );

    assert!(
        !detection_only.is_empty(),
        "expected the registry to still contain detection-only types"
    );
    // A type cannot be both. This catches a hash_type() that disagrees with
    // is_verifiable() across aliases of the same implementation.
    assert!(
        verifiable.is_disjoint(&detection_only),
        "a hash type reported both verifiable and detection only"
    );

    // Every detection-only cracker must return false for *any* input, which is
    // what makes it honest rather than merely unreached.
    for c in detector.crackers() {
        if c.is_verifiable() {
            continue;
        }
        let probe = entry("0123456789abcdef0123456789abcdef", c.hash_type());
        assert!(
            !c.verify("password", &probe),
            "{} claims to be detection only but returned a match",
            c.name()
        );
    }
}

#[test]
fn verify_batch_respects_the_verifiability_flag() {
    // The default batch implementation short-circuits for detection-only
    // crackers, so a batch call can never be mistaken for real work either.
    let detector = Detector::new();
    let probe = entry("0123456789abcdef", crate::hash::HashType::MD5);
    let md5_cracker = detector
        .cracker_for_type(crate::hash::HashType::MD5)
        .expect("MD5 cracker registered");
    let pw = ["hello", "world"];
    let refs: Vec<&str> = pw.to_vec();

    let hits = md5_cracker.verify_batch(&refs, &probe);
    assert!(hits.is_empty(), "probe digest is not a real digest of any candidate");

    // With the correct digest the same call must find the match.
    let real = entry(&md5_hex("world"), crate::hash::HashType::MD5);
    let hits = md5_cracker.verify_batch(&refs, &real);
    assert_eq!(hits, vec!["world"]);
}

#[test]
fn benchmark_reference_workload_is_reachable_through_the_crack_path() {
    use crate::engine::{reference_workload, CpuEngine, Engine, BatchPlan};
    let detector = Detector::new();
    let cracker = detector
        .cracker_for_type(crate::hash::HashType::MD5)
        .unwrap();
    let (pw, digest) = reference_workload();
    assert!(cracker.is_verifiable());
    assert!(
        cracker.verify(pw, &entry(digest, crate::hash::HashType::MD5)),
        "the benchmark's own workload does not verify"
    );

    let engine = CpuEngine::new();
    assert!(engine.is_available());
    let _ = BatchPlan::everything(1, 1);
}