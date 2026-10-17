//! The distributed mask expander must agree with the local one, candidate for
//! candidate.
//!
//! `engines/engine-distributed/src/mask.rs` is a second copy of
//! `src/attack/mask.rs`. It has to be a copy: `engine-distributed` is a
//! dependency of the root crate, so it cannot depend on the root crate, and a
//! worker in another process cannot reach the root crate's code.
//!
//! A copy is only safe while a test proves the two have not drifted. That is
//! this file. It walks a corpus of masks, including every token form and the
//! malformed ones, and asserts that the keyspace and every candidate match.
//!
//! Run with: cargo test --features engine-distributed --test distributed_mask_agreement

use engine_distributed::mask::{Mask as DistMask, MAX_KEYSPACE as DIST_MAX};
use pwdcrack::attack::mask::{Mask as RootMask, MAX_KEYSPACE as ROOT_MAX};

/// One mask plus the custom charsets to expand it with.
struct Case {
    spec: &'static str,
    custom: Vec<Option<Vec<u8>>>,
}

fn no_custom() -> Vec<Option<Vec<u8>>> {
    vec![]
}

fn cases() -> Vec<Case> {
    vec![
        Case { spec: "?l", custom: no_custom() },
        Case { spec: "?u", custom: no_custom() },
        Case { spec: "?d", custom: no_custom() },
        Case { spec: "?s", custom: no_custom() },
        Case { spec: "?a", custom: no_custom() },
        Case { spec: "?h", custom: no_custom() },
        Case { spec: "?H", custom: no_custom() },
        Case { spec: "?w", custom: no_custom() },
        Case { spec: "?l?l", custom: no_custom() },
        Case { spec: "?u?l?d?d", custom: no_custom() },
        Case { spec: "?d?d?d?d?d", custom: no_custom() },
        Case { spec: "?b?b", custom: no_custom() },
        Case { spec: "admin?d", custom: no_custom() },
        Case { spec: "x?l!y", custom: no_custom() },
        Case { spec: "?l?d?l?d", custom: no_custom() },
        Case { spec: "[?u?l]?d", custom: no_custom() },
        Case { spec: "[?d?s]", custom: no_custom() },
        Case { spec: "(?abc)", custom: no_custom() },
        Case { spec: "(?abc)?d", custom: no_custom() },
        Case { spec: "\\?l", custom: no_custom() },
        Case { spec: "\\!l", custom: no_custom() },
        Case { spec: "P@ss?d?d!word", custom: no_custom() },
        Case {
            spec: "?1?2",
            custom: vec![Some(b"ABC".to_vec()), Some(b"xyz".to_vec()), None, None],
        },
        Case {
            spec: "?1?d?1",
            custom: vec![Some(b"<>".to_vec()), None, None, None],
        },
        Case {
            spec: "?2?2?2?2",
            custom: vec![Some(b"0123456789".to_vec()), None, None, None],
        },
        // Keyspaces at and beyond the ceiling.
        Case { spec: "?b?b?b?b?b?b?b?b", custom: no_custom() },
        Case { spec: "?b?b?b?b?b?b?b?b?b", custom: no_custom() },
        Case { spec: "?b?b?b?b?b?b?b?b?b?b", custom: no_custom() },
        // Malformed. Both must reject, and with the same reason.
        Case { spec: "", custom: no_custom() },
        Case { spec: "?", custom: no_custom() },
        Case { spec: "?q", custom: no_custom() },
        Case { spec: "?5", custom: no_custom() },
        Case { spec: "(?ab", custom: no_custom() },
        Case { spec: "[?u?l", custom: no_custom() },
        Case { spec: "()", custom: no_custom() },
        Case { spec: "[]", custom: no_custom() },
        Case { spec: "[?q]", custom: no_custom() },
        Case { spec: "trailing\\", custom: no_custom() },
    ]
}

/// How many candidate indices to compare for a mask.
///
/// The whole keyspace is not enumerable for a large mask, so the first few and a
/// spread of later indices are compared. Indices beyond the keyspace are
/// included deliberately: both implementations document that they do not validate
/// the index, so they must at least wrap the same way.
fn probes(keyspace: u128) -> Vec<u128> {
    let n = keyspace.min(4096);
    let mut out: Vec<u128> = (0..n).collect();
    for i in 1..64u128 {
        let idx = i.wrapping_mul(keyspace / 64).max(i);
        if !out.contains(&idx) {
            out.push(idx);
        }
    }
    // And a few past the end, which both must render identically.
    for i in 1..8u128 {
        out.push(keyspace + i);
    }
    out
}

#[test]
fn both_implementations_parse_or_reject_the_same_masks() {
    for c in cases() {
        let root = RootMask::parse(c.spec, &c.custom);
        let dist = DistMask::parse(c.spec, &c.custom);
        match (&root, &dist) {
            (Ok(_), Ok(_)) => {}
            (Err(a), Err(b)) => assert_eq!(
                format!("{a}"),
                format!("{b}"),
                "mask {:?}: both must reject, with the same reason",
                c.spec
            ),
            _ => panic!(
                "mask {:?}: one accepted and the other did not (root={:?}, distributed={:?})",
                c.spec,
                root.map(|_| "ok"),
                dist.map(|_| "ok")
            ),
        }
    }
}

#[test]
fn both_implementations_report_the_same_keyspace() {
    for c in cases() {
        let root = RootMask::parse(c.spec, &c.custom);
        let dist = DistMask::parse(c.spec, &c.custom);
        if let (Ok(r), Ok(d)) = (root, dist) {
            assert_eq!(
                r.keyspace(&c.custom).ok(),
                d.keyspace(&c.custom).ok(),
                "mask {:?}: keyspace differs",
                c.spec
            );
        }
    }
}

#[test]
fn both_implementations_produce_the_same_candidates() {
    for c in cases() {
        let Ok(root) = RootMask::parse(c.spec, &c.custom) else {
            continue;
        };
        let Ok(dist) = DistMask::parse(c.spec, &c.custom) else {
            continue;
        };
        let keyspace = root.keyspace(&c.custom).unwrap();
        for i in probes(keyspace) {
            let a = root.candidate(i, &c.custom);
            let b = dist.candidate(i, &c.custom);
            assert_eq!(
                a.is_ok(),
                b.is_ok(),
                "mask {:?} index {i}: one produced a candidate and the other did not",
                c.spec
            );
            if let (Ok(a), Ok(b)) = (a, b) {
                assert_eq!(a, b, "mask {:?} index {i}: candidates differ", c.spec);
            }
            let a = root.candidate_string(i, &c.custom);
            let b = dist.candidate_string(i, &c.custom);
            assert_eq!(a.is_ok(), b.is_ok(), "mask {:?} index {i}: string form differs", c.spec);
            if let (Ok(a), Ok(b)) = (a, b) {
                assert_eq!(a, b, "mask {:?} index {i}: strings differ", c.spec);
            }
        }
    }
}

#[test]
fn both_implementations_refuse_the_same_keyspace_ceiling() {
    assert_eq!(
        DIST_MAX, ROOT_MAX,
        "the u64 addressable ceiling moved in one copy and not the other"
    );
    for spec in ["?b?b?b?b?b?b?b?b?b", "?b?b?b?b?b?b?b?b?b?b"] {
        let root = RootMask::parse(spec, &[]).unwrap().keyspace(&[]).unwrap();
        let dist = DistMask::parse(spec, &[]).unwrap().keyspace(&[]).unwrap();
        assert_eq!(root, dist, "mask {spec}: keyspace differs");
        assert!(root > ROOT_MAX, "{spec} should exceed the ceiling");
        assert!(
            DistMask::parse(spec, &[]).unwrap().keyspace_u64(&[]).is_err(),
            "{spec}: the distributed copy must refuse a keyspace it cannot address"
        );
        assert!(
            RootMask::parse(spec, &[]).unwrap().keyspace_u64(&[]).is_err(),
            "{spec}: the local copy must refuse it too"
        );
        // And both must agree about the boundary itself.
        assert_eq!(
            RootMask::parse("?b?b?b?b?b?b?b", &[]).unwrap().keyspace_u64(&[]).ok(),
            DistMask::parse("?b?b?b?b?b?b?b", &[]).unwrap().keyspace_u64(&[]).ok(),
            "the two copies disagree about the largest addressable keyspace"
        );
    }
}

/// A sanity check on the corpus itself: if every mask were rejected the
/// candidate test above would pass while comparing nothing.
#[test]
fn the_corpus_actually_contains_masks_that_parse() {
    let parsed = cases()
        .iter()
        .filter(|c| RootMask::parse(c.spec, &c.custom).is_ok())
        .count();
    let rejected = cases().len() - parsed;
    assert!(parsed >= 25, "only {parsed} of the corpus parses");
    assert!(rejected >= 8, "only {rejected} of the corpus is malformed");
}

/// A sanity check on the probe generator: the candidate test must be looking at
/// a spread of indices, not just the first few.
#[test]
fn the_probe_generator_spans_the_keyspace() {
    let keyspace = 1_000_000u128;
    let p = probes(keyspace);
    assert!(p.contains(&0), "no probe at the start");
    assert!(
        p.iter().any(|i| *i > keyspace / 2 && *i < keyspace),
        "no probe in the second half of the keyspace"
    );
    assert!(
        p.iter().any(|i| *i >= keyspace),
        "no probe past the end, which both implementations must also agree on"
    );
    assert!(
        p.iter().all(|i| *i < keyspace + 8),
        "a probe escaped the range the implementations wrap in"
    );
    assert!(p.len() > 100, "only {} probes", p.len());

    // A tiny keyspace is enumerated exhaustively plus the overflow probes.
    let small = probes(3);
    assert!(small.contains(&0) && small.contains(&1) && small.contains(&2));
    assert!(small.contains(&4), "no overflow probe for a small keyspace");
}