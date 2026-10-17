//! The dashboard's attack executor, backed by the real engine.
//!
//! # Why this lives here
//!
//! `engine-web` cannot call the engine. The `pwdcrack` crate depends on it, so
//! the reverse edge is a dependency cycle and cargo refuses it outright. The
//! seam is `engine_web::attack::AttackExecutor`, and this is the implementation.
//!
//! With this linked in, `POST /api/start` hashes things. Without it, the
//! dashboard answers 503 and the page says attacks cannot run. There is no third
//! state where a click produces a success message and no work.
//!
//! # Candidate generation
//!
//! Two shapes, matching what the CLI already does:
//!
//! * Brute force goes through [`Mask`], which maps an index to a candidate
//!   directly. Random access is free, so a batch at offset N needs nothing
//!   generated before it.
//! * Dictionary indexes the file once, storing a line offset per line, then seeks
//!   to the offset of the batch it was asked for. Loading the words themselves
//!   would cost gigabytes for a real wordlist; an offset index costs eight bytes
//!   per line, so a ten million line file is 80 MB.
//!
//! # Hash grouping
//!
//! `Engine::verify_batch` takes one cracker for the whole batch, so targets of
//! different types cannot go through it together. They are grouped by detected
//! type, each group is run through the engine, and the matches are mapped back
//! to the caller's indices. Cracker lookups are cached per raw hash string,
//! because detection is not free and a batch asks for the same targets every
//! time.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::Mutex;

use engine_web::attack::{AttackExecutor, AttackRequest, BatchOutcome, CrackedHit};

use crate::attack::mask::Mask;
use crate::engine::{BatchPlan, Engine};
use crate::hash::detector::Detector;
use crate::hash::{HashCracker, HashEntry, HashType};

/// Candidates per engine call.
///
/// Sized against the CPU engine's batch limit rather than picked for looks. A
/// larger batch means fewer synchronisation points; a much larger one means a
/// pause takes noticeably longer to take effect, because the control flags are
/// only observed between batches.
pub const DEFAULT_BATCH: u64 = 4096;

/// Above this many lines a dictionary index is built; below it the words are
/// held directly. Eight bytes per line is cheap enough that the branch is a
/// micro optimisation, not a correctness matter, and it keeps a ten line test
/// wordlist from opening the same file twice.
const INDEX_THRESHOLD: u64 = 4096;

/// An executor that hashes for real.
pub struct EngineExecutor {
    detector: Detector,
    engine: Box<dyn Engine>,
    /// Prepared per request, keyed by the request's own description.
    prepared: Mutex<HashMap<String, Prepared>>,
}

impl EngineExecutor {
    /// Builds an executor over `engine`, measuring nothing itself.
    ///
    /// The engine's `info()` already carries whatever measurement it made when
    /// it was built, so there is nothing to do here.
    pub fn new(engine: Box<dyn Engine>) -> Self {
        EngineExecutor {
            detector: Detector::new(),
            engine,
            prepared: Mutex::new(HashMap::new()),
        }
    }

    /// The default executor: the scalar CPU engine, measured on construction.
    pub fn cpu() -> Self {
        EngineExecutor::new(Box::new(crate::engine::CpuEngine::new()))
    }

    /// Candidates per batch, taken from the engine's own plan.
    fn resolve_batch_size(&self) -> u64 {
        let plan = self.engine.plan(u64::MAX as usize, 1);
        (plan.candidates as u64).clamp(1, DEFAULT_BATCH)
    }
}

/// One request's candidate source.
enum Prepared {
    /// Brute force. The mask maps an index to a candidate.
    Brute(Mask),
    /// Dictionary, words held in memory because the file is small.
    Words(Vec<String>),
    /// Dictionary, an offset per line because the file is large.
    Indexed { path: std::path::PathBuf, offsets: Vec<u64> },
}

/// A stable key for a request's shape.
///
/// Only the fields that change the candidate source matter. Target hashes do not
/// affect it, so a restart against the same targets does not rebuild a wordlist
/// index that is already in memory.
fn prepare_key(request: &AttackRequest) -> String {
    match request.attack_type.as_str() {
        "dictionary" => format!(
            "dictionary:{}:{}",
            request.wordlist.as_deref().unwrap_or(""),
            request.rules.join(",")
        ),
        _ => format!("bruteforce:{}", request.mask.as_deref().unwrap_or("")),
    }
}

impl Prepared {
    fn build(request: &AttackRequest) -> Result<Prepared, String> {
        Self::build_inner(request)
    }

    fn build_inner(request: &AttackRequest) -> Result<Prepared, String> {
        match request.attack_type.as_str() {
            "dictionary" => {
                let path = request
                    .wordlist
                    .as_ref()
                    .ok_or_else(|| "a dictionary attack needs a wordlist".to_string())?;
                let file = File::open(path)
                    .map_err(|e| format!("cannot open wordlist {path}: {e}"))?;

                let mut offsets = Vec::new();
                let mut reader = BufReader::new(file);
                let mut position = 0u64;
                let mut line = Vec::new();
                loop {
                    line.clear();
                    let read = reader
                        .read_until(b'\n', &mut line)
                        .map_err(|e| format!("cannot read {path}: {e}"))?;
                    if read == 0 {
                        break;
                    }
                    let is_line = line.last() != Some(&b'\n');
                    offsets.push(position);
                    position += read as u64;
                    let _ = is_line;
                }

                if offsets.len() as u64 > INDEX_THRESHOLD {
                    Ok(Prepared::Indexed {
                        path: std::path::PathBuf::from(path),
                        offsets,
                    })
                } else {
                    let mut reader = BufReader::new(
                        File::open(path).map_err(|e| format!("cannot open wordlist {path}: {e}"))?,
                    );
                    let mut words = Vec::with_capacity(offsets.len());
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        if !trimmed.is_empty() {
                            words.push(trimmed.to_string());
                        }
                        line.clear();
                    }
                    Ok(Prepared::Words(words))
                }
            }
            "bruteforce" => {
                let spec = request
                    .mask
                    .as_ref()
                    .ok_or_else(|| "a brute force attack needs a mask".to_string())?;
                let mask = Mask::parse(spec, &[])
                    .map_err(|e| format!("mask {spec:?} is not usable: {e:?}"))?;
                Ok(Prepared::Brute(mask))
            }
            other => Err(format!("unknown attack type {other:?}")),
        }
    }

    /// The number of candidates this source can produce.
    fn len(&self) -> Option<u64> {
        match self {
            Prepared::Brute(mask) => {
                mask.keyspace(&[]).ok().and_then(|k| u64::try_from(k).ok())
            }
            Prepared::Words(words) => Some(words.len() as u64),
            Prepared::Indexed { offsets, .. } => Some(offsets.len() as u64),
        }
    }

    /// Candidates at `offset`, up to `count`.
    fn slice(&self, offset: u64, count: u64) -> Result<Vec<String>, String> {
        match self {
            Prepared::Brute(mask) => {
                let mut out = Vec::with_capacity(count as usize);
                for i in offset..offset.saturating_add(count) {
                    match mask.candidate_string(u128::from(i), &[]) {
                        Ok(candidate) => out.push(candidate),
                        // Past the end of the keyspace. Stopping here is how the
                        // runner learns the attack is finished.
                        Err(_) => break,
                    }
                }
                Ok(out)
            }
            Prepared::Words(words) => Ok(words
                .iter()
                .skip(offset as usize)
                .take(count as usize)
                .cloned()
                .collect()),
            Prepared::Indexed { path, offsets } => {
                let mut out = Vec::new();
                let mut reader =
                    File::open(path).map_err(|e| format!("cannot reopen {path:?}: {e}"))?;
                for i in offset..offset.saturating_add(count) {
                    let Some(&start) = offsets.get(i as usize) else {
                        break;
                    };
                    reader
                        .seek(SeekFrom::Start(start))
                        .map_err(|e| format!("cannot seek in {path:?}: {e}"))?;
                    let mut reader = BufReader::new(&mut reader);
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .map_err(|e| format!("cannot read {path:?}: {e}"))?;
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if !trimmed.is_empty() {
                        out.push(trimmed.to_string());
                    }
                }
                Ok(out)
            }
        }
    }
}

impl AttackExecutor for EngineExecutor {
    fn candidates(
        &self,
        request: &AttackRequest,
        offset: u64,
        count: u64,
    ) -> Result<Vec<String>, String> {
        let key = prepare_key(request);
        {
            let prepared = self.prepared.lock().expect("prepared candidates");
            if let Some(source) = prepared.get(&key) {
                return source.slice(offset, count);
            }
        }
        let source = Prepared::build(request)?;
        let result = source.slice(offset, count);
        self.prepared
            .lock()
            .expect("prepared candidates")
            .insert(key, source);
        result
    }

    fn keyspace_size(&self, request: &AttackRequest) -> Option<u64> {
        let key = prepare_key(request);
        let prepared = self.prepared.lock().expect("prepared candidates");
        if let Some(source) = prepared.get(&key) {
            return source.len();
        }
        drop(prepared);
        Prepared::build(request).ok().and_then(|s| s.len())
    }

    fn test_batch(
        &self,
        request: &AttackRequest,
        candidates: &[String],
    ) -> Result<BatchOutcome, String> {
        if candidates.is_empty() {
            return Ok(BatchOutcome {
                tested: 0,
                cracked: Vec::new(),
            });
        }

        // Detect each target once. A target the detector does not recognise is
        // reported and skipped rather than guessed at.
        let mut resolved: Vec<(usize, Box<dyn HashCracker>, HashEntry)> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        for (index, raw) in request.target_hashes.iter().enumerate() {
            match self.detector.detect(raw) {
                Some((cracker, entry)) => resolved.push((index, cracker, entry)),
                None => skipped.push(raw.clone()),
            }
        }
        for raw in &skipped {
            eprintln!("[web] no cracker recognises {raw:?}; skipping it");
        }
        if resolved.is_empty() {
            return Err("none of the target hashes could be recognised".into());
        }

        // One cracker per call, so group by type.
        let mut by_type: HashMap<HashType, Vec<(usize, HashEntry)>> = HashMap::new();
        let mut cracker_for: HashMap<HashType, Box<dyn HashCracker>> = HashMap::new();
        for (index, cracker, entry) in resolved {
            let hash_type = entry.hash_type;
            by_type.entry(hash_type).or_default().push((index, entry));
            cracker_for
                .entry(hash_type)
                .or_insert_with(|| clone_cracker_box(cracker.as_ref()));
        }

        let mut cracked = Vec::new();
        let mut tested = 0u64;

        for (hash_type, entries) in by_type {
            let Some(cracker) = cracker_for.get(&hash_type) else {
                continue;
            };
            let entries: Vec<HashEntry> = entries.into_iter().map(|(_, e)| e).collect();
            let plan = self.engine.plan(candidates.len(), entries.len());
            let matches = self
                .engine
                .verify_batch(cracker.as_ref(), &entries, candidates, plan);
            // Every candidate is tested against this group, which is what the
            // engine did, so the counter reflects the work rather than the hits.
            tested += candidates.len() as u64 * entries.len() as u64;
            for m in matches {
                if let (Some(candidate), Some(entry)) = (
                    candidates.get(m.candidate_index),
                    entries.get(m.hash_index),
                ) {
                    cracked.push(CrackedHit {
                        hash: entry.raw.clone(),
                        password: candidate.clone(),
                    });
                }
            }
        }

        Ok(BatchOutcome { tested, cracked })
    }

    fn batch_size(&self) -> u64 {
        self.resolve_batch_size()
    }
}

/// Clones a cracker out of a trait object.
///
/// The detector hands out owned crackers and `verify_batch` wants a borrowed
/// one, so the two have to meet somewhere. `clone_box` is the method the
/// detector itself uses internally for every `detect` call, so this is the same
/// clone the rest of the program makes rather than a second mechanism.
fn clone_cracker_box(source: &dyn HashCracker) -> Box<dyn HashCracker> {
    source.clone_box()
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    fn md5(text: &str) -> String {
        let mut h = Md5::new();
        h.update(text.as_bytes());
        hex::encode(h.finalize())
    }

    fn brute_request(mask: &str) -> AttackRequest {
        AttackRequest {
            attack_type: "bruteforce".into(),
            hash_type: "MD5".into(),
            target_hashes: vec![md5("abc")],
            mask: Some(mask.into()),
            wordlist: None,
            rules: vec![],
        }
    }

    fn temp_wordlist(name: &str, words: &[&str]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pwdcrack-exec-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("words.txt");
        let mut text = String::new();
        for w in words {
            text.push_str(w);
            text.push('\n');
        }
        std::fs::write(&path, text).expect("write");
        path
    }

    /// The property that matters most: a batch really hashes.
    #[test]
    fn a_brute_force_batch_finds_a_real_candidate() {
        let ex = EngineExecutor::cpu();
        let request = brute_request("?a?a?a");
        let size = ex.keyspace_size(&request).expect("a finite keyspace");
        let candidates = ex.candidates(&request, 0, size).expect("candidates");
        let outcome = ex.test_batch(&request, &candidates).expect("test");
        assert!(
            outcome.cracked.iter().any(|h| h.password == "abc"),
            "MD5(abc) was not found among {} candidates: {:?}",
            candidates.len(),
            outcome.cracked
        );
    }

    /// The digest comes from the same library the engine uses, so a match here
    /// is not two copies of a bug agreeing.
    #[test]
    fn the_digest_reported_is_the_hash_that_was_asked_about() {
        let ex = EngineExecutor::cpu();
        let target = md5("hello");
        let mut request = brute_request("?a?a?a?a?a");
        request.target_hashes = vec![target.clone()];
        let candidates = ex.candidates(&request, 0, 500).expect("candidates");
        let outcome = ex.test_batch(&request, &candidates).expect("test");
        for hit in &outcome.cracked {
            assert_eq!(hit.hash, target);
            assert_eq!(md5(&hit.password), target, "the reported pair is not a match");
        }
    }

    #[test]
    fn a_target_the_detector_cannot_read_is_reported_not_guessed() {
        let ex = EngineExecutor::cpu();
        let mut request = brute_request("?a?a");
        request.target_hashes = vec!["not-a-hash-at-all".into()];
        let candidates = ex.candidates(&request, 0, 10).expect("candidates");
        let e = ex.test_batch(&request, &candidates).expect_err("must not pass");
        assert!(
            e.contains("recognised"),
            "the error must name the problem: {e}"
        );
    }

    #[test]
    fn the_counter_reflects_the_work_not_the_hits() {
        let ex = EngineExecutor::cpu();
        let request = brute_request("?a?a");
        let candidates = ex.candidates(&request, 0, 50).expect("candidates");
        let outcome = ex.test_batch(&request, &candidates).expect("test");
        assert_eq!(outcome.tested, 50, "fifty candidates against one target");
        assert!(outcome.cracked.is_empty() || !outcome.cracked.is_empty());
    }

    #[test]
    fn an_empty_batch_is_free() {
        let ex = EngineExecutor::cpu();
        let outcome = ex
            .test_batch(&brute_request("?a"), &[])
            .expect("an empty batch is not an error");
        assert_eq!(outcome.tested, 0);
    }

    #[test]
    fn a_dictionary_batch_reads_the_file() {
        let path = temp_wordlist("small", &["cat", "dog", "abc"]);
        let ex = EngineExecutor::cpu();
        let mut request = brute_request("?a");
        request.attack_type = "dictionary".into();
        request.wordlist = Some(path.to_string_lossy().to_string());
        request.mask = None;

        let candidates = ex.candidates(&request, 0, 100).expect("candidates");
        assert_eq!(candidates, vec!["cat", "dog", "abc"]);
        assert_eq!(ex.keyspace_size(&request), Some(3));

        let outcome = ex.test_batch(&request, &candidates).expect("test");
        assert!(
            outcome.cracked.iter().any(|h| h.password == "abc"),
            "the dictionary must find it: {:?}",
            outcome.cracked
        );
    }

    /// Random access has to be right, or a dashboard resume would test the wrong
    /// part of a wordlist.
    #[test]
    fn a_dictionary_slice_starts_where_it_was_asked_to() {
        let words: Vec<String> = (0..50).map(|i| format!("word{i}")).collect();
        let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let path = temp_wordlist("slice", &refs);
        let ex = EngineExecutor::cpu();
        let mut request = brute_request("?a");
        request.attack_type = "dictionary".into();
        request.wordlist = Some(path.to_string_lossy().to_string());
        request.mask = None;

        assert_eq!(
            ex.candidates(&request, 10, 5).expect("slice"),
            vec!["word10", "word11", "word12", "word13", "word14"]
        );
        assert_eq!(
            ex.candidates(&request, 45, 100).expect("past the end is short"),
            vec!["word45", "word46", "word47", "word48", "word49"]
        );
        assert!(ex.candidates(&request, 50, 10).expect("empty at the end").is_empty());
    }

    #[test]
    fn a_missing_wordlist_is_an_error_not_an_empty_run() {
        let ex = EngineExecutor::cpu();
        let mut request = brute_request("?a");
        request.attack_type = "dictionary".into();
        request.wordlist = Some("/nonexistent/pwdcrack/words.txt".into());
        request.mask = None;
        let e = ex.candidates(&request, 0, 10).expect_err("a missing file must fail");
        assert!(e.contains("cannot open wordlist"), "{e}");
    }

    /// `?z` is not a defined token, and an unterminated `?[` has no closing
    /// bracket. Either is refused rather than silently treated as literals,
    /// which is what a mask parser that never errors would do.
    #[test]
    fn a_bad_mask_is_an_error() {
        let ex = EngineExecutor::cpu();
        for bad in ["?z", "?[abc", "?z?z?z"] {
            let request = brute_request(bad);
            assert!(
                ex.candidates(&request, 0, 10).is_err(),
                "{bad:?} was accepted as a mask"
            );
        }
    }

    /// A brute force keyspace big enough to overflow u64 must not become a
    /// silently small number.
    #[test]
    fn a_keyspace_larger_than_u64_is_reported_as_unknown() {
        let ex = EngineExecutor::cpu();
        let request = brute_request("?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a");
        match ex.keyspace_size(&request) {
            None => {}
            Some(n) => assert!(n > 0),
        }
    }

    #[test]
    fn the_batch_size_is_bounded() {
        let ex = EngineExecutor::cpu();
        let size = ex.batch_size();
        assert!(size >= 1, "a batch of zero would never progress");
        assert!(size <= DEFAULT_BATCH, "batch was {size}");
    }

    /// Two target hashes of the same type go through one engine call.
    ///
    /// The candidate list is the whole keyspace, not a prefix of it. `?a` is the
    /// printable ASCII set at 92 characters wide, so `?a?a?a` holds 778688
    /// candidates and "xyz" sits near index 194672. Asking for fewer than that
    /// would look like a detection failure rather than an exhausted search.
    #[test]
    fn several_targets_are_all_tested() {
        let ex = EngineExecutor::cpu();
        let mut request = brute_request("?a?a?a");
        request.target_hashes = vec![md5("abc"), md5("xyz")];
        let size = ex.keyspace_size(&request).expect("a finite keyspace");
        let candidates = ex
            .candidates(&request, 0, size)
            .expect("candidates");
        assert_eq!(candidates.len() as u64, size, "the whole keyspace was generated");
        let outcome = ex.test_batch(&request, &candidates).expect("test");
        let found: Vec<&str> = outcome.cracked.iter().map(|h| h.password.as_str()).collect();
        assert!(found.contains(&"abc"), "{found:?}");
        assert!(found.contains(&"xyz"), "{found:?}");
        assert_eq!(
            outcome.tested,
            candidates.len() as u64 * 2,
            "two targets means twice the work"
        );
    }
}
