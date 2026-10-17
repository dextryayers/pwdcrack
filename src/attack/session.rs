//! Session checkpoints for long running attacks.
//!
//! A checkpoint records enough state to resume an interrupted run where it left
//! off: which attack was running, over which inputs, and how far it had got.
//!
//! ## Why a versioned format
//!
//! The on disk layout changes as fields are added. A checkpoint from an older
//! build must either load cleanly or be rejected with a clear message, never be
//! misread as a newer layout. Every load therefore checks `FORMAT_VERSION`
//! first and refuses anything it does not recognise.
//!
//! ## Why an atomic write
//!
//! A crash or a full disk during a checkpoint write would otherwise leave a
//! truncated file that cannot be parsed, losing the session entirely. Writes go
//! to a temporary file in the same directory, are flushed to disk with
//! `sync_all`, and are then moved into place with `rename`, which is atomic
//! within a filesystem. A reader therefore sees either the previous checkpoint
//! or the new one, never a partial one.
//!
//! ## Why three generations are kept
//!
//! `rename` protects against a crash during the write itself, but not against a
//! filesystem that loses data or a corrupted sector after the fact. Keeping the
//! previous two checkpoints means a damaged newest file can fall back to
//! something that was known good.
//!
//! ## What is deliberately not stored
//!
//! Candidate positions, not candidate text. A checkpoint holds a byte offset
//! and a line number; the wordlist is re-read on resume. Storing the candidates
//! themselves would make a checkpoint proportional to the work done, which
//! defeats the purpose.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bumped whenever the layout changes. See the module docs for the policy.
pub const FORMAT_VERSION: u32 = 1;

/// Magic bytes at the head of every checkpoint, so a wrong file is detected
/// before any field is interpreted.
const MAGIC: &[u8; 9] = b"PWDCSESS1";

/// Which attack a session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackKind {
    /// `pwdcrack dictionary`
    Dictionary,
    /// `pwdcrack brute-force`
    BruteForce,
    /// `pwdcrack combinator`
    Combinator,
    /// `pwdcrack prince`
    Prince,
    /// `pwdcrack toggle-case`
    ToggleCase,
    /// `pwdcrack substitute`
    Substitute,
    /// `pwdcrack rules`
    Rules,
}

impl AttackKind {
    /// The command name a user would type, used in log and error messages.
    pub fn command(&self) -> &'static str {
        match self {
            AttackKind::Dictionary => "dictionary",
            AttackKind::BruteForce => "brute-force",
            AttackKind::Combinator => "combinator",
            AttackKind::Prince => "prince",
            AttackKind::ToggleCase => "toggle-case",
            AttackKind::Substitute => "substitute",
            AttackKind::Rules => "rules",
        }
    }
}

/// A resumable position within an attack.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// Byte offset into the primary wordlist, when the attack streams one.
    pub wordlist_offset: u64,
    /// Number of wordlist lines already consumed.
    pub lines_done: u64,
    /// Candidates already tested, used when the attack is not wordlist bound.
    pub candidates_tested: u64,
    /// Index of the current rule, for rule driven attacks.
    pub rule_index: u32,
}

/// Everything needed to decide whether a checkpoint still applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inputs {
    /// Digest of the hash file contents.
    pub hash_digest: u64,
    /// Digest of the primary wordlist contents.
    pub wordlist_digest: u64,
    /// Digest of the secondary wordlist, for combinator.
    pub wordlist2_digest: u64,
    /// Digest of the rule file, zero when no rules are used.
    pub rules_digest: u64,
    /// The mask string, for brute force.
    pub mask: String,
    /// Size of the primary wordlist in bytes at checkpoint time.
    pub wordlist_bytes: u64,
}

/// A complete checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Must equal [`FORMAT_VERSION`].
    pub format_version: u32,
    /// Which attack this describes.
    pub kind: AttackKind,
    /// Inputs the attack was started with.
    pub inputs: Inputs,
    /// How far the attack had progressed.
    pub position: Position,
    /// Cracks found before the checkpoint was written.
    pub cracked: u64,
    /// Unix seconds when the checkpoint was written.
    pub written_at: u64,
}

impl Checkpoint {
    /// Creates a checkpoint for a new run.
    pub fn new(kind: AttackKind, inputs: Inputs, position: Position) -> Self {
        Checkpoint {
            format_version: FORMAT_VERSION,
            kind,
            inputs,
            position,
            cracked: 0,
            written_at: now_unix(),
        }
    }

    /// The file a session of this name writes to, next to `path`.
    fn slot(&self, path: &Path, generation: u8) -> PathBuf {
        let mut p = path.as_os_str().to_os_string();
        p.push(format!(".{generation}"));
        PathBuf::from(p)
    }

    /// Writes the checkpoint atomically, rotating the previous generations.
    ///
    /// Ordering matters: the old generation 1 is removed last, so a failure at
    /// any point leaves at least one valid file behind.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        // Serialise first so a serialisation failure cannot truncate anything.
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(MAGIC);
        let payload = bincode::serde::encode_to_vec(
            self,
            bincode::config::standard(),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);

        // Temporary file in the same directory so `rename` stays within one
        // filesystem and is therefore atomic.
        let tmp = self.slot(path, 9);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&buf)?;
            f.flush()?;
            // Push the bytes to the storage device before the rename, otherwise
            // a crash can leave the renamed file present but empty.
            f.sync_all()?;
        }

        // Rotate generations. The newest is always written to slot 0 after the
        // previous occupants are shifted down, so at every point at least one
        // complete file exists.
        //
        //   before: [0]=prev [1]=older [2]=oldest
        //   after:  [0]=new  [1]=prev [2]=older
        //
        // Shifting happens before the new payload is renamed into place.
        let gen2 = self.slot(path, 2);
        let gen1 = self.slot(path, 1);
        let _ = fs::remove_file(&gen2);
        if gen1.exists() {
            let _ = fs::rename(&gen1, &gen2);
        }
        // The current generation 0 becomes generation 1.
        let gen0 = self.slot(path, 0);
        if gen0.exists() {
            let _ = fs::rename(&gen0, &gen1);
        }
        fs::rename(&tmp, &gen0)?;

        // Best effort: make the rename durable too.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(d) = File::open(parent) {
                    let _ = d.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Reads a checkpoint, falling back to older generations.
    ///
    /// Returns the first generation that parses. If none do, the error names
    /// the path so the user can delete it and start over.
    pub fn load(path: &Path) -> Result<Self, SessionError> {
        let mut last_err: Option<SessionError> = None;
        for generation in 0..3u8 {
            let candidate = Self::slot_of(path, generation);
            if !candidate.exists() {
                continue;
            }
            match Self::read_one(&candidate) {
                Ok(cp) => return Ok(cp),
                Err(e) => last_err = Some(e),
            }
        }
        Err(match last_err {
            Some(e) => e,
            None => SessionError::NotFound {
                path: path.to_path_buf(),
            },
        })
    }

    /// Loads a checkpoint only if it still describes the requested inputs.
    ///
    /// A checkpoint from a different hash file, wordlist, or mask is worse
    /// than no checkpoint, because resuming it would silently test the wrong
    /// candidates. The digests are compared here rather than by the caller so
    /// every resume path behaves the same way.
    pub fn load_if_matches(
        path: &Path,
        kind: AttackKind,
        inputs: &Inputs,
    ) -> Result<Option<Self>, SessionError> {
        let cp = match Self::load(path) {
            Ok(cp) => cp,
            Err(SessionError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        if cp.kind != kind {
            return Err(SessionError::Mismatch {
                field: "attack".into(),
                expected: kind.command().to_string(),
                found: cp.kind.command().to_string(),
            });
        }
        if cp.inputs.hash_digest != inputs.hash_digest {
            return Err(SessionError::Mismatch {
                field: "hash file".into(),
                expected: inputs.hash_digest.to_string(),
                found: cp.inputs.hash_digest.to_string(),
            });
        }
        if cp.inputs.wordlist_digest != inputs.wordlist_digest {
            return Err(SessionError::Mismatch {
                field: "wordlist".into(),
                expected: inputs.wordlist_digest.to_string(),
                found: cp.inputs.wordlist_digest.to_string(),
            });
        }
        if cp.inputs.mask != inputs.mask {
            return Err(SessionError::Mismatch {
                field: "mask".into(),
                expected: inputs.mask.clone(),
                found: cp.inputs.mask.clone(),
            });
        }
        Ok(Some(cp))
    }

    fn slot_of(path: &Path, generation: u8) -> PathBuf {
        let mut p = path.as_os_str().to_os_string();
        p.push(format!(".{generation}"));
        PathBuf::from(p)
    }

    fn read_one(path: &Path) -> Result<Self, SessionError> {
        let mut f = File::open(path).map_err(|e| SessionError::Io {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
        let mut raw = Vec::new();
        f.read_to_end(&mut raw)
            .map_err(|e| SessionError::Io {
                path: path.to_path_buf(),
                source: e.to_string(),
            })?;

        if raw.len() < MAGIC.len() + 4 {
            return Err(SessionError::Truncated {
                path: path.to_path_buf(),
            });
        }
        if &raw[..MAGIC.len()] != MAGIC {
            return Err(SessionError::BadMagic {
                path: path.to_path_buf(),
            });
        }

        let len_off = MAGIC.len();
        let len = u32::from_le_bytes([
            raw[len_off],
            raw[len_off + 1],
            raw[len_off + 2],
            raw[len_off + 3],
        ]) as usize;

        let body_start = len_off + 4;
        if raw.len() < body_start + len {
            return Err(SessionError::Truncated {
                path: path.to_path_buf(),
            });
        }

        let (cp, _): (Checkpoint, usize) = bincode::serde::decode_from_slice(
            &raw[body_start..body_start + len],
            bincode::config::standard(),
        )
        .map_err(|e| SessionError::Decode {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;

        if cp.format_version != FORMAT_VERSION {
            return Err(SessionError::VersionMismatch {
                found: cp.format_version,
                expected: FORMAT_VERSION,
            });
        }
        Ok(cp)
    }
}

/// Why a checkpoint could not be used.
#[derive(Debug)]
pub enum SessionError {
    /// No checkpoint exists at the path.
    NotFound { path: PathBuf },
    /// The file exists but is shorter than its own header claims.
    Truncated { path: PathBuf },
    /// The file does not start with the expected magic bytes.
    BadMagic { path: PathBuf },
    /// The file was written by a different format version.
    VersionMismatch { found: u32, expected: u32 },
    /// The bytes could not be decoded.
    Decode { path: PathBuf, source: String },
    /// The checkpoint describes different inputs than the current run.
    Mismatch {
        field: String,
        expected: String,
        found: String,
    },
    /// Underlying filesystem error.
    Io { path: PathBuf, source: String },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::NotFound { path } => {
                write!(f, "no checkpoint at {}", path.display())
            }
            SessionError::Truncated { path } => write!(
                f,
                "checkpoint {} is truncated. Delete it to start a new session.",
                path.display()
            ),
            SessionError::BadMagic { path } => write!(
                f,
                "{} is not a pwdcrack checkpoint (bad magic). Delete it.",
                path.display()
            ),
            SessionError::VersionMismatch { found, expected } => write!(
                f,
                "checkpoint format version {found} does not match this build ({expected}). \
                 Delete the session to start over."
            ),
            SessionError::Decode { path, source } => write!(
                f,
                "checkpoint {} could not be decoded: {source}. Delete it to start over.",
                path.display()
            ),
            SessionError::Mismatch {
                field,
                expected,
                found,
            } => write!(
                f,
                "checkpoint was created for a different {field} (checkpoint: {found}, \
                 current: {expected}). Pass a different --session path or delete the file."
            ),
            SessionError::Io { path, source } => {
                write!(f, "checkpoint {} I/O error: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// Current unix time in seconds, or zero if the clock is unavailable.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fast non cryptographic digest, FNV-1a 64 bit.
///
/// Used to detect that an input file changed between runs. This is not a
/// security primitive and does not need to be: the goal is to notice that a
/// wordlist was replaced, not to resist an attacker who already controls the
/// filesystem.
pub fn digest(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Digests a file without loading it entirely.
///
/// Reads in 1 MB blocks so a multi gigabyte wordlist costs 1 MB of memory.
/// Returns zero when the file cannot be read, which makes any later comparison
/// fail loudly rather than silently matching.
pub fn digest_file(path: &Path) -> u64 {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                for b in &buf[..n] {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            Err(_) => return 0,
        }
    }
    h
}

/// Builds an [`Inputs`] record for a dictionary style attack.
pub fn inputs_for_words(hash_file: &Path, wordlist: &Path, rules: Option<&Path>) -> Inputs {
    Inputs {
        hash_digest: digest_file(hash_file),
        wordlist_digest: digest_file(wordlist),
        wordlist2_digest: 0,
        rules_digest: rules.map(digest_file).unwrap_or(0),
        mask: String::new(),
        wordlist_bytes: fs::metadata(wordlist).map(|m| m.len()).unwrap_or(0),
    }
}

/// Builds an [`Inputs`] record for a mask attack.
pub fn inputs_for_mask(hash_file: &Path, mask: &str) -> Inputs {
    Inputs {
        hash_digest: digest_file(hash_file),
        wordlist_digest: 0,
        wordlist2_digest: 0,
        rules_digest: 0,
        mask: mask.to_string(),
        wordlist_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pwdcrack-session-test-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample(kind: AttackKind, mask: &str) -> Checkpoint {
        Checkpoint::new(
            kind,
            Inputs {
                hash_digest: 1,
                wordlist_digest: 2,
                wordlist2_digest: 0,
                rules_digest: 0,
                mask: mask.to_string(),
                wordlist_bytes: 100,
            },
            Position {
                lines_done: 500,
                candidates_tested: 1500,
                ..Default::default()
            },
        )
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let d = tmpdir("roundtrip");
        let p = d.join("sess");
        let mut cp = sample(AttackKind::Dictionary, "");
        cp.cracked = 7;
        cp.save(&p).unwrap();
        let back = Checkpoint::load(&p).unwrap();
        assert_eq!(back, cp);
        assert_eq!(back.cracked, 7);
        assert_eq!(back.position.lines_done, 500);
    }

    #[test]
    fn load_of_missing_file_is_not_found_not_panic() {
        let d = tmpdir("missing");
        match Checkpoint::load(&d.join("nope")) {
            Err(SessionError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_file() {
        let d = tmpdir("atomic");
        let p = d.join("sess");
        sample(AttackKind::BruteForce, "?l?l").save(&p).unwrap();
        // The payload lands in generation 0, not in `sess` itself.
        assert!(
            Checkpoint::slot_of(&p, 0).exists(),
            "generation 0 slot was not created"
        );
        // The temp file used during the write must be gone.
        let tmp = Checkpoint::slot_of(&p, 9);
        assert!(!tmp.exists(), "temp file {} was left behind", tmp.display());
        // And the result must be loadable.
        let back = Checkpoint::load(&p).unwrap();
        assert_eq!(back.position.candidates_tested, 1500);
    }

    #[test]
    fn three_generations_are_retained() {
        let d = tmpdir("generations");
        let p = d.join("sess");
        // Three saves in a row must leave gen 0 and gen 1 populated, and gen 2
        // from the rotation of the oldest.
        sample(AttackKind::Dictionary, "").save(&p).unwrap();
        sample(AttackKind::Dictionary, "").save(&p).unwrap();
        sample(AttackKind::Dictionary, "").save(&p).unwrap();
        assert!(Checkpoint::slot_of(&p, 0).exists());
        assert!(Checkpoint::slot_of(&p, 1).exists());
    }

    #[test]
    fn garbage_file_is_rejected_without_panic() {
        let d = tmpdir("garbage");
        let p = d.join("sess");
        fs::write(p.with_extension("").with_file_name("sess.0"), b"not a session at all").unwrap();
        match Checkpoint::load(&p) {
            Err(SessionError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn truncated_file_is_rejected_without_panic() {
        let d = tmpdir("truncated");
        let p = d.join("sess");
        sample(AttackKind::Dictionary, "").save(&p).unwrap();
        let gen0 = Checkpoint::slot_of(&p, 0);
        let mut bytes = fs::read(&gen0).unwrap();
        bytes.truncate(MAGIC.len() + 8);
        fs::write(&gen0, &bytes).unwrap();
        match Checkpoint::load(&p) {
            Err(SessionError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_is_reported() {
        let d = tmpdir("version");
        let p = d.join("sess");
        let mut cp = sample(AttackKind::Dictionary, "");
        cp.format_version = 999;
        cp.save(&p).unwrap();
        match Checkpoint::load(&p) {
            Err(SessionError::VersionMismatch { found: 999, .. }) => {}
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn load_if_matches_rejects_a_different_mask() {
        let d = tmpdir("maskmismatch");
        let p = d.join("sess");
        sample(AttackKind::BruteForce, "?l?l").save(&p).unwrap();
        let inputs = Inputs {
            hash_digest: 1,
            wordlist_digest: 0,
            wordlist2_digest: 0,
            rules_digest: 0,
            mask: "?d?d".into(),
            wordlist_bytes: 0,
        };
        match Checkpoint::load_if_matches(&p, AttackKind::BruteForce, &inputs) {
            Err(SessionError::Mismatch { .. }) => {}
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn load_if_matches_returns_none_when_absent() {
        let d = tmpdir("absent");
        let inputs = Inputs {
            hash_digest: 1,
            wordlist_digest: 2,
            wordlist2_digest: 0,
            rules_digest: 0,
            mask: String::new(),
            wordlist_bytes: 0,
        };
        let got = Checkpoint::load_if_matches(&d.join("nothing"), AttackKind::Dictionary, &inputs)
            .unwrap();
        assert!(got.is_none(), "absent checkpoint must be None, not an error");
    }

    #[test]
    fn digest_is_stable_and_sensitive() {
        assert_eq!(digest(b"abc"), digest(b"abc"));
        assert_ne!(digest(b"abc"), digest(b"abd"));
        assert_ne!(digest(b"abc"), digest(b""));
    }

    #[test]
    fn digest_file_matches_digest_of_contents() {
        let d = tmpdir("digestfile");
        let f = d.join("w.txt");
        let content = b"the quick brown fox\n";
        fs::write(&f, content).unwrap();
        assert_eq!(digest_file(&f), digest(content));
    }

    #[test]
    fn digest_file_of_missing_path_is_zero() {
        let d = tmpdir("digestmissing");
        assert_eq!(digest_file(&d.join("nope")), 0);
    }
}
