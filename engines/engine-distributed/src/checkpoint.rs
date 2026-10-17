//! Master checkpoint: durable state, so a restart resumes instead of restarting.
//!
//! # What this replaces
//!
//! `MasterNode::save_checkpoint` wrote a pretty printed JSON blob to a hardcoded
//! `/tmp/pwdcrack_checkpoint.json`, and the background loop wrote a *different*
//! JSON blob to the same path every fifteen seconds. The second one is the one
//! that ran, and its keys are `completed`, `in_flight`, `pending` and `time`,
//! which are not the keys `load_checkpoint` reads. So the checkpoint that
//! existed could never be loaded, and loading one would have failed on the
//! missing keys even if the format had matched.
//!
//! Four defects, each fixed separately:
//!
//!   - **Not atomic.** `std::fs::write` truncates then writes. A master killed
//!     mid write left a half written file, and the next start found a corrupt
//!     checkpoint and refused to run.
//!   - **No integrity check.** Truncated JSON is a parse error with no way to
//!     tell it from a different program writing to `/tmp`.
//!   - **World readable `/tmp`.** On a multi user machine every local account
//!     could read which hashes are being attacked and which were cracked.
//!   - **World writable `/tmp`.** Any local user could replace the file and
//!     choose what the master resumes, which decides what plaintexts the cluster
//!     looks for.
//!
//! # What is written
//!
//! A small envelope plus a `bincode` payload, which is the same pattern as the
//! wire framing in [`crate::codec`] for the same reason: one place that knows how
//! a length, a version and a CRC go together.
//!
//! ```text
//! offset  size  field
//!      0     4  magic          "PWCK"
//!      4     4  schema         u32 little endian
//!      8     4  payload CRC-32 u32
//!     12     4  payload length u32
//!     16   len  payload        bincode of `Checkpoint`
//! ```
//!
//! Written to `<path>.tmp`, flushed, and renamed over `<path>`, keeping the
//! previous file as `<path>.1`. Rename within one directory is atomic on every
//! filesystem this runs on, so a reader sees either the old file or the new one
//! and never a partial one.
//!
//! # The guarantee, stated exactly
//!
//! At-least-once, not exactly-once. A span that was in flight when the master
//! stopped is returned to the free set and issued again after a resume, so a
//! candidate can be tested twice across a restart. Within one run it cannot, and
//! [`crate::scheduler::CoverageLedger`] proves that. Exactly-once across restarts
//! would need durable per candidate completion state, which is a different order
//! of magnitude of bookkeeping; it is not claimed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::protocol::{AttackType, CrackedEntry, TargetHash};
use crate::scheduler::{Job, Span};

/// Identifies a well formed checkpoint file.
pub const MAGIC: [u8; 4] = *b"PWCK";

/// Bytes before the payload.
pub const HEADER_LEN: usize = 16;

/// Schema version. Bumped whenever [`Checkpoint`] changes shape.
pub const SCHEMA: u32 = 1;

/// Ceiling on a checkpoint file, so a corrupt length cannot cause a large
/// allocation before the CRC is checked.
pub const MAX_CHECKPOINT: usize = 64 * 1024 * 1024;

/// The state a master must not lose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub schema: u32,
    /// RFC 3339, for a human reading the file.
    pub saved_at: String,
    /// Next batch id to hand out, so ids are not reused after a resume.
    pub next_batch_id: u64,
    /// Next job id.
    pub next_job_id: u64,
    pub jobs: Vec<JobState>,
    /// Spans that were in flight when the master stopped.
    ///
    /// Returned to the free set on load, because no worker is connected to a
    /// master that has just started.
    pub in_flight: Vec<InFlightState>,
    pub completed: Vec<CrackedEntry>,
}

/// One job's durable state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobState {
    pub id: u64,
    pub attack: AttackType,
    pub targets: Vec<TargetHash>,
    pub keyspace: u64,
    /// Hashes already found, lowercase.
    pub solved: Vec<String>,
    /// Remaining keyspace as separate spans.
    pub free: Vec<SpanState>,
}

/// A serialisable span. `scheduler::Span` is not derived because the ledger and
/// the wire schema should not inherit changes from the scheduler's internals by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanState {
    pub start: u64,
    pub end: u64,
}

impl From<Span> for SpanState {
    fn from(s: Span) -> Self {
        SpanState {
            start: s.start,
            end: s.end,
        }
    }
}

impl From<SpanState> for Span {
    fn from(s: SpanState) -> Self {
        Span::new(s.start, s.end)
    }
}

/// A batch that was in flight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InFlightState {
    pub batch_id: u64,
    pub job_id: u64,
    pub span: SpanState,
    /// Which worker held it, for the log line on resume.
    pub worker_name: String,
}

/// Why a checkpoint could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Io(String),
    BadMagic,
    WrongSchema { found: u32, expected: u32 },
    TooLarge { got: u64, limit: usize },
    Truncated { expected: usize, got: usize },
    CrcMismatch,
    Decode(String),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointError::Io(m) => write!(f, "{m}"),
            CheckpointError::BadMagic => write!(f, "not a pwdcrack checkpoint file"),
            CheckpointError::WrongSchema { found, expected } => write!(
                f,
                "checkpoint schema {found} cannot be read by this build, which writes {expected}"
            ),
            CheckpointError::TooLarge { got, limit } => write!(
                f,
                "checkpoint claims {got} bytes, which is over the {limit} byte limit"
            ),
            CheckpointError::Truncated { expected, got } => write!(
                f,
                "checkpoint is truncated: expected {expected} bytes, found {got}"
            ),
            CheckpointError::CrcMismatch => {
                write!(f, "checkpoint payload is corrupt, the CRC does not match")
            }
            CheckpointError::Decode(m) => write!(f, "checkpoint payload is unreadable: {m}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl Checkpoint {
    /// Assembles a checkpoint from scheduler state.
    pub fn capture(
        jobs: &[Job],
        in_flight: Vec<InFlightState>,
        completed: Vec<CrackedEntry>,
        next_batch_id: u64,
        next_job_id: u64,
    ) -> Self {
        Checkpoint {
            schema: SCHEMA,
            saved_at: chrono::Utc::now().to_rfc3339(),
            next_batch_id,
            next_job_id,
            jobs: jobs
                .iter()
                .map(|j| JobState {
                    id: j.id,
                    attack: j.attack.clone(),
                    targets: j.targets.clone(),
                    keyspace: j.keyspace,
                    solved: j.solved.iter().cloned().collect(),
                    free: j.free.to_vec().into_iter().map(SpanState::from).collect(),
                })
                .collect(),
            in_flight,
            completed,
        }
    }

    /// Rebuilds a job for the scheduler.
    ///
    /// The remaining keyspace is the free set plus whatever was in flight: a
    /// resumed master has no workers, so an in-flight span was never tested by
    /// anyone and belongs back in the free set. That is what makes a resume
    /// finish the same work rather than skipping a tail.
    pub fn into_jobs(self) -> (Vec<Job>, Vec<CrackedEntry>) {
        use std::collections::BTreeSet;
        let mut jobs = Vec::new();
        let mut recovered: Vec<(u64, Span)> = Vec::new();
        for f in &self.in_flight {
            recovered.push((f.job_id, Span::from(f.span)));
        }

        for j in self.jobs {
            let mut free = crate::scheduler::SpanSet::new();
            for s in j.free {
                let _ = free.give_back(Span::from(s));
            }
            for (job_id, span) in recovered.iter() {
                if *job_id == j.id {
                    let _ = free.give_back(*span);
                }
            }
            jobs.push(Job {
                id: j.id,
                attack: j.attack,
                targets: j.targets,
                keyspace: j.keyspace,
                solved: j.solved.into_iter().collect::<BTreeSet<String>>(),
                free,
            });
        }
        (jobs, self.completed)
    }
}

/// Serialises a checkpoint into the envelope above.
pub fn encode(cp: &Checkpoint) -> Result<Vec<u8>, CheckpointError> {
    let cfg = bincode::config::standard().with_limit::<MAX_CHECKPOINT>();
    let payload = bincode::serde::encode_to_vec(cp, cfg)
        .map_err(|e| CheckpointError::Decode(e.to_string()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SCHEMA.to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Parses a checkpoint envelope.
pub fn decode(bytes: &[u8]) -> Result<Checkpoint, CheckpointError> {
    if bytes.len() < HEADER_LEN {
        return Err(CheckpointError::Truncated {
            expected: HEADER_LEN,
            got: bytes.len(),
        });
    }
    if bytes[0..4] != MAGIC {
        return Err(CheckpointError::BadMagic);
    }
    let schema = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if schema != SCHEMA {
        return Err(CheckpointError::WrongSchema {
            found: schema,
            expected: SCHEMA,
        });
    }
    let want_crc = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if len > MAX_CHECKPOINT {
        return Err(CheckpointError::TooLarge {
            got: len as u64,
            limit: MAX_CHECKPOINT,
        });
    }
    let end = HEADER_LEN
        .checked_add(len)
        .ok_or(CheckpointError::TooLarge {
            got: u64::MAX,
            limit: MAX_CHECKPOINT,
        })?;
    if bytes.len() < end {
        return Err(CheckpointError::Truncated {
            expected: end,
            got: bytes.len(),
        });
    }
    let payload = &bytes[HEADER_LEN..end];
    if crc32fast::hash(payload) != want_crc {
        return Err(CheckpointError::CrcMismatch);
    }
    let cfg = bincode::config::standard().with_limit::<MAX_CHECKPOINT>();
    let (cp, _): (Checkpoint, usize) = bincode::serde::decode_from_slice(payload, cfg)
        .map_err(|e| CheckpointError::Decode(e.to_string()))?;
    Ok(cp)
}

/// Where a master keeps its checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointStore {
    path: PathBuf,
}

/// Environment variable that overrides the checkpoint location.
pub const CHECKPOINT_DIR_ENV: &str = "PWDCRACK_CHECKPOINT_DIR";

impl CheckpointStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        CheckpointStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The default location: `$PWDCRACK_CHECKPOINT_DIR/checkpoint.pwck`, else
    /// `$XDG_STATE_HOME/pwdcrack/checkpoint.pwck`, else
    /// `$HOME/.local/state/pwdcrack/checkpoint.pwck`.
    ///
    /// Not `/tmp`, which is where the old default was. `/tmp` is readable by
    /// every local account, and writable by every local account, and a checkpoint
    /// in a world writable directory is an input to what the cluster searches for
    /// next.
    pub fn discover() -> Result<Self, String> {
        if let Some(d) = std::env::var_os(CHECKPOINT_DIR_ENV) {
            if !d.is_empty() {
                return Ok(CheckpointStore::new(PathBuf::from(d).join("checkpoint.pwck")));
            }
        }
        if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
            if !base.is_empty() {
                return Ok(CheckpointStore::new(
                    PathBuf::from(base).join("pwdcrack").join("checkpoint.pwck"),
                ));
            }
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            format!(
                "no HOME and no {CHECKPOINT_DIR_ENV}, so there is nowhere to keep a \
                 checkpoint. Set {CHECKPOINT_DIR_ENV} to a directory only you can write."
            )
        })?;
        Ok(CheckpointStore::new(
            PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("pwdcrack")
                .join("checkpoint.pwck"),
        ))
    }

    /// Writes the checkpoint atomically, keeping the previous file as `.1`.
    ///
    /// Order matters: the previous file is moved aside *before* the new one is
    /// renamed into place, so a crash between the two leaves `.1` as the last
    /// good file rather than no file at all.
    pub fn save(&self, cp: &Checkpoint) -> Result<(), CheckpointError> {
        let bytes = encode(cp)?;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| CheckpointError::Io(format!("{} has no parent", self.path.display())))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| CheckpointError::Io(format!("cannot create {}: {e}", dir.display())))?;
        make_private(dir)?;

        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("checkpoint.pwck");
        let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| CheckpointError::Io(format!("cannot create {}: {e}", tmp.display())))?;
            make_private_file(&f)?;
            f.write_all(&bytes)
                .map_err(|e| CheckpointError::Io(format!("cannot write {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| CheckpointError::Io(format!("cannot flush {}: {e}", tmp.display())))?;
        }

        let previous = dir.join(format!("{name}.1"));
        if self.path.exists() {
            let _ = std::fs::remove_file(&previous);
            std::fs::rename(&self.path, &previous).map_err(|e| {
                CheckpointError::Io(format!("cannot rotate {}: {e}", self.path.display()))
            })?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            CheckpointError::Io(format!("cannot rename into {}: {e}", self.path.display()))
        })?;
        Ok(())
    }

    /// Reads the checkpoint, or `None` when there is none yet.
    ///
    /// A missing file is not an error: a first run has nothing to resume.
    pub fn load(&self) -> Result<Option<Checkpoint>, CheckpointError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CheckpointError::Io(e.to_string())),
        };
        decode(&bytes).map(Some)
    }

    /// Reads the previous checkpoint, for an operator whose current file is
    /// corrupt.
    pub fn load_previous(&self) -> Result<Option<Checkpoint>, CheckpointError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| CheckpointError::Io("no parent directory".into()))?;
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("checkpoint.pwck");
        let prev = dir.join(format!("{name}.1"));
        let bytes = match std::fs::read(&prev) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        decode(&bytes).map(Some)
    }
}

#[cfg(unix)]
fn make_private(dir: &Path) -> Result<(), CheckpointError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(dir)
        .map_err(|e| CheckpointError::Io(format!("cannot stat {}: {e}", dir.display())))?;
    if meta.permissions().mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CheckpointError::Io(format!("cannot chmod {}: {e}", dir.display())))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_private(_dir: &Path) -> Result<(), CheckpointError> {
    Ok(())
}

fn make_private_file(f: &std::fs::File) -> Result<(), CheckpointError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CheckpointError::Io(format!("cannot set mode: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::SpanSet;

    fn job() -> Job {
        Job {
            id: 3,
            attack: AttackType::BruteForce {
                mask: "?l?d".into(),
            },
            targets: vec![TargetHash::new("MD5", "5d41402abc4b2a76b9719d911017c592")],
            keyspace: 1000,
            solved: ["5d41402abc4b2a76b9719d911017c592".to_string()]
                .into_iter()
                .collect(),
            free: SpanSet::from_range(400, 1000),
        }
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint::capture(
            &[job()],
            vec![InFlightState {
                batch_id: 8,
                job_id: 3,
                span: SpanState { start: 0, end: 200 },
                worker_name: "worker-a".into(),
            }],
            vec![CrackedEntry {
                hash: "5d41402abc4b2a76b9719d911017c592".into(),
                password: "hello".into(),
                algorithm: "MD5".into(),
            }],
            9,
            4,
        )
    }

    #[test]
    fn a_checkpoint_round_trips() {
        let cp = checkpoint();
        let bytes = encode(&cp).unwrap();
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(decode(&bytes).unwrap(), cp);
    }

    /// The resume property: a span that was in flight comes back, so a restarted
    /// master finishes the same keyspace rather than skipping a tail.
    #[test]
    fn an_in_flight_span_returns_to_the_free_set_on_resume() {
        let cp = checkpoint();
        let (jobs, completed) = cp.into_jobs();
        assert_eq!(jobs.len(), 1);
        let free = &jobs[0].free;
        // [400,1000) plus the recovered [0,200), coalesced.
        assert_eq!(free.total(), 600 + 200);
        assert_eq!(free.to_vec(), vec![Span::new(0, 200), Span::new(400, 1000)]);
        assert_eq!(jobs[0].keyspace, 1000);
        assert_eq!(completed.len(), 1);
        assert_eq!(jobs[0].solved.len(), 1, "solved hashes must not be re-searched");
    }

    #[test]
    fn a_corrupt_payload_is_caught_by_the_crc() {
        let mut bytes = encode(&checkpoint()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(decode(&bytes), Err(CheckpointError::CrcMismatch));
    }

    #[test]
    fn a_foreign_file_is_not_a_checkpoint() {
        let bytes = b"{\"completed\":[],\"pending\":0}";
        assert_eq!(decode(bytes), Err(CheckpointError::BadMagic));
    }

    /// The old default file was pretty printed JSON. Opening one of those must
    /// fail cleanly rather than being mistaken for an empty run.
    #[test]
    fn the_old_json_checkpoint_is_refused_with_a_clear_reason() {
        let old = br#"{"completed":[],"in_flight":[],"pending":0,"time":"2024-01-01T00:00:00Z"}"#;
        assert_eq!(decode(old), Err(CheckpointError::BadMagic));
    }

    #[test]
    fn a_future_schema_is_refused_rather_than_misread() {
        let mut bytes = encode(&checkpoint()).unwrap();
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            decode(&bytes),
            Err(CheckpointError::WrongSchema {
                found: 99,
                expected: SCHEMA
            })
        );
    }

    #[test]
    fn a_truncated_file_is_refused() {
        let bytes = encode(&checkpoint()).unwrap();
        assert!(matches!(
            decode(&bytes[..bytes.len() - 5]),
            Err(CheckpointError::Truncated { .. })
        ));
    }

    #[test]
    fn an_absurd_length_is_refused_before_allocating() {
        let mut bytes = encode(&checkpoint()).unwrap();
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(decode(&bytes), Err(CheckpointError::TooLarge { .. })));
    }

    #[test]
    fn saving_then_loading_returns_the_same_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(dir.path().join("state").join("checkpoint.pwck"));
        let cp = checkpoint();
        store.save(&cp).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), cp);
    }

    #[test]
    fn a_missing_checkpoint_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(dir.path().join("nope.pwck"));
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn saving_twice_keeps_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(dir.path().join("checkpoint.pwck"));
        let first = checkpoint();
        store.save(&first).unwrap();

        let mut second = checkpoint();
        second.next_batch_id = 77;
        store.save(&second).unwrap();

        assert_eq!(store.load().unwrap().unwrap(), second);
        assert_eq!(store.load_previous().unwrap().unwrap(), first);
    }

    #[test]
    fn no_temporary_file_survives_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(dir.path().join("checkpoint.pwck"));
        for i in 0..3 {
            let mut cp = checkpoint();
            cp.next_batch_id = i;
            store.save(&cp).unwrap();
        }
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn a_checkpoint_is_not_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(dir.path().join("state").join("checkpoint.pwck"));
        store.save(&checkpoint()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "checkpoint mode was {mode:04o}");
            let dmode = std::fs::metadata(store.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700, "directory mode was {dmode:04o}");
        }
    }

    #[test]
    fn the_default_path_is_not_under_tmp() {
        let p = CheckpointStore::discover().unwrap().path().to_path_buf();
        assert!(
            !p.starts_with(std::env::temp_dir()),
            "the default checkpoint is {p:?}, which is the world writable location P9.2.03 removed"
        );
        assert!(p.ends_with("checkpoint.pwck"));
    }
}