//! Wordlist access control for cluster work units.
//!
//! # The defect this removes
//!
//! `WorkUnit::AttackType::Dictionary` carried a `wordlist_path: String`, and the
//! worker ran `File::open(path)` on whatever string arrived. Nothing checked it.
//!
//! The path comes from the master. A master is a peer, not a supervisor: in the
//! threat model this file is written for, it may be compromised, replaced, or
//! simply run by someone else. With an unchecked path that peer chooses which file
//! the worker opens, so it can read any file the worker can read. It cannot see
//! the contents directly, but the bytes flow back: the worker tests them as
//! candidate passwords against the target hashes, and the match set returned in
//! `Message::Result` tells the master which bytes were at which offsets. Reading
//! a private key or a password database that way is a real extraction channel,
//! not a theoretical one.
//!
//! # The rule
//!
//! A worker only opens a path that is inside a directory it was explicitly
//! granted, resolved through symlinks before the check rather than after.
//!
//! Two properties matter and both are easy to get wrong:
//!
//!   - Resolution happens first. A check on the literal string
//!     `/data/wordlists/../../etc/shadow` passes a prefix test and opens
//!     `/etc/shadow`. [`WordlistPolicy::resolve`] canonicalises first, so the
//!     path that is tested is the path that is opened.
//!   - The root is canonicalised too, so a root that is itself a symlink still
//!     works and still contains what the operator meant.
//!
//! A path inside the grant that still fails to resolve is refused rather than
//! opened, and the refusal names the path so the operator can see which unit
//! caused it.

use std::path::{Component, Path, PathBuf};

/// Why a path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDenied {
    /// The path, after resolution, is not under any granted root.
    OutsideGrant { resolved: PathBuf, roots: Vec<PathBuf> },

    /// The path does not exist, or a component of it cannot be read.
    Unresolvable { path: PathBuf, reason: String },

    /// The path names a directory rather than a file.
    NotAFile { path: PathBuf },

    /// The path is absolute or contains a parent component in a form that cannot
    /// be resolved, and therefore could not be checked.
    NotRelative { path: PathBuf },

    /// The granted roots list is empty, so nothing can be permitted.
    NoRootsGranted,
}

impl std::fmt::Display for PathDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathDenied::OutsideGrant { resolved, roots } => {
                let listed: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
                write!(
                    f,
                    "{} resolves to {}, which is outside the granted wordlist \
                     directories {listed:?}",
                    resolved.display(),
                    resolved.display()
                )
            }
            PathDenied::Unresolvable { path, reason } => {
                write!(f, "{} cannot be resolved: {reason}", path.display())
            }
            PathDenied::NotAFile { path } => {
                write!(f, "{} is not a regular file", path.display())
            }
            PathDenied::NotRelative { path } => write!(
                f,
                "{} is not a relative path, so it could not be checked against \
                 the granted directories",
                path.display()
            ),
            PathDenied::NoRootsGranted => write!(
                f,
                "no wordlist directories were granted, so no path can be permitted"
            ),
        }
    }
}

impl std::error::Error for PathDenied {}

/// Decides which files a worker will open on a master's instruction.
#[derive(Debug, Clone)]
pub struct WordlistPolicy {
    /// Canonicalised directories the worker will read from.
    roots: Vec<PathBuf>,
}

impl WordlistPolicy {
    /// Grants the given directories.
    ///
    /// Each is canonicalised once, at construction. A root that does not exist is
    /// an error rather than a silently dropped entry, because a worker that
    /// granted nothing would refuse every unit and look like a compute failure.
    pub fn new<I, P>(roots: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut canonical = Vec::new();
        for r in roots {
            let p = r.as_ref();
            let c = p.canonicalize().map_err(|e| {
                format!("wordlist root {} cannot be resolved: {e}", p.display())
            })?;
            if !c.is_dir() {
                return Err(format!(
                    "wordlist root {} is not a directory",
                    p.display()
                ));
            }
            canonical.push(c);
        }
        Ok(WordlistPolicy { roots: canonical })
    }

    /// A policy that permits nothing. Every path is refused.
    pub fn deny_all() -> Self {
        WordlistPolicy { roots: Vec::new() }
    }

    /// The granted directories.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// True when this policy will refuse every path.
    pub fn is_deny_all(&self) -> bool {
        self.roots.is_empty()
    }

    /// Resolves `requested` against the grants, returning the real path to open.
    ///
    /// `base` is the worker's current directory, used for relative requests.
    /// Passing it explicitly keeps the function pure enough to test.
    pub fn resolve(&self, requested: &str, base: &Path) -> Result<PathBuf, PathDenied> {
        if self.roots.is_empty() {
            return Err(PathDenied::NoRootsGranted);
        }

        let raw = Path::new(requested);

        // A path with a parent component or a root is refused outright rather
        // than resolved and checked. Resolution catches traversal that exists on
        // disk; refusing the form catches traversal aimed at a path that does not
        // exist yet, which canonicalisation cannot evaluate.
        let has_parent = raw
            .components()
            .any(|c| matches!(c, Component::ParentDir));
        if raw.is_absolute() || has_parent {
            return Err(PathDenied::NotRelative {
                path: raw.to_path_buf(),
            });
        }

        let joined = base.join(raw);

        // Canonicalise before testing, so the path compared against the roots is
        // the path that will actually be opened. This is the whole point: a
        // string prefix check on `/data/wl/../../etc/passwd` passes and then
        // opens something else entirely.
        let resolved = match joined.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Err(PathDenied::Unresolvable {
                    path: joined,
                    reason: e.to_string(),
                })
            }
        };

        if !self.under_a_root(&resolved) {
            return Err(PathDenied::OutsideGrant {
                resolved,
                roots: self.roots.clone(),
            });
        }

        if !resolved.is_file() {
            return Err(PathDenied::NotAFile { path: resolved });
        }

        Ok(resolved)
    }

    /// True when `candidate` is at or below one of the roots.
    ///
    /// Component-wise, not by string prefix. `/data/wlx` is not under `/data/wl`
    /// even though the strings share a prefix, and a prefix test would allow it.
    fn under_a_root(&self, candidate: &Path) -> bool {
        self.roots.iter().any(|root| candidate.starts_with(root))
    }

    /// Convenience: resolve, then read the requested line range.
    pub fn read_lines(
        &self,
        requested: &str,
        base: &Path,
        start: u64,
        end: u64,
    ) -> Result<Vec<String>, WorklistReadError> {
        let path = self.resolve(requested, base).map_err(WorklistReadError::Denied)?;
        read_lines_from(&path, start, end).map_err(WorklistReadError::Io)
    }
}

/// Why a line range could not be read.
#[derive(Debug)]
pub enum WorklistReadError {
    Denied(PathDenied),
    Io(String),
}

impl std::fmt::Display for WorklistReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorklistReadError::Denied(d) => write!(f, "{d}"),
            WorklistReadError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for WorklistReadError {}

fn read_lines_from(path: &Path, start: u64, end: u64) -> Result<Vec<String>, String> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let i = i as u64;
        if i >= end {
            break;
        }
        if i < start {
            continue;
        }
        match line {
            Ok(l) => lines.push(l),
            Err(e) => return Err(format!("read {} line {i}: {e}", path.display())),
        }
    }
    Ok(lines)
}

/// A digest of file contents, for a manifest that a worker can verify without
/// being told a path at all.
///
/// P9.1.05 offers two shapes: send the contents, or send a digest plus a signed
/// manifest. This is the primitive for the second. It is not a signature: a digest
/// proves the bytes are the bytes the master meant to send, and authenticating the
/// manifest is [`crate::netpolicy::ClusterAuth`]'s job.
pub fn content_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Builds the manifest a master sends instead of a raw path.
///
/// The master reads the file once, records its size and digest, and ships the
/// contents or the pair. A worker that trusts the pair can verify what it was
/// given. A worker that only trusts the contents has nothing to verify, which is
/// why the path was removed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WordlistManifest {
    pub name: String,
    pub byte_len: u64,
    pub sha256: String,
    /// Whether the source ended with a newline.
    ///
    /// A wordlist travels from the master to a worker as a `Vec<String>` of
    /// lines, and `lines()` plus `join("\n")` does not round trip: a file
    /// ending in a newline loses it. Rebuilding the content from the words and
    /// comparing that against a manifest built from the file's bytes could never
    /// match, because the lengths differ by one. The trailing newline is the
    /// whole difference, so it is carried rather than inferred from a length.
    pub trailing_newline: bool,
}

impl WordlistManifest {
    /// Builds a manifest from the bytes the master is about to send.
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Self {
        WordlistManifest {
            name: name.into(),
            byte_len: bytes.len() as u64,
            sha256: content_digest(bytes),
            trailing_newline: bytes.last() == Some(&b'\n'),
        }
    }

    /// Rebuilds the exact byte content this manifest describes.
    ///
    /// Used where the words have to be turned back into a file: the master sends
    /// lines, and a worker writing them out has to produce the same bytes the
    /// manifest was built from or every verification fails.
    pub fn render(&self, words: &[String]) -> Vec<u8> {
        let mut out = words.join("\n").into_bytes();
        if self.trailing_newline && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out
    }

    /// Checks received bytes against this manifest.
    ///
    /// Both size and digest. The size check is redundant given the digest, and is
    /// kept only so the failure message can say which went wrong.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), ManifestMismatch> {
        let len = bytes.len() as u64;
        if len != self.byte_len {
            return Err(ManifestMismatch::Length {
                expected: self.byte_len,
                got: len,
            });
        }
        let digest = content_digest(bytes);
        if digest != self.sha256 {
            return Err(ManifestMismatch::Digest {
                expected: self.sha256.clone(),
                got: digest,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestMismatch {
    Length { expected: u64, got: u64 },
    Digest { expected: String, got: String },
}

impl std::fmt::Display for ManifestMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestMismatch::Length { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            ManifestMismatch::Digest { expected, got } => {
                write!(f, "expected digest {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for ManifestMismatch {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Builds a small tree under a temporary directory and returns it.
    ///
    /// Uses a unique name per test so the tests do not collide when the harness
    /// runs them in parallel.
    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "pwdcrack-policy-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("wordlists")).unwrap();
        std::fs::create_dir_all(base.join("private")).unwrap();
        write_file(&base.join("wordlists/rockyou.txt"), b"alpha\nbravo\ncharlie\ndelta\n");
        write_file(&base.join("private/secret.txt"), b"top secret\n");
        base
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn a_file_inside_a_granted_root_is_opened() {
        let base = scratch("inside");
        let root = base.join("wordlists");
        let policy = WordlistPolicy::new([&root]).unwrap();
        let got = policy
            .resolve("rockyou.txt", &root)
            .expect("a file under the granted root is allowed");
        assert!(got.ends_with("rockyou.txt"));
        assert_eq!(policy.roots().len(), 1);
    }

    /// The case the plan names: a master naming a file outside the grant.
    #[test]
    fn a_file_outside_the_granted_root_is_refused() {
        let base = scratch("outside");
        // The policy grants only the wordlists directory, and its base is that
        // same directory, so a sibling name can only be reached by traversing
        // out of it. That is the case under test.
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        // Either denial is acceptable and both are safe. A parent component is
        // caught before resolution, so `NotRelative` is what actually comes
        // back; `OutsideGrant` would come from a symlink that resolves outside
        // the root without a parent component in the request. The test asserts
        // the path is refused, not which check refused it, because either one
        // leaves the worker with no file to open.
        match policy.resolve("../private/secret.txt", &base.join("wordlists")) {
            Err(PathDenied::NotRelative { .. }) | Err(PathDenied::OutsideGrant { .. }) => {}
            other => panic!("the path must be refused, got {other:?}"),
        }
    }

    /// Traversal that survives a naive string prefix test.
    ///
    /// `/w/../private/secret.txt` starts with `/w` and opens something outside
    /// it. Resolving before comparing is what stops this.
    #[test]
    fn traversal_out_of_the_granted_root_is_refused() {
        let base = scratch("traversal");
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        match policy.resolve("../private/secret.txt", &base.join("wordlists")) {
            Err(PathDenied::NotRelative { .. }) | Err(PathDenied::OutsideGrant { .. }) => {}
            other => panic!("traversal must be refused, got {other:?}"),
        }
    }

    /// A symlink inside a granted root pointing out of it.
    ///
    /// The check runs after canonicalisation, so the link target is what gets
    /// tested. This is the variant that a lexical check cannot catch at all.
    #[test]
    fn a_symlink_escaping_the_granted_root_is_refused() {
        let base = scratch("symlink");
        let link = base.join("wordlists/escape.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(base.join("private/secret.txt"), &link).unwrap();
        #[cfg(not(unix))]
        return;

        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        match policy.resolve("escape.txt", &base.join("wordlists")) {
            Err(PathDenied::OutsideGrant { .. }) => {}
            other => panic!("a symlink out of the root must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_absolute_path_is_refused_without_consulting_the_roots() {
        let base = scratch("absolute");
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        assert!(matches!(
            policy.resolve("/etc/passwd", &base.join("wordlists")),
            Err(PathDenied::NotRelative { .. })
        ));
    }

    #[test]
    fn a_missing_file_is_refused_rather_than_created() {
        let base = scratch("missing");
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        assert!(matches!(
            policy.resolve("not-there.txt", &base.join("wordlists")),
            Err(PathDenied::Unresolvable { .. })
        ));
    }

    #[test]
    fn a_directory_is_refused() {
        let base = scratch("directory");
        std::fs::create_dir_all(base.join("wordlists/subdir")).unwrap();
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        assert!(matches!(
            policy.resolve("subdir", &base.join("wordlists")),
            Err(PathDenied::NotRelative { .. }) | Err(PathDenied::NotAFile { .. })
        ));
    }

    /// A worker granted nothing refuses everything. Better than a worker that
    /// opens whatever it is told.
    #[test]
    fn a_policy_with_no_roots_refuses_everything() {
        let base = scratch("noroot");
        let policy = WordlistPolicy::deny_all();
        assert!(policy.is_deny_all());
        assert!(matches!(
            policy.resolve("rockyou.txt", &base),
            Err(PathDenied::NoRootsGranted)
        ));
    }

    /// Constructing with a root that does not exist is an error, not a silently
    /// dropped grant. A worker that granted nothing looks like a compute failure.
    #[test]
    fn a_nonexistent_root_is_an_error_at_construction() {
        let missing = std::env::temp_dir().join("pwdcrack-no-such-root-xyz");
        assert!(WordlistPolicy::new([missing]).is_err());
    }

    /// A root that is a file rather than a directory is an error.
    #[test]
    fn a_root_that_is_a_file_is_an_error() {
        let base = scratch("fileroot");
        assert!(WordlistPolicy::new([base.join("wordlists/rockyou.txt")]).is_err());
    }

    /// Component-wise containment, not string prefix.
    ///
    /// `/base/wordlists` is not a parent of `/base/wordlistsX`, even though one
    /// string starts with the other.
    #[test]
    fn containment_is_component_wise_not_string_prefix() {
        let base = scratch("prefix");
        std::fs::create_dir_all(base.join("wordlistsX")).unwrap();
        write_file(&base.join("wordlistsX/f.txt"), b"x\n");
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        assert!(
            policy
                .resolve("../wordlistsX/f.txt", &base.join("wordlists"))
                .is_err(),
            "a sibling directory sharing a name prefix must not be reachable"
        );
    }

    #[test]
    fn read_lines_returns_only_the_requested_range() {
        let base = scratch("range");
        let root = base.join("wordlists");
        let policy = WordlistPolicy::new([&root]).unwrap();
        let got = policy
            .read_lines("rockyou.txt", &root, 1, 3)
            .expect("permitted and readable");
        assert_eq!(got, vec!["bravo".to_string(), "charlie".to_string()]);
    }

    #[test]
    fn read_lines_refuses_a_denied_path_before_touching_the_disk() {
        let base = scratch("readdenied");
        let policy = WordlistPolicy::new([base.join("wordlists")]).unwrap();
        match policy.read_lines("../private/secret.txt", &base.join("wordlists"), 0, 10) {
            Err(WorklistReadError::Denied(_)) => {}
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    // ---- manifest ----

    #[test]
    fn a_manifest_accepts_the_bytes_it_was_built_from() {
        let m = WordlistManifest::from_bytes("rockyou", b"alpha\nbravo\n");
        assert!(m.verify(b"alpha\nbravo\n").is_ok());
    }

    #[test]
    fn a_manifest_rejects_different_bytes() {
        let m = WordlistManifest::from_bytes("rockyou", b"alpha\nbravo\n");
        match m.verify(b"alpha\nbrav0\n") {
            Err(ManifestMismatch::Digest { .. }) => {}
            other => panic!("expected a digest mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_reports_a_length_mismatch_before_the_digest() {
        let m = WordlistManifest::from_bytes("rockyou", b"alpha\n");
        match m.verify(b"alpha\nbravo\n") {
            Err(ManifestMismatch::Length { expected: 6, got: 12 }) => {}
            other => panic!("expected a length mismatch, got {other:?}"),
        }
    }

    /// A single flipped bit must change the digest.
    #[test]
    fn the_digest_detects_a_single_bit_flip() {
        let base = b"alpha\nbravo\n".to_vec();
        let d = content_digest(&base);
        for i in 0..base.len() * 8 {
            let mut m = base.clone();
            m[i / 8] ^= 1 << (i % 8);
            assert_ne!(content_digest(&m), d, "bit {i} went undetected");
        }
    }

    #[test]
    fn an_empty_manifest_is_still_checked() {
        let m = WordlistManifest::from_bytes("empty", b"");
        assert!(m.verify(b"").is_ok());
        assert!(m.verify(b"x").is_err());
    }
}