//! Access control for the dashboard: bind policy, bearer token, CSRF, rate
//! limit, audit log, CSP.
//!
//! # What was wrong
//!
//! `WebConfig::default()` returned `host: "0.0.0.0"` with `auth_token: None`. The
//! dashboard therefore listened on every interface of every machine it ran on,
//! and any process that could reach the port could start an attack. `start`
//! reported success, so the exposure was at least visible; the fix for that is in
//! `attack.rs`, and this file is what stops the port from being reachable at all
//! by anything but the operator.
//!
//! Four independent layers, because they fail differently:
//!
//!   1. [`WebBindPolicy`] keeps the listener on loopback unless the operator
//!      says otherwise, and says so loudly when they do.
//!   2. [`TokenStore`] makes every mutating route require a token the operator has.
//!   3. [`CsrfGuard`] stops another site in the operator's browser from spending
//!      that token, which a token alone does not prevent.
//!   4. [`RateLimiter`] bounds what a holder of the token can spend.
//!
//! Layers 1 and 2 are the gate; 3 and 4 are what makes the gate worth having.
//!
//! # Token storage
//!
//! The token is written with mode 0600 by creating the file under a mode that
//! already forbids group and other, so there is no window in which the token is
//! readable by anyone else. `load_or_create` reports whether it created the file
//! so the caller can print the token exactly once, on the run that made it.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::auth::BindRefusal::ExposedBindNotAllowed;

/// Header every mutating request must carry.
///
/// A cross site request from a browser cannot set a custom header without
/// passing a CORS preflight, and this server sends no CORS headers, so the
/// browser refuses to send the request at all. That is what makes the custom
/// header a CSRF defence rather than decoration.
pub const CSRF_HEADER: &str = "x-pwdcrack-request";

/// Value the header must carry. Any value would do; a named one makes an
/// outgoing request identifiable in a packet capture.
pub const CSRF_HEADER_VALUE: &str = "dashboard";

/// Header carrying the bearer token.
pub const AUTH_HEADER: &str = "authorization";

/// Name of the cookie set alongside the token.
pub const SESSION_COOKIE: &str = "pwdcrack_session";

/// Bytes of entropy in a generated token.
///
/// 32 bytes is the width of a Curve25519 key and 256 bits of a CSPRNG draw.
/// The token is the only thing standing between a routable port and the ability
/// to launch password cracking, so it gets a width that does not depend on
/// hiding it.
pub const TOKEN_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Bind policy
// ---------------------------------------------------------------------------

/// Why a bind was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindRefusal {
    /// A routable address was requested without the explicit opt in.
    ExposedBindNotAllowed(String),
    /// A routable address was requested, accepted, but without a token.
    ExposedBindNeedsToken(String),
    /// The address could not be parsed.
    UnparsableHost(String),
    /// A port of zero, which binds an arbitrary port and cannot be reported back
    /// to the operator usefully.
    ZeroPort,
}

impl fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindRefusal::ExposedBindNotAllowed(h) => write!(
                f,
                "refusing to bind {h}: it is reachable from outside this machine.\n\
                 Pass --allow-exposed-web-bind to do it anyway, and read what that\n\
                 means in docs/PHASE10_STATUS.md first."
            ),
            BindRefusal::ExposedBindNeedsToken(h) => write!(
                f,
                "refusing to bind {h} with no authentication token.\n\
                 A routable dashboard with no token lets anyone who can reach the\n\
                 port start an attack. Set a token, or bind to 127.0.0.1."
            ),
            BindRefusal::UnparsableHost(h) => {
                write!(f, "--web-host {h:?} is not an IP address")
            }
            BindRefusal::ZeroPort => {
                write!(f, "--web-port 0 binds an arbitrary port; pass a real one")
            }
        }
    }
}

impl std::error::Error for BindRefusal {}

/// Addresses that mean "every interface".
///
/// `0.0.0.0` is the IPv4 wildcard and `::` the IPv6 one. A dashboard that binds
/// `::` on a machine with IPv4 mapped addresses is reachable over IPv4 as well,
/// which is why the IPv6 wildcard is treated the same way rather than as a
/// separate, safer case.
pub const WILDCARD_HOSTS: &[&str] = &["0.0.0.0", "::", "[::]", "*", ""];

/// Whether a host string names a routable interface.
pub fn is_wildcard(host: &str) -> bool {
    let h = host.trim();
    WILDCARD_HOSTS.iter().any(|w| w.eq_ignore_ascii_case(h))
}

/// Whether a host string is a loopback address.
pub fn is_loopback(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    h == "::1" || h.starts_with("127.")
}

/// Where the dashboard listens, and what has to be true for that to be allowed.
#[derive(Debug, Clone)]
pub struct WebBindPolicy {
    pub host: String,
    pub port: u16,
    /// The operator passed the flag that permits a routable bind.
    pub allow_exposed: bool,
    /// A token exists.
    pub has_token: bool,
}

impl Default for WebBindPolicy {
    /// Loopback, and not routable. This default is the whole point of B-30.
    fn default() -> Self {
        WebBindPolicy {
            host: "127.0.0.1".to_string(),
            port: 8080,
            allow_exposed: false,
            has_token: false,
        }
    }
}

impl WebBindPolicy {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        WebBindPolicy {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Whether this bind is reachable from another machine.
    pub fn is_exposed(&self) -> bool {
        !is_loopback(&self.host)
    }

    /// The string handed to `TcpListener::bind`.
    pub fn socket_addr(&self) -> String {
        // Bare IPv6 literals need brackets to be a socket address.
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Whether this configuration is allowed to start.
    ///
    /// Three refusals, in increasing order of severity:
    ///
    /// * a wildcard host without `--allow-exposed-web-bind` is refused, because
    ///   the operator has not said they meant it;
    /// * a wildcard host with no token is refused even with the flag, because a
    ///   token is what makes an exposed dashboard defensible and the flag is not
    ///   a substitute for one;
    /// * port 0 is refused because it binds an arbitrary port.
    ///
    /// A non wildcard non loopback address such as `192.168.1.10` is exposed too
    /// and needs the flag for the same reason, so the check is on `is_loopback`
    /// rather than on the literal wildcard strings.
    pub fn check(&self) -> Result<(), BindRefusal> {
        if self.port == 0 {
            return Err(BindRefusal::ZeroPort);
        }
        if !is_loopback(&self.host) {
            if !self.allow_exposed {
                return Err(ExposedBindNotAllowed(self.host.clone()));
            }
            if !self.has_token {
                return Err(BindRefusal::ExposedBindNeedsToken(self.host.clone()));
            }
        }
        Ok(())
    }

    /// One line describing what this bind means, for the startup banner.
    pub fn describe(&self) -> String {
        if self.is_exposed() {
            format!(
                "{}:{} REACHABLE FROM OTHER MACHINES, token required",
                self.host, self.port
            )
        } else {
            format!("{}:{} loopback only", self.host, self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/// Why a token operation failed.
#[derive(Debug)]
pub enum TokenError {
    /// The OS entropy source could not be read.
    Entropy(std::io::Error),
    /// The file could not be read or written.
    Io(std::io::Error),
    /// The file exists and holds something that is not a token.
    Malformed { path: PathBuf, found: usize },
    /// The file exists but is readable by someone other than the owner.
    TooPermissive { path: PathBuf, mode: u32 },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Entropy(e) => write!(f, "cannot read the system entropy source: {e}"),
            TokenError::Io(e) => write!(f, "token file: {e}"),
            TokenError::Malformed { path, found } => write!(
                f,
                "{} holds {found} characters, which is not a token.\n\
                 Delete it to generate a new one; the old token is then unknown.",
                path.display()
            ),
            TokenError::TooPermissive { path, mode } => write!(
                f,
                "{} is mode {:04o}, so other users can read the dashboard token.\n\
                 Run: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            ),
        }
    }
}

impl std::error::Error for TokenError {}

/// Draws a token from the OS entropy source.
///
/// Refuses rather than falling back. A dashboard token that came from a clock or
/// a counter is a token an attacker can predict, and a predictable token on an
/// exposed port is the same as no token at all.
pub fn generate_token() -> Result<String, TokenError> {
    let mut buf = [0u8; TOKEN_BYTES];
    // getrandom reports failure as an error rather than panicking, so a machine
    // with no entropy source refuses to start the dashboard instead of aborting.
    // The crate's own error type is carried into std::io::Error so TokenError
    // does not have to name getrandom in its public surface.
    getrandom::getrandom(&mut buf)
        .map_err(|e| TokenError::Entropy(std::io::Error::other(e)))?;
    Ok(hex::encode(buf))
}

/// Compares two byte strings without an early exit on the first difference.
///
/// The length check is not constant time, which leaks the length and nothing
/// else. That is acceptable because a token is always `TOKEN_BYTES * 2` hex
/// characters, so the length is known in advance and reveals nothing new.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extracts a bearer token from an `Authorization` header value.
///
/// Returns `None` for a missing header, a scheme other than `bearer`, or an
/// empty credential. Case insensitive on the scheme because RFC 7235 says the
/// scheme is case insensitive and a strict match here would only produce
/// confusing 401s.
pub fn parse_bearer(header: Option<&str>) -> Option<&str> {
    let raw = header?;
    let (scheme, credential) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credential = credential.trim();
    if credential.is_empty() {
        return None;
    }
    Some(credential)
}

/// A token on disk.
#[derive(Debug, Clone)]
pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        TokenStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the token, or creates one if the file does not exist.
    ///
    /// The second element of the pair is `true` when a token was just generated,
    /// which is the only moment the operator can be shown it. The file is created
    /// with mode 0600 and the mode is verified after the write, so a filesystem
    /// with permissive defaults does not leave a window where the token is
    /// world readable.
    pub fn load_or_create(&self) -> Result<(String, bool), TokenError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                let token = text.trim().to_string();
                if token.len() != TOKEN_BYTES * 2 {
                    return Err(TokenError::Malformed {
                        path: self.path.clone(),
                        found: token.len(),
                    });
                }
                self.check_mode()?;
                Ok((token, false))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let token = generate_token()?;
                self.write_private(&token)?;
                Ok((token, true))
            }
            Err(e) => Err(TokenError::Io(e)),
        }
    }

    /// Fails when the token file is group or world readable.
    ///
    /// Checked on every load, not only on creation, because the operator may
    /// have changed it since, and a token file at 0644 is the same as no token.
    pub fn check_mode(&self) -> Result<(), TokenError> {
        let meta = fs::metadata(&self.path).map_err(TokenError::Io)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TokenError::TooPermissive {
                path: self.path.clone(),
                mode,
            });
        }
        Ok(())
    }

    /// Writes the token with mode 0600, creating the parent directory too.
    fn write_private(&self, token: &str) -> Result<(), TokenError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(TokenError::Io)?;
            }
        }
        // 0600 at creation. O_TRUNC on an existing file does not change its mode,
        // so the chmod below is what actually enforces it.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(TokenError::Io)?;
        writeln!(f, "{token}").map_err(TokenError::Io)?;
        f.sync_all().map_err(TokenError::Io)?;
        drop(f);
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
            .map_err(TokenError::Io)?;
        Ok(())
    }
}

/// The result of checking one request's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    Allowed,
    /// No token, or one that does not match.
    Rejected,
}

/// Checks a presented bearer token against the expected one.
pub fn verify_token(expected: &str, presented: Option<&str>) -> AuthOutcome {
    let Some(presented) = presented else {
        return AuthOutcome::Rejected;
    };
    // Compared as text, because that is what the credential is. Decoding the
    // expected token first and comparing raw bytes against the header string
    // compares a 32 byte value with a 64 character one, which can never be
    // equal, so every request would be refused including the operator's own.
    //
    // A token of the wrong width cannot be what this crate generated, so it is
    // refused rather than compared. That is the fail closed direction: a token
    // file edited into an empty string or a placeholder never opens the port.
    if expected.len() != TOKEN_BYTES * 2 {
        return AuthOutcome::Rejected;
    }
    if constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        AuthOutcome::Allowed
    } else {
        AuthOutcome::Rejected
    }
}

/// The `Set-Cookie` value for the session cookie.
///
/// `SameSite=Strict` rather than `Lax`: the dashboard has no reason to be
/// reachable from a link at all, and `Strict` is the value that keeps the cookie
/// off every cross site request. `HttpOnly` because script has no business
/// reading it, and the CSP forbids inline script besides.
pub fn session_cookie_value(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"
    )
}

/// The `Content-Security-Policy` the dashboard serves on every response.
///
/// `default-src 'none'` denies everything not named. The allowances are exactly
/// what `index.html`, `style.css` and `app.js` need: no inline script, no
/// inline style, no remote origin, no object, no frame.
///
/// `script-src 'self'` with no `'unsafe-inline'` and no `'unsafe-eval'` is the
/// part that matters. An XSS in a dashboard that can start an attack is worse
/// than no dashboard, and this header removes the inline script that such an
/// injection would normally use.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'self'; \
     style-src 'self'; \
     img-src 'self' data:; \
     connect-src 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'; \
     base-uri 'none'; \
     object-src 'none'";

/// Why a mutating request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfOutcome {
    Allowed,
    /// The custom header was absent, which a browser will not send cross site.
    MissingHeader,
    /// The header was present with the wrong value.
    WrongValue,
}

/// Checks the CSRF header on a state changing request.
pub fn check_csrf(header: Option<&str>) -> CsrfOutcome {
    match header {
        None => CsrfOutcome::MissingHeader,
        Some(v) if v.trim() == CSRF_HEADER_VALUE => CsrfOutcome::Allowed,
        Some(_) => CsrfOutcome::WrongValue,
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Per source address limiting of mutating requests.
#[derive(Debug)]
pub struct RateLimiter {
    /// Tokens, in thousandths. u64 because a burst in the thousands times a
    /// thousand does not fit in 32 bits.
    capacity: u64,
    /// Refill per second, also in thousandths, so a rate of 0.5 per second is
    /// expressible and two limiters with the same setting behave identically.
    refill_per_milli: u64,
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Overridden in tests so a limiter can be exercised without sleeping.
    now: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens left, in thousandths. Fractional so a rate of 0.5/s is expressible.
    level: u64,
    last: Instant,
}

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateOutcome {
    Allowed { remaining: u32 },
    /// Refused. `retry_after` is in whole milliseconds.
    Refused { retry_after_ms: u64 },
}

impl RateLimiter {
    /// `per_second` requests, with room for a burst of `burst`.
    ///
    /// A burst of zero or a rate of zero would make every request fail or every
    /// request pass, so both are floored at one. Refusing to configure rather
    /// than silently clamping is not worth a configuration error class here.
    pub fn new(per_second: u32, burst: u32) -> Self {
        RateLimiter {
            capacity: (burst.max(1) as u64) * 1000,
            refill_per_milli: (per_second.max(1) as u64) * 1000,
            buckets: Mutex::new(HashMap::new()),
            now: Mutex::new(None),
        }
    }

    /// The setting a dashboard should use.
    ///
    /// Ten a second with a burst of twenty: an operator clicking start and stop
    /// never notices it, and a script looping on the endpoint is refused after a
    /// fraction of a second.
    pub fn dashboard_default() -> Self {
        RateLimiter::new(10, 20)
    }

    /// Whether the limiter uses a fixed clock. Test only.
    pub fn freeze(&self, at: Instant) {
        *self.now.lock().expect("rate limiter clock") = Some(at);
    }

    fn timestamp(&self) -> Instant {
        match *self.now.lock().expect("rate limiter clock") {
            Some(at) => at,
            None => Instant::now(),
        }
    }

    /// Charges one request against `source`.
    pub fn check(&self, source: &str) -> RateOutcome {
        let now = self.timestamp();
        let refill = self.refill_per_milli;
        let capacity = self.capacity;

        let mut buckets = self.buckets.lock().expect("rate limiter buckets");
        let bucket = buckets.entry(source.to_string()).or_insert(Bucket {
            level: capacity,
            last: now,
        });

        let elapsed_ms = now.saturating_duration_since(bucket.last).as_millis() as u64;
        bucket.level = (bucket.level + elapsed_ms * refill).min(capacity);
        bucket.last = now;

        if bucket.level >= 1000 {
            bucket.level -= 1000;
            RateOutcome::Allowed {
                remaining: (bucket.level / 1000) as u32,
            }
        } else {
            // Never longer than a full refill, so a caller that backs off sees
            // the limit lift when the budget has actually returned.
            let missing = 1000 - bucket.level;
            let wait_ms = missing.div_ceil(refill).min(capacity.div_ceil(refill));
            RateOutcome::Refused {
                retry_after_ms: wait_ms,
            }
        }
    }

    /// Forgets every source. Test only.
    pub fn reset(&self) {
        self.buckets.lock().expect("rate limiter buckets").clear();
    }

    /// How many sources are being tracked.
    pub fn tracked_sources(&self) -> usize {
        self.buckets.lock().expect("rate limiter buckets").len()
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// One mutating request.
///
/// Serialized so `/api/audit` can return it. The fields are deliberately plain:
/// this is what an operator reads to find out who has been trying, and a nested
/// struct would only make that harder.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub at_millis: u64,
    pub method: String,
    pub path: String,
    pub source: String,
    /// 0 for "no token offered", 1 for "token accepted", 2 for "token rejected".
    pub auth: u8,
    /// Why the request was refused, or the empty string when it was allowed.
    pub refusal: String,
    pub rate_limited: bool,
}

/// Records what was attempted, not only what succeeded.
///
/// Kept in memory and readable over an authenticated route, because an
/// unauthenticated flood is exactly the event an operator needs to see and it
/// never produces a successful request to trigger a log write.
#[derive(Debug)]
pub struct AuditLog {
    entries: Mutex<Vec<AuditEntry>>,
    capacity: usize,
    start: Instant,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        AuditLog {
            entries: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
            start: Instant::now(),
        }
    }

    pub fn dashboard_default() -> Self {
        // Five hundred entries, which at ten a second is the last fifty seconds
        // of a flood.
        AuditLog::new(500)
    }

    /// Records one request.
    pub fn record(&self, method: &str, path: &str, source: &str, auth: u8, refusal: &str, limited: bool) {
        let mut entries = self.entries.lock().expect("audit log");
        entries.push(AuditEntry {
            at_millis: self.start.elapsed().as_millis() as u64,
            method: method.to_string(),
            path: path.to_string(),
            source: source.to_string(),
            auth,
            refusal: refusal.to_string(),
            rate_limited: limited,
        });
        // Oldest first out, so a long lived dashboard does not grow without
        // bound.
        while entries.len() > self.capacity {
            entries.remove(0);
        }
    }

    pub fn snapshot(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit log").clone()
    }

    /// How many refused requests are recorded.
    pub fn refused_count(&self) -> usize {
        self.entries
            .lock()
            .expect("audit log")
            .iter()
            .filter(|e| !e.refusal.is_empty())
            .count()
    }

    pub fn clear(&self) {
        self.entries.lock().expect("audit log").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- bind policy ----

    #[test]
    fn the_default_bind_is_loopback() {
        let p = WebBindPolicy::default();
        assert_eq!(p.host, "127.0.0.1");
        assert!(!p.is_exposed(), "the default must not be reachable from elsewhere");
        assert!(p.check().is_ok(), "the default has to be allowed to start");
    }

    /// The defect this whole module exists for.
    #[test]
    fn a_wildcard_bind_is_refused_without_the_flag() {
        let p = WebBindPolicy::new("0.0.0.0", 8080);
        let e = p.check().expect_err("0.0.0.0 must be refused");
        assert!(matches!(e, BindRefusal::ExposedBindNotAllowed(_)));
        let msg = e.to_string();
        assert!(msg.contains("--allow-exposed-web-bind"), "names the way out: {msg}");
    }

    /// The flag alone is not enough, which is the point of the second check.
    #[test]
    fn an_exposed_bind_without_a_token_is_refused_even_with_the_flag() {
        let mut p = WebBindPolicy::new("0.0.0.0", 8080);
        p.allow_exposed = true;
        p.has_token = false;
        assert!(matches!(
            p.check(),
            Err(BindRefusal::ExposedBindNeedsToken(_))
        ));

        p.has_token = true;
        assert!(p.check().is_ok(), "exposed plus a token plus the flag is allowed");
    }

    /// A routable address that is not the literal wildcard needs the flag too.
    #[test]
    fn a_lan_address_counts_as_exposed() {
        let mut p = WebBindPolicy::new("192.168.1.10", 8080);
        assert!(p.is_exposed());
        assert!(p.check().is_err(), "a LAN address is exposed, wildcard or not");
        p.allow_exposed = true;
        assert!(p.check().is_err(), "and still needs a token");
    }

    #[test]
    fn the_ipv6_wildcard_counts_as_exposed() {
        let p = WebBindPolicy::new("::", 8080);
        assert!(p.is_exposed(), ":: is reachable over IPv4 mapped addresses too");
        assert!(p.check().is_err());
    }

    #[test]
    fn loopback_needs_neither_flag_nor_token() {
        for host in ["127.0.0.1", "127.0.0.53", "::1", "[::1]"] {
            let p = WebBindPolicy::new(host, 8080);
            assert!(!p.is_exposed(), "{host} is loopback");
            assert!(p.check().is_ok(), "{host} must start with no token and no flag");
        }
    }

    #[test]
    fn port_zero_is_refused() {
        let p = WebBindPolicy::new("127.0.0.1", 0);
        assert_eq!(p.check(), Err(BindRefusal::ZeroPort));
    }

    #[test]
    fn an_ipv6_socket_address_gets_brackets() {
        let p = WebBindPolicy::new("::1", 8080);
        assert_eq!(p.socket_addr(), "[::1]:8080");
        let p = WebBindPolicy::new("127.0.0.1", 8080);
        assert_eq!(p.socket_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn the_description_says_whether_it_is_reachable() {
        let mut p = WebBindPolicy::new("0.0.0.0", 8080);
        p.allow_exposed = true;
        p.has_token = true;
        assert!(p.describe().contains("REACHABLE"), "{}", p.describe());
        assert!(WebBindPolicy::default().describe().contains("loopback"));
    }

    // ---- token ----

    #[test]
    fn a_generated_token_has_the_advertised_width() {
        let t = generate_token().expect("entropy is available");
        assert_eq!(t.len(), TOKEN_BYTES * 2);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()), "{t}");
    }

    #[test]
    fn two_generated_tokens_differ() {
        let a = generate_token().expect("entropy");
        let b = generate_token().expect("entropy");
        assert_ne!(a, b, "32 bytes of CSPRNG must not repeat");
    }

    #[test]
    fn a_token_is_created_private_and_reloaded_unchanged() {
        let dir = std::env::temp_dir().join(format!("pwdcrack-tok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("token");
        let store = TokenStore::new(&path);

        let (token, created) = store.load_or_create().expect("creates");
        assert!(created, "the first load reports that it generated");
        assert_eq!(token.len(), TOKEN_BYTES * 2);

        let mode = fs::metadata(&path).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {:04o}, not 0600", mode);

        let (again, created_again) = store.load_or_create().expect("reloads");
        assert!(!created_again, "the second load must not claim to have generated");
        assert_eq!(again, token, "the token is stable across loads");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A token file somebody chmodded to 0644 is the same as no token.
    #[test]
    fn a_world_readable_token_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("pwdcrack-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("token");
        let store = TokenStore::new(&path);
        let (token, _) = store.load_or_create().expect("creates");
        assert!(store.load_or_create().is_ok());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let e = store.load_or_create().expect_err("0644 must be refused");
        assert!(matches!(e, TokenError::TooPermissive { .. }));
        assert!(e.to_string().contains("chmod 600"), "says how to fix it: {e}");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod back");
        assert_eq!(store.load_or_create().expect("ok").0, token);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_token_file_is_refused_rather_than_accepted() {
        let dir = std::env::temp_dir().join(format!("pwdcrack-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("token");
        fs::write(&path, "short").expect("write");
        let store = TokenStore::new(&path);
        let e = store.load_or_create().expect_err("five characters is not a token");
        assert!(matches!(e, TokenError::Malformed { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- bearer parsing and comparison ----

    #[test]
    fn a_bearer_header_yields_its_credential() {
        assert_eq!(parse_bearer(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(parse_bearer(Some("bearer abc123")), Some("abc123"));
        assert_eq!(parse_bearer(Some("BEARER   abc123 ")), Some("abc123"));
    }

    #[test]
    fn a_missing_or_malformed_authorization_header_yields_nothing() {
        assert_eq!(parse_bearer(None), None);
        assert_eq!(parse_bearer(Some("abc123")), None, "no scheme");
        assert_eq!(parse_bearer(Some("Basic dXNlcjpwdw==")), None, "wrong scheme");
        assert_eq!(parse_bearer(Some("Bearer   ")), None, "empty credential");
    }

    #[test]
    fn the_right_token_is_accepted_and_any_other_is_not() {
        let token = generate_token().expect("entropy");
        let header = format!("Bearer {token}");
        assert_eq!(verify_token(&token, parse_bearer(Some(&header))), AuthOutcome::Allowed);
        assert_eq!(verify_token(&token, None), AuthOutcome::Rejected);
        assert_eq!(verify_token(&token, Some("nope")), AuthOutcome::Rejected);

        // One character different, same length.
        let mut wrong: Vec<char> = token.chars().collect();
        wrong[0] = if wrong[0] == 'a' { 'b' } else { 'a' };
        let wrong: String = wrong.into_iter().collect();
        assert_eq!(verify_token(&token, Some(&wrong)), AuthOutcome::Rejected);
    }

    /// A token file edited into something that this crate could not have
    /// generated must not open the port, even if the request presents the same
    /// wrong string. Failing closed is the point.
    #[test]
    fn an_expected_token_of_the_wrong_width_allows_nothing() {
        for bad in ["", "short", &"a".repeat(TOKEN_BYTES * 2 + 1)] {
            assert_eq!(
                verify_token(bad, Some(bad)),
                AuthOutcome::Rejected,
                "{bad:?} was accepted as a token"
            );
        }
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn the_session_cookie_is_httponly_and_samesite_strict() {
        let c = session_cookie_value("deadbeef");
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Strict"), "{c}");
        assert!(c.contains("pwdcrack_session=deadbeef"), "{c}");
        assert!(!c.contains("Secure"), "no TLS listener yet; documented in the status file");
    }

    // ---- CSRF ----

    #[test]
    fn a_mutating_request_needs_the_named_header() {
        assert_eq!(check_csrf(Some(CSRF_HEADER_VALUE)), CsrfOutcome::Allowed);
        assert_eq!(check_csrf(None), CsrfOutcome::MissingHeader);
        assert_eq!(check_csrf(Some("1")), CsrfOutcome::WrongValue);
        assert_eq!(check_csrf(Some("")), CsrfOutcome::WrongValue);
    }

    /// The header name has to be one a browser will not attach cross site.
    #[test]
    fn the_csrf_header_is_not_a_simple_field() {
        assert_eq!(CSRF_HEADER, CSRF_HEADER.to_lowercase());
        assert!(!CSRF_HEADER.contains(' '));
    }

    /// The policy this module promises, checked as a string so a later edit that
    /// weakens it fails here rather than in a browser.
    #[test]
    fn the_csp_forbids_inline_script() {
        assert!(CONTENT_SECURITY_POLICY.contains("script-src 'self'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-eval"));
        assert!(CONTENT_SECURITY_POLICY.contains("default-src 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
    }

    // ---- rate limiting ----

    #[test]
    fn a_burst_is_allowed_and_then_refused() {
        let rl = RateLimiter::new(10, 3);
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        match rl.check("a") {
            RateOutcome::Refused { .. } => {}
            RateOutcome::Allowed { .. } => panic!("the fourth request exceeds a burst of three"),
        }
    }

    /// The limit is per source, so one flooder does not lock out the operator.
    #[test]
    fn the_limit_is_per_source() {
        let rl = RateLimiter::new(10, 2);
        assert!(matches!(rl.check("flood"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("flood"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("flood"), RateOutcome::Refused { .. }));
        assert!(
            matches!(rl.check("operator"), RateOutcome::Allowed { .. }),
            "a different source has its own budget"
        );
        assert_eq!(rl.tracked_sources(), 2);
    }

    #[test]
    fn a_refused_request_names_a_bounded_wait() {
        let rl = RateLimiter::new(10, 1);
        rl.check("a");
        match rl.check("a") {
            RateOutcome::Refused { retry_after_ms } => {
                assert!(retry_after_ms > 0, "a refusal must say how long to wait");
                assert!(retry_after_ms <= 1000, "at 10/s a full refill is 100ms, got {retry_after_ms}");
            }
            RateOutcome::Allowed { .. } => panic!("the second request exceeds a burst of one"),
        }
    }

    /// The bucket refills over time, which is the property that makes the
    /// limiter usable rather than a one shot fuse.
    #[test]
    fn a_bucket_refills_after_the_configured_delay() {
        let rl = RateLimiter::new(10, 2);
        let t0 = Instant::now();
        rl.freeze(t0);
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        assert!(matches!(rl.check("a"), RateOutcome::Refused { .. }));

        // 250ms at 10/s refills two and a half tokens, so the next call passes.
        rl.freeze(t0 + std::time::Duration::from_millis(250));
        assert!(
            matches!(rl.check("a"), RateOutcome::Allowed { .. }),
            "the budget must return over time"
        );

        // A long gap refills to capacity, not beyond it.
        rl.freeze(t0 + std::time::Duration::from_secs(3600));
        match rl.check("a") {
            RateOutcome::Allowed { remaining } => assert!(
                (1..=2).contains(&remaining),
                "a long idle period refills to the burst size, got {remaining}"
            ),
            RateOutcome::Refused { .. } => panic!("a refilled bucket must allow the request"),
        }
    }

    #[test]
    fn a_degenerate_configuration_still_makes_sense() {
        // Zero rate and zero burst would otherwise divide by zero or refuse
        // everything with no explanation.
        let rl = RateLimiter::new(0, 0);
        assert!(matches!(rl.check("a"), RateOutcome::Allowed { .. }));
        rl.reset();
        assert_eq!(rl.tracked_sources(), 0);
    }

    // ---- audit ----

    #[test]
    fn the_audit_log_records_attempts_not_only_successes() {
        let log = AuditLog::new(10);
        log.record("POST", "/api/start", "10.0.0.5", 2, "no bearer token", false);
        log.record("POST", "/api/stop", "10.0.0.5", 1, "", false);
        log.record("POST", "/api/start", "10.0.0.9", 1, "", true);

        let entries = log.snapshot();
        assert_eq!(entries.len(), 3);
        assert_eq!(log.refused_count(), 1, "the flood is visible");
        assert_eq!(entries[0].path, "/api/start");
        assert_eq!(entries[2].rate_limited, true);
    }

    #[test]
    fn the_audit_log_drops_the_oldest_entries() {
        let log = AuditLog::new(3);
        for i in 0..10 {
            log.record("POST", &format!("/api/{i}"), "a", 0, "", false);
        }
        let entries = log.snapshot();
        assert_eq!(entries.len(), 3, "a long lived dashboard must not grow without bound");
        assert_eq!(entries[0].path, "/api/7", "the oldest entries are the ones dropped");
        assert_eq!(entries[2].path, "/api/9");
    }
}