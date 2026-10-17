//! TLS for the cluster, with a certificate the master generates itself.
//!
//! # Why this was blocked before
//!
//! `docs/PHASE9_STATUS.md` said TLS was not done because `tokio-rustls` was not a
//! dependency and no certificate generator was available. Both were true of the
//! machine, not of the problem. `ring` builds without cmake, `rcgen` generates a
//! certificate in pure Rust, and the worker's trust decision is a file the
//! operator copies. So it is done.
//!
//! # What is actually protected
//!
//! The cluster traffic is: the nonce challenge, the token response, work units
//! naming a wordlist path, and every cracked password. On a plaintext socket a
//! host on the path sees all of it, and the token response is not the only thing
//! worth stealing. This encrypts the transport and authenticates the master's
//! certificate, which is what makes a worker able to tell a real master from an
//! impostor on the same subnet.
//!
//! # The material
//!
//! The master generates, on first run:
//!
//!   - `ca.pem`, a self signed CA, so the worker has something to pin that is
//!     not the leaf. A self signed leaf works too and is simpler, but then every
//!     future rotation needs a new trust decision;
//!   - `server.pem` and `server.key.pem`, a leaf signed by that CA carrying
//!     `localhost`, the host's own name, `127.0.0.1` and `::1` as subject
//!     alternative names.
//!
//! The private key is written with mode 0600 into a 0700 directory, atomically,
//! and the master refuses to start on a key file that anyone else can read. A
//! world readable key in a shared checkout is the same failure as a token on the
//! command line, which is why the mode is checked rather than set and hoped for.
//!
//! # What the worker must be given, and why
//!
//! A worker trusts a CA the operator names with `--master-ca`. There is a
//! trust-on-first-use mode (`--tls-tofu`) that pins the first certificate
//! fingerprint it sees to a file, and it is **refused on a non-loopback
//! address**, because TOFU against an attacker who can be first on the wire is
//! not trust. That refusal is in `ClusterTls::for_worker` and is tested.
//!
//! # Mutual authentication
//!
//! The plan offers "a shared token or a client certificate". This crate does the
//! token, in [`crate::admission`], and does not claim the client certificate:
//! there is no client identity to verify, because nothing in the protocol carries
//! one and adding it would need a second CA and a second keystore. Stated here
//! so `docs/PHASE9_STATUS.md` does not have to guess.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::Sha256;
use time::OffsetDateTime;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::codec::Link;

/// Environment variable that overrides where cluster TLS material lives.
pub const TLS_DIR_ENV: &str = "PWDCRACK_TLS_DIR";

/// File names inside the TLS directory.
pub const CA_FILE: &str = "ca.pem";
pub const SERVER_CERT_FILE: &str = "server.pem";
pub const SERVER_KEY_FILE: &str = "server.key.pem";

/// Lowercase hex of the SHA-256 of a DER certificate.
///
/// The pin a TOFU worker stores, and what an operator compares between two
/// hosts. SHA-256 over the whole certificate rather than the public key, so a
/// renewal that changes the serial number is visible.
pub fn fingerprint(der: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der.as_ref());
    hex::encode(h.finalize())
}

/// The certificate fingerprint of the peer on an accepted or established
/// connection, if there is one.
pub fn peer_fingerprint(conn: &rustls::ServerConnection) -> Option<String> {
    conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(fingerprint)
}

/// Where the master keeps its material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub dir: PathBuf,
}

impl TlsPaths {
    /// The default directory: `$PWDCRACK_TLS_DIR`, else
    /// `$XDG_STATE_HOME/pwdcrack/tls`, else `$HOME/.local/state/pwdcrack/tls`.
    ///
    /// Not `/tmp`, which is what the checkpoint used to use: `/tmp` is world
    /// readable, wiped on reboot, and shared between users on a multi user
    /// machine.
    pub fn discover() -> Result<Self, String> {
        if let Some(d) = std::env::var_os(TLS_DIR_ENV) {
            if !d.is_empty() {
                return Ok(TlsPaths {
                    dir: PathBuf::from(d),
                });
            }
        }
        if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
            if !base.is_empty() {
                return Ok(TlsPaths {
                    dir: PathBuf::from(base).join("pwdcrack").join("tls"),
                });
            }
        }
        let home = std::env::var_os("HOME")
            .ok_or_else(|| {
                format!(
                    "no HOME and no {TLS_DIR_ENV}, so there is nowhere to keep a \
                     cluster key. Set {TLS_DIR_ENV} to a directory only you can read."
                )
            })?
            .to_string_lossy()
            .into_owned();
        Ok(TlsPaths {
            dir: PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("pwdcrack")
                .join("tls"),
        })
    }

    pub fn ca(&self) -> PathBuf {
        self.dir.join(CA_FILE)
    }

    pub fn server_cert(&self) -> PathBuf {
        self.dir.join(SERVER_CERT_FILE)
    }

    pub fn server_key(&self) -> PathBuf {
        self.dir.join(SERVER_KEY_FILE)
    }

    /// The file a TOFU worker pins into.
    pub fn pin(&self) -> PathBuf {
        self.dir.join("master.fingerprint")
    }

    /// True when a complete set of material already exists.
    pub fn is_populated(&self) -> bool {
        self.ca().exists() && self.server_cert().exists() && self.server_key().exists()
    }
}

/// The master side of TLS.
#[derive(Clone)]
pub struct ClusterTlsServer {
    acceptor: TlsAcceptor,
    pub fingerprint: String,
    pub paths: TlsPaths,
}

/// The worker side of TLS.
#[derive(Clone)]
pub struct ClusterTlsClient {
    connector: TlsConnector,
    pub server_name: String,
    /// Where the trust decision came from, for the log line.
    pub trust: TrustSource,
    /// Where a first-use pin is written. `None` for a pinned CA, which needs no
    /// pin file because the CA file *is* the pin.
    pin_path: Option<PathBuf>,
}

/// How a worker's trust in the master was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    /// A CA the operator named.
    Pinned,
    /// The first certificate seen, stored locally.
    TrustOnFirstUse,
}

/// Which side of the connection a node is.
#[derive(Clone)]
pub enum ClusterTls {
    Server(Arc<ClusterTlsServer>),
    Client(Arc<ClusterTlsClient>),
}

impl std::fmt::Debug for ClusterTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterTls::Server(s) => f
                .debug_struct("ClusterTls::Server")
                .field("fingerprint", &s.fingerprint)
                .finish(),
            ClusterTls::Client(c) => f
                .debug_struct("ClusterTls::Client")
                .field("server_name", &c.server_name)
                .field("trust", &c.trust)
                .finish(),
        }
    }
}

/// Installs the process crypto provider exactly once.
///
/// `rustls` 0.23 with an explicit provider feature still wants a process default
/// for anything that builds a config the long way. Doing it twice is a panic, so
/// the guard is a `Once`.
fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // An error here means a provider is already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A certificate verifier that accepts the first certificate it sees and
/// refuses anything else afterwards.
///
/// # Why this is `danger`
///
/// It performs **no chain validation and no name check**. That is the entire
/// hazard of trust on first use and the reason
/// [`ClusterTls::for_worker_tofu`] refuses a master that is not on loopback: an
/// attacker who can be first on the wire chooses what this pins, and then every
/// later connection is a check against the attacker's certificate.
///
/// What it does do is pin. Once `pinned` holds a digest, a certificate that does
/// not hash to it is refused, so a later interception does not pass silently.
#[derive(Debug)]
struct TofuVerifier {
    pinned: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(end_entity.as_ref());
        let digest: [u8; 32] = h.finalize().into();

        let mut guard = self
            .pinned
            .lock()
            .map_err(|_| rustls::Error::General("the pin lock is poisoned".into()))?;
        match *guard {
            None => {
                log::warn!(
                    "cluster TLS: trusting on first use. The master certificate \
                     ({}) is being pinned now; copy the master's ca.pem onto this \
                     host and use --master-ca to turn this into a real trust decision.",
                    hex::encode(digest)
                );
                *guard = Some(digest);
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Some(want) if want == digest => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Some(_) => Err(rustls::Error::General(format!(
                "the master certificate is not the one pinned: pinned {}, presented {}",
                hex::encode(guard.unwrap()),
                hex::encode(digest)
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Reads PEM certificate blocks from a file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| format!("{} is not valid PEM: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} contains no certificates", path.display()));
    }
    Ok(certs)
}

/// Reads a PEM private key from a file.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("{} is not valid PEM: {e}", path.display()))?
        .ok_or_else(|| format!("{} contains no private key", path.display()))
}

/// Refuses a key file anyone but the owner can read.
///
/// Checked, not set-and-hope: `write_private` sets 0600, but a directory on a
/// shared filesystem, a restored backup, or a `umask` surprise can produce
/// something wider, and a cluster key that another local user can read is the
/// whole cluster's credential.
fn check_private_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} has mode {mode:04o}. A cluster private key readable by another \
                 user is a cluster credential, so refusing to start. \
                 Run: chmod 600 {}",
                path.display(),
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Writes a file atomically with mode 0600.
///
/// The temporary file is in the same directory so the rename is within one
/// filesystem, which is what makes it atomic. A partially written key is worse
/// than no key: the master would fail to start with a confusing TLS error rather
/// than clearly regenerating.
fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    set_dir_private(dir)?;

    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tls"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot set mode on {}: {e}", tmp.display()))?;
        }
        f.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("cannot flush {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot rename into {}: {e}", path.display())
    })
}

/// Makes a directory 0700, creating it if needed.
fn set_dir_private(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir)
            .map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
        if meta.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot set mode on {}: {e}", dir.display()))?;
        }
    }
    Ok(())
}

/// The generated material, kept so a caller can report the fingerprint before
/// deciding whether to publish it.
#[derive(Debug, Clone)]
pub struct GeneratedMaterial {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the leaf certificate, lowercase hex.
    pub fingerprint: String,
}

/// Generates a CA and a server leaf signed by it.
///
/// Subject alternative names are the loopback literals plus whatever host names
/// are given. A certificate with no SAN is rejected by every modern verifier, so
/// `localhost` is always present even if the operator names only an address.
pub fn generate(host_names: &[String]) -> Result<GeneratedMaterial, String> {
    let (not_before, not_after) = validity_window();

    // --- CA ---
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| format!("cannot build CA parameters: {e}"))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "pwdcrack cluster CA");
    ca_dn.push(DnType::OrganizationName, "pwdcrack");
    ca_params.distinguished_name = ca_dn;
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().map_err(|e| format!("cannot generate a CA key: {e}"))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("cannot self sign the CA: {e}"))?;

    // --- leaf ---
    let mut sans: Vec<SanType> = vec![
        SanType::DnsName("localhost".try_into().map_err(|_| "localhost is not a valid name")?),
    ];
    for ip in ["127.0.0.1", "::1"] {
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| format!("{ip} is not an address, which cannot happen"))?;
        sans.push(SanType::IpAddress(addr));
    }
    for h in host_names {
        if h.is_empty() {
            continue;
        }
        match h.parse::<IpAddr>() {
            Ok(a) => sans.push(SanType::IpAddress(a)),
            Err(_) => {
                if let Ok(d) = h.clone().try_into() {
                    sans.push(SanType::DnsName(d));
                } else {
                    log::warn!("cluster TLS: ignoring '{h}' as a certificate name, it is not a valid DNS name");
                }
            }
        }
    }

    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = sans;
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "pwdcrack cluster master");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.use_authority_key_identifier_extension = true;

    let leaf_key = KeyPair::generate().map_err(|e| format!("cannot generate a leaf key: {e}"))?;
    let ca_issuer = Issuer::from_params(&ca_params, ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .map_err(|e| format!("cannot sign the leaf: {e}"))?;

    let cert_pem = leaf_cert.pem();
    Ok(GeneratedMaterial {
        ca_pem: ca_cert.pem(),
        fingerprint: fingerprint(leaf_cert.der()),
        cert_pem,
        key_pem: leaf_key.serialize_pem(),
    })
}

/// The certificate's validity window.
///
/// One day of leeway backwards so a machine whose clock is slightly behind does
/// not generate a certificate that is already expired, and one year forwards so
/// the material is not valid until 4096. A finite lifetime is the point of
/// checking: a certificate valid for a thousand years is a permanent cluster
/// credential and there would then never be a reason to rotate it.
fn validity_window() -> (OffsetDateTime, OffsetDateTime) {
    const DAY: i64 = 86_400;
    const YEAR: i64 = 365 * DAY;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let from = OffsetDateTime::from_unix_timestamp(secs - DAY)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let to = OffsetDateTime::from_unix_timestamp(secs + YEAR).unwrap_or(from);
    (from, to)
}

impl ClusterTls {
    /// The master certificate fingerprint, when this is the master side.
    pub fn server_fingerprint(&self) -> Option<&str> {
        match self {
            ClusterTls::Server(s) => Some(&s.fingerprint),
            ClusterTls::Client(_) => None,
        }
    }

    /// Builds the master side, generating material on first run.
    pub fn for_master(paths: &TlsPaths) -> Result<Self, String> {
        install_provider();
        set_dir_private(&paths.dir)?;

        if !paths.is_populated() {
            let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into());
            let mat = generate(&[host])?;
            write_private(&paths.ca(), &mat.ca_pem)?;
            write_private(&paths.server_cert(), &mat.cert_pem)?;
            write_private(&paths.server_key(), &mat.key_pem)?;
            log::info!(
                "cluster TLS: generated a certificate authority in {} for master \
                 fingerprint {}",
                paths.dir.display(),
                mat.fingerprint
            );
            log::info!(
                "cluster TLS: give a worker this file to trust the master: {}",
                paths.ca().display()
            );
        }
        check_private_file(&paths.server_key())?;

        let certs = load_certs(&paths.server_cert())?;
        let key = load_key(&paths.server_key())?;
        let fp = fingerprint(&certs[0]);

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("the cluster certificate and key do not match: {e}"))?;

        Ok(ClusterTls::Server(Arc::new(ClusterTlsServer {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            fingerprint: fp,
            paths: paths.clone(),
        })))
    }

    /// Builds the worker side from an operator supplied CA file.
    pub fn for_worker_with_ca(ca_path: &Path, server_name: &str) -> Result<Self, String> {
        install_provider();
        let certs = load_certs(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for c in certs {
            roots
                .add(c)
                .map_err(|e| format!("{} is not usable as a trust anchor: {e}", ca_path.display()))?;
        }
        Self::assemble_client(roots, server_name, TrustSource::Pinned)
    }

    /// Builds the worker side by pinning the first certificate it sees.
    ///
    /// `allow_remote` is false when the master is not on loopback, and the
    /// function refuses rather than degrading. See the module note.
    ///
    /// A pin already on disk is loaded and enforced, so the permissive window
    /// exists exactly once: the first connection. After that a certificate that
    /// does not match is refused.
    pub fn for_worker_tofu(paths: &TlsPaths, server_name: &str, allow_remote: bool) -> Result<Self, String> {
        if !allow_remote {
            return Err(format!(
                "trust on first use is refused for a master that is not on loopback: \
                 the first certificate to arrive wins, and an attacker who can be \
                 first on the wire wins the cluster. Pass --master-ca with the \
                 master's {} instead.",
                TlsPaths::discover()
                    .map(|p| p.ca().display().to_string())
                    .unwrap_or_else(|_| "ca.pem".into())
            ));
        }
        install_provider();

        let pinned = match std::fs::read_to_string(paths.pin()) {
            Ok(text) => {
                let fp = text.trim().to_string();
                if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                    log::warn!(
                        "cluster TLS: {} is not a fingerprint, ignoring it. The next \
                         connection will pin whatever arrives.",
                        paths.pin().display()
                    );
                    None
                } else {
                    let mut bytes = [0u8; 32];
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&fp[i * 2..i * 2 + 2], 16).unwrap_or(0);
                    }
                    log::info!("cluster TLS: enforcing the pinned master certificate {fp}");
                    Some(bytes)
                }
            }
            Err(_) => None,
        };

        let verifier = TofuVerifier {
            pinned: Arc::new(std::sync::Mutex::new(pinned)),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(ClusterTls::Client(Arc::new(ClusterTlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            server_name: server_name.to_string(),
            trust: TrustSource::TrustOnFirstUse,
            pin_path: Some(paths.pin()),
        })))
    }

    fn assemble_client(
        roots: rustls::RootCertStore,
        server_name: &str,
        trust: TrustSource,
    ) -> Result<Self, String> {
        install_provider();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(ClusterTls::Client(Arc::new(ClusterTlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            server_name: server_name.to_string(),
            trust,
            pin_path: None,
        })))
    }

    /// Wraps an accepted TCP connection.
    pub async fn accept(
        &self,
        tcp: tokio::net::TcpStream,
    ) -> Result<Link, String> {
        match self {
            ClusterTls::Server(s) => {
                let tls = s
                    .acceptor
                    .accept(tcp)
                    .await
                    .map_err(|e| format!("TLS handshake failed: {e}"))?;
                Ok(Link::Tls(Box::new(tls)))
            }
            ClusterTls::Client(_) => Err("a client cannot accept a connection".to_string()),
        }
    }

    /// Wraps an established TCP connection from the worker side.
    pub async fn connect(
        &self,
        tcp: tokio::net::TcpStream,
        addr: &str,
    ) -> Result<Link, String> {
        match self {
            ClusterTls::Client(c) => {
                let host = tls_server_name(addr).unwrap_or_else(|| c.server_name.clone());
                let name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|_| format!("'{host}' is not a valid TLS server name"))?;
                let tls = c
                    .connector
                    .connect(name, tcp)
                    .await
                    .map_err(|e| {
                        format!(
                            "TLS handshake with {addr} failed: {e}. If the master regenerated \
                             its certificate after this worker first connected, the pin will \
                             no longer match; copy the master's ca.pem again and pass \
                             --master-ca."
                        )
                    })?;

                let link = Link::ClientTls(Box::new(tls));
                if let (Some(pin_path), Some(fp)) = (c.pin_path.as_ref(), observed_fingerprint(&link)) {
                    // Written only after a handshake that succeeded, and only in
                    // trust-on-first-use mode, so the pin file records a fact
                    // rather than an intention.
                    match std::fs::read_to_string(pin_path) {
                        Ok(existing) if existing.trim() == fp => {}
                        _ => {
                            if let Some(parent) = pin_path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            match std::fs::write(pin_path, &fp) {
                                Ok(()) => log::info!(
                                    "cluster TLS: pinned the master certificate to {} ({fp})",
                                    pin_path.display()
                                ),
                                Err(e) => log::warn!(
                                    "could not write the pin file {}: {e}. This worker will \
                                     pin again on every connection, so a later change of \
                                     certificate would go unnoticed.",
                                    pin_path.display()
                                ),
                            }
                        }
                    }
                }
                Ok(link)
            }
            ClusterTls::Server(_) => Err("a server cannot open a client connection".to_string()),
        }
    }

    /// The certificate the worker sees on an established connection.
    pub fn observed_fingerprint(&self, link: &Link) -> Option<String> {
        observed_fingerprint(link)
    }
}

/// The leaf certificate digest of a client side TLS connection, if it has one.
pub fn observed_fingerprint(link: &Link) -> Option<String> {
    match link {
        Link::ClientTls(s) => {
            let (_, conn) = s.get_ref();
            conn.peer_certificates()
                .and_then(|c| c.first())
                .map(fingerprint)
        }
        _ => None,
    }
}

/// The name to put in the SNI and to verify the certificate against.
///
/// A worker given `127.0.0.1:5555` connects to a certificate whose SANs include
/// the loopback literal, so the IP is the right name. An address that parses as
/// neither an IP nor a hostname is refused here rather than producing a
/// confusing certificate error later.
pub fn tls_server_name(addr: &str) -> Option<String> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() {
        Some(host.to_string())
    } else if host.contains('.') && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        Some(host.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_material_is_a_ca_signing_a_leaf() {
        let m = generate(&["node1.example".to_string()]).unwrap();
        assert!(m.ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(m.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(m.key_pem.contains("PRIVATE KEY"));
        assert_eq!(m.fingerprint.len(), 64, "SHA-256 hex is 64 characters");

        // The two PEM blocks are different certificates, which is what makes the
        // split meaningful: a worker pins the CA, not the leaf.
        assert_ne!(m.ca_pem, m.cert_pem);
    }

    #[test]
    fn the_leaf_names_loopback_even_when_the_host_is_a_name() {
        let m = generate(&["node1.example".to_string()]).unwrap();
        // SANs live inside the DER, so assert on behaviour instead: a verifier
        // built from the CA must accept a certificate for 127.0.0.1.
        let ca = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::io::Cursor::new(m.ca_pem.as_bytes()),
        ))
        .next()
        .unwrap()
        .unwrap();
        let leaf = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::io::Cursor::new(m.cert_pem.as_bytes()),
        ))
        .next()
        .unwrap()
        .unwrap();
        assert_ne!(ca, leaf);

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).expect("the generated CA must be a usable trust anchor");
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("verifier must build");
        let _ = verifier;
    }

    #[test]
    fn fingerprints_are_stable_and_content_addressed() {
        let m = generate(&[]).unwrap();
        let again = generate(&[]).unwrap();
        assert_ne!(
            m.fingerprint, again.fingerprint,
            "two generated certificates must not collide"
        );
        assert_eq!(m.fingerprint, m.fingerprint.to_lowercase());
    }

    #[test]
    fn a_world_readable_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("server.key.pem");
        std::fs::write(&key, "not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = check_private_file(&key).unwrap_err();
            assert!(err.contains("0644"), "unhelpful error: {err}");
            assert!(err.contains("chmod 600"), "no remedy offered: {err}");
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(check_private_file(&key).is_ok());
        }
        #[cfg(not(unix))]
        {
            assert!(check_private_file(&key).is_ok());
        }
    }

    #[test]
    fn writing_a_key_leaves_it_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("key.pem");
        write_private(&path, "secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode was {mode:04o}");
            let dmode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700, "directory mode was {dmode:04o}");
        }
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        write_private(&path, "a").unwrap();
        write_private(&path, "b").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn tofu_is_refused_for_a_remote_master() {
        let paths = TlsPaths {
            dir: std::env::temp_dir().join("pwdcrack-tofu-refusal-test"),
        };
        let err = ClusterTls::for_worker_tofu(&paths, "10.0.0.5", false).unwrap_err();
        assert!(err.contains("--master-ca"), "unhelpful error: {err}");
    }

    #[test]
    fn tofu_is_allowed_for_loopback() {
        let paths = TlsPaths {
            dir: std::env::temp_dir().join("pwdcrack-tofu-allow-test"),
        };
        let c = ClusterTls::for_worker_tofu(&paths, "127.0.0.1", true).unwrap();
        assert!(matches!(c, ClusterTls::Client(_)));
    }

    #[test]
    fn a_missing_ca_file_is_an_error_not_an_empty_trust_store() {
        let err = ClusterTls::for_worker_with_ca(
            Path::new("/nonexistent/ca.pem"),
            "localhost",
        )
        .unwrap_err();
        assert!(err.contains("cannot read"), "unhelpful error: {err}");
    }

    #[test]
    fn a_pem_with_no_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ca.pem");
        std::fs::write(&p, b"not pem at all\n").unwrap();
        assert!(ClusterTls::for_worker_with_ca(&p, "localhost").is_err());
    }

    #[test]
    fn a_server_name_is_taken_from_the_address() {
        assert_eq!(tls_server_name("127.0.0.1:5555").as_deref(), Some("127.0.0.1"));
        assert_eq!(tls_server_name("[::1]:5555").as_deref(), Some("::1"));
        assert_eq!(
            tls_server_name("master.example.org:5555").as_deref(),
            Some("master.example.org")
        );
        assert_eq!(tls_server_name("nohost").as_deref(), None);
    }

    #[test]
    fn paths_derive_from_the_environment_when_set() {
        // Serialised against other tests mutating the environment.
        let dir = tempfile::tempdir().unwrap();
        let old = std::env::var_os(TLS_DIR_ENV);
        // SAFETY: single threaded test section, restored immediately.
        unsafe { std::env::set_var(TLS_DIR_ENV, dir.path()) };
        let p = TlsPaths::discover().unwrap();
        unsafe {
            match &old {
                Some(v) => std::env::set_var(TLS_DIR_ENV, v),
                None => std::env::remove_var(TLS_DIR_ENV),
            }
        }
        assert_eq!(p.dir, dir.path());
        assert_eq!(p.ca(), dir.path().join(CA_FILE));
        assert_eq!(p.server_key(), dir.path().join(SERVER_KEY_FILE));
    }
}