//! Verified TLS for service connections, built on rustls.
//!
//! [`MakeRustlsConnect`] is the only connector that satisfies
//! `sslmode=verify-full`, and it refuses every other mode. Each handshake
//!
//! * verifies the server chain against the explicitly configured trust roots
//!   only (never a platform or WebPKI store),
//! * verifies the end-entity certificate against the expected TLS identity of
//!   the endpoint being dialled (DNS or IP SAN), including discovered nodes,
//! * checks configured CRLs, and
//! * presents the configured client certificate for mutual TLS.
//!
//! Roots, client identity and CRLs are loaded together as one validated,
//! immutable **generation**. A handshake uses exactly one generation from
//! start to finish, so rotation can never mix old roots with a new client key.
//! A failed reload keeps the previous generation in service. Superseded
//! generations keep serving the sessions they already authenticated until they
//! are drained or revoked; revocation closes those sessions promptly, even
//! sessions that are currently borrowed and idle.

mod der;

use crate::config::{Config, SslMode};
use crate::endpoint::{self, EndpointLabel};
use crate::tls::{
    private, ChannelBinding, MakeTlsConnect, TlsConnect, TlsFailure, TlsFailureKind, TlsStream,
};
use ::rustls::client::WebPkiServerVerifier;
use ::rustls::crypto::CryptoProvider;
use ::rustls::pki_types::pem::PemObject;
use ::rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};
use ::rustls::sign::CertifiedKey;
use ::rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::future::Future;
use std::io::{self, Read};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))]
compile_error!(
    "the `rustls` feature needs a crypto provider: enable `rustls-aws-lc-rs`, `rustls-ring` or `rustls-fips`"
);

/// Upper bound on any credential file, so a misconfigured path cannot make the
/// process read an unbounded amount of data.
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1 << 20;

/// The crypto provider used for handshakes and signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provider {
    /// aws-lc-rs.
    #[cfg(feature = "rustls-aws-lc-rs")]
    AwsLcRs,
    /// ring.
    #[cfg(feature = "rustls-ring")]
    Ring,
    /// aws-lc-rs built against the AWS-LC FIPS module. Building a generation
    /// fails unless rustls reports the resulting configuration as FIPS mode.
    /// This is a build/runtime property, not by itself a compliance claim.
    #[cfg(feature = "rustls-fips")]
    AwsLcRsFips,
}

impl Default for Provider {
    #[allow(unreachable_code)]
    fn default() -> Provider {
        #[cfg(feature = "rustls-aws-lc-rs")]
        return Provider::AwsLcRs;
        #[cfg(all(feature = "rustls-ring", not(feature = "rustls-aws-lc-rs")))]
        return Provider::Ring;
    }
}

impl Provider {
    fn crypto_provider(self) -> CryptoProvider {
        match self {
            #[cfg(feature = "rustls-aws-lc-rs")]
            Provider::AwsLcRs => ::rustls::crypto::aws_lc_rs::default_provider(),
            #[cfg(feature = "rustls-ring")]
            Provider::Ring => ::rustls::crypto::ring::default_provider(),
            #[cfg(feature = "rustls-fips")]
            Provider::AwsLcRsFips => ::rustls::crypto::aws_lc_rs::default_provider(),
        }
    }

    fn requires_fips(self) -> bool {
        #[cfg(feature = "rustls-fips")]
        {
            if self == Provider::AwsLcRsFips {
                return true;
            }
        }
        false
    }
}

/// Which TLS protocol versions may be negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ProtocolVersions {
    /// TLS 1.3 only (default).
    #[default]
    Tls13Only,
    /// TLS 1.3, or TLS 1.2 with rustls's forward-secret AEAD suites, for
    /// servers that cannot negotiate TLS 1.3.
    Tls12AndTls13,
}

/// Provider and protocol settings for a [`MakeRustlsConnect`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsOptions {
    provider: Provider,
    protocol_versions: ProtocolVersions,
}

impl TlsOptions {
    /// Default options: the default provider and TLS 1.3 only.
    pub fn new() -> TlsOptions {
        TlsOptions::default()
    }

    /// Selects the crypto provider.
    pub fn provider(mut self, provider: Provider) -> TlsOptions {
        self.provider = provider;
        self
    }

    /// Selects the permitted protocol versions.
    pub fn protocol_versions(mut self, versions: ProtocolVersions) -> TlsOptions {
        self.protocol_versions = versions;
        self
    }
}

/// Why credential material was rejected. Messages name the role of the input
/// (`sslrootcert`, `sslkey`, ...) and never its path or contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsConfigErrorKind {
    /// The configuration did not request `sslmode=verify-full`.
    ModeNotVerifyFull,
    /// No trust roots were configured.
    MissingRootCert,
    /// Only one of `sslcert` and `sslkey` was configured.
    IncompleteClientIdentity,
    /// A credential file could not be read.
    Read,
    /// A credential file exceeds the size limit.
    FileTooLarge,
    /// The private key file is accessible to other users.
    KeyPermissions,
    /// The root file contained no certificates.
    NoRootCertificates,
    /// A root certificate could not be parsed or used as a trust anchor.
    InvalidRootCertificate,
    /// The client certificate chain could not be parsed.
    InvalidClientCertificate,
    /// A certificate is outside its validity period.
    CertificateNotCurrentlyValid,
    /// The private key could not be parsed or is not supported.
    InvalidPrivateKey,
    /// The key file contains more than one private key.
    MultiplePrivateKeys,
    /// The private key does not match the client leaf certificate.
    KeyMismatch,
    /// A CRL could not be parsed or used.
    InvalidCrl,
    /// The provider rejected the requested protocol configuration.
    Provider,
    /// FIPS mode was requested but the configuration is not in FIPS mode.
    FipsUnavailable,
    /// Draining requires a Tokio runtime.
    NoRuntime,
}

/// Credential material was rejected; the current generation is unchanged.
#[derive(Debug, Clone)]
pub struct TlsConfigError {
    kind: TlsConfigErrorKind,
    detail: &'static str,
}

impl TlsConfigError {
    fn new(kind: TlsConfigErrorKind, detail: &'static str) -> TlsConfigError {
        TlsConfigError { kind, detail }
    }

    /// The rejection category.
    pub fn kind(&self) -> TlsConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TLS configuration: {}", self.detail)
    }
}

impl std::error::Error for TlsConfigError {}

/// Bytes that are zeroed on drop.
#[derive(Clone)]
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

/// Unvalidated PEM inputs for one credential generation.
///
/// Nothing is trusted until [`MakeRustlsConnect::new`] or
/// [`MakeRustlsConnect::reload`] validates the whole set.
#[derive(Clone)]
pub struct TlsMaterial {
    roots: Vec<u8>,
    client: Option<(Vec<u8>, SecretBytes)>,
    crls: Vec<Vec<u8>>,
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("roots", &format_args!("<{} bytes>", self.roots.len()))
            .field("client_identity", &self.client.is_some())
            .field("crls", &self.crls.len())
            .finish()
    }
}

impl TlsMaterial {
    /// Starts from PEM-encoded trust roots. Only these roots are trusted.
    pub fn from_pem(roots: impl Into<Vec<u8>>) -> TlsMaterial {
        TlsMaterial {
            roots: roots.into(),
            client: None,
            crls: Vec::new(),
        }
    }

    /// Adds a PEM client certificate chain (leaf first) and its private key.
    pub fn with_client_identity(
        mut self,
        cert_chain: impl Into<Vec<u8>>,
        key: impl Into<Vec<u8>>,
    ) -> TlsMaterial {
        self.client = Some((cert_chain.into(), SecretBytes(key.into())));
        self
    }

    /// Adds PEM certificate revocation lists.
    pub fn with_crl(mut self, crl: impl Into<Vec<u8>>) -> TlsMaterial {
        self.crls.push(crl.into());
        self
    }

    /// Reads material from files. The key file must not be accessible to
    /// other users.
    pub fn from_files(
        root_cert: &Path,
        client_identity: Option<(&Path, &Path)>,
        crl: Option<&Path>,
    ) -> Result<TlsMaterial, TlsConfigError> {
        let mut material = TlsMaterial::from_pem(read_credential(root_cert, Role::RootCert)?);
        if let Some((cert, key)) = client_identity {
            let cert = read_credential(cert, Role::Cert)?;
            let key = read_credential(key, Role::Key)?;
            material = material.with_client_identity(cert, key);
        }
        if let Some(crl) = crl {
            material = material.with_crl(read_credential(crl, Role::Crl)?);
        }
        Ok(material)
    }

    /// Reads the `sslrootcert`, `sslcert`, `sslkey` and `sslcrl` files named
    /// by a configuration that requests `sslmode=verify-full`.
    pub fn from_config(config: &Config) -> Result<TlsMaterial, TlsConfigError> {
        if config.get_ssl_mode() != SslMode::VerifyFull {
            return Err(TlsConfigError::new(
                TlsConfigErrorKind::ModeNotVerifyFull,
                "service connections require sslmode=verify-full",
            ));
        }
        let root = config.get_ssl_root_cert().ok_or_else(|| {
            TlsConfigError::new(
                TlsConfigErrorKind::MissingRootCert,
                "sslmode=verify-full requires sslrootcert",
            )
        })?;
        let client = match (config.get_ssl_cert(), config.get_ssl_key()) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => {
                return Err(TlsConfigError::new(
                    TlsConfigErrorKind::IncompleteClientIdentity,
                    "sslcert and sslkey must be configured together",
                ))
            }
        };
        TlsMaterial::from_files(root, client, config.get_ssl_crl())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    RootCert,
    Cert,
    Key,
    Crl,
}

fn read_credential(path: &Path, role: Role) -> Result<Vec<u8>, TlsConfigError> {
    let read_error = match role {
        Role::RootCert => "sslrootcert could not be read",
        Role::Cert => "sslcert could not be read",
        Role::Key => "sslkey could not be read",
        Role::Crl => "sslcrl could not be read",
    };
    let file = std::fs::File::open(path)
        .map_err(|_| TlsConfigError::new(TlsConfigErrorKind::Read, read_error))?;
    #[cfg(unix)]
    {
        if role == Role::Key {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = file
                .metadata()
                .map_err(|_| TlsConfigError::new(TlsConfigErrorKind::Read, read_error))?;
            let mode = metadata.permissions().mode();
            // libpq's rule: at most u=rw (0600), or u=rw,g=r (0640) when the
            // file is owned by root.
            let allowed = if metadata.uid() == 0 { 0o640 } else { 0o600 };
            if mode & 0o777 & !allowed != 0 {
                return Err(TlsConfigError::new(
                    TlsConfigErrorKind::KeyPermissions,
                    "sslkey must not be accessible to other users (0600, or 0640 when owned by root)",
                ));
            }
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsConfigError::new(TlsConfigErrorKind::Read, read_error))?;
    if bytes.len() as u64 > MAX_CREDENTIAL_FILE_BYTES {
        return Err(TlsConfigError::new(
            TlsConfigErrorKind::FileTooLarge,
            "a credential file exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

/// Public facts about a validated generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationInfo {
    id: u64,
    roots: usize,
    client_identity: bool,
    crls: usize,
    provider: Provider,
    protocol_versions: ProtocolVersions,
    fips: bool,
    earliest_not_after: Option<SystemTime>,
}

impl GenerationInfo {
    /// Monotonic generation number, starting at 1.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Number of trust roots.
    pub fn roots(&self) -> usize {
        self.roots
    }

    /// Whether a client certificate is presented.
    pub fn has_client_identity(&self) -> bool {
        self.client_identity
    }

    /// Number of CRLs checked.
    pub fn crls(&self) -> usize {
        self.crls
    }

    /// The crypto provider.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// The permitted protocol versions.
    pub fn protocol_versions(&self) -> ProtocolVersions {
        self.protocol_versions
    }

    /// Whether rustls reports the configuration as FIPS mode.
    pub fn fips(&self) -> bool {
        self.fips
    }

    /// The earliest expiry among the roots and client chain, for alerting.
    pub fn earliest_not_after(&self) -> Option<SystemTime> {
        self.earliest_not_after
    }
}

struct Revocation {
    revoked: AtomicBool,
    next_waiter: AtomicU64,
    waiters: Mutex<HashMap<u64, Waker>>,
}

impl Revocation {
    fn new() -> Revocation {
        Revocation {
            revoked: AtomicBool::new(false),
            next_waiter: AtomicU64::new(0),
            waiters: Mutex::new(HashMap::new()),
        }
    }

    fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    fn revoke(&self) -> bool {
        let first = !self.revoked.swap(true, Ordering::SeqCst);
        let waiters = std::mem::take(&mut *self.waiters.lock());
        for (_, waker) in waiters {
            waker.wake();
        }
        first
    }

    fn register(&self, id: u64, cx: &Context<'_>) {
        let mut waiters = self.waiters.lock();
        match waiters.get(&id) {
            Some(existing) if existing.will_wake(cx.waker()) => {}
            _ => {
                waiters.insert(id, cx.waker().clone());
            }
        }
    }
}

struct Generation {
    info: GenerationInfo,
    client_config: Arc<ClientConfig>,
    revocation: Revocation,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn check_validity(
    der: &[u8],
    now: i64,
    earliest: &mut Option<i64>,
    invalid: TlsConfigError,
    expired: TlsConfigError,
) -> Result<(), TlsConfigError> {
    let (not_before, not_after) = der::validity(der).ok_or(invalid)?;
    if now < not_before || now > not_after {
        return Err(expired);
    }
    *earliest = Some(earliest.map_or(not_after, |e| e.min(not_after)));
    Ok(())
}

fn build_generation(
    material: &TlsMaterial,
    options: TlsOptions,
    id: u64,
) -> Result<Generation, TlsConfigError> {
    use TlsConfigErrorKind as K;
    let provider = Arc::new(options.provider.crypto_provider());
    let now = unix_now();
    let mut earliest = None;

    let mut roots = RootCertStore::empty();
    let mut root_count = 0;
    for item in CertificateDer::pem_slice_iter(&material.roots) {
        let der = item.map_err(|_| {
            TlsConfigError::new(K::InvalidRootCertificate, "sslrootcert is not valid PEM")
        })?;
        check_validity(
            &der,
            now,
            &mut earliest,
            TlsConfigError::new(
                K::InvalidRootCertificate,
                "sslrootcert contains an unparseable certificate",
            ),
            TlsConfigError::new(
                K::CertificateNotCurrentlyValid,
                "sslrootcert contains a certificate outside its validity period",
            ),
        )?;
        roots.add(der).map_err(|_| {
            TlsConfigError::new(
                K::InvalidRootCertificate,
                "sslrootcert contains a certificate that cannot be a trust anchor",
            )
        })?;
        root_count += 1;
    }
    if root_count == 0 {
        return Err(TlsConfigError::new(
            K::NoRootCertificates,
            "sslrootcert contains no certificates",
        ));
    }

    let mut crls = Vec::new();
    for pem in &material.crls {
        let before = crls.len();
        for item in CertificateRevocationListDer::pem_slice_iter(pem) {
            crls.push(
                item.map_err(|_| TlsConfigError::new(K::InvalidCrl, "sslcrl is not valid PEM"))?,
            );
        }
        if crls.len() == before {
            return Err(TlsConfigError::new(K::InvalidCrl, "sslcrl contains no CRLs"));
        }
    }
    let crl_count = crls.len();

    let mut verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone());
    if !crls.is_empty() {
        verifier = verifier.with_crls(crls).only_check_end_entity_revocation();
    }
    let verifier = verifier.build().map_err(|_| {
        TlsConfigError::new(
            K::InvalidCrl,
            "sslcrl or sslrootcert was rejected by the verifier",
        )
    })?;

    let versions: &[&'static SupportedProtocolVersion] = match options.protocol_versions {
        ProtocolVersions::Tls13Only => &[&::rustls::version::TLS13],
        ProtocolVersions::Tls12AndTls13 => {
            &[&::rustls::version::TLS13, &::rustls::version::TLS12]
        }
    };
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .map_err(|_| {
            TlsConfigError::new(
                K::Provider,
                "the crypto provider does not support the selected protocol versions",
            )
        })?
        .with_webpki_verifier(verifier);

    let mut client_config = match &material.client {
        None => builder.with_no_client_auth(),
        Some((chain_pem, key_pem)) => {
            let mut chain = Vec::new();
            for item in CertificateDer::pem_slice_iter(chain_pem) {
                let der = item.map_err(|_| {
                    TlsConfigError::new(K::InvalidClientCertificate, "sslcert is not valid PEM")
                })?;
                check_validity(
                    &der,
                    now,
                    &mut earliest,
                    TlsConfigError::new(
                        K::InvalidClientCertificate,
                        "sslcert contains an unparseable certificate",
                    ),
                    TlsConfigError::new(
                        K::CertificateNotCurrentlyValid,
                        "sslcert contains a certificate outside its validity period",
                    ),
                )?;
                chain.push(der);
            }
            if chain.is_empty() {
                return Err(TlsConfigError::new(
                    K::InvalidClientCertificate,
                    "sslcert contains no certificates",
                ));
            }
            let mut keys = PrivateKeyDer::pem_slice_iter(&key_pem.0);
            let key = keys
                .next()
                .ok_or_else(|| {
                    TlsConfigError::new(K::InvalidPrivateKey, "sslkey contains no private key")
                })?
                .map_err(|_| TlsConfigError::new(K::InvalidPrivateKey, "sslkey is not valid PEM"))?;
            if keys.next().is_some() {
                return Err(TlsConfigError::new(
                    K::MultiplePrivateKeys,
                    "sslkey contains more than one private key",
                ));
            }
            let signing_key = provider
                .key_provider
                .load_private_key(key.clone_key())
                .map_err(|_| {
                    TlsConfigError::new(
                        K::InvalidPrivateKey,
                        "sslkey is not a supported private key",
                    )
                })?;
            CertifiedKey::new(chain.clone(), signing_key)
                .keys_match()
                .map_err(|_| {
                    TlsConfigError::new(
                        K::KeyMismatch,
                        "sslkey does not match the sslcert leaf certificate",
                    )
                })?;
            builder.with_client_auth_cert(chain, key).map_err(|_| {
                TlsConfigError::new(
                    K::InvalidPrivateKey,
                    "sslkey was rejected by the crypto provider",
                )
            })?
        }
    };
    // Every connection performs a full handshake: no session resumption (a
    // resumed session skips certificate verification) and no early data.
    client_config.resumption = ::rustls::client::Resumption::disabled();
    client_config.enable_early_data = false;

    let fips = client_config.fips();
    if options.provider.requires_fips() && !fips {
        return Err(TlsConfigError::new(
            K::FipsUnavailable,
            "FIPS mode was requested but rustls does not report the configuration as FIPS",
        ));
    }

    Ok(Generation {
        info: GenerationInfo {
            id,
            roots: root_count,
            client_identity: material.client.is_some(),
            crls: crl_count,
            provider: options.provider,
            protocol_versions: options.protocol_versions,
            fips,
            earliest_not_after: earliest
                .filter(|t| *t >= 0)
                .map(|t| UNIX_EPOCH + Duration::from_secs(t as u64)),
        },
        client_config: Arc::new(client_config),
        revocation: Revocation::new(),
    })
}

struct Shared {
    options: TlsOptions,
    current: RwLock<Arc<Generation>>,
    next_id: AtomicU64,
    live: Mutex<Vec<Weak<Generation>>>,
    reload_lock: Mutex<()>,
    reload_failures: AtomicU64,
}

/// The verifying rustls connector for `sslmode=verify-full`.
///
/// Clones share the same generations, so one reload or revocation applies to
/// every pool and client using the connector.
#[derive(Clone)]
pub struct MakeRustlsConnect {
    shared: Arc<Shared>,
}

impl fmt::Debug for MakeRustlsConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MakeRustlsConnect")
            .field("current", &self.current())
            .finish()
    }
}

impl MakeRustlsConnect {
    /// Validates `material` as generation 1.
    pub fn new(material: &TlsMaterial, options: TlsOptions) -> Result<Self, TlsConfigError> {
        let generation = Arc::new(build_generation(material, options, 1)?);
        Ok(MakeRustlsConnect {
            shared: Arc::new(Shared {
                options,
                live: Mutex::new(vec![Arc::downgrade(&generation)]),
                current: RwLock::new(generation),
                next_id: AtomicU64::new(2),
                reload_lock: Mutex::new(()),
                reload_failures: AtomicU64::new(0),
            }),
        })
    }

    /// Loads the material named by a `verify-full` configuration.
    pub fn from_config(config: &Config, options: TlsOptions) -> Result<Self, TlsConfigError> {
        MakeRustlsConnect::new(&TlsMaterial::from_config(config)?, options)
    }

    /// The generation new connections use.
    pub fn current(&self) -> GenerationInfo {
        self.shared.current.read().info.clone()
    }

    /// Whether `generation` is the one new connections use.
    pub fn is_current(&self, generation: u64) -> bool {
        self.shared.current.read().info.id == generation
    }

    /// Whether `generation` has been revoked (or is no longer tracked).
    pub fn is_revoked(&self, generation: u64) -> bool {
        let live = self.shared.live.lock();
        !live
            .iter()
            .filter_map(Weak::upgrade)
            .any(|g| g.info.id == generation && !g.revocation.is_revoked())
    }

    /// Number of rejected reloads since creation.
    pub fn reload_failures(&self) -> u64 {
        self.shared.reload_failures.load(Ordering::SeqCst)
    }

    /// Validates `material` as a complete new generation and makes it current.
    ///
    /// On error nothing changes: the previous generation stays current and
    /// the failure counter increments. Existing sessions keep the generation
    /// they authenticated with until it is drained or revoked.
    pub fn reload(&self, material: &TlsMaterial) -> Result<GenerationInfo, TlsConfigError> {
        let _guard = self.shared.reload_lock.lock();
        let id = self.shared.next_id.load(Ordering::SeqCst);
        let generation = match build_generation(material, self.shared.options, id) {
            Ok(generation) => Arc::new(generation),
            Err(e) => {
                self.shared.reload_failures.fetch_add(1, Ordering::SeqCst);
                return Err(e);
            }
        };
        self.shared.next_id.store(id + 1, Ordering::SeqCst);
        let info = generation.info.clone();
        {
            let mut live = self.shared.live.lock();
            live.retain(|g| g.strong_count() > 0);
            live.push(Arc::downgrade(&generation));
        }
        *self.shared.current.write() = generation;
        Ok(info)
    }

    /// Like [`reload`](Self::reload), then revokes every superseded
    /// generation after `drain`, closing their sessions even while borrowed.
    ///
    /// Requires a Tokio runtime; without one nothing is changed.
    pub fn reload_and_drain(
        &self,
        material: &TlsMaterial,
        drain: Duration,
    ) -> Result<GenerationInfo, TlsConfigError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            TlsConfigError::new(
                TlsConfigErrorKind::NoRuntime,
                "draining superseded generations requires a Tokio runtime",
            )
        })?;
        let info = self.reload(material)?;
        let superseded: Vec<Weak<Generation>> = self
            .shared
            .live
            .lock()
            .iter()
            .filter(|g| g.upgrade().map_or(false, |g| g.info.id < info.id))
            .cloned()
            .collect();
        handle.spawn(async move {
            tokio::time::sleep(drain).await;
            for generation in superseded {
                if let Some(generation) = generation.upgrade() {
                    generation.revocation.revoke();
                }
            }
        });
        Ok(info)
    }

    /// Revokes every generation older than the current one now, closing their
    /// sessions. Returns how many generations were newly revoked.
    pub fn revoke_superseded(&self) -> usize {
        let current = self.shared.current.read().info.id;
        self.revoke_where(|id| id < current)
    }

    /// Emergency revocation of one generation. Revoking the current
    /// generation also refuses new connections until a successful reload.
    pub fn revoke_generation(&self, generation: u64) -> bool {
        self.revoke_where(|id| id == generation) > 0
    }

    fn revoke_where(&self, predicate: impl Fn(u64) -> bool) -> usize {
        let targets: Vec<Arc<Generation>> = {
            let mut live = self.shared.live.lock();
            live.retain(|g| g.strong_count() > 0);
            live.iter()
                .filter_map(Weak::upgrade)
                .filter(|g| predicate(g.info.id))
                .collect()
        };
        targets.iter().filter(|g| g.revocation.revoke()).count()
    }
}

impl<S> MakeTlsConnect<S> for MakeRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = TlsFailure;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnect, TlsFailure> {
        if domain.is_empty() {
            return Err(TlsFailure::new(
                TlsFailureKind::NoExpectedIdentity,
                "sslmode=verify-full requires an expected TLS identity (host)",
            ));
        }
        let label = endpoint::label(domain);
        let generation = self.shared.current.read().clone();
        if generation.revocation.is_revoked() {
            return Err(TlsFailure::new(
                TlsFailureKind::GenerationRevoked,
                "the current TLS credential generation has been revoked",
            )
            .with_endpoint(label));
        }
        let name = ServerName::try_from(domain.to_string()).map_err(|_| {
            TlsFailure::new(
                TlsFailureKind::NoExpectedIdentity,
                "the expected TLS identity is not a valid DNS name or IP address",
            )
            .with_endpoint(label)
        })?;
        Ok(RustlsConnect {
            generation,
            name,
            label,
        })
    }
}

/// A single verifying handshake bound to one generation.
pub struct RustlsConnect {
    generation: Arc<Generation>,
    name: ServerName<'static>,
    label: EndpointLabel,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = TlsFailure;
    type Future = Pin<Box<dyn Future<Output = Result<RustlsStream<S>, TlsFailure>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let connector =
                tokio_rustls::TlsConnector::from(self.generation.client_config.clone());
            let label = self.label;
            let tls = connector
                .connect(self.name, stream)
                .await
                .map_err(|e| classify_io_error(&e).with_endpoint(label))?;
            if self.generation.revocation.is_revoked() {
                return Err(TlsFailure::new(
                    TlsFailureKind::GenerationRevoked,
                    "the TLS credential generation was revoked during the handshake",
                )
                .with_endpoint(label));
            }
            let channel_binding = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|leaf| der::tls_server_end_point(leaf.as_ref()));
            let waiter = self
                .generation
                .revocation
                .next_waiter
                .fetch_add(1, Ordering::SeqCst);
            Ok(RustlsStream {
                inner: tls,
                generation: self.generation,
                waiter,
                channel_binding,
            })
        })
    }

    fn peer_verification(&self, _: private::ForcePrivateApi) -> private::PeerVerification {
        private::PeerVerification::VerifyFull
    }
}

/// A verified TLS session. Reads and writes fail as soon as its generation is
/// revoked.
pub struct RustlsStream<S> {
    inner: tokio_rustls::client::TlsStream<S>,
    generation: Arc<Generation>,
    waiter: u64,
    channel_binding: Option<Vec<u8>>,
}

impl<S> RustlsStream<S> {
    /// The credential generation this session authenticated with. Pools use
    /// this with [`MakeRustlsConnect::is_current`] to retire superseded
    /// sessions on return.
    pub fn generation(&self) -> u64 {
        self.generation.info.id
    }

    /// The negotiated protocol version, e.g. `TLSv1_3`.
    pub fn protocol_version(&self) -> Option<String> {
        self.inner
            .get_ref()
            .1
            .protocol_version()
            .map(|v| format!("{:?}", v))
    }

    fn check_revoked(&self, cx: &Context<'_>) -> io::Result<()> {
        let revocation = &self.generation.revocation;
        if !revocation.is_revoked() {
            revocation.register(self.waiter, cx);
            if !revocation.is_revoked() {
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            TlsFailure::new(
                TlsFailureKind::GenerationRevoked,
                "the TLS credential generation of this session was revoked",
            ),
        ))
    }
}

impl<S> Drop for RustlsStream<S> {
    fn drop(&mut self) {
        self.generation
            .revocation
            .waiters
            .lock()
            .remove(&self.waiter);
    }
}

impl<S> AsyncRead for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check_revoked(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check_revoked(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check_revoked(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> TlsStream for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        match &self.channel_binding {
            Some(hash) => ChannelBinding::tls_server_end_point(hash.clone()),
            None => ChannelBinding::none(),
        }
    }
}

fn classify_io_error(e: &io::Error) -> TlsFailure {
    if let Some(inner) = e.get_ref() {
        if let Some(failure) = inner.downcast_ref::<TlsFailure>() {
            return failure.clone();
        }
        if let Some(rustls_error) = inner.downcast_ref::<::rustls::Error>() {
            let (kind, detail) = classify_rustls_error(rustls_error);
            return TlsFailure::new(kind, detail);
        }
    }
    TlsFailure::new(
        TlsFailureKind::HandshakeFailure,
        match e.kind() {
            io::ErrorKind::UnexpectedEof => {
                "the server closed the connection during the TLS handshake"
            }
            io::ErrorKind::TimedOut => "the TLS handshake timed out",
            _ => "I/O error during the TLS handshake",
        },
    )
}

/// Maps a rustls error to a failure category and a message that never
/// contains endpoint names (rustls's own messages can include the expected and
/// presented names).
pub(crate) fn classify_rustls_error(e: &::rustls::Error) -> (TlsFailureKind, &'static str) {
    use ::rustls::{AlertDescription as A, CertificateError as C, Error as E};
    use TlsFailureKind as K;
    match e {
        E::InvalidCertificate(c) => match c {
            C::UnknownIssuer => (
                K::UnknownIssuer,
                "server certificate chain does not lead to a configured trust root",
            ),
            C::NotValidForName | C::NotValidForNameContext { .. } => (
                K::IdentityMismatch,
                "server certificate is not valid for the expected TLS identity",
            ),
            C::Expired | C::ExpiredContext { .. } => {
                (K::Expired, "server certificate has expired")
            }
            C::NotValidYet | C::NotValidYetContext { .. } => {
                (K::NotYetValid, "server certificate is not yet valid")
            }
            C::Revoked => (K::Revoked, "server certificate has been revoked"),
            C::UnknownRevocationStatus => (
                K::Revoked,
                "server certificate revocation status is unknown for the configured CRLs",
            ),
            _ => (K::InvalidCertificate, "server certificate was rejected"),
        },
        E::AlertReceived(alert) => match alert {
            A::CertificateRequired => (
                K::ClientCertificateRequired,
                "server requires a client certificate",
            ),
            A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::AccessDenied => (
                K::ClientCertificateRejected,
                "server rejected the client certificate",
            ),
            A::ProtocolVersion => (
                K::ProtocolVersion,
                "server does not support an allowed TLS protocol version",
            ),
            _ => (K::HandshakeFailure, "server aborted the TLS handshake"),
        },
        E::PeerIncompatible(_) => (
            K::ProtocolVersion,
            "server is incompatible with the allowed TLS protocol settings",
        ),
        _ => (K::HandshakeFailure, "TLS handshake failed"),
    }
}
