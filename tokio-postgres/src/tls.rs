//! TLS support.

use crate::endpoint::EndpointLabel;
use std::borrow::Cow;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) mod private {
    pub struct ForcePrivateApi;

    /// What a connector attests about peer verification. Only connectors
    /// inside this crate can override the attestation, because external code
    /// cannot name these types.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PeerVerification {
        /// Nothing is known about how (or whether) the peer is verified.
        Unattested,
        /// The connector verifies the chain against explicit trust roots and
        /// the certificate against the expected TLS identity.
        VerifyFull,
    }
}

/// Channel binding information returned from a TLS handshake.
pub struct ChannelBinding {
    pub(crate) tls_server_end_point: Option<Vec<u8>>,
}

impl ChannelBinding {
    /// Creates a `ChannelBinding` containing no information.
    pub fn none() -> ChannelBinding {
        ChannelBinding {
            tls_server_end_point: None,
        }
    }

    /// Creates a `ChannelBinding` containing `tls-server-end-point` channel binding information.
    pub fn tls_server_end_point(tls_server_end_point: Vec<u8>) -> ChannelBinding {
        ChannelBinding {
            tls_server_end_point: Some(tls_server_end_point),
        }
    }
}

/// A constructor of `TlsConnect`ors.
///
/// Requires the `runtime` Cargo feature (enabled by default).
#[cfg(feature = "runtime")]
pub trait MakeTlsConnect<S> {
    /// The stream type created by the `TlsConnect` implementation.
    type Stream: TlsStream + Unpin;
    /// The `TlsConnect` implementation created by this type.
    type TlsConnect: TlsConnect<S, Stream = Self::Stream>;
    /// The error type returned by the `TlsConnect` implementation.
    type Error: Into<Box<dyn Error + Sync + Send>>;

    /// Creates a new `TlsConnect`or.
    ///
    /// The domain name is provided for certificate verification and SNI.
    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error>;
}

/// An asynchronous function wrapping a stream in a TLS session.
pub trait TlsConnect<S> {
    /// The stream returned by the future.
    type Stream: TlsStream + Unpin;
    /// The error returned by the future.
    type Error: Into<Box<dyn Error + Sync + Send>>;
    /// The future returned by the connector.
    type Future: Future<Output = Result<Self::Stream, Self::Error>>;

    /// Returns a future performing a TLS handshake over the stream.
    fn connect(self, stream: S) -> Self::Future;

    #[doc(hidden)]
    fn can_connect(&self, _: private::ForcePrivateApi) -> bool {
        true
    }

    #[doc(hidden)]
    fn peer_verification(&self, _: private::ForcePrivateApi) -> private::PeerVerification {
        private::PeerVerification::Unattested
    }
}

/// A TLS-wrapped connection to a PostgreSQL database.
pub trait TlsStream: AsyncRead + AsyncWrite {
    /// Returns channel binding information for the session.
    fn channel_binding(&self) -> ChannelBinding;
}

/// A `MakeTlsConnect` and `TlsConnect` implementation which simply returns an error.
///
/// This can be used when `sslmode` is `none` or `prefer`.
#[derive(Debug, Copy, Clone)]
pub struct NoTls;

#[cfg(feature = "runtime")]
impl<S> MakeTlsConnect<S> for NoTls {
    type Stream = NoTlsStream;
    type TlsConnect = NoTls;
    type Error = NoTlsError;

    fn make_tls_connect(&mut self, _: &str) -> Result<NoTls, NoTlsError> {
        Ok(NoTls)
    }
}

impl<S> TlsConnect<S> for NoTls {
    type Stream = NoTlsStream;
    type Error = NoTlsError;
    type Future = NoTlsFuture;

    fn connect(self, _: S) -> NoTlsFuture {
        NoTlsFuture(())
    }

    fn can_connect(&self, _: private::ForcePrivateApi) -> bool {
        false
    }
}

/// The future returned by `NoTls`.
pub struct NoTlsFuture(());

impl Future for NoTlsFuture {
    type Output = Result<NoTlsStream, NoTlsError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Err(NoTlsError(())))
    }
}

/// The TLS "stream" type produced by the `NoTls` connector.
///
/// Since `NoTls` doesn't support TLS, this type is uninhabited.
pub enum NoTlsStream {}

impl AsyncRead for NoTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match *self {}
    }
}

impl AsyncWrite for NoTlsStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        match *self {}
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self {}
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self {}
    }
}

impl TlsStream for NoTlsStream {
    fn channel_binding(&self) -> ChannelBinding {
        match *self {}
    }
}

/// The error returned by `NoTls`.
#[derive(Debug)]
pub struct NoTlsError(());

impl fmt::Display for NoTlsError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("no TLS implementation configured")
    }
}

impl Error for NoTlsError {}

/// The category of a TLS failure, for callers that must react differently to
/// configuration mistakes, untrusted peers and transient conditions.
///
/// None of these categories is ever retried with weaker verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsFailureKind {
    /// `sslmode=verify-full` was requested with a connector that does not
    /// attest full verification (for example `NoTls` or a third-party
    /// connector).
    UnverifiedConnector,
    /// The verifying connector was used with a mode other than `verify-full`.
    ModeNotVerifyFull,
    /// No expected TLS identity (hostname or IP address) was available.
    NoExpectedIdentity,
    /// The server refused to start TLS.
    ServerRefusedTls,
    /// The server certificate chain does not lead to a configured trust root.
    UnknownIssuer,
    /// The server certificate is not valid for the expected TLS identity.
    IdentityMismatch,
    /// The server certificate has expired.
    Expired,
    /// The server certificate is not yet valid.
    NotYetValid,
    /// The server certificate has been revoked by a configured CRL.
    Revoked,
    /// A configured CRL needed to check the server chain is past its
    /// `nextUpdate` and CRL expiry is enforced
    /// (`rustls::CrlExpiration::Enforce`).
    CrlExpired,
    /// The server certificate was rejected for another reason.
    InvalidCertificate,
    /// The server rejected the client certificate.
    ClientCertificateRejected,
    /// The server required a client certificate and none was configured.
    ClientCertificateRequired,
    /// No mutually acceptable TLS protocol version.
    ProtocolVersion,
    /// The handshake failed for another reason.
    HandshakeFailure,
    /// The credential generation used by this session was revoked.
    GenerationRevoked,
}

/// A classified TLS failure.
///
/// The message never contains credentials, file paths, key material or raw
/// endpoint addresses; endpoints are reported as keyed labels.
#[derive(Debug, Clone)]
pub struct TlsFailure {
    kind: TlsFailureKind,
    detail: Cow<'static, str>,
    endpoint: Option<EndpointLabel>,
}

impl TlsFailure {
    pub(crate) fn new(kind: TlsFailureKind, detail: impl Into<Cow<'static, str>>) -> TlsFailure {
        TlsFailure {
            kind,
            detail: detail.into(),
            endpoint: None,
        }
    }

    #[cfg_attr(not(feature = "rustls"), allow(dead_code))]
    pub(crate) fn with_endpoint(mut self, endpoint: EndpointLabel) -> TlsFailure {
        self.endpoint = Some(endpoint);
        self
    }

    /// The failure category.
    pub fn kind(&self) -> TlsFailureKind {
        self.kind
    }

    /// The redacted label of the endpoint involved, when known.
    pub fn endpoint(&self) -> Option<EndpointLabel> {
        self.endpoint
    }
}

impl fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)?;
        if let Some(endpoint) = &self.endpoint {
            write!(f, " (endpoint {})", endpoint)?;
        }
        Ok(())
    }
}

impl Error for TlsFailure {}
