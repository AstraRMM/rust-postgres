use crate::config::SslMode;
use crate::maybe_tls_stream::MaybeTlsStream;
use crate::tls::private::{ForcePrivateApi, PeerVerification};
use crate::tls::{TlsConnect, TlsFailure, TlsFailureKind};
use crate::Error;
use bytes::BytesMut;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn connect_tls<S, T>(
    mut stream: S,
    mode: SslMode,
    tls: T,
    has_hostname: bool,
) -> Result<MaybeTlsStream<S, T::Stream>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TlsConnect<S>,
{
    // Every policy decision is made before a single byte is written, so a
    // misconfigured client never starts a negotiation it cannot finish safely.
    let verification = tls.peer_verification(ForcePrivateApi);
    if verification == PeerVerification::VerifyFull && mode != SslMode::VerifyFull {
        return Err(Error::tls(Box::new(TlsFailure::new(
            TlsFailureKind::ModeNotVerifyFull,
            "the verifying rustls connector only accepts sslmode=verify-full",
        ))));
    }

    match mode {
        SslMode::Disable => return Ok(MaybeTlsStream::Raw(stream)),
        SslMode::Prefer if !tls.can_connect(ForcePrivateApi) => {
            return Ok(MaybeTlsStream::Raw(stream))
        }
        SslMode::Prefer | SslMode::Require => {}
        SslMode::VerifyFull => {
            if verification != PeerVerification::VerifyFull {
                return Err(Error::tls(Box::new(TlsFailure::new(
                    TlsFailureKind::UnverifiedConnector,
                    "sslmode=verify-full requires the built-in verifying rustls connector \
                     (cargo feature `rustls`); this connector does not attest chain and \
                     identity verification",
                ))));
            }
            if !has_hostname {
                return Err(Error::tls(Box::new(TlsFailure::new(
                    TlsFailureKind::NoExpectedIdentity,
                    "sslmode=verify-full requires an expected TLS identity (host)",
                ))));
            }
        }
    }

    let mut buf = BytesMut::new();
    frontend::ssl_request(&mut buf);
    stream.write_all(&buf).await.map_err(Error::io)?;

    let mut buf = [0];
    stream.read_exact(&mut buf).await.map_err(Error::io)?;

    if buf[0] != b'S' {
        if mode == SslMode::Require || mode == SslMode::VerifyFull {
            // Whatever follows (for example an ErrorResponse) was sent before
            // any authentication of the server and is deliberately not read.
            let detail = if buf[0] == b'E' {
                "server answered the TLS request with an unauthenticated error message; refusing plaintext"
            } else {
                "server does not support TLS; refusing plaintext"
            };
            return Err(Error::tls(Box::new(TlsFailure::new(
                TlsFailureKind::ServerRefusedTls,
                detail,
            ))));
        } else {
            return Ok(MaybeTlsStream::Raw(stream));
        }
    }

    if !has_hostname {
        return Err(Error::tls("no hostname provided for TLS handshake".into()));
    }

    let stream = tls
        .connect(stream)
        .await
        .map_err(|e| Error::tls(e.into()))?;

    Ok(MaybeTlsStream::Tls(stream))
}
