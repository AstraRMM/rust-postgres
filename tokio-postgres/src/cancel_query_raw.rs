use crate::config::SslMode;
use crate::tls::TlsConnect;
use crate::{connect_tls, Error};
use bytes::BytesMut;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// How long a cancel request waits for the server to close the connection.
#[cfg(feature = "runtime")]
const CONFIRMATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn cancel_query_raw<S, T>(
    stream: S,
    mode: SslMode,
    tls: T,
    has_hostname: bool,
    process_id: i32,
    secret_key: i32,
    confirm: bool,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TlsConnect<S>,
{
    let mut stream = connect_tls::connect_tls(stream, mode, tls, has_hostname).await?;

    let mut buf = BytesMut::new();
    frontend::cancel_request(process_id, secret_key, &mut buf);

    stream.write_all(&buf).await.map_err(Error::io)?;
    stream.flush().await.map_err(Error::io)?;
    stream.shutdown().await.map_err(Error::io)?;
    crate::observe::note(crate::observe::Q::cancel_requests, None);

    // The server closes the connection once it has processed the request
    // (signalled the backend). `CancelToken::cancel_query` waits for that,
    // as libpq does, so a cancel cannot arrive after the caller has moved on
    // to its next query. The raw-stream API keeps returning once the request
    // is sent: its caller owns the stream and the executor.
    if confirm {
        confirm_close(&mut stream).await?;
    }
    Ok(())
}

/// Waits (bounded) for the server to close the cancel connection. Only a
/// clean close confirms the request; a TLS peer closing without
/// close_notify still counts as a close. A reset, a reply or a timeout is
/// an error.
#[cfg(feature = "runtime")]
async fn confirm_close<S>(stream: &mut S) -> Result<(), Error>
where
    S: AsyncRead + Unpin,
{
    use std::io;
    use tokio::io::AsyncReadExt;

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(CONFIRMATION_TIMEOUT, stream.read(&mut byte))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the server did not confirm the cancel request",
            ))
        });
    match read {
        Ok(0) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Ok(_) => Err(Error::io(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected data on the cancel connection",
        ))),
        Err(e) => Err(Error::io(e)),
    }
}

#[cfg(not(feature = "runtime"))]
async fn confirm_close<S>(_: &mut S) -> Result<(), Error> {
    Ok(())
}
