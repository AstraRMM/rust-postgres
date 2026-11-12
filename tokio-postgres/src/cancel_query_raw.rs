use crate::config::SslMode;
use crate::tls::TlsConnect;
use crate::{connect_tls, Error};
use bytes::BytesMut;
use postgres_protocol::message::frontend;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    // (signalled the backend). Waiting for that, as libpq does, keeps a
    // cancel from arriving after the caller has moved on to its next query.
    // Only a clean close confirms it; a TLS peer closing without
    // close_notify still counts as a close. A reset or a reply is an error.
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte);
    #[cfg(feature = "runtime")]
    let read = async {
        tokio::time::timeout(CONFIRMATION_TIMEOUT, read)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the server did not confirm the cancel request",
                ))
            })
    };
    match read.await {
        Ok(0) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Ok(_) => {
            return Err(Error::io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected data on the cancel connection",
            )))
        }
        Err(e) => return Err(Error::io(e)),
    }
    Ok(())
}
