use crate::config::SslMode;
use crate::tls::TlsConnect;
use crate::{connect_tls, Error};
use bytes::BytesMut;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    // The server closes the connection once it has processed the request
    // (signalled the backend). Waiting for that, as libpq does, keeps a
    // cancel from arriving after the caller has moved on to its next query.
    // Any read outcome other than data means the connection ended.
    let mut sink = [0u8; 64];
    while let Ok(n) = stream.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }

    crate::observe::note(crate::observe::Q::cancel_requests, None);
    Ok(())
}
