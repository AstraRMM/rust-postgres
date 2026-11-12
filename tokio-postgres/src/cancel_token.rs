use crate::config::SslMode;
use crate::tls::TlsConnect;
#[cfg(feature = "runtime")]
use crate::{cancel_query, client::SocketConfig, tls::MakeTlsConnect, Socket};
use crate::{cancel_query_raw, Error};
use tokio::io::{AsyncRead, AsyncWrite};

/// The capability to request cancellation of in-progress queries on a
/// connection.
#[derive(Clone)]
pub struct CancelToken {
    #[cfg(feature = "runtime")]
    pub(crate) socket_config: Option<SocketConfig>,
    pub(crate) ssl_mode: SslMode,
    pub(crate) process_id: i32,
    pub(crate) secret_key: i32,
}

impl CancelToken {
    /// Attempts to cancel the in-progress query on the connection associated
    /// with this `CancelToken`.
    ///
    /// The server provides no information about whether a cancellation attempt was successful or not.
    ///
    /// Cancellation is inherently racy. There is no guarantee that the
    /// cancellation request will reach the server before the query terminates
    /// normally, or that the connection associated with this token is still
    /// active.
    ///
    /// Returns once the server has closed the cancel connection, which it
    /// does after processing the request, so a successful return means the
    /// request has already been acted on. A peer that keeps the connection
    /// open, resets it or answers makes this fail (after 10 seconds for an
    /// open connection), although the request was sent. The wait uses the
    /// Tokio timer. The inherited OpenSSL and native-tls adapters may report
    /// a server close without TLS `close_notify` as an error.
    ///
    /// Requires the `runtime` Cargo feature (enabled by default).
    #[cfg(feature = "runtime")]
    pub async fn cancel_query<T>(&self, tls: T) -> Result<(), Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        cancel_query::cancel_query(
            self.socket_config.clone(),
            self.ssl_mode,
            tls,
            self.process_id,
            self.secret_key,
        )
        .await
    }

    /// Like `cancel_query`, but uses a stream which is already connected to the server rather than opening a new
    /// connection itself. Returns once the request is sent, without waiting for the server to close the stream.
    pub async fn cancel_query_raw<S, T>(&self, stream: S, tls: T) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: TlsConnect<S>,
    {
        cancel_query_raw::cancel_query_raw(
            stream,
            self.ssl_mode,
            tls,
            true,
            self.process_id,
            self.secret_key,
            false,
        )
        .await
    }
}
