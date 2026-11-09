//! TLS connectors the pool can retire sessions for.

use yb_tokio_postgres::tls::{MakeTlsConnect, NoTlsStream, TlsConnect};
use yb_tokio_postgres::{NoTls, Socket};

/// A connector usable by the pool.
///
/// Besides connecting, it tells the pool which credential generation a
/// session authenticated with and whether that generation is still the one
/// new connections use. Sessions of superseded generations are retired on
/// return and refused at checkout; sessions of revoked generations are
/// closed by the connector itself, even while borrowed.
pub trait PoolTls:
    MakeTlsConnect<
        Socket,
        Stream: Send + Sync + 'static,
        TlsConnect: Send + TlsConnect<Socket, Future: Send>,
    > + Clone
    + Send
    + Sync
    + 'static
{
    /// The generation `stream` authenticated with, if the connector tracks
    /// generations.
    fn stream_generation(stream: &Self::Stream) -> Option<u64>;

    /// Whether `generation` is still current. Connections whose generation
    /// is not current are retired.
    fn is_current(&self, generation: u64) -> bool;
}

/// Plaintext. Only for `sslmode=disable` test and local fixtures; production
/// pools use the verifying rustls connector.
impl PoolTls for NoTls {
    fn stream_generation(_: &NoTlsStream) -> Option<u64> {
        None
    }

    fn is_current(&self, _: u64) -> bool {
        true
    }
}

#[cfg(feature = "rustls")]
impl PoolTls for yb_tokio_postgres::rustls::MakeRustlsConnect {
    fn stream_generation(stream: &yb_tokio_postgres::rustls::RustlsStream<Socket>) -> Option<u64> {
        Some(stream.generation())
    }

    fn is_current(&self, generation: u64) -> bool {
        yb_tokio_postgres::rustls::MakeRustlsConnect::is_current(self, generation)
            && !self.is_revoked(generation)
    }
}
