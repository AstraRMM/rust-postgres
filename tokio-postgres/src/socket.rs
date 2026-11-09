use crate::observe::{SocketObservation, SocketRole};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

#[derive(Debug)]
enum Inner {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

/// The standard stream type used by the crate.
///
/// Requires the `runtime` Cargo feature (enabled by default).
#[derive(Debug)]
pub struct Socket {
    inner: Inner,
    observation: SocketObservation,
}

impl Socket {
    pub(crate) fn new_tcp(stream: TcpStream) -> Socket {
        Socket {
            inner: Inner::Tcp(stream),
            observation: SocketObservation::new(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn new_unix(stream: UnixStream) -> Socket {
        Socket {
            inner: Inner::Unix(stream),
            observation: SocketObservation::new(),
        }
    }

    pub(crate) fn set_observed_role(&mut self, role: SocketRole) {
        self.observation.set_role(role);
    }
}

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let filled = buf.filled().len();
        let result = match &mut this.inner {
            Inner::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Inner::Unix(s) => Pin::new(s).poll_read(cx, buf),
        };
        if let Poll::Ready(Ok(())) = result {
            this.observation.read(&buf.filled()[filled..]);
        }
        result
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let result = match &mut this.inner {
            Inner::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Inner::Unix(s) => Pin::new(s).poll_write(cx, buf),
        };
        if let Poll::Ready(Ok(written)) = result {
            this.observation.wrote(&buf[..written]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Inner::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Inner::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
