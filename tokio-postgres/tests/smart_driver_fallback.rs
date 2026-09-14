//! Regression tests for policy-preserving smart-driver fallback.
//!
//! The loopback fixture accepts a PostgreSQL login but rejects yb_servers().
//! It is deliberately not a Yugabyte cluster: these tests check that a seed
//! usable for discovery cannot silently become an unrestricted data connection.
#![cfg(feature = "runtime")]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use yb_tokio_postgres::{Config, NoTls};

#[derive(Clone, Copy, Debug)]
enum FailurePhase {
    Parse,
    Execute,
}

struct MetadataFailureServer {
    address: SocketAddr,
    logins: Arc<AtomicUsize>,
    metadata_queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MetadataFailureServer {
    async fn start(phase: FailurePhase) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let logins = Arc::new(AtomicUsize::new(0));
        let metadata_queries = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&logins);
        let queries = Arc::clone(&metadata_queries);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                if let Err(error) = serve(&mut socket, phase, &queries).await {
                    // The driver may drop the control socket immediately on
                    // ErrorResponse, before consuming the remaining frames.
                    assert!(
                        matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                        ),
                        "unexpected fixture I/O error: {}",
                        error,
                    );
                }
            }
        });
        Self {
            address,
            logins,
            metadata_queries,
            task,
        }
    }

    fn config(&self, parameters: &str) -> Config {
        format!(
            "host=127.0.0.1 port={} user=test dbname=test sslmode=disable \
             connect_timeout=1 {}",
            self.address.port(),
            parameters,
        )
        .parse()
        .unwrap()
    }
}

impl Drop for MetadataFailureServer {
    fn drop(&mut self) {
        // Aborting also drops the currently accepted socket. The fixture opens
        // no detached session tasks and never binds a non-loopback address.
        self.task.abort();
    }
}

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    socket.write_u8(tag).await?;
    socket.write_u32((payload.len() + 4) as u32).await?;
    socket.write_all(payload).await
}

async fn ready(socket: &mut TcpStream) -> io::Result<()> {
    message(socket, b'Z', b"I").await
}

async fn reject_metadata(socket: &mut TcpStream) -> io::Result<()> {
    message(
        socket,
        b'E',
        b"SERROR\0VERROR\0C42501\0Mmetadata discovery denied by test fixture\0\0",
    )
    .await
}

fn metadata_description() -> Vec<u8> {
    // Native built-in OIDs avoid any secondary type-introspection queries.
    let columns = [
        ("host", 25u32, -1i16),
        ("port", 20, 8),
        ("cloud", 25, -1),
        ("region", 25, -1),
        ("zone", 25, -1),
        ("public_ip", 25, -1),
        ("node_type", 25, -1),
    ];
    let mut payload = Vec::new();
    payload.extend_from_slice(&(columns.len() as u16).to_be_bytes());
    for (name, oid, size) in columns {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes()); // table OID
        payload.extend_from_slice(&0i16.to_be_bytes()); // column attribute
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&size.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        payload.extend_from_slice(&0i16.to_be_bytes()); // text format
    }
    payload
}

async fn serve(
    socket: &mut TcpStream,
    phase: FailurePhase,
    metadata_queries: &AtomicUsize,
) -> io::Result<()> {
    let length = socket.read_u32().await?;
    assert!((8..=65_536).contains(&length));
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    assert_eq!(&startup[..4], &196_608u32.to_be_bytes());
    message(socket, b'R', &0u32.to_be_bytes()).await?;
    message(socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(socket, b'S', b"client_encoding\0UTF8\0").await?;
    message(socket, b'S', b"server_version\x0015.0\0").await?;
    ready(socket).await?;

    let mut discard_until_sync = false;
    loop {
        let tag = match socket.read_u8().await {
            Ok(tag) => tag,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let length = socket.read_u32().await?;
        assert!((4..=65_536).contains(&length));
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        if tag == b'X' {
            return Ok(());
        }
        if discard_until_sync && tag != b'S' {
            continue;
        }
        match tag {
            b'P' => {
                let mut strings = body.split(|byte| *byte == 0);
                strings.next().unwrap(); // prepared-statement name
                let sql = strings.next().unwrap();
                assert_eq!(sql, b"select * from yb_servers()");
                metadata_queries.fetch_add(1, Ordering::SeqCst);
                match phase {
                    FailurePhase::Parse => {
                        reject_metadata(socket).await?;
                        discard_until_sync = true;
                    }
                    FailurePhase::Execute => message(socket, b'1', &[]).await?,
                }
            }
            b'D' => {
                assert_eq!(body.first(), Some(&b'S'));
                message(socket, b't', &0u16.to_be_bytes()).await?;
                message(socket, b'T', &metadata_description()).await?;
            }
            b'B' => message(socket, b'2', &[]).await?,
            b'E' => {
                reject_metadata(socket).await?;
                discard_until_sync = true;
            }
            b'S' => {
                discard_until_sync = false;
                ready(socket).await?;
            }
            b'C' => message(socket, b'3', &[]).await?,
            b'H' => (),
            other => panic!("unexpected frontend message: {}", other),
        }
    }
}

#[tokio::test]
async fn discovery_failure_cannot_bypass_restricted_routing() {
    let cases = [
        "load_balance=only-primary",
        "load_balance=only-rr",
        "load_balance=any topology_keys=test.region.allowed fallback_to_topology_keys_only=true",
        "load_balance=true topology_keys=test.region.allowed fallback_to_topology_keys_only=true",
        "load_balance=only-primary topology_keys=test.region.allowed",
    ];
    for phase in [FailurePhase::Parse, FailurePhase::Execute] {
        for parameters in cases {
            let server = MetadataFailureServer::start(phase).await;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                server.config(parameters).connect(NoTls),
            )
            .await
            .expect("restricted connect must finish without a stalled retry");
            let error = match result {
                Err(error) => error,
                Ok((client, connection)) => {
                    drop(client);
                    drop(connection);
                    panic!("restriction bypassed after {:?}: {}", phase, parameters);
                }
            };
            assert_eq!(error.as_db_error().unwrap().code().code(), "42501");
            assert_eq!(server.metadata_queries.load(Ordering::SeqCst), 1);
            assert_eq!(server.logins.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn discovery_failure_preserves_unrestricted_seed_fallback() {
    let cases = [
        "load_balance=any",
        "load_balance=true",
        "load_balance=prefer-primary",
        "load_balance=prefer-rr",
        // As before, the topology-only flag has no effect without topology keys.
        "load_balance=any fallback_to_topology_keys_only=true",
        // Topology preferences alone are not a strict placement restriction.
        "load_balance=any topology_keys=test.region.allowed",
    ];
    for phase in [FailurePhase::Parse, FailurePhase::Execute] {
        for parameters in cases {
            let server = MetadataFailureServer::start(phase).await;
            let (client, connection) = tokio::time::timeout(
                Duration::from_secs(5),
                server.config(parameters).connect(NoTls),
            )
            .await
            .expect("unrestricted fallback must finish")
            .expect("unrestricted clients retain upstream seed fallback");
            assert_eq!(server.metadata_queries.load(Ordering::SeqCst), 1);
            assert_eq!(server.logins.load(Ordering::SeqCst), 2);
            drop(client);
            drop(connection);
        }
    }
}

#[tokio::test]
async fn disabled_load_balancing_does_not_attempt_discovery() {
    let server = MetadataFailureServer::start(FailurePhase::Parse).await;
    let (client, connection) = tokio::time::timeout(
        Duration::from_secs(5),
        server.config("load_balance=false").connect(NoTls),
    )
    .await
    .expect("ordinary connection must finish")
    .expect("ordinary connection must not require yb_servers()");
    assert_eq!(server.metadata_queries.load(Ordering::SeqCst), 0);
    assert_eq!(server.logins.load(Ordering::SeqCst), 1);
    drop(client);
    drop(connection);
}
