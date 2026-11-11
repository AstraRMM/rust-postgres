//! Shared fixtures for the real-engine pool tests.
//!
//! Engines come from the environment (see `rig/run.sh`):
//!
//! * `POOL_TEST_PG` — `ip:port` of a plaintext PostgreSQL 16 (user
//!   `postgres`, password `pool-test-only`).
//! * `POOL_TEST_YB` — `ip:port` of a plaintext YugabyteDB YSQL endpoint
//!   (user `yugabyte`, trust).
//! * `POOL_TEST_TLS_PG` / `POOL_TEST_TLS_ROOTS` — port of a verify-full
//!   PostgreSQL whose certificate names `localhost`, and its CA bundle.
//! * `POOL_TEST_REQUIRE=1` — fail instead of skipping when unset.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yb_postgres_pool::yb_tokio_postgres::{Client, Config, NoTls};
use yb_postgres_pool::PoolConfig;

pub const PG_PASSWORD: &str = "pool-test-only";

#[derive(Clone, Debug)]
pub struct Engine {
    pub name: &'static str,
    pub addr: SocketAddr,
    pub user: &'static str,
    pub password: Option<&'static str>,
    pub dbname: &'static str,
}

pub fn require() -> bool {
    std::env::var("POOL_TEST_REQUIRE").is_ok_and(|v| v == "1")
}

pub fn engines() -> Vec<Engine> {
    let mut out = Vec::new();
    if let Ok(addr) = std::env::var("POOL_TEST_PG") {
        out.push(Engine {
            name: "pg",
            addr: addr.parse().expect("POOL_TEST_PG ip:port"),
            user: "postgres",
            password: Some(PG_PASSWORD),
            dbname: "postgres",
        });
    }
    if let Ok(addr) = std::env::var("POOL_TEST_YB") {
        out.push(Engine {
            name: "yb",
            addr: addr.parse().expect("POOL_TEST_YB ip:port"),
            user: "yugabyte",
            password: None,
            dbname: "yugabyte",
        });
    }
    if out.is_empty() {
        assert!(!require(), "POOL_TEST_PG / POOL_TEST_YB are not set");
        eprintln!("skipping: no engine configured");
    }
    out
}

impl Engine {
    pub fn conninfo_at(&self, addr: SocketAddr) -> String {
        let mut s = format!(
            "host={} port={} user={} dbname={} sslmode=disable connect_timeout=5",
            addr.ip(),
            addr.port(),
            self.user,
            self.dbname
        );
        if let Some(password) = self.password {
            s.push_str(&format!(" password={}", password));
        }
        s
    }

    pub fn config_at(&self, addr: SocketAddr) -> Config {
        self.conninfo_at(addr).parse().unwrap()
    }

    pub fn config(&self) -> Config {
        self.config_at(self.addr)
    }

    /// A direct, unpooled administrative connection.
    pub async fn admin(&self) -> Client {
        let mut config = self.config();
        config.application_name("pooltest_admin");
        let (client, connection) = config.connect(NoTls).await.unwrap();
        tokio::spawn(connection);
        client
    }
}

pub fn pool_config(app: &str) -> PoolConfig {
    let mut config = PoolConfig::default();
    config.session.application_name = Some(app.to_string());
    config.acquire_timeout = Duration::from_secs(10);
    config.connect_timeout = Duration::from_secs(10);
    config
}

pub async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0)
}

pub async fn backends(admin: &Client, app: &str) -> i64 {
    admin
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .await
        .unwrap()
        .get(0)
}

/// Polls `pg_stat_activity` until `app` has `want` backends or `within`
/// passes; returns the last count.
pub async fn eventually_backends(admin: &Client, app: &str, want: i64, within: Duration) -> i64 {
    let deadline = Instant::now() + within;
    loop {
        let n = backends(admin, app).await;
        if n == want || Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn eventually(within: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn terminate(admin: &Client, pid: i32) {
    admin
        .execute("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap();
}

/// Frontend message counts seen by a counting TCP proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WireCounts {
    pub startups: u64,
    pub cancels: u64,
    pub simple_queries: u64,
    pub parses: u64,
    pub binds: u64,
    pub describes: u64,
    pub executes: u64,
    pub syncs: u64,
    pub closes: u64,
    pub terminates: u64,
    pub other: u64,
}

impl WireCounts {
    pub fn since(&self, before: &WireCounts) -> WireCounts {
        WireCounts {
            startups: self.startups - before.startups,
            cancels: self.cancels - before.cancels,
            simple_queries: self.simple_queries - before.simple_queries,
            parses: self.parses - before.parses,
            binds: self.binds - before.binds,
            describes: self.describes - before.describes,
            executes: self.executes - before.executes,
            syncs: self.syncs - before.syncs,
            closes: self.closes - before.closes,
            terminates: self.terminates - before.terminates,
            other: self.other - before.other,
        }
    }

    /// Request/response exchanges (each ends in a `Sync` or is a simple
    /// query).
    pub fn round_trips(&self) -> u64 {
        self.syncs + self.simple_queries
    }

    pub fn messages(&self) -> u64 {
        self.simple_queries
            + self.parses
            + self.binds
            + self.describes
            + self.executes
            + self.syncs
            + self.closes
            + self.terminates
            + self.other
    }
}

#[derive(Default)]
pub struct Wire {
    counts: parking_lot::Mutex<HashMap<u8, u64>>,
    startups: AtomicU64,
    cancels: AtomicU64,
    /// When set, the next `COMMIT` is forwarded to the server and then both
    /// sides are disconnected before the reply reaches the client.
    pub kill_after_commit: AtomicBool,
    /// While set, nothing is relayed in either direction (a server that
    /// stops answering, including cancel requests).
    pub freeze: AtomicBool,
    pub hold_replies: AtomicBool,
    injectors: parking_lot::Mutex<Vec<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
}

impl Wire {
    /// Writes `bytes` to every proxied client, as if the server sent them.
    /// Only safe while the connections are idle.
    pub fn inject(&self, bytes: &[u8]) -> usize {
        let mut injectors = self.injectors.lock();
        injectors.retain(|tx| tx.send(bytes.to_vec()).is_ok());
        injectors.len()
    }

    pub fn snapshot(&self) -> WireCounts {
        let counts = self.counts.lock();
        let c = |t: u8| counts.get(&t).copied().unwrap_or(0);
        let known = [b'Q', b'P', b'B', b'D', b'E', b'S', b'C', b'X'];
        WireCounts {
            startups: self.startups.load(Ordering::SeqCst),
            cancels: self.cancels.load(Ordering::SeqCst),
            simple_queries: c(b'Q'),
            parses: c(b'P'),
            binds: c(b'B'),
            describes: c(b'D'),
            executes: c(b'E'),
            syncs: c(b'S'),
            closes: c(b'C'),
            terminates: c(b'X'),
            other: counts
                .iter()
                .filter(|(t, _)| !known.contains(t))
                .map(|(_, n)| *n)
                .sum(),
        }
    }
}

/// Starts a plaintext proxy to `target` that counts frontend messages.
pub async fn proxy(target: SocketAddr) -> (SocketAddr, Arc<Wire>) {
    proxy_delayed(target, Duration::ZERO).await
}

/// Like [`proxy`], but each connection waits `delay` before it is relayed,
/// so connects stay in flight that long.
pub async fn proxy_delayed(target: SocketAddr, delay: Duration) -> (SocketAddr, Arc<Wire>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let wire = Arc::new(Wire::default());
    let shared = wire.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let wire = shared.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = relay(client, target, wire).await;
            });
        }
    });
    (addr, wire)
}

async fn relay(client: TcpStream, target: SocketAddr, wire: Arc<Wire>) -> std::io::Result<()> {
    let server = TcpStream::connect(target).await?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    let (mut from_client, mut to_client) = client.into_split();
    let (mut from_server, mut to_server) = server.into_split();
    let (inject_tx, mut inject_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    wire.injectors.lock().push(inject_tx);
    let down_wire = wire.clone();
    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut held = Vec::new();
        loop {
            tokio::select! {
                read = from_server.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) if down_wire.hold_replies.load(Ordering::SeqCst) => {
                        held.extend_from_slice(&buf[..n]);
                    }
                    Ok(n) => {
                        if !held.is_empty() {
                            if to_client.write_all(&held).await.is_err() {
                                break;
                            }
                            held.clear();
                        }
                        if !down_wire.freeze.load(Ordering::SeqCst)
                            && to_client.write_all(&buf[..n]).await.is_err()
                        {
                            break;
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(5)), if !held.is_empty() => {
                    if !down_wire.hold_replies.load(Ordering::SeqCst) {
                        if to_client.write_all(&held).await.is_err() {
                            break;
                        }
                        held.clear();
                    }
                }
                Some(bytes) = inject_rx.recv() => {
                    if to_client.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to_client.shutdown().await;
    });
    // Startup or cancel packet: length then body, no type byte.
    let len = from_client.read_u32().await?;
    let mut body = vec![0u8; len as usize - 4];
    from_client.read_exact(&mut body).await?;
    let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if code == 80877102 {
        wire.cancels.fetch_add(1, Ordering::SeqCst);
        if wire.freeze.load(Ordering::SeqCst) {
            return Ok(());
        }
    } else {
        wire.startups.fetch_add(1, Ordering::SeqCst);
    }
    let mut frame = Vec::with_capacity(len as usize);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    to_server.write_all(&frame).await?;
    while let Ok(tag) = from_client.read_u8().await {
        let len = from_client.read_u32().await?;
        let mut body = vec![0u8; len as usize - 4];
        from_client.read_exact(&mut body).await?;
        *wire.counts.lock().entry(tag).or_insert(0) += 1;
        let mut frame = Vec::with_capacity(len as usize + 1);
        frame.push(tag);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        if tag == b'Q'
            && body.starts_with(b"COMMIT")
            && wire.kill_after_commit.swap(false, Ordering::SeqCst)
        {
            // Stop relaying replies, let the server commit, then cut the
            // client off: it never learns the outcome.
            down.abort();
            let _ = down.await;
            to_server.write_all(&frame).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            return Ok(());
        }
        if wire.freeze.load(Ordering::SeqCst) {
            continue;
        }
        to_server.write_all(&frame).await?;
    }
    let _ = to_server.shutdown().await;
    let _ = down.await;
    Ok(())
}

/// A listener that accepts connections and never answers, so connects to it
/// stall until their deadline.
pub async fn stall_listener() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    addr
}

/// A configuration that is never dialed (or only reaches `addr`).
pub fn unused_config(addr: SocketAddr) -> Config {
    format!(
        "host={} port={} user=pool dbname=pool sslmode=disable",
        addr.ip(),
        addr.port()
    )
    .parse()
    .unwrap()
}

/// A backend `ParameterStatus` message.
pub fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    let mut out = vec![b'S'];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}
