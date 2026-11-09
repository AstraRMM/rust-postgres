//! AST-2133 qualification harness: independent oracles for the driver's
//! semantic wire observation.
//!
//! * [`Proxy`] is a TCP proxy that relays real traffic between the driver and
//!   a real engine and parses the PostgreSQL framing itself (startup,
//!   `SSLRequest`, cancel requests, tagged messages, `ReadyForQuery` status).
//!   It shares no code with the driver's observer.
//! * [`server_log`] reads the PostgreSQL server log (`log_min_duration_statement
//!   = 0`), which records every `parse`, `bind`, `execute` and simple
//!   `statement` the backend processed, plus errors with their SQLSTATE.
//! * [`statement_calls`] reads `pg_stat_statements` (PostgreSQL and
//!   YugabyteDB).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use yb_tokio_postgres::{Client, Config, Connection, Error, NoTls, Socket};

/// Reads a required rig environment variable.
pub fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set by wire-qualification/rig/run.sh"))
}

/// Wire facts observed by the proxy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub connections: u64,
    /// All bytes the client sent / the server sent.
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub startups: u64,
    pub ssl_requests: u64,
    pub tls_sessions: u64,
    pub cancel_requests: u64,
    /// The startup `ReadyForQuery` of each session (not a request cycle).
    pub startup_ready: u64,
    /// Tagged frontend messages by tag (after startup; includes `p`, `X`).
    pub frontend: BTreeMap<char, u64>,
    /// Tagged backend messages by tag, excluding each startup `Z`.
    pub backend: BTreeMap<char, u64>,
    /// Bytes of frontend messages after the startup `ReadyForQuery`,
    /// excluding `Terminate`.
    pub frontend_request_bytes: u64,
    /// Bytes of backend messages after the startup `ReadyForQuery`,
    /// excluding asynchronous `S`/`N`/`A` messages.
    pub backend_request_bytes: u64,
    /// `ReadyForQuery` messages whose previous status was `T` or `E`.
    pub ready_after_transaction: u64,
    /// `ReadyForQuery` messages whose previous status was `E`.
    pub ready_after_failed: u64,
}

impl Tally {
    pub fn fe(&self, tag: char) -> u64 {
        self.frontend.get(&tag).copied().unwrap_or(0)
    }

    pub fn be(&self, tag: char) -> u64 {
        self.backend.get(&tag).copied().unwrap_or(0)
    }

    pub fn since(&self, before: &Tally) -> Tally {
        let sub = |a: &BTreeMap<char, u64>, b: &BTreeMap<char, u64>| {
            a.iter()
                .map(|(k, v)| (*k, v - b.get(k).copied().unwrap_or(0)))
                .filter(|(_, v)| *v != 0)
                .collect()
        };
        Tally {
            connections: self.connections - before.connections,
            client_bytes: self.client_bytes - before.client_bytes,
            server_bytes: self.server_bytes - before.server_bytes,
            startups: self.startups - before.startups,
            ssl_requests: self.ssl_requests - before.ssl_requests,
            tls_sessions: self.tls_sessions - before.tls_sessions,
            cancel_requests: self.cancel_requests - before.cancel_requests,
            startup_ready: self.startup_ready - before.startup_ready,
            frontend: sub(&self.frontend, &before.frontend),
            backend: sub(&self.backend, &before.backend),
            frontend_request_bytes: self.frontend_request_bytes - before.frontend_request_bytes,
            backend_request_bytes: self.backend_request_bytes - before.backend_request_bytes,
            ready_after_transaction: self.ready_after_transaction - before.ready_after_transaction,
            ready_after_failed: self.ready_after_failed - before.ready_after_failed,
        }
    }
}

#[derive(Default)]
struct ConnState {
    ssl_requested: bool,
    ssl_answered: bool,
    encrypted: bool,
    startup_done: bool,
    ready_seen: bool,
    status: u8,
}

fn be32(b: &[u8]) -> usize {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
}

fn parse_frontend(buf: &mut Vec<u8>, st: &mut ConnState, t: &mut Tally) {
    loop {
        if st.encrypted {
            buf.clear();
            return;
        }
        if !st.startup_done {
            if buf.len() < 8 {
                return;
            }
            let len = be32(&buf[0..4]);
            if buf.len() < len {
                return;
            }
            match be32(&buf[4..8]) {
                80877103 => {
                    t.ssl_requests += 1;
                    st.ssl_requested = true;
                }
                80877102 => t.cancel_requests += 1,
                80877104 => {}
                _ => {
                    t.startups += 1;
                    st.startup_done = true;
                }
            }
            buf.drain(..len);
            continue;
        }
        if buf.len() < 5 {
            return;
        }
        let tag = buf[0];
        let len = be32(&buf[1..5]);
        if buf.len() < 1 + len {
            return;
        }
        *t.frontend.entry(tag as char).or_default() += 1;
        if st.ready_seen && tag != b'X' {
            t.frontend_request_bytes += 1 + len as u64;
        }
        buf.drain(..1 + len);
    }
}

fn parse_backend(buf: &mut Vec<u8>, st: &mut ConnState, t: &mut Tally) {
    loop {
        if st.ssl_requested && !st.ssl_answered {
            if buf.is_empty() {
                return;
            }
            st.ssl_answered = true;
            if buf[0] == b'S' {
                st.encrypted = true;
                t.tls_sessions += 1;
            }
            buf.drain(..1);
            continue;
        }
        if st.encrypted {
            buf.clear();
            return;
        }
        if buf.len() < 5 {
            return;
        }
        let tag = buf[0];
        let len = be32(&buf[1..5]);
        if buf.len() < 1 + len {
            return;
        }
        let after_startup = st.ready_seen;
        if tag == b'Z' {
            let status = buf[5];
            if !st.ready_seen {
                st.ready_seen = true;
                t.startup_ready += 1;
            } else {
                *t.backend.entry('Z').or_default() += 1;
                if matches!(st.status, b'T' | b'E') {
                    t.ready_after_transaction += 1;
                }
                if st.status == b'E' {
                    t.ready_after_failed += 1;
                }
            }
            st.status = status;
        } else {
            *t.backend.entry(tag as char).or_default() += 1;
        }
        if after_startup && !matches!(tag, b'S' | b'N' | b'A') {
            t.backend_request_bytes += 1 + len as u64;
        }
        buf.drain(..1 + len);
    }
}

/// A relaying, parsing TCP proxy in front of one upstream.
pub struct Proxy {
    pub port: u16,
    tally: Arc<Mutex<Tally>>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    pub async fn start(upstream: SocketAddr) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tally = Arc::new(Mutex::new(Tally::default()));
        let shared = tally.clone();
        let task = tokio::spawn(async move {
            loop {
                let (client, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let server = match TcpStream::connect(upstream).await {
                    Ok(server) => server,
                    Err(_) => continue,
                };
                client.set_nodelay(true).unwrap();
                server.set_nodelay(true).unwrap();
                shared.lock().unwrap().connections += 1;
                let state = Arc::new(Mutex::new(ConnState {
                    status: b'I',
                    ..ConnState::default()
                }));
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                tokio::spawn(pump(cr, sw, true, state.clone(), shared.clone()));
                tokio::spawn(pump(sr, cw, false, state, shared.clone()));
            }
        });
        Proxy { port, tally, task }
    }

    pub fn tally(&self) -> Tally {
        self.tally.lock().unwrap().clone()
    }
}

async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    frontend: bool,
    state: Arc<Mutex<ConnState>>,
    tally: Arc<Mutex<Tally>>,
) {
    let mut chunk = vec![0u8; 64 * 1024];
    let mut pending = Vec::new();
    loop {
        let n = match from.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Parse before forwarding, so the tally is current whenever the peer
        // can react to these bytes.
        {
            let mut t = tally.lock().unwrap();
            let mut st = state.lock().unwrap();
            pending.extend_from_slice(&chunk[..n]);
            if frontend {
                t.client_bytes += n as u64;
                parse_frontend(&mut pending, &mut st, &mut t);
            } else {
                t.server_bytes += n as u64;
                parse_backend(&mut pending, &mut st, &mut t);
            }
        }
        if to.write_all(&chunk[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

/// Connects with `config` (runtime socket path) and spawns the connection.
pub async fn open(config: &Config) -> Result<(Client, JoinHandle<Result<(), Error>>), Error> {
    let (client, connection): (Client, Connection<Socket, _>) = config.connect(NoTls).await?;
    Ok((client, tokio::spawn(connection)))
}

/// A plaintext PostgreSQL config through `port` on 127.0.0.1.
pub fn pg_config(port: u16, app: &str) -> Config {
    let mut config = Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("postgres")
        .password(env("WQ_PG_PASSWORD"))
        .dbname("postgres")
        .application_name(app)
        .ssl_mode(yb_tokio_postgres::config::SslMode::Disable);
    config
}

/// Backend evidence from the PostgreSQL server log for one application name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogCounts {
    pub parse: u64,
    pub bind: u64,
    pub execute: u64,
    pub statement: u64,
    /// `ERROR` lines by SQLSTATE.
    pub errors: BTreeMap<String, u64>,
    pub fatal: u64,
    /// `FATAL` lines by SQLSTATE.
    pub fatal_codes: BTreeMap<String, u64>,
}

impl LogCounts {
    pub fn error_total(&self) -> u64 {
        self.errors.values().sum()
    }

    pub fn since(&self, before: &LogCounts) -> LogCounts {
        LogCounts {
            parse: self.parse - before.parse,
            bind: self.bind - before.bind,
            execute: self.execute - before.execute,
            statement: self.statement - before.statement,
            errors: self
                .errors
                .iter()
                .map(|(k, v)| (k.clone(), v - before.errors.get(k).copied().unwrap_or(0)))
                .filter(|(_, v)| *v != 0)
                .collect(),
            fatal: self.fatal - before.fatal,
            fatal_codes: self
                .fatal_codes
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v - before.fatal_codes.get(k).copied().unwrap_or(0),
                    )
                })
                .filter(|(_, v)| *v != 0)
                .collect(),
        }
    }
}

fn read_log_once(text: &str, app: &str) -> LogCounts {
    let prefix = format!("{app}|");
    let mut counts = LogCounts::default();
    for line in text.lines() {
        let rest = if app == "*" {
            line.split_once('|').map(|(_, rest)| rest)
        } else {
            line.strip_prefix(&prefix)
        };
        let rest = match rest {
            Some(rest) => rest,
            None => continue,
        };
        // log_line_prefix = '%a|%e|'
        let (sqlstate, message) = match rest.split_once('|') {
            Some(pair) => pair,
            None => continue,
        };
        if let Some(body) = message.strip_prefix("LOG:  duration: ") {
            let kind = body
                .split_once(" ms  ")
                .map(|(_, after)| after.split([' ', ':']).next().unwrap_or(""))
                .unwrap_or("");
            match kind {
                "parse" => counts.parse += 1,
                "bind" => counts.bind += 1,
                "execute" => counts.execute += 1,
                "statement" => counts.statement += 1,
                _ => {}
            }
        } else if message.starts_with("ERROR:  ") {
            *counts.errors.entry(sqlstate.to_string()).or_default() += 1;
        } else if message.starts_with("FATAL:  ") {
            counts.fatal += 1;
            *counts.fatal_codes.entry(sqlstate.to_string()).or_default() += 1;
        }
    }
    counts
}

/// Reads the server log for `app` (`"*"` for every session), waiting until
/// it stops changing.
pub async fn server_log(admin: &Client, app: &str) -> LogCounts {
    let mut last: Option<LogCounts> = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let text: String = admin
            .query_one("select pg_read_file(pg_current_logfile())", &[])
            .await
            .unwrap()
            .get(0);
        let counts = read_log_once(&text, app);
        if last.as_ref() == Some(&counts) {
            return counts;
        }
        last = Some(counts);
    }
    last.unwrap()
}

/// Total `pg_stat_statements` calls of statements whose text matches `like`.
pub async fn statement_calls(admin: &Client, like: &str) -> i64 {
    admin
        .query_one(
            "select coalesce(sum(calls), 0)::int8 from pg_stat_statements where query like $1",
            &[&like],
        )
        .await
        .unwrap()
        .get(0)
}

/// Waits until the proxy tally stops changing.
pub async fn settle(proxy: &Proxy) -> Tally {
    let mut last = proxy.tally();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = proxy.tally();
        if now == last {
            return now;
        }
        last = now;
    }
    last
}
