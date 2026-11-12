//! AST-2129: owned realm state, bounded refresh/retries and accounting.
//!
//! These tests speak the real PostgreSQL wire protocol to a loopback fixture
//! that plays a YugabyteDB cluster: every node answers logins and
//! `select * from yb_servers()` from a mutable topology, and each node's
//! behaviour (accept, refuse, stall, reject authentication, report busy) can
//! be changed mid-test. The real-engine two-realm checks against YugabyteDB
//! live in `tls-qualification`.
#![cfg(feature = "runtime")]

use std::io;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use yb_tokio_postgres::endpoint::EndpointPolicy;
use yb_tokio_postgres::realm::{NodeStanding, Realm};
use yb_tokio_postgres::{Client, Config, Error, NoTls, SimpleQueryMessage};

static NEXT_IP: AtomicU8 = AtomicU8::new(10);

fn next_ip() -> String {
    format!("127.0.42.{}", NEXT_IP.fetch_add(1, Ordering::SeqCst))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Behaviour {
    Accept,
    Refuse,
    Stall,
    AuthFail,
    Busy,
    /// Announces a startup message larger than any the driver accepts
    /// before the session is established, then stalls.
    HugeStartupMessage,
    /// Floods the startup with distinct parameter status messages.
    ParameterFlood,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Discovery {
    Rows,
    Error,
    Empty,
    Stall,
    Slow(u64),
    SlowError(u64),
    /// Every DataRow carries fewer fields than its RowDescription announced.
    ShortRows,
    /// The discovery query's `host` column has an unknown type whose lookup
    /// names another unknown element type, without end.
    TypeChain,
    /// As `TypeChain`, but the element types refer back to each other.
    TypeCycle,
    /// The simple-query reply row carries a 2000-byte value.
    LargeRow,
    /// The simple-query reply announces a row beyond the default 1 GiB
    /// message limit, then stalls.
    HugeRow,
    /// Discovery pads the published rows to this many rows.
    ManyRows(usize),
    /// Discovery reports every zone with this many bytes.
    LongZone(usize),
}

/// The first unknown type OID the `TypeChain`/`TypeCycle` fixtures report.
const UNKNOWN_TYPE: u32 = 100_000;

#[derive(Clone, Debug)]
struct NodeRow {
    host: String,
    port: u16,
    node_type: &'static str,
    zone: String,
}

#[derive(Clone)]
struct Cluster {
    rows: Arc<Mutex<Vec<NodeRow>>>,
    discovery: Arc<Mutex<Discovery>>,
    discoveries: Arc<AtomicUsize>,
    type_lookups: Arc<AtomicUsize>,
    region: String,
}

impl Cluster {
    fn new(region: &str) -> Cluster {
        Cluster {
            rows: Arc::new(Mutex::new(Vec::new())),
            discovery: Arc::new(Mutex::new(Discovery::Rows)),
            discoveries: Arc::new(AtomicUsize::new(0)),
            type_lookups: Arc::new(AtomicUsize::new(0)),
            region: region.to_string(),
        }
    }

    fn set_discovery(&self, mode: Discovery) {
        *self.discovery.lock().unwrap() = mode;
    }

    fn publish(&self, nodes: &[(&Node, &'static str, &str)]) {
        *self.rows.lock().unwrap() = nodes
            .iter()
            .map(|(node, node_type, zone)| NodeRow {
                host: node.ip.clone(),
                port: node.port,
                node_type,
                zone: zone.to_string(),
            })
            .collect();
    }
}

struct Node {
    ip: String,
    port: u16,
    behaviour: Arc<Mutex<Behaviour>>,
    logins: Arc<AtomicUsize>,
    #[allow(dead_code)]
    open: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    async fn start(cluster: &Cluster) -> Node {
        Node::start_at(cluster, &next_ip(), 0).await
    }

    async fn start_at(cluster: &Cluster, ip: &str, port: u16) -> Node {
        let listener = TcpListener::bind((ip, port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let behaviour = Arc::new(Mutex::new(Behaviour::Accept));
        let logins = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let task = {
            let (cluster, behaviour, logins, open, ip) =
                (cluster.clone(), behaviour.clone(), logins.clone(), open.clone(), ip.to_string());
            tokio::spawn(async move {
                loop {
                    let (socket, _) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    };
                    let mode = *behaviour.lock().unwrap();
                    let (cluster, logins, open, ip) =
                        (cluster.clone(), logins.clone(), open.clone(), ip.clone());
                    tokio::spawn(async move {
                        let _ = session(socket, mode, &ip, &cluster, &logins, &open).await;
                    });
                }
            })
        };
        Node {
            ip: ip.to_string(),
            port,
            behaviour,
            logins,
            open,
            task,
        }
    }

    fn set(&self, behaviour: Behaviour) {
        *self.behaviour.lock().unwrap() = behaviour;
    }

    fn logins(&self) -> usize {
        self.logins.load(Ordering::SeqCst)
    }
}

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    socket.write_u8(tag).await?;
    socket.write_u32((payload.len() + 4) as u32).await?;
    socket.write_all(payload).await
}

async fn error(socket: &mut TcpStream, code: &str, text: &str) -> io::Result<()> {
    let body = format!("SFATAL\0VFATAL\0C{code}\0M{text}\0\0");
    message(socket, b'E', body.as_bytes()).await
}

fn metadata_description(host_type: u32) -> Vec<u8> {
    let columns = [
        ("host", host_type, -1i16),
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
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&size.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
    }
    payload
}

/// The row description of the driver's `pg_type` lookup statement.
fn typeinfo_description() -> Vec<u8> {
    let columns = [
        ("typname", 19u32),
        ("typtype", 18),
        ("typelem", 26),
        ("rngsubtype", 26),
        ("typbasetype", 26),
        ("nspname", 19),
        ("typrelid", 26),
    ];
    let mut payload = (columns.len() as u16).to_be_bytes().to_vec();
    for (name, oid) in columns {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&(-1i16).to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
    }
    payload
}

/// Splits a NUL-terminated string off the front of a frontend message body.
fn cstr(body: &[u8]) -> (&[u8], &[u8]) {
    let end = body.iter().position(|b| *b == 0).expect("NUL-terminated string");
    (&body[..end], &body[end + 1..])
}

/// The value of the single binary parameter of a Bind message, if any.
fn bind_parameter(body: &[u8]) -> (&[u8], Option<&[u8]>) {
    let (_portal, rest) = cstr(body);
    let (statement, rest) = cstr(rest);
    let formats = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let rest = &rest[2 + 2 * formats..];
    if u16::from_be_bytes([rest[0], rest[1]]) == 0 {
        return (statement, None);
    }
    let len = i32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]) as usize;
    (statement, Some(&rest[6..6 + len]))
}

fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut payload = (values.len() as u16).to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(bytes) => {
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend_from_slice(bytes);
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload
}

async fn session(
    mut socket: TcpStream,
    mode: Behaviour,
    identity: &str,
    cluster: &Cluster,
    logins: &AtomicUsize,
    open: &Arc<AtomicUsize>,
) -> io::Result<()> {
    if mode == Behaviour::Refuse {
        return Ok(());
    }
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    logins.fetch_add(1, Ordering::SeqCst);
    match mode {
        Behaviour::Stall => {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return Ok(());
        }
        Behaviour::AuthFail => return error(&mut socket, "28P01", "password authentication failed").await,
        Behaviour::Busy => return error(&mut socket, "53300", "too many connections").await,
        _ => {}
    }
    message(&mut socket, b'R', &0u32.to_be_bytes()).await?;
    match mode {
        Behaviour::HugeStartupMessage => {
            socket.write_u8(b'S').await?;
            socket.write_u32(1024 * 1024).await?;
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return Ok(());
        }
        Behaviour::ParameterFlood => {
            for i in 0..300 {
                message(&mut socket, b'S', format!("p{}\0v\0", i).as_bytes()).await?;
            }
        }
        _ => {}
    }
    message(&mut socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut socket, b'S', b"client_encoding\0UTF8\0").await?;
    message(&mut socket, b'S', b"server_version\x0015.0\0").await?;
    message(&mut socket, b'Z', b"I").await?;
    open.fetch_add(1, Ordering::SeqCst);
    struct Close(Arc<AtomicUsize>);
    impl Drop for Close {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _close = Close(open.clone());

    let mut discard_until_sync = false;
    // Statements naming `pg_type`, and the type OID bound to the open portal.
    let mut typeinfo_statements = Vec::<Vec<u8>>::new();
    let mut typeinfo_oid = None;
    loop {
        let tag = match socket.read_u8().await {
            Ok(tag) => tag,
            Err(_) => return Ok(()),
        };
        let length = socket.read_u32().await?;
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        if tag == b'X' {
            return Ok(());
        }
        if discard_until_sync && tag != b'S' {
            continue;
        }
        match tag {
            b'Q' => {
                let mut row_description = 1u16.to_be_bytes().to_vec();
                row_description.extend_from_slice(b"node\0");
                row_description.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255, 255, 255, 255, 255, 255, 0, 0]);
                message(&mut socket, b'T', &row_description).await?;
                let discovery = *cluster.discovery.lock().unwrap();
                if discovery == Discovery::ShortRows {
                    message(&mut socket, b'D', &data_row(&[])).await?;
                } else if discovery == Discovery::LargeRow {
                    message(&mut socket, b'D', &data_row(&[Some(&[b'x'; 2000])])).await?;
                } else if discovery == Discovery::HugeRow {
                    socket.write_u8(b'D').await?;
                    socket.write_u32((1 << 30) + 4 + 1).await?;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return Ok(());
                } else {
                    message(&mut socket, b'D', &data_row(&[Some(identity.as_bytes())])).await?;
                }
                message(&mut socket, b'C', b"SELECT 1\0").await?;
                message(&mut socket, b'Z', b"I").await?;
            }
            b'P' => {
                let (name, rest) = cstr(&body);
                if cstr(rest).0.windows(7).any(|w| w == b"pg_type") {
                    typeinfo_statements.push(name.to_vec());
                    message(&mut socket, b'1', &[]).await?;
                    continue;
                }
                cluster.discoveries.fetch_add(1, Ordering::SeqCst);
                let discovery = *cluster.discovery.lock().unwrap();
                match discovery {
                    Discovery::Error => {
                        error(&mut socket, "XX000", "metadata unavailable").await?;
                        discard_until_sync = true;
                    }
                    Discovery::Stall => tokio::time::sleep(Duration::from_secs(3600)).await,
                    Discovery::SlowError(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        error(&mut socket, "XX000", "metadata unavailable").await?;
                        discard_until_sync = true;
                    }
                    Discovery::Slow(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        message(&mut socket, b'1', &[]).await?;
                    }
                    _ => message(&mut socket, b'1', &[]).await?,
                }
            }
            b'D' if typeinfo_statements.iter().any(|name| name[..] == body[1..body.len() - 1]) => {
                let mut parameters = 1u16.to_be_bytes().to_vec();
                parameters.extend_from_slice(&26u32.to_be_bytes());
                message(&mut socket, b't', &parameters).await?;
                message(&mut socket, b'T', &typeinfo_description()).await?;
            }
            b'D' => {
                let host_type = match *cluster.discovery.lock().unwrap() {
                    Discovery::TypeChain | Discovery::TypeCycle => UNKNOWN_TYPE,
                    _ => 25,
                };
                message(&mut socket, b't', &0u16.to_be_bytes()).await?;
                message(&mut socket, b'T', &metadata_description(host_type)).await?;
            }
            b'B' => {
                let (statement, parameter) = bind_parameter(&body);
                typeinfo_oid = match parameter {
                    Some(oid) if typeinfo_statements.iter().any(|name| name[..] == *statement) => {
                        Some(u32::from_be_bytes([oid[0], oid[1], oid[2], oid[3]]))
                    }
                    _ => None,
                };
                message(&mut socket, b'2', &[]).await?
            }
            b'E' if typeinfo_oid.is_some() => {
                let oid = typeinfo_oid.take().unwrap();
                cluster.type_lookups.fetch_add(1, Ordering::SeqCst);
                let element = match *cluster.discovery.lock().unwrap() {
                    Discovery::TypeCycle if oid != UNKNOWN_TYPE => UNKNOWN_TYPE,
                    _ => oid + 1,
                };
                let name = format!("t{}", oid);
                message(
                    &mut socket,
                    b'D',
                    &data_row(&[
                        Some(name.as_bytes()),
                        Some(b"b"),
                        Some(&element.to_be_bytes()),
                        None,
                        Some(&0u32.to_be_bytes()),
                        Some(b"public"),
                        Some(&0u32.to_be_bytes()),
                    ]),
                )
                .await?;
                message(&mut socket, b'C', b"SELECT 1\0").await?;
            }
            b'E' => {
                let rows = if *cluster.discovery.lock().unwrap() == Discovery::Empty {
                    Vec::new()
                } else {
                    cluster.rows.lock().unwrap().clone()
                };
                let rows: Vec<NodeRow> = match *cluster.discovery.lock().unwrap() {
                    // Pad with rows of a node type discovery skips, so only
                    // the row count differs from a good answer.
                    Discovery::ManyRows(n) => {
                        let pad = NodeRow {
                            node_type: "unsupported",
                            ..rows[0].clone()
                        };
                        let padding = n - rows.len();
                        rows.into_iter().chain(std::iter::repeat(pad).take(padding)).collect()
                    }
                    Discovery::LongZone(n) => rows
                        .into_iter()
                        .map(|row| NodeRow { zone: "z".repeat(n), ..row })
                        .collect(),
                    _ => rows,
                };
                let short = *cluster.discovery.lock().unwrap() == Discovery::ShortRows;
                for row in &rows {
                    if short {
                        message(&mut socket, b'D', &data_row(&[Some(row.host.as_bytes())])).await?;
                        continue;
                    }
                    let port = (row.port as i64).to_be_bytes();
                    message(
                        &mut socket,
                        b'D',
                        &data_row(&[
                            Some(row.host.as_bytes()),
                            Some(&port),
                            Some(b"qual"),
                            Some(cluster.region.as_bytes()),
                            Some(row.zone.as_bytes()),
                            None,
                            Some(row.node_type.as_bytes()),
                        ]),
                    )
                    .await?;
                }
                message(&mut socket, b'C', format!("SELECT {}\0", rows.len()).as_bytes()).await?;
            }
            b'S' => {
                discard_until_sync = false;
                message(&mut socket, b'Z', b"I").await?;
            }
            b'C' => message(&mut socket, b'3', &[]).await?,
            b'H' => {}
            other => panic!("unexpected frontend message {}", other as char),
        }
    }
}

fn config(seed: &Node, parameters: &str) -> Config {
    format!(
        "host={} port={} user=test dbname=test sslmode=disable connect_timeout=2 {}",
        seed.ip, seed.port, parameters
    )
    .parse()
    .unwrap()
}

struct Session {
    client: Client,
    _task: JoinHandle<Result<(), Error>>,
}

async fn connect(config: &Config, realm: &Realm) -> Result<Session, Error> {
    let mut config = config.clone();
    config.realm(realm.clone());
    let (client, connection) = config.connect(NoTls).await?;
    Ok(Session {
        client,
        _task: tokio::spawn(connection),
    })
}

async fn node_of(session: &Session) -> String {
    for message in session.client.simple_query("node").await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap().to_string();
        }
    }
    panic!("no node row");
}

fn total(realm: &Realm) -> usize {
    realm.connection_counts().values().sum()
}

// --------------------------------------------------------------- isolation

#[tokio::test]
async fn two_realms_share_no_hosts_counts_failures_or_fallback() {
    let (ca, cb) = (Cluster::new("a"), Cluster::new("b"));
    let (a1, a2) = (Node::start(&ca).await, Node::start(&ca).await);
    let (b1, b2) = (Node::start(&cb).await, Node::start(&cb).await);
    ca.publish(&[(&a1, "primary", "z1"), (&a2, "primary", "z1")]);
    cb.publish(&[(&b1, "primary", "z1"), (&b2, "primary", "z1")]);
    let (ra, rb) = (Realm::new("a"), Realm::new("b"));
    let (conf_a, conf_b) = (config(&a1, "load_balance=true"), config(&b1, "load_balance=true"));

    let mut sessions = Vec::new();
    for _ in 0..4 {
        sessions.push(connect(&conf_a, &ra).await.unwrap());
        sessions.push(connect(&conf_b, &rb).await.unwrap());
    }
    let a_ids = [a1.ip.clone(), a2.ip.clone()];
    let b_ids = [b1.ip.clone(), b2.ip.clone()];
    assert!(ra.connection_counts().keys().all(|k| a_ids.contains(k)));
    assert!(rb.connection_counts().keys().all(|k| b_ids.contains(k)));
    assert_eq!((total(&ra), total(&rb)), (4, 4));
    // Balanced within each realm.
    assert_eq!(ra.connection_counts().values().copied().collect::<Vec<_>>(), vec![2, 2]);
    for s in &sessions {
        let node = node_of(s).await;
        assert!(a_ids.contains(&node) || b_ids.contains(&node));
    }

    // Failures stay in their realm, and realm A never falls back into B.
    for node in [&a1, &a2] {
        node.set(Behaviour::Refuse);
    }
    let b_logins = b1.logins() + b2.logins();
    ra.invalidate_topology();
    let e = connect(&conf_a, &ra).await.err().expect("realm A is down");
    assert!(!e.is_security_failure(), "{}", e);
    assert!(e.is_transport(), "{}", e);
    assert_eq!(b1.logins() + b2.logins(), b_logins, "realm A touched realm B");
    assert!(rb.failed_nodes().is_empty());
    assert_eq!(total(&ra), 4, "failed attempts must not leak counts");
    assert_eq!(node_of(&connect(&conf_b, &rb).await.unwrap()).await.len() > 0, true);

    drop(sessions);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!((total(&ra), total(&rb)), (0, 0));
}

#[tokio::test]
async fn implicit_realms_are_keyed_by_the_whole_trusted_configuration() {
    let (ca, cb) = (Cluster::new("a"), Cluster::new("b"));
    let (a1, b1) = (Node::start(&ca).await, Node::start(&cb).await);
    ca.publish(&[(&a1, "primary", "z1")]);
    cb.publish(&[(&b1, "primary", "z1")]);
    for _ in 0..3 {
        let (client, connection) = config(&a1, "load_balance=true").connect(NoTls).await.unwrap();
        tokio::spawn(connection);
        assert_eq!(client.node_identity(), Some(a1.ip.as_str()));
        let (client, connection) = config(&b1, "load_balance=true").connect(NoTls).await.unwrap();
        tokio::spawn(connection);
        assert_eq!(client.node_identity(), Some(b1.ip.as_str()));
    }
}

// --------------------------------------------------------- strict routing

#[tokio::test]
async fn strict_roles_fail_closed_when_exhausted() {
    let cluster = Cluster::new("r");
    let (p1, p2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&p1, "primary", "z1"), (&p2, "primary", "z1")]);
    let realm = Realm::new("roles");
    let before = p1.logins() + p2.logins();
    let e = connect(&config(&p1, "load_balance=only-rr"), &realm).await.err().expect("no read replicas");
    assert!(e.to_string().contains("eligible"), "{}", e);
    // Only the control connection logged in; no data session reached a primary.
    assert_eq!(p1.logins() + p2.logins() - before, 1);
    let s = connect(&config(&p1, "load_balance=prefer-rr"), &realm).await.unwrap();
    assert!([p1.ip.clone(), p2.ip.clone()].contains(&node_of(&s).await));

    let replicas = Cluster::new("rr");
    let r1 = Node::start(&replicas).await;
    replicas.publish(&[(&r1, "read_replica", "z1")]);
    connect(&config(&r1, "load_balance=only-primary"), &Realm::new("rr")).await.err().expect("no primaries");
}

#[tokio::test]
async fn preference_never_escapes_strict_placement() {
    let cluster = Cluster::new("p");
    let (z1, z2p, z2r) = (Node::start(&cluster).await, Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&z1, "primary", "z1"), (&z2p, "primary", "z2"), (&z2r, "read_replica", "z2")]);
    let realm = Realm::new("placement");
    let strict = config(&z1, "load_balance=prefer-primary topology_keys=qual.p.z2 fallback_to_topology_keys_only=true");
    for _ in 0..4 {
        let s = connect(&strict, &realm).await.unwrap();
        assert_eq!(node_of(&s).await, z2p.ip);
    }
    // With the preferred primary down, the soft role preference falls to the
    // z2 replica; the hard placement still excludes z1.
    z2p.set(Behaviour::Refuse);
    for _ in 0..4 {
        let s = connect(&strict, &realm).await.unwrap();
        assert_eq!(node_of(&s).await, z2r.ip);
    }
    z2r.set(Behaviour::Refuse);
    let z1_logins = z1.logins();
    realm.invalidate_topology();
    connect(&strict, &realm).await.err().expect("strict placement exhausted");
    // z1 served discovery (it is the seed) but never a data session.
    assert!(z1.logins() - z1_logins <= 1);
}

// --------------------------------------------------- membership and metadata

#[tokio::test]
async fn node_removal_and_metadata_changes_reconcile_atomically() {
    let cluster = Cluster::new("m");
    let (n1, n2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1")]);
    let realm = Realm::new("membership");
    let conf = config(&n1, "load_balance=true yb_servers_refresh_interval=0");
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(connect(&conf, &realm).await.unwrap());
    }
    assert_eq!(realm.connection_counts().get(&n2.ip), Some(&2));

    // n2 departs: no new connection goes there, existing ones stay counted.
    cluster.publish(&[(&n1, "primary", "z1")]);
    for _ in 0..4 {
        assert_eq!(node_of(&connect(&conf, &realm).await.unwrap()).await, n1.ip);
    }
    assert_eq!(realm.topology().unwrap().nodes().len(), 1);
    assert_eq!(realm.connection_counts().get(&n2.ip), Some(&2));
    held.clear();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(realm.connection_counts().get(&n2.ip), None);

    // Port change: n3 replaces n2's identity on a new port.
    let n2_new = Node::start_at(&cluster, &n2.ip, 0).await;
    assert_ne!(n2_new.port, n2.port);
    drop(n2);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2_new, "primary", "z1")]);
    n1.set(Behaviour::Refuse);
    let s = connect(&config(&n2_new, "load_balance=true yb_servers_refresh_interval=0 failed_host_reconnect_delay_secs=0"), &realm).await.unwrap();
    assert_eq!(node_of(&s).await, n2_new.ip);
    // The refused attempt may have quarantined n1; that is correct
    // behaviour, so clear it rather than wait out the reconnect delay.
    n1.set(Behaviour::Accept);
    realm.invalidate_topology();

    // Role change: n2 becomes a read replica, so only-primary avoids it.
    cluster.publish(&[(&n1, "primary", "z1"), (&n2_new, "read_replica", "z1")]);
    let only_primary = config(&n1, "load_balance=only-primary yb_servers_refresh_interval=0 failed_host_reconnect_delay_secs=0");
    for _ in 0..4 {
        assert_eq!(node_of(&connect(&only_primary, &realm).await.unwrap()).await, n1.ip);
    }
}

#[tokio::test]
async fn empty_and_failed_discovery_use_bounded_staleness() {
    let cluster = Cluster::new("s");
    let (n1, n2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1")]);

    // Bootstrap with empty metadata: unrestricted falls back to the seed,
    // restricted fails closed.
    cluster.set_discovery(Discovery::Empty);
    let realm = Realm::new("bootstrap");
    let s = connect(&config(&n1, "load_balance=true"), &realm).await.unwrap();
    assert_eq!(node_of(&s).await, n1.ip);
    connect(&config(&n1, "load_balance=only-primary"), &realm).await.err().expect("restricted");
    assert!(realm.topology().is_none());

    // A good snapshot, then refresh errors: used while within max staleness.
    cluster.set_discovery(Discovery::Rows);
    let realm = Realm::new("stale");
    let conf = config(&n1, "load_balance=only-primary yb_servers_refresh_interval=0 yb_topology_max_staleness=2");
    connect(&conf, &realm).await.unwrap();
    cluster.set_discovery(Discovery::Error);
    n1.set(Behaviour::Refuse);
    let s = connect(&conf, &realm).await.unwrap();
    assert_eq!(node_of(&s).await, n2.ip);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    connect(&conf, &realm).await.err().expect("snapshot beyond max staleness must not be used");
    assert!(realm.topology().is_none());
}

#[tokio::test]
async fn concurrent_refreshes_coalesce_per_realm() {
    let cluster = Cluster::new("c");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    cluster.set_discovery(Discovery::Slow(300));
    let realm = Realm::new("coalesce");
    let conf = config(&n1, "load_balance=true yb_servers_refresh_interval=60");
    let attempts: Vec<_> = (0..20)
        .map(|_| {
            let (conf, realm) = (conf.clone(), realm.clone());
            tokio::spawn(async move { connect(&conf, &realm).await.map(|_| ()) })
        })
        .collect();
    for attempt in attempts {
        attempt.await.unwrap().unwrap();
    }
    assert_eq!(realm.discovery_count(), 1);
    assert_eq!(cluster.discoveries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_refreshes_coalesce_and_serve_the_stale_snapshot() {
    let cluster = Cluster::new("g");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    let realm = Realm::new("coalesce-failure");
    let conf = config(&n1, "load_balance=only-primary yb_servers_refresh_interval=1");
    let _held = connect(&conf, &realm).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    cluster.set_discovery(Discovery::SlowError(300));
    let before = cluster.discoveries.load(Ordering::SeqCst);
    let attempts: Vec<_> = (0..10)
        .map(|_| {
            let (conf, realm) = (conf.clone(), realm.clone());
            tokio::spawn(async move { connect(&conf, &realm).await.map(|_| ()) })
        })
        .collect();
    for attempt in attempts {
        attempt.await.unwrap().unwrap();
    }
    // One refresh attempt (the seed, then the one known node), shared by all.
    assert_eq!(cluster.discoveries.load(Ordering::SeqCst) - before, 2);
}

#[tokio::test]
async fn discovery_seeds_are_bounded_by_the_attempt_timeout() {
    let cluster = Cluster::new("h");
    let (stalled, healthy) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&healthy, "primary", "z1")]);
    stalled.set(Behaviour::Stall);
    let conf: Config = format!(
        "host={},{} port={},{} user=test dbname=test sslmode=disable load_balance=only-primary yb_attempt_timeout=1",
        stalled.ip, healthy.ip, stalled.port, healthy.port
    )
    .parse()
    .unwrap();
    let started = Instant::now();
    let s = connect(&conf, &Realm::new("seed-bound")).await.unwrap();
    assert_eq!(node_of(&s).await, healthy.ip);
    assert!(started.elapsed() < Duration::from_millis(2500), "{:?}", started.elapsed());
}

// ------------------------------------------------ deadlines and cancellation

#[tokio::test]
async fn stalled_endpoints_are_bounded_by_attempt_and_acquisition_budgets() {
    let cluster = Cluster::new("t");
    let (s1, s2, s3) = (Node::start(&cluster).await, Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&s1, "primary", "z1"), (&s2, "primary", "z1"), (&s3, "primary", "z1")]);
    let realm = Realm::new("stall");
    let conf = config(&s1, "load_balance=only-primary yb_attempt_timeout=1 yb_acquire_timeout=4 yb_max_attempts=3");
    let _first = connect(&conf, &realm).await.unwrap(); // snapshot, held
    for node in [&s1, &s2, &s3] {
        node.set(Behaviour::Stall);
    }
    let started = Instant::now();
    let e = connect(&conf, &realm).await.err().expect("every node stalls");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(4500), "{:?}: {}", elapsed, e);
    assert_eq!(total(&realm), 1, "only the first session remains counted");

    // A stalled discovery query is bounded by the acquisition budget.
    cluster.set_discovery(Discovery::Stall);
    for node in [&s1, &s2, &s3] {
        node.set(Behaviour::Accept);
    }
    let stalled = Realm::new("stalled-discovery");
    let started = Instant::now();
    connect(&config(&s1, "load_balance=only-primary yb_acquire_timeout=2"), &stalled)
        .await
        .err()
        .expect("discovery stalls");
    assert!(started.elapsed() < Duration::from_millis(2600), "{:?}", started.elapsed());
}

/// ASTS-97: an unbounded budget set through the builder is honoured instead
/// of overflowing the deadline, and connection strings are bounded.
#[tokio::test]
async fn unbounded_budgets_do_not_overflow_and_parsed_budgets_are_bounded() {
    let cluster = Cluster::new("unbounded");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    let mut conf = config(&n1, "load_balance=only-primary");
    conf.yb_acquire_timeout(Duration::MAX);
    conf.yb_attempt_timeout(Duration::MAX);
    let realm = Realm::new("unbounded");
    let s = connect(&conf, &realm).await.unwrap();
    assert_eq!(node_of(&s).await, n1.ip);
    // The idle-pool refresh shares the acquisition budget.
    realm.refresh(NoTls, &conf).await.unwrap();
    let mut direct = config(&n1, "load_balance=false");
    direct.yb_acquire_timeout(Duration::MAX);
    let (client, connection) = direct.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    drop(client);

    for key in ["yb_acquire_timeout", "yb_attempt_timeout", "yb_topology_max_staleness"] {
        let base = "host=localhost user=test sslmode=disable";
        format!("{} {}=86400", base, key).parse::<Config>().unwrap();
        for bad in ["0", "86401", "18446744073709551615"] {
            assert!(
                format!("{} {}={}", base, key, bad).parse::<Config>().is_err(),
                "{}={} must be rejected",
                key,
                bad
            );
        }
    }
}

#[tokio::test]
async fn cancellation_at_every_stage_releases_state() {
    let cluster = Cluster::new("x");
    let (n1, n2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1")]);
    let realm = Realm::new("cancel");
    let conf = config(&n1, "load_balance=only-primary yb_servers_refresh_interval=0");

    // During discovery.
    cluster.set_discovery(Discovery::Stall);
    assert!(timeout(Duration::from_millis(300), connect(&conf, &realm)).await.is_err());
    cluster.set_discovery(Discovery::Rows);
    // The refresh gate was released by the cancelled caller.
    let s = timeout(Duration::from_secs(5), connect(&conf, &realm)).await.unwrap().unwrap();
    assert_eq!(total(&realm), 1);

    // During a data connection.
    n1.set(Behaviour::Stall);
    n2.set(Behaviour::Stall);
    assert!(timeout(Duration::from_millis(500), connect(&conf, &realm)).await.is_err());
    assert_eq!(total(&realm), 1, "a cancelled attempt must release its reservation");
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(total(&realm), 0);
}

#[tokio::test]
async fn all_candidates_failing_quarantines_and_keeps_counts_exact() {
    let cluster = Cluster::new("f");
    let (n1, n2, n3) = (Node::start(&cluster).await, Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1"), (&n3, "primary", "z1")]);
    let realm = Realm::new("failing");
    let conf = config(&n1, "load_balance=only-primary failed_host_reconnect_delay_secs=60");
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(connect(&conf, &realm).await.unwrap());
    }
    for node in [&n2, &n3] {
        node.set(Behaviour::Refuse);
    }
    let mut extra = Vec::new();
    for _ in 0..5 {
        // Only n1 remains; repeated failures elsewhere never skew counts.
        // Holding the sessions raises n1's load, so the refusing nodes are
        // tried (and quarantined) first.
        let s = connect(&conf, &realm).await.unwrap();
        assert_eq!(node_of(&s).await, n1.ip);
        extra.push(s);
    }
    assert_eq!(realm.connection_counts().get(&n1.ip), Some(&6));
    drop(extra);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut failed = realm.failed_nodes();
    failed.sort();
    let mut expected = vec![n2.ip.clone(), n3.ip.clone()];
    expected.sort();
    assert_eq!(failed, expected);
    n1.set(Behaviour::Refuse);
    connect(&conf, &realm).await.err().expect("all candidates fail");
    assert_eq!(total(&realm), 3);
    held.truncate(1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(total(&realm), 1);
}

#[tokio::test]
async fn busy_nodes_are_skipped_without_quarantine() {
    let cluster = Cluster::new("b");
    let (n1, n2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1")]);
    let realm = Realm::new("busy");
    let conf = config(&n1, "load_balance=only-primary");
    connect(&conf, &realm).await.unwrap();
    n2.set(Behaviour::Busy);
    for _ in 0..4 {
        assert_eq!(node_of(&connect(&conf, &realm).await.unwrap()).await, n1.ip);
    }
    assert!(realm.failed_nodes().is_empty());
}

#[tokio::test]
async fn authentication_failure_is_terminal_and_not_a_quarantine() {
    let cluster = Cluster::new("a");
    let (n1, n2) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&n1, "primary", "z1"), (&n2, "primary", "z1")]);
    let realm = Realm::new("auth");
    let conf = config(&n1, "load_balance=only-primary");
    connect(&conf, &realm).await.unwrap();
    n1.set(Behaviour::AuthFail);
    n2.set(Behaviour::AuthFail);
    let before = n1.logins() + n2.logins();
    let e = connect(&conf, &realm).await.err().expect("authentication fails");
    assert!(e.is_security_failure(), "{}", e);
    assert!(!e.is_transport(), "{}", e);
    assert_eq!(e.code().map(|c| c.code()), Some("28P01"));
    assert_eq!(n1.logins() + n2.logins() - before, 1, "no second endpoint may be tried");
    assert!(realm.failed_nodes().is_empty());
}

#[tokio::test]
async fn shutdown_refuses_new_acquisitions_only() {
    let cluster = Cluster::new("d");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    let realm = Realm::new("shutdown");
    let conf = config(&n1, "load_balance=true");
    let s = connect(&conf, &realm).await.unwrap();
    realm.shutdown();
    let started = Instant::now();
    connect(&conf, &realm).await.err().expect("shut down");
    assert!(started.elapsed() < Duration::from_millis(50));
    assert_eq!(node_of(&s).await, n1.ip);
}

// ------------------------------------- PR #1 behaviour, re-verified here

#[tokio::test]
async fn discovery_failure_cannot_bypass_restricted_routing() {
    for parameters in [
        "load_balance=only-primary",
        "load_balance=only-rr",
        "load_balance=any topology_keys=qual.e.z9 fallback_to_topology_keys_only=true",
        "load_balance=prefer-primary topology_keys=qual.e.z9 fallback_to_topology_keys_only=true",
    ] {
        let cluster = Cluster::new("e");
        let n1 = Node::start(&cluster).await;
        cluster.publish(&[(&n1, "primary", "z1")]);
        cluster.set_discovery(Discovery::Error);
        let before = n1.logins();
        connect(&config(&n1, parameters), &Realm::new("restricted"))
            .await
            .err()
            .unwrap_or_else(|| panic!("restriction bypassed: {}", parameters));
        assert_eq!(n1.logins() - before, 1, "{}", parameters);
    }
}

#[tokio::test]
async fn discovery_failure_preserves_unrestricted_seed_fallback() {
    for parameters in ["load_balance=any", "load_balance=prefer-rr", "load_balance=any topology_keys=qual.e.z9"] {
        let cluster = Cluster::new("e");
        let n1 = Node::start(&cluster).await;
        cluster.publish(&[(&n1, "primary", "z1")]);
        cluster.set_discovery(Discovery::Error);
        let realm = Realm::new("unrestricted");
        let s = connect(&config(&n1, parameters), &realm).await.unwrap();
        assert_eq!(node_of(&s).await, n1.ip);
        assert_eq!(realm.connection_counts().get(&n1.ip), Some(&1), "{}", parameters);
    }
}

#[tokio::test]
async fn disabled_load_balancing_does_not_attempt_discovery() {
    let cluster = Cluster::new("o");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    let (client, connection) = config(&n1, "load_balance=false").connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    assert_eq!(cluster.discoveries.load(Ordering::SeqCst), 0);
    drop(client);
}

#[tokio::test]
async fn standing_follows_quarantine_expiry_removal_and_policy() {
    let cluster = Cluster::new("st");
    let (a, b) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&a, "primary", "z1"), (&b, "primary", "z2")]);
    let realm = Realm::new("standing");
    let mut conf = config(&b, "load_balance=true topology_keys=qual.st.z1:1,qual.st.z2:2");
    conf.failed_host_reconnect_delay_secs(Duration::from_millis(300));
    conf.yb_servers_refresh_interval(Duration::ZERO);

    a.set(Behaviour::Refuse);
    let fallback = connect(&conf, &realm).await.unwrap();
    assert_eq!(node_of(&fallback).await, b.ip);
    assert_eq!(fallback.client.node_standing(), NodeStanding::Preferred);
    let first_epoch = realm.topology_epoch();

    a.set(Behaviour::Accept);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(fallback.client.node_standing(), NodeStanding::Fallback);
    let preferred = connect(&conf, &realm).await.unwrap();
    assert_eq!(node_of(&preferred).await, a.ip);
    assert_eq!(preferred.client.node_standing(), NodeStanding::Preferred);

    realm.refresh(NoTls, &conf).await.unwrap();
    assert_eq!(realm.topology_epoch(), first_epoch, "an unchanged snapshot is not a change");

    cluster.publish(&[(&a, "primary", "z1")]);
    let info = realm.refresh(NoTls, &conf).await.unwrap();
    assert_eq!(info.nodes().len(), 1);
    assert_eq!(realm.topology_epoch(), first_epoch + 1);
    assert_eq!(info.epoch(), realm.topology_epoch());
    assert_eq!(fallback.client.node_standing(), NodeStanding::Departed);
    assert_eq!(preferred.client.node_standing(), NodeStanding::Preferred);

    cluster.publish(&[(&a, "read_replica", "z1"), (&b, "primary", "z2")]);
    let mut primaries = config(&b, "load_balance=only-primary");
    primaries.yb_servers_refresh_interval(Duration::ZERO);
    let only_primary = Realm::new("standing-primary");
    let session = connect(&primaries, &only_primary).await.unwrap();
    assert_eq!(node_of(&session).await, b.ip);
    assert_eq!(only_primary.standing(&primaries, &a.ip), NodeStanding::Ineligible);
    assert_eq!(only_primary.standing(&primaries, &b.ip), NodeStanding::Preferred);

    let direct: Config = format!(
        "host={} port={} user=test dbname=test sslmode=disable connect_timeout=2",
        a.ip, a.port
    )
    .parse()
    .unwrap();
    let (client, connection) = direct.connect(NoTls).await.unwrap();
    let _task = tokio::spawn(connection);
    assert_eq!(client.node_standing(), NodeStanding::Unknown);
    assert!(direct.resolved_realm().is_none());
}

#[tokio::test]
async fn an_unlisted_seed_has_no_standing() {
    let cluster = Cluster::new("px");
    let (seed, listed) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&listed, "primary", "z1")]);
    listed.set(Behaviour::Refuse);
    let realm = Realm::new("unlisted-seed");
    let mut conf = config(&seed, "load_balance=true");
    conf.yb_servers_refresh_interval(Duration::ZERO);
    let session = connect(&conf, &realm).await.unwrap();
    assert_eq!(node_of(&session).await, seed.ip);
    assert_eq!(session.client.node_standing(), NodeStanding::Unknown);
}

/// ASTS-83 (RUSTSEC-2026-0178): a DataRow with fewer fields than the row
/// description is a protocol error, not an out-of-bounds panic, on both the
/// extended path (the discovery query) and the simple-query path.
#[tokio::test]
async fn short_data_rows_are_errors_not_panics() {
    let cluster = Cluster::new("short");
    let n1 = Node::start(&cluster).await;
    cluster.publish(&[(&n1, "primary", "z1")]);
    cluster.set_discovery(Discovery::ShortRows);

    let realm = Realm::new("short-discovery");
    connect(&config(&n1, "load_balance=only-primary"), &realm)
        .await
        .err()
        .expect("a short discovery row must fail restricted routing closed");
    assert!(realm.topology().is_none());

    let realm = Realm::new("short-simple");
    let session = connect(&config(&n1, "load_balance=false"), &realm).await.unwrap();
    session
        .client
        .simple_query("select 1")
        .await
        .err()
        .expect("a short simple-query row must be rejected");
}

/// ASTS-90: the type lookups a statement description triggers are bounded in
/// depth and refuse cycles, on the driver's own discovery query.
#[tokio::test]
async fn unknown_type_chains_and_cycles_are_bounded() {
    for (mode, most) in [(Discovery::TypeChain, 16), (Discovery::TypeCycle, 2)] {
        let cluster = Cluster::new("types");
        let n1 = Node::start(&cluster).await;
        cluster.publish(&[(&n1, "primary", "z1")]);
        cluster.set_discovery(mode);
        let realm = Realm::new("types");
        let started = Instant::now();
        connect(&config(&n1, "load_balance=only-primary"), &realm)
            .await
            .err()
            .expect("an unresolvable discovery column type must fail restricted routing closed");
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}: {:?}", mode, started.elapsed());
        let lookups = cluster.type_lookups.load(Ordering::SeqCst);
        assert!(lookups > 0 && lookups <= most, "{:?}: {} type lookups", mode, lookups);
        assert!(realm.topology().is_none());
    }
}

/// ASTS-90: a backend message larger than the configured limit fails the
/// connection from its header, without waiting to buffer it; the default
/// limit admits large legitimate rows.
#[tokio::test]
async fn oversized_backend_messages_are_rejected_from_their_header() {
    let cluster = Cluster::new("frames");
    let n1 = Node::start(&cluster).await;
    let direct = config(&n1, "load_balance=false");

    // The default limit (1 GiB, PostgreSQL's own) admits a large row...
    cluster.set_discovery(Discovery::LargeRow);
    let (client, connection) = direct.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    client.simple_query("node").await.unwrap();

    // ...while a configured lower limit rejects it.
    let mut limited = direct.clone();
    limited.max_message_size(1024);
    assert_eq!(limited.get_max_message_size(), 1024);
    let (client, connection) = limited.connect(NoTls).await.unwrap();
    let connection = tokio::spawn(connection);
    client.simple_query("node").await.err().expect("a row beyond the configured limit");
    let e = timeout(Duration::from_secs(1), connection).await.unwrap().unwrap().err().unwrap();
    assert!(e.to_string().contains("byte limit"), "{}", e);

    // A frame beyond the default limit fails as soon as its header arrives.
    cluster.set_discovery(Discovery::HugeRow);
    let (client, connection) = direct.connect(NoTls).await.unwrap();
    let connection = tokio::spawn(connection);
    timeout(Duration::from_secs(1), client.simple_query("node"))
        .await
        .expect("the oversized frame must be refused from its header")
        .err()
        .expect("a frame beyond the default limit");
    let e = timeout(Duration::from_secs(1), connection).await.unwrap().unwrap().err().unwrap();
    assert!(e.to_string().contains("byte limit"), "{}", e);
}

/// ASTS-90: before the session is established, messages are limited to
/// 128 KiB and the parameter status messages retained are bounded.
#[tokio::test]
async fn startup_messages_are_bounded() {
    let cluster = Cluster::new("startup");
    let n1 = Node::start(&cluster).await;
    let direct = config(&n1, "load_balance=false");

    n1.set(Behaviour::HugeStartupMessage);
    let started = Instant::now();
    let e = direct.connect(NoTls).await.err().expect("an oversized startup message");
    assert!(e.to_string().contains("byte limit"), "{}", e);
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());

    n1.set(Behaviour::ParameterFlood);
    let e = direct.connect(NoTls).await.err().expect("a parameter status flood");
    assert!(e.to_string().contains("too many parameter status"), "{}", e);
}

/// ASTS-90: a discovery answer with more rows, or longer fields, than any
/// real cluster reports is an invalid snapshot, not a topology.
#[tokio::test]
async fn oversized_discovery_answers_are_rejected() {
    for (mode, accepted) in [
        (Discovery::ManyRows(4096), true),
        (Discovery::ManyRows(4097), false),
        (Discovery::LongZone(1024), true),
        (Discovery::LongZone(1025), false),
    ] {
        let cluster = Cluster::new("oversized");
        let n1 = Node::start(&cluster).await;
        cluster.publish(&[(&n1, "primary", "z1")]);
        cluster.set_discovery(mode);
        let realm = Realm::new("oversized");
        let result = connect(&config(&n1, "load_balance=only-primary"), &realm).await;
        assert_eq!(result.is_ok(), accepted, "{:?}", mode);
        assert_eq!(realm.topology().is_some(), accepted, "{:?}", mode);
    }
}

// ------------------------------------------- ASTS-87 discovered-port pinning
//
// An endpoint policy enforces admission without TLS, so these run on the
// plaintext fixture; `tls-qualification` repeats the seed case under
// verify-full against YugabyteDB.

fn admitting(conninfo: String, policy: EndpointPolicy) -> Config {
    let mut config: Config = conninfo.parse().unwrap();
    config.endpoint_policy(policy);
    config
}

fn not_admitted(e: &Error) -> bool {
    e.to_string().contains("no discovered node is admitted")
}

fn other_port(port: u16) -> u16 {
    if port == u16::MAX {
        1
    } else {
        port + 1
    }
}

fn publish_rows(cluster: &Cluster, rows: &[(&str, u16)]) {
    *cluster.rows.lock().unwrap() = rows
        .iter()
        .map(|(host, port)| NodeRow {
            host: host.to_string(),
            port: *port,
            node_type: "primary",
            zone: "z1".to_string(),
        })
        .collect();
}

#[tokio::test]
async fn seed_identity_is_admitted_only_on_the_seed_port() {
    for key in ["host", "hostaddr"] {
        let cluster = Cluster::new("port");
        let seed = Node::start(&cluster).await;
        // Another listener on the seed's address, on a port no seed names.
        let other = Node::start_at(&cluster, &seed.ip, 0).await;
        let conninfo = |lb: &str| {
            format!(
                "{key}={} port={} user=test dbname=test sslmode=disable connect_timeout=2 load_balance={lb}",
                seed.ip, seed.port
            )
        };
        cluster.publish(&[(&other, "primary", "z1")]);

        // Restricted routing fails closed without dialling the other port.
        let restricted = admitting(conninfo("only-primary"), EndpointPolicy::new());
        let before = seed.logins();
        let e = connect(&restricted, &Realm::new("port-restricted")).await.err().expect("refused");
        assert!(not_admitted(&e), "{}: {}", key, e);
        assert_eq!((other.logins(), seed.logins() - before), (0, 1), "{}", key);

        // Unrestricted routing skips the node and uses the seed itself.
        let unrestricted = admitting(conninfo("any"), EndpointPolicy::new());
        let s = connect(&unrestricted, &Realm::new("port-unrestricted")).await.unwrap();
        assert_eq!(node_of(&s).await, seed.ip);
        assert_eq!(other.logins(), 0, "{}", key);

        // The seed reported on its own port is admitted through discovery.
        cluster.publish(&[(&seed, "primary", "z1")]);
        let realm = Realm::new("port-match");
        let _held = connect(&restricted, &realm).await.unwrap();
        assert_eq!(realm.connection_counts().get(&seed.ip), Some(&1), "{}", key);

        // Without verify-full and without a policy nothing is enforced and
        // the reported port is dialled, as before.
        cluster.publish(&[(&other, "primary", "z1")]);
        let open: Config = conninfo("only-primary").parse().unwrap();
        connect(&open, &Realm::new("port-open")).await.unwrap();
        assert_eq!(other.logins(), 1, "{}", key);
    }
}

#[tokio::test]
async fn per_seed_ports_do_not_admit_each_other() {
    let cluster = Cluster::new("ports");
    let s1 = Node::start(&cluster).await;
    let mut s2 = Node::start(&cluster).await;
    // Distinct addresses can be given the same ephemeral port.
    while s2.port == s1.port {
        s2 = Node::start(&cluster).await;
    }
    // s1's address on s2's port: a port the configuration names, but for
    // another seed.
    let decoy = Node::start_at(&cluster, &s1.ip, s2.port).await;
    cluster.publish(&[(&decoy, "primary", "z1"), (&s2, "primary", "z1")]);
    let config = admitting(
        format!(
            "host={},{} port={},{} user=test dbname=test sslmode=disable connect_timeout=2 load_balance=only-primary",
            s1.ip, s2.ip, s1.port, s2.port
        ),
        EndpointPolicy::new(),
    );
    let realm = Realm::new("per-seed-ports");
    let mut sessions = Vec::new();
    for _ in 0..4 {
        let s = connect(&config, &realm).await.unwrap();
        assert_eq!(node_of(&s).await, s2.ip);
        sessions.push(s);
    }
    assert_eq!(decoy.logins(), 0);
    assert!(realm.failed_nodes().is_empty());
    assert_eq!(realm.connection_counts().get(&s1.ip), None);
}

#[tokio::test]
async fn suffix_admission_requires_its_port() {
    assert!(EndpointPolicy::new().admit_dns_suffix_on_port("yb.invalid", 0).is_err());
    let cluster = Cluster::new("suffix");
    let seed = Node::start(&cluster).await;
    let conninfo = || {
        format!(
            "host={} port={} user=test dbname=test sslmode=disable connect_timeout=2 \
             load_balance=only-primary yb_attempt_timeout=5",
            seed.ip, seed.port
        )
    };
    // `.invalid` never resolves, so an admitted node fails to dial with a
    // transport error, while a refused one never becomes a candidate.
    let pinned = other_port(seed.port);
    for (policy, refused_port, admitted_port) in [
        // Without a port the suffix admits only the configured seed port.
        (EndpointPolicy::new().admit_dns_suffix("yb.invalid").unwrap(), pinned, seed.port),
        (EndpointPolicy::new().admit_dns_suffix_on_port("yb.invalid", pinned).unwrap(), seed.port, pinned),
    ] {
        let config = admitting(conninfo(), policy);
        publish_rows(&cluster, &[("n1.yb.invalid", refused_port)]);
        let e = connect(&config, &Realm::new("suffix-refused")).await.err().expect("refused");
        assert!(not_admitted(&e), "{}", e);

        publish_rows(&cluster, &[("n1.yb.invalid", admitted_port)]);
        let e = connect(&config, &Realm::new("suffix-admitted")).await.err().expect("unresolvable");
        assert!(!not_admitted(&e), "{}", e);
    }
}
