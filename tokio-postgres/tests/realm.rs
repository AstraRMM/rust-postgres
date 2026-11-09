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
use yb_tokio_postgres::realm::Realm;
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
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Discovery {
    Rows,
    Error,
    Empty,
    Stall,
    Slow(u64),
    SlowError(u64),
}

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
    region: String,
}

impl Cluster {
    fn new(region: &str) -> Cluster {
        Cluster {
            rows: Arc::new(Mutex::new(Vec::new())),
            discovery: Arc::new(Mutex::new(Discovery::Rows)),
            discoveries: Arc::new(AtomicUsize::new(0)),
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

fn metadata_description() -> Vec<u8> {
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
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&size.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
    }
    payload
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
                message(&mut socket, b'D', &data_row(&[Some(identity.as_bytes())])).await?;
                message(&mut socket, b'C', b"SELECT 1\0").await?;
                message(&mut socket, b'Z', b"I").await?;
            }
            b'P' => {
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
            b'D' => {
                message(&mut socket, b't', &0u16.to_be_bytes()).await?;
                message(&mut socket, b'T', &metadata_description()).await?;
            }
            b'B' => message(&mut socket, b'2', &[]).await?,
            b'E' => {
                let rows = if *cluster.discovery.lock().unwrap() == Discovery::Empty {
                    Vec::new()
                } else {
                    cluster.rows.lock().unwrap().clone()
                };
                for row in &rows {
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
    for _ in 0..5 {
        // Only n1 remains; repeated failures elsewhere never skew counts.
        let s = connect(&conf, &realm).await.unwrap();
        assert_eq!(node_of(&s).await, n1.ip);
    }
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
