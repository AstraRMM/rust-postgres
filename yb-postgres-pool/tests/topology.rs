//! AST-1911: warm capacity through topology refresh, recovery and generation
//! replacement. A loopback fixture speaks the PostgreSQL wire protocol as a
//! YugabyteDB cluster whose `yb_servers()` topology and per-node behaviour
//! change mid-test. Each test prints an `EVIDENCE` line with the counts it
//! observed before, during and after the change.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use yb_postgres_pool::yb_tokio_postgres::realm::{NodeStanding, Realm};
use yb_postgres_pool::yb_tokio_postgres::{Config, NoTls, SimpleQueryMessage};
use yb_postgres_pool::{
    ConnectionLimiter, Pool, PoolConfig, PoolError, PoolKey, PoolSet, PoolSetConfig, PoolSpec,
};

static NEXT_IP: AtomicU8 = AtomicU8::new(10);

fn next_ip() -> String {
    format!("127.0.43.{}", NEXT_IP.fetch_add(1, Ordering::SeqCst))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Behaviour {
    Accept,
    Refuse,
}

type NodeRow = (String, u16, &'static str, String);

#[derive(Clone)]
struct Cluster {
    rows: Arc<Mutex<Vec<NodeRow>>>,
    discoveries: Arc<AtomicUsize>,
    region: String,
}

impl Cluster {
    fn new(region: &str) -> Cluster {
        Cluster {
            rows: Arc::new(Mutex::new(Vec::new())),
            discoveries: Arc::new(AtomicUsize::new(0)),
            region: region.to_string(),
        }
    }

    fn publish(&self, nodes: &[(&Node, &'static str)]) {
        *self.rows.lock().unwrap() = nodes
            .iter()
            .map(|(node, zone)| (node.ip.clone(), node.port, "primary", zone.to_string()))
            .collect();
    }
}

struct Node {
    ip: String,
    port: u16,
    behaviour: Arc<Mutex<Behaviour>>,
    logins: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    async fn start(cluster: &Cluster) -> Node {
        let ip = next_ip();
        let listener = TcpListener::bind((ip.as_str(), 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let behaviour = Arc::new(Mutex::new(Behaviour::Accept));
        let logins = Arc::new(AtomicUsize::new(0));
        let task = {
            let (cluster, behaviour, logins, ip) = (
                cluster.clone(),
                behaviour.clone(),
                logins.clone(),
                ip.clone(),
            );
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let mode = *behaviour.lock().unwrap();
                    let (cluster, logins, ip) = (cluster.clone(), logins.clone(), ip.clone());
                    tokio::spawn(async move {
                        let _ = session(socket, mode, &ip, &cluster, &logins).await;
                    });
                }
            })
        };
        Node {
            ip,
            port,
            behaviour,
            logins,
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
    let mut payload = (columns.len() as u16).to_be_bytes().to_vec();
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

async fn session(
    mut socket: TcpStream,
    mode: Behaviour,
    identity: &str,
    cluster: &Cluster,
    logins: &AtomicUsize,
) -> io::Result<()> {
    if mode == Behaviour::Refuse {
        return Ok(());
    }
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    logins.fetch_add(1, Ordering::SeqCst);
    message(&mut socket, b'R', &0u32.to_be_bytes()).await?;
    message(&mut socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut socket, b'S', b"client_encoding\0UTF8\0").await?;
    message(&mut socket, b'S', b"server_version\x0015.0\0").await?;
    message(&mut socket, b'Z', b"I").await?;
    loop {
        let tag = match socket.read_u8().await {
            Ok(tag) => tag,
            Err(_) => return Ok(()),
        };
        let length = socket.read_u32().await?;
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        match tag {
            b'X' => return Ok(()),
            b'Q' => {
                let mut description = 1u16.to_be_bytes().to_vec();
                description.extend_from_slice(b"node\0");
                description.extend_from_slice(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255, 255, 255, 255, 255, 255, 0, 0,
                ]);
                message(&mut socket, b'T', &description).await?;
                message(&mut socket, b'D', &data_row(&[Some(identity.as_bytes())])).await?;
                message(&mut socket, b'C', b"SELECT 1\0").await?;
                message(&mut socket, b'Z', b"I").await?;
            }
            b'P' => {
                cluster.discoveries.fetch_add(1, Ordering::SeqCst);
                message(&mut socket, b'1', &[]).await?;
            }
            b'D' => {
                message(&mut socket, b't', &0u16.to_be_bytes()).await?;
                message(&mut socket, b'T', &metadata_description()).await?;
            }
            b'B' => message(&mut socket, b'2', &[]).await?,
            b'E' => {
                let rows = cluster.rows.lock().unwrap().clone();
                for (host, port, node_type, zone) in &rows {
                    let port = (*port as i64).to_be_bytes();
                    message(
                        &mut socket,
                        b'D',
                        &data_row(&[
                            Some(host.as_bytes()),
                            Some(&port),
                            Some(b"qual"),
                            Some(cluster.region.as_bytes()),
                            Some(zone.as_bytes()),
                            None,
                            Some(node_type.as_bytes()),
                        ]),
                    )
                    .await?;
                }
                message(
                    &mut socket,
                    b'C',
                    format!("SELECT {}\0", rows.len()).as_bytes(),
                )
                .await?;
            }
            b'S' => message(&mut socket, b'Z', b"I").await?,
            b'C' => message(&mut socket, b'3', &[]).await?,
            _ => {}
        }
    }
}

fn driver_config(seed: &Node, realm: &Realm, parameters: &str) -> Config {
    let mut config: Config = format!(
        "host={} port={} user=test dbname=test sslmode=disable connect_timeout=2 {}",
        seed.ip, seed.port, parameters
    )
    .parse()
    .unwrap();
    config.realm(realm.clone());
    config.yb_servers_refresh_interval(Duration::from_millis(100));
    config
}

fn pool_config(floor: u32, max: u32) -> PoolConfig {
    let mut config = PoolConfig::default();
    config.max_size = max;
    config.warm_floor = floor;
    config.maintenance_interval = Duration::from_millis(50);
    config.acquire_timeout = Duration::from_secs(3);
    config.connect_timeout = Duration::from_secs(2);
    config
}

async fn eventually(within: Duration, mut condition: impl FnMut() -> bool) -> bool {
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

/// Samples the limiter's permits in use (every physical connection,
/// including dials and sockets still closing, across every pool sharing it)
/// and the pool's physical count until stopped.
struct Sampler {
    stop: Arc<AtomicBool>,
    max_in_use: Arc<AtomicU32>,
    min_physical: Arc<AtomicU32>,
    task: JoinHandle<()>,
}

impl Sampler {
    fn start(limiter: &ConnectionLimiter, physical: impl Fn() -> u32 + Send + 'static) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let max_in_use = Arc::new(AtomicU32::new(0));
        let min_physical = Arc::new(AtomicU32::new(u32::MAX));
        let task = {
            let (stop, max_in_use, min_physical, limiter) = (
                stop.clone(),
                max_in_use.clone(),
                min_physical.clone(),
                limiter.clone(),
            );
            tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) {
                    max_in_use.fetch_max(limiter.in_use(), Ordering::SeqCst);
                    min_physical.fetch_min(physical(), Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };
        Sampler {
            stop,
            max_in_use,
            min_physical,
            task,
        }
    }

    async fn finish(self) -> (u32, u32) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.task.await;
        (
            self.max_in_use.load(Ordering::SeqCst),
            self.min_physical.load(Ordering::SeqCst),
        )
    }
}

async fn node_of(pool: &Pool<NoTls>) -> String {
    let client = pool.get().await.unwrap();
    let rows = client.simple_query("select node").await.unwrap();
    rows.into_iter()
        .find_map(|m| match m {
            SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
            _ => None,
        })
        .unwrap()
}

fn counts(realm: &Realm) -> BTreeMap<String, usize> {
    realm.connection_counts()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removal_retires_and_rewarms_within_bound() {
    let cluster = Cluster::new("rm");
    let (a, b, c) = (
        Node::start(&cluster).await,
        Node::start(&cluster).await,
        Node::start(&cluster).await,
    );
    cluster.publish(&[(&a, "z1"), (&b, "z1"), (&c, "z1")]);
    let realm = Realm::new("removal");
    let limiter = ConnectionLimiter::new(8);
    let pool = Pool::with_limiter(
        driver_config(&a, &realm, "load_balance=true"),
        NoTls,
        pool_config(6, 8),
        limiter.clone(),
        "removal",
    )
    .unwrap();
    let started = Instant::now();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 6).await);
    let warmed_in = started.elapsed();
    let before = counts(&realm);
    assert_eq!(before.values().copied().collect::<Vec<_>>(), vec![2, 2, 2]);

    let sampler = Sampler::start(&limiter, {
        let pool = pool.clone();
        move || pool.state().physical
    });
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let removed = Instant::now();
    let recovered = eventually(Duration::from_secs(5), || {
        let now = counts(&realm);
        !now.contains_key(&c.ip) && pool.state().physical == 6 && now.values().sum::<usize>() == 6
    })
    .await;
    let recovered_in = removed.elapsed();
    let (max_in_use, min_physical) = sampler.finish().await;
    let after = counts(&realm);
    let stats = pool.state().stats;
    println!(
        "EVIDENCE removal: warm floor 6 reached in {:?}; before={:?}; c removed; after={:?} in {:?}; \
         retired_topology={} warm_connects={} max_permits_in_use={}",
        warmed_in, before, after, recovered_in, stats.retired_topology, stats.warm_connects, max_in_use
    );
    assert!(
        recovered,
        "pool did not re-warm on the remaining nodes: {:?}",
        after
    );
    assert_eq!(stats.retired_topology, 2);
    assert!(max_in_use <= 8);
    assert!(
        min_physical >= 6,
        "warm capacity dipped to {}",
        min_physical
    );
    assert!(recovered_in < Duration::from_secs(2), "{:?}", recovered_in);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn additions_and_unchanged_refreshes_keep_warm_connections() {
    let cluster = Cluster::new("add");
    let (a, b, c) = (
        Node::start(&cluster).await,
        Node::start(&cluster).await,
        Node::start(&cluster).await,
    );
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let realm = Realm::new("additions");
    let pool = Pool::new(
        driver_config(&a, &realm, "load_balance=true"),
        NoTls,
        pool_config(4, 8),
    )
    .unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 4).await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let steady = pool.state().stats;
    let discoveries = cluster.discoveries.load(Ordering::SeqCst);

    cluster.publish(&[(&a, "z1"), (&b, "z1"), (&c, "z1")]);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let stats = pool.state().stats;
    let retired = stats.retired_topology
        + stats.retired_rebalanced
        + stats.retired_closed
        + stats.retired_idle
        + stats.reaped;
    println!(
        "EVIDENCE additions: steady sweeps={} refreshes={}; after adding c: connects {} -> {}, \
         retired={} sweeps={} discoveries {} -> {} counts={:?}",
        steady.idle_sweeps,
        steady.topology_refreshes,
        steady.connects,
        stats.connects,
        retired,
        stats.idle_sweeps,
        discoveries,
        cluster.discoveries.load(Ordering::SeqCst),
        counts(&realm)
    );
    assert_eq!(steady.idle_sweeps, 1, "unchanged refreshes must not sweep");
    assert!(stats.topology_refreshes > steady.topology_refreshes);
    assert_eq!(
        stats.connects, steady.connects,
        "healthy connections were churned"
    );
    assert_eq!(retired, 0);
    assert_eq!(stats.idle_sweeps, 2);
    assert!(!counts(&realm).contains_key(&c.ip));

    let held: Vec<_> = futures_util::future::join_all((0..5).map(|_| pool.get()))
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        counts(&realm).get(&c.ip),
        Some(&1),
        "new capacity goes to the new node"
    );
    drop(held);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_connections_rebalance_warm_first() {
    let cluster = Cluster::new("fb");
    let (a, b) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&a, "z1"), (&b, "z2")]);
    let realm = Realm::new("fallback");
    let mut pg = driver_config(
        &b,
        &realm,
        "load_balance=true topology_keys=qual.fb.z1:1,qual.fb.z2:2",
    );
    pg.failed_host_reconnect_delay_secs(Duration::from_millis(400));
    a.set(Behaviour::Refuse);
    let limiter = ConnectionLimiter::new(6);
    let pool =
        Pool::with_limiter(pg, NoTls, pool_config(4, 6), limiter.clone(), "fallback").unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 4).await);
    let before = counts(&realm);
    assert_eq!(before.get(&b.ip), Some(&4));

    let sampler = Sampler::start(&limiter, {
        let pool = pool.clone();
        move || pool.state().physical
    });
    a.set(Behaviour::Accept);
    let recovered = Instant::now();
    let moved = eventually(Duration::from_secs(5), || {
        let now = counts(&realm);
        now.get(&a.ip) == Some(&4) && !now.contains_key(&b.ip)
    })
    .await;
    let moved_in = recovered.elapsed();
    let (max_in_use, min_physical) = sampler.finish().await;
    let stats = pool.state().stats;
    println!(
        "EVIDENCE fallback: before={:?}; preferred node recovered; after={:?} in {:?} \
         (includes the 400 ms quarantine); retired_rebalanced={} deferrals={} \
         min_physical={} max_permits_in_use={}",
        before,
        counts(&realm),
        moved_in,
        stats.retired_rebalanced,
        stats.rebalance_deferrals,
        min_physical,
        max_in_use
    );
    assert!(moved, "{:?}", counts(&realm));
    assert_eq!(stats.retired_rebalanced, 4);
    assert!(
        min_physical >= 4,
        "warm capacity dipped to {}",
        min_physical
    );
    assert!(max_in_use <= 6);
    assert_eq!(node_of(&pool).await, a.ip);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_without_free_permits_is_deferred_not_exceeded() {
    let cluster = Cluster::new("fd");
    let (a, b) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&a, "z1"), (&b, "z2")]);
    let realm = Realm::new("deferred");
    let mut pg = driver_config(
        &b,
        &realm,
        "load_balance=true topology_keys=qual.fd.z1:1,qual.fd.z2:2",
    );
    pg.failed_host_reconnect_delay_secs(Duration::from_millis(300));
    a.set(Behaviour::Refuse);
    let limiter = ConnectionLimiter::new(3);
    let pool =
        Pool::with_limiter(pg, NoTls, pool_config(3, 3), limiter.clone(), "deferred").unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 3).await);
    let sampler = Sampler::start(&limiter, {
        let pool = pool.clone();
        move || pool.state().physical
    });
    a.set(Behaviour::Accept);
    tokio::time::sleep(Duration::from_millis(900)).await;
    let (max_in_use, min_physical) = sampler.finish().await;
    let stats = pool.state().stats;
    println!(
        "EVIDENCE deferred: limit 3 = floor 3; counts={:?} deferrals={} retired_rebalanced={} \
         min_physical={} max_permits_in_use={}",
        counts(&realm),
        stats.rebalance_deferrals,
        stats.retired_rebalanced,
        min_physical,
        max_in_use
    );
    assert!(stats.rebalance_deferrals > 0);
    assert_eq!(stats.retired_rebalanced, 0);
    assert_eq!(counts(&realm).get(&b.ip), Some(&3));
    assert_eq!(min_physical, 3);
    assert!(max_in_use <= 3);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_work_survives_removal() {
    let cluster = Cluster::new("cw");
    let (a, b, c) = (
        Node::start(&cluster).await,
        Node::start(&cluster).await,
        Node::start(&cluster).await,
    );
    cluster.publish(&[(&a, "z1"), (&b, "z1"), (&c, "z1")]);
    let realm = Realm::new("concurrent");
    let limiter = ConnectionLimiter::new(8);
    let pool = Pool::with_limiter(
        driver_config(&a, &realm, "load_balance=true"),
        NoTls,
        pool_config(4, 8),
        limiter.clone(),
        "concurrent",
    )
    .unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 4).await);
    let sampler = Sampler::start(&limiter, || 0);
    let workers: Vec<JoinHandle<Result<usize, PoolError>>> = (0..8)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move {
                let mut done = 0;
                for _ in 0..150 {
                    let client = pool.get().await?;
                    client
                        .simple_query("select node")
                        .await
                        .map_err(|e| client.classify_error(e))?;
                    done += 1;
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Ok(done)
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let during = counts(&realm);
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let mut completed = 0;
    for worker in workers {
        completed += worker
            .await
            .unwrap()
            .expect("a query failed during removal");
    }
    let drained = Instant::now();
    assert!(
        eventually(Duration::from_secs(10), || !counts(&realm)
            .contains_key(&c.ip))
        .await,
        "{:?}",
        counts(&realm)
    );
    let drained_in = drained.elapsed();
    let (max_in_use, _) = sampler.finish().await;
    let stats = pool.state().stats;
    println!(
        "EVIDENCE concurrent: {} queries by 8 workers; during={:?}; after={:?} ({:?} after the \
         workers finished); retired_topology={} max_permits_in_use={}",
        completed,
        during,
        counts(&realm),
        drained_in,
        stats.retired_topology,
        max_in_use
    );
    assert_eq!(completed, 8 * 150);
    assert!(stats.retired_topology > 0);
    assert!(max_in_use <= 8);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forced_refresh_and_shutdown() {
    let cluster = Cluster::new("fr");
    let (a, b) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let realm = Realm::new("forced");
    let mut pg = driver_config(&a, &realm, "load_balance=true");
    pg.yb_servers_refresh_interval(Duration::from_secs(600));
    let pool = Pool::new(pg, NoTls, pool_config(4, 6)).unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 4).await);

    cluster.publish(&[(&a, "z1")]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        counts(&realm).get(&b.ip),
        Some(&2),
        "fresh snapshots are not refreshed"
    );
    let discoveries = cluster.discoveries.load(Ordering::SeqCst);
    realm.invalidate_topology();
    assert!(
        eventually(Duration::from_secs(2), || {
            let now = counts(&realm);
            !now.contains_key(&b.ip) && now.get(&a.ip) == Some(&4)
        })
        .await,
        "{:?}",
        counts(&realm)
    );
    assert_eq!(cluster.discoveries.load(Ordering::SeqCst), discoveries + 1);

    let report = pool.shutdown(Duration::from_secs(1)).await;
    let logins = a.logins() + b.logins();
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!(
        "EVIDENCE forced refresh and shutdown: {:?}; logins after shutdown {} -> {}; counts={:?}",
        report,
        logins,
        a.logins() + b.logins(),
        counts(&realm)
    );
    assert_eq!(report.physical_after, 0);
    assert!(counts(&realm).is_empty());
    assert_eq!(
        a.logins() + b.logins(),
        logins,
        "maintenance outlived shutdown"
    );
    assert_eq!(
        realm.standing(&driver_config(&a, &realm, "load_balance=true"), &a.ip),
        NodeStanding::Preferred
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generation_replacement_warms_then_drains_within_the_limit() {
    let cluster = Cluster::new("gen");
    let (a, b) = (Node::start(&cluster).await, Node::start(&cluster).await);
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let realm = Realm::new("generations");
    let pg = driver_config(&a, &realm, "load_balance=true");
    let resolver = move |_: &PoolKey| -> Result<PoolSpec<NoTls>, PoolError> {
        Ok(PoolSpec::new(pg.clone(), NoTls, pool_config(4, 6)))
    };
    let mut set_config = PoolSetConfig::default();
    set_config.max_connections = 6;
    set_config.drain_timeout = Duration::from_secs(2);
    let set = PoolSet::new(set_config, resolver).unwrap();
    let limiter = set.limiter().clone();
    let gen0 = PoolKey::for_realm(&realm, "test", "test");
    let gen1 = gen0.clone().with_credential_generation(1);

    let old = set.pool(&gen0).unwrap();
    assert!(eventually(Duration::from_secs(5), || old.state().physical == 4).await);
    let in_flight = old.get().await.unwrap();
    let sampler = Sampler::start(&limiter, || 0);

    let replaced = Instant::now();
    let new = set.pool(&gen1).unwrap();
    let during = (old.state().physical, new.state().physical);
    let rows = in_flight.simple_query("select node").await.unwrap();
    assert!(
        !rows.is_empty(),
        "in-flight work on the old generation still runs"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(in_flight);
    let warmed = eventually(Duration::from_secs(5), || {
        new.state().physical == 4 && old.is_closed() && old.state().physical == 0
    })
    .await;
    let warmed_in = replaced.elapsed();
    let (max_in_use, _) = sampler.finish().await;
    println!(
        "EVIDENCE generations: limit 6, floor 4; old/new physical during={:?}; new floor reached \
         and old drained in {:?}; max_permits_in_use={}; counts={:?}",
        during,
        warmed_in,
        max_in_use,
        counts(&realm)
    );
    assert!(warmed);
    assert!(set.state(&gen0).is_none());
    assert!(max_in_use <= 6);
    assert_eq!(counts(&realm).values().sum::<usize>(), 4);
    set.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_new_topology_keeps_departed_sessions_until_replaced() {
    let cluster = Cluster::new("ur");
    let (a, b, d) = (
        Node::start(&cluster).await,
        Node::start(&cluster).await,
        Node::start(&cluster).await,
    );
    cluster.publish(&[(&a, "z1"), (&b, "z1")]);
    let realm = Realm::new("unreachable");
    let mut pg = driver_config(&a, &realm, "load_balance=true");
    pg.failed_host_reconnect_delay_secs(Duration::from_millis(300));
    let pool = Pool::new(pg, NoTls, pool_config(4, 6)).unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 4).await);
    let before = counts(&realm);

    d.set(Behaviour::Refuse);
    cluster.publish(&[(&d, "z1")]);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let during = counts(&realm);
    let served = node_of(&pool).await;
    let deferred = pool.state().stats;
    assert_eq!(
        during.get(&a.ip).copied().unwrap_or(0) + during.get(&b.ip).copied().unwrap_or(0),
        4
    );
    assert!(served == a.ip || served == b.ip);
    assert!(deferred.rebalance_deferrals > 0);
    assert_eq!(deferred.retired_topology, 0);

    d.set(Behaviour::Accept);
    let replaced = eventually(Duration::from_secs(10), || {
        counts(&realm).get(&d.ip) == Some(&4) && counts(&realm).len() == 1
    })
    .await;
    let stats = pool.state().stats;
    println!(
        "EVIDENCE unreachable topology: before={:?}; topology swapped to an unreachable node; \
         during={:?} (served by {}), deferrals={} retired=0, sweeps while waiting={}; \
         after it accepts: {:?}, retired_topology={}",
        before,
        during,
        served,
        deferred.rebalance_deferrals,
        deferred.idle_sweeps,
        counts(&realm),
        stats.retired_topology
    );
    assert!(replaced, "{:?}", counts(&realm));
    assert_eq!(stats.retired_topology, 4);
    assert!(
        deferred.rebalance_deferrals <= 8,
        "replacement attempts must back off: {} deferrals in 1.5 s",
        deferred.rebalance_deferrals
    );
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_last_handle_stops_maintenance() {
    let cluster = Cluster::new("dr");
    let a = Node::start(&cluster).await;
    cluster.publish(&[(&a, "z1")]);
    let realm = Realm::new("dropped");
    let pool = Pool::new(
        driver_config(&a, &realm, "load_balance=true"),
        NoTls,
        pool_config(3, 4),
    )
    .unwrap();
    assert!(eventually(Duration::from_secs(5), || pool.state().physical == 3).await);
    drop(pool);
    assert!(
        eventually(Duration::from_secs(3), || counts(&realm).is_empty()).await,
        "{:?}",
        counts(&realm)
    );
    let logins = a.logins();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        a.logins(),
        logins,
        "maintenance kept running after the pool was dropped"
    );
}
