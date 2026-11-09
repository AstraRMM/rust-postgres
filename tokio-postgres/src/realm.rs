//! Owned smart-driver state for one YugabyteDB realm.
//!
//! A [`Realm`] owns everything the load-balancing driver remembers about one
//! cluster: the validated topology snapshot, refresh coalescing, failure
//! (quarantine) state and per-node connection accounting. Nothing is shared
//! between realms, so two independent clusters in one process can never see
//! each other's nodes, counts or failures, and no fallback ever selects a node
//! of another realm.
//!
//! Selection is applied in this order:
//!
//! 1. trusted realm and endpoint admission ([`crate::endpoint`]),
//! 2. hard role and placement eligibility (`only-primary`, `only-rr`,
//!    `fallback_to_topology_keys_only`),
//! 3. preference among eligible nodes (`prefer-*`, topology-key priority),
//! 4. load (fewest connections, random tie-break).
//!
//! Every acquisition runs under one overall budget
//! ([`Config::yb_acquire_timeout`]) that covers discovery, DNS, TCP, TLS,
//! authentication and retries, with a smaller per-attempt bound
//! ([`Config::yb_attempt_timeout`]) and a bounded number of node attempts
//! ([`Config::yb_max_attempts`]). Refresh runs inline in the caller's task,
//! coalesced per realm; there are no detached tasks to outlive the caller,
//! its TLS connector or the realm.

use crate::client::Client;
use crate::config::{Config, Host};
use crate::connect::{
    allows_unbalanced_fallback, connect_host, connect_with_tls_ref, control_connection_config,
    error_chain, public_ip_mode_allowed, resolve_node, seeds_label,
};
use crate::endpoint;
use crate::tls::MakeTlsConnect;
use crate::{Connection, Error, Socket};
use futures_util::{future, pin_mut, Future, FutureExt};
use lazy_static::lazy_static;
use log::{debug, info, warn};
use parking_lot::{Mutex, RwLock};
use rand::seq::SliceRandom;
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;

/// Bound on establishing one control connection (connect, TLS, authentication).
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on the `yb_servers()` query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Closing a control connection is a courtesy.
const CONTROL_CONN_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on implicitly created realms (see [`Realm::for_config`]).
const MAX_IMPLICIT_REALMS: usize = 256;

/// Stable realm identity plus the cluster incarnation it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RealmKey {
    name: String,
    incarnation: Option<String>,
}

impl RealmKey {
    /// The realm name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The cluster incarnation, if one was declared.
    pub fn incarnation(&self) -> Option<&str> {
        self.incarnation.as_deref()
    }
}

/// The role a node reports in `yb_servers()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRole {
    /// A primary-cluster tablet server.
    Primary,
    /// A read-replica tablet server.
    ReadReplica,
}

/// One node of a validated topology snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    identity: String,
    port: u16,
    role: NodeRole,
    cloud: String,
    region: String,
    zone: String,
    public_ip: Option<String>,
}

impl NodeInfo {
    /// Canonical node identity (the `host` column).
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// YSQL port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Node role.
    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// `cloud.region.zone`.
    pub fn placement(&self) -> String {
        format!("{}.{}.{}", self.cloud, self.region, self.zone)
    }

    fn matches(&self, pattern: &str) -> bool {
        let mut parts = pattern.splitn(3, '.');
        let (cloud, region, zone) = match (parts.next(), parts.next(), parts.next()) {
            (Some(c), Some(r), Some(z)) => (c, r, z),
            _ => return false,
        };
        cloud == self.cloud && region == self.region && (zone == "*" || zone == self.zone)
    }
}

/// A complete, validated `yb_servers()` result.
#[derive(Debug)]
pub(crate) struct Topology {
    nodes: BTreeMap<String, NodeInfo>,
    fetched_at: Instant,
}

/// A read-only view of a realm's current topology snapshot.
#[derive(Debug, Clone)]
pub struct TopologyInfo {
    nodes: Vec<NodeInfo>,
    age: Duration,
}

impl TopologyInfo {
    /// Nodes in the snapshot, ordered by identity.
    pub fn nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    /// Time since the snapshot was fetched.
    pub fn age(&self) -> Duration {
        self.age
    }
}

struct RealmInner {
    key: RealmKey,
    snapshot: RwLock<Option<Arc<Topology>>>,
    refresh_gate: tokio::sync::Mutex<()>,
    refresh_epoch: AtomicU64,
    discoveries: AtomicU64,
    failures: Mutex<HashMap<String, Instant>>,
    counts: Mutex<HashMap<String, usize>>,
    public_mode: AtomicBool,
    shutdown: AtomicBool,
}

/// Owned smart-driver state for one realm. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Realm {
    inner: Arc<RealmInner>,
}

impl PartialEq for Realm {
    fn eq(&self, other: &Realm) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for Realm {}

impl fmt::Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Realm")
            .field("key", &self.inner.key)
            .field("shut_down", &self.is_shut_down())
            .finish()
    }
}

/// Identity of an implicitly created realm: the trusted seed and TLS
/// configuration of the cluster, not merely its seeds and database name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ImplicitKey(String);

lazy_static! {
    static ref IMPLICIT_REALMS: Mutex<Vec<(ImplicitKey, Realm)>> = Mutex::new(Vec::new());
}

impl Realm {
    /// Creates a realm. The resource directory chooses the realm before
    /// driver selection; the driver never moves a request between realms.
    pub fn new(name: impl Into<String>) -> Realm {
        Realm::build(RealmKey {
            name: name.into(),
            incarnation: None,
        })
    }

    /// Creates a realm bound to a specific cluster incarnation.
    pub fn with_incarnation(name: impl Into<String>, incarnation: impl Into<String>) -> Realm {
        Realm::build(RealmKey {
            name: name.into(),
            incarnation: Some(incarnation.into()),
        })
    }

    fn build(key: RealmKey) -> Realm {
        Realm {
            inner: Arc::new(RealmInner {
                key,
                snapshot: RwLock::new(None),
                refresh_gate: tokio::sync::Mutex::new(()),
                refresh_epoch: AtomicU64::new(0),
                discoveries: AtomicU64::new(0),
                failures: Mutex::new(HashMap::new()),
                counts: Mutex::new(HashMap::new()),
                public_mode: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
            }),
        }
    }

    /// The realm used for a configuration without an explicit realm.
    ///
    /// Implicit realms are keyed by the complete trusted endpoint and TLS
    /// configuration (every seed host, address and port, the TLS mode and
    /// trust inputs and the endpoint policy), and their number is bounded.
    /// Services should pass an explicit realm with [`Config::realm`].
    pub(crate) fn for_config(config: &Config) -> Realm {
        let key = ImplicitKey(format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            config.host,
            config.hostaddr,
            config.port,
            config.ssl_mode,
            config.ssl_root_cert,
            config.ssl_cert,
            config.ssl_crl,
            config.endpoint_policy,
            config.dbname,
        ));
        let mut realms = IMPLICIT_REALMS.lock();
        if let Some((_, realm)) = realms.iter().find(|(k, _)| *k == key) {
            return realm.clone();
        }
        if realms.len() >= MAX_IMPLICIT_REALMS {
            realms.remove(0);
        }
        let realm = Realm::new(format!("implicit-{}", realms.len()));
        realms.push((key, realm.clone()));
        realm
    }

    /// The realm identity.
    pub fn key(&self) -> &RealmKey {
        &self.inner.key
    }

    /// Stops new acquisitions through this realm. Established connections
    /// are unaffected; nothing runs in the background, so nothing needs to
    /// be joined.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }

    /// Whether [`shutdown`](Self::shutdown) was called.
    pub fn is_shut_down(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    /// The current topology snapshot, if any.
    pub fn topology(&self) -> Option<TopologyInfo> {
        self.inner.snapshot.read().as_ref().map(|t| TopologyInfo {
            nodes: t.nodes.values().cloned().collect(),
            age: t.fetched_at.elapsed(),
        })
    }

    /// Forces the next acquisition to refresh the topology.
    pub fn invalidate_topology(&self) {
        *self.inner.snapshot.write() = None;
    }

    /// Live connections and in-flight attempts per canonical node identity.
    pub fn connection_counts(&self) -> BTreeMap<String, usize> {
        self.inner
            .counts
            .lock()
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Nodes currently quarantined after transport failures.
    pub fn failed_nodes(&self) -> Vec<String> {
        let mut nodes: Vec<String> = self.inner.failures.lock().keys().cloned().collect();
        nodes.sort();
        nodes
    }

    /// Number of `yb_servers()` queries this realm has executed.
    pub fn discovery_count(&self) -> u64 {
        self.inner.discoveries.load(Ordering::SeqCst)
    }

    fn reserve(&self, identity: &str) -> NodeLease {
        *self
            .inner
            .counts
            .lock()
            .entry(identity.to_string())
            .or_insert(0) += 1;
        NodeLease {
            realm: self.inner.clone(),
            identity: identity.to_string(),
        }
    }

    fn mark_failed(&self, identity: &str) {
        info!("Quarantining {} after a transport failure", endpoint::label(identity));
        self.inner
            .failures
            .lock()
            .insert(identity.to_string(), Instant::now());
    }

    fn failures(&self, delay: Duration) -> HashMap<String, Instant> {
        let mut failures = self.inner.failures.lock();
        failures.retain(|_, at| at.elapsed() <= delay);
        failures.clone()
    }

    /// Acquires a load-balanced connection within this realm.
    pub(crate) async fn connect<T>(
        &self,
        tls: &mut T,
        config: &Config,
    ) -> Result<(Client, Connection<Socket, T::Stream>), Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        if self.is_shut_down() {
            return Err(Error::connect(io::Error::new(
                io::ErrorKind::NotConnected,
                "the realm has been shut down",
            )));
        }
        let deadline = Instant::now() + config.yb_acquire_timeout;
        let budget_error = || {
            Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "no connection was acquired within the {:?} acquisition budget",
                    config.yb_acquire_timeout
                ),
            ))
        };

        let topology = match self.current_topology(tls, config, deadline).await {
            Ok(topology) => Some(topology),
            Err(e) => {
                if e.is_security_failure() || !allows_unbalanced_fallback(config) {
                    return Err(e);
                }
                warn!(
                    "Topology unavailable: {}. Falling back to the configured host(s) {} of the same realm",
                    error_chain(&e),
                    seeds_label(config)
                );
                None
            }
        };

        let mut last_error = None;
        if let Some(topology) = &topology {
            let failures = self.failures(config.failed_host_reconnect_delay_secs);
            let counts = self.inner.counts.lock().clone();
            match plan(config, topology, &failures, &counts) {
                Ok(candidates) => {
                    for identity in candidates.into_iter().take(config.yb_max_attempts) {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(last_error.unwrap_or_else(budget_error));
                        }
                        let node = &topology.nodes[&identity];
                        let mut target = match resolve_node(config, &identity, node.port) {
                            Some(target) => target,
                            None => continue,
                        };
                        if public_ip_mode_allowed(config)
                            && self.inner.public_mode.load(Ordering::SeqCst)
                        {
                            match &node.public_ip {
                                Some(public) => {
                                    target.dial = public.clone();
                                    target.tls_name = public.clone();
                                }
                                None => continue,
                            }
                        }
                        let label = endpoint::label(&identity);
                        info!("Creating connection to {}", label);
                        let lease = self.reserve(&identity);
                        let attempt = connect_host(
                            Host::Tcp(target.dial.clone()),
                            Some(target.tls_name.clone()),
                            target.port,
                            tls,
                            config,
                            Some(identity.clone()),
                        );
                        let limit = cmp::min(config.yb_attempt_timeout, remaining);
                        let outcome = match time::timeout(limit, attempt).await {
                            Ok(outcome) => outcome,
                            Err(_) => Err(Error::connect(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("connection attempt to {} exceeded {:?}", label, limit),
                            ))),
                        };
                        match outcome {
                            Ok((mut client, connection)) => {
                                client.set_lease(Box::new(lease));
                                return Ok((client, connection));
                            }
                            Err(e) => {
                                drop(lease);
                                match classify(&e) {
                                    AttemptFailure::Terminal => {
                                        warn!(
                                            "Connection to {} failed terminally: {}",
                                            label,
                                            error_chain(&e)
                                        );
                                        return Err(e);
                                    }
                                    AttemptFailure::Busy => {
                                        info!("{} is busy: {}, trying another node", label, error_chain(&e));
                                    }
                                    AttemptFailure::Transport => {
                                        info!(
                                            "Connection to {} failed: {}, trying another node",
                                            label,
                                            error_chain(&e)
                                        );
                                        self.mark_failed(&identity);
                                    }
                                }
                                last_error = Some(e);
                            }
                        }
                    }
                }
                Err(e) => last_error = Some(e),
            }
        }

        if !allows_unbalanced_fallback(config) {
            return Err(last_error.unwrap_or_else(budget_error));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(last_error.unwrap_or_else(budget_error));
        }
        if let Some(e) = &last_error {
            warn!(
                "No eligible discovered node accepted a connection ({}). Falling back to the \
                 configured host(s) {} of the same realm",
                error_chain(e),
                seeds_label(config)
            );
        }
        let attempt = cmp::min(config.yb_attempt_timeout, remaining);
        match time::timeout(remaining, connect_with_tls_ref(tls, config, Some(attempt))).await {
            Ok(Ok((mut client, connection))) => {
                let identity = self.seed_identity(&client, topology.as_deref());
                if let Some(identity) = identity {
                    client.set_lease(Box::new(self.reserve(&identity)));
                }
                Ok((client, connection))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(budget_error()),
        }
    }

    /// Accounts a seed connection against the discovered identity of the
    /// same endpoint when the snapshot knows it, so one node never has two
    /// accounting keys.
    fn seed_identity(&self, client: &Client, topology: Option<&Topology>) -> Option<String> {
        let socket = client.get_socket_config()?;
        let seed = socket.node.clone()?;
        let dial = match &socket.addr {
            crate::client::Addr::Tcp(ip) => ip.to_string(),
            #[cfg(unix)]
            crate::client::Addr::Unix(_) => return Some(seed),
        };
        if let Some(topology) = topology {
            for node in topology.nodes.values() {
                if node.port == socket.port && (node.identity == dial || node.identity == seed) {
                    return Some(node.identity.clone());
                }
            }
        }
        Some(seed)
    }

    async fn current_topology<T>(
        &self,
        tls: &mut T,
        config: &Config,
        deadline: Instant,
    ) -> Result<Arc<Topology>, Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        let fresh = |t: &Arc<Topology>| t.fetched_at.elapsed() <= config.yb_servers_refresh_interval;
        let snapshot = self.inner.snapshot.read().clone();
        if let Some(topology) = &snapshot {
            if fresh(topology) && config.yb_servers_refresh_interval > Duration::ZERO {
                return Ok(topology.clone());
            }
        }
        let epoch = self.inner.refresh_epoch.load(Ordering::SeqCst);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _gate = match time::timeout(remaining, self.inner.refresh_gate.lock()).await {
            Ok(gate) => gate,
            Err(_) => {
                return self.stale_or(
                    snapshot,
                    config,
                    Error::connect(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for a topology refresh in progress",
                    )),
                )
            }
        };
        // Coalesce: another caller refreshed while this one waited.
        if self.inner.refresh_epoch.load(Ordering::SeqCst) != epoch {
            if let Some(topology) = self.inner.snapshot.read().clone() {
                return Ok(topology);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let discovered = time::timeout(remaining, self.discover(tls, config, snapshot.as_deref(), deadline)).await;
        match discovered {
            Ok(Ok(topology)) => {
                let topology = Arc::new(topology);
                {
                    let mut failures = self.inner.failures.lock();
                    failures.retain(|identity, _| topology.nodes.contains_key(identity));
                }
                *self.inner.snapshot.write() = Some(topology.clone());
                self.inner.refresh_epoch.fetch_add(1, Ordering::SeqCst);
                Ok(topology)
            }
            Ok(Err(e)) if e.is_security_failure() => Err(e),
            Ok(Err(e)) => self.stale_or(snapshot, config, e),
            Err(_) => self.stale_or(
                snapshot,
                config,
                Error::connect(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "topology discovery exceeded the acquisition budget",
                )),
            ),
        }
    }

    fn stale_or(
        &self,
        snapshot: Option<Arc<Topology>>,
        config: &Config,
        error: Error,
    ) -> Result<Arc<Topology>, Error> {
        match snapshot {
            Some(topology) if topology.fetched_at.elapsed() <= config.yb_topology_max_staleness => {
                warn!(
                    "Topology refresh failed ({}); using the snapshot from {:?} ago",
                    error_chain(&error),
                    topology.fetched_at.elapsed()
                );
                Ok(topology)
            }
            Some(_) => {
                warn!("Topology refresh failed and the last snapshot exceeds the maximum staleness; discarding it");
                *self.inner.snapshot.write() = None;
                Err(error)
            }
            None => Err(error),
        }
    }

    async fn discover<T>(
        &self,
        tls: &mut T,
        config: &Config,
        previous: Option<&Topology>,
        deadline: Instant,
    ) -> Result<Topology, Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        let control = control_connection_config(config);
        let attempt = cmp::min(LOGIN_TIMEOUT, deadline.saturating_duration_since(Instant::now()));
        let mut last = match connect_with_tls_ref(tls, &control, Some(attempt)).await {
            Ok((client, connection)) => {
                info!("Control connection created to one of the configured host(s) {}", seeds_label(config));
                match self.query_topology(client, connection, config).await {
                    Ok(topology) => return Ok(topology),
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        if last.is_security_failure() {
            return Err(last);
        }
        info!(
            "Discovery through the configured host(s) {} failed: {}; trying known nodes",
            seeds_label(config),
            error_chain(&last)
        );
        let failures = self.failures(config.failed_host_reconnect_delay_secs);
        if let Some(previous) = previous {
            for node in previous.nodes.values() {
                if failures.contains_key(&node.identity) {
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let target = match resolve_node(config, &node.identity, node.port) {
                    Some(target) => target,
                    None => continue,
                };
                let label = endpoint::label(&node.identity);
                let attempt = time::timeout(
                    cmp::min(LOGIN_TIMEOUT, remaining),
                    connect_host(
                        Host::Tcp(target.dial.clone()),
                        Some(target.tls_name.clone()),
                        target.port,
                        tls,
                        &control,
                        Some(node.identity.clone()),
                    ),
                )
                .await;
                match attempt {
                    Ok(Ok((client, connection))) => {
                        info!("Control connection created to {}", label);
                        match self.query_topology(client, connection, config).await {
                            Ok(topology) => return Ok(topology),
                            Err(e) if e.is_security_failure() => return Err(e),
                            Err(e) => last = e,
                        }
                    }
                    Ok(Err(e)) if e.is_security_failure() => return Err(e),
                    Ok(Err(e)) => {
                        self.mark_failed(&node.identity);
                        last = e;
                    }
                    Err(_) => {
                        self.mark_failed(&node.identity);
                        last = Error::connect(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("control connection to {} timed out", label),
                        ));
                    }
                }
            }
        }
        Err(last)
    }

    async fn query_topology<S>(
        &self,
        client: Client,
        mut connection: Connection<Socket, S>,
        config: &Config,
    ) -> Result<Topology, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let control_host = client
            .get_socket_config()
            .and_then(|c| c.hostname)
            .unwrap_or_default();
        self.inner.discoveries.fetch_add(1, Ordering::SeqCst);
        let rows = {
            let query = client.query("select * from yb_servers()", &[]);
            pin_mut!(query);
            time::timeout(
                QUERY_TIMEOUT,
                future::poll_fn(|cx| {
                    if connection.poll_unpin(cx)?.is_ready() {
                        return Poll::Ready(Err(Error::closed()));
                    }
                    query.as_mut().poll(cx)
                }),
            )
            .await
            .map_err(|_| {
                Error::connect(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("`select * from yb_servers()` did not complete within {:?}", QUERY_TIMEOUT),
                ))
            })??
        };
        drop(client);
        let _ = time::timeout(CONTROL_CONN_CLOSE_TIMEOUT, connection).await;

        let mut nodes = BTreeMap::new();
        for row in rows {
            let host: String = row.try_get("host")?;
            let port: i64 = row.try_get("port")?;
            let node_type: String = row.try_get("node_type")?;
            let cloud: String = row.try_get("cloud")?;
            let region: String = row.try_get("region")?;
            let zone: String = row.try_get("zone")?;
            let public_ip: Option<String> = row.try_get("public_ip")?;
            let label = endpoint::label(&host);
            if host.is_empty() || !(1..=65535).contains(&port) {
                return Err(invalid_topology("an entry has an empty host or an invalid port"));
            }
            let role = match node_type.as_str() {
                "primary" => NodeRole::Primary,
                "read_replica" => NodeRole::ReadReplica,
                _ => {
                    warn!("Ignoring {} with unsupported node_type", label);
                    continue;
                }
            };
            let public_ip = public_ip.filter(|p| !p.is_empty());
            if let Some(public) = &public_ip {
                if !control_host.is_empty() && control_host.eq_ignore_ascii_case(public) {
                    if public_ip_mode_allowed(config) {
                        self.inner.public_mode.store(true, Ordering::SeqCst);
                    } else {
                        warn!(
                            "The control connection reached a node by its public address; public/private \
                             address switching is not supported with verify-full or an endpoint policy"
                        );
                    }
                }
            }
            let info = NodeInfo {
                identity: host.clone(),
                port: port as u16,
                role,
                cloud,
                region,
                zone,
                public_ip,
            };
            debug!("Discovered {} as {:?} in {}", label, role, info.placement());
            if nodes.insert(host, info).is_some() {
                return Err(invalid_topology("an identity appears more than once"));
            }
        }
        if nodes.is_empty() {
            return Err(invalid_topology("no usable nodes"));
        }
        Ok(Topology {
            nodes,
            fetched_at: Instant::now(),
        })
    }
}

fn invalid_topology(reason: &str) -> Error {
    Error::connect(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("rejected yb_servers() snapshot: {}", reason),
    ))
}

/// Accounts one connection (or in-flight attempt) against a node. Dropping
/// the lease releases the count, on success, error, cancellation or close.
struct NodeLease {
    realm: Arc<RealmInner>,
    identity: String,
}

impl Drop for NodeLease {
    fn drop(&mut self) {
        let mut counts = self.realm.counts.lock();
        if let Some(count) = counts.get_mut(&self.identity) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.identity);
            }
        }
    }
}

enum AttemptFailure {
    /// Security, authorization or configuration: never retried elsewhere.
    Terminal,
    /// The node refused new sessions for now; another node may be tried
    /// without quarantining this one.
    Busy,
    /// Network-level failure: quarantine the node and try another.
    Transport,
}

fn classify(e: &Error) -> AttemptFailure {
    if e.is_security_failure() {
        return AttemptFailure::Terminal;
    }
    match e.code().map(|c| c.code()) {
        Some("53300") | Some("57P03") | Some("53400") => AttemptFailure::Busy,
        Some(_) => AttemptFailure::Terminal,
        None => AttemptFailure::Transport,
    }
}

/// Orders the eligible candidates of a snapshot.
pub(crate) fn plan(
    config: &Config,
    topology: &Topology,
    failures: &HashMap<String, Instant>,
    counts: &HashMap<String, usize>,
) -> Result<Vec<String>, Error> {
    use NodeRole::{Primary, ReadReplica};
    const PRIMARY: &[NodeRole] = &[Primary];
    const REPLICA: &[NodeRole] = &[ReadReplica];
    const ANY: &[NodeRole] = &[Primary, ReadReplica];
    let role_tiers: Vec<&[NodeRole]> = match config.load_balance.as_str() {
        "only-primary" => vec![PRIMARY],
        "only-rr" => vec![REPLICA],
        "prefer-primary" => vec![PRIMARY, REPLICA],
        "prefer-rr" => vec![REPLICA, PRIMARY],
        _ => vec![ANY],
    };
    let mut priorities: Vec<&i64> = config.topology_keys.keys().collect();
    priorities.sort();
    let mut placement_tiers: Vec<Option<&Vec<String>>> =
        priorities.into_iter().map(|p| config.topology_keys.get(p)).collect();
    let strict_placement = !placement_tiers.is_empty() && config.fallback_to_topology_keys_only;
    if !strict_placement {
        placement_tiers.push(None);
    }

    // 1. Admission and 2. hard eligibility.
    let eligible: Vec<&NodeInfo> = topology
        .nodes
        .values()
        .filter(|node| resolve_node(config, &node.identity, node.port).is_some())
        .filter(|node| role_tiers.iter().any(|roles| roles.contains(&node.role)))
        .filter(|node| {
            !strict_placement
                || placement_tiers
                    .iter()
                    .flatten()
                    .any(|patterns| patterns.iter().any(|p| node.matches(p)))
        })
        .collect();
    let available: Vec<&NodeInfo> = eligible
        .iter()
        .copied()
        .filter(|node| !failures.contains_key(&node.identity))
        .collect();

    // 3. Preference tiers and 4. load within each tier.
    let mut ordered: Vec<String> = Vec::new();
    let mut rng = rand::thread_rng();
    for roles in &role_tiers {
        for placement in &placement_tiers {
            let mut tier: Vec<&NodeInfo> = available
                .iter()
                .copied()
                .filter(|node| roles.contains(&node.role))
                .filter(|node| match placement {
                    Some(patterns) => patterns.iter().any(|p| node.matches(p)),
                    None => true,
                })
                .filter(|node| !ordered.contains(&node.identity))
                .collect();
            tier.shuffle(&mut rng);
            tier.sort_by_key(|node| counts.get(&node.identity).copied().unwrap_or(0));
            ordered.extend(tier.into_iter().map(|node| node.identity.clone()));
        }
    }
    if ordered.is_empty() {
        let reason = if eligible.is_empty() {
            "no discovered node is admitted and eligible under the configured role and placement policy"
        } else {
            "every eligible node is quarantined after recent failures"
        };
        return Err(Error::connect(io::Error::new(io::ErrorKind::ConnectionRefused, reason)));
    }
    Ok(ordered)
}
