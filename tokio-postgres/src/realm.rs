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
    all_seed_aliases, allows_unbalanced_fallback, connect_host, connect_with_tls_ref,
    control_connection_config, error_chain, public_ip_mode_allowed, record_failure, resolve_node,
    seeds_label, HostAttempt, SeedPass, Seeds, BACKSTOP_GRACE,
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
use std::collections::{BTreeMap, HashMap, HashSet};
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
///
/// Its `Debug` output shows the identity and public IP only as keyed
/// [`endpoint::label`](crate::endpoint::label)s.
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeInfo")
            .field("identity", &crate::endpoint::label(&self.identity))
            .field("port", &self.port)
            .field("role", &self.role)
            .field("placement", &self.placement())
            .field(
                "public_ip",
                &self.public_ip.as_deref().map(crate::endpoint::label),
            )
            .finish()
    }
}

/// A complete, validated `yb_servers()` result.
#[derive(Debug)]
pub(crate) struct Topology {
    nodes: BTreeMap<String, NodeInfo>,
    fetched_at: Instant,
    epoch: u64,
}

/// A read-only view of a realm's current topology snapshot.
#[derive(Debug, Clone)]
pub struct TopologyInfo {
    nodes: Vec<NodeInfo>,
    age: Duration,
    epoch: u64,
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

    /// The realm's [`topology_epoch`](Realm::topology_epoch) when this
    /// snapshot was read.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The endpoint a connection reached and the selection policy it was made
/// under, classified against each new snapshot.
#[derive(Clone)]
pub(crate) struct Placement {
    pub(crate) realm: Realm,
    pub(crate) config: Arc<Config>,
    /// Candidate identities: the canonical node, and for a seed fallback
    /// also the configured seed name and dialed address.
    pub(crate) identities: Vec<String>,
    pub(crate) port: u16,
    /// A seed fallback that matches no listed endpoint is unclassified,
    /// not departed.
    pub(crate) seed: bool,
}

impl Placement {
    pub(crate) fn standing(&self) -> NodeStanding {
        self.realm.standing_of(self)
    }
}

/// Where a connected node stands under a configuration's role and placement
/// policy in its realm's current snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeStanding {
    /// In the best preference tier that has an available node.
    Preferred,
    /// Eligible, but a better preference tier has an available node again.
    Fallback,
    /// No longer listed in the topology. The node may still serve its
    /// sessions (for example while it drains), so callers can keep using
    /// them until replacements are established.
    Departed,
    /// Listed, but excluded by endpoint admission, role or strict placement.
    Ineligible,
    /// Load balancing is off, the realm has no snapshot, or the connection
    /// has no node identity.
    Unknown,
}

struct RealmInner {
    key: RealmKey,
    snapshot: RwLock<Option<Arc<Topology>>>,
    refresh_gate: tokio::sync::Mutex<()>,
    refresh_epoch: AtomicU64,
    change_epoch: AtomicU64,
    attempt_epoch: AtomicU64,
    last_failure: Mutex<Option<String>>,
    discoveries: AtomicU64,
    failures: Mutex<HashMap<String, Instant>>,
    /// Lower-case identity -> (when, penalty event); the identities of one
    /// endpoint share the event number.
    penalties: Mutex<HashMap<String, (Instant, u64)>>,
    penalty_events: AtomicU64,
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
                change_epoch: AtomicU64::new(0),
                attempt_epoch: AtomicU64::new(0),
                last_failure: Mutex::new(None),
                discoveries: AtomicU64::new(0),
                failures: Mutex::new(HashMap::new()),
                penalties: Mutex::new(HashMap::new()),
                penalty_events: AtomicU64::new(0),
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
            config.endpoint_policy.as_deref().map(|p| p.key_material()),
            config.dbname,
        ));
        let mut realms = IMPLICIT_REALMS.lock();
        if let Some((_, realm)) = realms.iter().find(|(k, _)| *k == key) {
            return realm.clone();
        }
        if realms.len() >= MAX_IMPLICIT_REALMS {
            // Reclaim the oldest realm nobody uses: leases and in-flight
            // acquisitions hold references, so an active realm is never
            // evicted (and duplicated). If every realm is active, grow.
            if let Some(index) = realms
                .iter()
                .position(|(_, realm)| Arc::strong_count(&realm.inner) == 1)
            {
                realms.remove(index);
            } else {
                warn!("More than {} implicit realms are active; pass explicit realms with Config::realm", MAX_IMPLICIT_REALMS);
            }
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
        self.inner.snapshot.read().as_ref().map(|t| self.info(t))
    }

    fn info(&self, topology: &Topology) -> TopologyInfo {
        TopologyInfo {
            nodes: topology.nodes.values().cloned().collect(),
            age: topology.fetched_at.elapsed(),
            epoch: topology.epoch,
        }
    }

    /// Number of refreshes whose snapshot differed in nodes or metadata
    /// from the one it replaced (including the first snapshot, and a
    /// snapshot after one was discarded). A snapshot carries the value from
    /// when it was installed ([`TopologyInfo::epoch`]).
    pub fn topology_epoch(&self) -> u64 {
        self.inner.change_epoch.load(Ordering::SeqCst)
    }

    fn standing_of(&self, placement: &Placement) -> NodeStanding {
        let config = &placement.config;
        if config.load_balance == "false" {
            return NodeStanding::Unknown;
        }
        let topology = match self.inner.snapshot.read().clone() {
            Some(topology) => topology,
            None => return NodeStanding::Unknown,
        };
        let listed = placement.identities.iter().find(|identity| {
            topology
                .nodes
                .get(identity.as_str())
                .is_some_and(|node| node.port == placement.port)
        });
        match listed {
            Some(identity) => {
                let failures = self.failures_within(config.failed_host_reconnect_delay_secs);
                let public_only =
                    public_ip_mode_allowed(config) && self.inner.public_mode.load(Ordering::SeqCst);
                standing_in(config, &topology, &failures, identity, public_only)
            }
            None if placement.seed => NodeStanding::Unknown,
            None => NodeStanding::Departed,
        }
    }

    /// Where `identity` stands under `config`'s selection policy in the
    /// current snapshot. Reads local state only.
    pub fn standing(&self, config: &Config, identity: &str) -> NodeStanding {
        if config.load_balance == "false" {
            return NodeStanding::Unknown;
        }
        let topology = match self.inner.snapshot.read().clone() {
            Some(topology) => topology,
            None => return NodeStanding::Unknown,
        };
        let failures = self.failures_within(config.failed_host_reconnect_delay_secs);
        let public_only =
            public_ip_mode_allowed(config) && self.inner.public_mode.load(Ordering::SeqCst);
        standing_in(config, &topology, &failures, identity, public_only)
    }

    /// Refreshes the snapshot if it is older than
    /// [`Config::yb_servers_refresh_interval`], within
    /// [`Config::yb_acquire_timeout`], with the same coalescing and staleness
    /// rules as an acquisition. Lets an idle pool notice topology changes
    /// without opening a connection.
    pub async fn refresh<T>(&self, mut tls: T, config: &Config) -> Result<TopologyInfo, Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        if self.is_shut_down() {
            return Err(Error::connect(io::Error::new(
                io::ErrorKind::NotConnected,
                "the realm has been shut down",
            )));
        }
        let deadline = deadline_after(config.yb_acquire_timeout);
        let topology = self.current_topology(&mut tls, config, deadline).await?;
        Ok(self.info(&topology))
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

    /// Nodes quarantined under `config`'s reconnect delay, sorted.
    pub fn quarantined(&self, config: &Config) -> Vec<String> {
        let mut nodes: Vec<String> = self
            .failures_within(config.failed_host_reconnect_delay_secs)
            .into_keys()
            .collect();
        nodes.sort();
        nodes
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

    /// Identities (in lower case) penalised after a node-scoped TLS or
    /// server failure, with the most recent penalty of each.
    ///
    /// A penalised node is not quarantined: it stays eligible, but is tried
    /// only after every other candidate until the penalty expires under the
    /// `failed_host_reconnect_delay_secs` of the configuration connecting.
    pub fn penalized_nodes(&self) -> Vec<String> {
        let mut nodes: Vec<String> = self.inner.penalties.lock().keys().cloned().collect();
        nodes.sort();
        nodes
    }

    /// Number of node-scoped failures that penalised a node in this realm.
    pub fn penalty_count(&self) -> u64 {
        self.inner.penalty_events.load(Ordering::SeqCst)
    }

    fn penalize(&self, identity: &str) {
        self.penalize_aliases(&[identity.to_string()]);
    }

    /// Penalises one failed endpoint under every identity it may be listed
    /// under, counting one event. Identities are kept in lower case, as
    /// host names match case-insensitively (`resolve_node`).
    fn penalize_aliases(&self, aliases: &[String]) {
        if aliases.is_empty() {
            return;
        }
        let event = self.inner.penalty_events.fetch_add(1, Ordering::SeqCst) + 1;
        let now = Instant::now();
        let mut penalties = self.inner.penalties.lock();
        for alias in aliases {
            penalties.insert(alias.to_ascii_lowercase(), (now, event));
        }
    }

    /// Lower-case identities penalised within `delay` together with one of
    /// `config`'s seeds, such as the address a seed name resolved to.
    fn seed_endpoints(&self, config: &Config, delay: Duration) -> HashSet<String> {
        let penalties = self.inner.penalties.lock();
        let events: HashSet<u64> = all_seed_aliases(config)
            .iter()
            .flatten()
            .filter_map(|alias| penalties.get(&alias.to_ascii_lowercase()))
            .filter(|(at, _)| at.elapsed() <= delay)
            .map(|(_, event)| *event)
            .collect();
        penalties
            .iter()
            .filter(|(_, (at, event))| at.elapsed() <= delay && events.contains(event))
            .map(|(identity, _)| identity.clone())
            .collect()
    }

    /// Penalties within `delay`, keyed by lower-case identity
    /// ([`is_penalized`]). The shared map is not pruned by one caller's
    /// delay (other configurations of the realm may use a longer one); a
    /// penalty older than every delay is replaced on the next failure.
    fn penalties(&self, delay: Duration) -> HashMap<String, Instant> {
        self.inner
            .penalties
            .lock()
            .iter()
            .filter(|(_, (at, _))| at.elapsed() <= delay)
            .map(|(k, (at, _))| (k.clone(), *at))
            .collect()
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

    /// Failures within `delay`, without pruning the shared map (other
    /// configurations of the realm may use a longer delay).
    fn failures_within(&self, delay: Duration) -> HashMap<String, Instant> {
        self.inner
            .failures
            .lock()
            .iter()
            .filter(|(_, at)| at.elapsed() <= delay)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
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
        let deadline = deadline_after(config.yb_acquire_timeout);
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
        // The first node-scoped security failure is what the caller sees if
        // no candidate succeeds; it is never replaced by a later error.
        let mut security_error = None;
        if let Some(topology) = &topology {
            let failures = self.failures(config.failed_host_reconnect_delay_secs);
            let counts = self.inner.counts.lock().clone();
            match plan(config, topology, &failures, &counts) {
                Ok(mut candidates) => {
                    // Penalised nodes stay eligible but go last (stable sort).
                    let penalties = self.penalties(config.failed_host_reconnect_delay_secs);
                    candidates.sort_by_key(|identity| is_penalized(&penalties, identity));
                    for identity in candidates.into_iter().take(config.yb_max_attempts) {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(security_error.or(last_error).unwrap_or_else(budget_error));
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
                        let limit = cmp::min(config.yb_attempt_timeout, remaining);
                        // Bounded by `limit` itself, so a TLS error of an
                        // earlier resolved address is not lost to a timeout.
                        let outcome = connect_host(
                            Host::Tcp(target.dial.clone()),
                            Some(target.tls_name.clone()),
                            target.port,
                            tls,
                            config,
                            Some(identity.clone()),
                            &mut HostAttempt::bounded(Some(limit)),
                        )
                        .await;
                        match outcome {
                            Ok((mut client, connection)) => {
                                client.set_lease(Box::new(lease));
                                client.set_placement(Placement {
                                    realm: self.clone(),
                                    config: Arc::new(config.clone()),
                                    identities: vec![identity.clone()],
                                    port: node.port,
                                    seed: false,
                                });
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
                                    AttemptFailure::Penalized => {
                                        warn!(
                                            "Connection to {} failed: {}; penalising the node and trying \
                                             another admitted node under the same verification",
                                            label,
                                            error_chain(&e)
                                        );
                                        self.penalize(&identity);
                                        if e.is_security_failure() {
                                            security_error.get_or_insert(e);
                                            continue;
                                        }
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

        // A security failure is never followed by a fallback that could hide it.
        if let Some(e) = security_error {
            return Err(e);
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
        let penalties = self.penalties(config.failed_host_reconnect_delay_secs);
        let mut pass = SeedPass::new(Some(attempt))
            .deadline(deadline)
            .deferring(penalties.into_keys().collect());
        let outcome = time::timeout(
            remaining.saturating_add(BACKSTOP_GRACE),
            connect_with_tls_ref(tls, config, &mut pass),
        )
        .await;
        self.penalize_seeds(&pass);
        match outcome {
            Ok(Ok((mut client, connection))) => {
                let identity = self.seed_identity(&client, topology.as_deref());
                if let Some(identity) = &identity {
                    client.set_lease(Box::new(self.reserve(identity)));
                }
                if let Some(socket) = client.get_socket_config() {
                    let mut identities: Vec<String> = identity.into_iter().collect();
                    identities.extend(socket.node.clone());
                    if let crate::client::Addr::Tcp(ip) = &socket.addr {
                        identities.push(ip.to_string());
                    }
                    identities.dedup();
                    client.set_placement(Placement {
                        realm: self.clone(),
                        config: Arc::new(config.clone()),
                        identities,
                        port: socket.port,
                        seed: true,
                    });
                }
                Ok((client, connection))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(pass.take_reportable().unwrap_or_else(budget_error)),
        }
    }

    /// Penalises the seeds whose own endpoint failed in `pass`.
    fn penalize_seeds(&self, pass: &SeedPass) {
        for aliases in &pass.node_failures {
            if let Some(seed) = aliases.first() {
                warn!(
                    "Penalising configured host {} after a node-scoped failure",
                    endpoint::label(seed)
                );
            }
            self.penalize_aliases(aliases);
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
        let attempts = self.inner.attempt_epoch.load(Ordering::SeqCst);
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
        // Coalesce failures too: a refresh attempted while this caller
        // waited failed, so share its outcome instead of repeating it.
        if self.inner.attempt_epoch.load(Ordering::SeqCst) != attempts {
            let reason = self
                .inner
                .last_failure
                .lock()
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            return self.stale_or(
                self.inner.snapshot.read().clone(),
                config,
                Error::connect(io::Error::new(
                    io::ErrorKind::Other,
                    format!("a concurrent topology refresh failed: {}", reason),
                )),
            );
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        // AST-2133 hook: discovery (the control connections `discover` opens
        // and the `yb_servers()` exchange in `query_topology`) is attributed
        // to `Class::Discovery`, including control-socket bytes.
        let discovery = crate::observe::with_class(
            crate::observe::Class::Discovery,
            self.discover(tls, config, snapshot.as_deref(), deadline),
        );
        // Discovery bounds its own connection attempts by `deadline` and then
        // returns the error it recorded (for example a seed's TLS failure);
        // this timeout is only the backstop, so it fires a little later.
        let discovered = time::timeout(remaining.saturating_add(BACKSTOP_GRACE), discovery).await;
        match &discovered {
            Ok(Ok(_)) => *self.inner.last_failure.lock() = None,
            Ok(Err(e)) => *self.inner.last_failure.lock() = Some(error_chain(e)),
            Err(_) => {
                *self.inner.last_failure.lock() =
                    Some("discovery exceeded the acquisition budget".to_string())
            }
        }
        self.inner.attempt_epoch.fetch_add(1, Ordering::SeqCst);
        match discovered {
            Ok(Ok(topology)) => Ok(self.install(topology)),
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

    fn install(&self, mut topology: Topology) -> Arc<Topology> {
        {
            let mut failures = self.inner.failures.lock();
            failures.retain(|identity, _| topology.nodes.contains_key(identity));
        }
        let topology = {
            let mut current = self.inner.snapshot.write();
            topology.epoch = match current.as_ref() {
                Some(previous) if previous.nodes == topology.nodes => previous.epoch,
                _ => self.inner.change_epoch.fetch_add(1, Ordering::SeqCst) + 1,
            };
            let topology = Arc::new(topology);
            *current = Some(topology.clone());
            topology
        };
        self.inner.refresh_epoch.fetch_add(1, Ordering::SeqCst);
        topology
    }

    /// Whether the snapshot is missing or older than
    /// [`Config::yb_servers_refresh_interval`].
    pub fn refresh_due(&self, config: &Config) -> bool {
        match self.inner.snapshot.read().as_ref() {
            Some(topology) => !fresh_for(topology, config),
            None => true,
        }
    }

    /// Refreshes the snapshot by running `yb_servers()` on `client`, an
    /// established session of this realm, instead of opening a control
    /// connection. Returns the current snapshot when it is not due (or a
    /// refresh is in progress and it is within the maximum staleness), and
    /// the query's error otherwise; the snapshot is left as it was, so a
    /// caller can fall back to [`refresh`](Self::refresh).
    pub async fn refresh_with(&self, client: &Client, config: &Config) -> Result<TopologyInfo, Error> {
        if client.realm() != Some(self) {
            return Err(Error::config(
                "refresh_with needs a load-balanced session of this realm".into(),
            ));
        }
        let snapshot = self.inner.snapshot.read().clone();
        if let Some(topology) = &snapshot {
            if fresh_for(topology, config) {
                return Ok(self.info(topology));
            }
        }
        let _gate = match self.inner.refresh_gate.try_lock() {
            Ok(gate) => gate,
            Err(_) => {
                return match snapshot {
                    Some(topology)
                        if topology.fetched_at.elapsed() <= config.yb_topology_max_staleness =>
                    {
                        Ok(self.info(&topology))
                    }
                    _ => Err(Error::connect(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "a topology refresh is already in progress",
                    ))),
                }
            }
        };
        let control_host = client
            .get_socket_config()
            .and_then(|c| c.hostname)
            .unwrap_or_default();
        self.inner.discoveries.fetch_add(1, Ordering::SeqCst);
        let query = crate::observe::with_class(
            crate::observe::Class::Discovery,
            client.query("select * from pg_catalog.yb_servers()", &[]),
        );
        let outcome = match time::timeout(QUERY_TIMEOUT, query).await {
            Ok(Ok(rows)) => self.parse_topology(rows, &control_host, config),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "`select * from yb_servers()` did not complete within {:?}",
                    QUERY_TIMEOUT
                ),
            ))),
        };
        self.inner.attempt_epoch.fetch_add(1, Ordering::SeqCst);
        match outcome {
            Ok(topology) => {
                *self.inner.last_failure.lock() = None;
                Ok(self.info(&self.install(topology)))
            }
            Err(e) => {
                *self.inner.last_failure.lock() = Some(error_chain(&e));
                Err(e)
            }
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
        let attempt_bound = cmp::min(LOGIN_TIMEOUT, config.yb_attempt_timeout);
        let delay = config.failed_host_reconnect_delay_secs;
        // Order: seeds that are not penalised, then the other known nodes
        // (penalised ones last), then the penalised seeds. Without a previous
        // snapshot there are no known nodes: one pass over the seeds,
        // penalised ones last.
        let deferred: Vec<String> = self.penalties(delay).into_keys().collect();
        let seeds = all_seed_aliases(config);
        let penalised_seed = |aliases: &Vec<String>| {
            aliases
                .iter()
                .any(|alias| deferred.contains(&alias.to_ascii_lowercase()))
        };
        let (first, last_pass) = match previous {
            Some(_) => (
                seeds
                    .iter()
                    .any(|aliases| !penalised_seed(aliases))
                    .then(|| Seeds::Undeferred),
                seeds.iter().any(penalised_seed).then(|| Seeds::Deferred),
            ),
            None => (Some(Seeds::All), None),
        };
        let mut last = None;
        if let Some(select) = first {
            let seeded = self
                .discover_through_seeds(
                    tls,
                    &control,
                    config,
                    attempt_bound,
                    deadline,
                    &deferred,
                    select,
                )
                .await?;
            match seeded {
                Ok(topology) => return Ok(topology),
                Err(e) => record_failure(&mut last, e),
            }
        }
        let failures = self.failures(delay);
        if let Some(previous) = previous {
            // Including any penalty the seed pass just recorded.
            let penalties = self.penalties(delay);
            let seed_endpoints = self.seed_endpoints(config, delay);
            // Penalised nodes failed recently: try every other known node
            // first (stable sort).
            let mut known: Vec<&NodeInfo> = previous.nodes.values().collect();
            known.sort_by_key(|node| is_penalized(&penalties, &node.identity));
            for node in known {
                if failures.contains_key(&node.identity) {
                    continue;
                }
                // The seed passes cover the seeds, under any identity.
                if is_seed(config, &node.identity)
                    || seed_endpoints.contains(&node.identity.to_ascii_lowercase())
                {
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let mut target = match resolve_node(config, &node.identity, node.port) {
                    Some(target) => target,
                    None => continue,
                };
                if public_ip_mode_allowed(config) && self.inner.public_mode.load(Ordering::SeqCst) {
                    match &node.public_ip {
                        Some(public) => {
                            target.dial = public.clone();
                            target.tls_name = public.clone();
                        }
                        None => continue,
                    }
                }
                let label = endpoint::label(&node.identity);
                let attempt = connect_host(
                    Host::Tcp(target.dial.clone()),
                    Some(target.tls_name.clone()),
                    target.port,
                    tls,
                    &control,
                    Some(node.identity.clone()),
                    &mut HostAttempt::bounded(Some(cmp::min(attempt_bound, remaining))),
                )
                .await;
                match attempt {
                    Ok((client, connection)) => {
                        info!("Control connection created to {}", label);
                        match self.query_topology(client, connection, config).await {
                            Ok(topology) => return Ok(topology),
                            Err(e) if is_node_scoped_failure(&e) => {
                                warn!(
                                    "Topology query on {} failed: {}; penalising the node",
                                    label,
                                    error_chain(&e)
                                );
                                self.penalize(&node.identity);
                                record_failure(&mut last, e);
                            }
                            Err(e) if e.is_security_failure() => return Err(e),
                            Err(e) => record_failure(&mut last, e),
                        }
                    }
                    Err(e) if is_node_scoped_failure(&e) => {
                        warn!(
                            "Control connection to {} failed: {}; penalising the node",
                            label,
                            error_chain(&e)
                        );
                        self.penalize(&node.identity);
                        record_failure(&mut last, e);
                    }
                    Err(e) if e.is_security_failure() => return Err(e),
                    Err(e) => {
                        self.mark_failed(&node.identity);
                        record_failure(&mut last, e);
                    }
                }
            }
        }
        if let (Some(select), false) = (
            last_pass,
            deadline.saturating_duration_since(Instant::now()).is_zero(),
        ) {
            let seeded = self
                .discover_through_seeds(
                    tls,
                    &control,
                    config,
                    attempt_bound,
                    deadline,
                    &deferred,
                    select,
                )
                .await?;
            match seeded {
                Ok(topology) => return Ok(topology),
                Err(e) => record_failure(&mut last, e),
            }
        }
        Err(last.unwrap_or_else(|| {
            Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                "topology discovery exceeded the acquisition budget",
            ))
        }))
    }

    /// Discovery through a control connection to one of the `select`ed
    /// configured seeds, `deferred` (penalised) ones last. The outer `Err`
    /// ends discovery (a failure that is not node-scoped); the inner one lets
    /// the caller try the known nodes. A seed whose own endpoint failed is
    /// penalised.
    #[allow(clippy::too_many_arguments)]
    async fn discover_through_seeds<T>(
        &self,
        tls: &mut T,
        control: &Config,
        config: &Config,
        attempt_bound: Duration,
        deadline: Instant,
        deferred: &[String],
        select: Seeds,
    ) -> Result<Result<Topology, Error>, Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        let mut pass = SeedPass::new(Some(attempt_bound))
            .deadline(deadline)
            .deferring(deferred.to_vec())
            .select(select);
        let outcome = connect_with_tls_ref(tls, control, &mut pass).await;
        self.penalize_seeds(&pass);
        let e = match outcome {
            Ok((client, connection)) => {
                info!(
                    "Control connection created to one of the configured host(s) {}",
                    seeds_label(config)
                );
                // The identities the seed that served may be listed under.
                let mut aliases = Vec::new();
                if let Some(socket) = client.get_socket_config() {
                    aliases.extend(socket.node.clone());
                    if let crate::client::Addr::Tcp(ip) = &socket.addr {
                        aliases.push(ip.to_string());
                    }
                }
                match self.query_topology(client, connection, config).await {
                    Ok(topology) => return Ok(Ok(topology)),
                    Err(e) => {
                        if is_node_scoped_failure(&e) {
                            warn!(
                                "Topology query on one of the configured host(s) {} failed: {}; \
                                 penalising it",
                                seeds_label(config),
                                error_chain(&e)
                            );
                            self.penalize_aliases(&aliases);
                        }
                        // An earlier seed's TLS error still takes precedence.
                        record_failure(&mut pass.failure, e);
                        pass.take_failure()
                    }
                }
            }
            Err(e) => e,
        };
        // A node-scoped TLS failure of the seed(s) still lets the previously
        // known admitted nodes serve discovery; its error wins if none does.
        if e.is_security_failure() && !is_node_scoped_failure(&e) {
            return Err(e);
        }
        info!(
            "Discovery through the configured host(s) {} failed: {}",
            seeds_label(config),
            error_chain(&e)
        );
        Ok(Err(e))
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
            let query = discovery_rows(&client);
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
        self.parse_topology(rows, &control_host, config)
    }

    fn parse_topology(
        &self,
        rows: Vec<crate::Row>,
        control_host: &str,
        config: &Config,
    ) -> Result<Topology, Error> {
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
            if matches!(
                crate::connect::admit_node(config, &info.identity, info.port),
                Err(crate::connect::Refusal::PortMismatch)
            ) {
                warn!(
                    "Skipping {}: discovery reported port {}, which is not the trusted port for that node",
                    label, info.port
                );
            }
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
            epoch: 0,
        })
    }
}

/// Whether `identity` is penalised; `penalties` is keyed by lower case.
fn is_penalized(penalties: &HashMap<String, Instant>, identity: &str) -> bool {
    penalties.contains_key(&identity.to_ascii_lowercase())
}

fn fresh_for(topology: &Topology, config: &Config) -> bool {
    config.yb_servers_refresh_interval != Duration::ZERO
        && topology.fetched_at.elapsed() <= config.yb_servers_refresh_interval
}

/// `now + budget`, or a far-future instant when that overflows (a budget of
/// `Duration::MAX` set through the builder means "unbounded").
pub(crate) fn deadline_after(budget: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(budget)
        .or_else(|| now.checked_add(FAR_FUTURE))
        .unwrap_or(now)
}

/// About 30 years, as Tokio uses for an unbounded timer.
const FAR_FUTURE: Duration = Duration::from_secs(86400 * 365 * 30);

/// Whether a node identity is one of the configured seeds (by name or address).
fn is_seed(config: &Config, identity: &str) -> bool {
    config
        .host
        .iter()
        .any(|host| matches!(host, Host::Tcp(name) if name.eq_ignore_ascii_case(identity)))
        || config
            .hostaddr
            .iter()
            .any(|addr| addr.to_string() == identity)
}

fn invalid_topology(reason: &str) -> Error {
    Error::connect(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("rejected yb_servers() snapshot: {}", reason),
    ))
}

/// Runs the discovery query, refusing an answer with more rows, or longer
/// fields, than any real cluster reports, as it streams in.
async fn discovery_rows(client: &Client) -> Result<Vec<crate::Row>, Error> {
    use futures_util::TryStreamExt;

    /// Far more nodes than a YugabyteDB universe runs.
    const MAX_ROWS: usize = 4096;
    /// Host names are at most 253 bytes; placement names and UUIDs are short.
    const MAX_FIELD_LEN: usize = 1024;

    let rows = client
        .query_raw("select * from yb_servers()", crate::slice_iter(&[]))
        .await?;
    pin_mut!(rows);
    let mut collected = Vec::new();
    while let Some(row) = rows.try_next().await? {
        if collected.len() >= MAX_ROWS {
            return Err(invalid_topology("too many rows"));
        }
        if row.max_field_len() > MAX_FIELD_LEN {
            return Err(invalid_topology("a field is too long"));
        }
        collected.push(row);
    }
    Ok(collected)
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
    /// Credential, authorization or configuration: never retried elsewhere.
    Terminal,
    /// A failure attributable to the dialled node ([`is_node_scoped_failure`]):
    /// penalise the node and try another admitted node.
    Penalized,
    /// The node refused new sessions for now; another node may be tried
    /// without quarantining this one.
    Busy,
    /// Network-level failure: quarantine the node and try another.
    Transport,
}

fn classify(e: &Error) -> AttemptFailure {
    if is_node_scoped_failure(e) {
        return AttemptFailure::Penalized;
    }
    if e.is_security_failure() {
        return AttemptFailure::Terminal;
    }
    match e.code().map(|c| c.code()) {
        Some("53300") | Some("57P03") | Some("53400") => AttemptFailure::Busy,
        Some(_) => AttemptFailure::Terminal,
        None if e.is_transport() => AttemptFailure::Transport,
        None => AttemptFailure::Terminal,
    }
}

struct Policy<'a> {
    role_tiers: Vec<&'static [NodeRole]>,
    placement_tiers: Vec<Option<&'a Vec<String>>>,
    strict_placement: bool,
}

impl<'a> Policy<'a> {
    fn new(config: &'a Config) -> Policy<'a> {
        use NodeRole::{Primary, ReadReplica};
        const PRIMARY: &[NodeRole] = &[Primary];
        const REPLICA: &[NodeRole] = &[ReadReplica];
        const ANY: &[NodeRole] = &[Primary, ReadReplica];
        let role_tiers: Vec<&'static [NodeRole]> = match config.load_balance.as_str() {
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
        Policy {
            role_tiers,
            placement_tiers,
            strict_placement,
        }
    }

    /// Admission and hard role/placement eligibility.
    fn eligible(&self, config: &Config, node: &NodeInfo) -> bool {
        resolve_node(config, &node.identity, node.port).is_some()
            && self.role_tiers.iter().any(|roles| roles.contains(&node.role))
            && (!self.strict_placement
                || self
                    .placement_tiers
                    .iter()
                    .flatten()
                    .any(|patterns| patterns.iter().any(|p| node.matches(p))))
    }

    /// The first preference tier (role-major, then placement) containing
    /// `node`.
    fn tier(&self, node: &NodeInfo) -> Option<usize> {
        let width = self.placement_tiers.len();
        for (r, roles) in self.role_tiers.iter().enumerate() {
            if !roles.contains(&node.role) {
                continue;
            }
            for (p, placement) in self.placement_tiers.iter().enumerate() {
                let matches = match placement {
                    Some(patterns) => patterns.iter().any(|pattern| node.matches(pattern)),
                    None => true,
                };
                if matches {
                    return Some(r * width + p);
                }
            }
        }
        None
    }
}

pub(crate) fn standing_in(
    config: &Config,
    topology: &Topology,
    failures: &HashMap<String, Instant>,
    identity: &str,
    public_only: bool,
) -> NodeStanding {
    let policy = Policy::new(config);
    let node = match topology.nodes.get(identity) {
        Some(node) if policy.eligible(config, node) => node,
        Some(_) => return NodeStanding::Ineligible,
        None => return NodeStanding::Departed,
    };
    let own = match policy.tier(node) {
        Some(0) => return NodeStanding::Preferred,
        Some(tier) => tier,
        None => return NodeStanding::Ineligible,
    };
    let best = topology
        .nodes
        .values()
        .filter(|n| n.identity != identity && !failures.contains_key(&n.identity))
        .filter(|n| !public_only || n.public_ip.is_some())
        .filter(|n| policy.eligible(config, n))
        .filter_map(|n| policy.tier(n))
        .min();
    match best {
        Some(best) if best < own => NodeStanding::Fallback,
        _ => NodeStanding::Preferred,
    }
}

/// Whether a failure is attributable to the node that was dialled, so the
/// identical attempt against another admitted node of the same realm may
/// succeed.
///
/// TLS failures of the server's side of the handshake qualify: they happen
/// before any credential is sent, and every other node is verified exactly
/// the same way. So do server errors that report the node itself as
/// unhealthy. Failures that would repeat on every node stay terminal:
/// credentials and authorization (SQLSTATE class 28 and client-side
/// authentication rejections), a rejected or missing client certificate, the
/// client's own TLS configuration, a generic handshake failure that is local
/// or reported by a server alert (it may be rejecting the client
/// certificate), and every other SQLSTATE.
/// Continuing after those would present one bad credential to every node.
pub(crate) fn is_node_scoped_failure(e: &Error) -> bool {
    use crate::tls::TlsFailureKind as K;
    if let Some(code) = e.code() {
        // admin_shutdown, crash_shutdown, system_error, io_error, disk_full,
        // out_of_memory, internal_error.
        return matches!(
            code.code(),
            "57P01" | "57P02" | "58000" | "58030" | "53100" | "53200" | "XX000"
        );
    }
    matches!(
        e.tls_failure(),
        Some(K::ServerRefusedTls)
            | Some(K::UnknownIssuer)
            | Some(K::IdentityMismatch)
            | Some(K::Expired)
            | Some(K::NotYetValid)
            | Some(K::Revoked)
            | Some(K::InvalidCertificate)
            | Some(K::ProtocolVersion)
    ) || (e.tls_failure() == Some(K::HandshakeFailure) && e.tls_peer_fault())
}

/// Orders the eligible candidates of a snapshot.
pub(crate) fn plan(
    config: &Config,
    topology: &Topology,
    failures: &HashMap<String, Instant>,
    counts: &HashMap<String, usize>,
) -> Result<Vec<String>, Error> {
    let policy = Policy::new(config);

    // 1. Admission and 2. hard eligibility.
    let eligible: Vec<&NodeInfo> = topology
        .nodes
        .values()
        .filter(|node| policy.eligible(config, node))
        .collect();
    let available: Vec<&NodeInfo> = eligible
        .iter()
        .copied()
        .filter(|node| !failures.contains_key(&node.identity))
        .collect();

    // 3. Preference tiers and 4. load within each tier.
    let mut tiers: BTreeMap<usize, Vec<&NodeInfo>> = BTreeMap::new();
    for node in available {
        if let Some(tier) = policy.tier(node) {
            tiers.entry(tier).or_default().push(node);
        }
    }
    let mut ordered: Vec<String> = Vec::new();
    let mut rng = rand::thread_rng();
    for (_, mut tier) in tiers {
        tier.shuffle(&mut rng);
        tier.sort_by_key(|node| counts.get(&node.identity).copied().unwrap_or(0));
        ordered.extend(tier.into_iter().map(|node| node.identity.clone()));
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
