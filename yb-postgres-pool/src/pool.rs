//! The bb8 manager, the pool handle and the borrowed-client guard.

use crate::cache::{Lookup, StatementCache};
use crate::config::{HealthCheck, PoolConfig, QueueStrategy, SessionInit};
use crate::error::{is_stale_statement, ErrorKind, PoolError};
use crate::limiter::ConnectionLimiter;
use crate::stats::{add_duration, bump, PoolStats, Retire, Stats};
use crate::tls::PoolTls;
use crate::transaction::{PoolTransaction, TransactionOptions};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::task::AbortHandle;
use yb_tokio_postgres::realm::{NodeStanding, Realm};
use yb_tokio_postgres::types::{ToSql, Type};
use yb_tokio_postgres::{Client, Config, Row, Statement, TransactionStatus};

tokio::task_local! {
    static SWEEPING: ();
}

fn sweeping() -> bool {
    SWEEPING.try_with(|_| ()).is_ok()
}

/// One physical connection as bb8 stores it.
pub struct NativeConnection {
    pub(crate) client: Client,
    pub(crate) cache: StatementCache,
    pub(crate) stats: Arc<Stats>,
    terminal: Arc<Mutex<Option<PoolError>>>,
    task: AbortHandle,
    id: u64,
    generation: Option<u64>,
    created: Instant,
    idle_since: Instant,
    param_baseline: u64,
    retire: Option<Retire>,
}

impl fmt::Debug for NativeConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeConnection")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("age", &self.created.elapsed())
            .finish()
    }
}

impl Drop for NativeConnection {
    fn drop(&mut self) {
        self.stats.retired(self.retire);
        // Dropping the client (right after this) releases the driver's
        // per-node lease (AST-2129) and lets the connection task finish its
        // outstanding requests, terminate and close the socket, returning
        // its permits. A connection whose cleanup failed, or that still has
        // requests in flight, may never get those responses (a cancelled
        // query on a dead or stalled server): abort its task so the socket
        // and the permits are released now.
        if self.retire == Some(Retire::CleanupFailed) || self.client.pending_requests() > 0 {
            self.task.abort();
        }
    }
}

/// The pool-capacity and process-wide permits one physical connection
/// holds from just before it dials until its socket is closed.
struct Permits {
    _pool: OwnedSemaphorePermit,
    _process: OwnedSemaphorePermit,
}

fn reusable(client: &Client) -> bool {
    client.pending_caller_requests() == 0 && client.transaction_status() == TransactionStatus::Idle
}

/// Removes a connection from the live registry and returns its permits when
/// its task ends, completes or is aborted.
struct LiveGuard {
    live: Weak<Mutex<HashMap<u64, AbortHandle>>>,
    id: u64,
    _permits: Permits,
}

/// Counts an open (dial) in progress for as long as it runs.
struct Opening<'a>(&'a AtomicU64);

impl<'a> Opening<'a> {
    fn start(counter: &'a AtomicU64) -> Opening<'a> {
        counter.fetch_add(1, Ordering::SeqCst);
        Opening(counter)
    }
}

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Dialing<'a, T: PoolTls> {
    shared: &'a Shared<T>,
    id: u64,
}

impl<'a, T: PoolTls> Dialing<'a, T> {
    fn start(shared: &'a Shared<T>) -> Dialing<'a, T> {
        let id = shared.next_dial.fetch_add(1, Ordering::SeqCst);
        shared.dials.lock().insert(id, Instant::now());
        shared.limiter.dial_started();
        Dialing { shared, id }
    }
}

impl<T: PoolTls> Drop for Dialing<'_, T> {
    fn drop(&mut self) {
        self.shared.dials.lock().remove(&self.id);
        self.shared.limiter.dial_ended();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Occupancy {
    pub(crate) borrowed: u64,
    pub(crate) max_size: u32,
    pub(crate) permits_in_use: u32,
    pub(crate) permits_dialing: u32,
    pub(crate) permits_max: u32,
    pub(crate) oldest_dial: Option<Duration>,
    pub(crate) mean_connect: Option<Duration>,
    pub(crate) connect_errors: u64,
}

impl Occupancy {
    fn saturated(&self) -> bool {
        self.borrowed >= u64::from(self.max_size)
            || self.permits_in_use.saturating_sub(self.permits_dialing) >= self.permits_max
    }
}

impl fmt::Display for Occupancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of {} borrowed, {} of {} process permits in use ({} dialing), ",
            self.borrowed,
            self.max_size,
            self.permits_in_use,
            self.permits_max,
            self.permits_dialing
        )?;
        match self.oldest_dial {
            Some(age) => write!(f, "oldest own dial in flight for {:?}", age)?,
            None => f.write_str("no own dial in flight")?,
        }
        if let Some(mean) = self.mean_connect {
            write!(f, ", mean connect {:?}", mean)?;
        }
        Ok(())
    }
}

pub(crate) fn probe_timeout_kind(
    start: &Occupancy,
    end: &Occupancy,
    waited: Duration,
) -> ErrorKind {
    let threshold = end
        .mean_connect
        .map_or(waited / 2, |mean| (waited / 2).max(mean * 2));
    let stalled_dial = end.oldest_dial.is_some_and(|age| age >= threshold);
    let failed_dial = end.connect_errors > start.connect_errors;
    if stalled_dial || failed_dial || !(start.saturated() || end.saturated()) {
        ErrorKind::Transport
    } else {
        ErrorKind::AcquireTimeout
    }
}

fn probe_detail(kind: ErrorKind, start: &Occupancy, end: &Occupancy) -> String {
    let verdict = if kind == ErrorKind::AcquireTimeout {
        "pool saturated"
    } else {
        "pool not saturated or its connect path stalled"
    };
    format!(
        "probe: {} (wait began: {}; deadline: {})",
        verdict, start, end
    )
}

/// Counts a checkout in progress (activity for pool-set eviction).
struct Waiting<'a>(&'a AtomicU64);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        if let Some(live) = self.live.upgrade() {
            live.lock().remove(&self.id);
        }
    }
}

pub(crate) struct Shared<T: PoolTls> {
    pg: Config,
    tls: T,
    pub(crate) config: PoolConfig,
    init_sql: Option<String>,
    limiter: ConnectionLimiter,
    /// `max_size` permits, held per physical connection exactly like the
    /// process-wide ones, so physical connections (including dials in
    /// flight and sockets still closing) never exceed `max_size`, whoever
    /// opens them (bb8 or warm-floor maintenance).
    capacity: ConnectionLimiter,
    pub(crate) stats: Arc<Stats>,
    label: String,
    closed: AtomicBool,
    shutdown_signal: Notify,
    /// Dials in progress.
    opening: AtomicU64,
    dials: Mutex<HashMap<u64, Instant>>,
    next_dial: AtomicU64,
    /// Checkouts in progress.
    waiting: AtomicU64,
    /// Connect failures and shutdown wake waiters: a failed connect is
    /// final (the driver already spent its bounded acquisition budget, and
    /// security failures are terminal), so waiters get its error.
    fatal: Notify,
    fatal_seq: AtomicU64,
    connect_error_seq: AtomicU64,
    last_error: Mutex<Option<PoolError>>,
    last_fatal: Mutex<Option<PoolError>>,
    live: Arc<Mutex<HashMap<u64, AbortHandle>>>,
    next_id: AtomicU64,
    epoch: AtomicU64,
    borrowed: AtomicU64,
    released: Notify,
    last_activity: Mutex<Instant>,
    /// Serializes warm-floor top-ups so concurrent passes cannot overshoot.
    warm_lock: tokio::sync::Mutex<()>,
    /// The realm of load-balanced connections, if load balancing is on.
    realm: Option<Realm>,
    /// Connection tasks that ended while their session was still pooled or
    /// borrowed, and the count the last sweep saw.
    died: Arc<AtomicU64>,
    swept_died: AtomicU64,
    /// A connection arrived on a node that is not preferred; the next pass
    /// sweeps.
    recheck: AtomicBool,
    /// Topology epoch and quarantine set at the last idle sweep.
    swept: Mutex<Option<(u64, Vec<String>)>>,
    /// Departed or fallback-tier connections await replacement.
    rebalance_pending: AtomicBool,
    /// Bumped by every return of a departed or fallback-tier session.
    rebalance_requests: AtomicU64,
    /// Serializes sweeps so concurrent passes cannot spend the same surplus.
    sweep_lock: tokio::sync::Mutex<()>,
    /// When the oldest idle session a sweep returned reaches `idle_timeout`
    /// (a sweep restarts bb8's own idle clock).
    idle_deadline: Mutex<Option<Instant>>,
    /// Earliest next replacement retry and the current backoff.
    rebalance_retry: Mutex<(Instant, Duration)>,
}

impl<T: PoolTls> Shared<T> {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn record_connect_failure(&self, error: &PoolError) {
        bump(&self.stats.connect_failures);
        *self.last_error.lock() = Some(error.clone());
        self.connect_error_seq.fetch_add(1, Ordering::SeqCst);
        *self.last_fatal.lock() = Some(error.clone());
        self.fatal_seq.fetch_add(1, Ordering::SeqCst);
        self.fatal.notify_waiters();
        log::warn!("pool {}: connect failed: {}", self.label, error);
    }

    /// Opens one physical connection within `connect_timeout`. With
    /// `wait_for_permit` false the pool-capacity and process-wide permits are
    /// only tried, never waited on (warm-floor maintenance). Shutdown cancels
    /// a dial in progress, and a dial that completes after shutdown began is
    /// closed instead of being pooled.
    async fn open(self: &Arc<Self>, wait_for_permit: bool) -> Result<NativeConnection, PoolError> {
        self.open_reporting(wait_for_permit, true).await
    }

    /// Like [`open`](Self::open) with free permits only; a failure is not
    /// published to waiting checkouts (the caller keeps working sessions).
    async fn open_optional(self: &Arc<Self>) -> Result<NativeConnection, PoolError> {
        self.open_reporting(false, false).await
    }

    async fn open_reporting(
        self: &Arc<Self>,
        wait_for_permit: bool,
        report: bool,
    ) -> Result<NativeConnection, PoolError> {
        if self.is_closed() {
            return Err(PoolError::kind_only(ErrorKind::PoolClosed));
        }
        let _opening = Opening::start(&self.opening);
        let started = Instant::now();
        let budget = self.config.connect_timeout;
        let attempt = self.attempt(wait_for_permit, started, budget);
        let result = tokio::select! {
            biased;
            _ = self.until_closed() => Err(PoolError::new(
                ErrorKind::PoolClosed,
                "pool shut down while connecting",
            )),
            result = attempt => result,
        };
        let result = match result {
            Ok(mut conn) if self.is_closed() => {
                conn.retire = Some(Retire::Shutdown);
                Err(PoolError::new(
                    ErrorKind::PoolClosed,
                    "pool shut down while connecting",
                ))
            }
            other => other,
        };
        match &result {
            Ok(_) => {
                bump(&self.stats.connects);
                add_duration(&self.stats.connect_nanos, started.elapsed());
            }
            Err(e) if e.kind() == ErrorKind::PoolClosed => {}
            Err(e) if !wait_for_permit && e.kind() == ErrorKind::ProcessLimit => {}
            Err(e) if !wait_for_permit && e.kind() == ErrorKind::AcquireTimeout => {}
            Err(e) if !report => {
                bump(&self.stats.connect_failures);
                log::debug!("pool {}: optional connect failed: {}", self.label, e);
            }
            Err(e) => self.record_connect_failure(e),
        }
        result
    }

    async fn attempt(
        self: &Arc<Self>,
        wait_for_permit: bool,
        started: Instant,
        budget: Duration,
    ) -> Result<NativeConnection, PoolError> {
        let capacity = if wait_for_permit {
            self.capacity.acquire(budget).await
        } else {
            self.capacity.try_acquire()
        }
        .map_err(|e| {
            e.with_kind(ErrorKind::AcquireTimeout)
                .with_message("pool capacity held by connections still open or closing")
        })?;
        let remaining = budget.saturating_sub(started.elapsed());
        let process = if wait_for_permit {
            self.limiter.acquire(remaining).await
        } else {
            self.limiter.try_acquire()
        }?;
        let permits = Permits {
            _pool: capacity,
            _process: process,
        };
        let remaining = budget.saturating_sub(started.elapsed());
        let _dialing = Dialing::start(self.as_ref());
        match tokio::time::timeout(remaining, self.dial(permits)).await {
            Ok(result) => result,
            Err(_) => Err(PoolError::new(
                ErrorKind::Transport,
                format!("connect did not complete within {:?}", budget),
            )),
        }
    }

    async fn until_closed(&self) {
        loop {
            let notified = self.shutdown_signal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    async fn dial(self: &Arc<Self>, permits: Permits) -> Result<NativeConnection, PoolError> {
        let (client, connection) = self
            .pg
            .connect(self.tls.clone())
            .await
            .map_err(PoolError::from_driver)?;
        let generation = connection.tls_stream().and_then(T::stream_generation);
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let guard = LiveGuard {
            live: Arc::downgrade(&self.live),
            id,
            _permits: permits,
        };
        let stats = self.stats.clone();
        let label = self.label.clone();
        let terminal: Arc<Mutex<Option<PoolError>>> = Arc::new(Mutex::new(None));
        let terminal_slot = terminal.clone();
        let died = self.died.clone();
        let mut connection = connection;
        let task;
        {
            // Hold the registry lock across spawn so the task cannot remove
            // its entry before it is inserted.
            let mut live = self.live.lock();
            let handle = tokio::spawn(async move {
                let _guard = guard;
                // Poll by reference so the cause is recorded before the
                // connection (and with it the client's channel) is dropped:
                // a borrower that sees the closed client can find it.
                if let Err(e) = (&mut connection).await {
                    bump(&stats.terminal_failures);
                    log::debug!("pool {}: connection {} ended: {}", label, id, e);
                    *terminal_slot.lock() = Some(PoolError::from_driver(e));
                }
                if Arc::strong_count(&terminal_slot) > 1 {
                    died.fetch_add(1, Ordering::SeqCst);
                }
                drop(connection);
            });
            live.insert(id, handle.abort_handle());
            task = handle.abort_handle();
        }
        let mut conn = NativeConnection {
            client,
            cache: StatementCache::new(
                self.config.statement_cache_capacity,
                self.epoch.load(Ordering::SeqCst),
            ),
            stats: self.stats.clone(),
            terminal,
            task,
            id,
            generation,
            created: Instant::now(),
            idle_since: Instant::now(),
            param_baseline: 0,
            retire: None,
        };
        if let Some(sql) = &self.init_sql {
            bump(&self.stats.session_init_round_trips);
            if let Err(e) = conn.client.batch_execute(sql).await {
                conn.retire = Some(Retire::Closed);
                return Err(PoolError::from_driver(e).with_message("session initialization failed"));
            }
        }
        conn.param_baseline = conn.client.parameter_status_changes();
        if matches!(
            conn.client.node_standing(),
            NodeStanding::Fallback | NodeStanding::Departed | NodeStanding::Ineligible
        ) {
            self.recheck.store(true, Ordering::SeqCst);
        }
        Ok(conn)
    }

    /// Local checkout checks; no traffic unless `HealthCheck::AfterIdle`.
    async fn check_out(&self, conn: &mut NativeConnection) -> Result<(), PoolError> {
        let now = Instant::now();
        let reason = if self.is_closed() {
            Some(Retire::Shutdown)
        } else if conn.client.is_closed() {
            Some(Retire::Closed)
        } else if conn.generation.is_some_and(|g| !self.tls.is_current(g)) {
            Some(Retire::SupersededTls)
        } else if self
            .config
            .max_lifetime
            .is_some_and(|lt| now.duration_since(conn.created) >= lt)
        {
            Some(Retire::Aged)
        } else if self
            .config
            .idle_timeout
            .is_some_and(|it| now.duration_since(conn.idle_since) >= it)
        {
            Some(Retire::Idle)
        } else if conn.client.node_standing() == NodeStanding::Ineligible {
            Some(Retire::Topology)
        } else if !reusable(&conn.client)
            // A ParameterStatus that arrived while the connection was idle
            // (for example a server-side setting change) means the session
            // no longer matches what was returned.
            || conn.client.parameter_status_changes() != conn.param_baseline
        {
            Some(Retire::DirtySession)
        } else {
            None
        };
        if let Some(reason) = reason {
            conn.retire = Some(reason);
            if sweeping() {
                // Handed to the sweep, which drops it: failing the check
                // would make bb8 look for (and approve a dial for) another.
                return Ok(());
            }
            return Err(PoolError::new(
                ErrorKind::Transport,
                format!("connection {} retired at checkout: {:?}", conn.id, reason),
            ));
        }
        if let HealthCheck::AfterIdle(after) = self.config.health_check {
            if !sweeping() && now.duration_since(conn.idle_since) >= after {
                bump(&self.stats.probes);
                let started = Instant::now();
                let probe =
                    tokio::time::timeout(self.config.connect_timeout, conn.client.simple_query(""))
                        .await;
                add_duration(&self.stats.probe_nanos, started.elapsed());
                if !matches!(probe, Ok(Ok(_))) {
                    bump(&self.stats.probe_failures);
                    conn.retire = Some(Retire::ProbeFailed);
                    return Err(PoolError::new(
                        ErrorKind::Transport,
                        "checkout probe failed",
                    ));
                }
            }
        }
        if conn.cache.sync_epoch(self.epoch.load(Ordering::SeqCst)) {
            bump(&self.stats.statement_invalidations);
        }
        Ok(())
    }

    /// Why `conn` must not be reused as is, if anything; also returns
    /// whether cleanup could make it reusable.
    fn assess(&self, conn: &NativeConnection) -> Result<bool, Retire> {
        if let Some(reason) = conn.retire {
            return Err(reason);
        }
        if self.is_closed() {
            return Err(Retire::Shutdown);
        }
        let client = &conn.client;
        if client.is_closed() {
            return Err(Retire::Closed);
        }
        if client.parameter_status_changes() != conn.param_baseline {
            return Err(Retire::DirtySession);
        }
        if conn.generation.is_some_and(|g| !self.tls.is_current(g)) {
            return Err(Retire::SupersededTls);
        }
        match client.node_standing() {
            NodeStanding::Ineligible => return Err(Retire::Topology),
            NodeStanding::Departed | NodeStanding::Fallback if !sweeping() => {
                self.rebalance_requests.fetch_add(1, Ordering::SeqCst);
                self.rebalance_pending.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
        Ok(!reusable(client))
    }

    /// bb8's return hook (`has_broken`): the final, synchronous gate.
    fn on_return(&self, conn: &mut NativeConnection) -> bool {
        if !sweeping() {
            conn.idle_since = Instant::now();
        }
        match self.assess(conn) {
            Ok(false) => false,
            Ok(true) => {
                conn.retire = Some(Retire::DirtySession);
                true
            }
            Err(reason) => {
                conn.retire = Some(reason);
                true
            }
        }
    }

    /// Return cleanup for a connection with requests in flight or an open
    /// transaction: wait `cleanup_grace`, then cancel, wait, and roll back,
    /// all within `cleanup_timeout`. Anything unexpected retires it.
    async fn cleanup(&self, conn: &mut NativeConnection) -> bool {
        bump(&self.stats.cleanups);
        let started = Instant::now();
        let budget = self.config.cleanup_timeout;
        let remaining = || budget.saturating_sub(started.elapsed());
        let client = &conn.client;
        if tokio::time::timeout(self.config.cleanup_grace, client.wait_until_settled())
            .await
            .is_err()
        {
            bump(&self.stats.cleanup_cancels);
            let token = client.cancel_token();
            if let Err(e) = tokio::time::timeout(remaining(), token.cancel_query(self.tls.clone()))
                .await
                .unwrap_or_else(|_| Ok(()))
            {
                log::debug!("pool {}: cancel request failed: {}", self.label, e);
            }
            if tokio::time::timeout(remaining(), client.wait_until_settled())
                .await
                .is_err()
            {
                return false;
            }
        }
        if client.is_closed() {
            return false;
        }
        match client.transaction_status() {
            TransactionStatus::Idle => {}
            TransactionStatus::InTransaction | TransactionStatus::Failed => {
                bump(&self.stats.cleanup_rollbacks);
                match tokio::time::timeout(remaining(), client.batch_execute("ROLLBACK")).await {
                    Ok(Ok(())) => {}
                    _ => return false,
                }
            }
            _ => return false,
        }
        reusable(client)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown_signal.notify_waiters();
        *self.last_fatal.lock() = Some(PoolError::kind_only(ErrorKind::PoolClosed));
        self.fatal_seq.fetch_add(1, Ordering::SeqCst);
        self.fatal.notify_waiters();
    }

    async fn fatal_after(&self, seq: u64) -> PoolError {
        loop {
            let notified = self.fatal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.fatal_seq.load(Ordering::SeqCst) > seq {
                return self
                    .last_fatal
                    .lock()
                    .clone()
                    .unwrap_or_else(|| PoolError::kind_only(ErrorKind::PoolClosed));
            }
            notified.await;
        }
    }

    fn timeout_error(&self, error_seq: u64, budget: Duration, max_size: u32) -> PoolError {
        bump(&self.stats.acquire_timeouts);
        if self.connect_error_seq.load(Ordering::SeqCst) > error_seq {
            if let Some(last) = self.last_error.lock().clone() {
                return match last.kind() {
                    ErrorKind::ProcessLimit
                    | ErrorKind::Security
                    | ErrorKind::Config
                    | ErrorKind::PoolClosed => last,
                    _ => {
                        let message = format!(
                            "no connection within {:?}; last connect failure: {}",
                            budget, last
                        );
                        last.with_kind(ErrorKind::AcquireTimeout)
                            .with_message(message)
                    }
                };
            }
        }
        PoolError::new(
            ErrorKind::AcquireTimeout,
            format!(
                "no connection within {:?}: {} of {} borrowed",
                budget,
                self.borrowed.load(Ordering::SeqCst),
                max_size
            ),
        )
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    fn occupancy(&self) -> Occupancy {
        let now = Instant::now();
        Occupancy {
            borrowed: self.borrowed.load(Ordering::SeqCst),
            max_size: self.config.max_size,
            permits_in_use: self.limiter.in_use(),
            permits_dialing: self.limiter.dialing(),
            permits_max: self.limiter.max(),
            oldest_dial: self
                .dials
                .lock()
                .values()
                .map(|started| now.duration_since(*started))
                .max(),
            mean_connect: match self.stats.connects.load(Ordering::Relaxed) {
                0 => None,
                connects => Some(
                    Duration::from_nanos(self.stats.connect_nanos.load(Ordering::Relaxed))
                        / u32::try_from(connects).unwrap_or(u32::MAX),
                ),
            },
            connect_errors: self.connect_error_seq.load(Ordering::SeqCst),
        }
    }
}

/// The bb8 manager.
pub struct Manager<T: PoolTls> {
    shared: Arc<Shared<T>>,
}

impl<T: PoolTls> fmt::Debug for Manager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Manager({})", self.shared.label)
    }
}

impl<T: PoolTls> bb8::ManageConnection for Manager<T> {
    type Connection = NativeConnection;
    type Error = PoolError;

    fn connect(&self) -> impl Future<Output = Result<NativeConnection, PoolError>> + Send {
        let shared = self.shared.clone();
        async move { shared.open(true).await }
    }

    fn is_valid(
        &self,
        conn: &mut NativeConnection,
    ) -> impl Future<Output = Result<(), PoolError>> + Send {
        let shared = self.shared.clone();
        async move { shared.check_out(conn).await }
    }

    fn has_broken(&self, conn: &mut NativeConnection) -> bool {
        self.shared.on_return(conn)
    }
}

#[derive(Debug)]
struct LogSink(String);

impl bb8::ErrorSink<PoolError> for LogSink {
    fn sink(&self, error: PoolError) {
        log::debug!("pool {}: {}", self.0, error);
    }

    fn boxed_clone(&self) -> Box<dyn bb8::ErrorSink<PoolError>> {
        Box::new(LogSink(self.0.clone()))
    }
}

struct Inner<T: PoolTls> {
    pool: bb8::Pool<Manager<T>>,
    shared: Arc<Shared<T>>,
}

/// A bounded pool of native clients for one realm/database/role identity.
///
/// Must be created inside a Tokio runtime. Cloning is cheap; all clones
/// share the pool. Dropping every handle closes idle connections once
/// borrowed clients come back; [`shutdown`](Self::shutdown) closes
/// deterministically.
pub struct Pool<T: PoolTls> {
    inner: Arc<Inner<T>>,
}

impl<T: PoolTls> Clone for Pool<T> {
    fn clone(&self) -> Self {
        Pool {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PoolTls> fmt::Debug for Pool<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("label", &self.inner.shared.label)
            .field("state", &self.state())
            .finish()
    }
}

/// A point-in-time view of a pool.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolState {
    /// Physical connections whose connection task is still running: idle,
    /// borrowed, in cleanup, or retired but still closing.
    pub physical: u32,
    /// Connections bb8 counts against `max_size`.
    pub pooled: u32,
    /// Idle connections ready for checkout.
    pub idle: u32,
    /// Clients currently borrowed (including ones in return cleanup).
    pub borrowed: u32,
    /// Physical connects in progress.
    pub opening: u32,
    /// Checkouts in progress.
    pub waiting: u32,
    /// Permits in use on the shared process-wide limiter.
    pub limiter_in_use: u32,
    /// The process-wide limit.
    pub limiter_max: u32,
    /// Counters.
    pub stats: PoolStats,
}

/// What [`Pool::shutdown`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShutdownReport {
    /// Borrowed clients still out when the drain budget ran out.
    pub borrowed_at_deadline: u32,
    /// Connection tasks aborted (sockets closed under their borrowers).
    pub forced_closes: u32,
    /// Physical connections still closing when shutdown returned.
    pub physical_after: u32,
}

impl<T: PoolTls> Pool<T> {
    /// Creates a pool with its own process-wide limiter of `max_size`.
    pub fn new(pg: Config, tls: T, config: PoolConfig) -> Result<Pool<T>, PoolError> {
        let limiter = ConnectionLimiter::new(config.max_size);
        Pool::with_limiter(pg, tls, config, limiter, "pool")
    }

    /// Creates a pool sharing `limiter` with other pools. `label` names the
    /// pool in logs (no secrets).
    pub fn with_limiter(
        mut pg: Config,
        tls: T,
        config: PoolConfig,
        limiter: ConnectionLimiter,
        label: &str,
    ) -> Result<Pool<T>, PoolError> {
        config.validate()?;
        config
            .session
            .parameters
            .reject_overrides(pg.get_options())?;
        if config.warm_floor > limiter.max() || config.min_idle.unwrap_or(0) > limiter.max() {
            return Err(PoolError::config(
                "warm_floor and min_idle must not exceed the process-wide limit",
            ));
        }
        let mut init_sql = None;
        match config.session.init {
            SessionInit::StartupOptions => {
                let options = config.session.startup_options()?;
                if !options.is_empty() {
                    let combined = match pg.get_options() {
                        Some(existing) if !existing.is_empty() => {
                            format!("{} {}", existing, options)
                        }
                        _ => options,
                    };
                    pg.options(&combined);
                }
            }
            SessionInit::AfterConnect => {
                let sql = config.session.init_sql()?;
                if !sql.is_empty() {
                    init_sql = Some(sql);
                }
            }
        }
        if let Some(name) = &config.session.application_name {
            pg.application_name(name);
        }
        // Keep the driver's own acquisition budget inside the pool's connect
        // budget so it ends with its classified error, not our timeout.
        if pg.get_yb_acquire_timeout() > config.connect_timeout {
            pg.yb_acquire_timeout(config.connect_timeout);
        }
        if pg.get_yb_attempt_timeout() > config.connect_timeout {
            pg.yb_attempt_timeout(config.connect_timeout);
        }
        let realm = pg.resolved_realm();
        let shared = Arc::new(Shared {
            pg,
            tls,
            config: config.clone(),
            init_sql,
            limiter,
            capacity: ConnectionLimiter::new(config.max_size),
            stats: Arc::new(Stats::default()),
            label: label.to_string(),
            closed: AtomicBool::new(false),
            shutdown_signal: Notify::new(),
            opening: AtomicU64::new(0),
            dials: Mutex::new(HashMap::new()),
            next_dial: AtomicU64::new(0),
            waiting: AtomicU64::new(0),
            fatal: Notify::new(),
            fatal_seq: AtomicU64::new(0),
            connect_error_seq: AtomicU64::new(0),
            last_error: Mutex::new(None),
            last_fatal: Mutex::new(None),
            live: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            epoch: AtomicU64::new(0),
            borrowed: AtomicU64::new(0),
            released: Notify::new(),
            last_activity: Mutex::new(Instant::now()),
            warm_lock: tokio::sync::Mutex::new(()),
            realm,
            swept: Mutex::new(None),
            recheck: AtomicBool::new(false),
            died: Arc::new(AtomicU64::new(0)),
            swept_died: AtomicU64::new(0),
            rebalance_pending: AtomicBool::new(false),
            rebalance_requests: AtomicU64::new(0),
            sweep_lock: tokio::sync::Mutex::new(()),
            idle_deadline: Mutex::new(None),
            rebalance_retry: Mutex::new((Instant::now(), REBALANCE_BACKOFF_MIN)),
        });
        let pool = bb8::Pool::builder()
            .max_size(config.max_size)
            .min_idle(None)
            .test_on_check_out(true)
            .max_lifetime(config.max_lifetime)
            .idle_timeout(config.idle_timeout)
            .connection_timeout(config.acquire_timeout)
            // Never retried by the pool: the driver bounds discovery and node
            // attempts itself (yb_acquire_timeout / yb_attempt_timeout /
            // yb_max_attempts) and treats security failures as terminal.
            .retry_connection(false)
            .reaper_rate(config.reaper_rate)
            .queue_strategy(match config.queue_strategy {
                QueueStrategy::Lifo => bb8::QueueStrategy::Lifo,
                _ => bb8::QueueStrategy::Fifo,
            })
            .error_sink(Box::new(LogSink(label.to_string())))
            .build_unchecked(Manager {
                shared: shared.clone(),
            });
        let inner = Arc::new(Inner { pool, shared });
        if config.warm_floor > 0 || config.min_idle.unwrap_or(0) > 0 || inner.shared.realm.is_some()
        {
            let weak = Arc::downgrade(&inner);
            let interval = config.maintenance_interval;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let inner = match weak.upgrade() {
                        Some(inner) => inner,
                        None => break,
                    };
                    if inner.shared.is_closed() {
                        break;
                    }
                    Pool { inner }.maintain().await;
                }
            });
        }
        Ok(Pool { inner })
    }

    /// Borrows a client within the configured `acquire_timeout`.
    pub async fn get(&self) -> Result<PooledClient<T>, PoolError> {
        self.get_within(self.inner.shared.config.acquire_timeout)
            .await
    }

    /// Borrows a client within `min(budget, acquire_timeout)`. Covers
    /// waiting for an idle client and opening a new one (limiter, TLS,
    /// authentication, session initialization). A failed connect is not
    /// retried by the pool and ends the wait with its classified error
    /// (security, process limit, transport...).
    pub async fn get_within(&self, budget: Duration) -> Result<PooledClient<T>, PoolError> {
        let shared = &self.inner.shared;
        if shared.is_closed() {
            return Err(PoolError::kind_only(ErrorKind::PoolClosed));
        }
        let budget = budget.min(shared.config.acquire_timeout);
        shared.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(&shared.waiting);
        shared.touch();
        let error_seq = shared.connect_error_seq.load(Ordering::SeqCst);
        let fatal_seq = shared.fatal_seq.load(Ordering::SeqCst);
        let get = tokio::time::timeout(budget, self.inner.pool.get_owned());
        let result = tokio::select! {
            biased;
            r = get => match r {
                Ok(Ok(conn)) => Ok(conn),
                Ok(Err(bb8::RunError::User(e))) => Err(e),
                Ok(Err(bb8::RunError::TimedOut)) | Err(_) => {
                    Err(shared.timeout_error(error_seq, budget, shared.config.max_size))
                }
            },
            e = shared.fatal_after(fatal_seq) => Err(e),
        };
        let mut conn = result?;
        // Register the lease before re-checking closure. With `shutdown`
        // storing `closed` before it reads `borrowed` (both SeqCst), either
        // shutdown sees this borrower (and waits for or force-closes it) or
        // this check sees the closure; a live client never leaves a closed
        // pool.
        shared.borrowed.fetch_add(1, Ordering::SeqCst);
        let lease = Lease {
            shared: shared.clone(),
        };
        if shared.is_closed() {
            conn.retire = Some(Retire::Shutdown);
            drop(conn);
            drop(lease);
            return Err(PoolError::kind_only(ErrorKind::PoolClosed));
        }
        bump(&shared.stats.checkouts);
        shared.touch();
        Ok(PooledClient {
            conn: Some(conn),
            lease: Some(lease),
            shared: shared.clone(),
        })
    }

    /// Readiness probe. Borrows a client within `min(budget,
    /// acquire_timeout)` and runs one empty simple query within what is left
    /// of `budget`. The client goes back to the pool only when the query
    /// succeeds; a failed, timed-out or abandoned query retires it. When
    /// less than 5 ms of the budget is left after the checkout, no query is
    /// sent, the probe fails and the client goes back to the pool unchanged.
    /// A `budget` under 5 ms is rejected with [`ErrorKind::Config`] and not
    /// counted. Otherwise every call is counted in
    /// [`PoolStats::readiness_probes`], and every call that does not
    /// succeed, including one whose future is dropped, in
    /// [`PoolStats::readiness_probe_failures`].
    ///
    /// # Saturation
    ///
    /// The probe competes for a client like any borrower. A probe that gets
    /// no client in time reports [`ErrorKind::AcquireTimeout`] (saturation)
    /// unless there is evidence against this pool's connect path, in which
    /// case it reports [`ErrorKind::Transport`]. The evidence is:
    ///
    /// * one of this pool's dials was still in flight at the deadline after
    ///   running for at least half the wait, or for twice the pool's mean
    ///   successful connect time if that is longer (half the wait alone
    ///   until the pool has connected once);
    /// * one of this pool's dials failed during the wait;
    /// * the pool had room both when the wait began and at the deadline:
    ///   fewer than `max_size` clients borrowed, and process-wide permits
    ///   free once permits held by dials in progress (of any pool sharing
    ///   the limiter) are discounted.
    ///
    /// The same rule, not counting the probe's own client, decides the kind
    /// when the checkout succeeds but leaves less than 5 ms for the query.
    /// Occupancy is sampled at those two points, not traced, so a pool that
    /// filled and drained between them is not seen. Permits held by sockets
    /// that are still closing count as established connections. A connect
    /// failure can also end the wait directly with its own kind
    /// ([`ErrorKind::Transport`], [`ErrorKind::Security`],
    /// [`ErrorKind::Config`], or [`ErrorKind::ProcessLimit`] when the
    /// process-wide limit stayed exhausted for the whole connect budget). A
    /// query that fails or times out is [`ErrorKind::Transport`] or the
    /// driver error's kind. Whether a saturated pool counts as ready is the
    /// service's decision.
    ///
    /// Pools that share a [`ConnectionLimiter`] (every pool of a
    /// [`PoolSet`]) affect each other: when one pool's stalled dials hold
    /// the shared permits, a probe of a healthy sibling that cannot get a
    /// permit reports [`ErrorKind::Transport`]. For readiness per realm or
    /// endpoint, give those pools separate limiters, or treat a sibling's
    /// failures as that sibling's.
    ///
    /// A classified timeout keeps the checkout's own message (budget,
    /// borrowed count, last connect failure) and appends both occupancy
    /// samples. [`PoolStats::acquire_timeouts`] counts every checkout that
    /// timed out, including one a probe then reports as
    /// [`ErrorKind::Transport`].
    ///
    /// A probe is a checkout, so it counts as activity: a [`PoolSet`]
    /// pool that is probed periodically is never evicted for idleness.
    ///
    /// [`PoolSet`]: crate::PoolSet
    pub async fn probe(&self, budget: Duration) -> Result<(), PoolError> {
        if budget < PROBE_QUERY_FLOOR {
            return Err(PoolError::config(format!(
                "probe budget must be at least {:?}",
                PROBE_QUERY_FLOOR
            )));
        }
        let mut record = ProbeRecord::start(&self.inner.shared.stats);
        let result = self.run_probe(record.started, budget).await;
        record.succeeded = result.is_ok();
        result
    }

    async fn run_probe(&self, started: Instant, budget: Duration) -> Result<(), PoolError> {
        let shared = &self.inner.shared;
        let before = shared.occupancy();
        let mut client = match self.get_within(budget).await {
            Ok(client) => client,
            Err(error) if error.kind() == ErrorKind::AcquireTimeout => {
                let after = shared.occupancy();
                let kind = probe_timeout_kind(&before, &after, started.elapsed());
                return Err(error
                    .with_kind(kind)
                    .append_message(&probe_detail(kind, &before, &after)));
            }
            Err(error) => return Err(error),
        };
        let remaining = match probe_query_budget(budget, started.elapsed()) {
            Some(remaining) => remaining,
            None => {
                let mut after = shared.occupancy();
                after.borrowed = after.borrowed.saturating_sub(1);
                let kind = probe_timeout_kind(&before, &after, started.elapsed());
                return Err(PoolError::new(
                    kind,
                    format!(
                        "checkout used the probe budget of {:?}; no query was sent",
                        budget
                    ),
                )
                .append_message(&probe_detail(kind, &before, &after)));
            }
        };
        client.native_mut().retire = Some(Retire::ProbeFailed);
        let outcome = tokio::time::timeout(remaining, client.client().simple_query("")).await;
        match outcome {
            Ok(Ok(_)) => {
                client.native_mut().retire = None;
                Ok(())
            }
            Ok(Err(e)) => Err(client.classify_error(e)),
            Err(_) => Err(PoolError::new(
                ErrorKind::Transport,
                format!("probe did not complete within {:?}", budget),
            )),
        }
    }

    /// One maintenance pass: refresh the realm's topology if it is due,
    /// sweep idle connections if the topology or quarantine set changed,
    /// then top up to `warm_floor`. Maintenance calls this every
    /// `maintenance_interval`.
    pub async fn maintain(&self) {
        let shared = &self.inner.shared;
        let unused = shared.config.warm_floor == 0
            && shared.config.min_idle.unwrap_or(0) == 0
            && shared.live.lock().is_empty()
            && self.inner.pool.state().connections == 0;
        if unused {
            return;
        }
        self.refresh_topology().await;
        self.sweep().await;
        self.top_up().await;
    }

    async fn refresh_topology(&self) {
        let shared = &self.inner.shared;
        let realm = match &shared.realm {
            Some(realm) => realm,
            None => return,
        };
        let permits = match (shared.capacity.try_acquire(), shared.limiter.try_acquire()) {
            (Ok(pool), Ok(process)) => Permits {
                _pool: pool,
                _process: process,
            },
            _ => {
                bump(&shared.stats.topology_refresh_failures);
                return;
            }
        };
        let refresh = tokio::time::timeout(
            shared.config.connect_timeout,
            realm.refresh(shared.tls.clone(), &shared.pg),
        );
        let outcome = tokio::select! {
            biased;
            _ = shared.until_closed() => return,
            outcome = refresh => outcome,
        };
        match outcome {
            Ok(Ok(_)) => bump(&shared.stats.topology_refreshes),
            Ok(Err(e)) => {
                bump(&shared.stats.topology_refresh_failures);
                log::debug!("pool {}: topology refresh failed: {}", shared.label, e);
            }
            Err(_) => bump(&shared.stats.topology_refresh_failures),
        }
        drop(permits);
    }

    /// Checks every idle connection: closes those whose transport ended or
    /// whose node the policy now excludes. Those on departed or
    /// fallback-tier nodes are closed outright while the pool holds more
    /// than `warm_floor`; within the floor they are first replaced by
    /// preferred-tier connections opened from free permits (an unreachable
    /// new topology therefore never takes the pool below its floor). Runs only when a pooled connection's task
    /// has ended, the topology epoch or quarantine set changed, or a
    /// deferred replacement may now find free permits. Sends no traffic on
    /// the swept connections and leaves their idle timers untouched.
    async fn sweep(&self) {
        let shared = &self.inner.shared;
        let _serial = shared.sweep_lock.lock().await;
        let digest = shared
            .realm
            .as_ref()
            .map(|realm| (realm.topology_epoch(), realm.quarantined(&shared.pg)));
        let died = shared.died.load(Ordering::SeqCst);
        let dead = died != shared.swept_died.load(Ordering::SeqCst);
        let changed = digest.is_some() && *shared.swept.lock() != digest;
        let state = self.inner.pool.state();
        let surplus = state
            .connections
            .saturating_sub(shared.config.warm_floor)
            .min(
                state
                    .idle_connections
                    .saturating_sub(shared.config.min_idle.unwrap_or(0)),
            );
        let retry = shared.rebalance_pending.load(Ordering::SeqCst)
            && (surplus > 0
                || (Instant::now() >= shared.rebalance_retry.lock().0
                    && shared.capacity.in_use() < shared.capacity.max()
                    && shared.limiter.in_use() < shared.limiter.max()));
        let idle_due = shared
            .idle_deadline
            .lock()
            .is_some_and(|deadline| Instant::now() >= deadline);
        let recheck = shared.recheck.swap(false, Ordering::SeqCst);
        if !dead && !changed && !retry && !idle_due && !recheck {
            return;
        }
        bump(&shared.stats.idle_sweeps);
        shared.swept_died.store(died, Ordering::SeqCst);
        let epoch_changed = match (&digest, &*shared.swept.lock()) {
            (Some((epoch, _)), Some((swept, _))) => epoch != swept,
            _ => false,
        };
        if epoch_changed {
            *shared.rebalance_retry.lock() = (Instant::now(), REBALANCE_BACKOFF_MIN);
        }
        let requests = shared.rebalance_requests.load(Ordering::SeqCst);
        let need = SWEEPING
            .scope((), async {
                let held = self.take_idle().await;
                let mut surplus = self.retireable(&held);
                let mut need = 0u64;
                let idle_deadline = shared.config.idle_timeout.and_then(|timeout| {
                    held.iter()
                        .filter(|conn| conn.retire.is_none())
                        .map(|conn| conn.idle_since + timeout)
                        .min()
                });
                *shared.idle_deadline.lock() = idle_deadline;
                for mut conn in held {
                    if conn.retire.is_some() {
                        continue;
                    }
                    let reason = match conn.client.node_standing() {
                        NodeStanding::Fallback => Retire::Rebalanced,
                        NodeStanding::Departed => Retire::Topology,
                        _ => continue,
                    };
                    if surplus > 0 {
                        surplus -= 1;
                        conn.retire = Some(reason);
                    } else {
                        need += 1;
                    }
                }
                need
            })
            .await;
        let may_replace = Instant::now() >= shared.rebalance_retry.lock().0;
        let (mut attempted, mut pending) = (false, false);
        if need > 0 && !may_replace {
            pending = true;
        }
        if need > 0 && may_replace {
            attempted = true;
            let mut opened = 0;
            while opened < need {
                let replacement = match self.replacement().await {
                    Some(replacement) => replacement,
                    None => {
                        bump(&shared.stats.rebalance_deferrals);
                        pending = true;
                        break;
                    }
                };
                match self.inner.pool.add(replacement) {
                    Ok(()) => opened += 1,
                    Err(bb8::AddError::Broken(mut replacement))
                    | Err(bb8::AddError::NoCapacity(mut replacement)) => {
                        replacement.retire = Some(Retire::Explicit);
                        bump(&shared.stats.rebalance_deferrals);
                        pending = true;
                        break;
                    }
                }
            }
            if opened > 0 {
                SWEEPING
                    .scope((), async {
                        let held = self.take_idle().await;
                        let mut budget = opened.min(self.retireable(&held) as u64);
                        for mut conn in held {
                            if budget == 0 {
                                break;
                            }
                            if conn.retire.is_some() {
                                continue;
                            }
                            let reason = match conn.client.node_standing() {
                                NodeStanding::Fallback => Retire::Rebalanced,
                                NodeStanding::Departed => Retire::Topology,
                                _ => continue,
                            };
                            conn.retire = Some(reason);
                            budget -= 1;
                        }
                    })
                    .await;
            }
        }
        shared.rebalance_pending.store(pending, Ordering::SeqCst);
        if shared.rebalance_requests.load(Ordering::SeqCst) != requests {
            shared.rebalance_pending.store(true, Ordering::SeqCst);
        }
        if attempted {
            let mut retry = shared.rebalance_retry.lock();
            let backoff = if pending {
                (retry.1 * 2).min(REBALANCE_BACKOFF_MAX)
            } else {
                REBALANCE_BACKOFF_MIN
            };
            *retry = (Instant::now() + retry.1, backoff);
        }
        if digest.is_some() {
            *shared.swept.lock() = digest;
        }
    }

    /// How many of the held idle sessions can be closed without a
    /// replacement: what exceeds both the warm floor (all connections) and
    /// the `min_idle` reserve (idle connections).
    fn retireable(&self, held: &[bb8::PooledConnection<'_, Manager<T>>]) -> u32 {
        let config = &self.inner.shared.config;
        let retiring = held.iter().filter(|conn| conn.retire.is_some()).count() as u32;
        let idle = held.len() as u32 - retiring;
        let total = self.inner.pool.state().connections.saturating_sub(retiring);
        total
            .saturating_sub(config.warm_floor)
            .min(idle.saturating_sub(config.min_idle.unwrap_or(0)))
    }

    /// Checks out every idle connection without waiting. bb8 discards the
    /// ones that fail the checkout checks on the way. bb8 has no idle-only
    /// checkout, so a checkout racing this one can still make bb8 approve a
    /// dial; it stays within `max_size` and the limiter.
    async fn take_idle(&self) -> Vec<bb8::PooledConnection<'_, Manager<T>>> {
        let idle = self.inner.pool.state().idle_connections;
        let mut held = Vec::new();
        for _ in 0..idle {
            if self.inner.pool.state().idle_connections == 0 {
                break;
            }
            match tokio::time::timeout(Duration::ZERO, self.inner.pool.get()).await {
                Ok(Ok(conn)) => held.push(conn),
                _ => break,
            }
        }
        held
    }

    /// A connection to a preferred-tier node opened from free permits, or
    /// `None` when no permit is free or the driver could only reach a
    /// fallback, departed or seed node. A failure is not published to
    /// waiting checkouts.
    async fn replacement(&self) -> Option<NativeConnection> {
        let mut conn = self.inner.shared.open_optional().await.ok()?;
        if conn.client.node_standing() == NodeStanding::Preferred {
            Some(conn)
        } else {
            conn.retire = Some(Retire::Explicit);
            None
        }
    }

    /// Opens connections until the pool holds `warm_floor` physical
    /// connections, using only free process-wide permits. Returns how many
    /// were opened. Maintenance calls this every `maintenance_interval`.
    pub async fn top_up(&self) -> u32 {
        let shared = &self.inner.shared;
        let floor = shared.config.warm_floor;
        let min_idle = shared.config.min_idle.unwrap_or(0);
        let mut opened = 0;
        let _serial = shared.warm_lock.lock().await;
        while !shared.is_closed() {
            // Dials already in flight (bb8's or ours) count toward the floor.
            let state = self.inner.pool.state();
            let opening = shared.opening.load(Ordering::SeqCst) as u32;
            let have = state.connections + opening;
            let idle = state.idle_connections;
            let short_of_idle = idle < min_idle && have < shared.config.max_size;
            if have >= floor && !short_of_idle {
                shared.stats.warm_deficit.store(0, Ordering::Relaxed);
                break;
            }
            match shared.open(false).await {
                Ok(conn) => match self.inner.pool.add(conn) {
                    Ok(()) => {
                        opened += 1;
                        bump(&shared.stats.warm_connects);
                    }
                    Err(bb8::AddError::Broken(mut conn))
                    | Err(bb8::AddError::NoCapacity(mut conn)) => {
                        conn.retire = Some(Retire::Explicit);
                        break;
                    }
                },
                Err(_) => {
                    let have = self.inner.pool.state().connections
                        + shared.opening.load(Ordering::SeqCst) as u32;
                    shared
                        .stats
                        .warm_deficit
                        .store(floor.saturating_sub(have) as u64, Ordering::Relaxed);
                    break;
                }
            }
        }
        opened
    }

    /// The current state and counters.
    pub fn state(&self) -> PoolState {
        let shared = &self.inner.shared;
        let bb8_state = self.inner.pool.state();
        PoolState {
            physical: shared.live.lock().len() as u32,
            pooled: bb8_state.connections,
            idle: bb8_state.idle_connections,
            borrowed: shared.borrowed.load(Ordering::SeqCst) as u32,
            opening: shared.opening.load(Ordering::SeqCst) as u32,
            waiting: shared.waiting.load(Ordering::SeqCst) as u32,
            limiter_in_use: shared.limiter.in_use(),
            limiter_max: shared.limiter.max(),
            stats: shared.stats.snapshot(),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.inner.shared.config
    }

    /// Clears every connection's statement cache at its next checkout (for
    /// example after a migration changed the schema).
    pub fn invalidate_statements(&self) {
        self.inner.shared.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether the pool has been shut down.
    pub fn is_closed(&self) -> bool {
        self.inner.shared.is_closed()
    }

    /// Time since the last checkout or return.
    pub fn idle_for(&self) -> Duration {
        self.inner.shared.last_activity.lock().elapsed()
    }

    pub(crate) fn touch(&self) {
        self.inner.shared.touch();
    }

    /// Whether anything is borrowed, being checked out or being opened.
    pub(crate) fn busy(&self) -> bool {
        let shared = &self.inner.shared;
        shared.borrowed.load(Ordering::SeqCst) > 0
            || shared.waiting.load(Ordering::SeqCst) > 0
            || shared.opening.load(Ordering::SeqCst) > 0
    }

    /// Drops every idle connection (each fails the checkout check once the
    /// pool is closed).
    async fn drain_idle(&self) {
        if self.inner.pool.state().idle_connections > 0 {
            let _ = tokio::time::timeout(Duration::from_millis(20), self.inner.pool.get()).await;
        }
    }

    /// Closes the pool: refuses new checkouts (waiters fail with
    /// `PoolClosed`), closes idle connections, waits up to `drain` for
    /// borrowed clients to come back (each is closed on return), then aborts
    /// the remaining connection tasks.
    pub async fn shutdown(&self, drain: Duration) -> ShutdownReport {
        let shared = &self.inner.shared;
        shared.close();
        // Dials in flight see the shutdown signal and end.
        let opens = Instant::now() + Duration::from_secs(1);
        while shared.opening.load(Ordering::SeqCst) > 0 && Instant::now() < opens {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.drain_idle().await;
        let deadline = Instant::now() + drain;
        loop {
            let notified = shared.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if shared.borrowed.load(Ordering::SeqCst) == 0 {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
        let borrowed_at_deadline = shared.borrowed.load(Ordering::SeqCst) as u32;
        let mut forced_closes = 0;
        if borrowed_at_deadline > 0 {
            let handles: Vec<AbortHandle> = shared.live.lock().values().cloned().collect();
            for handle in handles {
                handle.abort();
                forced_closes += 1;
                bump(&shared.stats.forced_closes);
            }
        }
        // Closing sockets is asynchronous; give the tasks a moment, and
        // close anything a dial that finished concurrently handed to bb8.
        let settle = Instant::now() + Duration::from_secs(1);
        loop {
            self.drain_idle().await;
            let quiet = shared.opening.load(Ordering::SeqCst) == 0
                && self.inner.pool.state().idle_connections == 0
                && shared.live.lock().is_empty();
            if quiet || Instant::now() >= settle {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ShutdownReport {
            borrowed_at_deadline,
            forced_closes,
            physical_after: shared.live.lock().len() as u32,
        }
    }
}

pub(crate) const PROBE_QUERY_FLOOR: Duration = Duration::from_millis(5);
const REBALANCE_BACKOFF_MIN: Duration = Duration::from_secs(1);
const REBALANCE_BACKOFF_MAX: Duration = Duration::from_secs(5);

pub(crate) fn probe_query_budget(budget: Duration, elapsed: Duration) -> Option<Duration> {
    Some(budget.saturating_sub(elapsed)).filter(|left| *left >= PROBE_QUERY_FLOOR)
}

struct ProbeRecord<'a> {
    stats: &'a Stats,
    started: Instant,
    succeeded: bool,
}

impl<'a> ProbeRecord<'a> {
    fn start(stats: &'a Stats) -> ProbeRecord<'a> {
        bump(&stats.readiness_probes);
        ProbeRecord {
            stats,
            started: Instant::now(),
            succeeded: false,
        }
    }
}

impl Drop for ProbeRecord<'_> {
    fn drop(&mut self) {
        add_duration(&self.stats.readiness_probe_nanos, self.started.elapsed());
        if !self.succeeded {
            bump(&self.stats.readiness_probe_failures);
        }
    }
}

/// Decrements the borrowed count once a client is back in the pool (after
/// any cleanup).
struct Lease<T: PoolTls> {
    shared: Arc<Shared<T>>,
}

impl<T: PoolTls> Drop for Lease<T> {
    fn drop(&mut self) {
        self.shared.touch();
        self.shared.borrowed.fetch_sub(1, Ordering::SeqCst);
        self.shared.released.notify_waiters();
    }
}

/// A borrowed client. Dereferences to the native [`Client`].
///
/// # Return contract
///
/// Dropping the guard returns the client:
///
/// * idle, outside a transaction, with no request in flight other than the
///   `Close` of a dropped statement or portal, and no reported
///   session-state change: back to the pool with no round trip;
/// * other requests in flight (a dropped/cancelled query future) or a
///   transaction open: return cleanup waits `cleanup_grace`, sends a cancel
///   request if still busy, waits, and issues `ROLLBACK`, all within
///   `cleanup_timeout`, then re-checks; failure retires the connection;
/// * transport closed, TLS generation superseded, session marked dirty
///   ([`mark_session_dirty`](Self::mark_session_dirty)) or a
///   `ParameterStatus` change: the connection is closed.
///
/// Session-level `SET`, `SET ROLE`, `SET SESSION AUTHORIZATION`, `LISTEN`,
/// SQL-level `PREPARE`, temporary tables and session advisory locks are not
/// detectable in general (only `GUC_REPORT` settings are). Use
/// transaction-local settings, or call `mark_session_dirty` after any
/// session-level change.
pub struct PooledClient<T: PoolTls> {
    conn: Option<bb8::PooledConnection<'static, Manager<T>>>,
    lease: Option<Lease<T>>,
    shared: Arc<Shared<T>>,
}

impl<T: PoolTls> fmt::Debug for PooledClient<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledClient")
            .field("pool", &self.shared.label)
            .field("connection", &self.conn.as_deref())
            .finish()
    }
}

impl<T: PoolTls> Deref for PooledClient<T> {
    type Target = Client;

    fn deref(&self) -> &Client {
        &self.native().client
    }
}

impl<T: PoolTls> DerefMut for PooledClient<T> {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.native_mut().client
    }
}

macro_rules! cached_call {
    ($self:ident, $sql:ident, $params:ident, $method:ident) => {{
        let statement = $self.prepare_cached($sql).await?;
        let first = $self.native().client.$method(&statement, $params).await;
        drop(statement);
        match first {
            Ok(value) => Ok(value),
            Err(e) if is_stale_statement(&e) => {
                if $self.invalidate_for_retry().await {
                    bump(&$self.shared.stats.stale_statement_retries);
                    let statement = $self.prepare_cached($sql).await?;
                    let second = $self.native().client.$method(&statement, $params).await;
                    second.map_err(|e| $self.map_error(e))
                } else {
                    Err(PoolError::from_driver(e))
                }
            }
            Err(e) => Err($self.map_error(e)),
        }
    }};
}

impl<T: PoolTls> PooledClient<T> {
    fn native(&self) -> &NativeConnection {
        self.conn.as_deref().expect("pooled connection present")
    }

    fn native_mut(&mut self) -> &mut NativeConnection {
        self.conn.as_deref_mut().expect("pooled connection present")
    }

    /// The native client.
    pub fn client(&self) -> &Client {
        &self.native().client
    }

    /// A pool-local identifier of the physical connection.
    pub fn connection_id(&self) -> u64 {
        self.native().id
    }

    /// The TLS credential generation the session authenticated with.
    pub fn tls_generation(&self) -> Option<u64> {
        self.native().generation
    }

    /// Time since the physical connection was opened.
    pub fn connection_age(&self) -> Duration {
        self.native().created.elapsed()
    }

    /// Statements currently cached on this connection.
    pub fn cached_statements(&self) -> usize {
        self.native().cache.len()
    }

    /// Closes the connection on return instead of reusing it. Call after
    /// any session-level state change (`SET`, `SET ROLE`, `LISTEN`, ...).
    pub fn mark_session_dirty(&mut self) {
        self.native_mut().retire = Some(Retire::DirtySession);
    }

    /// Closes the connection on return.
    pub fn retire(&mut self) {
        self.native_mut().retire = Some(Retire::Explicit);
    }

    /// The error that ended this connection's task, if it ended with one
    /// (for example a revoked TLS generation or a server termination).
    pub fn terminal_error(&self) -> Option<PoolError> {
        self.native().terminal.lock().clone()
    }

    /// Classifies an error from this client. A transport error on a client
    /// whose connection task already failed reports that cause instead, so a
    /// session closed by TLS revocation is [`ErrorKind::Security`] rather
    /// than a bare "connection closed".
    pub fn classify_error(&self, error: yb_tokio_postgres::Error) -> PoolError {
        let error = PoolError::from_driver(error);
        if error.kind() == ErrorKind::Transport && self.native().client.is_closed() {
            if let Some(cause) = self.terminal_error() {
                return cause;
            }
        }
        error
    }

    fn map_error(&mut self, error: yb_tokio_postgres::Error) -> PoolError {
        let error = self.classify_error(error);
        if error.kind() == ErrorKind::StaleStatement {
            let n = self.native_mut().cache.clear();
            if n > 0 {
                bump(&self.shared.stats.statement_invalidations);
            }
        }
        error
    }

    /// Clears the cache; reports whether the failed statement can be retried
    /// (autocommit: the server rejected it before executing anything).
    async fn invalidate_for_retry(&mut self) -> bool {
        let conn = self.native_mut();
        conn.cache.clear();
        bump(&conn.stats.statement_invalidations);
        conn.client.wait_until_settled().await;
        !conn.client.is_closed() && conn.client.transaction_status() == TransactionStatus::Idle
    }

    /// Prepares `sql` with inferred parameter types, reusing this
    /// connection's cached statement when present.
    pub async fn prepare_cached(&mut self, sql: &str) -> Result<Statement, PoolError> {
        self.prepare_typed_cached(sql, &[]).await
    }

    /// Prepares `sql` with explicit parameter types, cached per connection
    /// under (SQL, types).
    pub async fn prepare_typed_cached(
        &mut self,
        sql: &str,
        types: &[Type],
    ) -> Result<Statement, PoolError> {
        let conn = self.native_mut();
        prepare_cached(&conn.client, &mut conn.cache, &conn.stats, sql, types).await
    }

    /// Runs a cached statement and returns all rows. Outside a transaction a
    /// stale cached statement is re-prepared and retried once.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, PoolError> {
        cached_call!(self, sql, params, query)
    }

    /// Like [`query`](Self::query), requiring exactly one row.
    pub async fn query_one(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, PoolError> {
        cached_call!(self, sql, params, query_one)
    }

    /// Like [`query`](Self::query), requiring zero or one row.
    pub async fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, PoolError> {
        cached_call!(self, sql, params, query_opt)
    }

    /// Runs a cached statement and returns the affected row count.
    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, PoolError> {
        cached_call!(self, sql, params, execute)
    }

    /// Begins a transaction (`BEGIN`, one round trip).
    pub async fn transaction(&mut self) -> Result<PoolTransaction<'_>, PoolError> {
        self.build_transaction(TransactionOptions::default()).await
    }

    /// Begins a transaction with explicit isolation/read-only/deferrable
    /// settings (one `START TRANSACTION` round trip).
    pub async fn build_transaction(
        &mut self,
        options: TransactionOptions,
    ) -> Result<PoolTransaction<'_>, PoolError> {
        let NativeConnection {
            client,
            cache,
            stats,
            ..
        } = self.native_mut();
        PoolTransaction::begin(client, cache, stats, options).await
    }
}

pub(crate) async fn prepare_cached(
    client: &Client,
    cache: &mut StatementCache,
    stats: &Stats,
    sql: &str,
    types: &[Type],
) -> Result<Statement, PoolError> {
    if let Lookup::Hit(statement) = cache.get(sql, types) {
        bump(&stats.statement_cache_hits);
        return Ok(statement);
    }
    bump(&stats.statement_prepares);
    let statement = client
        .prepare_typed(sql, types)
        .await
        .map_err(PoolError::from_driver)?;
    let evicted = cache.insert(sql, types, statement.clone());
    if evicted > 0 {
        stats
            .statement_cache_evictions
            .fetch_add(evicted, Ordering::Relaxed);
    }
    Ok(statement)
}

impl<T: PoolTls> Drop for PooledClient<T> {
    fn drop(&mut self) {
        let mut conn = match self.conn.take() {
            Some(conn) => conn,
            None => return,
        };
        let lease = self.lease.take();
        match self.shared.assess(&conn) {
            Ok(false) => {}
            Err(reason) => conn.retire = Some(reason),
            Ok(true) => match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    let shared = self.shared.clone();
                    handle.spawn(async move {
                        if !shared.cleanup(&mut conn).await {
                            conn.retire = Some(Retire::CleanupFailed);
                        }
                        drop(conn);
                        drop(lease);
                    });
                    return;
                }
                Err(_) => conn.retire = Some(Retire::CleanupFailed),
            },
        }
        drop(conn);
        drop(lease);
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        option_setting_names, DateOrder, DateOutput, DateStyle, PlanCacheMode, PoolConfig,
        SessionConfig, SessionInit, SessionParameters,
    };
    use std::time::Duration;

    #[test]
    fn probe_timeouts_are_saturation_without_evidence_against_the_pool() {
        use crate::error::ErrorKind;
        use crate::pool::{probe_timeout_kind, Occupancy};
        let idle = Occupancy {
            borrowed: 0,
            max_size: 2,
            permits_in_use: 0,
            permits_dialing: 0,
            permits_max: 4,
            oldest_dial: None,
            mean_connect: None,
            connect_errors: 7,
        };
        let full = Occupancy {
            borrowed: 2,
            permits_in_use: 2,
            ..idle
        };
        let waited = Duration::from_millis(400);
        let kind = |start: &Occupancy, end: &Occupancy| probe_timeout_kind(start, end, waited);
        assert_eq!(kind(&full, &full), ErrorKind::AcquireTimeout);
        assert_eq!(
            kind(&full, &idle),
            ErrorKind::AcquireTimeout,
            "hand-off at the deadline"
        );
        assert_eq!(
            kind(&idle, &full),
            ErrorKind::AcquireTimeout,
            "filled during the wait"
        );
        assert_eq!(kind(&idle, &idle), ErrorKind::Transport);
        let replacing = Occupancy {
            permits_in_use: 1,
            permits_dialing: 1,
            oldest_dial: Some(Duration::from_millis(100)),
            ..idle
        };
        assert_eq!(kind(&full, &replacing), ErrorKind::AcquireTimeout);
        let stalled = Occupancy {
            oldest_dial: Some(Duration::from_millis(200)),
            ..full
        };
        assert_eq!(kind(&full, &stalled), ErrorKind::Transport);
        let slow_endpoint = Occupancy {
            mean_connect: Some(Duration::from_millis(300)),
            ..replacing
        };
        let replacing_slowly = Occupancy {
            oldest_dial: Some(Duration::from_millis(250)),
            ..slow_endpoint
        };
        assert_eq!(
            kind(&full, &replacing_slowly),
            ErrorKind::AcquireTimeout,
            "a budget under twice the connect latency while replacing a connection"
        );
        let stalled_slow_endpoint = Occupancy {
            oldest_dial: Some(Duration::from_millis(600)),
            ..slow_endpoint
        };
        assert_eq!(kind(&full, &stalled_slow_endpoint), ErrorKind::Transport);
        let replacing_without_history = Occupancy {
            oldest_dial: Some(Duration::from_millis(250)),
            ..replacing
        };
        assert_eq!(
            kind(&full, &replacing_without_history),
            ErrorKind::Transport
        );
        let failed = Occupancy {
            connect_errors: 8,
            ..full
        };
        assert_eq!(kind(&full, &failed), ErrorKind::Transport);
        let shared_full_of_dials = Occupancy {
            permits_in_use: 4,
            permits_dialing: 4,
            ..idle
        };
        assert_eq!(
            kind(&shared_full_of_dials, &shared_full_of_dials),
            ErrorKind::Transport
        );
        let shared_full = Occupancy {
            permits_in_use: 4,
            ..idle
        };
        assert_eq!(kind(&shared_full, &shared_full), ErrorKind::AcquireTimeout);
    }

    #[test]
    fn probe_sends_its_query_only_with_budget_left() {
        use crate::pool::{probe_query_budget, PROBE_QUERY_FLOOR};
        let budget = Duration::from_secs(1);
        assert_eq!(
            probe_query_budget(budget, Duration::from_millis(400)),
            Some(Duration::from_millis(600))
        );
        assert_eq!(
            probe_query_budget(budget, budget - PROBE_QUERY_FLOOR),
            Some(PROBE_QUERY_FLOOR)
        );
        assert_eq!(
            probe_query_budget(budget, budget - Duration::from_millis(4)),
            None
        );
        assert_eq!(probe_query_budget(budget, budget), None);
        assert_eq!(probe_query_budget(budget, budget * 2), None);
    }

    #[test]
    fn session_parameters_render_last() {
        let mut session = SessionConfig {
            statement_timeout: Some(Duration::from_secs(5)),
            role: Some("app_runtime".into()),
            parameters: SessionParameters::sqlx_parity(),
            ..SessionConfig::default()
        };
        assert_eq!(
            session.startup_options().unwrap(),
            "-c statement_timeout=5000 -c role=app_runtime -c DateStyle=ISO,MDY -c TimeZone=UTC -c extra_float_digits=2"
        );
        session.parameters.date_style = Some(DateStyle::new(DateOutput::Sql, DateOrder::Dmy));
        session.parameters.time_zone = Some("America/New_York".into());
        session.parameters.plan_cache_mode = Some(PlanCacheMode::ForceCustomPlan);
        session.init = SessionInit::AfterConnect;
        assert_eq!(
            session.init_sql().unwrap(),
            "SET statement_timeout = 5000; SET ROLE app_runtime; SET DateStyle = 'SQL,DMY'; SET TimeZone = 'America/New_York'; SET extra_float_digits = 2; SET plan_cache_mode = force_custom_plan"
        );
        for zone in ["", "UTC'; DROP", "a b", "x\\y"] {
            let mut parameters = SessionParameters::sqlx_parity();
            parameters.time_zone = Some(zone.into());
            assert!(parameters.validate().is_err(), "{zone}");
        }
        for digits in [-16, 4] {
            let mut parameters = SessionParameters::sqlx_parity();
            parameters.extra_float_digits = Some(digits);
            assert!(parameters.validate().is_err(), "{digits}");
        }
    }

    #[test]
    fn option_names_follow_server_switch_parsing() {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("-c TimeZone=UTC", &["timezone"]),
            ("-cTIMEZONE=UTC", &["timezone"]),
            ("--DateStyle=SQL", &["datestyle"]),
            ("-c extra-float-digits=3", &["extra_float_digits"]),
            ("-c Time\\Zone=x", &["timezone"]),
            ("-c\\ timezone=x", &["timezone"]),
            ("-e", &["datestyle"]),
            ("-Fe", &["datestyle"]),
            ("-d e", &[]),
            ("-c -e", &["_e"]),
            (
                "\t-c  work_mem=8MB\n--plan_cache_mode=auto ",
                &["work_mem", "plan_cache_mode"],
            ),
            ("-c", &[""]),
        ];
        for (options, want) in cases {
            assert_eq!(option_setting_names(options), *want, "{options:?}");
        }
        let parity = SessionParameters::sqlx_parity();
        assert!(parity
            .reject_overrides(Some("-c timezone=PST8PDT"))
            .is_err());
        assert!(parity.reject_overrides(Some("-c work_mem=8MB")).is_ok());
        assert!(parity.reject_overrides(None).is_ok());
        assert!(parity
            .reject_overrides(Some("-c plan_cache_mode=auto"))
            .is_ok());
        assert!(SessionParameters::default()
            .reject_overrides(Some("-c TimeZone=UTC"))
            .is_ok());
    }

    #[test]
    fn session_settings_render_without_quoting() {
        let mut session = SessionConfig {
            statement_timeout: Some(Duration::from_secs(5)),
            lock_timeout: Some(Duration::from_micros(10)),
            idle_in_transaction_session_timeout: Some(Duration::from_secs(30)),
            role: Some("app_runtime".into()),
            search_path: Some(vec!["app".into(), "public".into()]),
            ..SessionConfig::default()
        };
        assert_eq!(
            session.startup_options().unwrap(),
            "-c statement_timeout=5000 -c lock_timeout=1 -c idle_in_transaction_session_timeout=30000 -c search_path=app,public -c role=app_runtime"
        );
        session.init = SessionInit::AfterConnect;
        assert_eq!(
            session.init_sql().unwrap(),
            "SET statement_timeout = 5000; SET lock_timeout = 1; SET idle_in_transaction_session_timeout = 30000; SET search_path = app,public; SET ROLE app_runtime"
        );
    }

    #[test]
    fn rejects_unsafe_identifiers_and_inconsistent_limits() {
        for bad in ["App", "a b", "x;drop", "", "1abc"] {
            let session = SessionConfig {
                role: Some(bad.into()),
                ..SessionConfig::default()
            };
            assert!(session.validate().is_err(), "{bad}");
        }
        let mut config = PoolConfig::default();
        config.warm_floor = config.max_size + 1;
        assert!(config.validate().is_err());
        let mut config = PoolConfig::default();
        config.cleanup_grace = config.cleanup_timeout;
        assert!(config.validate().is_err());
        let mut config = PoolConfig::default();
        config.statement_cache_capacity = crate::config::MAX_STATEMENT_CACHE_CAPACITY + 1;
        assert!(config.validate().is_err());
        assert!(PoolConfig::default().validate().is_ok());
    }
}
