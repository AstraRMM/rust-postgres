//! Pool counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Why a physical connection was closed by the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retire {
    /// The transport had already closed or failed.
    Closed,
    /// Its TLS credential generation is no longer current.
    SupersededTls,
    /// Older than `max_lifetime`.
    Aged,
    /// Idle longer than `idle_timeout` at checkout.
    Idle,
    /// Session state changed (`ParameterStatus`) or was marked dirty.
    DirtySession,
    /// Return cleanup (cancel/rollback) failed or ran out of budget.
    CleanupFailed,
    /// A checkout or readiness probe failed.
    ProbeFailed,
    /// The borrower asked for it.
    Explicit,
    /// The pool is shutting down.
    Shutdown,
    /// Its node left the realm's topology or no longer matches the role,
    /// placement or admission policy.
    Topology,
    /// Replaced by a connection to a better preference tier.
    Rebalanced,
}

#[derive(Default)]
pub(crate) struct Stats {
    pub connects: AtomicU64,
    pub connect_failures: AtomicU64,
    pub connect_nanos: AtomicU64,
    pub session_init_round_trips: AtomicU64,
    pub checkouts: AtomicU64,
    pub acquire_timeouts: AtomicU64,
    pub probes: AtomicU64,
    pub probe_failures: AtomicU64,
    pub probe_nanos: AtomicU64,
    pub readiness_probes: AtomicU64,
    pub readiness_probe_failures: AtomicU64,
    pub readiness_probe_nanos: AtomicU64,
    pub terminal_failures: AtomicU64,
    pub retired_closed: AtomicU64,
    pub retired_superseded_tls: AtomicU64,
    pub retired_aged: AtomicU64,
    pub retired_idle: AtomicU64,
    pub retired_dirty_session: AtomicU64,
    pub retired_cleanup_failed: AtomicU64,
    pub retired_probe_failed: AtomicU64,
    pub retired_explicit: AtomicU64,
    pub retired_shutdown: AtomicU64,
    pub reaped: AtomicU64,
    pub cleanups: AtomicU64,
    pub cleanup_cancels: AtomicU64,
    pub cleanup_rollbacks: AtomicU64,
    pub statement_prepares: AtomicU64,
    pub statement_cache_hits: AtomicU64,
    pub statement_cache_evictions: AtomicU64,
    pub statement_invalidations: AtomicU64,
    pub stale_statement_retries: AtomicU64,
    pub warm_connects: AtomicU64,
    pub warm_deficit: AtomicU64,
    pub forced_closes: AtomicU64,
    pub retired_topology: AtomicU64,
    pub retired_rebalanced: AtomicU64,
    pub topology_refreshes: AtomicU64,
    pub topology_refresh_failures: AtomicU64,
    pub idle_sweeps: AtomicU64,
    pub rebalance_deferrals: AtomicU64,
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn add_duration(counter: &AtomicU64, d: Duration) {
    counter.fetch_add(d.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
}

impl Stats {
    pub(crate) fn retired(&self, reason: Option<Retire>) {
        let counter = match reason {
            Some(Retire::Closed) => &self.retired_closed,
            Some(Retire::SupersededTls) => &self.retired_superseded_tls,
            Some(Retire::Aged) => &self.retired_aged,
            Some(Retire::Idle) => &self.retired_idle,
            Some(Retire::DirtySession) => &self.retired_dirty_session,
            Some(Retire::CleanupFailed) => &self.retired_cleanup_failed,
            Some(Retire::ProbeFailed) => &self.retired_probe_failed,
            Some(Retire::Explicit) => &self.retired_explicit,
            Some(Retire::Shutdown) => &self.retired_shutdown,
            Some(Retire::Topology) => &self.retired_topology,
            Some(Retire::Rebalanced) => &self.retired_rebalanced,
            None => &self.reaped,
        };
        bump(counter);
    }

    pub(crate) fn snapshot(&self) -> PoolStats {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        PoolStats {
            connects: l(&self.connects),
            connect_failures: l(&self.connect_failures),
            connect_time: Duration::from_nanos(l(&self.connect_nanos)),
            session_init_round_trips: l(&self.session_init_round_trips),
            checkouts: l(&self.checkouts),
            acquire_timeouts: l(&self.acquire_timeouts),
            probes: l(&self.probes),
            probe_failures: l(&self.probe_failures),
            probe_time: Duration::from_nanos(l(&self.probe_nanos)),
            readiness_probes: l(&self.readiness_probes),
            readiness_probe_failures: l(&self.readiness_probe_failures),
            readiness_probe_time: Duration::from_nanos(l(&self.readiness_probe_nanos)),
            terminal_failures: l(&self.terminal_failures),
            retired_closed: l(&self.retired_closed),
            retired_superseded_tls: l(&self.retired_superseded_tls),
            retired_aged: l(&self.retired_aged),
            retired_idle: l(&self.retired_idle),
            retired_dirty_session: l(&self.retired_dirty_session),
            retired_cleanup_failed: l(&self.retired_cleanup_failed),
            retired_probe_failed: l(&self.retired_probe_failed),
            retired_explicit: l(&self.retired_explicit),
            retired_shutdown: l(&self.retired_shutdown),
            reaped: l(&self.reaped),
            cleanups: l(&self.cleanups),
            cleanup_cancels: l(&self.cleanup_cancels),
            cleanup_rollbacks: l(&self.cleanup_rollbacks),
            statement_prepares: l(&self.statement_prepares),
            statement_cache_hits: l(&self.statement_cache_hits),
            statement_cache_evictions: l(&self.statement_cache_evictions),
            statement_invalidations: l(&self.statement_invalidations),
            stale_statement_retries: l(&self.stale_statement_retries),
            warm_connects: l(&self.warm_connects),
            warm_deficit: l(&self.warm_deficit),
            forced_closes: l(&self.forced_closes),
            retired_topology: l(&self.retired_topology),
            retired_rebalanced: l(&self.retired_rebalanced),
            topology_refreshes: l(&self.topology_refreshes),
            topology_refresh_failures: l(&self.topology_refresh_failures),
            idle_sweeps: l(&self.idle_sweeps),
            rebalance_deferrals: l(&self.rebalance_deferrals),
        }
    }
}

/// A snapshot of a pool's counters (monotonic unless noted).
///
/// Protocol cost accounting: the pool itself sends traffic only for
/// `session_init_round_trips` (one per connect with
/// [`SessionInit::AfterConnect`](crate::SessionInit::AfterConnect)),
/// `probes` (only with [`HealthCheck::AfterIdle`](crate::HealthCheck)),
/// `readiness_probes` (one per [`Pool::probe`](crate::Pool::probe) call,
/// each sending at most one empty query, plus any connect it triggers,
/// counted in `connects`),
/// `cleanup_cancels` (one cancel request on a separate connection each),
/// `cleanup_rollbacks` (one `ROLLBACK` each) and `statement_prepares` (one
/// Parse/Describe/Sync exchange each, plus `Close` for evictions). A clean
/// checkout and return costs nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolStats {
    /// Physical connections opened.
    pub connects: u64,
    /// Physical connect attempts that failed (including limiter timeouts).
    pub connect_failures: u64,
    /// Total time spent in successful connects.
    pub connect_time: Duration,
    /// Session-initialization round trips sent.
    pub session_init_round_trips: u64,
    /// Successful checkouts.
    pub checkouts: u64,
    /// Checkouts that ran out of budget.
    pub acquire_timeouts: u64,
    /// Checkout probes sent.
    pub probes: u64,
    /// Checkout probes that failed.
    pub probe_failures: u64,
    /// Total probe latency.
    pub probe_time: Duration,
    /// [`Pool::probe`](crate::Pool::probe) calls.
    pub readiness_probes: u64,
    /// [`Pool::probe`](crate::Pool::probe) calls that failed, including
    /// checkout failures and timeouts.
    pub readiness_probe_failures: u64,
    /// Total time spent in [`Pool::probe`](crate::Pool::probe).
    pub readiness_probe_time: Duration,
    /// Connection tasks that ended with an error.
    pub terminal_failures: u64,
    /// Retired because the transport was closed.
    pub retired_closed: u64,
    /// Retired because the TLS generation was superseded or revoked.
    pub retired_superseded_tls: u64,
    /// Retired at checkout because older than `max_lifetime`.
    pub retired_aged: u64,
    /// Retired at checkout because idle longer than `idle_timeout`.
    pub retired_idle: u64,
    /// Retired because session state changed or was marked dirty.
    pub retired_dirty_session: u64,
    /// Retired because return cleanup failed.
    pub retired_cleanup_failed: u64,
    /// Retired because a checkout or readiness probe failed.
    pub retired_probe_failed: u64,
    /// Retired on request.
    pub retired_explicit: u64,
    /// Retired by shutdown.
    pub retired_shutdown: u64,
    /// Closed by bb8's idle/lifetime reaper or by dropping the pool.
    pub reaped: u64,
    /// Returns that needed cleanup (requests in flight or a transaction open).
    pub cleanups: u64,
    /// Cancel requests sent by return cleanup.
    pub cleanup_cancels: u64,
    /// `ROLLBACK`s sent by return cleanup.
    pub cleanup_rollbacks: u64,
    /// Statements prepared through the cache (misses).
    pub statement_prepares: u64,
    /// Statement cache hits.
    pub statement_cache_hits: u64,
    /// Statements evicted from full caches.
    pub statement_cache_evictions: u64,
    /// Cache clears after stale-statement errors or epoch changes.
    pub statement_invalidations: u64,
    /// Autocommit queries retried once after a stale-statement error.
    pub stale_statement_retries: u64,
    /// Connections opened by maintenance for `warm_floor` or `min_idle`.
    pub warm_connects: u64,
    /// Gauge: connections short of `warm_floor` after the last maintenance pass.
    pub warm_deficit: u64,
    /// Connections whose task was aborted by a forced shutdown.
    pub forced_closes: u64,
    /// Retired because the node left the topology or the policy.
    pub retired_topology: u64,
    /// Fallback-tier connections replaced by preferred-tier ones.
    pub retired_rebalanced: u64,
    /// Maintenance topology refreshes that returned a usable snapshot
    /// (most reuse a fresh snapshot without discovery).
    pub topology_refreshes: u64,
    /// Maintenance topology refreshes that failed, or were skipped because
    /// no pool or process-wide permit was free for the control connection.
    pub topology_refresh_failures: u64,
    /// Idle sweeps run after a pooled connection died, the topology or
    /// quarantine set changed, or a deferred rebalance found free permits.
    pub idle_sweeps: u64,
    /// Fallback-tier connections kept because no replacement could be
    /// opened within the free permits.
    pub rebalance_deferrals: u64,
}
