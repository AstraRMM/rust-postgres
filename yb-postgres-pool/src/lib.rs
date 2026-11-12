//! A thin bb8 pool and session contract over the native `yb-tokio-postgres`
//! client (AST-2130, Revision 4 §8.5).
//!
//! # Ownership
//!
//! The driver owns node selection, discovery, endpoint admission and TLS
//! verification. This crate owns physical-client lifecycle:
//!
//! * every `Connection` future runs on its own task; when it ends (error or
//!   close) the client reports closed and is never handed out again;
//! * per-pool (`max_size`) and process-wide ([`ConnectionLimiter`]) caps on
//!   physical connections, counted from dial until the socket closes;
//! * lazy pools keyed by [`PoolKey`] in a [`PoolSet`] with a bound on active
//!   pools and idle eviction;
//! * one acquisition budget per checkout;
//! * retirement of sessions whose verify-full credential generation is no
//!   longer current (revoked generations are closed by the connector even
//!   while borrowed);
//! * session initialization, return hygiene and a bounded per-connection
//!   statement cache.
//!
//! # Checkout cost
//!
//! A checkout performs only local checks (transport closed, TLS generation,
//! age, idle time, protocol-tracked transaction status) and sends nothing,
//! matching the no-acquire-ping policy (AST-1619). [`HealthCheck::AfterIdle`]
//! is an explicit, counted opt-in. `idle_timeout` is enforced at checkout,
//! so a handed-out connection was never idle longer than it; set it below
//! the shortest idle-close on the path (AST-1239).
//!
//! # Session hygiene
//!
//! The fork's client tracks the `ReadyForQuery` transaction status and
//! requests in flight ([`Client::transaction_status`],
//! [`Client::pending_requests`]). A returned client that is idle outside a
//! transaction goes straight back to the pool, even while the `Close` of a
//! dropped statement or portal is still in flight
//! ([`Client::pending_caller_requests`]). One with an open or failed
//! transaction or a request in flight (a cancelled query future) is cleaned
//! up first: wait briefly, cancel, wait, `ROLLBACK`; failing that it is
//! closed. Sessions whose `GUC_REPORT` settings changed, that were marked
//! dirty, whose TLS generation was superseded, or that received a response
//! its request's protocol does not allow ([`Client::is_poisoned`]) are
//! closed rather than reset: `DISCARD ALL` would also drop the statement cache and cannot undo
//! every session change, while a reconnect is paid only on that rare path.
//! Tenant state belongs in transaction-local settings
//! ([`PoolTransaction::set_local`]).
//!
//! [`SessionParameters`] (`DateStyle`, `TimeZone`, `extra_float_digits`,
//! `plan_cache_mode`) cannot be overridden through `Config::options`: they
//! are applied after it, and a pool whose `Config::options` names one of
//! them refuses to start. Run-time changes to the unreported ones are not
//! detected; see [`SessionParameters`] for the limits and why
//! [`SessionInit::StartupOptions`] is the robust mode for them.
//!
//! # Observability
//!
//! [`Pool::state`] returns gauges and counters;
//! [`PoolState::render_prometheus`] and [`render_pools_prometheus`] export
//! them with bounded labels. [`Pool::probe`] is a counted readiness check
//! that borrows a client and runs one empty query.
//!
//! # Errors
//!
//! [`PoolError::kind`] separates pool timeouts, process-limit exhaustion,
//! security failures, transport failures, database errors and timeouts,
//! stale cached statements and ambiguous commits. Nothing in this crate
//! replays a write.
//!
//! [`Client::transaction_status`]: yb_tokio_postgres::Client::transaction_status
//! [`Client::pending_requests`]: yb_tokio_postgres::Client::pending_requests
//! [`Client::pending_caller_requests`]: yb_tokio_postgres::Client::pending_caller_requests
//! [`Client::is_poisoned`]: yb_tokio_postgres::Client::is_poisoned

#![warn(missing_docs, rust_2018_idioms)]

mod cache;
mod config;
mod error;
mod key;
mod limiter;
mod metrics;
mod pool;
mod set;
mod stats;
mod tls;
mod transaction;

pub use crate::config::{
    DateOrder, DateOutput, DateStyle, HealthCheck, PlanCacheMode, PoolConfig, PoolSetConfig,
    QueueStrategy, SessionConfig, SessionInit, SessionParameters, MAX_STATEMENT_CACHE_CAPACITY,
};
pub use crate::error::{classify, is_stale_statement, ErrorKind, PoolError};
pub use crate::key::PoolKey;
pub use crate::limiter::ConnectionLimiter;
pub use crate::metrics::render_pools_prometheus;
pub use crate::pool::{Manager, NativeConnection, Pool, PoolState, PooledClient, ShutdownReport};
pub use crate::set::{PoolResolver, PoolSet, PoolSpec};
pub use crate::stats::PoolStats;
pub use crate::tls::PoolTls;
pub use crate::transaction::{PoolTransaction, TransactionOptions};
pub use yb_tokio_postgres;
