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
//! transaction goes straight back to the pool. One with an open or failed
//! transaction or a request in flight (a cancelled query future) is cleaned
//! up first: wait briefly, cancel, wait, `ROLLBACK`; failing that it is
//! closed. Sessions whose `GUC_REPORT` settings changed, that were marked
//! dirty, or whose TLS generation was superseded are closed rather than
//! reset: `DISCARD ALL` would also drop the statement cache and cannot undo
//! every session change, while a reconnect is paid only on that rare path.
//! Tenant state belongs in transaction-local settings
//! ([`PoolTransaction::set_local`]).
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

#![warn(missing_docs, rust_2018_idioms)]

mod cache;
mod config;
mod error;
mod key;
mod limiter;
mod pool;
mod set;
mod stats;
mod tls;
mod transaction;

pub use crate::config::{
    HealthCheck, PoolConfig, PoolSetConfig, QueueStrategy, SessionConfig, SessionInit,
    MAX_STATEMENT_CACHE_CAPACITY,
};
pub use crate::error::{classify, is_stale_statement, ErrorKind, PoolError};
pub use crate::key::PoolKey;
pub use crate::limiter::ConnectionLimiter;
pub use crate::pool::{Manager, NativeConnection, Pool, PoolState, PooledClient, ShutdownReport};
pub use crate::set::{PoolResolver, PoolSet, PoolSpec};
pub use crate::stats::PoolStats;
pub use crate::tls::PoolTls;
pub use crate::transaction::{PoolTransaction, TransactionOptions};
pub use yb_tokio_postgres;
