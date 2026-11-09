//! Pool, session and pool-set configuration.

use crate::error::PoolError;
use std::time::Duration;

/// How session settings are applied to a new physical connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SessionInit {
    /// Send the settings as `-c name=value` startup options. Costs no round
    /// trip, and the values become the session defaults that `RESET`
    /// returns to.
    #[default]
    StartupOptions,
    /// Apply the settings with one simple-query round trip after
    /// authentication. For paths that strip or reject startup options.
    AfterConnect,
}

/// Session state every physical connection starts with.
///
/// Tenant or request state belongs in transaction-local settings
/// (`SET LOCAL`, `set_config(name, value, true)`, see
/// [`PoolTransaction::set_local`](crate::PoolTransaction::set_local)); it
/// ends with the transaction and cannot leak to another borrower.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionConfig {
    /// `statement_timeout`; `None` keeps the server default.
    pub statement_timeout: Option<Duration>,
    /// `lock_timeout`; `None` keeps the server default.
    pub lock_timeout: Option<Duration>,
    /// `idle_in_transaction_session_timeout`; `None` keeps the server default.
    pub idle_in_transaction_session_timeout: Option<Duration>,
    /// `application_name` (sent as the startup parameter).
    pub application_name: Option<String>,
    /// `role` to assume after login (`SET ROLE`). Must be a lowercase
    /// unquoted identifier.
    pub role: Option<String>,
    /// `search_path` schemas, each a lowercase unquoted identifier.
    pub search_path: Option<Vec<String>>,
    /// How the settings are applied.
    pub init: SessionInit,
}

impl Default for SessionConfig {
    fn default() -> SessionConfig {
        SessionConfig {
            statement_timeout: None,
            lock_timeout: None,
            idle_in_transaction_session_timeout: None,
            application_name: None,
            role: None,
            search_path: None,
            init: SessionInit::StartupOptions,
        }
    }
}

fn identifier_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => {}
        _ => return false,
    }
    name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '$')
}

fn millis(d: Duration) -> Result<u64, PoolError> {
    let ms = d.as_millis();
    if ms > i32::MAX as u128 {
        return Err(PoolError::config(
            "session timeout exceeds i32::MAX milliseconds",
        ));
    }
    // Sub-millisecond non-zero values round up instead of disabling the timeout.
    Ok(if ms == 0 && !d.is_zero() {
        1
    } else {
        ms as u64
    })
}

impl SessionConfig {
    /// Validates names and values.
    pub fn validate(&self) -> Result<(), PoolError> {
        if let Some(role) = &self.role {
            if !identifier_ok(role) {
                return Err(PoolError::config(
                    "session role must be a lowercase unquoted identifier",
                ));
            }
        }
        if let Some(path) = &self.search_path {
            if path.is_empty() || !path.iter().all(|s| identifier_ok(s)) {
                return Err(PoolError::config(
                    "search_path must list lowercase unquoted identifiers",
                ));
            }
        }
        if let Some(name) = &self.application_name {
            if name.len() > 63 || !name.chars().all(|c| c.is_ascii_graphic()) {
                return Err(PoolError::config(
                    "application_name must be at most 63 printable ASCII characters without spaces",
                ));
            }
        }
        for d in [
            self.statement_timeout,
            self.lock_timeout,
            self.idle_in_transaction_session_timeout,
        ]
        .into_iter()
        .flatten()
        {
            millis(d)?;
        }
        Ok(())
    }

    /// `(setting, value)` pairs, in application order. Values are validated
    /// identifiers or integers, so they need no quoting.
    pub(crate) fn settings(&self) -> Result<Vec<(&'static str, String)>, PoolError> {
        self.validate()?;
        let mut out = Vec::new();
        if let Some(d) = self.statement_timeout {
            out.push(("statement_timeout", millis(d)?.to_string()));
        }
        if let Some(d) = self.lock_timeout {
            out.push(("lock_timeout", millis(d)?.to_string()));
        }
        if let Some(d) = self.idle_in_transaction_session_timeout {
            out.push((
                "idle_in_transaction_session_timeout",
                millis(d)?.to_string(),
            ));
        }
        if let Some(path) = &self.search_path {
            out.push(("search_path", path.join(",")));
        }
        if let Some(role) = &self.role {
            out.push(("role", role.clone()));
        }
        Ok(out)
    }

    /// The `options` startup string for [`SessionInit::StartupOptions`].
    pub(crate) fn startup_options(&self) -> Result<String, PoolError> {
        Ok(self
            .settings()?
            .into_iter()
            .map(|(k, v)| format!("-c {}={}", k, v))
            .collect::<Vec<_>>()
            .join(" "))
    }

    /// The batch for [`SessionInit::AfterConnect`].
    pub(crate) fn init_sql(&self) -> Result<String, PoolError> {
        Ok(self
            .settings()?
            .into_iter()
            .map(|(k, v)| match k {
                "role" => format!("SET ROLE {}", v),
                "search_path" => format!("SET search_path = {}", v),
                _ => format!("SET {} = {}", k, v),
            })
            .collect::<Vec<_>>()
            .join("; "))
    }
}

/// Whether checkout may probe the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HealthCheck {
    /// Never send anything on checkout (the default, matching AST-1619's
    /// no-acquire-ping policy). Checkout runs only local checks: closed
    /// transport, superseded TLS generation, age and idle time.
    #[default]
    Never,
    /// Send one empty query on checkout when the connection has been idle
    /// longer than the given duration. Counted in
    /// [`PoolStats::probes`](crate::PoolStats::probes).
    AfterIdle(Duration),
}

/// Order in which idle connections are handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum QueueStrategy {
    /// Most recently returned first: keeps a hot working set and lets idle
    /// timeout retire the surplus.
    #[default]
    Lifo,
    /// Least recently returned first: rotates through every idle connection.
    Fifo,
}

/// Limits and policies of one pool.
///
/// # Capacity semantics (AST-1911)
///
/// * `max_size` bounds the pool's physical connections: idle, borrowed,
///   being cleaned up and being opened. The process-wide
///   [`ConnectionLimiter`](crate::ConnectionLimiter) bounds the sum over
///   every pool sharing it.
/// * `min_idle` is bb8's minimum number of **idle** connections: under load
///   the pool opens more so that `min_idle` stay idle (up to `max_size`).
/// * `warm_floor` is a minimum **total** number of physical connections
///   (idle plus borrowed). Maintenance tops the pool up to the floor, but
///   only with permits the limiter has free right now; it never waits for or
///   exceeds the process-wide limit, so overlapping generations are never
///   prewarmed past the aggregate maximum. A shortfall is reported in
///   [`PoolStats::warm_deficit`](crate::PoolStats::warm_deficit).
/// * Warm connections are still retired by `idle_timeout` and
///   `max_lifetime` and replaced by maintenance, so a handed-out connection
///   has never been idle longer than `idle_timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Per-pool physical connection cap.
    pub max_size: u32,
    /// Minimum idle connections (bb8 `min_idle`).
    pub min_idle: Option<u32>,
    /// Minimum total physical connections kept warm.
    pub warm_floor: u32,
    /// Default checkout budget ([`Pool::get`](crate::Pool::get)).
    pub acquire_timeout: Duration,
    /// Budget for one physical connect: limiter wait, discovery, DNS, TCP,
    /// TLS, authentication and session initialization.
    pub connect_timeout: Duration,
    /// Retire connections idle this long. Set it below the shortest
    /// idle-close on the network path (AST-1239). Enforced at checkout as
    /// well as by the reaper.
    pub idle_timeout: Option<Duration>,
    /// Retire connections older than this (at checkout, return and reap).
    pub max_lifetime: Option<Duration>,
    /// Checkout probe policy.
    pub health_check: HealthCheck,
    /// Prepared statements cached per physical connection; 0 disables.
    pub statement_cache_capacity: usize,
    /// How long a returned connection with requests still in flight may
    /// finish them before the pool sends a cancel request.
    pub cleanup_grace: Duration,
    /// Total budget for return cleanup (cancel, wait, `ROLLBACK`); past it
    /// the connection is retired instead.
    pub cleanup_timeout: Duration,
    /// Interval of the warm-floor maintenance task.
    pub maintenance_interval: Duration,
    /// Interval of bb8's idle/lifetime reaper.
    pub reaper_rate: Duration,
    /// Idle queue order.
    pub queue_strategy: QueueStrategy,
    /// Session state for every connection.
    pub session: SessionConfig,
}

impl Default for PoolConfig {
    fn default() -> PoolConfig {
        PoolConfig {
            max_size: 10,
            min_idle: None,
            warm_floor: 0,
            acquire_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(30)),
            max_lifetime: Some(Duration::from_secs(300)),
            health_check: HealthCheck::Never,
            statement_cache_capacity: 128,
            cleanup_grace: Duration::from_millis(100),
            cleanup_timeout: Duration::from_secs(5),
            maintenance_interval: Duration::from_secs(1),
            reaper_rate: Duration::from_secs(5),
            queue_strategy: QueueStrategy::Lifo,
            session: SessionConfig::default(),
        }
    }
}

/// Upper bound on [`PoolConfig::statement_cache_capacity`].
pub const MAX_STATEMENT_CACHE_CAPACITY: usize = 4096;

impl PoolConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.max_size == 0 {
            return Err(PoolError::config("max_size must be greater than zero"));
        }
        if self.min_idle.is_some_and(|m| m > self.max_size) {
            return Err(PoolError::config("min_idle must not exceed max_size"));
        }
        if self.warm_floor > self.max_size {
            return Err(PoolError::config("warm_floor must not exceed max_size"));
        }
        for (name, d) in [
            ("acquire_timeout", Some(self.acquire_timeout)),
            ("connect_timeout", Some(self.connect_timeout)),
            ("idle_timeout", self.idle_timeout),
            ("max_lifetime", self.max_lifetime),
            ("cleanup_timeout", Some(self.cleanup_timeout)),
            ("maintenance_interval", Some(self.maintenance_interval)),
            ("reaper_rate", Some(self.reaper_rate)),
        ] {
            if d.is_some_and(|d| d.is_zero()) {
                return Err(PoolError::config(format!("{} must be non-zero", name)));
            }
        }
        if let HealthCheck::AfterIdle(d) = self.health_check {
            if d.is_zero() {
                return Err(PoolError::config(
                    "HealthCheck::AfterIdle needs a non-zero duration (use Never)",
                ));
            }
        }
        if self.cleanup_grace >= self.cleanup_timeout {
            return Err(PoolError::config(
                "cleanup_grace must be shorter than cleanup_timeout",
            ));
        }
        if self.statement_cache_capacity > MAX_STATEMENT_CACHE_CAPACITY {
            return Err(PoolError::config(format!(
                "statement_cache_capacity must be at most {}",
                MAX_STATEMENT_CACHE_CAPACITY
            )));
        }
        self.session.validate()
    }
}

/// Limits of a [`PoolSet`](crate::PoolSet).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolSetConfig {
    /// Process-wide physical connection limit shared by every pool in the set.
    pub max_connections: u32,
    /// Maximum pools alive at once.
    pub max_pools: usize,
    /// Pools with nothing borrowed and no checkout for this long are shut
    /// down and removed.
    pub pool_idle_ttl: Duration,
    /// How long eviction and replacement wait for borrowed clients before
    /// closing them.
    pub drain_timeout: Duration,
    /// Interval of the pool-eviction janitor.
    pub maintenance_interval: Duration,
}

impl Default for PoolSetConfig {
    fn default() -> PoolSetConfig {
        PoolSetConfig {
            max_connections: 64,
            max_pools: 16,
            pool_idle_ttl: Duration::from_secs(300),
            drain_timeout: Duration::from_secs(10),
            maintenance_interval: Duration::from_secs(5),
        }
    }
}

impl PoolSetConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.max_connections == 0 || self.max_pools == 0 {
            return Err(PoolError::config(
                "max_connections and max_pools must be greater than zero",
            ));
        }
        if self.pool_idle_ttl.is_zero() || self.maintenance_interval.is_zero() {
            return Err(PoolError::config(
                "pool_idle_ttl and maintenance_interval must be non-zero",
            ));
        }
        Ok(())
    }
}
