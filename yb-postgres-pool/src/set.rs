//! Lazily created, bounded pools keyed by [`PoolKey`].

use crate::config::{PoolConfig, PoolSetConfig};
use crate::error::{ErrorKind, PoolError};
use crate::key::PoolKey;
use crate::limiter::ConnectionLimiter;
use crate::pool::{Pool, PoolState, PooledClient};
use crate::tls::PoolTls;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use yb_tokio_postgres::Config;

/// Everything needed to open a pool for one key.
#[derive(Clone)]
#[non_exhaustive]
pub struct PoolSpec<T: PoolTls> {
    /// Driver configuration: hosts, credentials, `sslmode`, discovery and
    /// endpoint policy. The pool adds the session options to it.
    pub config: Config,
    /// The connector (normally the realm's shared verifying connector).
    pub tls: T,
    /// Pool limits and session settings.
    pub pool: PoolConfig,
}

impl<T: PoolTls> PoolSpec<T> {
    /// A spec from its parts.
    pub fn new(config: Config, tls: T, pool: PoolConfig) -> PoolSpec<T> {
        PoolSpec { config, tls, pool }
    }
}

/// Produces the spec for a key the set has no pool for. Called with the
/// set's registry locked: keep it fast and free of I/O.
pub trait PoolResolver<T: PoolTls>: Send + Sync + 'static {
    /// The spec for `key`.
    fn resolve(&self, key: &PoolKey) -> Result<PoolSpec<T>, PoolError>;
}

impl<T, F> PoolResolver<T> for F
where
    T: PoolTls,
    F: Fn(&PoolKey) -> Result<PoolSpec<T>, PoolError> + Send + Sync + 'static,
{
    fn resolve(&self, key: &PoolKey) -> Result<PoolSpec<T>, PoolError> {
        self(key)
    }
}

struct SetInner<T: PoolTls> {
    config: PoolSetConfig,
    limiter: ConnectionLimiter,
    resolver: Box<dyn PoolResolver<T>>,
    pools: Mutex<HashMap<PoolKey, Pool<T>>>,
    /// Superseded generations still draining, awaited by `shutdown`.
    retiring: Mutex<HashMap<PoolKey, Pool<T>>>,
    closed: AtomicBool,
}

/// The process's pools: one per [`PoolKey`], created on first use, sharing
/// one process-wide [`ConnectionLimiter`], at most
/// [`PoolSetConfig::max_pools`] alive, and evicted after
/// [`PoolSetConfig::pool_idle_ttl`] with nothing borrowed.
///
/// Must be created inside a Tokio runtime.
pub struct PoolSet<T: PoolTls> {
    inner: Arc<SetInner<T>>,
}

impl<T: PoolTls> Clone for PoolSet<T> {
    fn clone(&self) -> Self {
        PoolSet {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PoolTls> fmt::Debug for PoolSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolSet")
            .field("pools", &self.active_pools())
            .field("limiter", &self.inner.limiter)
            .finish()
    }
}

impl<T: PoolTls> PoolSet<T> {
    /// Creates a set; pools are created lazily through `resolver`.
    pub fn new(
        config: PoolSetConfig,
        resolver: impl PoolResolver<T>,
    ) -> Result<PoolSet<T>, PoolError> {
        config.validate()?;
        let inner = Arc::new(SetInner {
            limiter: ConnectionLimiter::new(config.max_connections),
            config,
            resolver: Box::new(resolver),
            pools: Mutex::new(HashMap::new()),
            retiring: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let weak: Weak<SetInner<T>> = Arc::downgrade(&inner);
        let interval = inner.config.maintenance_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let inner = match weak.upgrade() {
                    Some(inner) => inner,
                    None => break,
                };
                if inner.closed.load(Ordering::SeqCst) {
                    break;
                }
                PoolSet { inner }.evict_idle();
            }
        });
        Ok(PoolSet { inner })
    }

    /// The shared process-wide limiter.
    pub fn limiter(&self) -> &ConnectionLimiter {
        &self.inner.limiter
    }

    /// Pools currently alive.
    pub fn active_pools(&self) -> usize {
        self.inner.pools.lock().len()
    }

    /// The pool for `key`, created on first use.
    ///
    /// When the set is full, the least recently used pool with nothing
    /// borrowed, checked out or being opened is evicted, but only after the
    /// replacement has been resolved and validated.
    pub fn pool(&self, key: &PoolKey) -> Result<Pool<T>, PoolError> {
        let mut pools = self.inner.pools.lock();
        // Checked under the registry lock: `shutdown` sets the flag before
        // draining the registry, so no pool is inserted after it.
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PoolError::kind_only(ErrorKind::PoolClosed));
        }
        if let Some(pool) = pools.get(key) {
            if !pool.is_closed() {
                // Counts as activity, so the janitor cannot evict the pool
                // between this lookup and the checkout.
                pool.touch();
                return Ok(pool.clone());
            }
            pools.remove(key);
        }
        if pools.keys().any(|k| k.supersedes(key))
            || self
                .inner
                .retiring
                .lock()
                .keys()
                .any(|k| k.supersedes(key) || k == key)
        {
            return Err(PoolError::new(
                ErrorKind::PoolClosed,
                format!("{} was superseded by a newer generation", key),
            ));
        }
        let superseded_keys: Vec<PoolKey> = pools
            .keys()
            .filter(|k| key.supersedes(k))
            .cloned()
            .collect();
        let victim = if pools.len() - superseded_keys.len() >= self.inner.config.max_pools {
            let victim = pools
                .iter()
                .filter(|(k, _)| !superseded_keys.contains(k))
                .filter(|(_, p)| !p.busy())
                .max_by_key(|(_, p)| p.idle_for())
                .map(|(k, _)| k.clone());
            match victim {
                Some(victim) => Some(victim),
                None => {
                    return Err(PoolError::new(
                        ErrorKind::TooManyPools,
                        format!(
                            "{} pools active and all are in use",
                            self.inner.config.max_pools
                        ),
                    ))
                }
            }
        } else {
            None
        };
        let spec = self.inner.resolver.resolve(key)?;
        let pool = Pool::with_limiter(
            spec.config,
            spec.tls,
            spec.pool,
            self.inner.limiter.clone(),
            &key.to_string(),
        )?;
        if let Some(victim) = victim {
            if let Some(evicted) = pools.remove(&victim) {
                log::info!("pool set: evicting {} to admit {}", victim, key);
                let drain = self.inner.config.drain_timeout;
                tokio::spawn(async move {
                    evicted.shutdown(drain).await;
                });
            }
        }
        let superseded: Vec<(PoolKey, Pool<T>)> = superseded_keys
            .iter()
            .filter_map(|k| pools.remove(k).map(|p| (k.clone(), p)))
            .collect();
        if !superseded.is_empty() {
            log::info!(
                "pool set: {} supersedes {} older generation pool(s)",
                key,
                superseded.len()
            );
            self.inner
                .retiring
                .lock()
                .extend(superseded.iter().cloned());
            let warming = pool.clone();
            let drain = self.inner.config.drain_timeout;
            let interval = warming
                .config()
                .maintenance_interval
                .min(Duration::from_millis(100));
            let inner = Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                let draining = futures_util::future::join_all(
                    superseded.iter().map(|(_, p)| p.shutdown(drain)),
                );
                tokio::pin!(draining);
                loop {
                    warming.top_up().await;
                    tokio::select! {
                        _ = &mut draining => break,
                        _ = tokio::time::sleep(interval) => {}
                    }
                }
                if let Some(inner) = inner.upgrade() {
                    let mut retiring = inner.retiring.lock();
                    for (key, old) in &superseded {
                        if retiring.get(key).is_some_and(|p| p.same_pool(old)) {
                            retiring.remove(key);
                        }
                    }
                }
                warming.top_up().await;
            });
        }
        pools.insert(key.clone(), pool.clone());
        Ok(pool)
    }

    /// Borrows a client from the pool for `key` within its `acquire_timeout`.
    pub async fn get(&self, key: &PoolKey) -> Result<PooledClient<T>, PoolError> {
        self.pool(key)?.get().await
    }

    /// Borrows a client from the pool for `key` within `budget`.
    pub async fn get_within(
        &self,
        key: &PoolKey,
        budget: Duration,
    ) -> Result<PooledClient<T>, PoolError> {
        self.pool(key)?.get_within(budget).await
    }

    /// State of the pool for `key`, if it exists.
    pub fn state(&self, key: &PoolKey) -> Option<PoolState> {
        self.inner.pools.lock().get(key).map(|p| p.state())
    }

    /// Shuts down and removes pools with nothing borrowed, checked out or
    /// being opened and no activity for `pool_idle_ttl`. Returns how many were evicted. The janitor runs
    /// this every `maintenance_interval`.
    pub fn evict_idle(&self) -> usize {
        let ttl = self.inner.config.pool_idle_ttl;
        let evicted: Vec<Pool<T>> = {
            let mut pools = self.inner.pools.lock();
            let keys: Vec<PoolKey> = pools
                .iter()
                .filter(|(_, p)| !p.busy() && p.idle_for() >= ttl)
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| pools.remove(k)).collect()
        };
        let n = evicted.len();
        for pool in evicted {
            tokio::spawn(async move {
                pool.shutdown(Duration::ZERO).await;
            });
        }
        n
    }

    /// Removes the pool for `key` (for example after its credentials were
    /// superseded) and shuts it down within `drain`.
    pub async fn retire(&self, key: &PoolKey, drain: Duration) -> bool {
        let pool = self.inner.pools.lock().remove(key);
        let pool = pool.or_else(|| self.inner.retiring.lock().get(key).cloned());
        match pool {
            Some(pool) => {
                pool.shutdown(drain).await;
                true
            }
            None => false,
        }
    }

    /// Shuts every pool down within `drain` and refuses new pools.
    pub async fn shutdown(&self, drain: Duration) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let mut pools: Vec<Pool<T>> = self.inner.pools.lock().drain().map(|(_, p)| p).collect();
        pools.extend(self.inner.retiring.lock().drain().map(|(_, p)| p));
        futures_util::future::join_all(pools.iter().map(|p| p.shutdown(drain))).await;
    }
}
