//! Regression tests for the independent review of PR #4 (AST-2130). Each
//! test names the finding it pins.

mod common;

use common::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use yb_postgres_pool::yb_tokio_postgres::NoTls;
use yb_postgres_pool::{
    ConnectionLimiter, ErrorKind, Pool, PoolConfig, PoolError, PoolKey, PoolSet, PoolSetConfig,
    PoolSpec,
};

fn set_config() -> PoolSetConfig {
    let mut config = PoolSetConfig::default();
    config.max_connections = 8;
    config.max_pools = 1;
    config.pool_idle_ttl = Duration::from_millis(100);
    config.maintenance_interval = Duration::from_millis(20);
    config.drain_timeout = Duration::from_millis(100);
    config
}

/// Finding 1: shutdown cancels connects in flight; a connect that would
/// complete afterwards never leaves an idle connection holding a permit,
/// even with the reapers disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_1_shutdown_cancels_connects_in_flight() {
    for e in engines() {
        let app = format!("pt_review1_{}", e.name);
        let admin = e.admin().await;
        let (slow, wire) = proxy_delayed(e.addr, Duration::from_millis(600)).await;
        let limiter = ConnectionLimiter::new(4);
        let mut config = pool_config(&app);
        config.idle_timeout = None;
        config.max_lifetime = None;
        let pool =
            Pool::with_limiter(e.config_at(slow), NoTls, config, limiter.clone(), "r1").unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.get().await.map(drop) })
        };
        assert!(eventually(Duration::from_secs(2), || pool.state().opening == 1).await);
        assert_eq!(limiter.in_use(), 1);
        let started = Instant::now();
        let report = pool.shutdown(Duration::ZERO).await;
        let took = started.elapsed();
        assert!(took < Duration::from_millis(1500), "{took:?}");
        let err = waiter.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PoolClosed, "{err}");
        // Well past the moment the delayed connect would have completed.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let state = pool.state();
        println!(
            "[{}] review 1: {report:?} in {took:?}, after: {state:?}, startups {}",
            e.name,
            wire.snapshot().startups
        );
        assert_eq!(limiter.in_use(), 0);
        assert_eq!((state.opening, state.idle, state.physical), (0, 0, 0));
        assert_eq!(backends(&admin, &app).await, 0);
    }
}

/// Finding 2: warm-floor top-up counts connects in flight, and pool
/// capacity is a permit held for the whole connection, so the pool never
/// has more than `max_size` physical connections even with a larger shared
/// limiter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_2_top_up_never_exceeds_max_size() {
    for e in engines() {
        let app = format!("pt_review2_{}", e.name);
        let (slow, _wire) = proxy_delayed(e.addr, Duration::from_millis(400)).await;
        let limiter = ConnectionLimiter::new(16);
        let mut config = pool_config(&app);
        config.max_size = 2;
        config.warm_floor = 2;
        config.maintenance_interval = Duration::from_millis(20);
        let pool =
            Pool::with_limiter(e.config_at(slow), NoTls, config, limiter.clone(), "r2").unwrap();
        let peak = Arc::new(AtomicU32::new(0));
        let sampler = {
            let (limiter, peak) = (limiter.clone(), peak.clone());
            tokio::spawn(async move {
                let until = Instant::now() + Duration::from_secs(3);
                while Instant::now() < until {
                    peak.fetch_max(limiter.in_use(), Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };
        let gets: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let client = pool.get().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    drop(client);
                })
            })
            .collect();
        for get in gets {
            get.await.unwrap();
        }
        assert!(eventually(Duration::from_secs(5), || pool.state().pooled == 2).await);
        pool.top_up().await;
        sampler.await.unwrap();
        println!(
            "[{}] review 2: peak physical {} for max_size 2",
            e.name,
            peak.load(Ordering::SeqCst)
        );
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert!(pool.state().physical <= 2);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

/// Finding 3: no pool can be inserted after `PoolSet::shutdown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn review_3_no_pool_survives_set_shutdown() {
    let addr = stall_listener().await;
    for round in 0..20 {
        let mut config = set_config();
        config.max_pools = 1000;
        let set = PoolSet::new(
            config,
            move |_: &PoolKey| -> Result<PoolSpec<NoTls>, PoolError> {
                Ok(PoolSpec::new(
                    unused_config(addr),
                    NoTls,
                    PoolConfig::default(),
                ))
            },
        )
        .unwrap();
        let tasks: Vec<_> = (0..64)
            .map(|i| {
                let set = set.clone();
                tokio::spawn(async move {
                    tokio::task::yield_now().await;
                    set.pool(&PoolKey::new("r", "db", "role").with_discriminator(&i.to_string()))
                })
            })
            .collect();
        set.shutdown(Duration::ZERO).await;
        for task in tasks {
            match task.await.unwrap() {
                Ok(pool) => assert!(pool.is_closed(), "round {round}: open pool after shutdown"),
                Err(e) => assert_eq!(e.kind(), ErrorKind::PoolClosed),
            }
        }
        assert_eq!(set.active_pools(), 0, "round {round}");
    }
}

/// Finding 4: a checkout waiting on a slow connect is activity; the idle
/// janitor does not evict its pool and fail it with `PoolClosed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_4_waiting_checkout_blocks_eviction() {
    let addr = stall_listener().await;
    let set = PoolSet::new(
        set_config(),
        move |_: &PoolKey| -> Result<PoolSpec<NoTls>, PoolError> {
            let mut config = PoolConfig::default();
            config.connect_timeout = Duration::from_millis(1500);
            config.acquire_timeout = Duration::from_secs(3);
            Ok(PoolSpec::new(unused_config(addr), NoTls, config))
        },
    )
    .unwrap();
    let key = PoolKey::new("r", "db", "role");
    let started = Instant::now();
    let err = set.get(&key).await.unwrap_err();
    let took = started.elapsed();
    println!("review 4: slow connect ended with {err} after {took:?}");
    assert_ne!(err.kind(), ErrorKind::PoolClosed, "{err}");
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert!(took >= Duration::from_millis(1000), "{took:?}");
    assert_eq!(
        set.active_pools(),
        1,
        "the pool was not evicted mid-checkout"
    );
    // Once idle, it is evicted as usual.
    assert!(eventually(Duration::from_secs(3), || set.active_pools() == 0).await);
    set.shutdown(Duration::ZERO).await;
}

/// Finding 5: a full set resolves and validates the replacement before it
/// evicts anything, so a failing resolver keeps the healthy pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_5_failed_resolution_keeps_the_victim() {
    let addr = stall_listener().await;
    let mut config = set_config();
    config.pool_idle_ttl = Duration::from_secs(3600);
    let set = PoolSet::new(
        config,
        move |key: &PoolKey| -> Result<PoolSpec<NoTls>, PoolError> {
            let mut pool = PoolConfig::default();
            match key.discriminator() {
                Some("unresolvable") => return Err(resolve_error()),
                Some("invalid") => pool.max_size = 0,
                _ => {}
            }
            Ok(PoolSpec::new(unused_config(addr), NoTls, pool))
        },
    )
    .unwrap();
    let key = |d: &str| PoolKey::new("r", "db", "role").with_discriminator(d);
    let healthy = set.pool(&key("healthy")).unwrap();
    for bad in ["unresolvable", "invalid"] {
        let err = set.pool(&key(bad)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{err}");
        assert!(!healthy.is_closed(), "{bad}: healthy pool evicted");
        assert_eq!(set.active_pools(), 1);
        assert!(set.state(&key("healthy")).is_some());
    }
    // A valid replacement still evicts the idle pool.
    let _next = set.pool(&key("next")).unwrap();
    assert!(set.state(&key("healthy")).is_none());
    assert!(eventually(Duration::from_secs(3), || healthy.is_closed()).await);
    set.shutdown(Duration::ZERO).await;
}

fn resolve_error() -> PoolError {
    // Any configuration failure (PoolError has no public constructor).
    invalid_pool_config().validate().unwrap_err()
}

fn invalid_pool_config() -> PoolConfig {
    let mut config = PoolConfig::default();
    config.max_size = 0;
    config
}

/// Re-review finding 1: a return whose cleanup fails (a cancelled query on
/// a server that never answers, cancel request included) aborts the
/// connection task, so its capacity and process permits are released and a
/// `max_size = 1` pool can open a replacement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rereview_1_failed_cleanup_releases_capacity() {
    for e in engines() {
        let app = format!("pt_rereview1_{}", e.name);
        let (addr, wire) = proxy(e.addr).await;
        let mut config = pool_config(&app);
        config.max_size = 1;
        config.cleanup_grace = Duration::from_millis(100);
        config.cleanup_timeout = Duration::from_millis(500);
        let pool = Pool::new(e.config_at(addr), NoTls, config).unwrap();
        let pid = backend_pid(&pool.get().await.unwrap()).await;
        {
            let client = pool.get().await.unwrap();
            wire.freeze.store(true, Ordering::SeqCst);
            let stuck = client.simple_query("SELECT 1");
            assert!(tokio::time::timeout(Duration::from_millis(200), stuck)
                .await
                .is_err());
        }
        assert!(
            eventually(Duration::from_secs(3), || pool
                .state()
                .stats
                .retired_cleanup_failed
                == 1)
            .await
        );
        assert!(eventually(Duration::from_secs(3), || pool.state().physical == 0).await);
        wire.freeze.store(false, Ordering::SeqCst);
        let client = pool.get_within(Duration::from_secs(3)).await.unwrap();
        let replacement = backend_pid(&client).await;
        println!(
            "[{}] rereview 1: stuck session {pid} retired and aborted; replacement {replacement}",
            e.name
        );
        assert_ne!(replacement, pid);
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

/// Re-review finding 2: a checkout racing shutdown either is registered
/// (and force-closed by a zero-drain shutdown) or sees the closure; no live
/// client leaves a closed pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rereview_2_no_live_client_from_closed_pool() {
    for e in engines() {
        let app = format!("pt_rereview2_{}", e.name);
        let mut leaked = 0;
        let mut handed_out = 0;
        for round in 0..30 {
            let mut config = pool_config(&app);
            config.max_size = 4;
            let pool = Pool::new(e.config(), NoTls, config).unwrap();
            let warm = [
                pool.get().await.unwrap(),
                pool.get().await.unwrap(),
                pool.get().await.unwrap(),
                pool.get().await.unwrap(),
            ];
            drop(warm);
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    let pool = pool.clone();
                    tokio::spawn(
                        async move { pool.get_within(Duration::from_millis(500)).await.ok() },
                    )
                })
                .collect();
            for _ in 0..(round % 5) {
                tokio::task::yield_now().await;
            }
            pool.shutdown(Duration::ZERO).await;
            for task in tasks {
                if let Some(client) = task.await.unwrap() {
                    handed_out += 1;
                    if !eventually(Duration::from_secs(1), || client.is_closed()).await {
                        leaked += 1;
                    }
                }
            }
        }
        println!(
            "[{}] rereview 2: {handed_out} clients handed out around shutdown, {leaked} still open",
            e.name
        );
        assert_eq!(leaked, 0);
    }
}

/// Re-review finding 3: a `ParameterStatus` that arrives while a connection
/// is idle makes checkout retire it instead of handing it out as clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rereview_3_idle_parameter_change_retires() {
    for e in engines() {
        let app = format!("pt_rereview3_{}", e.name);
        let (addr, wire) = proxy(e.addr).await;
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(addr), NoTls, config).unwrap();
        let pid = backend_pid(&pool.get().await.unwrap()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(wire.inject(&parameter_status("TimeZone", "Injected/Zone")) >= 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let client = pool.get().await.unwrap();
        let replacement = backend_pid(&client).await;
        assert_ne!(
            replacement, pid,
            "idle session with a changed parameter was handed out"
        );
        assert_eq!(pool.state().stats.retired_dirty_session, 1);
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}
