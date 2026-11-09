//! AST-2130 real-engine qualification of the native pool and session
//! contract. Every test runs against each configured engine (PostgreSQL 16
//! and YugabyteDB 2025.2); see `rig/run.sh`. Run with `--test-threads=1`:
//! several tests assert timing bounds and physical connection counts.

mod common;

use common::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use yb_postgres_pool::yb_tokio_postgres::{NoTls, SimpleQueryMessage, TransactionStatus};
use yb_postgres_pool::{
    classify, ConnectionLimiter, ErrorKind, HealthCheck, Pool, PoolError, PoolKey, PoolSet,
    PoolSetConfig, PoolSpec, SessionInit,
};

fn short(app: &str) -> yb_postgres_pool::PoolConfig {
    let mut config = pool_config(app);
    config.acquire_timeout = Duration::from_secs(3);
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturation_and_acquisition_deadlines() {
    for e in engines() {
        let app = format!("pt_saturation_{}", e.name);
        let admin = e.admin().await;
        let mut config = short(&app);
        config.max_size = 2;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();

        let a = pool.get().await.unwrap();
        let b = pool.get().await.unwrap();
        assert_eq!(
            eventually_backends(&admin, &app, 2, Duration::from_secs(5)).await,
            2
        );

        let started = Instant::now();
        let err = pool
            .get_within(Duration::from_millis(300))
            .await
            .unwrap_err();
        let waited = started.elapsed();
        assert_eq!(err.kind(), ErrorKind::AcquireTimeout, "{err}");
        assert!(
            (Duration::from_millis(280)..Duration::from_millis(1500)).contains(&waited),
            "deadline honoured: {waited:?}"
        );
        assert_eq!(
            pool.state().physical,
            2,
            "saturation opened no extra connection"
        );

        // A waiter is served as soon as a client comes back.
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let started = Instant::now();
                let client = pool.get_within(Duration::from_secs(3)).await.unwrap();
                (started.elapsed(), backend_pid(&client).await)
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let a_pid = backend_pid(&a).await;
        drop(a);
        let (waited, pid) = waiter.await.unwrap();
        assert_eq!(pid, a_pid, "waiter got the returned client");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        drop(b);

        let stats = pool.state().stats;
        assert_eq!(stats.connects, 2);
        assert_eq!(stats.acquire_timeouts, 1);
        println!(
            "[{}] saturation: deadline {:?}, waiter served after {:?}, physical {}",
            e.name,
            Duration::from_millis(300),
            waited,
            pool.state().physical
        );

        // Process-wide limit shared by two pools.
        let limiter = ConnectionLimiter::new(1);
        let mut one = short(&format!("{app}_l1"));
        one.max_size = 2;
        let mut two = short(&format!("{app}_l2"));
        two.max_size = 2;
        two.connect_timeout = Duration::from_millis(300);
        two.acquire_timeout = Duration::from_millis(900);
        let p1 = Pool::with_limiter(e.config(), NoTls, one, limiter.clone(), "l1").unwrap();
        let p2 = Pool::with_limiter(e.config(), NoTls, two, limiter.clone(), "l2").unwrap();
        let held = p1.get().await.unwrap();
        assert_eq!(limiter.in_use(), 1);
        let err = p2.get().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ProcessLimit, "{err}");
        drop(held);
        p1.shutdown(Duration::from_secs(1)).await;
        // p2's connect was still waiting on the limiter within its own
        // connect budget and takes the freed permit; the total never
        // exceeds the limit.
        let ok = p2.get().await.unwrap();
        assert_eq!(limiter.in_use(), 1);
        assert_eq!(p1.state().physical + p2.state().physical, 1);
        drop(ok);
        p2.shutdown(Duration::from_secs(1)).await;
        pool.shutdown(Duration::from_secs(1)).await;
        assert_eq!(
            eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
            0
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_connection_tasks_are_never_reused() {
    for e in engines() {
        let app = format!("pt_failed_{}", e.name);
        let admin = e.admin().await;
        let mut config = short(&app);
        config.max_size = 2;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();

        // Killed under its borrower.
        let client = pool.get().await.unwrap();
        let p1 = backend_pid(&client).await;
        terminate(&admin, p1).await;
        assert!(eventually(Duration::from_secs(5), || client.is_closed()).await);
        let err = client.simple_query("SELECT 1").await.unwrap_err();
        assert_eq!(classify(&err), ErrorKind::Transport, "{err}");
        drop(client);
        let client = pool.get().await.unwrap();
        let p2 = backend_pid(&client).await;
        assert_ne!(p1, p2, "a dead client is never handed out again");
        drop(client);

        // Killed while idle in the pool: checkout discards it locally (no
        // ping) and reconnects; the borrower never sees the dead one.
        terminate(&admin, p2).await;
        assert!(eventually(Duration::from_secs(5), || pool.state().physical == 0).await);
        let client = pool.get().await.unwrap();
        let p3 = backend_pid(&client).await;
        assert_ne!(p2, p3);
        drop(client);

        let stats = pool.state().stats;
        assert!(stats.retired_closed >= 2, "{stats:?}");
        assert!(stats.terminal_failures >= 2, "{stats:?}");
        assert_eq!(stats.probes, 0);
        println!(
            "[{}] dead connections: retired_closed {}, terminal_failures {}, connects {}",
            e.name, stats.retired_closed, stats.terminal_failures, stats.connects
        );

        // Reconnect after every backend of the pool is terminated.
        let held = [pool.get().await.unwrap(), pool.get().await.unwrap()];
        let pids = [backend_pid(&held[0]).await, backend_pid(&held[1]).await];
        drop(held);
        for pid in &pids {
            terminate(&admin, *pid).await;
        }
        assert!(eventually(Duration::from_secs(5), || pool.state().physical == 0).await);
        let a = pool.get().await.unwrap();
        let b = pool.get().await.unwrap();
        assert!(!pids.contains(&backend_pid(&a).await));
        assert!(!pids.contains(&backend_pid(&b).await));
        drop((a, b));
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_borrow_and_return() {
    for e in engines() {
        let app = format!("pt_concurrent_{}", e.name);
        let admin = e.admin().await;
        let mut config = short(&app);
        config.max_size = 4;
        config.acquire_timeout = Duration::from_secs(20);
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let max_seen = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut tasks = Vec::new();
        for t in 0..32i64 {
            let pool = pool.clone();
            let max_seen = max_seen.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..50i64 {
                    let mut client = pool.get().await.unwrap();
                    max_seen.fetch_max(pool.state().physical, Ordering::SeqCst);
                    let v = t * 1000 + i;
                    let got: i64 = client
                        .query_one("SELECT $1::int8", &[&v])
                        .await
                        .unwrap()
                        .get(0);
                    assert_eq!(got, v);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let state = pool.state();
        assert!(max_seen.load(Ordering::SeqCst) <= 4);
        assert_eq!(state.stats.checkouts, 1600);
        assert!(state.stats.connects <= 4, "{:?}", state.stats);
        assert!(state.stats.statement_prepares <= 4, "{:?}", state.stats);
        assert_eq!(
            state.stats.statement_cache_hits + state.stats.statement_prepares,
            1600
        );
        assert!(backends(&admin, &app).await <= 4);
        println!(
            "[{}] concurrent: 1600 checkouts, connects {}, prepares {}, max physical {}",
            e.name,
            state.stats.connects,
            state.stats.statement_prepares,
            max_seen.load(Ordering::SeqCst)
        );
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_and_automatic_rollback() {
    for e in engines() {
        let app = format!("pt_cancel_{}", e.name);
        let admin = e.admin().await;
        let table = format!("pool_cancel_{}", e.name);
        admin
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id int PRIMARY KEY)"
            ))
            .await
            .unwrap();
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = short(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();

        // 1. A query future dropped mid-flight inside an open transaction.
        let pid1;
        {
            let client = pool.get().await.unwrap();
            pid1 = backend_pid(&client).await;
            client
                .batch_execute(&format!("BEGIN; INSERT INTO {table} VALUES (1)"))
                .await
                .unwrap();
            assert_eq!(
                client.transaction_status(),
                TransactionStatus::InTransaction
            );
            let slow = client.simple_query("SELECT pg_sleep(30)");
            assert!(tokio::time::timeout(Duration::from_millis(200), slow)
                .await
                .is_err());
            assert!(client.pending_requests() >= 1);
        }
        let started = Instant::now();
        let mut client = pool.get().await.unwrap();
        let cleanup = started.elapsed();
        assert!(cleanup < Duration::from_secs(5), "{cleanup:?}");
        assert_eq!(backend_pid(&client).await, pid1, "cleanup kept the session");
        assert_eq!(client.transaction_status(), TransactionStatus::Idle);
        let n: i64 = client
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "the open transaction was rolled back");
        drop(client);
        let stats = pool.state().stats;
        assert_eq!(stats.cleanup_cancels, 1, "{stats:?}");
        assert_eq!(stats.cleanup_rollbacks, 1, "{stats:?}");
        assert_eq!(wire.snapshot().cancels, 1);
        println!(
            "[{}] cancellation: cleanup + next checkout {:?}, cancels {}, rollbacks {}",
            e.name, cleanup, stats.cleanup_cancels, stats.cleanup_rollbacks
        );

        // 2. A transaction dropped without commit.
        {
            let mut client = pool.get().await.unwrap();
            let mut tx = client.transaction().await.unwrap();
            tx.execute(&format!("INSERT INTO {table} VALUES (2)"), &[])
                .await
                .unwrap();
        }
        // 3. An explicit BEGIN left open by the borrower.
        {
            let client = pool.get().await.unwrap();
            client
                .batch_execute(&format!("BEGIN; INSERT INTO {table} VALUES (3)"))
                .await
                .unwrap();
        }
        // 4. A failed transaction left behind.
        {
            let client = pool.get().await.unwrap();
            let _ = client.batch_execute("BEGIN; SELECT 1/0").await.unwrap_err();
        }
        let mut client = pool.get().await.unwrap();
        assert_eq!(
            backend_pid(&client).await,
            pid1,
            "all cleanups reused the session"
        );
        assert_eq!(client.transaction_status(), TransactionStatus::Idle);
        let n: i64 = client
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0);
        drop(client);
        let stats = pool.state().stats;
        assert_eq!(stats.cleanup_cancels, 1, "no further cancels: {stats:?}");
        assert!(stats.cleanup_rollbacks >= 3, "{stats:?}");
        assert_eq!(stats.connects, 1);
        pool.shutdown(Duration::from_secs(1)).await;
        admin
            .batch_execute(&format!("DROP TABLE {table}"))
            .await
            .unwrap();
    }
}

async fn text(client: &yb_postgres_pool::yb_tokio_postgres::Client, sql: &str) -> String {
    for message in client.simple_query(sql).await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap_or("").to_string();
        }
    }
    panic!("no row for {sql}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_init_and_leakage() {
    for e in engines() {
        let admin = e.admin().await;
        admin
            .batch_execute(
                "DO $$ BEGIN CREATE ROLE pool_test_role NOLOGIN; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$",
            )
            .await
            .unwrap();
        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_session_{}_{:?}", e.name, init).to_lowercase();
            let (proxy_addr, wire) = proxy(e.addr).await;
            let mut config = short(&app);
            config.max_size = 1;
            config.session.statement_timeout = Some(Duration::from_millis(1500));
            config.session.lock_timeout = Some(Duration::from_millis(700));
            config.session.idle_in_transaction_session_timeout = Some(Duration::from_secs(60));
            config.session.role = Some("pool_test_role".into());
            config.session.search_path = Some(vec!["pool_test_schema".into(), "public".into()]);
            config.session.init = init;
            let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();

            let client = pool.get().await.unwrap();
            let pid1 = backend_pid(&client).await;
            let settings = text(
                &client,
                "SELECT string_agg(name || '=' || setting, ',' ORDER BY name) FROM pg_settings \
                 WHERE name IN ('statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout')",
            )
            .await;
            assert_eq!(
                settings,
                "idle_in_transaction_session_timeout=60000,lock_timeout=700,statement_timeout=1500"
            );
            assert_eq!(text(&client, "SELECT current_user").await, "pool_test_role");
            assert_eq!(text(&client, "SELECT session_user").await, e.user);
            assert_eq!(
                text(&client, "SELECT current_setting('search_path')")
                    .await
                    .replace(' ', ""),
                "pool_test_schema,public"
            );
            assert_eq!(
                text(&client, "SELECT current_setting('application_name')").await,
                app
            );
            let init_cost = wire.snapshot();
            println!(
                "[{}] session init {:?}: simple queries at connect {}",
                e.name, init, init_cost.simple_queries
            );
            let init_queries: u64 = if init == SessionInit::AfterConnect {
                1
            } else {
                0
            };
            // Plus the five checks above.
            assert_eq!(init_cost.simple_queries, init_queries + 5);

            // Statement timeout is a typed database timeout; the session survives.
            let err = PoolError::from(client.simple_query("SELECT pg_sleep(3)").await.unwrap_err());
            assert_eq!(err.kind(), ErrorKind::DatabaseTimeout, "{err}");
            drop(client);

            // Transaction-local tenant state ends with the transaction.
            {
                let mut client = pool.get().await.unwrap();
                assert_eq!(backend_pid(&client).await, pid1);
                let mut tx = client.transaction().await.unwrap();
                tx.set_local("app.tenant", "tenant-a").await.unwrap();
                let v: String = tx
                    .query_one("SELECT current_setting('app.tenant')", &[])
                    .await
                    .unwrap()
                    .get(0);
                assert_eq!(v, "tenant-a");
                tx.commit().await.unwrap();
            }
            {
                let mut client = pool.get().await.unwrap();
                assert_eq!(backend_pid(&client).await, pid1);
                let v: Option<String> = client
                    .query_one("SELECT current_setting('app.tenant', true)", &[])
                    .await
                    .unwrap()
                    .get(0);
                assert_ne!(v.as_deref(), Some("tenant-a"), "tenant state leaked");
            }

            // A reported session change retires the session.
            let pid2 = {
                let client = pool.get().await.unwrap();
                client
                    .batch_execute("SET application_name = 'leaked'")
                    .await
                    .unwrap();
                backend_pid(&client).await
            };
            assert_eq!(pid2, pid1);
            let pid3 = {
                let client = pool.get().await.unwrap();
                assert_eq!(
                    text(&client, "SELECT current_setting('application_name')").await,
                    app
                );
                backend_pid(&client).await
            };
            assert_ne!(
                pid3, pid1,
                "session with changed application_name was retired"
            );

            // Role escalation back to the (superuser) session user flips the
            // reported is_superuser and retires the session.
            {
                let client = pool.get().await.unwrap();
                client.batch_execute("SET ROLE NONE").await.unwrap();
                assert_eq!(text(&client, "SELECT current_user").await, e.user);
            }
            let pid4 = {
                let client = pool.get().await.unwrap();
                assert_eq!(text(&client, "SELECT current_user").await, "pool_test_role");
                backend_pid(&client).await
            };
            assert_ne!(pid4, pid3, "role change was detected");

            // Declared session changes retire the session.
            {
                let mut client = pool.get().await.unwrap();
                client
                    .batch_execute("SET search_path = leaked")
                    .await
                    .unwrap();
                client.mark_session_dirty();
            }
            let pid5 = {
                let client = pool.get().await.unwrap();
                assert_eq!(
                    text(&client, "SELECT current_setting('search_path')")
                        .await
                        .replace(' ', ""),
                    "pool_test_schema,public"
                );
                backend_pid(&client).await
            };
            assert_ne!(pid5, pid4);

            // Contract boundary: an undeclared, unreported session change is
            // the caller's responsibility (documented on PooledClient).
            {
                let client = pool.get().await.unwrap();
                client
                    .batch_execute("SET search_path = undeclared")
                    .await
                    .unwrap();
            }
            {
                let client = pool.get().await.unwrap();
                let observed = text(&client, "SELECT current_setting('search_path')").await;
                println!(
                    "[{}] {:?}: undeclared SET search_path seen by next borrower: {:?} (same session: {})",
                    e.name,
                    init,
                    observed,
                    backend_pid(&client).await == pid5
                );
                client.batch_execute("RESET search_path").await.unwrap();
            }

            let stats = pool.state().stats;
            assert_eq!(stats.retired_dirty_session, 3, "{stats:?}");
            assert_eq!(
                stats.session_init_round_trips,
                if init == SessionInit::AfterConnect {
                    stats.connects
                } else {
                    0
                }
            );
            pool.shutdown(Duration::from_secs(1)).await;
        }

        // idle_in_transaction_session_timeout closes the session server-side;
        // the pool retires it and reconnects.
        let app = format!("pt_idle_tx_{}", e.name);
        let mut config = short(&app);
        config.max_size = 1;
        config.session.idle_in_transaction_session_timeout = Some(Duration::from_millis(500));
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let pid1 = {
            let client = pool.get().await.unwrap();
            client.batch_execute("BEGIN").await.unwrap();
            let pid = backend_pid(&client).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let err = PoolError::from(client.simple_query("SELECT 1").await.unwrap_err());
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::Transport | ErrorKind::DatabaseTimeout
                ),
                "{err}"
            );
            pid
        };
        let client = pool.get().await.unwrap();
        assert_ne!(backend_pid(&client).await, pid1);
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn statement_cache_reuse_and_invalidation() {
    for e in engines() {
        let app = format!("pt_cache_{}", e.name);
        let admin = e.admin().await;
        let table = format!("pool_cache_{}", e.name);
        admin
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (a int PRIMARY KEY); \
                 INSERT INTO {table} VALUES (1)"
            ))
            .await
            .unwrap();
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = short(&app);
        config.max_size = 1;
        config.statement_cache_capacity = 4;
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();

        // Reuse: one Parse for ten executions.
        let _ = pool.get().await.unwrap();
        let before = wire.snapshot();
        for i in 0..10i64 {
            let mut client = pool.get().await.unwrap();
            let v: i64 = client
                .query_one("SELECT $1::int8 + 1", &[&i])
                .await
                .unwrap()
                .get(0);
            assert_eq!(v, i + 1);
        }
        let d = wire.snapshot().since(&before);
        println!("[{}] 10 cached executions: {:?}", e.name, d);
        assert_eq!(d.parses, 1);
        assert_eq!(d.binds, 10);
        assert_eq!(d.executes, 10);
        assert_eq!(d.round_trips(), 11);
        let stats = pool.state().stats;
        assert_eq!(stats.statement_prepares, 1);
        assert_eq!(stats.statement_cache_hits, 9);

        // Bounded: six distinct statements through a cache of four.
        let mut client = pool.get().await.unwrap();
        let before = wire.snapshot();
        for i in 0..6 {
            let sql = format!("SELECT {i}::int8");
            let _ = client.query_one(&sql, &[]).await.unwrap();
        }
        assert_eq!(client.cached_statements(), 4);
        drop(client);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let d = wire.snapshot().since(&before);
        let stats = pool.state().stats;
        assert_eq!(stats.statement_cache_evictions, 3, "{stats:?}");
        assert!(
            d.closes >= 3,
            "evicted statements are closed server-side: {d:?}"
        );

        // Result type change: "cached plan must not change result type".
        let mut client = pool.get().await.unwrap();
        let select = format!("SELECT * FROM {table}");
        assert_eq!(client.query(&select, &[]).await.unwrap()[0].len(), 1);
        admin
            .batch_execute(&format!("ALTER TABLE {table} ADD COLUMN b int"))
            .await
            .unwrap();
        let rows = client.query(&select, &[]).await;
        let stats = pool.state().stats;
        println!(
            "[{}] after ALTER TABLE: {:?} retries {} invalidations {}",
            e.name,
            rows.as_ref().map(|r| r[0].len()),
            stats.stale_statement_retries,
            stats.statement_invalidations
        );
        assert_eq!(rows.unwrap()[0].len(), 2, "autocommit query re-prepared");

        // The same change met inside a transaction aborts it with a typed
        // error. (The DDL runs before BEGIN: an open transaction holding the
        // table would block it.)
        assert_eq!(client.query(&select, &[]).await.unwrap()[0].len(), 2);
        admin
            .batch_execute(&format!("ALTER TABLE {table} ADD COLUMN c int"))
            .await
            .unwrap();
        let mut tx = client.transaction().await.unwrap();
        let in_tx = tx.query(&select, &[]).await;
        match in_tx {
            Err(err) => {
                println!("[{}] stale statement in transaction: {}", e.name, err);
                assert!(
                    matches!(err.kind(), ErrorKind::StaleStatement | ErrorKind::Database),
                    "{err}"
                );
                let err = tx.commit().await.unwrap_err();
                assert_eq!(err.kind(), ErrorKind::TransactionAborted, "{err}");
            }
            Ok(rows) => {
                // An engine may revalidate transparently inside the
                // transaction; record it.
                println!(
                    "[{}] in-transaction schema change revalidated to {} columns",
                    e.name,
                    rows[0].len()
                );
                tx.commit().await.unwrap();
            }
        }
        assert_eq!(client.transaction_status(), TransactionStatus::Idle);

        // Protocol-level statements dropped behind the cache (26000).
        let _ = client.query_one("SELECT 42::int8", &[]).await.unwrap();
        client.batch_execute("DEALLOCATE ALL").await.unwrap();
        let retries = pool.state().stats.stale_statement_retries;
        let v: i64 = client
            .query_one("SELECT 42::int8", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(v, 42);
        assert_eq!(pool.state().stats.stale_statement_retries, retries + 1);

        // Pool-wide epoch: caches clear at their next checkout.
        assert!(client.cached_statements() > 0);
        drop(client);
        pool.invalidate_statements();
        let client = pool.get().await.unwrap();
        assert_eq!(client.cached_statements(), 0);
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
        admin
            .batch_execute(&format!("DROP TABLE {table}"))
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aged_and_idle_connections_are_retired_at_checkout() {
    for e in engines() {
        let app = format!("pt_aged_{}", e.name);
        let admin = e.admin().await;
        let mut config = short(&app);
        config.max_size = 1;
        config.max_lifetime = Some(Duration::from_millis(800));
        config.idle_timeout = None;
        config.reaper_rate = Duration::from_secs(60);
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let p1 = backend_pid(&pool.get().await.unwrap()).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let p2 = backend_pid(&pool.get().await.unwrap()).await;
        assert_ne!(p1, p2);
        assert_eq!(pool.state().stats.retired_aged, 1);
        pool.shutdown(Duration::from_secs(1)).await;

        let mut config = short(&app);
        config.max_size = 1;
        config.idle_timeout = Some(Duration::from_millis(800));
        config.reaper_rate = Duration::from_secs(60);
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let p1 = backend_pid(&pool.get().await.unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            backend_pid(&pool.get().await.unwrap()).await,
            p1,
            "not idle long enough"
        );
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let p3 = backend_pid(&pool.get().await.unwrap()).await;
        assert_ne!(p1, p3, "idle past idle_timeout is never handed out");
        assert_eq!(pool.state().stats.retired_idle, 1);
        assert_eq!(pool.state().stats.probes, 0);
        pool.shutdown(Duration::from_secs(1)).await;
        assert_eq!(
            eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
            0
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warm_floor_versus_min_idle() {
    for e in engines() {
        let admin = e.admin().await;
        // warm_floor: minimum total.
        let app = format!("pt_warm_{}", e.name);
        let mut config = short(&app);
        config.max_size = 5;
        config.warm_floor = 3;
        config.maintenance_interval = Duration::from_millis(100);
        let started = Instant::now();
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        assert!(eventually(Duration::from_secs(10), || pool.state().pooled >= 3).await);
        let warm_after = started.elapsed();
        assert_eq!(
            eventually_backends(&admin, &app, 3, Duration::from_secs(5)).await,
            3
        );
        let held = [
            pool.get().await.unwrap(),
            pool.get().await.unwrap(),
            pool.get().await.unwrap(),
        ];
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            pool.state().pooled,
            3,
            "borrowing the floor opens nothing extra"
        );
        drop(held);
        println!("[{}] warm floor 3 reached in {:?}", e.name, warm_after);
        pool.shutdown(Duration::from_secs(1)).await;

        // min_idle: minimum idle, so borrowing grows the total.
        let app = format!("pt_minidle_{}", e.name);
        let mut config = short(&app);
        config.max_size = 5;
        config.min_idle = Some(2);
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        assert!(eventually(Duration::from_secs(10), || pool.state().idle >= 2).await);
        let held = pool.get().await.unwrap();
        assert!(eventually(Duration::from_secs(10), || pool.state().pooled == 3).await);
        assert_eq!(pool.state().idle, 2);
        drop(held);
        pool.shutdown(Duration::from_secs(1)).await;

        // The floor never exceeds the shared process-wide limit.
        let limiter = ConnectionLimiter::new(3);
        let mut busy = short(&format!("pt_floor_busy_{}", e.name));
        busy.max_size = 3;
        let busy = Pool::with_limiter(e.config(), NoTls, busy, limiter.clone(), "busy").unwrap();
        let held = [busy.get().await.unwrap(), busy.get().await.unwrap()];
        let mut warm = short(&format!("pt_floor_warm_{}", e.name));
        warm.max_size = 3;
        warm.warm_floor = 2;
        warm.maintenance_interval = Duration::from_millis(100);
        let warm = Pool::with_limiter(e.config(), NoTls, warm, limiter.clone(), "warm").unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(warm.state().pooled, 1);
        assert_eq!(warm.state().stats.warm_deficit, 1);
        assert_eq!(limiter.in_use(), 3);
        drop(held);
        busy.shutdown(Duration::from_secs(1)).await;
        assert!(eventually(Duration::from_secs(5), || warm.state().pooled == 2).await);
        assert_eq!(warm.state().stats.warm_deficit, 0);
        warm.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_then_forces() {
    for e in engines() {
        let app = format!("pt_shutdown_{}", e.name);
        let admin = e.admin().await;
        let mut config = short(&app);
        config.max_size = 3;
        config.warm_floor = 3;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        pool.top_up().await;
        assert_eq!(
            eventually_backends(&admin, &app, 3, Duration::from_secs(5)).await,
            3
        );
        let held = pool.get().await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let _a = pool.get().await;
                let _b = pool.get().await;
                pool.get_within(Duration::from_secs(5)).await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        let report = pool.shutdown(Duration::from_millis(300)).await;
        let took = started.elapsed();
        println!("[{}] forced shutdown {:?} in {:?}", e.name, report, took);
        assert_eq!(report.borrowed_at_deadline, 1);
        assert!(report.forced_closes >= 1);
        assert_eq!(report.physical_after, 0);
        let waited = waiter.await.unwrap();
        assert!(waited.is_err());
        let err = held.simple_query("SELECT 1").await.unwrap_err();
        assert_eq!(classify(&err), ErrorKind::Transport, "{err}");
        drop(held);
        assert_eq!(pool.get().await.unwrap_err().kind(), ErrorKind::PoolClosed);
        assert_eq!(
            eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
            0
        );

        // Graceful: nothing borrowed, nothing forced.
        let app = format!("pt_shutdown_graceful_{}", e.name);
        let mut config = short(&app);
        config.max_size = 2;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        drop((pool.get().await.unwrap(), pool.get().await.unwrap()));
        let report = pool.shutdown(Duration::from_secs(2)).await;
        assert_eq!(report.forced_closes, 0, "{report:?}");
        assert_eq!(report.physical_after, 0, "{report:?}");
        assert_eq!(
            eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
            0
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ambiguous_commit_is_never_replayed() {
    for e in engines() {
        let app = format!("pt_commit_{}", e.name);
        let admin = e.admin().await;
        let table = format!("pool_commit_{}", e.name);
        admin
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id int PRIMARY KEY)"
            ))
            .await
            .unwrap();
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = short(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();
        {
            let mut client = pool.get().await.unwrap();
            let mut tx = client.transaction().await.unwrap();
            tx.execute(&format!("INSERT INTO {table} VALUES (1)"), &[])
                .await
                .unwrap();
            wire.kill_after_commit.store(true, Ordering::SeqCst);
            let err = tx.commit().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::AmbiguousCommit, "{err}");
        }
        // The client was cut off before the server even saw COMMIT; the
        // server still commits it.
        let mut n = 0i64;
        let deadline = Instant::now() + Duration::from_secs(5);
        while n == 0 && Instant::now() < deadline {
            n = admin
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get(0);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!(
            "[{}] ambiguous commit: row committed = {} (a blind replay would duplicate it)",
            e.name,
            n == 1
        );
        assert_eq!(n, 1);

        // A failed transaction's COMMIT is reported, not silently rolled back.
        {
            let mut client = pool.get().await.unwrap();
            let mut tx = client.transaction().await.unwrap();
            tx.execute(&format!("INSERT INTO {table} VALUES (2)"), &[])
                .await
                .unwrap();
            let dup = tx
                .execute(&format!("INSERT INTO {table} VALUES (1)"), &[])
                .await
                .unwrap_err();
            assert_eq!(dup.kind(), ErrorKind::Database);
            assert_eq!(dup.code().map(|c| c.code()), Some("23505"));
            let err = tx.commit().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::TransactionAborted, "{err}");
        }
        let n: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1);
        pool.shutdown(Duration::from_secs(1)).await;
        admin
            .batch_execute(&format!("DROP TABLE {table}"))
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_set_is_lazy_bounded_and_evicts() {
    for e in engines() {
        let admin = e.admin().await;
        let engine = e.clone();
        let resolver = move |key: &PoolKey| -> Result<PoolSpec<NoTls>, PoolError> {
            let mut config = pool_config(&format!(
                "pt_set_{}_{}",
                engine.name,
                key.discriminator().unwrap_or("none")
            ));
            config.max_size = 3;
            config.acquire_timeout = Duration::from_secs(1);
            config.connect_timeout = Duration::from_millis(300);
            Ok(PoolSpec::new(engine.config(), NoTls, config))
        };
        let mut set_config = PoolSetConfig::default();
        set_config.max_connections = 3;
        set_config.max_pools = 2;
        set_config.pool_idle_ttl = Duration::from_millis(700);
        set_config.maintenance_interval = Duration::from_millis(100);
        set_config.drain_timeout = Duration::from_secs(1);
        let set = PoolSet::new(set_config, resolver).unwrap();
        let key = |d: &str| PoolKey::new("test", e.dbname, e.user).with_discriminator(d);
        assert_eq!(set.active_pools(), 0, "pools are lazy");

        let a = set.get(&key("a")).await.unwrap();
        let b = set.get(&key("b")).await.unwrap();
        assert_eq!(set.active_pools(), 2);
        let err = set.get(&key("c")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TooManyPools, "{err}");
        drop(a);
        assert!(
            eventually(Duration::from_secs(2), || set
                .state(&key("a"))
                .is_none_or(|s| s.borrowed == 0))
            .await
        );
        let c1 = set.get(&key("c")).await.unwrap();
        assert_eq!(set.active_pools(), 2);
        assert!(
            set.state(&key("a")).is_none(),
            "least recently used idle pool evicted"
        );
        let limiter = set.limiter().clone();
        assert!(eventually(Duration::from_secs(5), || limiter.in_use() == 2).await);

        // Process-wide limit across pools.
        let c2 = set.get(&key("c")).await.unwrap();
        assert_eq!(limiter.in_use(), 3);
        let err = set.get(&key("c")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ProcessLimit, "{err}");
        drop((b, c1, c2));

        // Idle pools are evicted and their connections closed.
        assert!(eventually(Duration::from_secs(5), || set.active_pools() == 0).await);
        assert!(eventually(Duration::from_secs(5), || limiter.in_use() == 0).await);
        for d in ["a", "b", "c"] {
            let app = format!("pt_set_{}_{}", e.name, d);
            assert_eq!(
                eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
                0
            );
        }
        set.shutdown(Duration::from_secs(1)).await;
        assert_eq!(
            set.get(&key("a")).await.unwrap_err().kind(),
            ErrorKind::PoolClosed
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_cost_of_checkout_probe_and_reset() {
    for e in engines() {
        let app = format!("pt_cost_{}", e.name);
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = short(&app);
        config.max_size = 2;
        config.warm_floor = 2;
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();
        assert!(eventually(Duration::from_secs(10), || pool.state().pooled == 2).await);
        let at_rest = wire.snapshot();
        assert_eq!(at_rest.startups, 2);
        println!(
            "[{}] two connects (startup + auth + init): {:?}",
            e.name, at_rest
        );

        // Checkout and return without a query: nothing on the wire.
        let before = wire.snapshot();
        for _ in 0..100 {
            drop(pool.get().await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let d = wire.snapshot().since(&before);
        assert_eq!(d.messages(), 0, "checkout/return is free: {d:?}");

        // One cached query per checkout: one exchange each after the Parse.
        let before = wire.snapshot();
        for i in 0..100i64 {
            let mut client = pool.get().await.unwrap();
            let _ = client.query_one("SELECT $1::int8", &[&i]).await.unwrap();
        }
        let d = wire.snapshot().since(&before);
        println!("[{}] 100 checkouts x 1 cached query: {:?}", e.name, d);
        assert!(d.parses <= 2);
        assert_eq!(d.binds, 100);
        assert_eq!(d.simple_queries, 0);
        assert_eq!(d.round_trips(), 100 + d.parses);
        pool.shutdown(Duration::from_secs(1)).await;

        // Opt-in probe: one empty query per checkout after the idle threshold.
        let app = format!("pt_probe_{}", e.name);
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = short(&app);
        config.max_size = 1;
        config.health_check = HealthCheck::AfterIdle(Duration::from_millis(100));
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();
        drop(pool.get().await.unwrap());
        let before = wire.snapshot();
        drop(pool.get().await.unwrap());
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(pool.get().await.unwrap());
        let d = wire.snapshot().since(&before);
        let stats = pool.state().stats;
        println!(
            "[{}] AfterIdle probe: {} probes, {:?} total, wire {:?}",
            e.name, stats.probes, stats.probe_time, d
        );
        assert_eq!(stats.probes, 1);
        assert_eq!(d.simple_queries, 1);
        pool.shutdown(Duration::from_secs(1)).await;

        // Reset policy evidence: DISCARD ALL round trip versus reconnect.
        let client = e.admin().await;
        let started = Instant::now();
        let mut discard_error = None;
        for _ in 0..20 {
            if let Err(err) = client.batch_execute("DISCARD ALL").await {
                discard_error = Some(err.to_string());
                break;
            }
        }
        let discard = started.elapsed() / 20;
        if let Some(err) = discard_error {
            println!("[{}] DISCARD ALL failed: {}", e.name, err);
        }
        let started = Instant::now();
        for _ in 0..5 {
            let (c, conn) = e.config().connect(NoTls).await.unwrap();
            let task = tokio::spawn(conn);
            drop(c);
            let _ = task.await;
        }
        let reconnect = started.elapsed() / 5;
        println!(
            "[{}] reset cost: DISCARD ALL {:?} per call (drops the statement cache), reconnect {:?}",
            e.name, discard, reconnect
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn realm_leases_follow_pool_lifecycle() {
    use yb_postgres_pool::yb_tokio_postgres::realm::Realm;
    let key = PoolKey::for_realm(&Realm::with_incarnation("r1", "inc-7"), "db", "app");
    assert_eq!((key.realm(), key.incarnation()), ("r1", Some("inc-7")));
    for e in engines() {
        let app = format!("pt_realm_{}", e.name);
        let admin = e.admin().await;
        let realm = Realm::new(format!("pool-test-{}", e.name));
        let mut pg = e.config();
        pg.realm(realm.clone());
        if e.name == "yb" {
            // The smart-driver path: discovery through yb_servers().
            pg.load_balance("true");
        }
        let leased = |r: &Realm| r.connection_counts().values().sum::<usize>();
        let mut config = short(&app);
        config.max_size = 3;
        let pool = Pool::new(pg, NoTls, config).unwrap();
        let mut held = [
            pool.get().await.unwrap(),
            pool.get().await.unwrap(),
            pool.get().await.unwrap(),
        ];
        let counted = leased(&realm);
        println!(
            "[{}] realm leases with 3 borrowed: {:?} (topology {:?})",
            e.name,
            realm.connection_counts(),
            realm.topology().map(|t| t.nodes().len())
        );
        if e.name == "yb" {
            assert_eq!(counted, 3);
        }
        assert!(counted == 3 || counted == 0, "{counted}");
        held[0].retire();
        drop(held);
        assert!(eventually(Duration::from_secs(5), || pool.state().physical == 2).await);
        if counted == 3 {
            assert_eq!(leased(&realm), 2, "a retired client releases its lease");
        }
        pool.shutdown(Duration::from_secs(1)).await;
        assert!(eventually(Duration::from_secs(5), || leased(&realm) == 0).await);
        assert_eq!(
            eventually_backends(&admin, &app, 0, Duration::from_secs(5)).await,
            0
        );
    }
}

#[cfg(feature = "rustls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_full_generation_retirement() {
    use yb_postgres_pool::yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
    use yb_postgres_pool::yb_tokio_postgres::Config;
    let (port, roots, wrong_roots) = match (
        std::env::var("POOL_TEST_TLS_PG"),
        std::env::var("POOL_TEST_TLS_ROOTS"),
    ) {
        (Ok(port), Ok(roots)) => {
            let wrong = std::path::Path::new(&roots).with_file_name("ca-b.crt");
            (
                port,
                std::fs::read(&roots).unwrap(),
                std::fs::read(wrong).unwrap(),
            )
        }
        _ => {
            assert!(
                !require(),
                "POOL_TEST_TLS_PG / POOL_TEST_TLS_ROOTS are not set"
            );
            eprintln!("skipping: no verify-full engine configured");
            return;
        }
    };
    let conninfo = format!(
        "host=localhost port={port} user=postgres password={PG_PASSWORD} dbname=postgres sslmode=verify-full"
    );
    let config: Config = conninfo.parse().unwrap();
    let material = TlsMaterial::from_pem(roots);
    // Separate connectors: the admin session must not share the pool's
    // generations (revocation below would close it too).
    let admin_tls = MakeRustlsConnect::new(&material, TlsOptions::new()).unwrap();
    let mut admin_config = config.clone();
    admin_config.application_name("pooltest_admin");
    let (admin, connection) = admin_config.connect(admin_tls).await.unwrap();
    tokio::spawn(connection);

    let tls = MakeRustlsConnect::new(&material, TlsOptions::new()).unwrap();
    let app = "pt_tls";
    let mut pool_config = short(app);
    pool_config.max_size = 2;
    let pool = Pool::new(config, tls.clone(), pool_config).unwrap();

    let client = pool.get().await.unwrap();
    assert_eq!(client.tls_generation(), Some(1));
    let p1 = backend_pid(&client).await;
    assert_eq!(
        text(
            &client,
            "SELECT ssl::text FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        )
        .await,
        "true"
    );
    drop(client);

    // Reload: the idle generation-1 session is refused at checkout.
    tls.reload(&material).unwrap();
    let client = pool.get().await.unwrap();
    assert_eq!(client.tls_generation(), Some(2));
    let p2 = backend_pid(&client).await;
    assert_ne!(p1, p2);
    assert_eq!(pool.state().stats.retired_superseded_tls, 1);
    assert_eq!(
        eventually_backends(&admin, app, 1, Duration::from_secs(5)).await,
        1
    );

    // Reload while borrowed: the superseded session keeps working for its
    // borrower and is retired on return.
    tls.reload(&material).unwrap();
    assert_eq!(text(&client, "SELECT 'still-usable'").await, "still-usable");
    drop(client);
    assert_eq!(pool.state().stats.retired_superseded_tls, 2);
    assert_eq!(
        eventually_backends(&admin, app, 0, Duration::from_secs(5)).await,
        0
    );

    // Revocation closes a borrowed session immediately.
    let client = pool.get().await.unwrap();
    assert_eq!(client.tls_generation(), Some(3));
    tls.reload(&material).unwrap();
    assert!(tls.revoke_superseded() >= 1);
    let raw = client.simple_query("SELECT 1").await.unwrap_err();
    let err = client.classify_error(raw);
    println!("revoked borrowed session: {} ({:?})", err, err.kind());
    assert_eq!(err.kind(), ErrorKind::Security, "{err}");
    drop(client);
    let client = pool.get().await.unwrap();
    assert_eq!(client.tls_generation(), Some(4));
    assert_eq!(text(&client, "SELECT 'fresh'").await, "fresh");
    drop(client);
    let stats = pool.state().stats;
    println!("verify-full pool stats: {stats:?}");
    pool.shutdown(Duration::from_secs(1)).await;
    assert_eq!(
        eventually_backends(&admin, app, 0, Duration::from_secs(5)).await,
        0
    );

    // A verification failure is a typed security error and ends the wait at
    // once instead of surfacing as an acquisition timeout.
    let wrong =
        MakeRustlsConnect::new(&TlsMaterial::from_pem(wrong_roots), TlsOptions::new()).unwrap();
    let mut wrong_config = short("pt_tls_wrong_ca");
    wrong_config.acquire_timeout = Duration::from_secs(8);
    let pool = Pool::new(conninfo.parse().unwrap(), wrong, wrong_config).unwrap();
    let started = Instant::now();
    let err = pool.get().await.unwrap_err();
    let took = started.elapsed();
    println!("wrong CA: {} ({:?}) after {:?}", err, err.kind(), took);
    assert_eq!(err.kind(), ErrorKind::Security, "{err}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    // Terminal: the pool does not retry it in the background.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(pool.state().stats.connect_failures, 1);
    pool.shutdown(Duration::from_secs(1)).await;
}
