//! Return-time session fingerprint (opt-in), the non-superuser role change
//! the protocol does not report, and what `DISCARD ALL`, `RESET SESSION
//! AUTHORIZATION`, `RESET ROLE` and `RESET ALL` do to a pool role. Every test
//! runs against each configured engine (PostgreSQL 16 and YugabyteDB
//! 2025.2); see `rig/run.sh`. Run with `--test-threads=1`.

mod common;

use common::*;
use std::time::Duration;
use yb_postgres_pool::yb_tokio_postgres::{Client, Config, NoTls, SimpleQueryMessage};
use yb_postgres_pool::{
    Pool, PoolConfig, PoolStats, SessionFingerprint, SessionInit, SessionParameters,
};

const LOGIN: &str = "pool_fp_login";
const ROLE_A: &str = "pool_fp_a";
const ROLE_B: &str = "pool_fp_b";
const SCHEMA: &str = "pool_fp_schema";

async fn text(client: &Client, sql: &str) -> String {
    for message in client.simple_query(sql).await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap_or("").to_string();
        }
    }
    panic!("no row for {sql}");
}

/// A non-superuser login that is a member of two non-superuser roles;
/// returns its configuration for `addr` (the engine or a proxy to it).
async fn non_superuser_login(e: &Engine, addr: std::net::SocketAddr) -> Config {
    let admin = e.admin().await;
    for (role, attributes) in [
        (LOGIN, format!("LOGIN NOSUPERUSER PASSWORD '{PG_PASSWORD}'")),
        (ROLE_A, "NOLOGIN NOSUPERUSER".to_string()),
        (ROLE_B, "NOLOGIN NOSUPERUSER".to_string()),
    ] {
        admin
            .batch_execute(&format!(
                "DO $$ BEGIN CREATE ROLE {role} {attributes}; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$"
            ))
            .await
            .unwrap();
    }
    admin
        .batch_execute(&format!(
            "GRANT {ROLE_A} TO {LOGIN}; GRANT {ROLE_B} TO {LOGIN}; \
             CREATE SCHEMA IF NOT EXISTS {SCHEMA}"
        ))
        .await
        .unwrap();
    let mut config = e.config_at(addr);
    config.user(LOGIN);
    config
}

fn role_pool_config(app: &str, init: SessionInit) -> PoolConfig {
    let mut config = pool_config(app);
    config.acquire_timeout = Duration::from_secs(5);
    config.max_size = 1;
    config.session.role = Some(ROLE_A.into());
    config.session.search_path = Some(vec![SCHEMA.into(), "public".into()]);
    config.session.init = init;
    config
}

/// The pool returns asynchronously when a fingerprint is checked; wait for
/// the connection to be back (or retired) before reading counters.
async fn settled<T: yb_postgres_pool::PoolTls>(pool: &Pool<T>) -> PoolStats {
    assert!(eventually(Duration::from_secs(5), || pool.state().borrowed == 0).await);
    pool.state().stats
}

/// Without a fingerprint, `SET ROLE` between two non-superuser roles is not
/// reported by the server, so the next borrower gets the changed role. (The
/// role case in `tests/pool.rs` is detected only because its login user is
/// a superuser and `is_superuser` is reported.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_superuser_role_change_is_not_reported() {
    for e in engines() {
        let pg = non_superuser_login(&e, e.addr).await;
        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_fp_role_{}_{:?}", e.name, init).to_lowercase();
            let pool = Pool::new(pg.clone(), NoTls, role_pool_config(&app, init)).unwrap();
            let pid = {
                let client = pool.get().await.unwrap();
                assert_eq!(text(&client, "SELECT current_user").await, ROLE_A);
                assert_eq!(text(&client, "SELECT session_user").await, LOGIN);
                assert_eq!(text(&client, "SHOW is_superuser").await, "off");
                client
                    .batch_execute(&format!("SET ROLE {ROLE_B}"))
                    .await
                    .unwrap();
                backend_pid(&client).await
            };
            {
                let client = pool.get().await.unwrap();
                let role = text(&client, "SELECT current_user").await;
                println!(
                    "[{}] {:?}: after SET ROLE {ROLE_B} without fingerprint the next borrower is {role} (same session: {})",
                    e.name,
                    init,
                    backend_pid(&client).await == pid
                );
                assert_eq!(backend_pid(&client).await, pid, "not retired");
                assert_eq!(role, ROLE_B, "the role change survived the lease");
            }
            let stats = settled(&pool).await;
            assert_eq!(stats.retired_dirty_session, 0, "{stats:?}");
            assert_eq!(stats.session_fingerprint_checks, 0, "{stats:?}");
            pool.shutdown(Duration::from_secs(1)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fingerprint_retires_unreported_session_changes() {
    for e in engines() {
        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_fp_check_{}_{:?}", e.name, init).to_lowercase();
            let (proxy_addr, wire) = proxy(e.addr).await;
            let pg = non_superuser_login(&e, proxy_addr).await;
            let mut config = role_pool_config(&app, init);
            config.session_fingerprint = Some(SessionFingerprint::new(["app.tenant"]));
            let pool = Pool::new(pg, NoTls, config).unwrap();

            // A clean return costs exactly one simple query and keeps the
            // session.
            let client = pool.get().await.unwrap();
            let pid = backend_pid(&client).await;
            let before = wire.snapshot();
            drop(client);
            let client = pool.get().await.unwrap();
            assert_eq!(backend_pid(&client).await, pid, "clean return kept");
            let cost = wire.snapshot().since(&before);
            assert_eq!(cost.simple_queries, 1, "{cost:?}");
            drop(client);
            let stats = settled(&pool).await;
            assert_eq!(stats.connects, 1, "{stats:?}");
            assert_eq!(stats.session_fingerprint_checks, 3, "{stats:?}");

            // Transaction-local state of a listed setting ends with the
            // transaction and does not trip the check.
            {
                let mut client = pool.get().await.unwrap();
                let mut tx = client.transaction().await.unwrap();
                tx.set_local("app.tenant", "tenant-a").await.unwrap();
                tx.commit().await.unwrap();
            }
            {
                let client = pool.get().await.unwrap();
                assert_eq!(
                    backend_pid(&client).await,
                    pid,
                    "SET LOCAL kept the session"
                );
                // The server now reads the placeholder as '' rather than
                // NULL, which is why the fingerprint compares unset as empty.
                assert_eq!(
                    text(
                        &client,
                        "SELECT pg_catalog.quote_nullable(current_setting('app.tenant', true))"
                    )
                    .await,
                    "''"
                );
            }

            // A rolled-back session change leaves the fingerprint intact.
            {
                let client = pool.get().await.unwrap();
                client
                    .batch_execute("BEGIN; SET search_path = public")
                    .await
                    .unwrap();
            }
            {
                let client = pool.get().await.unwrap();
                assert_eq!(backend_pid(&client).await, pid, "rolled back and kept");
            }
            let stats = settled(&pool).await;
            assert_eq!(stats.cleanup_rollbacks, 1, "{stats:?}");
            assert_eq!(stats.retired_session_fingerprint, 0, "{stats:?}");

            // Unreported session changes retire the session.
            let leaks = [
                format!("SET ROLE {ROLE_B}"),
                "SET ROLE NONE".to_string(),
                "SET search_path = public".to_string(),
                "SET row_security = off".to_string(),
                "SELECT pg_catalog.set_config('app.tenant', 'tenant-b', false)".to_string(),
            ];
            let mut pid = pid;
            for leak in &leaks {
                {
                    let client = pool.get().await.unwrap();
                    assert_eq!(backend_pid(&client).await, pid);
                    client.batch_execute(leak).await.unwrap();
                }
                let client = pool.get().await.unwrap();
                let next = backend_pid(&client).await;
                assert_ne!(next, pid, "{leak}: session retired");
                assert_eq!(text(&client, "SELECT current_user").await, ROLE_A);
                assert_eq!(
                    text(&client, "SELECT current_setting('search_path')")
                        .await
                        .replace(' ', ""),
                    format!("{SCHEMA},public")
                );
                assert_eq!(
                    text(&client, "SELECT current_setting('row_security')").await,
                    "on"
                );
                assert_eq!(
                    text(&client, "SELECT current_setting('app.tenant', true)").await,
                    ""
                );
                pid = next;
            }
            let stats = settled(&pool).await;
            assert_eq!(
                stats.retired_session_fingerprint,
                leaks.len() as u64,
                "{stats:?}"
            );

            // A session change before a transaction left open: cleanup rolls
            // the transaction back, then the fingerprint still differs.
            {
                let client = pool.get().await.unwrap();
                client
                    .batch_execute("SELECT pg_catalog.set_config('app.tenant', 'tenant-c', false)")
                    .await
                    .unwrap();
                client.batch_execute("BEGIN").await.unwrap();
            }
            {
                let client = pool.get().await.unwrap();
                assert_ne!(backend_pid(&client).await, pid, "retired after cleanup");
                assert_eq!(
                    text(&client, "SELECT current_setting('app.tenant', true)").await,
                    ""
                );
            }

            // After a session change and a reset, the next borrower gets
            // the pool's role and search_path: either the reset restored
            // them (the fingerprint matches) or the session is retired.
            for reset in ["DISCARD ALL", "RESET SESSION AUTHORIZATION", "RESET ROLE"] {
                let before = settled(&pool).await;
                let pid = {
                    let client = pool.get().await.unwrap();
                    client
                        .batch_execute(&format!("SET ROLE {ROLE_B}"))
                        .await
                        .unwrap();
                    client
                        .batch_execute("SET search_path = public")
                        .await
                        .unwrap();
                    client.batch_execute(reset).await.unwrap();
                    backend_pid(&client).await
                };
                let client = pool.get().await.unwrap();
                let user = text(&client, "SELECT current_user").await;
                let path = text(&client, "SELECT current_setting('search_path')")
                    .await
                    .replace(' ', "");
                let same = backend_pid(&client).await == pid;
                drop(client);
                let after = settled(&pool).await;
                let fingerprint =
                    after.retired_session_fingerprint - before.retired_session_fingerprint;
                let dirty = after.retired_dirty_session - before.retired_dirty_session;
                println!(
                    "[{}] {:?}: SET ROLE + SET search_path + {reset}: next borrower {user} {path} (same session: {same}; retired by fingerprint {fingerprint}, by ParameterStatus {dirty})",
                    e.name, init
                );
                assert_eq!(user, ROLE_A, "{reset}");
                assert_eq!(path, format!("{SCHEMA},public"), "{reset}");
                assert_eq!(same, fingerprint + dirty == 0, "{reset}: {after:?}");
            }

            let stats = settled(&pool).await;
            println!("[{}] {:?}: fingerprint stats {stats:?}", e.name, init);
            assert_eq!(stats.retired_cleanup_failed, 0, "{stats:?}");
            assert!(
                stats.retired_session_fingerprint > leaks.len() as u64,
                "{stats:?}"
            );
            pool.shutdown(Duration::from_secs(1)).await;
        }
    }
}

/// Measures what each reset statement does to a pool role, `search_path`
/// and a pool session parameter, for both initialization modes, with a
/// non-superuser login. Pins the documentation on `SessionParameters`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resets_versus_pool_session_defaults() {
    let mut all_failures = Vec::new();
    for e in engines() {
        let pg = non_superuser_login(&e, e.addr).await;
        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_fp_reset_{}_{:?}", e.name, init).to_lowercase();
            let mut config = role_pool_config(&app, init);
            config.session.parameters = SessionParameters::sqlx_parity();
            let pool = Pool::new(pg.clone(), NoTls, config).unwrap();
            let pool_path = format!("{SCHEMA},public");
            let mut failures = Vec::new();
            for reset in [
                "DISCARD ALL",
                "RESET SESSION AUTHORIZATION",
                "RESET ROLE",
                "RESET ALL",
            ] {
                let mut client = pool.get().await.unwrap();
                client.mark_session_dirty();
                for set in [
                    format!("SET ROLE {ROLE_B}"),
                    "SET search_path = public".to_string(),
                    "SET extra_float_digits = 0".to_string(),
                ] {
                    client.batch_execute(&set).await.unwrap();
                }
                client.batch_execute(reset).await.unwrap();
                let user = text(&client, "SELECT current_user").await;
                let session = text(&client, "SELECT session_user").await;
                let path = text(&client, "SELECT current_setting('search_path')")
                    .await
                    .replace(' ', "");
                let digits = text(&client, "SELECT current_setting('extra_float_digits')").await;
                println!(
                    "[{}] {:?}: after {reset}: current_user={user} session_user={session} search_path={path} extra_float_digits={digits}",
                    e.name, init
                );
                let startup = init == SessionInit::StartupOptions;
                let (want_user, want_path, want_digits) = match reset {
                    "DISCARD ALL" if startup => (ROLE_A, pool_path.as_str(), "2"),
                    "DISCARD ALL" => (LOGIN, "\"$user\",public", "1"),
                    "RESET SESSION AUTHORIZATION" if startup => (ROLE_A, "public", "0"),
                    "RESET SESSION AUTHORIZATION" => (LOGIN, "public", "0"),
                    "RESET ROLE" if startup => (ROLE_A, "public", "0"),
                    "RESET ROLE" => (LOGIN, "public", "0"),
                    "RESET ALL" if startup => (ROLE_B, pool_path.as_str(), "2"),
                    _ => (ROLE_B, "\"$user\",public", "1"),
                };
                if (user.as_str(), path.as_str(), digits.as_str())
                    != (want_user, want_path, want_digits)
                    || session != LOGIN
                {
                    failures.push(format!(
                        "{reset}: got ({user}, {session}, {path}, {digits}), want ({want_user}, {LOGIN}, {want_path}, {want_digits})"
                    ));
                }
            }
            pool.shutdown(Duration::from_secs(1)).await;
            all_failures.extend(
                failures
                    .into_iter()
                    .map(|f| format!("[{}] {:?}: {f}", e.name, init)),
            );
        }
    }
    assert!(all_failures.is_empty(), "{all_failures:#?}");
}

/// A return whose fingerprint task is dropped before it runs (its runtime
/// shut down) must not put an unverified session back in the pool.
#[test]
fn unverified_return_is_retired_when_its_task_never_runs() {
    let main = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    for e in engines() {
        let app = format!("pt_fp_unpolled_{}", e.name);
        let pg = main.block_on(non_superuser_login(&e, e.addr));
        let mut config = role_pool_config(&app, SessionInit::StartupOptions);
        config.session_fingerprint = Some(SessionFingerprint::default());
        let pool = main.block_on(async { Pool::new(pg, NoTls, config).unwrap() });
        let (client, pid) = main.block_on(async {
            let client = pool.get().await.unwrap();
            client
                .batch_execute(&format!("SET ROLE {ROLE_B}"))
                .await
                .unwrap();
            let pid = backend_pid(&client).await;
            (client, pid)
        });
        // Return on a runtime that never polls the return task, then shut
        // that runtime down.
        let short = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        {
            let _entered = short.enter();
            drop(client);
        }
        drop(short);
        main.block_on(async {
            let stats = settled(&pool).await;
            let client = pool.get().await.unwrap();
            let user = text(&client, "SELECT current_user").await;
            let same = backend_pid(&client).await == pid;
            println!(
                "[{}] unpolled return: next borrower {user} (same session: {same}), {stats:?}",
                e.name
            );
            assert_eq!(user, ROLE_A);
            assert!(!same, "unverified session retired");
            assert_eq!(stats.retired_cleanup_failed, 1, "{stats:?}");
            drop(client);
            pool.shutdown(Duration::from_secs(1)).await;
        });
    }
}
