//! AST-2293: pool-owned session parameters, the Prometheus export and the
//! readiness probe. Engine tests run against each configured engine (see
//! `rig/run.sh`); the others need none.

mod common;

use common::*;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use yb_postgres_pool::yb_tokio_postgres::{Client, NoTls, SimpleQueryMessage};
use yb_postgres_pool::{
    render_pools_prometheus, ConnectionLimiter, DateOrder, DateOutput, DateStyle, ErrorKind,
    PlanCacheMode, Pool, PoolConfig, SessionInit, SessionParameters,
};

async fn first(client: &Client, sql: &str) -> String {
    for message in client.simple_query(sql).await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap_or("").to_string();
        }
    }
    panic!("no row for {sql}");
}

async fn setting(client: &Client, name: &str) -> String {
    first(client, &format!("SELECT current_setting('{name}')")).await
}

fn parity(app: &str, init: SessionInit) -> PoolConfig {
    let mut config = pool_config(app);
    config.max_size = 1;
    config.session.parameters = SessionParameters::sqlx_parity();
    config.session.init = init;
    config
}

fn refused_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_parameters_apply_and_retire_on_change() {
    for e in engines() {
        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_parity_{}_{:?}", e.name, init).to_lowercase();
            let (addr, wire) = proxy(e.addr).await;
            let mut pg = e.config_at(addr);
            pg.options("-c work_mem=8MB");
            let pool = Pool::new(pg, NoTls, parity(&app, init)).unwrap();
            let pid = {
                let client = pool.get().await.unwrap();
                assert_eq!(setting(&client, "DateStyle").await, "ISO, MDY");
                assert_eq!(setting(&client, "TimeZone").await, "UTC");
                assert_eq!(setting(&client, "extra_float_digits").await, "2");
                assert_eq!(setting(&client, "work_mem").await, "8MB");
                assert_eq!(
                    first(
                        &client,
                        "SELECT '2024-03-01 12:00:00+02'::timestamptz::text"
                    )
                    .await,
                    "2024-03-01 10:00:00+00"
                );
                backend_pid(&client).await
            };
            let init_queries = u64::from(init == SessionInit::AfterConnect);
            assert_eq!(wire.snapshot().simple_queries, init_queries + 5);

            let client = pool.get().await.unwrap();
            assert_eq!(
                backend_pid(&client).await,
                pid,
                "the pool's parameters are the session baseline"
            );
            client
                .batch_execute("SET TimeZone = 'America/Chicago'")
                .await
                .unwrap();
            drop(client);

            let client = pool.get().await.unwrap();
            let replacement = backend_pid(&client).await;
            assert_ne!(replacement, pid, "a changed TimeZone retires the session");
            assert_eq!(setting(&client, "TimeZone").await, "UTC");
            drop(client);

            let stats = pool.state().stats;
            assert_eq!(stats.retired_dirty_session, 1, "{stats:?}");
            assert_eq!(stats.connects, 2, "{stats:?}");
            println!(
                "[{}] {:?}: parity applied, reused, retired after SET TimeZone",
                e.name, init
            );
            pool.shutdown(Duration::from_secs(1)).await;
        }

        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_parity_custom_{}_{:?}", e.name, init).to_lowercase();
            let mut config = pool_config(&app);
            config.session.init = init;
            config.session.parameters.date_style =
                Some(DateStyle::new(DateOutput::Sql, DateOrder::Dmy));
            config.session.parameters.time_zone = Some("Europe/Berlin".into());
            config.session.parameters.extra_float_digits = Some(0);
            config.session.parameters.plan_cache_mode = Some(PlanCacheMode::ForceCustomPlan);
            let pool = Pool::new(e.config(), NoTls, config).unwrap();
            let client = pool.get().await.unwrap();
            assert_eq!(setting(&client, "DateStyle").await, "SQL, DMY");
            assert_eq!(setting(&client, "TimeZone").await, "Europe/Berlin");
            assert_eq!(setting(&client, "extra_float_digits").await, "0");
            assert_eq!(
                setting(&client, "plan_cache_mode").await,
                "force_custom_plan"
            );
            assert!(
                first(
                    &client,
                    "SELECT '2024-03-01 12:00:00+00'::timestamptz::text"
                )
                .await
                .starts_with("01/03/2024 13:00:00"),
                "day-first SQL style in Europe/Berlin"
            );
            drop(client);
            pool.shutdown(Duration::from_secs(1)).await;
        }
    }
}

async fn direct(pg: &yb_postgres_pool::yb_tokio_postgres::Config) -> Result<Client, String> {
    match pg.connect(NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(connection);
            Ok(client)
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_applies_the_spellings_the_pool_rejects() {
    for e in engines() {
        for (options, name, value) in [
            ("-c TimeZone=America/Chicago", "TimeZone", "America/Chicago"),
            ("-cTimeZone=America/Chicago", "TimeZone", "America/Chicago"),
            ("--timezone=America/Chicago", "TimeZone", "America/Chicago"),
            (
                "-c Time\\Zone=America/Chicago",
                "TimeZone",
                "America/Chicago",
            ),
            ("--extra-float-digits=3", "extra_float_digits", "3"),
            ("-e", "DateStyle", "ISO, DMY"),
        ] {
            let mut pg = e.config();
            pg.options(options);
            let client = direct(&pg).await.unwrap();
            assert_eq!(
                setting(&client, name).await,
                value,
                "[{}] {options}",
                e.name
            );
            let err = Pool::new(
                pg,
                NoTls,
                parity("pt_spelling", SessionInit::StartupOptions),
            )
            .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config, "{options}: {err}");
        }
        let mut pg = e.config();
        pg.options("--time-zone=America/Chicago");
        let outcome = match direct(&pg).await {
            Ok(client) => {
                let zone = setting(&client, "TimeZone").await;
                assert_ne!(zone, "America/Chicago", "--time-zone set TimeZone");
                format!("accepted, TimeZone {zone}")
            }
            Err(err) => format!("refused: {err}"),
        };
        println!("[{}] --time-zone=America/Chicago: {outcome}", e.name);
        let pool = Pool::new(
            pg,
            NoTls,
            parity("pt_spelling", SessionInit::StartupOptions),
        )
        .unwrap();
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_parameters_win_over_role_defaults() {
    for e in engines() {
        let admin = e.admin().await;
        admin
            .batch_execute(&format!(
                "DO $$ BEGIN CREATE ROLE pool_parity_login LOGIN PASSWORD '{PG_PASSWORD}'; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
                 ALTER ROLE pool_parity_login SET TimeZone = 'America/Chicago'; \
                 ALTER ROLE pool_parity_login SET DateStyle = 'SQL, DMY'; \
                 ALTER ROLE pool_parity_login SET extra_float_digits = 0"
            ))
            .await
            .unwrap();
        let mut pg = e.config();
        pg.user("pool_parity_login");
        let plain = direct(&pg).await.unwrap();
        assert_eq!(setting(&plain, "TimeZone").await, "America/Chicago");
        assert_eq!(setting(&plain, "DateStyle").await, "SQL, DMY");
        assert_eq!(setting(&plain, "extra_float_digits").await, "0");
        drop(plain);

        for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
            let app = format!("pt_parity_role_{}_{:?}", e.name, init).to_lowercase();
            let pool = Pool::new(pg.clone(), NoTls, parity(&app, init)).unwrap();
            let client = pool.get().await.unwrap();
            assert_eq!(setting(&client, "TimeZone").await, "UTC", "{init:?}");
            assert_eq!(setting(&client, "DateStyle").await, "ISO, MDY", "{init:?}");
            assert_eq!(
                setting(&client, "extra_float_digits").await,
                "2",
                "{init:?}"
            );
            let pid = backend_pid(&client).await;

            client
                .batch_execute("SET extra_float_digits = 3; RESET ALL")
                .await
                .unwrap();
            let after_reset = (
                setting(&client, "TimeZone").await,
                setting(&client, "extra_float_digits").await,
            );
            drop(client);
            let next = backend_pid(&pool.get().await.unwrap()).await;
            match init {
                SessionInit::StartupOptions => {
                    assert_eq!(after_reset, ("UTC".into(), "2".into()));
                    assert_eq!(next, pid, "RESET ALL kept the pool's values");
                }
                _ => {
                    assert_eq!(after_reset, ("America/Chicago".into(), "0".into()));
                    assert_ne!(next, pid, "the reverted TimeZone retired the session");
                }
            }
            println!(
                "[{}] {:?} over role defaults: RESET ALL gives {:?}",
                e.name, init, after_reset
            );
            pool.shutdown(Duration::from_secs(1)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_options_cannot_override_session_parameters() {
    let addr = refused_addr();
    let parity_config = |init| {
        let mut config = PoolConfig::default();
        config.session.parameters = SessionParameters::sqlx_parity();
        config.session.init = init;
        config
    };
    for init in [SessionInit::StartupOptions, SessionInit::AfterConnect] {
        for options in [
            "-c TimeZone=PST8PDT",
            "-ctimezone=UTC",
            "--DateStyle=SQL",
            "--Extra-Float-Digits=3",
            "-c work_mem=8MB -e",
            "-c Time\\Zone=x",
            "-c statement_timeout=5 -c EXTRA_FLOAT_DIGITS=1",
        ] {
            let mut pg = unused_config(addr);
            pg.options(options);
            let err = Pool::new(pg, NoTls, parity_config(init)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config, "{options}: {err}");
        }
        let mut pg = unused_config(addr);
        pg.options("-c work_mem=8MB --plan_cache_mode=auto");
        let pool = Pool::new(pg, NoTls, parity_config(init)).unwrap();
        pool.shutdown(Duration::from_secs(1)).await;
    }
    let mut pg = unused_config(addr);
    pg.options("-c TimeZone=UTC");
    let pool = Pool::new(pg, NoTls, PoolConfig::default()).unwrap();
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_of_a_pool_that_cannot_connect() {
    let mut config = PoolConfig::default();
    config.connect_timeout = Duration::from_secs(2);
    config.acquire_timeout = Duration::from_secs(5);
    let pool = Pool::new(unused_config(refused_addr()), NoTls, config).unwrap();
    let err = pool.probe(Duration::from_secs(5)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    let state = pool.state();
    assert_eq!(state.stats.readiness_probes, 1);
    assert_eq!(state.stats.readiness_probe_failures, 1);
    assert_eq!(state.stats.checkouts, 0);
    assert!(state.stats.connect_failures >= 1, "{:?}", state.stats);
    assert_eq!(state.physical, 0);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_rejects_a_budget_below_the_query_floor() {
    let pool = Pool::new(unused_config(refused_addr()), NoTls, PoolConfig::default()).unwrap();
    for budget in [
        Duration::ZERO,
        Duration::from_micros(1000),
        Duration::from_micros(4999),
    ] {
        let err = pool.probe(budget).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{budget:?}: {err}");
    }
    let stats = pool.state().stats;
    assert_eq!(stats.readiness_probes, 0);
    assert_eq!(stats.connects + stats.connect_failures, 0);
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_times_out_while_connecting() {
    let addr = stall_listener().await;
    for max_size in [10, 1] {
        let mut config = PoolConfig::default();
        config.max_size = max_size;
        let pool = Pool::new(unused_config(addr), NoTls, config).unwrap();
        let started = Instant::now();
        let err = pool.probe(Duration::from_millis(300)).await.unwrap_err();
        let waited = started.elapsed();
        assert_eq!(
            err.kind(),
            ErrorKind::Transport,
            "a stalled connect is not saturation: {err}"
        );
        assert!(
            (Duration::from_millis(280)..Duration::from_millis(1500)).contains(&waited),
            "{waited:?}"
        );
        let stats = pool.state().stats;
        assert_eq!(stats.readiness_probes, 1);
        assert_eq!(stats.readiness_probe_failures, 1);
        assert_eq!(stats.acquire_timeouts, 1);
        assert!(stats.readiness_probe_time >= Duration::from_millis(280));
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_reuses_on_success_and_retires_on_timeout_or_drop() {
    for e in engines() {
        let app = format!("pt_probe_ready_{}", e.name);
        let (addr, wire) = proxy(e.addr).await;
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(addr), NoTls, config).unwrap();
        pool.probe(Duration::from_secs(5)).await.unwrap();
        pool.probe(Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            pool.state().stats.connects,
            1,
            "a passing probe keeps the client"
        );
        assert_eq!(wire.snapshot().simple_queries, 2);

        wire.freeze.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let err = pool.probe(Duration::from_millis(500)).await.unwrap_err();
        let waited = started.elapsed();
        assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
        assert!(
            (Duration::from_millis(480)..Duration::from_secs(2)).contains(&waited),
            "{waited:?}"
        );
        assert!(eventually(Duration::from_secs(5), || pool.state().physical == 0).await);
        wire.freeze.store(false, Ordering::SeqCst);

        pool.probe(Duration::from_secs(5)).await.unwrap();
        assert_eq!(pool.state().stats.connects, 2);

        wire.freeze.store(true, Ordering::SeqCst);
        let abandoned = tokio::time::timeout(
            Duration::from_millis(300),
            pool.probe(Duration::from_secs(5)),
        )
        .await;
        assert!(abandoned.is_err(), "the probe future was dropped mid-query");
        let stats = pool.state().stats;
        assert_eq!(stats.readiness_probes, 5, "{stats:?}");
        assert_eq!(stats.readiness_probe_failures, 2, "{stats:?}");
        assert!(stats.readiness_probe_time >= Duration::from_millis(780));
        assert!(eventually(Duration::from_secs(5), || pool.state().physical == 0).await);
        wire.freeze.store(false, Ordering::SeqCst);

        pool.probe(Duration::from_secs(5)).await.unwrap();
        let state = pool.state();
        let stats = &state.stats;
        assert_eq!(stats.readiness_probes, 6, "{stats:?}");
        assert_eq!(stats.readiness_probe_failures, 2, "{stats:?}");
        assert_eq!(stats.retired_probe_failed, 2, "{stats:?}");
        assert_eq!(stats.connects, 3, "{stats:?}");
        assert_eq!(stats.checkouts, 6, "{stats:?}");
        assert_eq!(stats.probes, 0, "{stats:?}");

        let text = state.render_prometheus("pt", &[("pool", "probe")]).unwrap();
        for line in [
            "pt_pool_probes_total{pool=\"probe\",kind=\"readiness\"} 6",
            "pt_pool_probe_failures_total{pool=\"probe\",kind=\"readiness\"} 2",
            "pt_pool_retirements_total{pool=\"probe\",reason=\"probe_failed\"} 2",
            "pt_pool_connects_total{pool=\"probe\"} 3",
            "pt_pool_checkouts_total{pool=\"probe\"} 6",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "{line} missing from\n{text}"
            );
        }
        println!(
            "[{}] readiness probe: {} probes, {} failed, {:?} total",
            e.name,
            stats.readiness_probes,
            stats.readiness_probe_failures,
            stats.readiness_probe_time
        );
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_reports_saturation_apart_from_failures() {
    for e in engines() {
        let app = format!("pt_probe_saturated_{}", e.name);
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let held = pool.get().await.unwrap();
        let err = pool.probe(Duration::from_millis(300)).await.unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::AcquireTimeout,
            "pool saturated: {err}"
        );
        drop(held);
        pool.probe(Duration::from_secs(5)).await.unwrap();
        assert_eq!(pool.state().stats.retired_probe_failed, 0);
        pool.shutdown(Duration::from_secs(1)).await;

        let limiter = ConnectionLimiter::new(1);
        let one = pool_config(&format!("{app}_l1"));
        let two = pool_config(&format!("{app}_l2"));
        let p1 = Pool::with_limiter(e.config(), NoTls, one, limiter.clone(), "l1").unwrap();
        let p2 = Pool::with_limiter(e.config(), NoTls, two, limiter.clone(), "l2").unwrap();
        let held = p1.get().await.unwrap();
        let err = p2.probe(Duration::from_millis(300)).await.unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::AcquireTimeout | ErrorKind::ProcessLimit
            ),
            "process limit saturated: {err}"
        );
        drop(held);
        p1.shutdown(Duration::from_secs(1)).await;
        p2.probe(Duration::from_secs(5)).await.unwrap();
        p2.shutdown(Duration::from_secs(1)).await;
        println!("[{}] saturated probes report {:?}", e.name, err.kind());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_keeps_saturation_through_a_hand_off() {
    for e in engines() {
        let app = format!("pt_probe_hand_off_{}", e.name);
        let (addr, _wire) = proxy_delayed(e.addr, Duration::from_millis(600)).await;
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(addr), NoTls, config).unwrap();
        let held = pool.get().await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let mut client = pool.get_within(Duration::from_secs(10)).await.unwrap();
                client.mark_session_dirty();
                tokio::time::sleep(Duration::from_millis(850)).await;
                drop(client);
            })
        };
        assert!(eventually(Duration::from_secs(5), || pool.state().waiting == 1).await);
        let probe = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.probe(Duration::from_secs(1)).await })
        };
        assert!(eventually(Duration::from_secs(5), || pool.state().waiting == 2).await);
        drop(held);
        let err = probe.await.unwrap().unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::AcquireTimeout,
            "saturated when the wait began, then handed off and replaced: {err}"
        );
        waiter.await.unwrap();
        println!("[{}] hand-off probe: {err}", e.name);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_blames_a_limiter_full_of_stalled_dials() {
    let stall = stall_listener().await;
    let limiter = ConnectionLimiter::new(1);
    let sibling = Pool::with_limiter(
        unused_config(stall),
        NoTls,
        PoolConfig::default(),
        limiter.clone(),
        "sibling",
    )
    .unwrap();
    let pending = {
        let sibling = sibling.clone();
        tokio::spawn(async move { sibling.get_within(Duration::from_secs(3)).await.is_ok() })
    };
    assert!(eventually(Duration::from_secs(2), || limiter.in_use() == 1).await);
    let pool = Pool::with_limiter(
        unused_config(refused_addr()),
        NoTls,
        PoolConfig::default(),
        limiter.clone(),
        "probed",
    )
    .unwrap();
    let err = pool.probe(Duration::from_millis(300)).await.unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::Transport,
        "the only permit is held by a stalled dial, not a connection: {err}"
    );
    let text = err.to_string();
    assert!(text.contains("no connection within 300ms"), "{text}");
    assert!(
        text.contains("1 of 1 process permits in use (1 dialing)"),
        "{text}"
    );
    assert_eq!(pool.state().stats.acquire_timeouts, 1);
    pending.abort();
    sibling.shutdown(Duration::from_secs(1)).await;
    pool.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prometheus_export_is_grouped_and_bounded() {
    let addr = stall_listener().await;
    let a = Pool::new(unused_config(addr), NoTls, PoolConfig::default()).unwrap();
    let b = Pool::new(unused_config(addr), NoTls, PoolConfig::default()).unwrap();
    assert!(a.probe(Duration::from_millis(50)).await.is_err());
    let (sa, sb) = (a.state(), b.state());
    let a_labels: &[(&str, &str)] = &[("service", "git-storage"), ("pool", "primary")];
    let b_labels: &[(&str, &str)] = &[("service", "git-storage"), ("pool", "q\"d\\\n")];
    let text = render_pools_prometheus("git_storage", &[(a_labels, &sa), (b_labels, &sb)]).unwrap();

    let mut families = HashSet::new();
    let mut current = String::new();
    let mut series = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split(' ');
            current = parts.next().unwrap().to_string();
            assert!(
                matches!(parts.next(), Some("gauge") | Some("counter")),
                "{line}"
            );
            assert!(families.insert(current.clone()), "{current} declared twice");
            continue;
        }
        let name = line.split(['{', ' ']).next().unwrap();
        assert_eq!(name, current, "series grouped under its family: {line}");
        assert!(name.starts_with("git_storage_pool_"), "{line}");
        let value = line.rsplit(' ').next().unwrap();
        assert!(value.parse::<f64>().is_ok(), "{line}");
        series += 1;
    }
    assert_eq!(families.len(), 30, "{text}");
    assert_eq!(series, 2 * 42, "{text}");
    for line in [
        "git_storage_pool_probes_total{pool=\"primary\",service=\"git-storage\",kind=\"readiness\"} 1",
        "git_storage_pool_probe_failures_total{pool=\"primary\",service=\"git-storage\",kind=\"readiness\"} 1",
        "git_storage_pool_acquire_timeouts_total{pool=\"primary\",service=\"git-storage\"} 1",
        "git_storage_pool_probes_total{pool=\"q\\\"d\\\\\\n\",service=\"git-storage\",kind=\"readiness\"} 0",
        "git_storage_pool_retirements_total{pool=\"primary\",service=\"git-storage\",reason=\"reaped\"} 0",
        "git_storage_pool_limiter_max_connections{pool=\"primary\",service=\"git-storage\"} 10",
    ] {
        assert!(text.lines().any(|l| l == line), "{line} missing from\n{text}");
    }
    assert_eq!(
        sa.render_prometheus("git_storage", a_labels).unwrap(),
        render_pools_prometheus("git_storage", &[(a_labels, &sa)]).unwrap()
    );
    assert!(sa
        .render_prometheus("ns", &[])
        .unwrap()
        .lines()
        .any(|l| l == "ns_pool_physical_connections 0"));
    assert_eq!(render_pools_prometheus("ns", &[]).unwrap(), "");
    let reordered: &[(&str, &str)] = &[("pool", "primary"), ("service", "git-storage")];
    assert_eq!(
        sa.render_prometheus("git_storage", reordered).unwrap(),
        sa.render_prometheus("git_storage", a_labels).unwrap()
    );
    let empty: &[(&str, &str)] = &[];
    for pools in [
        &[(a_labels, &sa), (a_labels, &sb)][..],
        &[(a_labels, &sa), (reordered, &sb)][..],
        &[(empty, &sa), (empty, &sb)][..],
    ] {
        let err = render_pools_prometheus("git_storage", pools).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    }
    a.shutdown(Duration::from_secs(1)).await;
    b.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prometheus_export_rejects_unbounded_label_names() {
    let pool = Pool::new(unused_config(refused_addr()), NoTls, PoolConfig::default()).unwrap();
    let state = pool.state();
    for labels in [
        &[("reason", "x")][..],
        &[("kind", "x")][..],
        &[("__name__", "x")][..],
        &[("bad-name", "x")][..],
        &[("pool", "a"), ("pool", "b")][..],
    ] {
        let err = state.render_prometheus("ns", labels).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{labels:?}: {err}");
    }
    for namespace in ["", "9ns", "a-b", "a:b"] {
        let err = state.render_prometheus(namespace, &[]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{namespace:?}: {err}");
    }
    pool.shutdown(Duration::from_secs(1)).await;
}
