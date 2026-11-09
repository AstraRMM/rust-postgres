//! AST-2133 real-engine qualification of semantic wire observation.
//!
//! Every count is checked against at least one independent oracle: the
//! parsing [`Proxy`] (actual frames on the wire) and, on PostgreSQL, the
//! server log (`log_min_duration_statement = 0`) or `pg_stat_statements`,
//! on YugabyteDB `pg_stat_statements`. Requires the rig from
//! `wire-qualification/rig/run.sh`. Tests share process-wide totals, so they
//! serialize on one lock.

use futures_util::{future, pin_mut, TryStreamExt};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use wire_qualification::{env, open, pg_config, server_log, settle, statement_calls, Proxy, Tally};
use yb_tokio_postgres::config::{SslMode, TargetSessionAttrs};
use yb_tokio_postgres::error::SqlState;
use yb_tokio_postgres::observe::{self, Class, ClassCounts, Counts, SocketRole};
use yb_tokio_postgres::{Client, Config, NoTls};

fn serial() -> &'static Mutex<()> {
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| Mutex::new(()))
}

fn pg_addr() -> SocketAddr {
    env("WQ_PG_ADDR").parse().unwrap()
}

fn yb_addr() -> SocketAddr {
    env("WQ_YB_ADDR").parse().unwrap()
}

async fn pg_admin() -> Arc<Client> {
    let (client, _task) = open(&pg_config(pg_addr().port(), "wq_admin"))
        .await
        .unwrap();
    Arc::new(client)
}

fn yb_config(addr: SocketAddr, app: &str) -> Config {
    let mut config = Config::new();
    config
        .host(&addr.ip().to_string())
        .port(addr.port())
        .user("yugabyte")
        .dbname("yugabyte")
        .application_name(app)
        .ssl_mode(SslMode::Disable);
    config
}

async fn yb_admin() -> Arc<Client> {
    let (client, _task) = open(&yb_config(yb_addr(), "wq_admin")).await.unwrap();
    Arc::new(client)
}

/// The driver's counts must equal what the proxy saw on the wire.
#[track_caller]
fn assert_wire(name: &str, c: &ClassCounts, wire: &Tally) {
    let pairs = [
        ("Query", c.query_messages, wire.fe('Q')),
        ("Parse", c.parse_messages, wire.fe('P')),
        ("Bind", c.bind_messages, wire.fe('B')),
        ("Describe", c.describe_messages, wire.fe('D')),
        ("Execute", c.execute_messages, wire.fe('E')),
        ("Close", c.close_messages, wire.fe('C')),
        ("Sync", c.sync_messages, wire.fe('S')),
        ("CopyData", c.copy_data_messages, wire.fe('d')),
        ("CopyDone", c.copy_done_messages, wire.fe('c')),
        ("ReadyForQuery", c.cycles_completed, wire.be('Z')),
        ("ErrorResponse", c.error_responses, wire.be('E')),
        (
            "protocol bytes sent",
            c.protocol_bytes_sent,
            wire.frontend_request_bytes,
        ),
        (
            "protocol bytes received",
            c.protocol_bytes_received,
            wire.backend_request_bytes,
        ),
        (
            "transaction cycles",
            c.transaction_cycles,
            wire.ready_after_transaction,
        ),
        (
            "failed transaction cycles",
            c.failed_transaction_cycles,
            wire.ready_after_failed,
        ),
    ];
    for (what, driver, oracle) in pairs {
        assert_eq!(
            driver, oracle,
            "{name}: {what}: driver {driver} != wire {oracle}\n{c:#?}\n{wire:#?}"
        );
    }
    println!(
        "WIRE-MATCH {name}: cycles={} messages={} bytes_sent={} bytes_received={}",
        c.cycles_completed,
        c.messages(),
        c.protocol_bytes_sent,
        c.protocol_bytes_received
    );
}

fn print_counts(name: &str, counts: &Counts) {
    for class in Class::ALL {
        let c = counts.class(class);
        if *c != ClassCounts::default() {
            let fields: Vec<String> = c
                .iter()
                .filter(|(_, v)| *v != 0)
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            println!("COUNTS {name} {}: {}", class.label(), fields.join(" "));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_counts_match_wire_and_server_log() {
    let _serial = serial().lock().await;
    let admin = pg_admin().await;
    let proxy = Proxy::start(pg_addr()).await;
    let app = "wq_basic";
    let (mut client, _task) = open(&pg_config(proxy.port, app)).await.unwrap();
    let wire_before = settle(&proxy).await;
    let log_before = server_log(&admin, app).await;

    let ((), counts) = observe::scope("wq.basic", async {
        let stmt = client.prepare("select $1::int4 + 1").await.unwrap();
        for i in 0..3i32 {
            let row = client.query_one(&stmt, &[&i]).await.unwrap();
            assert_eq!(row.get::<_, i32>(0), i + 1);
        }
        client
            .execute(
                "create temp table wq_basic (id int4 primary key, v text)",
                &[],
            )
            .await
            .unwrap();
        client.simple_query("select 1; select 2").await.unwrap();
        client
            .batch_execute("insert into wq_basic values (1, 'a')")
            .await
            .unwrap();
        // floor(random()) is volatile, so the division runs at Execute (a
        // constant divisor already fails at Bind, while planning).
        let err = client
            .query("select 1 / (floor(random())::int4 + $1::int4)", &[&0i32])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some(&SqlState::DIVISION_BY_ZERO));
        let tx = client.transaction().await.unwrap();
        tx.execute("insert into wq_basic values (2, 'b')", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(stmt);
        client.simple_query("select 'barrier'").await.unwrap();
    })
    .await;
    let wire = settle(&proxy).await.since(&wire_before);
    let log = server_log(&admin, app).await.since(&log_before);
    print_counts("basic", &counts);
    println!("LOG basic: {log:?}");

    assert!(counts.is_complete(), "{counts:#?}");
    assert_eq!(counts.detached_pending_cycles(), 0);
    let total = counts.total();
    assert_wire("pg basic", &total, &wire);

    // Backend evidence: what the server actually processed.
    assert_eq!(log.parse, total.parse_messages, "server parse lines");
    assert_eq!(log.bind, total.bind_messages, "server bind lines");
    assert_eq!(
        log.execute + log.error_total(),
        total.execute_messages,
        "server execute lines + errors"
    );
    assert_eq!(
        log.statement, total.query_messages,
        "server simple statement lines"
    );
    assert_eq!(log.errors.get("22012"), Some(&1));

    // The exact protocol budget of this sequence.
    let request = counts.class(Class::Request);
    let preparation = counts.class(Class::Preparation);
    assert_eq!(request.operations, 11);
    assert_eq!(preparation.operations, 1);
    assert_eq!(request.cycles_completed, 11);
    assert_eq!(preparation.cycles_completed, 8);
    assert_eq!(preparation.detached_cycles_queued, 4);
    assert_eq!(preparation.parse_messages, 4);
    assert_eq!(total.bind_messages, 6);
    assert_eq!(total.close_messages, 4);
    assert_eq!(total.query_messages, 5);
    assert_eq!(total.error_responses, 1);
    assert_eq!(total.transaction_cycles, 4);
    assert_eq!(total.cycles_abandoned, 0);
    client.__private_api_close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_rollbacks_are_counted_and_backed_by_the_server() {
    let _serial = serial().lock().await;
    let admin = pg_admin().await;
    let proxy = Proxy::start(pg_addr()).await;
    let app = "wq_rollback";
    let (mut client, _task) = open(&pg_config(proxy.port, app)).await.unwrap();
    client
        .batch_execute("create temp table wq_rollback (id int4)")
        .await
        .unwrap();
    let wire_before = settle(&proxy).await;
    let log_before = server_log(&admin, app).await;

    let ((), counts) = observe::scope("wq.rollback", async {
        {
            let tx = client.transaction().await.unwrap();
            tx.batch_execute("insert into wq_rollback values (1)")
                .await
                .unwrap();
            // Dropped: automatic ROLLBACK.
        }
        {
            let tx = client.transaction().await.unwrap();
            tx.batch_execute("insert into wq_rollback values (2)")
                .await
                .unwrap();
            tx.rollback().await.unwrap();
        }
        {
            let tx = client.transaction().await.unwrap();
            let err = tx.batch_execute("select 1 / 0").await.unwrap_err();
            assert_eq!(err.code(), Some(&SqlState::DIVISION_BY_ZERO));
            // Dropped inside a failed transaction block.
        }
        client.simple_query("select 'barrier'").await.unwrap();
    })
    .await;
    let wire = settle(&proxy).await.since(&wire_before);
    let log = server_log(&admin, app).await.since(&log_before);
    print_counts("rollback", &counts);
    println!("LOG rollback: {log:?}");

    let rows: i64 = client
        .query_one("select count(*) from wq_rollback", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "every transaction was rolled back on the server");

    assert!(counts.is_complete(), "{counts:#?}");
    let total = counts.total();
    assert_wire("pg rollback", &total, &wire);
    assert_eq!(total.rollbacks, 3);
    assert_eq!(total.automatic_rollbacks, 2);
    assert_eq!(total.failed_transaction_cycles, 1);
    // A failed simple statement is logged as its error, not its duration.
    assert_eq!(log.statement + log.error_total(), total.query_messages);
    assert_eq!(log.errors.get("22012"), Some(&1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_cancellation_dropped_futures_and_killed_sessions() {
    let _serial = serial().lock().await;
    let admin = pg_admin().await;
    let proxy = Proxy::start(pg_addr()).await;
    let app = "wq_cancel";
    let (client, _task) = open(&pg_config(proxy.port, app)).await.unwrap();
    let sleep = client.prepare("select pg_sleep($1::float8)").await.unwrap();

    // 1. A cancel request sent from a spawned task carrying the scope.
    let wire_before = settle(&proxy).await;
    let log_before = server_log(&admin, app).await;
    let sockets_before = *observe::totals().sockets(SocketRole::Cancel);
    let token = client.cancel_token();
    let ((), counts) = observe::scope("wq.cancel", async {
        let handle = observe::current().expect("inside a scope");
        let canceller = tokio::spawn(handle.attach(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            token.cancel_query(NoTls).await
        }));
        let err = client.query(&sleep, &[&30.0f64]).await.unwrap_err();
        assert_eq!(err.code(), Some(&SqlState::QUERY_CANCELED));
        canceller.await.unwrap().unwrap();
    })
    .await;
    let wire = settle(&proxy).await.since(&wire_before);
    let log = server_log(&admin, app).await.since(&log_before);
    let sockets = *observe::totals().sockets(SocketRole::Cancel);
    print_counts("cancel", &counts);
    let total = counts.total();
    assert!(counts.is_complete(), "{counts:#?}");
    assert_eq!(total.cancel_requests, 1);
    assert_eq!(total.cancel_requests, wire.cancel_requests);
    assert_eq!(total.error_responses, 1);
    assert_eq!(
        log.errors.get("57014"),
        Some(&1),
        "server cancelled the statement"
    );
    assert_eq!(sockets.opened - sockets_before.opened, 1);
    assert_eq!(
        sockets.plaintext_bytes_sent - sockets_before.plaintext_bytes_sent,
        16
    );
    assert_wire("pg cancel", &total, &wire);

    // 2. A request future dropped mid-flight: the scope ends incomplete and
    // the exchange completes late, still owned by that scope.
    let before = observe::totals();
    let (result, counts) = observe::scope(
        "wq.dropped",
        tokio::time::timeout(Duration::from_millis(200), client.query(&sleep, &[&1.0f64])),
    )
    .await;
    assert!(
        result.is_err(),
        "the query future was dropped by the timeout"
    );
    assert!(!counts.is_complete());
    assert_eq!(counts.pending_cycles(), 1);
    client
        .simple_query("select 'after the dropped request'")
        .await
        .unwrap();
    let after = observe::totals();
    assert_eq!(after.late_completed - before.late_completed, 1);
    assert_eq!(
        after.scoped(Class::Request).cycles_completed
            - before.scoped(Class::Request).cycles_completed,
        1,
        "the late completion is attributed to its scope, not to the unscoped barrier"
    );

    // 3. A session killed by the server while a request is in flight.
    let victim_app = "wq_killed";
    let (victim, victim_task) = open(&pg_config(proxy.port, victim_app)).await.unwrap();
    let pid: i32 = victim
        .query_one("select pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let log_before = server_log(&admin, victim_app).await;
    let killer = admin.clone();
    let ((), counts) = observe::scope("wq.killed", async {
        // Not attached: the killer's own SQL is not this scope's.
        let kill = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            killer
                .execute("select pg_terminate_backend($1)", &[&pid])
                .await
                .unwrap();
        });
        let err = victim.query("select pg_sleep(30)", &[]).await.unwrap_err();
        assert_eq!(err.code(), Some(&SqlState::ADMIN_SHUTDOWN), "{err:?}");
        let _ = victim_task.await;
        kill.await.unwrap();
    })
    .await;
    let log = server_log(&admin, victim_app).await.since(&log_before);
    print_counts("killed", &counts);
    let total = counts.total();
    assert!(!counts.is_complete());
    assert_eq!(total.error_responses, 1);
    assert_eq!(
        total.cycles_completed, 1,
        "only the preparation cycle completed"
    );
    assert_eq!(
        total.cycles_abandoned, 2,
        "the execution and the detached close"
    );
    assert_eq!(total.pending_cycles(), 0);
    assert_eq!(log.fatal, 1, "server terminated the session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attribution_is_isolated_and_follows_the_issuer() {
    let _serial = serial().lock().await;
    let proxy = Proxy::start(pg_addr()).await;
    let (client, _task) = open(&pg_config(proxy.port, "wq_attribution"))
        .await
        .unwrap();
    let client = Arc::new(client);
    let stmt = client.prepare("select $1::int4").await.unwrap();

    // Pipelined scopes sharing one connection keep their own counts.
    let wire_before = settle(&proxy).await;
    let run = |n: i32| {
        let client = client.clone();
        let stmt = stmt.clone();
        async move {
            for i in 0..n {
                client.query_one(&stmt, &[&i]).await.unwrap();
            }
        }
    };
    let (((), a), ((), b)) = future::join(
        observe::scope("wq.a", run(5)),
        observe::scope("wq.b", run(3)),
    )
    .await;
    let wire = settle(&proxy).await.since(&wire_before);
    assert_eq!(a.class(Class::Request).cycles_completed, 5);
    assert_eq!(b.class(Class::Request).cycles_completed, 3);
    assert!(a.is_complete() && b.is_complete());
    assert_eq!(wire.be('Z'), 8);
    let mut both = a.total();
    both.merge(&b.total());
    assert_wire("pipelined scopes", &both, &wire);

    // Unscoped work is background.
    let before = observe::totals();
    client.query_one(&stmt, &[&1i32]).await.unwrap();
    client.query_one(&stmt, &[&2i32]).await.unwrap();
    let after = observe::totals();
    assert_eq!(
        after.unscoped(Class::Request).cycles_completed
            - before.unscoped(Class::Request).cycles_completed,
        2
    );

    // Spawned tasks only count when the context is attached.
    let before = observe::totals();
    let ((), counts) = observe::scope("wq.spawn", async {
        let (c1, s1) = (client.clone(), stmt.clone());
        tokio::spawn(async move { c1.query_one(&s1, &[&1i32]).await.unwrap() })
            .await
            .unwrap();
        let (c2, s2) = (client.clone(), stmt.clone());
        let handle = observe::current().unwrap();
        tokio::spawn(handle.attach(async move { c2.query_one(&s2, &[&2i32]).await.unwrap() }))
            .await
            .unwrap();
        assert_eq!(observe::current_route(), Some("wq.spawn"));
    })
    .await;
    let after = observe::totals();
    assert_eq!(counts.class(Class::Request).cycles_completed, 1);
    assert_eq!(
        after.unscoped(Class::Request).cycles_completed
            - before.unscoped(Class::Request).cycles_completed,
        1
    );

    // A row stream consumed after its scope ended completes late, owned by
    // the issuing scope.
    let series = client
        .prepare("select generate_series(1, $1::int4)")
        .await
        .unwrap();
    let before = observe::totals();
    let (stream, counts) = observe::scope("wq.stream", async {
        client
            .query_raw(
                &series,
                [&200_000i32 as &(dyn yb_tokio_postgres::types::ToSql + Sync)],
            )
            .await
            .unwrap()
    })
    .await;
    assert_eq!(counts.pending_cycles(), 1, "{counts:#?}");
    pin_mut!(stream);
    let mut rows = 0;
    while stream.try_next().await.unwrap().is_some() {
        rows += 1;
    }
    assert_eq!(rows, 200_000);
    let after = observe::totals();
    assert_eq!(after.late_completed - before.late_completed, 1);
    assert_eq!(
        after.unscoped(Class::Request).cycles_completed,
        before.unscoped(Class::Request).cycles_completed
    );

    // Nested scopes are independent; classes and acquisitions are separate.
    let ((inner, ()), outer) = observe::scope("wq.outer", async {
        let inner = observe::scope("wq.inner", async {
            client.query_one(&stmt, &[&1i32]).await.unwrap();
        })
        .await
        .1;
        client.query_one(&stmt, &[&2i32]).await.unwrap();
        observe::note_acquisition();
        observe::with_class(Class::HealthCheck, client.simple_query("select 1"))
            .await
            .unwrap();
        (inner, ())
    })
    .await;
    assert_eq!(inner.class(Class::Request).cycles_completed, 1);
    assert_eq!(outer.class(Class::Request).cycles_completed, 1);
    assert_eq!(outer.class(Class::Request).acquisitions, 1);
    assert_eq!(outer.class(Class::HealthCheck).cycles_completed, 1);
    assert_eq!(outer.class(Class::HealthCheck).operations, 1);
    assert_eq!(outer.route(), "wq.outer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_setup_and_preparation_are_separate_classes() {
    let _serial = serial().lock().await;
    let admin = pg_admin().await;
    admin
        .batch_execute(
            "do $$ begin create type wq_mood as enum ('calm', 'busy'); \
             exception when duplicate_object then null; end $$",
        )
        .await
        .unwrap();
    let proxy = Proxy::start(pg_addr()).await;

    // Connecting inside a scope: startup and the read-write check are setup.
    let app = "wq_setup";
    let mut config = pg_config(proxy.port, app);
    config.target_session_attrs(TargetSessionAttrs::ReadWrite);
    let wire_before = settle(&proxy).await;
    let sockets_before = *observe::totals().sockets(SocketRole::Data);
    let ((client, _task), counts) =
        observe::scope("wq.setup", async { open(&config).await.unwrap() }).await;
    let wire = settle(&proxy).await.since(&wire_before);
    let sockets = *observe::totals().sockets(SocketRole::Data);
    print_counts("setup", &counts);
    let setup = counts.class(Class::SessionSetup);
    assert!(counts.is_complete());
    assert_eq!(setup.sessions_started, 1);
    assert_eq!(setup.operations, 1);
    assert_eq!(setup.cycles_completed, 1);
    assert_eq!(*counts.class(Class::Request), ClassCounts::default());
    assert_eq!(wire.startups, 1);
    assert_eq!(wire.startup_ready, 1);
    assert_wire("session setup", setup, &wire);
    assert_eq!(sockets.opened - sockets_before.opened, 1);
    assert_eq!(
        sockets.plaintext_bytes_sent - sockets_before.plaintext_bytes_sent,
        wire.client_bytes
    );
    assert_eq!(
        sockets.plaintext_bytes_received - sockets_before.plaintext_bytes_received,
        wire.server_bytes
    );

    // A failed authentication is a session failure, confirmed by the server.
    let bad_app = "wq_badauth";
    let mut bad = pg_config(proxy.port, bad_app);
    bad.password("wq-not-the-password");
    // The application name is not known to the server log before
    // authentication completes, so read every session's lines.
    let log_before = server_log(&admin, "*").await;
    let (result, counts) = observe::scope("wq.badauth", open(&bad)).await;
    let err = result.expect_err("authentication must fail");
    assert_eq!(err.code(), Some(&SqlState::INVALID_PASSWORD));
    assert_eq!(counts.class(Class::SessionSetup).session_failures, 1);
    assert_eq!(counts.class(Class::SessionSetup).sessions_started, 0);
    let log = server_log(&admin, "*").await.since(&log_before);
    assert_eq!(log.fatal_codes.get("28P01"), Some(&1), "{log:?}");

    // Preparation, including the type lookups it triggers, is attributed to
    // preparation and not to the request.
    let wire_before = settle(&proxy).await;
    let (stmt, counts) = observe::scope("wq.prepare", client.prepare("select $1::wq_mood")).await;
    let wire = settle(&proxy).await.since(&wire_before);
    stmt.unwrap();
    print_counts("prepare", &counts);
    let preparation = counts.class(Class::Preparation);
    assert!(counts.is_complete());
    assert_eq!(preparation.operations, 1);
    assert_eq!(
        preparation.cycles_completed, 5,
        "prepare + typeinfo prepare/query + enum prepare/query"
    );
    assert_eq!(*counts.class(Class::Request), ClassCounts::default());
    assert_wire("preparation", preparation, &wire);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yb_discovery_is_attributed_and_backed_by_pg_stat_statements() {
    let _serial = serial().lock().await;
    let admin = yb_admin().await;
    let mut config = yb_config(yb_addr(), "wq_discovery");
    config
        .load_balance("true")
        .yb_servers_refresh_interval(Duration::from_secs(0));
    let calls_before = statement_calls(&admin, "%yb_servers()%").await;
    let before = observe::totals();
    let ((client, _task), counts) =
        observe::scope("wq.discovery", async { open(&config).await.unwrap() }).await;
    let after = observe::totals();
    let calls = statement_calls(&admin, "%yb_servers()%").await - calls_before;
    print_counts("discovery", &counts);
    let discovery = counts.class(Class::Discovery);
    let setup = counts.class(Class::SessionSetup);
    assert!(counts.is_complete(), "{counts:#?}");
    assert_eq!(discovery.sessions_started, 1, "one control connection");
    assert_eq!(discovery.operations, 1);
    assert_eq!(discovery.parse_messages, 1);
    assert_eq!(discovery.execute_messages, 1);
    // The returned rows keep the statement alive until the control
    // connection is closed, so its Close is never sent: two cycles.
    assert_eq!(discovery.cycles_completed, 2, "prepare and execute");
    assert_eq!(discovery.close_messages, 0);
    assert_eq!(calls, 1, "the server executed yb_servers() once");
    assert_eq!(setup.sessions_started, 1, "one data connection");
    assert_eq!(*counts.class(Class::Request), ClassCounts::default());
    let sockets = |t: &observe::Totals, role| t.sockets(role).opened;
    assert_eq!(
        sockets(&after, SocketRole::Discovery) - sockets(&before, SocketRole::Discovery),
        1
    );
    assert_eq!(
        sockets(&after, SocketRole::Data) - sockets(&before, SocketRole::Data),
        1
    );
    assert!(client.node_identity().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yb_statements_errors_and_retries_match_wire_and_backend() {
    let _serial = serial().lock().await;
    let admin = yb_admin().await;
    let proxy = Proxy::start(yb_addr()).await;
    let (mut client, _task) = open(&yb_config(
        SocketAddr::new("127.0.0.1".parse().unwrap(), proxy.port),
        "wq_yb",
    ))
    .await
    .unwrap();
    let table = format!("wq_yb_{}", std::process::id());
    client
        .batch_execute(&format!(
            "drop table if exists {table}; create table {table} (k int4 primary key, v text)"
        ))
        .await
        .unwrap();
    let insert = client
        .prepare(&format!("insert into {table} values ($1, $2)"))
        .await
        .unwrap();
    let like = format!("insert into {table}%");
    let calls_before = statement_calls(&admin, &like).await;
    let wire_before = settle(&proxy).await;

    let (successes, counts) = observe::scope("wq.yb", async {
        let mut successes = 0;
        for k in 0..5i32 {
            client.execute(&insert, &[&k, &"v"]).await.unwrap();
            successes += 1;
        }
        let tx = client.transaction().await.unwrap();
        tx.execute(&insert, &[&10i32, &"t"]).await.unwrap();
        tx.execute(&insert, &[&11i32, &"t"]).await.unwrap();
        tx.commit().await.unwrap();
        successes += 2;
        // A consumer-level retry: the first attempt conflicts, the retry
        // uses a fresh key.
        let mut key = 0i32;
        loop {
            match client.execute(&insert, &[&key, &"retry"]).await {
                Ok(_) => break,
                Err(e) => {
                    assert_eq!(e.code(), Some(&SqlState::UNIQUE_VIOLATION));
                    key = 100;
                }
            }
        }
        successes += 1;
        client.simple_query("select 'barrier'").await.unwrap();
        successes
    })
    .await;
    let wire = settle(&proxy).await.since(&wire_before);
    let calls = statement_calls(&admin, &like).await - calls_before;
    print_counts("yb", &counts);
    let total = counts.total();
    assert!(counts.is_complete(), "{counts:#?}");
    assert_wire("yb statements", &total, &wire);
    assert_eq!(
        calls, successes,
        "pg_stat_statements counts each successful execution"
    );
    assert_eq!(
        total.execute_messages as i64,
        successes + 1,
        "plus the failed attempt"
    );
    assert_eq!(total.error_responses, 1);
    assert_eq!(counts.class(Class::Request).operations, 5 + 4 + 2 + 1);
    assert_eq!(total.transaction_cycles, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_socket_bytes_are_encrypted_and_separate_from_protocol_bytes() {
    use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
    let _serial = serial().lock().await;
    let ca =
        std::fs::read(std::path::Path::new(&env("TLS_QUAL_FIXTURES")).join("ca-a.crt")).unwrap();
    let tls = MakeRustlsConnect::new(&TlsMaterial::from_pem(ca), TlsOptions::new()).unwrap();
    let upstream = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        env("WQ_PG_TLS_PORT").parse().unwrap(),
    );
    let proxy = Proxy::start(upstream).await;
    let mut config = Config::new();
    config
        .host("localhost")
        .hostaddr("127.0.0.1".parse().unwrap())
        .port(proxy.port)
        .user("postgres")
        .password(env("WQ_PG_PASSWORD"))
        .dbname("postgres")
        .application_name("wq_tls")
        .ssl_mode(SslMode::VerifyFull);

    let before = *observe::totals().sockets(SocketRole::Data);
    let wire_before = proxy.tally();
    let (client, connection) = config.connect(tls).await.unwrap();
    assert!(connection.tls_stream().is_some());
    let task = tokio::spawn(connection);
    let ((), counts) = observe::scope("wq.tls", async {
        let ssl: bool = client
            .query_one(
                "select ssl from pg_stat_ssl where pid = pg_backend_pid()",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(ssl, "the server reports the session as TLS");
        for i in 0..20i32 {
            client
                .query_one("select $1::int4, repeat('x', 512)", &[&i])
                .await
                .unwrap();
        }
    })
    .await;
    // Measure while the session is idle: every byte either side sent has
    // been read by the other. (After Terminate the server's close_notify is
    // never read by the client.)
    let wire = settle(&proxy).await.since(&wire_before);
    let after = *observe::totals().sockets(SocketRole::Data);
    drop(client);
    task.await.unwrap().unwrap();
    let total = counts.total();
    println!(
        "TLS bytes: protocol sent={} received={}; socket encrypted sent={} received={}; plaintext sent={} received={}",
        total.protocol_bytes_sent,
        total.protocol_bytes_received,
        after.encrypted_bytes_sent - before.encrypted_bytes_sent,
        after.encrypted_bytes_received - before.encrypted_bytes_received,
        after.plaintext_bytes_sent - before.plaintext_bytes_sent,
        after.plaintext_bytes_received - before.plaintext_bytes_received,
    );
    assert_eq!(wire.tls_sessions, 1);
    assert_eq!(
        after.plaintext_bytes_sent - before.plaintext_bytes_sent,
        8,
        "the SSLRequest"
    );
    assert_eq!(
        after.plaintext_bytes_received - before.plaintext_bytes_received,
        1,
        "the 'S' reply"
    );
    assert_eq!(
        after.encrypted_bytes_sent - before.encrypted_bytes_sent,
        wire.client_bytes - 8
    );
    assert_eq!(
        after.encrypted_bytes_received - before.encrypted_bytes_received,
        wire.server_bytes - 1
    );
    assert!(total.protocol_bytes_sent > 0 && total.protocol_bytes_received > 0);
    assert!(
        after.encrypted_bytes_received - before.encrypted_bytes_received
            > total.protocol_bytes_received
    );
    assert!(counts.is_complete());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn representative_budgets() {
    let _serial = serial().lock().await;
    let pg = pg_addr();
    let budget = |name: &str, counts: &Counts, elapsed: Duration| {
        let mut fields = vec![
            format!("\"name\":\"{name}\""),
            format!("\"complete\":{}", counts.is_complete()),
            format!("\"elapsed_us\":{}", elapsed.as_micros()),
        ];
        for class in Class::ALL {
            let c = counts.class(class);
            if c.cycles_queued > 0 || c.sessions_started > 0 {
                fields.push(format!(
                    "\"{}\":{{\"operations\":{},\"cycles\":{},\"detached\":{},\"messages\":{},\"sessions\":{}}}",
                    class.label(),
                    c.operations,
                    c.cycles_completed,
                    c.detached_cycles_queued,
                    c.messages(),
                    c.sessions_started
                ));
            }
        }
        println!("BUDGET {{{}}}", fields.join(","));
    };
    let start = Instant::now();
    let ((client, _task), counts) = observe::scope("budget.cold_connect", async {
        open(&pg_config(pg.port(), "wq_budget")).await.unwrap()
    })
    .await;
    budget("pg_cold_connect", &counts, start.elapsed());
    assert_eq!(counts.class(Class::SessionSetup).sessions_started, 1);

    let start = Instant::now();
    let (_, counts) = observe::scope("budget.cold_text", async {
        client.query_one("select $1::int4", &[&1i32]).await.unwrap();
        client.simple_query("select 'barrier'").await.unwrap();
    })
    .await;
    budget("pg_text_query_then_barrier", &counts, start.elapsed());
    assert_eq!(
        counts.class(Class::Preparation).cycles_completed,
        2,
        "prepare + detached close"
    );
    assert_eq!(counts.class(Class::Request).cycles_completed, 2);

    let stmt = client.prepare("select $1::int4").await.unwrap();
    let start = Instant::now();
    let (_, counts) = observe::scope("budget.warm", client.query_one(&stmt, &[&1i32])).await;
    budget("pg_warm_prepared", &counts, start.elapsed());
    assert_eq!(counts.total().cycles_completed, 1);

    let mut client = client;
    let start = Instant::now();
    let (_, counts) = observe::scope("budget.tx", async {
        let tx = client.transaction().await.unwrap();
        tx.query_one(&stmt, &[&1i32]).await.unwrap();
        tx.query_one(&stmt, &[&2i32]).await.unwrap();
        tx.commit().await.unwrap();
    })
    .await;
    budget("pg_transaction_two_prepared", &counts, start.elapsed());
    assert_eq!(counts.total().cycles_completed, 4);
    assert_eq!(counts.total().transaction_cycles, 3);

    let mut config = yb_config(yb_addr(), "wq_budget");
    config
        .load_balance("true")
        .yb_servers_refresh_interval(Duration::from_secs(0));
    let start = Instant::now();
    let ((yb, _task), counts) = observe::scope("budget.yb_discovery_connect", async {
        open(&config).await.unwrap()
    })
    .await;
    budget("yb_discovery_connect", &counts, start.elapsed());
    let yb_stmt = yb.prepare("select $1::int4").await.unwrap();
    let start = Instant::now();
    let (_, counts) = observe::scope("budget.yb_warm", yb.query_one(&yb_stmt, &[&1i32])).await;
    budget("yb_warm_prepared", &counts, start.elapsed());
    assert_eq!(counts.total().cycles_completed, 1);
}

#[tokio::test]
async fn labels_and_routes_are_bounded() {
    let _serial = serial().lock().await;
    assert_eq!(observe::route_label("bad\"label"), observe::INVALID_ROUTE);
    assert_eq!(observe::route_label(""), observe::INVALID_ROUTE);
    assert_eq!(
        observe::route_label("repo/{id}/refs:list"),
        "repo/{id}/refs:list"
    );
    for i in 0..(observe::MAX_ROUTES * 2) {
        let route: &'static str = Box::leak(format!("wq.route.{i}").into_boxed_str());
        observe::scope(route, async {}).await;
    }
    let ((), counts) = observe::scope("bad\"label", async {}).await;
    assert_eq!(counts.route(), observe::INVALID_ROUTE);
    let totals = observe::totals();
    assert!(
        totals.routes.len() <= observe::MAX_ROUTES + 1,
        "{}",
        totals.routes.len()
    );
    assert!(totals
        .routes
        .iter()
        .any(|r| r.route == observe::OTHER_ROUTE));
    let text = totals.render_prometheus("wq");
    let series = text.lines().filter(|l| !l.starts_with('#')).count();
    let expected = ClassCounts::NAMES.len() * 2 * Class::ALL.len()
        + SocketRole::ALL.len() * 5
        + 3
        + totals.routes.len() * 4;
    assert_eq!(series, expected);
    assert!(!text.contains("bad\""));
    println!("CARDINALITY series={series} routes={}", totals.routes.len());
}
