//! ASTS-89 real-engine qualification: a `COPY FROM STDIN` request ends with
//! exactly one `ReadyForQuery`, whether or not its statement entered copy-in
//! mode, so the requests after it on the same client get their own
//! responses. Runs against PostgreSQL and YugabyteDB through the parsing
//! [`Proxy`]; requires the rig from `wire-qualification/rig/run.sh`.

use futures_util::{pin_mut, SinkExt};
use std::net::SocketAddr;
use std::time::Duration;
use wire_qualification::{env, open, pg_config, settle, Proxy, Tally};
use yb_tokio_postgres::config::SslMode;
use yb_tokio_postgres::error::SqlState;
use yb_tokio_postgres::observe::{self, ClassCounts};
use yb_tokio_postgres::{Client, Config, Error, SimpleQueryMessage, Statement};

const ROLE: &str = "wq_copy_role";
const LOCKED: &str = "wq_copy_locked";

#[derive(Clone, Copy, Debug)]
enum Engine {
    Pg,
    Yb,
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    /// `COPY` into a table the role may not write: fails before copy-in mode.
    Denied,
    /// Not a `COPY` at all: the statement runs and never enters copy-in mode.
    NotCopy,
    /// The sink is dropped mid-copy (`CopyFail`).
    Aborted,
    /// The server rejects the data mid-copy.
    BadData,
    /// A successful copy.
    Copied,
}

const SCENARIOS: [Scenario; 5] = [
    Scenario::Denied,
    Scenario::NotCopy,
    Scenario::Aborted,
    Scenario::BadData,
    Scenario::Copied,
];

impl Engine {
    fn upstream(self) -> SocketAddr {
        match self {
            Engine::Pg => env("WQ_PG_ADDR").parse().unwrap(),
            Engine::Yb => env("WQ_YB_ADDR").parse().unwrap(),
        }
    }

    fn admin_config(self) -> Config {
        match self {
            Engine::Pg => pg_config(self.upstream().port(), "wq_copy_admin"),
            Engine::Yb => {
                let addr = self.upstream();
                let mut config = Config::new();
                config
                    .host(&addr.ip().to_string())
                    .port(addr.port())
                    .user("yugabyte")
                    .dbname("yugabyte")
                    .application_name("wq_copy_admin")
                    .ssl_mode(SslMode::Disable);
                config
            }
        }
    }

    /// The unprivileged role, through the proxy.
    fn role_config(self, proxy_port: u16) -> Config {
        let mut config = Config::new();
        config
            .host("127.0.0.1")
            .port(proxy_port)
            .user(ROLE)
            .password(env("WQ_PG_PASSWORD"))
            .dbname(match self {
                Engine::Pg => "postgres",
                Engine::Yb => "yugabyte",
            })
            .application_name("wq_copy")
            .ssl_mode(SslMode::Disable);
        config
    }

    async fn setup(self) {
        let (admin, _task) = open(&self.admin_config()).await.unwrap();
        admin
            .batch_execute(&format!(
                "DO $$ BEGIN
                   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ROLE}') THEN
                     CREATE ROLE {ROLE} LOGIN PASSWORD '{password}';
                   END IF;
                 END $$;
                 DROP TABLE IF EXISTS {LOCKED};
                 CREATE TABLE {LOCKED} (id int4, v text);
                 REVOKE ALL ON {LOCKED} FROM PUBLIC;",
                password = env("WQ_PG_PASSWORD"),
            ))
            .await
            .unwrap();
    }
}

fn sql(scenario: Scenario) -> String {
    match scenario {
        Scenario::Denied => format!("COPY {LOCKED} FROM STDIN"),
        Scenario::NotCopy => "SELECT 1".to_string(),
        _ => "COPY wq_copy_temp FROM STDIN".to_string(),
    }
}

/// Runs one `COPY FROM STDIN` scenario on a prepared statement. Returns a
/// description of anything other than the expected outcome.
async fn copy(client: &Client, statement: &Statement, scenario: Scenario) -> Result<(), String> {
    let started = client.copy_in::<_, &'static [u8]>(statement).await;
    match scenario {
        Scenario::Denied => match started {
            Err(e) if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) => Ok(()),
            Err(e) => Err(format!("expected 42501, got {e}")),
            Ok(_) => Err("copy into a locked table started".into()),
        },
        Scenario::NotCopy => match started {
            Err(_) => Ok(()),
            Ok(_) => Err("copy_in of a SELECT started".into()),
        },
        Scenario::Aborted => {
            let sink = started.map_err(|e| format!("copy_in failed: {e}"))?;
            pin_mut!(sink);
            sink.send(b"1\tdropped\n" as &'static [u8])
                .await
                .map_err(|e| format!("send failed: {e}"))?;
            Ok(())
        }
        Scenario::BadData => {
            let sink = started.map_err(|e| format!("copy_in failed: {e}"))?;
            pin_mut!(sink);
            let _ = sink.send(b"not-a-number\tx\n" as &'static [u8]).await;
            match sink.as_mut().finish().await {
                Err(e) if e.code().is_some() => Ok(()),
                Err(e) => Err(format!("expected a server error, got {e}")),
                Ok(rows) => Err(format!("bad data copied {rows} rows")),
            }
        }
        Scenario::Copied => {
            let sink = started.map_err(|e| format!("copy_in failed: {e}"))?;
            pin_mut!(sink);
            sink.send(b"1\ta\n2\tb\n" as &'static [u8])
                .await
                .map_err(|e| format!("send failed: {e}"))?;
            match sink.as_mut().finish().await {
                Ok(2) => Ok(()),
                other => Err(format!("expected 2 rows, got {other:?}")),
            }
        }
    }
}

fn answer(result: Result<Vec<SimpleQueryMessage>, Error>) -> String {
    match result {
        Ok(messages) => messages
            .iter()
            .find_map(|m| match m {
                SimpleQueryMessage::Row(row) => Some(row.get(0).unwrap_or("NULL").to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "<no row>".to_string()),
        Err(e) => format!("<error: {e}>"),
    }
}

/// Two distinct pipelined queries, then a third: each must get its own row.
async fn pipelined_answers(client: &Client) -> Result<(), String> {
    let (first, second) = tokio::join!(
        client.simple_query("select 'first'"),
        client.simple_query("select 'second'")
    );
    let (first, second) = (answer(first), answer(second));
    let third = answer(client.simple_query("select 'third'").await);
    if (first.as_str(), second.as_str(), third.as_str()) != ("first", "second", "third") {
        return Err(format!(
            "pipelined answers: first={first:?} second={second:?} third={third:?} closed={}",
            client.is_closed()
        ));
    }
    Ok(())
}

/// The copy request alone must be one cycle on the wire and in the driver's
/// observation: one `Flush`, one `Sync`, one `ReadyForQuery`.
fn wire_check(scenario: Scenario, c: &ClassCounts, wire: &Tally) -> Result<(), String> {
    let mut problems = Vec::new();
    let expect = |problems: &mut Vec<String>, what: &str, got: u64, want: u64| {
        if got != want {
            problems.push(format!("{what}: {got} != {want}"));
        }
    };
    expect(&mut problems, "wire Sync", wire.fe('S'), 1);
    expect(&mut problems, "wire Flush", wire.fe('H'), 1);
    expect(&mut problems, "wire ReadyForQuery", wire.be('Z'), 1);
    let errors = match scenario {
        Scenario::NotCopy | Scenario::Copied => 0,
        _ => 1,
    };
    expect(&mut problems, "wire ErrorResponse", wire.be('E'), errors);
    expect(&mut problems, "driver Sync", c.sync_messages, wire.fe('S'));
    expect(
        &mut problems,
        "driver Flush",
        c.flush_messages,
        wire.fe('H'),
    );
    expect(
        &mut problems,
        "driver CopyData",
        c.copy_data_messages,
        wire.fe('d'),
    );
    expect(
        &mut problems,
        "driver CopyDone",
        c.copy_done_messages,
        wire.fe('c'),
    );
    expect(
        &mut problems,
        "driver CopyFail",
        c.copy_fail_messages,
        wire.fe('f'),
    );
    expect(
        &mut problems,
        "driver cycles",
        c.cycles_completed,
        wire.be('Z'),
    );
    expect(
        &mut problems,
        "driver errors",
        c.error_responses,
        wire.be('E'),
    );
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("{}\n{c:#?}\n{wire:#?}", problems.join("; ")))
    }
}

/// One scenario on a fresh session. With `idle`, the session waits before
/// the follow-up queries, so any stray response arrives while nothing is
/// queued; otherwise the follow-ups are pipelined right behind the copy.
async fn run(engine: Engine, proxy: &Proxy, scenario: Scenario, idle: bool) -> Vec<String> {
    let mut failures = Vec::new();
    let (client, task) = open(&engine.role_config(proxy.port)).await.unwrap();
    client
        .batch_execute("create temp table wq_copy_temp (id int4, v text)")
        .await
        .unwrap();
    // Prepared outside the measurement, and kept until after it (dropping it
    // sends a `Close`).
    let statement = match client.prepare(&sql(scenario)).await {
        Ok(statement) => statement,
        Err(e) => return vec![format!("prepare failed: {e}")],
    };
    let before = settle(proxy).await;
    let (outcome, counts) = observe::scope("wq.copy_in", async {
        let outcome = copy(&client, &statement, scenario).await;
        if idle {
            client.wait_until_settled().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        outcome
    })
    .await;
    if let Err(e) = outcome {
        failures.push(format!("copy: {e}"));
    }
    // Only a response the request's protocol does not allow (the SELECT's
    // rows where CopyInResponse belongs) poisons the session.
    let poisoned = matches!(scenario, Scenario::NotCopy);
    if client.is_poisoned() != poisoned {
        failures.push(format!("is_poisoned() = {}", client.is_poisoned()));
    }
    if idle {
        let wire = settle(proxy).await.since(&before);
        if !counts.is_complete() {
            failures.push(format!("observation incomplete: {counts:#?}"));
        }
        if let Err(e) = wire_check(scenario, &counts.total(), &wire) {
            failures.push(format!("wire: {e}"));
        }
    }
    if let Err(e) = pipelined_answers(&client).await {
        failures.push(e);
    }
    drop(statement);
    drop(client);
    if let Ok(Ok(Err(e))) = tokio::time::timeout(Duration::from_secs(5), task).await {
        failures.push(format!("connection task failed: {e}"));
    }
    failures
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_in_requests_end_with_one_ready_for_query() {
    let mut failures = Vec::new();
    for engine in [Engine::Pg, Engine::Yb] {
        engine.setup().await;
        let proxy = Proxy::start(engine.upstream()).await;
        for scenario in SCENARIOS {
            for idle in [false, true] {
                let variant = if idle { "idle" } else { "pipelined" };
                let found = run(engine, &proxy, scenario, idle).await;
                if found.is_empty() {
                    println!("COPY-IN {engine:?} {scenario:?} {variant}: ok");
                } else {
                    for f in &found {
                        println!("COPY-IN {engine:?} {scenario:?} {variant}: FAIL {f}");
                    }
                    failures.push(format!("{engine:?} {scenario:?} {variant}: {found:?}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
