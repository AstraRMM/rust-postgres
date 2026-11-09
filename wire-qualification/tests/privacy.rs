//! AST-2133 log privacy: capture every driver log record at `trace` level
//! while running secret-bearing SQL, parameters, errors, notices, failed
//! authentication, discovery and its fallback against real engines, then
//! assert that no SQL text, parameter, server message text, password or
//! endpoint address reached the logs. Positive controls prove the secrets
//! were really on the wire and that the instrumented log sites ran.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use wire_qualification::{env, open, pg_config};
use yb_tokio_postgres::config::SslMode;
use yb_tokio_postgres::error::SqlState;
use yb_tokio_postgres::observe::{self, Redacted};
use yb_tokio_postgres::{Config, SimpleQueryMessage};

struct Capture(Mutex<Vec<String>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        // Only the message text is checked: the target is the crate path.
        self.0
            .lock()
            .unwrap()
            .push(format!("{} {}", record.level(), record.args()));
    }

    fn flush(&self) {}
}

fn capture() -> &'static Capture {
    static CAPTURE: OnceLock<&'static Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(Vec::new()))));
        log::set_logger(capture).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        capture
    })
}

const SQL_SECRET: &str = "wq-secret-sql-literal";
const PARAM_SECRET: &str = "wq-secret-param-value";
const KEY_SECRET: &str = "wq-secret-key-value";
const NOTICE_SECRET: &str = "wq-secret-notice";
const WRONG_PASSWORD: &str = "wq-secret-wrong-password";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_sql_parameters_credentials_or_addresses_reach_the_logs() {
    let capture = capture();
    observe::enable();
    let pg_port: u16 = env("WQ_PG_ADDR")
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let password = env("WQ_PG_PASSWORD");

    // SCRAM session, SQL and parameters with secrets.
    let (client, _task) = open(&pg_config(pg_port, "wq_privacy")).await.unwrap();
    let row = client
        .query_one(
            &format!("select '{SQL_SECRET}'::text, $1::text"),
            &[&PARAM_SECRET],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, &str>(1),
        PARAM_SECRET,
        "positive control: the parameter was sent"
    );
    client
        .execute(
            &format!("select length('{SQL_SECRET}' || $1::text)"),
            &[&PARAM_SECRET],
        )
        .await
        .unwrap();
    client
        .simple_query(&format!("select '{SQL_SECRET}'"))
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "create temp table wq_privacy (k text primary key); comment on table wq_privacy is '{SQL_SECRET}'"
        ))
        .await
        .unwrap();

    // A server error whose detail quotes a parameter value.
    let insert = client
        .prepare("insert into wq_privacy values ($1)")
        .await
        .unwrap();
    client.execute(&insert, &[&KEY_SECRET]).await.unwrap();
    let err = client.execute(&insert, &[&KEY_SECRET]).await.unwrap_err();
    assert_eq!(err.code(), Some(&SqlState::UNIQUE_VIOLATION));
    assert!(
        format!("{err}").contains(KEY_SECRET),
        "positive control: the raw error text quotes the key"
    );
    let redacted = Redacted(&err).to_string();
    assert!(!redacted.contains(KEY_SECRET), "{redacted}");
    assert!(redacted.contains("23505"), "{redacted}");

    // A notice with secret text, logged by the connection task.
    client
        .batch_execute(&format!(
            "do $$ begin raise notice '{NOTICE_SECRET} %', current_setting('application_name'); end $$"
        ))
        .await
        .unwrap();

    // Failed authentication with a secret password.
    let mut bad = pg_config(pg_port, "wq_privacy_bad");
    bad.password(WRONG_PASSWORD);
    let err = open(&bad).await.err().expect("wrong password");
    assert!(
        !Redacted(&err).to_string().contains("postgres\""),
        "{}",
        Redacted(&err)
    );

    // Smart-driver mode against PostgreSQL: yb_servers() is missing, the
    // refresh fails with server text and the driver logs its fallback.
    let mut fallback = pg_config(pg_port, "wq_privacy_fallback");
    fallback
        .load_balance("true")
        .yb_servers_refresh_interval(Duration::from_secs(0));
    let (fallback_client, _task) = open(&fallback).await.unwrap();
    fallback_client.simple_query("select 1").await.unwrap();

    // Real discovery on YugabyteDB: logs every discovered node.
    let yb: std::net::SocketAddr = env("WQ_YB_ADDR").parse().unwrap();
    let mut config = Config::new();
    config
        .host(&yb.ip().to_string())
        .port(yb.port())
        .user("yugabyte")
        .dbname("yugabyte")
        .ssl_mode(SslMode::Disable)
        .load_balance("true")
        .yb_servers_refresh_interval(Duration::from_secs(0));
    let (yb_client, _task) = open(&config).await.unwrap();
    let rows = yb_client
        .simple_query("select host from yb_servers()")
        .await
        .unwrap();
    let discovered: Vec<String> = rows
        .iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
            _ => None,
        })
        .collect();
    assert!(!discovered.is_empty());
    yb_tokio_postgres::close(&yb_client);

    // Let the connection tasks log anything pending (notices).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let lines = capture.0.lock().unwrap().clone();
    let mut forbidden: Vec<String> = vec![
        SQL_SECRET.into(),
        PARAM_SECRET.into(),
        KEY_SECRET.into(),
        NOTICE_SECRET.into(),
        WRONG_PASSWORD.into(),
        password.clone(),
        "127.0.0.".into(),
        "localhost".into(),
        "yb_servers()\" does not exist".into(),
        "function yb_servers".into(),
    ];
    forbidden.extend(discovered.iter().cloned());
    let mut leaks = Vec::new();
    for line in &lines {
        for secret in &forbidden {
            if line.contains(secret.as_str()) {
                leaks.push(format!("{secret:?} in {line:?}"));
            }
        }
    }
    println!("PRIVACY captured {} log records", lines.len());
    for line in lines.iter().take(400) {
        println!("LOG {line}");
    }
    assert!(leaks.is_empty(), "leaked into logs:\n{}", leaks.join("\n"));

    // The instrumented log sites really ran at trace/debug/info level.
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(has("executing statement"), "statement debug lines captured");
    assert!(has("preparing statement"), "prepare debug lines captured");
    assert!(has("executing simple query"));
    assert!(has("NOTICE (00000)"), "notice logged with SQLSTATE only");
    assert!(has("ep-"), "discovery logged redacted endpoint labels");
    assert!(
        has("(42883)"),
        "fallback logged the refresh error as SQLSTATE only"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("TRACE ")),
        "trace records captured"
    );
}
