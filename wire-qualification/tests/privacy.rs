//! AST-2133 log privacy: capture every driver log record at `trace` level
//! while running secret-bearing SQL, parameters, errors, notices, failed
//! authentication, discovery and its fallback against real engines, then
//! assert that no SQL text, parameter, server message text, password or
//! endpoint address reached the logs. Positive controls prove the secrets
//! were really on the wire and that the instrumented log sites ran.
//!
//! ASTS-95 extends it to conversion errors, `Debug` output of configuration,
//! topology and simple-query rows, connection-string parse errors, and
//! server-chosen severity and SQLSTATE fields (from a scripted server).

use bytes::BytesMut;
use std::error::Error as StdError;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wire_qualification::{env, open, pg_config};
use yb_tokio_postgres::config::SslMode;
use yb_tokio_postgres::endpoint::{EndpointPolicy, NodeEndpoint};
use yb_tokio_postgres::error::SqlState;
use yb_tokio_postgres::observe::{self, Redacted};
use yb_tokio_postgres::realm::Realm;
use yb_tokio_postgres::types::{FromSql, IsNull, ToSql, Type};
use yb_tokio_postgres::{Config, NoTls, SimpleQueryMessage};

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
const COLUMN_SECRET: &str = "wq-secret-column-value";
const CONVERSION_SECRET: &str = "wq-secret-conversion-param";
const FORGED: &str = "wq-forged";

/// A column type whose conversion error quotes the value it rejected.
struct EchoColumn;

impl<'a> FromSql<'a> for EchoColumn {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn StdError + Sync + Send>> {
        Err(format!("rejected {}", String::from_utf8_lossy(raw)).into())
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TEXT
    }
}

/// A parameter whose conversion error quotes the value it refused to encode.
#[derive(Debug)]
struct EchoParam(&'static str);

impl ToSql for EchoParam {
    fn to_sql(
        &self,
        _: &Type,
        _: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn StdError + Sync + Send>> {
        Err(format!("rejected {}", self.0).into())
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TEXT
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn StdError + Sync + Send>> {
        self.to_sql(ty, out)
    }
}

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
    let messages = client
        .simple_query(&format!("select '{SQL_SECRET}'"))
        .await
        .unwrap();
    assert!(
        messages.iter().any(|m| matches!(
            m,
            SimpleQueryMessage::Row(row) if row.get(0) == Some(SQL_SECRET)
        )),
        "positive control: the simple-query row holds the value"
    );
    let debug = format!("{messages:?}");
    assert!(!debug.contains(SQL_SECRET), "{debug}");

    // Conversion errors whose own message quotes the value.
    let row = client
        .query_one(&format!("select '{COLUMN_SECRET}'::text"), &[])
        .await
        .unwrap();
    let err = row
        .try_get::<_, EchoColumn>(0)
        .err()
        .expect("FromSql error");
    assert!(
        format!("{err}").contains(COLUMN_SECRET),
        "positive control: the raw error quotes the column value"
    );
    assert_eq!(Redacted(&err).to_string(), "error deserializing column 0");
    let err = client
        .query("select $1::text", &[&EchoParam(CONVERSION_SECRET)])
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains(CONVERSION_SECRET),
        "positive control: the raw error quotes the parameter"
    );
    assert_eq!(Redacted(&err).to_string(), "error serializing parameter 0");
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
    assert_eq!(redacted, "db error: ERROR (23505)");

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
    let err = open(&bad).await.expect_err("wrong password");
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
    let realm = Realm::new("wq_privacy");
    let mut config = Config::new();
    config
        .realm(realm.clone())
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
    let topology = realm.topology().expect("discovery stored a topology");
    assert!(
        topology
            .nodes()
            .iter()
            .any(|n| discovered.iter().any(|d| d == n.identity())),
        "positive control: the snapshot holds the discovered identities"
    );
    let debug = format!("{topology:?}");
    assert!(debug.contains("ep-"), "{debug}");
    for identity in &discovered {
        assert!(!debug.contains(identity.as_str()), "{debug}");
    }
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
    assert!(
        !lines.iter().any(|l| l.contains(FORGED)),
        "server-chosen severity or SQLSTATE text logged"
    );
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

/// Connection-string parse errors do not echo unknown keys, and `Config` and
/// `EndpointPolicy` `Debug` output shows endpoints only as keyed labels.
#[test]
fn parse_errors_and_config_debug_are_redacted() {
    for s in [
        "host=localhost user=postgres wq_secret_fragment=1",
        "postgresql://postgres@localhost/postgres?wq_secret_fragment=1",
    ] {
        let err = s.parse::<Config>().unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(shown.contains("unknown option"), "{shown}");
        assert!(!shown.contains("wq_secret"), "{shown}");
    }

    let policy = EndpointPolicy::new()
        .admit_node(
            "node-wq-secret.example.internal",
            NodeEndpoint::new()
                .dial("10.9.8.7")
                .tls_name("tls-wq-secret.example.internal")
                .port(5433),
        )
        .unwrap()
        .admit_dns_suffix("suffix-wq-secret.internal")
        .unwrap();
    let mut config = Config::new();
    config
        .host("host-wq-secret.example.internal")
        .hostaddr(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 6)))
        .user("postgres")
        .password("wq-secret-password")
        .options("-c wq_secret_option=on")
        .endpoint_policy(policy.clone());
    assert_eq!(config.get_options(), Some("-c wq_secret_option=on"));
    for debug in [format!("{config:?}"), format!("{policy:?}")] {
        assert!(debug.contains("ep-"), "{debug}");
        for secret in ["wq-secret", "wq_secret", "10.9.8."] {
            assert!(!debug.contains(secret), "{secret} in {debug}");
        }
    }
}

fn put_fields(out: &mut Vec<u8>, tag: u8, fields: &[(u8, &str)]) {
    let mut body = Vec::new();
    for (field, value) in fields {
        body.push(*field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    out.push(tag);
    out.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    out.extend_from_slice(&body);
}

async fn read_startup(socket: &mut TcpStream) {
    let len = socket.read_u32().await.unwrap() as usize;
    let mut rest = vec![0; len - 4];
    socket.read_exact(&mut rest).await.unwrap();
}

/// A scripted server whose error and notices carry forged severity and
/// SQLSTATE fields (no `V` field, or a localized-looking `S`): logs and
/// `Redacted` print only the parsed severity and a validated SQLSTATE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_chosen_severity_and_sqlstate_are_not_logged() {
    let capture = capture();
    let mut config = Config::new();
    config
        .user("postgres")
        .dbname("postgres")
        .ssl_mode(SslMode::Disable);
    let forged_severity = format!("FATAL\nINFO {FORGED}-severity");
    let forged_code = format!("{FORGED}-sqlstate");

    // A startup error with forged fields.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (severity, code) = (forged_severity.clone(), forged_code.clone());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_startup(&mut socket).await;
        let mut out = Vec::new();
        put_fields(
            &mut out,
            b'E',
            &[
                (b'S', severity.as_str()),
                (b'C', code.as_str()),
                (b'M', "m"),
            ],
        );
        socket.write_all(&out).await.unwrap();
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let err = config
        .connect_raw(stream, NoTls)
        .await
        .err()
        .expect("startup error");
    server.await.unwrap();
    let db = err.as_db_error().expect("a server error");
    assert!(db.severity().contains(FORGED), "positive control");
    assert!(db.code().code().contains(FORGED), "positive control");
    assert_eq!(Redacted(&err).to_string(), "db error: UNKNOWN (?????)");

    // Startup notices with forged fields, logged by the connection task.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (severity, code) = (forged_severity.clone(), forged_code.clone());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_startup(&mut socket).await;
        let mut out = Vec::new();
        out.extend_from_slice(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
        let localized = format!("WARNING {FORGED}-localized");
        put_fields(
            &mut out,
            b'N',
            &[
                (b'S', localized.as_str()),
                (b'V', "WARNING"),
                (b'C', "01000"),
                (b'M', "m"),
            ],
        );
        put_fields(
            &mut out,
            b'N',
            &[
                (b'S', severity.as_str()),
                (b'C', code.as_str()),
                (b'M', "m"),
            ],
        );
        out.extend_from_slice(&[b'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2]);
        out.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
        socket.write_all(&out).await.unwrap();
        // Hold the session until the client terminates it.
        let mut sink = Vec::new();
        let _ = socket.read_to_end(&mut sink).await;
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let (client, connection) = config.connect_raw(stream, NoTls).await.unwrap();
    let task = tokio::spawn(connection);
    let logged = |needle: &str| capture.0.lock().unwrap().iter().any(|l| l.contains(needle));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !(logged("WARNING (01000)") && logged("UNKNOWN (?????)")) {
        assert!(
            std::time::Instant::now() < deadline,
            "both notices logged as severity and SQLSTATE"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(client);
    let _ = task.await;
    server.await.unwrap();
    assert!(
        !logged(FORGED),
        "server-chosen severity or SQLSTATE text logged"
    );
}
