//! ASTS-95: the pool's log sites print driver errors in their redacted form
//! (kind, severity and SQLSTATE), never server message, detail or hint text.
//! Captures every pool log record while a connect fails with a server error
//! that names a secret, and while a pooled session is terminated by the
//! server. Runs against each configured engine; see `rig/run.sh`.

mod common;

use common::*;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use yb_postgres_pool::yb_tokio_postgres::NoTls;
use yb_postgres_pool::{ConnectionLimiter, Pool};

struct Capture(Mutex<Vec<String>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
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

fn lines() -> Vec<String> {
    capture().0.lock().unwrap().clone()
}

const DB_SECRET: &str = "asts95_secret_database_name";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_logs_redact_driver_errors() {
    capture();
    for e in engines() {
        // 1. A connect failure whose server message names the database.
        let mut pg = e.config();
        pg.dbname(DB_SECRET);
        let mut config = pool_config(&format!("pt_logpriv_{}", e.name));
        config.acquire_timeout = Duration::from_secs(3);
        let label = format!("logpriv-connect-{}", e.name);
        let pool =
            Pool::with_limiter(pg, NoTls, config, ConnectionLimiter::new(4), &label).unwrap();
        let err = pool.get().await.unwrap_err();
        assert!(
            err.to_string().contains(DB_SECRET),
            "positive control: the raw error quotes the server message: {err}"
        );
        let redacted = err.redacted().to_string();
        assert!(!redacted.contains(DB_SECRET), "{redacted}");
        assert!(redacted.contains("(3D000)"), "{redacted}");
        pool.shutdown(Duration::from_secs(1)).await;

        let logged = lines();
        let connect_lines: Vec<&String> = logged
            .iter()
            .filter(|l| l.contains(&format!("pool {label}:")))
            .collect();
        assert!(
            connect_lines
                .iter()
                .any(|l| l.contains("connect failed") && l.contains("(3D000)")),
            "connect failure logged with its SQLSTATE: {connect_lines:#?}"
        );

        // 2. A pooled session the server terminates: the connection task logs
        // how it ended.
        let label = format!("logpriv-ended-{}", e.name);
        let app = format!("pt_logpriv_end_{}", e.name);
        let admin = e.admin().await;
        let pool = Pool::with_limiter(
            e.config(),
            NoTls,
            pool_config(&app),
            ConnectionLimiter::new(4),
            &label,
        )
        .unwrap();
        let client = pool.get().await.unwrap();
        let pid = backend_pid(&client).await;
        admin
            .execute("SELECT pg_terminate_backend($1)", &[&pid])
            .await
            .unwrap();
        let ended = format!("pool {label}: connection");
        assert!(
            eventually(Duration::from_secs(10), || lines()
                .iter()
                .any(|l| l.contains(&ended) && l.contains("ended:")))
            .await,
            "terminated session logged by the connection task"
        );
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
        let ended_lines: Vec<String> = lines()
            .into_iter()
            .filter(|l| l.contains(&ended) && l.contains("ended:"))
            .collect();
        for line in &ended_lines {
            assert!(
                !line.contains("terminating connection"),
                "server message text logged: {line}"
            );
        }
        if e.name == "pg" {
            assert!(
                ended_lines
                    .iter()
                    .any(|l| l.contains("db error: FATAL (57P01)")),
                "termination logged as severity and SQLSTATE: {ended_lines:#?}"
            );
        }
    }

    let leaks: Vec<String> = lines()
        .into_iter()
        .filter(|l| l.contains(DB_SECRET))
        .collect();
    for line in lines() {
        println!("LOG {line}");
    }
    assert!(leaks.is_empty(), "leaked into logs:\n{}", leaks.join("\n"));
}
