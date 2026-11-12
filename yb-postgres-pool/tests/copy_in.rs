//! ASTS-89 real-engine qualification: a `COPY FROM STDIN` that fails before
//! copy-in mode leaves the pooled session clean for the next lease. Runs
//! against each configured engine; see `rig/run.sh`.

mod common;

use common::*;
use yb_postgres_pool::yb_tokio_postgres::{
    error::SqlState, Client, Config, NoTls, SimpleQueryMessage,
};
use yb_postgres_pool::Pool;

const ROLE: &str = "pooltest_copy_role";
const LOCKED: &str = "pooltest_copy_locked";

/// A non-superuser role and a table it may not write (superusers bypass
/// table privileges).
async fn setup(e: &Engine) -> Config {
    let admin = e.admin().await;
    admin
        .batch_execute(&format!(
            "DO $$ BEGIN
               IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ROLE}') THEN
                 CREATE ROLE {ROLE} LOGIN PASSWORD '{PG_PASSWORD}';
               END IF;
             END $$;
             DROP TABLE IF EXISTS {LOCKED};
             CREATE TABLE {LOCKED} (id int4, v text);
             REVOKE ALL ON {LOCKED} FROM PUBLIC;"
        ))
        .await
        .unwrap();
    let mut config = e.config();
    config.user(ROLE).password(PG_PASSWORD);
    config
}

fn answer(messages: Vec<SimpleQueryMessage>) -> String {
    messages
        .iter()
        .find_map(|m| match m {
            SimpleQueryMessage::Row(row) => Some(row.get(0).unwrap_or("NULL").to_string()),
            _ => None,
        })
        .unwrap_or_else(|| "<no row>".to_string())
}

/// Two pipelined queries and a third; each must get its own row.
async fn answers(client: &Client) -> Vec<String> {
    let (first, second) = tokio::join!(
        client.simple_query("select 'first'"),
        client.simple_query("select 'second'")
    );
    let third = client.simple_query("select 'third'").await;
    [first, second, third]
        .into_iter()
        .map(|r| r.map(answer).unwrap_or_else(|e| format!("<error: {e}>")))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_copy_in_leaves_the_next_lease_in_step() {
    for e in engines() {
        let app = format!("pt_copy_in_{}", e.name);
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(setup(&e).await, NoTls, config).unwrap();
        let mut wrong = Vec::new();
        for round in 0..10 {
            let lease = pool.get().await.unwrap();
            let err = lease
                .copy_in::<_, &'static [u8]>(&format!("COPY {LOCKED} FROM STDIN"))
                .await
                .err()
                .expect("copy into a locked table must fail");
            assert_eq!(
                err.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "[{}] {err}",
                e.name
            );
            drop(lease);

            // The next lease (the same physical connection: max_size 1)
            // pipelines right away.
            let lease = pool.get().await.unwrap();
            let got = answers(&lease).await;
            if got != ["first", "second", "third"] {
                wrong.push(format!("round {round}: {got:?}"));
            }
        }
        let stats = pool.state().stats;
        println!(
            "[{}] copy_in denied x10: wrong {} connects {} retired_closed {} terminal_failures {}",
            e.name,
            wrong.len(),
            stats.connects,
            stats.retired_closed,
            stats.terminal_failures
        );
        assert!(wrong.is_empty(), "[{}] {wrong:#?}", e.name);
    }
}
