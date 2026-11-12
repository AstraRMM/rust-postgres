//! ASTS-97: availability hardening of the pool. Engine tests run against
//! each configured engine (see `rig/run.sh`); run with `--test-threads=1`.

mod common;

use common::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use yb_postgres_pool::yb_tokio_postgres::{NoTls, TransactionStatus};
use yb_postgres_pool::{ErrorKind, Pool, PoolConfig, TransactionOptions};

/// An unbounded drain does not overflow the deadline: shutdown waits for
/// the borrowed client and returns once it comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_accepts_an_unbounded_drain() {
    let pool = Pool::new(
        unused_config(stall_listener().await),
        NoTls,
        PoolConfig::default(),
    )
    .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(5), pool.shutdown(Duration::MAX))
        .await
        .expect("nothing borrowed: shutdown returns at once");
    assert_eq!(report.borrowed_at_deadline, 0);

    for e in engines() {
        let app = format!("pt_avail_drain_{}", e.name);
        let pool = Pool::new(e.config(), NoTls, pool_config(&app)).unwrap();
        let client = pool.get().await.unwrap();
        let returner = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(client);
        });
        let report = tokio::time::timeout(Duration::from_secs(10), pool.shutdown(Duration::MAX))
            .await
            .expect("shutdown returns once the client is back");
        returner.await.unwrap();
        assert_eq!(report.borrowed_at_deadline, 0, "{report:?}");
        assert_eq!(report.forced_closes, 0, "{report:?}");
    }
}

/// Stale-statement detection trusts the "version mismatch" text only under
/// the SQLSTATEs YugabyteDB reports it with. A data exception or a RAISE
/// whose message carries the same words is an ordinary database error: no
/// retry, no cache invalidation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_mismatch_text_outside_its_sqlstates_is_not_stale() {
    for e in engines() {
        let app = format!("pt_avail_stale_{}", e.name);
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config(), NoTls, config).unwrap();
        let mut client = pool.get().await.unwrap();
        let _ = client.query_one("SELECT 1::int8", &[]).await.unwrap();
        let cached = client.cached_statements();
        assert!(cached > 0);
        for text in ["catalog version mismatch", "schema version mismatch"] {
            let err = client
                .query("SELECT $1::text::int", &[&text])
                .await
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Database, "{err}");
            assert_eq!(err.code().map(|c| c.code()), Some("22P02"), "{err}");
            assert!(
                err.as_db_error().unwrap().message().contains(text),
                "the message echoes the value: {err}"
            );
        }
        let raised = client
            .execute(
                "DO $$ BEGIN RAISE EXCEPTION 'catalog version mismatch'; END $$",
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(raised.kind(), ErrorKind::Database, "{raised}");
        assert_eq!(raised.code().map(|c| c.code()), Some("P0001"), "{raised}");
        assert!(client.cached_statements() >= cached, "cache kept");
        let stats = pool.state().stats;
        assert_eq!(stats.stale_statement_retries, 0, "{stats:?}");
        assert_eq!(stats.statement_invalidations, 0, "{stats:?}");
        drop(client);
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

/// A `transaction()` / `build_transaction()` future dropped after `BEGIN`
/// was sent queues a `ROLLBACK`, so the borrower's later statements run in
/// autocommit instead of inside an orphaned transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_begin_rolls_back() {
    for e in engines() {
        let app = format!("pt_avail_begin_{}", e.name);
        let admin = e.admin().await;
        let table = format!("pool_avail_begin_{}", e.name);
        admin
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id int PRIMARY KEY)"
            ))
            .await
            .unwrap();
        let (proxy_addr, wire) = proxy(e.addr).await;
        let mut config = pool_config(&app);
        config.max_size = 1;
        let pool = Pool::new(e.config_at(proxy_addr), NoTls, config).unwrap();
        let mut client = pool.get().await.unwrap();
        for (id, options) in [
            (1, None),
            (2, Some(TransactionOptions::default().read_only(false))),
        ] {
            wire.hold_replies.store(true, Ordering::SeqCst);
            let abandoned = match options {
                None => tokio::time::timeout(Duration::from_millis(200), client.transaction())
                    .await
                    .map(|_| ()),
                Some(options) => tokio::time::timeout(
                    Duration::from_millis(200),
                    client.build_transaction(options),
                )
                .await
                .map(|_| ()),
            };
            assert!(abandoned.is_err(), "BEGIN was sent and its reply held");
            wire.hold_replies.store(false, Ordering::SeqCst);
            client.client().wait_until_settled().await;
            assert_eq!(
                client.transaction_status(),
                TransactionStatus::Idle,
                "the abandoned BEGIN was rolled back"
            );
            client
                .execute(&format!("INSERT INTO {table} VALUES ($1)"), &[&id])
                .await
                .unwrap();
        }
        drop(client);
        let n: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 2, "both inserts committed in autocommit");
        pool.shutdown(Duration::from_secs(1)).await;
        admin
            .batch_execute(&format!("DROP TABLE {table}"))
            .await
            .unwrap();
    }
}
