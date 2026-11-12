//! ASTS-97: availability hardening of the pool. Engine tests run against
//! each configured engine (see `rig/run.sh`); run with `--test-threads=1`.

mod common;

use common::*;
use std::time::Duration;
use yb_postgres_pool::yb_tokio_postgres::NoTls;
use yb_postgres_pool::{ErrorKind, Pool, PoolConfig};

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
