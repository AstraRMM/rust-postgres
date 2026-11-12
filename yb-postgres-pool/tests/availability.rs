//! ASTS-97: availability hardening of the pool. Engine tests run against
//! each configured engine (see `rig/run.sh`); run with `--test-threads=1`.

mod common;

use common::*;
use std::time::Duration;
use yb_postgres_pool::yb_tokio_postgres::NoTls;
use yb_postgres_pool::{Pool, PoolConfig};

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
