//! Transactions over a pooled client.

use crate::cache::StatementCache;
use crate::error::{ErrorKind, PoolError};
use crate::pool::prepare_cached;
use crate::stats::{bump, Stats};
use std::ops::{Deref, DerefMut};
use yb_tokio_postgres::types::{ToSql, Type};
use yb_tokio_postgres::{Client, IsolationLevel, Row, Statement, Transaction, TransactionStatus};

/// Options for [`PooledClient::build_transaction`](crate::PooledClient::build_transaction).
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TransactionOptions {
    /// Isolation level; `None` uses the session default.
    pub isolation: Option<IsolationLevel>,
    /// `READ ONLY` when true.
    pub read_only: bool,
    /// `DEFERRABLE` when true.
    pub deferrable: bool,
}

impl TransactionOptions {
    /// Options with the given isolation level.
    pub fn isolation(isolation: IsolationLevel) -> TransactionOptions {
        TransactionOptions {
            isolation: Some(isolation),
            ..TransactionOptions::default()
        }
    }

    /// Sets `READ ONLY`.
    pub fn read_only(mut self, read_only: bool) -> TransactionOptions {
        self.read_only = read_only;
        self
    }

    /// Sets `DEFERRABLE`.
    pub fn deferrable(mut self, deferrable: bool) -> TransactionOptions {
        self.deferrable = deferrable;
        self
    }
}

/// A transaction on a borrowed client, with the connection's statement
/// cache. Dereferences to the native [`Transaction`].
///
/// Dropping it without [`commit`](Self::commit) rolls back (the `ROLLBACK`
/// is queued without waiting; the pool's return check waits for it).
///
/// Errors inside the transaction are never retried: after a stale cached
/// statement the transaction is aborted, the cache is cleared and the error
/// is [`ErrorKind::StaleStatement`]; retry the whole transaction under its
/// own retry contract.
pub struct PoolTransaction<'a> {
    tx: Option<Transaction<'a>>,
    cache: &'a mut StatementCache,
    stats: &'a Stats,
}

impl<'a> PoolTransaction<'a> {
    pub(crate) async fn begin(
        client: &'a mut Client,
        cache: &'a mut StatementCache,
        stats: &'a Stats,
        options: TransactionOptions,
    ) -> Result<PoolTransaction<'a>, PoolError> {
        let mut builder = client.build_transaction();
        if let Some(isolation) = options.isolation {
            builder = builder.isolation_level(isolation);
        }
        if options.read_only {
            builder = builder.read_only(true);
        }
        if options.deferrable {
            builder = builder.deferrable(true);
        }
        let tx = builder.start().await.map_err(PoolError::from_driver)?;
        Ok(PoolTransaction {
            tx: Some(tx),
            cache,
            stats,
        })
    }

    fn tx(&self) -> &Transaction<'a> {
        self.tx.as_ref().expect("transaction present")
    }

    fn map_error(&mut self, error: yb_tokio_postgres::Error) -> PoolError {
        let error = PoolError::from_driver(error);
        if error.kind() == ErrorKind::StaleStatement && self.cache.clear() > 0 {
            bump(&self.stats.statement_invalidations);
        }
        error
    }

    /// Prepares `sql` with inferred types through the connection's cache.
    pub async fn prepare_cached(&mut self, sql: &str) -> Result<Statement, PoolError> {
        self.prepare_typed_cached(sql, &[]).await
    }

    /// Prepares `sql` with explicit types through the connection's cache.
    pub async fn prepare_typed_cached(
        &mut self,
        sql: &str,
        types: &[Type],
    ) -> Result<Statement, PoolError> {
        let tx = self.tx.as_ref().expect("transaction present");
        prepare_cached(tx.client(), self.cache, self.stats, sql, types).await
    }

    /// Runs a cached statement and returns all rows.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, PoolError> {
        let statement = self.prepare_cached(sql).await?;
        let result = self.tx().query(&statement, params).await;
        result.map_err(|e| self.map_error(e))
    }

    /// Runs a cached statement requiring exactly one row.
    pub async fn query_one(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, PoolError> {
        let statement = self.prepare_cached(sql).await?;
        let result = self.tx().query_one(&statement, params).await;
        result.map_err(|e| self.map_error(e))
    }

    /// Runs a cached statement requiring zero or one row.
    pub async fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, PoolError> {
        let statement = self.prepare_cached(sql).await?;
        let result = self.tx().query_opt(&statement, params).await;
        result.map_err(|e| self.map_error(e))
    }

    /// Runs a cached statement and returns the affected row count.
    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, PoolError> {
        let statement = self.prepare_cached(sql).await?;
        let result = self.tx().execute(&statement, params).await;
        result.map_err(|e| self.map_error(e))
    }

    /// Sets a transaction-local setting (`set_config(name, value, true)`):
    /// the value ends with this transaction and cannot leak to the next
    /// borrower. One round trip (cached statement).
    pub async fn set_local(&mut self, name: &str, value: &str) -> Result<(), PoolError> {
        self.query_one("SELECT set_config($1, $2, true)", &[&name, &value])
            .await
            .map(|_| ())
    }

    /// Commits.
    ///
    /// * `Ok(())`: the server acknowledged `COMMIT`.
    /// * [`ErrorKind::TransactionAborted`]: an earlier statement failed, so
    ///   the server would have answered `COMMIT` with a rollback; nothing
    ///   was committed.
    /// * [`ErrorKind::Database`] (or `DatabaseTimeout`): the server rejected
    ///   `COMMIT` (for example a serialization failure); nothing committed.
    /// * [`ErrorKind::AmbiguousCommit`]: the connection failed with `COMMIT`
    ///   in flight; the outcome is unknown. Do not replay the writes
    ///   automatically. Dropping the future returned by `commit` mid-flight
    ///   is equally ambiguous.
    pub async fn commit(mut self) -> Result<(), PoolError> {
        let tx = self.tx.take().expect("transaction present");
        tx.client().wait_until_settled().await;
        if tx.client().transaction_status() == TransactionStatus::Failed {
            let _ = tx.rollback().await;
            return Err(PoolError::kind_only(ErrorKind::TransactionAborted));
        }
        match tx.commit().await {
            Ok(()) => Ok(()),
            Err(e) => {
                let error = PoolError::from_driver(e);
                if error.kind() == ErrorKind::Transport {
                    Err(error.with_kind(ErrorKind::AmbiguousCommit))
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Rolls back and reports any error.
    pub async fn rollback(mut self) -> Result<(), PoolError> {
        let tx = self.tx.take().expect("transaction present");
        tx.rollback().await.map_err(PoolError::from_driver)
    }
}

impl<'a> Deref for PoolTransaction<'a> {
    type Target = Transaction<'a>;

    fn deref(&self) -> &Transaction<'a> {
        self.tx()
    }
}

impl<'a> DerefMut for PoolTransaction<'a> {
    fn deref_mut(&mut self) -> &mut Transaction<'a> {
        self.tx.as_mut().expect("transaction present")
    }
}
