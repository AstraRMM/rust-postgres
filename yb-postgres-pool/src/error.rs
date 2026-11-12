//! The typed error boundary between the pool, the transport and the database.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use yb_tokio_postgres::error::{DbError, Severity, SqlState};

/// What kind of failure a [`PoolError`] reports. Services map these into
/// their own categories; none of them authorizes replaying a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// No client became available within the acquisition budget: the pool
    /// stayed saturated, or transient connect failures continued until the
    /// deadline. [`PoolError::source`] carries the last connect failure seen
    /// during the wait, if any.
    AcquireTimeout,
    /// The process-wide physical connection limit stayed exhausted for the
    /// whole connect budget.
    ProcessLimit,
    /// The pool (or pool set) is shut down.
    PoolClosed,
    /// The pool set already holds its maximum number of active pools and
    /// none of them is idle enough to evict.
    TooManyPools,
    /// TLS verification, credential-generation, authentication or
    /// authorization (SQLSTATE class 28) failure. Never retried against a
    /// weaker transport or another realm.
    Security,
    /// Invalid pool, session or driver configuration.
    Config,
    /// The connection failed or closed (I/O error, server termination,
    /// FATAL error). The client is retired. If a write was in flight its
    /// outcome is unknown.
    Transport,
    /// A server-side timeout: `statement_timeout` or a cancel (57014),
    /// `lock_timeout` (55P03) or `idle_in_transaction_session_timeout`
    /// (25P03, which also closes the session).
    DatabaseTimeout,
    /// The database rejected the request; see [`PoolError::code`]. A
    /// rejected `COMMIT` is definitive: the transaction did not commit.
    Database,
    /// A cached prepared statement was invalidated by a schema or
    /// search-path change ("cached plan must not change result type",
    /// 26000, YugabyteDB schema/catalog version mismatch). The connection's
    /// statement cache was cleared. Outside a transaction the pooled query
    /// helpers already retried once; inside one the transaction is aborted.
    StaleStatement,
    /// The connection failed while `COMMIT` was in flight: the transaction
    /// may or may not have committed. Resolve through idempotency or outcome
    /// reconciliation; never replay automatically.
    AmbiguousCommit,
    /// `COMMIT` was requested for a transaction the server had already
    /// marked failed; the server rolled it back.
    TransactionAborted,
    /// A client-side error: parameter serialization, row decoding,
    /// unexpected row count or column lookup.
    Client,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorKind::AcquireTimeout => "pool acquisition timed out",
            ErrorKind::ProcessLimit => "process-wide connection limit exhausted",
            ErrorKind::PoolClosed => "pool is closed",
            ErrorKind::TooManyPools => "maximum number of active pools reached",
            ErrorKind::Security => "security failure",
            ErrorKind::Config => "invalid configuration",
            ErrorKind::Transport => "transport failure",
            ErrorKind::DatabaseTimeout => "database timeout",
            ErrorKind::Database => "database error",
            ErrorKind::StaleStatement => "cached statement invalidated",
            ErrorKind::AmbiguousCommit => "commit outcome unknown",
            ErrorKind::TransactionAborted => "transaction was aborted; commit rolled back",
            ErrorKind::Client => "client error",
        };
        f.write_str(s)
    }
}

/// An error from the pool or from a pooled operation.
///
/// Cloning is cheap; the driver error (when there is one) is shared.
#[derive(Clone)]
pub struct PoolError {
    kind: ErrorKind,
    message: Option<Arc<str>>,
    source: Option<Arc<yb_tokio_postgres::Error>>,
}

impl PoolError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<Arc<str>>) -> PoolError {
        PoolError {
            kind,
            message: Some(message.into()),
            source: None,
        }
    }

    pub(crate) fn kind_only(kind: ErrorKind) -> PoolError {
        PoolError {
            kind,
            message: None,
            source: None,
        }
    }

    pub(crate) fn config(message: impl Into<Arc<str>>) -> PoolError {
        PoolError::new(ErrorKind::Config, message)
    }

    pub(crate) fn with_kind(mut self, kind: ErrorKind) -> PoolError {
        self.kind = kind;
        self
    }

    pub(crate) fn with_message(mut self, message: impl Into<Arc<str>>) -> PoolError {
        self.message = Some(message.into());
        self
    }

    pub(crate) fn append_message(mut self, detail: &str) -> PoolError {
        self.message = Some(match self.message.take() {
            Some(message) => format!("{}; {}", message, detail).into(),
            None => detail.into(),
        });
        self
    }

    /// Classifies a driver error.
    pub fn from_driver(error: yb_tokio_postgres::Error) -> PoolError {
        PoolError {
            kind: classify(&error),
            message: None,
            source: Some(Arc::new(error)),
        }
    }

    /// The failure category.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The SQLSTATE, when the database reported the error.
    pub fn code(&self) -> Option<&SqlState> {
        self.source.as_deref().and_then(|e| e.code())
    }

    /// The database error, when the database reported one.
    pub fn as_db_error(&self) -> Option<&DbError> {
        self.source.as_deref().and_then(|e| e.as_db_error())
    }

    /// The underlying driver error, if any.
    pub fn driver_error(&self) -> Option<&yb_tokio_postgres::Error> {
        self.source.as_deref()
    }

    /// Formats the error for logs: the kind, the pool's own message and the
    /// driver error reduced by
    /// [`observe::Redacted`](yb_tokio_postgres::observe::Redacted), so no
    /// server message, detail or hint text is included.
    pub fn redacted(&self) -> impl fmt::Display + '_ {
        RedactedPoolError(self)
    }

    /// Whether the failure means the physical connection is unusable.
    pub fn is_transport(&self) -> bool {
        matches!(self.kind, ErrorKind::Transport | ErrorKind::AmbiguousCommit)
    }

    /// Whether a timeout of any layer (pool or database) caused the error.
    pub fn is_timeout(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::AcquireTimeout | ErrorKind::ProcessLimit | ErrorKind::DatabaseTimeout
        )
    }
}

impl fmt::Debug for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(message) = &self.message {
            write!(f, ": {}", message)?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {}", source)?;
        }
        Ok(())
    }
}

struct RedactedPoolError<'a>(&'a PoolError);

impl fmt::Display for RedactedPoolError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.kind)?;
        if let Some(message) = &self.0.message {
            write!(f, ": {}", message)?;
        }
        if let Some(source) = &self.0.source {
            write!(f, ": {}", yb_tokio_postgres::observe::Redacted(source))?;
        }
        Ok(())
    }
}

impl StdError for PoolError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<yb_tokio_postgres::Error> for PoolError {
    fn from(error: yb_tokio_postgres::Error) -> PoolError {
        PoolError::from_driver(error)
    }
}

/// Whether the error invalidates cached prepared statements.
pub fn is_stale_statement(error: &yb_tokio_postgres::Error) -> bool {
    let db = match error.as_db_error() {
        Some(db) => db,
        None => return false,
    };
    if *db.code() == SqlState::INVALID_SQL_STATEMENT_NAME {
        return true;
    }
    let message = db.message();
    let code = db.code();
    // YugabyteDB reports schema and catalog version mismatches as an
    // internal error (XX000) or a serialization failure (40001). The
    // message is only trusted under those codes: other errors (data
    // exceptions, constraint violations, RAISE) can echo stored or
    // caller-supplied text.
    (*code == SqlState::FEATURE_NOT_SUPPORTED
        && message.contains("cached plan must not change result type"))
        || ((*code == SqlState::INTERNAL_ERROR || *code == SqlState::T_R_SERIALIZATION_FAILURE)
            && (message.contains("schema version mismatch")
                || message.contains("catalog version mismatch")))
}

/// Maps a driver error onto an [`ErrorKind`].
pub fn classify(error: &yb_tokio_postgres::Error) -> ErrorKind {
    if error.is_security_failure() {
        return ErrorKind::Security;
    }
    if let Some(db) = error.as_db_error() {
        if is_stale_statement(error) {
            return ErrorKind::StaleStatement;
        }
        let code = db.code();
        if *code == SqlState::QUERY_CANCELED
            || *code == SqlState::LOCK_NOT_AVAILABLE
            || *code == SqlState::IDLE_IN_TRANSACTION_SESSION_TIMEOUT
        {
            return ErrorKind::DatabaseTimeout;
        }
        if *code == SqlState::ADMIN_SHUTDOWN
            || *code == SqlState::CRASH_SHUTDOWN
            || *code == SqlState::CANNOT_CONNECT_NOW
            || matches!(
                db.parsed_severity(),
                Some(Severity::Fatal) | Some(Severity::Panic)
            )
        {
            return ErrorKind::Transport;
        }
        return ErrorKind::Database;
    }
    // The driver's own classification (AST-2129): I/O, protocol, closed,
    // connect and timeout failures, never security failures.
    if error.is_transport() {
        return ErrorKind::Transport;
    }
    let text = error.to_string();
    if text.starts_with("invalid configuration") || text.starts_with("invalid connection string") {
        return ErrorKind::Config;
    }
    ErrorKind::Client
}
