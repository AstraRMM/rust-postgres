use crate::codec::{BackendMessages, FrontendMessage};
use crate::config::SslMode;
use crate::connection::{Request, RequestMessages};
use crate::copy_out::CopyOutStream;
#[cfg(feature = "runtime")]
use crate::keepalive::KeepaliveConfig;
use crate::observe::{self, Class, RequestObservation};
use crate::query::RowStream;
use crate::session_status::{SessionShared, TransactionStatus};
use crate::simple_query::SimpleQueryStream;
#[cfg(feature = "runtime")]
use crate::tls::MakeTlsConnect;
use crate::tls::TlsConnect;
use crate::types::{Oid, ToSql, Type};
#[cfg(feature = "runtime")]
use crate::Socket;
use crate::{
    copy_in, copy_out, prepare, query, simple_query, slice_iter, CancelToken, CopyInSink, Error,
    Row, SimpleQueryMessage, Statement, ToStatement, Transaction, TransactionBuilder,
};
use bytes::{Buf, BytesMut};
use fallible_iterator::FallibleIterator;
use futures_channel::mpsc;
use futures_util::{future, pin_mut, ready, StreamExt, TryStreamExt};
use parking_lot::Mutex;
use postgres_protocol::message::{backend::Message, frontend};
use postgres_types::BorrowToSql;
use std::collections::HashMap;
use std::fmt;
#[cfg(feature = "runtime")]
use std::net::IpAddr;
#[cfg(feature = "runtime")]
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll};
#[cfg(feature = "runtime")]
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Responses {
    receiver: mpsc::Receiver<BackendMessages>,
    cur: BackendMessages,
    session: Arc<SessionShared>,
}

impl Responses {
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Message, Error>> {
        loop {
            let message = match self.cur.next() {
                Ok(message) => message,
                Err(e) => {
                    self.session.poison();
                    return Poll::Ready(Err(Error::parse(e)));
                }
            };
            match message {
                Some(Message::ErrorResponse(body)) => return Poll::Ready(Err(Error::db(body))),
                Some(message) => return Poll::Ready(Ok(message)),
                None => {}
            }

            match ready!(self.receiver.poll_next_unpin(cx)) {
                Some(messages) => self.cur = messages,
                None => return Poll::Ready(Err(Error::closed())),
            }
        }
    }

    pub async fn next(&mut self) -> Result<Message, Error> {
        future::poll_fn(|cx| self.poll_next(cx)).await
    }

    /// The error for a response the request's protocol does not allow. It
    /// poisons the session: the client and server may no longer agree on
    /// which response belongs to which request.
    pub fn unexpected(&self) -> Error {
        self.session.poison();
        Error::unexpected_message()
    }
}

/// A cache of type info and prepared statements for fetching type info
/// (corresponding to the queries in the [prepare](prepare) module).
#[derive(Default)]
struct CachedTypeInfo {
    /// A statement for basic information for a type from its
    /// OID. Corresponds to [TYPEINFO_QUERY](prepare::TYPEINFO_QUERY) (or its
    /// fallback).
    typeinfo: Option<Statement>,
    /// A statement for getting information for a composite type from its OID.
    /// Corresponds to [TYPEINFO_QUERY](prepare::TYPEINFO_COMPOSITE_QUERY).
    typeinfo_composite: Option<Statement>,
    /// A statement for getting information for a composite type from its OID.
    /// Corresponds to [TYPEINFO_QUERY](prepare::TYPEINFO_COMPOSITE_QUERY) (or
    /// its fallback).
    typeinfo_enum: Option<Statement>,

    /// Cache of types already looked up.
    types: HashMap<Oid, Type>,
}

pub struct InnerClient {
    sender: mpsc::UnboundedSender<Request>,
    session: Arc<SessionShared>,
    cached_typeinfo: Mutex<CachedTypeInfo>,

    /// A buffer to use when writing out postgres commands.
    buffer: Mutex<BytesMut>,
}

impl InnerClient {
    pub fn send(&self, messages: RequestMessages) -> Result<Responses, Error> {
        self.send_observed(messages, None, false)
    }

    /// Sends a request whose exchanges are attributed to `purpose` unless an
    /// ambient [`observe::with_class`] overrides it.
    pub fn send_for(
        &self,
        messages: RequestMessages,
        purpose: Option<Class>,
    ) -> Result<Responses, Error> {
        self.send_observed(messages, purpose, false)
    }

    /// Sends a fire-and-forget request issued from a destructor (closing a
    /// statement or portal); see `observe::ClassCounts::detached_cycles_queued`.
    pub fn send_detached(&self, messages: RequestMessages, purpose: Option<Class>) {
        let _ = self.send_observed(messages, purpose, true);
    }

    fn send_observed(
        &self,
        messages: RequestMessages,
        purpose: Option<Class>,
        detached: bool,
    ) -> Result<Responses, Error> {
        let (sender, receiver) = mpsc::channel(1);
        let request = Request {
            messages,
            sender,
            observation: RequestObservation::start(purpose, detached),
            detached,
        };
        // Count before handing over: the connection may complete the request
        // before `unbounded_send` returns.
        self.session.request_sent(detached);
        if self.sender.unbounded_send(request).is_err() {
            self.session.request_complete(None, detached);
            return Err(Error::closed());
        }

        Ok(Responses {
            receiver,
            cur: BackendMessages::empty(),
            session: self.session.clone(),
        })
    }

    pub fn typeinfo(&self) -> Option<Statement> {
        self.cached_typeinfo.lock().typeinfo.clone()
    }

    pub fn set_typeinfo(&self, statement: &Statement) {
        self.cached_typeinfo.lock().typeinfo = Some(statement.clone());
    }

    pub fn typeinfo_composite(&self) -> Option<Statement> {
        self.cached_typeinfo.lock().typeinfo_composite.clone()
    }

    pub fn set_typeinfo_composite(&self, statement: &Statement) {
        self.cached_typeinfo.lock().typeinfo_composite = Some(statement.clone());
    }

    pub fn typeinfo_enum(&self) -> Option<Statement> {
        self.cached_typeinfo.lock().typeinfo_enum.clone()
    }

    pub fn set_typeinfo_enum(&self, statement: &Statement) {
        self.cached_typeinfo.lock().typeinfo_enum = Some(statement.clone());
    }

    pub fn type_(&self, oid: Oid) -> Option<Type> {
        self.cached_typeinfo.lock().types.get(&oid).cloned()
    }

    pub fn set_type(&self, oid: Oid, type_: &Type) {
        self.cached_typeinfo.lock().types.insert(oid, type_.clone());
    }

    pub fn clear_type_cache(&self) {
        self.cached_typeinfo.lock().types.clear();
    }

    /// Call the given function with a buffer to be used when writing out
    /// postgres commands.
    pub fn with_buf<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BytesMut) -> R,
    {
        let mut buffer = self.buffer.lock();
        let r = f(&mut buffer);
        buffer.clear();
        r
    }
}

#[cfg(feature = "runtime")]
#[derive(Clone)]
pub(crate) struct SocketConfig {
    pub addr: Addr,
    /// Expected TLS identity used for this connection (and its cancel requests).
    pub hostname: Option<String>,
    /// Canonical node identity used for connection accounting.
    pub node: Option<String>,
    pub port: u16,
    pub connect_timeout: Option<Duration>,
    pub tcp_user_timeout: Option<Duration>,
    pub keepalive: Option<KeepaliveConfig>,
}

#[cfg(feature = "runtime")]
#[derive(Clone)]
pub(crate) enum Addr {
    Tcp(IpAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

/// An asynchronous PostgreSQL client.
///
/// The client is one half of what is returned when a connection is established. Users interact with the database
/// through this client object.
pub struct Client {
    inner: Arc<InnerClient>,
    #[cfg(feature = "runtime")]
    socket_config: Option<SocketConfig>,
    /// Releases this connection's node accounting when the client is dropped.
    #[cfg(feature = "runtime")]
    lease: Option<Box<dyn std::any::Any + Send + Sync>>,
    #[cfg(feature = "runtime")]
    placement: Option<crate::realm::Placement>,
    ssl_mode: SslMode,
    process_id: i32,
    secret_key: i32,
}

impl Client {
    pub(crate) fn new(
        sender: mpsc::UnboundedSender<Request>,
        session: Arc<SessionShared>,
        ssl_mode: SslMode,
        process_id: i32,
        secret_key: i32,
    ) -> Client {
        Client {
            inner: Arc::new(InnerClient {
                sender,
                session,
                cached_typeinfo: Default::default(),
                buffer: Default::default(),
            }),
            #[cfg(feature = "runtime")]
            socket_config: None,
            #[cfg(feature = "runtime")]
            lease: None,
            #[cfg(feature = "runtime")]
            placement: None,
            ssl_mode,
            process_id,
            secret_key,
        }
    }

    pub(crate) fn inner(&self) -> &Arc<InnerClient> {
        &self.inner
    }

    #[cfg(feature = "runtime")]
    pub(crate) fn set_socket_config(&mut self, socket_config: SocketConfig) {
        self.socket_config = Some(socket_config);
    }

    pub(crate) fn get_socket_config(&self) -> Option<SocketConfig> {
        self.socket_config.clone()
    }

    #[cfg(feature = "runtime")]
    pub(crate) fn set_lease(&mut self, lease: Box<dyn std::any::Any + Send + Sync>) {
        self.lease = Some(lease);
    }

    #[cfg(feature = "runtime")]
    pub(crate) fn realm(&self) -> Option<&crate::realm::Realm> {
        self.placement.as_ref().map(|placement| &placement.realm)
    }

    #[cfg(feature = "runtime")]
    pub(crate) fn set_placement(&mut self, placement: crate::realm::Placement) {
        self.placement = Some(placement);
    }

    /// Where this client's node stands in its realm's current topology
    /// under the selection policy it was connected with. Reads local state
    /// only; [`Realm::refresh`](crate::realm::Realm::refresh) updates it.
    #[cfg(feature = "runtime")]
    pub fn node_standing(&self) -> crate::realm::NodeStanding {
        match &self.placement {
            Some(placement) => placement.standing(),
            None => crate::realm::NodeStanding::Unknown,
        }
    }

    /// The canonical identity of the node this client is connected to, as
    /// used for smart-driver connection accounting: the discovered
    /// `yb_servers()` host for load-balanced connections, or the configured
    /// host for direct connections.
    #[cfg(feature = "runtime")]
    pub fn node_identity(&self) -> Option<&str> {
        self.socket_config.as_ref().and_then(|c| c.node.as_deref())
    }

    /// Creates a new prepared statement.
    ///
    /// Prepared statements can be executed repeatedly, and may contain query parameters (indicated by `$1`, `$2`, etc),
    /// which are set when executed. Prepared statements can only be used with the connection that created them.
    pub async fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.prepare_typed(query, &[]).await
    }

    /// Like `prepare`, but allows the types of query parameters to be explicitly specified.
    ///
    /// The list of types may be smaller than the number of parameters - the types of the remaining parameters will be
    /// inferred. For example, `client.prepare_typed(query, &[])` is equivalent to `client.prepare(query)`.
    pub async fn prepare_typed(
        &self,
        query: &str,
        parameter_types: &[Type],
    ) -> Result<Statement, Error> {
        observe::operation(Some(Class::Preparation));
        prepare::prepare(&self.inner, query, parameter_types).await
    }

    /// Executes a statement, returning a vector of the resulting rows.
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    pub async fn query<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.query_raw(statement, slice_iter(params))
            .await?
            .try_collect()
            .await
    }

    /// Executes a statement which returns a single row, returning it.
    ///
    /// Returns an error if the query does not return exactly one row.
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    pub async fn query_one<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error>
    where
        T: ?Sized + ToStatement,
    {
        let stream = self.query_raw(statement, slice_iter(params)).await?;
        pin_mut!(stream);

        let row = match stream.try_next().await? {
            Some(row) => row,
            None => return Err(Error::row_count()),
        };

        if stream.try_next().await?.is_some() {
            return Err(Error::row_count());
        }

        Ok(row)
    }

    /// Executes a statements which returns zero or one rows, returning it.
    ///
    /// Returns an error if the query returns more than one row.
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    pub async fn query_opt<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        let stream = self.query_raw(statement, slice_iter(params)).await?;
        pin_mut!(stream);

        let row = match stream.try_next().await? {
            Some(row) => row,
            None => return Ok(None),
        };

        if stream.try_next().await?.is_some() {
            return Err(Error::row_count());
        }

        Ok(Some(row))
    }

    /// The maximally flexible version of [`query`].
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    ///
    /// [`query`]: #method.query
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn async_main(client: &yb_tokio_postgres::Client) -> Result<(), yb_tokio_postgres::Error> {
    /// use yb_tokio_postgres::types::ToSql;
    /// use futures_util::{pin_mut, TryStreamExt};
    ///
    /// let params: Vec<String> = vec![
    ///     "first param".into(),
    ///     "second param".into(),
    /// ];
    /// let mut it = client.query_raw(
    ///     "SELECT foo FROM bar WHERE biz = $1 AND baz = $2",
    ///     params,
    /// ).await?;
    ///
    /// pin_mut!(it);
    /// while let Some(row) = it.try_next().await? {
    ///     let foo: i32 = row.get("foo");
    ///     println!("foo: {}", foo);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_raw<T, P, I>(&self, statement: &T, params: I) -> Result<RowStream, Error>
    where
        T: ?Sized + ToStatement,
        P: BorrowToSql,
        I: IntoIterator<Item = P>,
        I::IntoIter: ExactSizeIterator,
    {
        observe::operation(None);
        let statement = statement.__convert().into_statement(self).await?;
        query::query(&self.inner, statement, params).await
    }

    /// Executes a statement, returning the number of rows modified.
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    ///
    /// If the statement does not modify any rows (e.g. `SELECT`), 0 is returned.
    pub async fn execute<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.execute_raw(statement, slice_iter(params)).await
    }

    /// The maximally flexible version of [`execute`].
    ///
    /// A statement may contain parameters, specified by `$n`, where `n` is the index of the parameter of the list
    /// provided, 1-indexed.
    ///
    /// The `statement` argument can either be a `Statement`, or a raw query string. If the same statement will be
    /// repeatedly executed (perhaps with different query parameters), consider preparing the statement up front
    /// with the `prepare` method.
    ///
    /// [`execute`]: #method.execute
    pub async fn execute_raw<T, P, I>(&self, statement: &T, params: I) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
        P: BorrowToSql,
        I: IntoIterator<Item = P>,
        I::IntoIter: ExactSizeIterator,
    {
        observe::operation(None);
        let statement = statement.__convert().into_statement(self).await?;
        query::execute(self.inner(), statement, params).await
    }

    /// Executes a `COPY FROM STDIN` statement, returning a sink used to write the copy data.
    ///
    /// PostgreSQL does not support parameters in `COPY` statements, so this method does not take any. The copy *must*
    /// be explicitly completed via the `Sink::close` or `finish` methods. If it is not, the copy will be aborted.
    pub async fn copy_in<T, U>(&self, statement: &T) -> Result<CopyInSink<U>, Error>
    where
        T: ?Sized + ToStatement,
        U: Buf + 'static + Send,
    {
        observe::operation(None);
        let statement = statement.__convert().into_statement(self).await?;
        copy_in::copy_in(self.inner(), statement).await
    }

    /// Executes a `COPY TO STDOUT` statement, returning a stream of the resulting data.
    ///
    /// PostgreSQL does not support parameters in `COPY` statements, so this method does not take any.
    pub async fn copy_out<T>(&self, statement: &T) -> Result<CopyOutStream, Error>
    where
        T: ?Sized + ToStatement,
    {
        observe::operation(None);
        let statement = statement.__convert().into_statement(self).await?;
        copy_out::copy_out(self.inner(), statement).await
    }

    /// Executes a sequence of SQL statements using the simple query protocol, returning the resulting rows.
    ///
    /// Statements should be separated by semicolons. If an error occurs, execution of the sequence will stop at that
    /// point. The simple query protocol returns the values in rows as strings rather than in their binary encodings,
    /// so the associated row type doesn't work with the `FromSql` trait. Rather than simply returning a list of the
    /// rows, this method returns a list of an enum which indicates either the completion of one of the commands,
    /// or a row of data. This preserves the framing between the separate statements in the request.
    ///
    /// # Warning
    ///
    /// Prepared statements should be use for any query which contains user-specified data, as they provided the
    /// functionality to safely embed that data in the request. Do not form statements via string concatenation and pass
    /// them to this method!
    pub async fn simple_query(&self, query: &str) -> Result<Vec<SimpleQueryMessage>, Error> {
        self.simple_query_raw(query).await?.try_collect().await
    }

    pub(crate) async fn simple_query_raw(&self, query: &str) -> Result<SimpleQueryStream, Error> {
        observe::operation(None);
        simple_query::simple_query(self.inner(), query).await
    }

    /// Executes a sequence of SQL statements using the simple query protocol.
    ///
    /// Statements should be separated by semicolons. If an error occurs, execution of the sequence will stop at that
    /// point. This is intended for use when, for example, initializing a database schema.
    ///
    /// # Warning
    ///
    /// Prepared statements should be use for any query which contains user-specified data, as they provided the
    /// functionality to safely embed that data in the request. Do not form statements via string concatenation and pass
    /// them to this method!
    pub async fn batch_execute(&self, query: &str) -> Result<(), Error> {
        observe::operation(None);
        simple_query::batch_execute(self.inner(), query).await
    }

    /// Begins a new database transaction.
    ///
    /// The transaction will roll back by default - use the `commit` method to commit it.
    pub async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        struct RollbackIfNotDone<'me> {
            client: &'me Client,
            done: bool,
        }

        impl<'a> Drop for RollbackIfNotDone<'a> {
            fn drop(&mut self) {
                if self.done {
                    return;
                }

                let buf = self.client.inner().with_buf(|buf| {
                    frontend::query("ROLLBACK", buf).unwrap();
                    buf.split().freeze()
                });
                observe::note(observe::Q::rollbacks, None);
                observe::note(observe::Q::automatic_rollbacks, None);
                let _ = self
                    .client
                    .inner()
                    .send(RequestMessages::Single(FrontendMessage::Raw(buf)));
            }
        }

        // This is done, as `Future` created by this method can be dropped after
        // `RequestMessages` is synchronously send to the `Connection` by
        // `batch_execute()`, but before `Responses` is asynchronously polled to
        // completion. In that case `Transaction` won't be created and thus
        // won't be rolled back.
        {
            let mut cleaner = RollbackIfNotDone {
                client: self,
                done: false,
            };
            self.batch_execute("BEGIN").await?;
            cleaner.done = true;
        }

        Ok(Transaction::new(self))
    }

    /// Returns a builder for a transaction with custom settings.
    ///
    /// Unlike the `transaction` method, the builder can be used to control the transaction's isolation level and other
    /// attributes.
    pub fn build_transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder::new(self)
    }

    /// Constructs a cancellation token that can later be used to request cancellation of a query running on the
    /// connection associated with this client.
    pub fn cancel_token(&self) -> CancelToken {
        CancelToken {
            #[cfg(feature = "runtime")]
            socket_config: self.socket_config.clone(),
            ssl_mode: self.ssl_mode,
            process_id: self.process_id,
            secret_key: self.secret_key,
        }
    }

    /// Attempts to cancel an in-progress query.
    ///
    /// The server provides no information about whether a cancellation attempt was successful or not. An error will
    /// only be returned if the client was unable to connect to the database.
    ///
    /// Requires the `runtime` Cargo feature (enabled by default).
    #[cfg(feature = "runtime")]
    #[deprecated(since = "0.6.0", note = "use Client::cancel_token() instead")]
    pub async fn cancel_query<T>(&self, tls: T) -> Result<(), Error>
    where
        T: MakeTlsConnect<Socket>,
    {
        self.cancel_token().cancel_query(tls).await
    }

    /// Like `cancel_query`, but uses a stream which is already connected to the server rather than opening a new
    /// connection itself.
    #[deprecated(since = "0.6.0", note = "use Client::cancel_token() instead")]
    pub async fn cancel_query_raw<S, T>(&self, stream: S, tls: T) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: TlsConnect<S>,
    {
        self.cancel_token().cancel_query_raw(stream, tls).await
    }

    /// Clears the client's type information cache.
    ///
    /// When user-defined types are used in a query, the client loads their definitions from the database and caches
    /// them for the lifetime of the client. If those definitions are changed in the database, this method can be used
    /// to flush the local cache and allow the new, updated definitions to be loaded.
    pub fn clear_type_cache(&self) {
        self.inner().clear_type_cache();
    }

    /// Determines if the connection to the server has already closed.
    ///
    /// In that case, all future queries will fail.
    pub fn is_closed(&self) -> bool {
        self.inner.sender.is_closed()
    }

    /// The transaction status reported by the most recent `ReadyForQuery`
    /// the connection processed. Costs no round trip.
    ///
    /// While [`pending_requests`](Self::pending_requests) is non-zero this
    /// can lag behind requests already sent.
    pub fn transaction_status(&self) -> TransactionStatus {
        self.inner.session.transaction_status()
    }

    /// Requests sent to the connection whose `ReadyForQuery` has not been
    /// processed yet, including fire-and-forget requests such as the
    /// `ROLLBACK` of a dropped [`Transaction`] or the `Close` of a dropped
    /// [`Statement`]. A dropped (cancelled) query future leaves its request
    /// pending until the server finishes it.
    pub fn pending_requests(&self) -> u64 {
        self.inner.session.pending()
    }

    /// Of [`pending_requests`](Self::pending_requests), those other than the
    /// fire-and-forget `Close` a dropped [`Statement`] or [`Portal`] sends.
    /// The `ROLLBACK` of a dropped [`Transaction`] and a dropped (cancelled)
    /// query future's request are counted.
    ///
    /// A `Close` changes no session state and the connection writes later
    /// requests after it, so a client whose count is zero and whose
    /// [`transaction_status`](Self::transaction_status) is
    /// [`TransactionStatus::Idle`] can be reused at once. Read this count
    /// first: once it is zero, `transaction_status` reflects the
    /// `ReadyForQuery` of every request it counted.
    ///
    /// [`Portal`]: crate::Portal
    pub fn pending_caller_requests(&self) -> u64 {
        self.inner.session.caller_pending()
    }

    /// Whether a response broke the protocol of the request it was routed to
    /// (an unexpected or unparseable message). Such a session may have lost
    /// track of which response belongs to which request, so it should not be
    /// reused for another caller; pools retire it. Never cleared.
    pub fn is_poisoned(&self) -> bool {
        self.inner.session.poisoned()
    }

    /// The number of `ParameterStatus` messages received after startup.
    ///
    /// The server reports changes to `GUC_REPORT` settings (for example
    /// `application_name`, `TimeZone`, `DateStyle`, `is_superuser` and
    /// `session_authorization`), so a change in this counter means session
    /// state was modified. Other settings such as `search_path` (before
    /// PostgreSQL 18) and `role` are not reported.
    pub fn parameter_status_changes(&self) -> u64 {
        self.inner.session.parameter_changes()
    }

    /// Resolves once no request is pending or the connection has closed.
    ///
    /// Only one task should wait at a time.
    pub async fn wait_until_settled(&self) {
        self.inner.session.settle().await
    }

    #[doc(hidden)]
    pub fn __private_api_close(&mut self) {
        self.inner.sender.close_channel()
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish()
    }
}
