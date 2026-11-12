//! Semantic SQL wire observation.
//!
//! This module accounts for the PostgreSQL protocol exchanges a client makes,
//! attributed to the request (scope) that issued them, without recording SQL
//! text, parameters, credentials or endpoint addresses. It ports the AST-1761
//! observation contract from the retired SQLx facade to the native driver.
//!
//! # Boundaries
//!
//! Every quantity is observed at a documented protocol boundary:
//!
//! * **Logical operations** are counted when a [`Client`](crate::Client) or
//!   [`Transaction`](crate::Transaction) API call that issues SQL starts
//!   (`query*`, `execute*`, `prepare*`, `simple_query`, `batch_execute`,
//!   `copy_in`, `copy_out`, `bind*`, `query_portal*`). Convenience wrappers
//!   (`query`, `query_one`, ...) count once. Statement preparation that a
//!   query performs implicitly is not a separate operation.
//! * A **protocol cycle** is one driver request handed to the connection task,
//!   ended by its terminating `ReadyForQuery`. Each request carries exactly one
//!   `Sync` or simple `Query`, except `COPY FROM STDIN`, whose extra `Sync` is
//!   ignored by the server. A cycle is *queued* when handed to the connection
//!   task, *written* when its first frame is encoded into the transport
//!   buffer, *completed* when a valid `ReadyForQuery` (`I`, `T` or `E`) is
//!   routed to it, and *abandoned* when the connection ends (or the request
//!   could not be handed over) before that. A cycle is not a network round
//!   trip and not a statement count: a simple query with three statements is
//!   one cycle, and pipelined cycles share round trips.
//! * **Frontend messages** (`Query`, `Parse`, `Bind`, `Describe`, `Execute`,
//!   `Close`, `Sync`, `Flush`, `CopyData`, `CopyDone`, `CopyFail`) are counted
//!   by tag as the connection task encodes them; **protocol bytes** are the
//!   plaintext PostgreSQL message bytes written for, and routed to, a request.
//! * **Socket bytes** are counted on the runtime [`Socket`](crate::Socket)
//!   itself and split into plaintext and encrypted (after a TLS negotiation
//!   `S` reply), per [`SocketRole`]. TLS records interleave requests, so socket
//!   bytes are only reported in process totals, never per scope.
//! * **Sessions** are counted when the startup/authentication exchange ends
//!   (`ReadyForQuery`, or an error after the transport connected).
//!
//! # Attribution
//!
//! [`scope`] runs a future with a request context (a bounded route label). A
//! request captures the context of the task that issues it, and the capture
//! travels with the request across the connection task, so counts from
//! pipelined requests on a shared connection, from row streams polled after
//! the call returned, and from automatic rollbacks stay with their issuer.
//! Spawned tasks do not inherit the context: carry it with [`current`] and
//! [`ScopeHandle::attach`]. Work issued with no context is *unscoped*
//! (background). Work completing after its scope finished is still added to
//! that scope's (unread) counts and to the `late_*` totals.
//!
//! Each event is attributed to a [`Class`]: the ambient class set with
//! [`with_class`] (discovery, health checks, session setup) wins; otherwise
//! statement preparation (`Parse`/`Describe`, type lookups, statement close)
//! is [`Class::Preparation`]; everything else is [`Class::Request`]. The
//! driver itself marks connection establishment as
//! [`Class::SessionSetup`] and `yb_servers()` refreshes, including their
//! control connections, as [`Class::Discovery`].
//!
//! # Cost
//!
//! Until [`enable`] (or the first [`scope`]) the hooks cost one relaxed atomic
//! load each. Enabled, a request costs one context lookup, one header walk
//! over its frontend and backend bytes, and a few uncontended lock and
//! atomic updates.
//!
//! # Privacy
//!
//! Nothing here stores SQL text, parameters, server messages or addresses.
//! Labels are bounded: five classes, three socket roles, and route labels that
//! are `&'static str` (so bounded by the program), validated, and capped at
//! [`MAX_ROUTES`] distinct values in the process totals.

use std::fmt::{self, Write as _};
use std::future::Future;
use std::sync::atomic::{
    AtomicU64,
    Ordering::{Relaxed, SeqCst},
};
use std::sync::{Arc, Mutex, MutexGuard};

/// Observation switch and disable epoch in one word: `epoch << 1 | enabled`.
/// Every disable advances the epoch and clears bit 0 in a single atomic
/// update, so a scope that captured an enabled state and finds the identical
/// state at its end saw observation on for its whole lifetime.
static STATE: AtomicU64 = AtomicU64::new(0);

/// Turns observation on for the whole process.
///
/// Requests and sockets created while observation is off are not counted.
/// Install it before opening connections. [`scope`] enables it implicitly.
pub fn enable() {
    set_enabled(true);
}

/// Turns observation on or off. Requests already in flight keep the
/// accounting they started with. A scope that was open while observation
/// was turned off reports [`Counts::observed`] `false`, even if it was
/// turned on again before the scope ended.
pub fn set_enabled(enabled: bool) {
    if enabled {
        STATE.fetch_or(1, SeqCst);
    } else {
        let _ = STATE.fetch_update(SeqCst, SeqCst, |state| {
            Some(((state >> 1).wrapping_add(1)) << 1)
        });
    }
}

/// Whether observation is on.
pub fn is_enabled() -> bool {
    enabled()
}

#[inline]
pub(crate) fn enabled() -> bool {
    STATE.load(Relaxed) & 1 == 1
}

/// What a protocol exchange was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Application SQL.
    Request,
    /// Statement preparation: `Parse`/`Describe`, type lookups and closing
    /// prepared statements.
    Preparation,
    /// Connection establishment: transport, TLS, startup, authentication and
    /// any SQL run while setting up the session (for example
    /// `target_session_attrs` checks or pool session initialisation).
    SessionSetup,
    /// Connection health checks (for example a pool's validation ping).
    HealthCheck,
    /// Topology discovery: `yb_servers()` refreshes and their control
    /// connections.
    Discovery,
}

/// The number of [`Class`] values.
pub const CLASSES: usize = 5;

impl Class {
    /// Every class, in label order.
    pub const ALL: [Class; CLASSES] = [
        Class::Request,
        Class::Preparation,
        Class::SessionSetup,
        Class::HealthCheck,
        Class::Discovery,
    ];

    /// The bounded metric label for this class.
    pub fn label(self) -> &'static str {
        match self {
            Class::Request => "request",
            Class::Preparation => "preparation",
            Class::SessionSetup => "session_setup",
            Class::HealthCheck => "health_check",
            Class::Discovery => "discovery",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

macro_rules! quantities {
    ($( $(#[$doc:meta])* $name:ident, )*) => {
        /// Counts for one [`Class`]. Every field is a monotonically increasing
        /// event count (saturating).
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct ClassCounts {
            $( $(#[$doc])* pub $name: u64, )*
        }

        // Every quantity has a variant; only some are recorded one at a time.
        #[allow(non_camel_case_types, dead_code)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum Q {
            $( $name, )*
        }

        const QUANTITY_NAMES: &[&str] = &[$( stringify!($name), )*];
        const QUANTITIES: usize = QUANTITY_NAMES.len();

        impl ClassCounts {
            /// Field names, in [`ClassCounts::iter`] order. Also the metric
            /// quantity names.
            pub const NAMES: &'static [&'static str] = QUANTITY_NAMES;

            #[inline]
            fn add(&mut self, q: Q, n: u64) {
                match q {
                    $( Q::$name => self.$name = self.$name.saturating_add(n), )*
                }
            }

            fn values(&self) -> [u64; QUANTITIES] {
                [$( self.$name, )*]
            }

            fn from_values(values: [u64; QUANTITIES]) -> ClassCounts {
                let mut it = IntoIterator::into_iter(values);
                ClassCounts {
                    $( $name: it.next().unwrap_or(0), )*
                }
            }
        }
    };
}

quantities! {
    /// Logical SQL operations started through the client API.
    operations,
    /// Connection acquisition attempts reported by a pool
    /// ([`note_acquisition`]). Never inferred from SQL.
    acquisitions,
    /// Protocol cycles handed to the connection task.
    cycles_queued,
    /// Protocol cycles whose frames were encoded into the transport buffer.
    cycles_written,
    /// Protocol cycles ended by a valid `ReadyForQuery`.
    cycles_completed,
    /// Protocol cycles that ended without `ReadyForQuery` (connection closed,
    /// failed or dropped first, or an invalid `ReadyForQuery`).
    cycles_abandoned,
    /// Of `cycles_queued`, fire-and-forget cycles issued when a prepared
    /// statement or portal is dropped (`Close`/`Sync`). Nobody waits for them,
    /// so they do not make a scope incomplete while in flight.
    detached_cycles_queued,
    /// Of `cycles_completed + cycles_abandoned`, detached cycles that ended.
    detached_cycles_ended,
    /// Simple-protocol `Query` messages.
    query_messages,
    /// `Parse` messages.
    parse_messages,
    /// `Bind` messages.
    bind_messages,
    /// `Describe` messages.
    describe_messages,
    /// `Execute` messages.
    execute_messages,
    /// `Close` messages.
    close_messages,
    /// `Sync` messages.
    sync_messages,
    /// `Flush` messages.
    flush_messages,
    /// `CopyData` messages sent.
    copy_data_messages,
    /// `CopyDone` messages.
    copy_done_messages,
    /// `CopyFail` messages.
    copy_fail_messages,
    /// Other frontend messages.
    other_messages,
    /// Plaintext protocol bytes written for requests.
    protocol_bytes_sent,
    /// Plaintext protocol bytes routed to requests (excludes asynchronous
    /// notices, notifications and parameter-status messages).
    protocol_bytes_received,
    /// `ErrorResponse` messages routed to requests.
    error_responses,
    /// Cycles that started inside a transaction block (the previous
    /// `ReadyForQuery` reported `T` or `E`): transaction-internal statements
    /// including the closing `COMMIT`/`ROLLBACK`, excluding `BEGIN`.
    transaction_cycles,
    /// Cycles that started inside a failed transaction block (`E`).
    failed_transaction_cycles,
    /// Rollbacks issued by the driver (explicit `Transaction::rollback` and
    /// automatic rollbacks).
    rollbacks,
    /// Rollbacks issued automatically because a transaction was dropped or
    /// its `BEGIN` was cancelled.
    automatic_rollbacks,
    /// Cancel requests sent (`CancelToken`).
    cancel_requests,
    /// Sessions whose startup and authentication completed.
    sessions_started,
    /// Sessions that failed after the transport connected (TLS, startup or
    /// authentication).
    session_failures,
}

impl ClassCounts {
    /// `(name, value)` pairs for every field.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> {
        QUANTITY_NAMES.iter().copied().zip(self.values())
    }

    /// Adds `other` to `self`.
    pub fn merge(&mut self, other: &ClassCounts) {
        let mut values = self.values();
        for (value, add) in values.iter_mut().zip(other.values()) {
            *value = value.saturating_add(add);
        }
        *self = ClassCounts::from_values(values);
    }

    /// Awaited cycles handed over but not yet completed or abandoned.
    /// Detached cycles are reported by [`ClassCounts::detached_pending_cycles`].
    pub fn pending_cycles(&self) -> u64 {
        let awaited = self
            .cycles_queued
            .saturating_sub(self.detached_cycles_queued);
        let ended = self
            .cycles_completed
            .saturating_add(self.cycles_abandoned)
            .saturating_sub(self.detached_cycles_ended);
        awaited.saturating_sub(ended)
    }

    /// Detached cycles (statement or portal close on drop) still in flight.
    pub fn detached_pending_cycles(&self) -> u64 {
        self.detached_cycles_queued
            .saturating_sub(self.detached_cycles_ended)
    }

    /// All frontend messages counted by tag.
    pub fn messages(&self) -> u64 {
        [
            self.query_messages,
            self.parse_messages,
            self.bind_messages,
            self.describe_messages,
            self.execute_messages,
            self.close_messages,
            self.sync_messages,
            self.flush_messages,
            self.copy_data_messages,
            self.copy_done_messages,
            self.copy_fail_messages,
            self.other_messages,
        ]
        .iter()
        .fold(0u64, |a, b| a.saturating_add(*b))
    }
}

/// Counts for one scope, by class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    route: &'static str,
    observed: bool,
    classes: [ClassCounts; CLASSES],
}

impl Counts {
    /// The scope's route label.
    pub fn route(&self) -> &'static str {
        self.route
    }

    /// Whether observation stayed enabled for the scope's whole lifetime.
    /// Counts of an unobserved scope are not evidence of zero exchanges.
    pub fn observed(&self) -> bool {
        self.observed
    }

    /// The counts of one class.
    pub fn class(&self, class: Class) -> &ClassCounts {
        &self.classes[class.index()]
    }

    /// The sum over all classes.
    pub fn total(&self) -> ClassCounts {
        let mut total = ClassCounts::default();
        for class in &self.classes {
            total.merge(class);
        }
        total
    }

    /// Awaited cycles of any class that had not ended when the scope
    /// finished.
    pub fn pending_cycles(&self) -> u64 {
        self.total().pending_cycles()
    }

    /// Detached cycles of any class still in flight when the scope finished.
    pub fn detached_pending_cycles(&self) -> u64 {
        self.total().detached_pending_cycles()
    }

    /// Whether the counts are a complete observation: observed, with every
    /// awaited cycle ended by a valid `ReadyForQuery` and no cycle abandoned.
    /// Detached cycles still in flight are allowed; they finish on the
    /// connection before any later request and are reported by
    /// [`Counts::detached_pending_cycles`] and the `late_*` totals.
    /// Incomplete counts must not be recorded as if they were exact
    /// (AST-1761).
    pub fn is_complete(&self) -> bool {
        let total = self.total();
        self.observed && total.pending_cycles() == 0 && total.cycles_abandoned == 0
    }
}

/// Process totals per [`SocketRole`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketCounts {
    /// Sockets that carried at least one byte, counted once under their
    /// final role.
    pub opened: u64,
    /// Bytes written while the socket carried plaintext (including the TLS
    /// negotiation request).
    pub plaintext_bytes_sent: u64,
    /// Bytes read while the socket carried plaintext (including the TLS
    /// negotiation reply).
    pub plaintext_bytes_received: u64,
    /// Bytes written after TLS was negotiated (handshake and records).
    pub encrypted_bytes_sent: u64,
    /// Bytes read after TLS was negotiated (handshake and records).
    pub encrypted_bytes_received: u64,
}

/// What a socket was opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketRole {
    /// A connection that serves SQL.
    Data,
    /// A discovery control connection.
    Discovery,
    /// A cancel-request connection.
    Cancel,
}

impl SocketRole {
    /// Every role, in label order.
    pub const ALL: [SocketRole; 3] = [SocketRole::Data, SocketRole::Discovery, SocketRole::Cancel];

    /// The bounded metric label for this role.
    pub fn label(self) -> &'static str {
        match self {
            SocketRole::Data => "data",
            SocketRole::Discovery => "discovery",
            SocketRole::Cancel => "cancel",
        }
    }
}

/// Totals for one route label.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteTotals {
    /// The route label (or `"other"` once [`MAX_ROUTES`] were seen).
    pub route: &'static str,
    /// Scopes that finished with complete counts.
    pub complete_scopes: u64,
    /// Scopes that finished with incomplete counts.
    pub incomplete_scopes: u64,
    /// Scopes dropped before their future finished.
    pub cancelled_scopes: u64,
    /// Sum over all classes of everything attributed to scopes of this
    /// route: finished and cancelled scopes, including work that completed
    /// after its scope ended.
    pub counts: ClassCounts,
}

/// Process-wide totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    scoped: [ClassCounts; CLASSES],
    unscoped: [ClassCounts; CLASSES],
    /// Cycles completed after their scope finished.
    pub late_completed: u64,
    /// Cycles abandoned after their scope finished.
    pub late_abandoned: u64,
    /// Other updates recorded after their scope finished (for example a
    /// late batch of rows), counted per update.
    pub late_other: u64,
    sockets: [SocketCounts; 3],
    /// Per-route totals (bounded by [`MAX_ROUTES`] plus `"other"`).
    pub routes: Vec<RouteTotals>,
}

impl Totals {
    /// Events attributed to a scope (including late ones).
    pub fn scoped(&self, class: Class) -> &ClassCounts {
        &self.scoped[class.index()]
    }

    /// Events issued with no scope (background work).
    pub fn unscoped(&self, class: Class) -> &ClassCounts {
        &self.unscoped[class.index()]
    }

    /// Socket totals for one role.
    pub fn sockets(&self, role: SocketRole) -> &SocketCounts {
        &self.sockets[role as usize]
    }

    /// Renders the totals in the Prometheus text format under `namespace`
    /// (for example `git_storage`). Every label value is bounded.
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is not a valid metric name prefix.
    pub fn render_prometheus(&self, namespace: &str) -> String {
        assert!(
            !namespace.is_empty()
                && namespace.bytes().enumerate().all(|(i, b)| b == b'_'
                    || b.is_ascii_alphabetic()
                    || (i > 0 && b.is_ascii_digit())),
            "invalid metric namespace"
        );
        let mut out = String::new();
        for (index, name) in QUANTITY_NAMES.iter().enumerate() {
            let _ = writeln!(out, "# TYPE {namespace}_sql_wire_{name}_total counter");
            for (scope, counts) in [("scoped", &self.scoped), ("unscoped", &self.unscoped)] {
                for class in Class::ALL {
                    let _ = writeln!(
                        out,
                        "{namespace}_sql_wire_{name}_total{{scope=\"{scope}\",class=\"{}\"}} {}",
                        class.label(),
                        counts[class.index()].values()[index]
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "# TYPE {namespace}_sql_wire_socket_bytes_total counter"
        );
        for role in SocketRole::ALL {
            let s = self.sockets(role);
            for (encryption, direction, value) in [
                ("plaintext", "sent", s.plaintext_bytes_sent),
                ("plaintext", "received", s.plaintext_bytes_received),
                ("encrypted", "sent", s.encrypted_bytes_sent),
                ("encrypted", "received", s.encrypted_bytes_received),
            ] {
                let _ = writeln!(
                    out,
                    "{namespace}_sql_wire_socket_bytes_total{{role=\"{}\",encryption=\"{encryption}\",direction=\"{direction}\"}} {value}",
                    role.label()
                );
            }
        }
        let _ = writeln!(
            out,
            "# TYPE {namespace}_sql_wire_sockets_opened_total counter"
        );
        for role in SocketRole::ALL {
            let _ = writeln!(
                out,
                "{namespace}_sql_wire_sockets_opened_total{{role=\"{}\"}} {}",
                role.label(),
                self.sockets(role).opened
            );
        }
        let _ = writeln!(out, "# TYPE {namespace}_sql_wire_late_total counter");
        for (kind, value) in [
            ("completed", self.late_completed),
            ("abandoned", self.late_abandoned),
            ("other", self.late_other),
        ] {
            let _ = writeln!(
                out,
                "{namespace}_sql_wire_late_total{{kind=\"{kind}\"}} {value}"
            );
        }
        let _ = writeln!(out, "# TYPE {namespace}_sql_wire_scopes_total counter");
        let _ = writeln!(
            out,
            "# TYPE {namespace}_sql_wire_route_cycles_completed_total counter"
        );
        for route in &self.routes {
            for (outcome, value) in [
                ("complete", route.complete_scopes),
                ("incomplete", route.incomplete_scopes),
                ("cancelled", route.cancelled_scopes),
            ] {
                let _ = writeln!(
                    out,
                    "{namespace}_sql_wire_scopes_total{{route=\"{}\",outcome=\"{outcome}\"}} {value}",
                    route.route
                );
            }
            let _ = writeln!(
                out,
                "{namespace}_sql_wire_route_cycles_completed_total{{route=\"{}\"}} {}",
                route.route, route.counts.cycles_completed
            );
        }
        out
    }
}

/// The maximum number of distinct route labels kept in [`Totals::routes`].
/// Later labels are folded into `"other"`.
pub const MAX_ROUTES: usize = 128;

/// The label used for routes that fail validation.
pub const INVALID_ROUTE: &str = "invalid";

/// The label used for routes beyond [`MAX_ROUTES`].
pub const OTHER_ROUTE: &str = "other";

/// Returns `route` if it is a valid bounded label (1 to 64 bytes of ASCII
/// letters, digits and `_ . : / - { }`), else [`INVALID_ROUTE`].
pub fn route_label(route: &'static str) -> &'static str {
    let valid = !route.is_empty()
        && route.len() <= 64
        && route
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-{}".contains(&b));
    if valid {
        route
    } else {
        INVALID_ROUTE
    }
}

// ---------------------------------------------------------------------------
// Global state.

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const ROW: [AtomicU64; QUANTITIES] = [ZERO; QUANTITIES];
#[allow(clippy::declare_interior_mutable_const)]
const SOCKET_ROW: [AtomicU64; 5] = [ZERO; 5];

static SCOPED: [[AtomicU64; QUANTITIES]; CLASSES] = [ROW; CLASSES];
static UNSCOPED: [[AtomicU64; QUANTITIES]; CLASSES] = [ROW; CLASSES];
static SOCKETS: [[AtomicU64; 5]; 3] = [SOCKET_ROW; 3];
static LATE_COMPLETED: AtomicU64 = AtomicU64::new(0);
static LATE_ABANDONED: AtomicU64 = AtomicU64::new(0);
static LATE_OTHER: AtomicU64 = AtomicU64::new(0);
static ROUTES: Mutex<Vec<RouteTotals>> = Mutex::new(Vec::new());

// Observation must never turn poisoned metadata into a database panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn load(row: &[AtomicU64; QUANTITIES]) -> ClassCounts {
    let mut values = [0u64; QUANTITIES];
    for (value, atom) in values.iter_mut().zip(row.iter()) {
        *value = atom.load(Relaxed);
    }
    ClassCounts::from_values(values)
}

/// Returns the process totals.
pub fn totals() -> Totals {
    let mut totals = Totals {
        late_completed: LATE_COMPLETED.load(Relaxed),
        late_abandoned: LATE_ABANDONED.load(Relaxed),
        late_other: LATE_OTHER.load(Relaxed),
        routes: lock(&ROUTES).clone(),
        ..Totals::default()
    };
    for class in Class::ALL {
        totals.scoped[class.index()] = load(&SCOPED[class.index()]);
        totals.unscoped[class.index()] = load(&UNSCOPED[class.index()]);
    }
    for role in SocketRole::ALL {
        let row = &SOCKETS[role as usize];
        totals.sockets[role as usize] = SocketCounts {
            opened: row[0].load(Relaxed),
            plaintext_bytes_sent: row[1].load(Relaxed),
            plaintext_bytes_received: row[2].load(Relaxed),
            encrypted_bytes_sent: row[3].load(Relaxed),
            encrypted_bytes_received: row[4].load(Relaxed),
        };
    }
    totals
}

fn route_entry<'a>(routes: &'a mut Vec<RouteTotals>, route: &'static str) -> &'a mut RouteTotals {
    let route = match routes.iter().position(|r| r.route == route) {
        Some(index) => return &mut routes[index],
        None if routes.len() < MAX_ROUTES || route == OTHER_ROUTE => route,
        None => OTHER_ROUTE,
    };
    match routes.iter().position(|r| r.route == route) {
        Some(index) => &mut routes[index],
        None => {
            routes.push(RouteTotals {
                route,
                ..RouteTotals::default()
            });
            routes.last_mut().unwrap()
        }
    }
}

// ---------------------------------------------------------------------------
// Scopes and context.

struct ScopeData {
    classes: [ClassCounts; CLASSES],
    closed: bool,
}

struct ScopeCell {
    route: &'static str,
    /// `STATE` when the scope started.
    start_state: u64,
    data: Mutex<ScopeData>,
}

tokio::task_local! {
    static OWNER: Arc<ScopeCell>;
    static CLASS: Class;
}

fn current_owner() -> Option<Arc<ScopeCell>> {
    OWNER.try_with(Arc::clone).ok()
}

fn current_class() -> Option<Class> {
    CLASS.try_with(|class| *class).ok()
}

struct ScopeGuard(Arc<ScopeCell>);

impl ScopeGuard {
    fn finish(&self) -> Counts {
        let classes = {
            let mut data = lock(&self.0.data);
            data.closed = true;
            data.classes
        };
        let observed = self.0.start_state & 1 == 1 && STATE.load(SeqCst) == self.0.start_state;
        let counts = Counts {
            route: self.0.route,
            observed,
            classes,
        };
        let total = counts.total();
        let mut routes = lock(&ROUTES);
        let entry = route_entry(&mut routes, self.0.route);
        if counts.is_complete() {
            entry.complete_scopes = entry.complete_scopes.saturating_add(1);
        } else {
            entry.incomplete_scopes = entry.incomplete_scopes.saturating_add(1);
        }
        entry.counts.merge(&total);
        counts
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let (closed, classes) = {
            let mut data = lock(&self.0.data);
            (std::mem::replace(&mut data.closed, true), data.classes)
        };
        if !closed {
            let mut total = ClassCounts::default();
            for class in &classes {
                total.merge(class);
            }
            let mut routes = lock(&ROUTES);
            let entry = route_entry(&mut routes, self.0.route);
            entry.cancelled_scopes = entry.cancelled_scopes.saturating_add(1);
            entry.counts.merge(&total);
        }
    }
}

/// Runs `future` as one observed request labelled `route`, returning its
/// output and the protocol exchanges it issued.
///
/// The route should be a bounded label such as an operation name; invalid
/// labels become [`INVALID_ROUTE`]. Nested scopes are independent: the inner
/// scope's exchanges are not added to the outer one. The ambient [`Class`] is
/// inherited. Enables observation.
pub async fn scope<F: Future>(route: &'static str, future: F) -> (F::Output, Counts) {
    enable();
    let start_state = STATE.load(SeqCst);
    let cell = Arc::new(ScopeCell {
        route: route_label(route),
        start_state,
        data: Mutex::new(ScopeData {
            classes: [ClassCounts::default(); CLASSES],
            closed: false,
        }),
    });
    let guard = ScopeGuard(cell.clone());
    let output = OWNER.scope(cell, future).await;
    (output, guard.finish())
}

/// Runs `future` with `class` as the ambient attribution class. The scope
/// (if any) is unchanged. The innermost `with_class` wins.
///
/// Pools should wrap health checks in [`Class::HealthCheck`] and session
/// initialisation in [`Class::SessionSetup`].
pub fn with_class<F: Future>(class: Class, future: F) -> impl Future<Output = F::Output> {
    CLASS.scope(class, future)
}

/// A handle to the current request context, used to carry it into spawned
/// tasks and other futures polled outside the scope.
#[derive(Clone)]
pub struct ScopeHandle {
    owner: Option<Arc<ScopeCell>>,
    class: Option<Class>,
}

impl fmt::Debug for ScopeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeHandle")
            .field("route", &self.route())
            .field("class", &self.class)
            .finish()
    }
}

impl ScopeHandle {
    /// The route label, or `None` outside any scope.
    pub fn route(&self) -> Option<&'static str> {
        self.owner.as_ref().map(|owner| owner.route)
    }

    /// The ambient class, if one was set.
    pub fn class(&self) -> Option<Class> {
        self.class
    }

    /// Runs `future` within this context. Parts of the context the handle
    /// does not carry (no scope, or no ambient class) are inherited from
    /// wherever the returned future is polled.
    pub fn attach<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        let owner = self.owner.clone();
        let class = self.class;
        async move {
            match (owner, class) {
                (Some(owner), Some(class)) => OWNER.scope(owner, CLASS.scope(class, future)).await,
                (Some(owner), None) => OWNER.scope(owner, future).await,
                (None, Some(class)) => CLASS.scope(class, future).await,
                (None, None) => future.await,
            }
        }
    }
}

/// The current request context, if the caller is inside [`scope`] or
/// [`with_class`]. Capture it before spawning and [`ScopeHandle::attach`] it
/// in the spawned task.
pub fn current() -> Option<ScopeHandle> {
    let owner = current_owner();
    let class = current_class();
    if owner.is_none() && class.is_none() {
        return None;
    }
    Some(ScopeHandle { owner, class })
}

/// The current scope's route label, if any.
pub fn current_route() -> Option<&'static str> {
    current_owner().map(|owner| owner.route)
}

/// Records one connection acquisition attempt for the current context. Pools
/// call this; the driver never infers acquisitions from SQL traffic.
pub fn note_acquisition() {
    if let Some(attribution) = Attribution::capture(None) {
        attribution.add(Q::acquisitions, 1);
    }
}

// ---------------------------------------------------------------------------
// Crate-internal recording.

#[derive(Clone)]
pub(crate) struct Attribution {
    owner: Option<Arc<ScopeCell>>,
    class: Class,
}

impl Attribution {
    /// Captures the current context, or `None` while observation is off.
    /// `purpose` applies unless an ambient class overrides it.
    #[inline]
    pub(crate) fn capture(purpose: Option<Class>) -> Option<Attribution> {
        if !enabled() {
            return None;
        }
        let owner = current_owner();
        // An ambient class set with `with_class` (including an explicit
        // `Class::Request`) wins over the driver's own purpose.
        let class = current_class().or(purpose).unwrap_or(Class::Request);
        Some(Attribution { owner, class })
    }

    pub(crate) fn add(&self, q: Q, n: u64) {
        let mut delta = ClassCounts::default();
        delta.add(q, n);
        self.apply(&delta);
    }

    fn apply(&self, delta: &ClassCounts) {
        let values = delta.values();
        let row = match &self.owner {
            Some(owner) => {
                let closed = {
                    let mut data = lock(&owner.data);
                    data.classes[self.class.index()].merge(delta);
                    data.closed
                };
                if closed {
                    // The scope already merged its snapshot into the route
                    // aggregate; late work is added there too.
                    {
                        let mut routes = lock(&ROUTES);
                        route_entry(&mut routes, owner.route).counts.merge(delta);
                    }
                    if delta.cycles_completed == 0 && delta.cycles_abandoned == 0 {
                        LATE_OTHER.fetch_add(1, Relaxed);
                    }
                    LATE_COMPLETED.fetch_add(delta.cycles_completed, Relaxed);
                    LATE_ABANDONED.fetch_add(delta.cycles_abandoned, Relaxed);
                }
                &SCOPED[self.class.index()]
            }
            None => &UNSCOPED[self.class.index()],
        };
        for (atom, value) in row.iter().zip(values) {
            if value != 0 {
                atom.fetch_add(value, Relaxed);
            }
        }
    }
}

/// Records one event of `q` for the current context.
#[inline]
pub(crate) fn note(q: Q, purpose: Option<Class>) {
    if let Some(attribution) = Attribution::capture(purpose) {
        attribution.add(q, 1);
    }
}

/// Counts one logical operation.
#[inline]
pub(crate) fn operation(purpose: Option<Class>) {
    note(Q::operations, purpose);
}

/// Per-request accounting, carried with the request into the connection task.
pub(crate) struct RequestObservation {
    attribution: Attribution,
    detached: bool,
    written: bool,
    ended: bool,
}

impl RequestObservation {
    /// Captures the issuing context and counts the cycle as queued. If the
    /// request is never handed over, dropping it counts it as abandoned.
    /// A `detached` request is one nobody awaits (close on drop).
    #[inline]
    pub(crate) fn start(purpose: Option<Class>, detached: bool) -> Option<RequestObservation> {
        let attribution = Attribution::capture(purpose)?;
        attribution.apply(&ClassCounts {
            cycles_queued: 1,
            detached_cycles_queued: detached as u64,
            ..ClassCounts::default()
        });
        Some(RequestObservation {
            attribution,
            detached,
            written: false,
            ended: false,
        })
    }

    /// Counts frontend messages encoded into the transport buffer for this
    /// request. `raw` is the encoded message bytes when available; otherwise
    /// the frame is a single `CopyData`.
    pub(crate) fn frontend(&mut self, raw: Option<&[u8]>, encoded_len: usize) {
        let mut delta = ClassCounts::default();
        if !self.written {
            self.written = true;
            delta.cycles_written = 1;
        }
        match raw {
            Some(raw) => classify_frontend(raw, &mut delta),
            None => delta.copy_data_messages = 1,
        }
        delta.protocol_bytes_sent = encoded_len as u64;
        self.attribution.apply(&delta);
    }

    /// Counts backend messages routed to this request. `ready` is the
    /// `ReadyForQuery` status when the batch completes the request, and
    /// `prior` the connection's transaction status before it.
    pub(crate) fn backend(&mut self, scan: BackendScan, ready: Option<u8>, prior: u8) {
        let mut delta = ClassCounts {
            protocol_bytes_received: scan.bytes,
            error_responses: scan.errors,
            ..ClassCounts::default()
        };
        if let Some(status) = ready {
            self.ended = true;
            delta.detached_cycles_ended = self.detached as u64;
            if matches!(status, b'I' | b'T' | b'E') {
                if !self.written {
                    self.written = true;
                    delta.cycles_written = 1;
                }
                delta.cycles_completed = 1;
                if matches!(prior, b'T' | b'E') {
                    delta.transaction_cycles = 1;
                }
                if prior == b'E' {
                    delta.failed_transaction_cycles = 1;
                }
            } else {
                delta.cycles_abandoned = 1;
            }
        }
        self.attribution.apply(&delta);
    }
}

impl Drop for RequestObservation {
    fn drop(&mut self) {
        if !self.ended {
            self.attribution.apply(&ClassCounts {
                cycles_abandoned: 1,
                detached_cycles_ended: self.detached as u64,
                ..ClassCounts::default()
            });
        }
    }
}

/// Header-only summary of a batch of backend messages.
#[derive(Clone, Copy, Default)]
pub(crate) struct BackendScan {
    pub(crate) bytes: u64,
    pub(crate) errors: u64,
}

pub(crate) fn scan_backend(buf: &[u8]) -> BackendScan {
    let mut scan = BackendScan {
        bytes: buf.len() as u64,
        errors: 0,
    };
    let mut i = 0;
    while i + 5 <= buf.len() {
        if buf[i] == b'E' {
            scan.errors += 1;
        }
        let len = u32::from_be_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]) as usize;
        i = i.saturating_add(1).saturating_add(len.max(4));
    }
    scan
}

fn classify_frontend(buf: &[u8], delta: &mut ClassCounts) {
    let mut i = 0;
    while i + 5 <= buf.len() {
        let q = match buf[i] {
            b'Q' => &mut delta.query_messages,
            b'P' => &mut delta.parse_messages,
            b'B' => &mut delta.bind_messages,
            b'D' => &mut delta.describe_messages,
            b'E' => &mut delta.execute_messages,
            b'C' => &mut delta.close_messages,
            b'S' => &mut delta.sync_messages,
            b'H' => &mut delta.flush_messages,
            b'd' => &mut delta.copy_data_messages,
            b'c' => &mut delta.copy_done_messages,
            b'f' => &mut delta.copy_fail_messages,
            _ => &mut delta.other_messages,
        };
        *q += 1;
        let len = u32::from_be_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]) as usize;
        i = i.saturating_add(1).saturating_add(len.max(4));
    }
}

/// Counts a session that finished startup, or failed after connecting.
pub(crate) fn session(ok: bool) {
    note(
        if ok {
            Q::sessions_started
        } else {
            Q::session_failures
        },
        Some(Class::SessionSetup),
    );
}

// ---------------------------------------------------------------------------
// Socket bytes.

/// The PostgreSQL `SSLRequest` frame: length 8, code 80877103.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Negotiation {
    /// The first frontend bytes so far are this many bytes of an
    /// `SSLRequest` (a short write can split it).
    Fresh(u8),
    /// A complete `SSLRequest` was written; the server's answer decides.
    Requested,
    Plain,
    Tls,
}

impl Negotiation {
    fn wrote(&mut self, buf: &[u8]) {
        if let Negotiation::Fresh(matched) = *self {
            let matched = matched as usize;
            let want = &SSL_REQUEST[matched..];
            let take = buf.len().min(want.len());
            *self = if buf[..take] != want[..take] || buf.len() > want.len() {
                Negotiation::Plain
            } else if matched + take == SSL_REQUEST.len() {
                Negotiation::Requested
            } else {
                Negotiation::Fresh((matched + take) as u8)
            };
        }
    }

    /// Returns whether `buf` was read while the socket carried TLS.
    fn read(&mut self, buf: &[u8]) -> bool {
        let encrypted = *self == Negotiation::Tls;
        match (*self, buf.first()) {
            (Negotiation::Requested, Some(b'S')) => *self = Negotiation::Tls,
            (Negotiation::Requested, Some(_)) | (Negotiation::Fresh(_), Some(_)) => {
                *self = Negotiation::Plain
            }
            _ => {}
        }
        encrypted
    }
}

/// Classifies a byte sequence the way a runtime socket does: returns whether
/// the socket is encrypted after the given frontend writes and backend
/// reads. Exposed only for the qualification suite.
#[doc(hidden)]
pub fn __negotiation_is_encrypted(writes: &[&[u8]], reads: &[&[u8]]) -> bool {
    let mut negotiation = Negotiation::Fresh(0);
    for buf in writes.iter().filter(|b| !b.is_empty()) {
        negotiation.wrote(buf);
    }
    for buf in reads {
        negotiation.read(buf);
    }
    negotiation == Negotiation::Tls
}

/// Byte accounting for one runtime socket. The plaintext/encrypted split
/// follows the protocol: a socket is encrypted from the byte after the
/// server's `S` answer to an `SSLRequest`. A socket is counted as opened,
/// once and under its final role, when it first carries a byte.
#[derive(Debug)]
pub(crate) struct SocketObservation {
    role: SocketRole,
    negotiation: Negotiation,
    counted: bool,
}

impl SocketObservation {
    pub(crate) fn new() -> SocketObservation {
        let role = match current_class() {
            Some(Class::Discovery) => SocketRole::Discovery,
            _ => SocketRole::Data,
        };
        SocketObservation {
            role,
            negotiation: Negotiation::Fresh(0),
            counted: false,
        }
    }

    /// Sets the role. Callers set it before the first byte is written, so
    /// the opening is counted once under the final role.
    pub(crate) fn set_role(&mut self, role: SocketRole) {
        self.role = role;
    }

    #[inline]
    fn count(&mut self, column: usize, bytes: usize) {
        if enabled() {
            let row = &SOCKETS[self.role as usize];
            if !self.counted {
                self.counted = true;
                row[0].fetch_add(1, Relaxed);
            }
            row[column].fetch_add(bytes as u64, Relaxed);
        }
    }

    #[inline]
    pub(crate) fn wrote(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        self.negotiation.wrote(buf);
        let column = if self.negotiation == Negotiation::Tls {
            3
        } else {
            1
        };
        self.count(column, buf.len());
    }

    #[inline]
    pub(crate) fn read(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        let column = if self.negotiation.read(buf) { 4 } else { 2 };
        self.count(column, buf.len());
    }
}

// ---------------------------------------------------------------------------
// Redaction.

/// Formats an [`Error`](crate::Error) for logs without server-supplied text.
///
/// Database errors are reduced to their severity and SQLSTATE (see
/// [`RedactedDb`]); the message, detail, hint, position and `where` fields
/// (which can quote SQL, parameter values or keys) are omitted. Parameter and
/// column conversion errors print only their kind and index, since the
/// conversion's own message can quote the value. Other errors print their
/// kind and cause chain, which the driver builds from fixed text and redacted
/// endpoint labels.
pub struct Redacted<'a>(pub &'a crate::Error);

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::error::Error as _;
        if let Some(db) = self.0.as_db_error() {
            return write!(f, "db error: {}", RedactedDb(db));
        }
        self.0.fmt_kind(f)?;
        if self.0.is_conversion() {
            return Ok(());
        }
        let mut source = self.0.source();
        while let Some(cause) = source {
            if let Some(db) = cause.downcast_ref::<crate::error::DbError>() {
                write!(f, ": db error: {}", RedactedDb(db))?;
            } else if let Some(e) = cause.downcast_ref::<crate::Error>() {
                // A nested driver error is redacted by the same rules.
                return write!(f, ": {}", Redacted(e));
            } else {
                write!(f, ": {}", cause)?;
            }
            source = cause.source();
        }
        Ok(())
    }
}

/// Formats a [`DbError`](crate::error::DbError) (an error or notice) as
/// `SEVERITY (SQLSTATE)` using only values the driver validates.
///
/// The severity is the parsed, non-localized [`Severity`](crate::error::Severity)
/// (`UNKNOWN` when the server sent none the driver recognises), and the
/// SQLSTATE is printed only when it is five ASCII letters or digits
/// (`?????` otherwise). Neither field can carry other server text.
pub struct RedactedDb<'a>(pub &'a crate::error::DbError);

impl fmt::Display for RedactedDb<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.known_severity() {
            Some(severity) => write!(f, "{}", severity)?,
            None => f.write_str("UNKNOWN")?,
        }
        let code = self.0.code().code();
        if code.len() == 5 && code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            write!(f, " ({})", code)
        } else {
            f.write_str(" (?????)")
        }
    }
}

impl fmt::Debug for RedactedDb<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
