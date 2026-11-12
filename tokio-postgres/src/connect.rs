use crate::client::{Addr, SocketConfig};
use crate::config::{Host, LoadBalanceHosts, SslMode, TargetSessionAttrs};
use crate::connect_raw::connect_raw;
use crate::connect_socket::connect_socket;
use crate::endpoint::{self, ResolvedEndpoint};
use crate::realm::{deadline_after, is_node_scoped_failure, Realm};
use crate::tls::MakeTlsConnect;
use crate::{Client, Config, Connection, Error, SimpleQueryMessage, Socket};
use futures_util::{future, pin_mut, Future, FutureExt, Stream};
use log::warn;
use rand::seq::SliceRandom;
use std::net::IpAddr;
use std::task::Poll;
use std::time::{Duration, Instant};
use std::{cmp, io};
use tokio::net;
use tokio::time;

/// Upper bound on the TCP connect of a control connection. `connect_timeout`
/// only reaches `TcpStream::connect`; the TLS handshake and authentication
/// are bounded by the per-attempt limits in [`crate::realm`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect<T>(
    mut tls: T,
    config: &Config,
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    // Administrative, migration and probe clients connect directly. They get
    // the same bounds as load-balanced acquisitions: each host attempt
    // (DNS, TCP, TLS, authentication) within `yb_attempt_timeout`, the whole
    // call within `yb_acquire_timeout`.
    let mut pass = SeedPass::new(Some(config.yb_attempt_timeout))
        .deadline(deadline_after(config.yb_acquire_timeout));
    let outcome = time::timeout(
        config.yb_acquire_timeout.saturating_add(BACKSTOP_GRACE),
        connect_with_tls_ref(&mut tls, config, &mut pass),
    )
    .await;
    match outcome {
        Ok(result) => result,
        // A TLS or configuration error recorded before the budget ran out is
        // more useful to the caller than the timeout.
        Err(_) => Err(pass.take_reportable().unwrap_or_else(|| {
            Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "no connection was established within the {:?} acquisition budget",
                    config.yb_acquire_timeout
                ),
            ))
        })),
    }
}

/// How long after its deadline a timeout around a deadline-bounded attempt
/// fires. The attempt returns its own recorded error at the deadline; the
/// timeout is only a backstop and must not pre-empt that.
pub(crate) const BACKSTOP_GRACE: Duration = Duration::from_millis(50);

/// The bound on one host attempt ([`connect_host`]) and the resolved
/// addresses whose own endpoint failed in it.
pub(crate) struct HostAttempt {
    limit: Option<(Duration, Instant)>,
    /// Resolved addresses that failed with [`is_node_scoped_failure`].
    pub(crate) failed_addrs: Vec<String>,
}

impl HostAttempt {
    /// An attempt bounded by `limit` from now, if given.
    pub(crate) fn bounded(limit: Option<Duration>) -> HostAttempt {
        HostAttempt {
            limit: limit.map(|limit| (limit, deadline_after(limit))),
            failed_addrs: Vec::new(),
        }
    }

    /// Whether the bound has passed.
    fn expired(&self) -> bool {
        self.limit
            .map_or(false, |(_, deadline)| Instant::now() >= deadline)
    }

    /// Runs `step` within what is left of the bound.
    async fn run<F, R>(&self, label: &str, step: F) -> Result<R, Error>
    where
        F: Future<Output = Result<R, Error>>,
    {
        match self.limit {
            Some((limit, deadline)) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                establish_control_connection(label, limit, time::timeout(remaining, step).await)
            }
            None => step.await,
        }
    }
}

/// Which configured hosts a [`SeedPass`] tries, by whether they are
/// deferred.
#[derive(Clone, Copy)]
pub(crate) enum Seeds {
    All,
    Undeferred,
    Deferred,
}

/// Bounds and bookkeeping for one pass over the configured hosts.
pub(crate) struct SeedPass {
    select: Seeds,
    /// Bound on each host attempt.
    attempt_timeout: Option<Duration>,
    /// No attempt runs past this instant.
    deadline: Option<Instant>,
    /// Lower-case seed identities to try after every other seed.
    deferred: Vec<String>,
    /// What the caller sees if no host succeeds ([`record_failure`]).
    pub(crate) failure: Option<Error>,
    /// The aliases ([`seed_aliases`]) of each seed whose own endpoint
    /// failed ([`is_node_scoped_failure`]), one entry per failure.
    pub(crate) node_failures: Vec<Vec<String>>,
    /// Indices of the configured hosts this pass attempted.
    pub(crate) tried: Vec<usize>,
}

impl SeedPass {
    pub(crate) fn new(attempt_timeout: Option<Duration>) -> SeedPass {
        SeedPass {
            select: Seeds::All,
            attempt_timeout,
            deadline: None,
            deferred: Vec::new(),
            failure: None,
            node_failures: Vec::new(),
            tried: Vec::new(),
        }
    }

    pub(crate) fn deadline(mut self, deadline: Instant) -> SeedPass {
        self.deadline = Some(deadline);
        self
    }

    pub(crate) fn deferring(mut self, deferred: Vec<String>) -> SeedPass {
        self.deferred = deferred;
        self
    }

    pub(crate) fn select(mut self, select: Seeds) -> SeedPass {
        self.select = select;
        self
    }

    /// The recorded failure, or a timeout if none was recorded.
    pub(crate) fn take_failure(&mut self) -> Error {
        self.failure.take().unwrap_or_else(|| {
            Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                "the acquisition budget ran out before a configured host could be tried",
            ))
        })
    }

    /// The recorded failure if it is a TLS or client configuration error,
    /// for a caller whose own timeout cut the pass short.
    pub(crate) fn take_reportable(&mut self) -> Option<Error> {
        take_reportable(&mut self.failure)
    }
}

/// Takes the failure recorded in `slot` ([`record_failure`]) if it is a TLS
/// or client configuration error, for a caller whose timeout cut an attempt
/// short: that error is more useful than the timeout.
pub(crate) fn take_reportable(slot: &mut Option<Error>) -> Option<Error> {
    match slot {
        Some(e) if failure_rank(e) > 0 => slot.take(),
        _ => None,
    }
}

/// The accounting identity of configured host `i`: its name, or its
/// `hostaddr` when it has no TCP name.
pub(crate) fn seed_identity(config: &Config, i: usize) -> Option<String> {
    match config.host.get(i) {
        Some(Host::Tcp(name)) => Some(name.clone()),
        _ => None,
    }
    .or_else(|| config.hostaddr.get(i).map(|addr| addr.to_string()))
}

/// The identities configured host `i` may be listed under in a topology:
/// its TCP name and its `hostaddr`.
pub(crate) fn seed_aliases(config: &Config, i: usize) -> Vec<String> {
    let mut aliases = Vec::new();
    if let Some(Host::Tcp(name)) = config.host.get(i) {
        aliases.push(name.clone());
    }
    if let Some(addr) = config.hostaddr.get(i) {
        aliases.push(addr.to_string());
    }
    aliases
}

/// [`seed_aliases`] of every configured host, in order. A host without
/// aliases (a Unix socket) has an empty list and is never deferred.
pub(crate) fn all_seed_aliases(config: &Config) -> Vec<Vec<String>> {
    (0..cmp::max(config.host.len(), config.hostaddr.len()))
        .map(|i| seed_aliases(config, i))
        .collect()
}

/// Precedence of the errors of a pass over several endpoints when none
/// succeeds. Credential failures, client certificate and client TLS errors
/// never get here: they end the pass at once.
///
/// 2. A client-side configuration error (for example a password the server
///    asked for but the configuration lacks). It would repeat on every
///    endpoint that asks for it and only the caller can fix it, so it wins
///    over an earlier node-scoped TLS error. The pass still tries the
///    remaining endpoints, as one of them may not need it.
/// 1. The first node-scoped TLS failure: verification failed on a reachable
///    endpoint, and a later transport error or timeout must not hide it.
/// 0. Otherwise the last other error (transport, timeout, server).
fn failure_rank(e: &Error) -> u8 {
    if e.is_client_config() {
        2
    } else if e.is_security_failure() {
        1
    } else {
        0
    }
}

/// Records `next` in `slot` according to [`failure_rank`]: a higher rank
/// replaces a lower one, the first error of rank 1 or 2 is kept, and a later
/// error of rank 0 replaces an earlier one.
pub(crate) fn record_failure(slot: &mut Option<Error>, next: Error) {
    let keep = match slot {
        Some(current) => {
            let (current, next) = (failure_rank(current), failure_rank(&next));
            current > next || (current == next && current > 0)
        }
        None => false,
    };
    if !keep {
        *slot = Some(next);
    }
}

/// Same as [`connect`], but borrows the `MakeTlsConnect` instead of taking it by
/// value. This lets callers that only hold a `&mut T` (such as the control
/// connection in `check_and_refresh`) reuse the exact host-iteration logic
/// while still using the caller-provided TLS connector.
/// `pass.attempt_timeout` bounds each candidate individually, not the loop as
/// a whole, so that a couple of blackholed candidates do not starve the rest;
/// `pass.deadline`, if set, bounds the loop.
pub(crate) async fn connect_with_tls_ref<T>(
    tls: &mut T,
    config: &Config,
    pass: &mut SeedPass,
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    if config.host.is_empty() && config.hostaddr.is_empty() {
        return Err(Error::config("both host and hostaddr are missing".into()));
    }

    if !config.host.is_empty()
        && !config.hostaddr.is_empty()
        && config.host.len() != config.hostaddr.len()
    {
        let msg = format!(
            "number of hosts ({}) is different from number of hostaddrs ({})",
            config.host.len(),
            config.hostaddr.len(),
        );
        return Err(Error::config(msg.into()));
    }

    // At this point, either one of the following two scenarios could happen:
    // (1) either config.host or config.hostaddr must be empty;
    // (2) if both config.host and config.hostaddr are NOT empty; their lengths must be equal.
    let num_hosts = cmp::max(config.host.len(), config.hostaddr.len());

    if config.port.len() > 1 && config.port.len() != num_hosts {
        return Err(Error::config("invalid number of ports".into()));
    }

    let mut indices = (0..num_hosts).collect::<Vec<_>>();
    if config.load_balance_hosts == LoadBalanceHosts::Random {
        indices.shuffle(&mut rand::thread_rng());
    }
    let deferred = |i: usize| {
        seed_aliases(config, i)
            .iter()
            .any(|alias| pass.deferred.contains(&alias.to_ascii_lowercase()))
    };
    match pass.select {
        Seeds::All => {}
        Seeds::Undeferred => indices.retain(|&i| !deferred(i)),
        Seeds::Deferred => indices.retain(|&i| deferred(i)),
    }
    if !pass.deferred.is_empty() {
        // Stable: seeds whose endpoint failed recently go last.
        indices.sort_by_key(|&i| deferred(i));
    }

    for i in indices {
        let attempt_timeout = match pass.deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                Some(
                    pass.attempt_timeout
                        .map_or(remaining, |limit| cmp::min(limit, remaining)),
                )
            }
            None => pass.attempt_timeout,
        };
        let host = config.host.get(i);
        let hostaddr = config.hostaddr.get(i);
        let port = config
            .port
            .get(i)
            .or_else(|| config.port.first())
            .copied()
            .unwrap_or(5433);

        // The value of host is used as the hostname for TLS validation,
        let hostname = match host {
            Some(Host::Tcp(host)) => Some(host.clone()),
            // postgres doesn't support TLS over unix sockets, so the choice here doesn't matter
            #[cfg(unix)]
            Some(Host::Unix(_)) => None,
            None => None,
        };

        // Try to use the value of hostaddr to establish the TCP connection,
        // fallback to host if hostaddr is not present.
        let addr = match hostaddr {
            Some(ipaddr) => Host::Tcp(ipaddr.to_string()),
            None => host.cloned().unwrap(),
        };

        // A seed's accounting identity is its configured name (or address).
        let node = seed_identity(config, i);
        let label = host_label(&addr);
        // The host attempt bounds itself, so a TLS error recorded on one of
        // its resolved addresses is returned rather than lost to a timeout.
        let mut host = HostAttempt::bounded(attempt_timeout);
        pass.tried.push(i);
        let outcome = connect_host(
            addr,
            hostname,
            port,
            &mut *tls,
            config,
            node.clone(),
            &mut host,
        )
        .await;

        match outcome {
            Ok((client, connection)) => return Ok((client, connection)),
            // A credential, client certificate or client TLS failure is never
            // hidden by trying another seed. A failure of this seed's own TLS
            // endpoint moves on to the next seed under the same verification
            // (which error the caller sees: `record_failure`).
            Err(e) if e.is_security_failure() && !is_node_scoped_failure(&e) => return Err(e),
            Err(e) => {
                if is_node_scoped_failure(&e) {
                    warn!(
                        "Connection to {} failed: {}; trying the next configured host",
                        label,
                        error_chain(&e)
                    );
                    let mut aliases = seed_aliases(config, i);
                    aliases.extend(host.failed_addrs);
                    pass.node_failures.push(aliases);
                }
                record_failure(&mut pass.failure, e);
            }
        }
    }

    Err(pass.take_failure())
}

pub async fn yb_connect<T>(
    mut tls: T,
    config: &Config,
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    if config.host.is_empty() && config.hostaddr.is_empty() {
        return Err(Error::config("both host and hostaddr are missing".into()));
    }

    if !config.host.is_empty()
        && !config.hostaddr.is_empty()
        && config.host.len() != config.hostaddr.len()
    {
        let msg = format!(
            "number of hosts ({}) is different from number of hostaddrs ({})",
            config.host.len(),
            config.hostaddr.len(),
        );
        return Err(Error::config(msg.into()));
    }

    // At this point, either one of the following two scenarios could happen:
    // (1) either config.host or config.hostaddr must be empty;
    // (2) if both config.host and config.hostaddr are NOT empty; their lengths must be equal.
    let num_hosts = cmp::max(config.host.len(), config.hostaddr.len());

    if config.port.len() > 1 && config.port.len() != num_hosts {
        return Err(Error::config("invalid number of ports".into()));
    }

    let realm = match &config.realm {
        Some(realm) => realm.clone(),
        None => Realm::for_config(config),
    };
    realm.connect(&mut tls, config).await
}

/// Whether a failed or unavailable topology may fall back to the configured
/// seeds of the same realm. Restricted routing never falls back.
pub(crate) fn allows_unbalanced_fallback(config: &Config) -> bool {
    config.load_balance != "only-rr"
        && config.load_balance != "only-primary"
        && (config.topology_keys.is_empty() || !config.fallback_to_topology_keys_only)
}

/// Whether the legacy public/private address switching may be used.
pub(crate) fn public_ip_mode_allowed(config: &Config) -> bool {
    config.ssl_mode != SslMode::VerifyFull && config.endpoint_policy.is_none()
}

/// Resolves a discovered node identity through trusted configuration only.
///
/// Returns `None` when the node is not admitted, or when its discovered port
/// is invalid or not the trusted port for that identity.
pub(crate) fn resolve_node(config: &Config, identity: &str, port: u16) -> Option<ResolvedEndpoint> {
    admit_node(config, identity, port).ok()
}

/// Why trusted configuration refused a discovered node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No seed or policy rule admits the identity.
    NotAdmitted,
    /// The identity is admitted, but not on the port discovery reported.
    PortMismatch,
}

/// The configured port of seed `i`: one port for every seed, one per seed,
/// or 5433.
pub(crate) fn seed_port(config: &Config, i: usize) -> u16 {
    config
        .port
        .get(i)
        .or_else(|| config.port.first())
        .copied()
        .unwrap_or(5433)
}

/// [`resolve_node`] with the reason for a refusal.
pub(crate) fn admit_node(
    config: &Config,
    identity: &str,
    port: u16,
) -> Result<ResolvedEndpoint, Refusal> {
    if port == 0 || identity.is_empty() {
        return Err(Refusal::NotAdmitted);
    }
    let policy = config.endpoint_policy.as_deref();
    if let Some(node) = policy.and_then(|p| p.node(identity)) {
        return ResolvedEndpoint::from_policy(identity, node, port).ok_or(Refusal::PortMismatch);
    }
    // Without verify-full and without a policy nothing is enforced: every
    // discovered node is dialled on the port it reported.
    let legacy_open = config.ssl_mode != SslMode::VerifyFull && policy.is_none();
    let identity_ip = identity.parse::<IpAddr>().ok();
    let mut refusal = Refusal::NotAdmitted;
    // Configured seeds: a `host=name hostaddr=ip` pair says that `name` is
    // served at `ip` on the seed's port, so either identity dials `ip` and
    // verifies `name`, and only on that port.
    for (i, seed) in config.host.iter().enumerate() {
        if let Host::Tcp(name) = seed {
            let hostaddr = config.hostaddr.get(i);
            let by_name = name.eq_ignore_ascii_case(identity);
            let by_addr = identity_ip.is_some() && hostaddr == identity_ip.as_ref();
            if by_name || by_addr {
                if legacy_open || port == seed_port(config, i) {
                    return Ok(ResolvedEndpoint {
                        identity: identity.to_string(),
                        dial: hostaddr.map_or_else(|| name.clone(), |addr| addr.to_string()),
                        tls_name: name.clone(),
                        port,
                    });
                }
                refusal = Refusal::PortMismatch;
            }
        }
    }
    if config.host.is_empty() {
        if let Some(ip) = identity_ip {
            for (i, addr) in config.hostaddr.iter().enumerate() {
                if *addr == ip {
                    if legacy_open || port == seed_port(config, i) {
                        return Ok(ResolvedEndpoint {
                            identity: identity.to_string(),
                            dial: ip.to_string(),
                            tls_name: ip.to_string(),
                            port,
                        });
                    }
                    refusal = Refusal::PortMismatch;
                }
            }
        }
    }
    // A seed identity reported on another port is not re-admitted by a
    // suffix: the seed's configuration is the more specific statement.
    if refusal == Refusal::PortMismatch {
        return Err(refusal);
    }
    let suffix_ports = policy.map_or_else(Vec::new, |p| p.suffix_ports(identity));
    if !suffix_ports.is_empty() {
        let seeds = cmp::max(config.host.len(), config.hostaddr.len());
        let admitted = suffix_ports.iter().any(|pin| match pin {
            Some(pin) => *pin == port,
            None => (0..cmp::max(seeds, 1)).any(|i| seed_port(config, i) == port),
        });
        if !admitted {
            return Err(Refusal::PortMismatch);
        }
    }
    if !suffix_ports.is_empty() || legacy_open {
        return Ok(ResolvedEndpoint {
            identity: identity.to_string(),
            dial: identity.to_string(),
            tls_name: identity.to_string(),
            port,
        });
    }
    Err(refusal)
}

fn host_label(host: &Host) -> String {
    match host {
        Host::Tcp(name) => endpoint::label(name).to_string(),
        #[cfg(unix)]
        Host::Unix(_) => "unix-socket".to_string(),
    }
}

pub(crate) fn seeds_label(config: &Config) -> String {
    let labels: Vec<String> = config.host.iter().map(host_label).collect();
    format!("[{}]", labels.join(", "))
}

/// Walks an [`Error`]'s `source` chain and renders it as a single
/// `outer: inner: innermost` string, so control-connection failures surface the
/// real underlying cause (DNS, TCP refused, TLS rejected, auth failed, ...)
/// instead of a generic wrapper.
///
/// Server-supplied database error text is reduced to severity and SQLSTATE
/// (AST-2133): it can quote SQL, parameter values or keys.
pub(crate) fn error_chain(err: &Error) -> String {
    crate::observe::Redacted(err).to_string()
}

/// Builds the `Config` used for control connections with connect_timeout bounded to
/// `CONNECT_TIMEOUT`.
pub(crate) fn control_connection_config(config: &Config) -> Config {
    let mut control_config = config.clone();
    control_config.connect_timeout = Some(
        config
            .connect_timeout
            .map_or(CONNECT_TIMEOUT, |timeout| {
                cmp::min(timeout, CONNECT_TIMEOUT)
            }),
    );
    control_config
}

/// Collapses the `time::timeout` result around a control-connection establish into
/// the plain `Result` the call sites already handle, naming the bound that fired.
fn establish_control_connection<T>(
    target: &str,
    limit: Duration,
    outcome: Result<Result<T, Error>, time::error::Elapsed>,
) -> Result<T, Error> {
    match outcome {
        Ok(inner) => inner,
        Err(_) => {
            warn!(
                "Connection to {} did not finish connecting, TLS and \
                 authentication within {:?}, giving up on it",
                target, limit
            );
            Err(Error::connect(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "connection to {} was not established within {:?}",
                    target, limit
                ),
            )))
        }
    }
}

pub(crate) async fn connect_host<T>(
    host: Host,
    hostname: Option<String>,
    port: u16,
    tls: &mut T,
    config: &Config,
    node: Option<String>,
    attempt: &mut HostAttempt,
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    let label = host_label(&host);
    match host {
        Host::Tcp(host) => {
            let lookup = async {
                net::lookup_host((&*host, port))
                    .await
                    .map_err(Error::connect)
            };
            let mut addrs = attempt.run(&label, lookup).await?.collect::<Vec<_>>();

            if config.load_balance_hosts == LoadBalanceHosts::Random {
                addrs.shuffle(&mut rand::thread_rng());
            }

            let mut failure = None;
            for addr in addrs {
                if failure.is_some() && attempt.expired() {
                    break;
                }
                let once = connect_once(
                    Addr::Tcp(addr.ip()),
                    hostname.as_deref(),
                    port,
                    tls,
                    config,
                    node.clone(),
                );
                match attempt.run(&label, once).await {
                    Ok(stream) => return Ok(stream),
                    // Never let another resolved address mask a credential
                    // or client-side failure. A TLS failure of this address's
                    // endpoint moves on to the next address under the same
                    // verification (precedence: `record_failure`).
                    Err(e) if e.is_security_failure() && !is_node_scoped_failure(&e) => {
                        return Err(e)
                    }
                    Err(e) => {
                        if is_node_scoped_failure(&e) {
                            attempt.failed_addrs.push(addr.ip().to_string());
                        }
                        if e.is_security_failure() {
                            warn!(
                                "Connection to an address of {} failed: {}; trying the next address",
                                endpoint::label(&host),
                                error_chain(&e)
                            );
                        }
                        record_failure(&mut failure, e);
                    }
                };
            }

            Err(failure.unwrap_or_else(|| {
                Error::connect(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not resolve any addresses",
                ))
            }))
        }
        #[cfg(unix)]
        Host::Unix(path) => {
            let once = connect_once(
                Addr::Unix(path),
                hostname.as_deref(),
                port,
                tls,
                config,
                node,
            );
            attempt.run(&label, once).await
        }
    }
}

async fn connect_once<T>(
    addr: Addr,
    hostname: Option<&str>,
    port: u16,
    tls: &mut T,
    config: &Config,
    node: Option<String>,
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    let socket = connect_socket(
        &addr,
        port,
        config.connect_timeout,
        config.tcp_user_timeout,
        if config.keepalives {
            Some(&config.keepalive_config)
        } else {
            None
        },
    )
    .await?;

    let tls = tls
        .make_tls_connect(hostname.unwrap_or(""))
        .map_err(|e| Error::tls(e.into()))?;
    let has_hostname = hostname.is_some();
    let (mut client, mut connection) = connect_raw(socket, tls, has_hostname, config).await?;

    if let TargetSessionAttrs::ReadWrite = config.target_session_attrs {
        let rows = client.simple_query_raw("SHOW transaction_read_only");
        pin_mut!(rows);

        let rows = future::poll_fn(|cx| {
            if connection.poll_unpin(cx)?.is_ready() {
                return Poll::Ready(Err(Error::closed()));
            }

            rows.as_mut().poll(cx)
        })
        .await?;
        pin_mut!(rows);

        loop {
            let next = future::poll_fn(|cx| {
                if connection.poll_unpin(cx)?.is_ready() {
                    return Poll::Ready(Some(Err(Error::closed())));
                }

                rows.as_mut().poll_next(cx)
            });

            match next.await.transpose()? {
                Some(SimpleQueryMessage::Row(row)) => {
                    if row.try_get(0)? == Some("on") {
                        return Err(Error::connect(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "database does not allow writes",
                        )));
                    } else {
                        break;
                    }
                }
                Some(_) => {}
                None => return Err(Error::unexpected_message()),
            }
        }
    }

    client.set_socket_config(SocketConfig {
        addr,
        hostname: hostname.map(|s| s.to_string()),
        node,
        port,
        connect_timeout: config.connect_timeout,
        tcp_user_timeout: config.tcp_user_timeout,
        keepalive: if config.keepalives {
            Some(config.keepalive_config.clone())
        } else {
            None
        },
    });

    Ok((client, connection))
}
