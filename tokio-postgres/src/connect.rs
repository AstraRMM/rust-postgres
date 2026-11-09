use crate::client::{Addr, SocketConfig};
use crate::config::{Host, LoadBalanceHosts, SslMode, TargetSessionAttrs};
use crate::connect_raw::connect_raw;
use crate::connect_socket::connect_socket;
use crate::endpoint::{self, ResolvedEndpoint};
use crate::realm::Realm;
use crate::tls::MakeTlsConnect;
use crate::{Client, Config, Connection, Error, SimpleQueryMessage, Socket};
use futures_util::{future, pin_mut, FutureExt, Stream};
use log::warn;
use rand::seq::SliceRandom;
use std::net::IpAddr;
use std::task::Poll;
use std::time::Duration;
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
    match time::timeout(
        config.yb_acquire_timeout,
        connect_with_tls_ref(&mut tls, config, Some(config.yb_attempt_timeout)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(Error::connect(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "no connection was established within the {:?} acquisition budget",
                config.yb_acquire_timeout
            ),
        ))),
    }
}

/// Same as [`connect`], but borrows the `MakeTlsConnect` instead of taking it by
/// value. This lets callers that only hold a `&mut T` (such as the control
/// connection in `check_and_refresh`) reuse the exact host-iteration logic
/// while still using the caller-provided TLS connector.
/// `attempt_timeout` bounds each candidate individually, not the loop as a whole,
/// so that a couple of blackholed candidates do not starve the rest.
pub(crate) async fn connect_with_tls_ref<T>(
    tls: &mut T,
    config: &Config,
    attempt_timeout: Option<Duration>,
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

    let mut error = None;
    for i in indices {
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
        let node = hostname
            .clone()
            .or_else(|| hostaddr.map(|addr| addr.to_string()));
        let label = host_label(&addr);
        let attempt = connect_host(addr, hostname, port, &mut *tls, config, node);
        let outcome = match attempt_timeout {
            Some(limit) => {
                establish_control_connection(&label, limit, time::timeout(limit, attempt).await)
            }
            None => attempt.await,
        };

        match outcome {
            Ok((client, connection)) => return Ok((client, connection)),
            // A verification or authentication failure is never hidden by
            // trying another seed.
            Err(e) if e.is_security_failure() => return Err(e),
            Err(e) => error = Some(e),
        }
    }

    Err(error.unwrap())
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
/// is invalid or conflicts with a pinned port.
pub(crate) fn resolve_node(config: &Config, identity: &str, port: u16) -> Option<ResolvedEndpoint> {
    if port == 0 || identity.is_empty() {
        return None;
    }
    let policy = config.endpoint_policy.as_deref();
    if let Some(node) = policy.and_then(|p| p.node(identity)) {
        return ResolvedEndpoint::from_policy(identity, node, port);
    }
    let identity_ip = identity.parse::<IpAddr>().ok();
    // Configured seeds: a `host=name hostaddr=ip` pair says that `name` is
    // served at `ip`, so either identity dials `ip` and verifies `name`.
    for (i, seed) in config.host.iter().enumerate() {
        if let Host::Tcp(name) = seed {
            let hostaddr = config.hostaddr.get(i);
            let by_name = name.eq_ignore_ascii_case(identity);
            let by_addr = identity_ip.is_some() && hostaddr == identity_ip.as_ref();
            if by_name || by_addr {
                return Some(ResolvedEndpoint {
                    identity: identity.to_string(),
                    dial: hostaddr.map_or_else(|| name.clone(), |addr| addr.to_string()),
                    tls_name: name.clone(),
                    port,
                });
            }
        }
    }
    if config.host.is_empty() {
        if let Some(ip) = identity_ip {
            if config.hostaddr.contains(&ip) {
                return Some(ResolvedEndpoint {
                    identity: identity.to_string(),
                    dial: ip.to_string(),
                    tls_name: ip.to_string(),
                    port,
                });
            }
        }
    }
    let admitted_by_suffix = policy.map_or(false, |p| p.suffix_admits(identity));
    let legacy_open = config.ssl_mode != SslMode::VerifyFull && policy.is_none();
    if admitted_by_suffix || legacy_open {
        return Some(ResolvedEndpoint {
            identity: identity.to_string(),
            dial: identity.to_string(),
            tls_name: identity.to_string(),
            port,
        });
    }
    None
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
pub(crate) fn error_chain(err: &Error) -> String {
    use std::error::Error as StdError;

    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(&format!(": {}", cause));
        source = cause.source();
    }
    message
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
) -> Result<(Client, Connection<Socket, T::Stream>), Error>
where
    T: MakeTlsConnect<Socket>,
{
    match host {
        Host::Tcp(host) => {
            let mut addrs = net::lookup_host((&*host, port))
                .await
                .map_err(Error::connect)?
                .collect::<Vec<_>>();

            if config.load_balance_hosts == LoadBalanceHosts::Random {
                addrs.shuffle(&mut rand::thread_rng());
            }

            let mut last_err = None;
            for addr in addrs {
                match connect_once(
                    Addr::Tcp(addr.ip()),
                    hostname.as_deref(),
                    port,
                    tls,
                    config,
                    node.clone(),
                )
                .await
                {
                    Ok(stream) => return Ok(stream),
                    // Never let another resolved address mask a TLS or
                    // authentication failure.
                    Err(e) if e.is_security_failure() => return Err(e),
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                };
            }

            Err(last_err.unwrap_or_else(|| {
                Error::connect(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not resolve any addresses",
                ))
            }))
        }
        #[cfg(unix)]
        Host::Unix(path) => {
            connect_once(Addr::Unix(path), hostname.as_deref(), port, tls, config, node).await
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
