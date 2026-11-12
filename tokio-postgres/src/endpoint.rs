//! Trusted endpoint admission and redacted endpoint labels.
//!
//! A node returned by `yb_servers()` is described by three separate values:
//!
//! * its **canonical identity** — the `host` column reported by the cluster,
//!   used for connection accounting and failure state;
//! * its **dial address** — where the TCP connection is actually made, which
//!   may be a private endpoint, a load-balancer address or a numeric address;
//! * its **expected TLS name** — the DNS name or IP address the server
//!   certificate must be valid for.
//!
//! Discovery only reports identities. Which identities are admitted, and how
//! each maps to a dial address and TLS name, comes from trusted configuration
//! (the configured seeds and an optional [`EndpointPolicy`]). Discovery can
//! therefore never widen its own trust boundary, and a discovered node is never
//! verified against the seed hostname.

use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

/// How a trusted node identity is dialled and verified.
///
/// Its `Debug` output shows the dial address and TLS name only as keyed
/// [`label`]s.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct NodeEndpoint {
    dial: Option<String>,
    tls_name: Option<String>,
    port: Option<u16>,
}

impl NodeEndpoint {
    /// Creates an endpoint that dials the identity itself and expects a
    /// certificate valid for the identity.
    pub fn new() -> NodeEndpoint {
        NodeEndpoint::default()
    }

    /// Sets the address (hostname or IP) the TCP connection is made to.
    pub fn dial(mut self, dial: &str) -> NodeEndpoint {
        self.dial = Some(dial.to_string());
        self
    }

    /// Sets the DNS name or IP address the server certificate must be valid for.
    pub fn tls_name(mut self, tls_name: &str) -> NodeEndpoint {
        self.tls_name = Some(tls_name.to_string());
        self
    }

    /// Pins the port. A discovered port that differs from the pin makes the
    /// node ineligible instead of being dialled.
    pub fn port(mut self, port: u16) -> NodeEndpoint {
        self.port = Some(port);
        self
    }
}

impl fmt::Debug for NodeEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeEndpoint")
            .field("dial", &self.dial.as_deref().map(label))
            .field("tls_name", &self.tls_name.as_deref().map(label))
            .field("port", &self.port)
            .finish()
    }
}

/// An error building an [`EndpointPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPolicyError(&'static str);

impl fmt::Display for EndpointPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid endpoint policy: {}", self.0)
    }
}

impl std::error::Error for EndpointPolicyError {}

/// Trusted realm configuration that admits discovered nodes.
///
/// Under `sslmode=verify-full` a discovered node is eligible only when its
/// canonical identity is
///
/// 1. listed with [`EndpointPolicy::admit_node`],
/// 2. one of the configured seed `host` or `hostaddr` values (a seed given as
///    `host=name hostaddr=ip` maps both identities to dial `ip` and verify
///    `name`), or
/// 3. a DNS name under a suffix admitted with
///    [`EndpointPolicy::admit_dns_suffix`] (dialled and verified by that name).
///
/// IP identities are only admitted explicitly or as seeds.
///
/// Its `Debug` output shows node identities, dial addresses, TLS names and
/// DNS suffixes only as keyed [`label`]s.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EndpointPolicy {
    nodes: BTreeMap<String, NodeEndpoint>,
    dns_suffixes: Vec<String>,
}

impl fmt::Debug for EndpointPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Nodes<'a>(&'a BTreeMap<String, NodeEndpoint>);
        impl fmt::Debug for Nodes<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map()
                    .entries(
                        self.0
                            .iter()
                            .map(|(identity, node)| (label(identity), node)),
                    )
                    .finish()
            }
        }

        f.debug_struct("EndpointPolicy")
            .field("nodes", &Nodes(&self.nodes))
            .field(
                "dns_suffixes",
                &self
                    .dns_suffixes
                    .iter()
                    .map(String::as_str)
                    .map(label)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EndpointPolicy {
    /// Creates an empty policy that admits only the configured seeds.
    pub fn new() -> EndpointPolicy {
        EndpointPolicy::default()
    }

    /// Admits one canonical node identity with its dial address, TLS name and
    /// optional port pin.
    pub fn admit_node(
        mut self,
        identity: &str,
        endpoint: NodeEndpoint,
    ) -> Result<EndpointPolicy, EndpointPolicyError> {
        let identity = normalize_identity(identity)
            .ok_or(EndpointPolicyError("node identity must be a hostname or IP address"))?;
        if let Some(dial) = &endpoint.dial {
            normalize_identity(dial)
                .ok_or(EndpointPolicyError("dial address must be a hostname or IP address"))?;
        }
        if let Some(name) = &endpoint.tls_name {
            if !is_valid_tls_name(name) {
                return Err(EndpointPolicyError(
                    "expected TLS name must be a DNS name or IP address",
                ));
            }
        }
        if endpoint.port == Some(0) {
            return Err(EndpointPolicyError("port pin must be between 1 and 65535"));
        }
        self.nodes.insert(identity, endpoint);
        Ok(self)
    }

    /// Admits discovered DNS identities under `suffix` (for example
    /// `yb.internal` admits `node-1.yb.internal`). The suffix needs at least
    /// two labels and cannot contain wildcards.
    pub fn admit_dns_suffix(mut self, suffix: &str) -> Result<EndpointPolicy, EndpointPolicyError> {
        let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
        if suffix.split('.').count() < 2 || !is_valid_dns_name(&suffix) {
            return Err(EndpointPolicyError(
                "DNS suffix must be a valid name with at least two labels",
            ));
        }
        self.dns_suffixes.push(format!(".{}", suffix));
        Ok(self)
    }

    /// The complete, unredacted policy, used only as an in-memory realm key.
    /// Never log it.
    pub(crate) fn key_material(&self) -> String {
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .map(|(identity, node)| (identity, &node.dial, &node.tls_name, node.port))
            .collect();
        format!("{:?}|{:?}", nodes, self.dns_suffixes)
    }

    pub(crate) fn node(&self, identity: &str) -> Option<&NodeEndpoint> {
        self.nodes.get(&normalize_identity(identity)?)
    }

    pub(crate) fn suffix_admits(&self, identity: &str) -> bool {
        let identity = identity.to_ascii_lowercase();
        identity.parse::<IpAddr>().is_err()
            && is_valid_dns_name(&identity)
            && self
                .dns_suffixes
                .iter()
                .any(|suffix| identity.len() > suffix.len() && identity.ends_with(suffix.as_str()))
    }
}

/// How a node is reached once admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedEndpoint {
    /// Canonical node identity, used for accounting.
    pub identity: String,
    /// Address the TCP connection is made to.
    pub dial: String,
    /// Name the server certificate must be valid for.
    pub tls_name: String,
    pub port: u16,
}

impl ResolvedEndpoint {
    pub(crate) fn from_policy(identity: &str, endpoint: &NodeEndpoint, port: u16) -> Option<Self> {
        if let Some(pin) = endpoint.port {
            if pin != port {
                return None;
            }
        }
        Some(ResolvedEndpoint {
            identity: identity.to_string(),
            dial: endpoint.dial.clone().unwrap_or_else(|| identity.to_string()),
            tls_name: endpoint
                .tls_name
                .clone()
                .unwrap_or_else(|| identity.to_string()),
            port,
        })
    }
}

fn normalize_identity(identity: &str) -> Option<String> {
    let identity = identity.trim();
    if let Ok(ip) = identity.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let lower = identity.to_ascii_lowercase();
    if is_valid_dns_name(&lower) {
        Some(lower)
    } else {
        None
    }
}

fn is_valid_tls_name(name: &str) -> bool {
    name.parse::<IpAddr>().is_ok() || is_valid_dns_name(&name.to_ascii_lowercase())
}

fn is_valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

lazy_static! {
    static ref LABEL_KEY: [u8; 32] = {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    };
}

/// A stable, keyed, non-reversible label for an endpoint identity.
///
/// Labels are HMAC-SHA-256 under a random per-process key, so they correlate
/// log lines within one process without exposing addresses, and they cannot be
/// reversed by hashing a small address space.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointLabel([u8; 8]);

impl fmt::Display for EndpointLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ep-")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for EndpointLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Returns the redacted label for an endpoint identity.
pub fn label(identity: &str) -> EndpointLabel {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&LABEL_KEY[..]).expect("HMAC accepts any key length");
    mac.update(identity.trim().to_ascii_lowercase().as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    EndpointLabel(out)
}
