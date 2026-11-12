//! ASTS-99: `sslmode=verify-full` admission of discovered endpoints.
//!
//! A loopback fixture plays a YugabyteDB cluster over real TLS: every node
//! answers SSLRequest with a certificate from a throwaway in-process CA,
//! accepts logins, and serves `yb_servers()` from a mutable topology. All
//! nodes of one test listen on the same port on different loopback
//! addresses, so admission is decided by identity alone.
//!
//! The suffix test dials names that `tls-qualification/rig/run.sh` maps in
//! `/etc/hosts`; everything else needs no rig.

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    SanType,
};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use yb_tokio_postgres::endpoint::{EndpointPolicy, NodeEndpoint};
use yb_tokio_postgres::realm::Realm;
use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
use yb_tokio_postgres::tls::{MakeTlsConnect, TlsFailureKind};
use yb_tokio_postgres::{Client, Config, Error, NoTls, SimpleQueryMessage, Socket};

// ------------------------------------------------------------------- PKI

/// A throwaway CA. Nothing here is a real credential.
struct Pki {
    ca: rcgen::Certificate,
    key: KeyPair,
}

impl Pki {
    fn new() -> Pki {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ASTS-99 admission CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2036, 1, 1);
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        Pki { ca, key }
    }

    /// A server configuration whose certificate is valid for exactly `sans`.
    fn server(&self, sans: &[&str]) -> Arc<ServerConfig> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|san| match san.parse::<IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*san).try_into().unwrap()),
            })
            .collect();
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2035, 1, 1);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca, &self.key).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Arc::new(config)
    }

    fn connector(&self) -> MakeRustlsConnect {
        let tls = MakeRustlsConnect::new(&TlsMaterial::from_pem(self.ca.pem()), client_options())
            .unwrap();
        check_provider(&tls);
        tls
    }
}

/// Client provider under test, selected with `TLS_QUAL_PROVIDER` (default
/// aws-lc-rs) exactly as in `verify_full.rs`, so the rig's provider matrix
/// qualifies these scenarios too. The fixture servers always use aws-lc-rs.
fn client_options() -> TlsOptions {
    match std::env::var("TLS_QUAL_PROVIDER")
        .unwrap_or_default()
        .as_str()
    {
        "" | "aws-lc-rs" => TlsOptions::new(),
        #[cfg(feature = "ring")]
        "ring" => TlsOptions::new().provider(yb_tokio_postgres::rustls::Provider::Ring),
        #[cfg(feature = "fips")]
        "fips" => TlsOptions::new().provider(yb_tokio_postgres::rustls::Provider::AwsLcRsFips),
        other => panic!("provider {other} is not compiled in"),
    }
}

fn check_provider(tls: &MakeRustlsConnect) {
    if std::env::var("TLS_QUAL_PROVIDER").as_deref() == Ok("fips") {
        assert!(tls.current().fips(), "FIPS provider must report FIPS mode");
    }
}

// --------------------------------------------------------------- cluster

#[derive(Clone)]
struct Row {
    host: String,
    port: u16,
    node_type: &'static str,
    public_ip: Option<String>,
}

fn row(host: &str, port: u16, node_type: &'static str) -> Row {
    Row {
        host: host.to_string(),
        port,
        node_type,
        public_ip: None,
    }
}

#[derive(Clone, Default)]
struct Cluster {
    rows: Arc<Mutex<Vec<Row>>>,
}

impl Cluster {
    fn publish(&self, rows: Vec<Row>) {
        *self.rows.lock().unwrap() = rows;
    }
}

/// Binds one listener per address, all on the same port.
async fn listeners(ips: &[&str]) -> (u16, Vec<TcpListener>) {
    'retry: for _ in 0..50 {
        let first = TcpListener::bind((ips[0], 0)).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let mut all = vec![first];
        for ip in &ips[1..] {
            match TcpListener::bind((*ip, port)).await {
                Ok(listener) => all.push(listener),
                Err(_) => continue 'retry,
            }
        }
        return (port, all);
    }
    panic!("no port is free on every one of {ips:?}");
}

struct Node {
    accepts: Arc<AtomicUsize>,
    logins: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    /// Serves `listener` as the node that reports itself as `identity`.
    /// SSLRequest is answered with `tls`; a plaintext startup is accepted too,
    /// so legacy (non-verify-full) behaviour can be shown on the same fixture.
    fn serve(
        listener: TcpListener,
        cluster: &Cluster,
        identity: &str,
        tls: Arc<ServerConfig>,
    ) -> Node {
        let accepts = Arc::new(AtomicUsize::new(0));
        let logins = Arc::new(AtomicUsize::new(0));
        let task = {
            let (cluster, identity, accepts, logins) = (
                cluster.clone(),
                identity.to_string(),
                accepts.clone(),
                logins.clone(),
            );
            let acceptor = TlsAcceptor::from(tls);
            tokio::spawn(async move {
                loop {
                    let (socket, _) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    };
                    accepts.fetch_add(1, Ordering::SeqCst);
                    let (cluster, identity, logins, acceptor) = (
                        cluster.clone(),
                        identity.clone(),
                        logins.clone(),
                        acceptor.clone(),
                    );
                    tokio::spawn(async move {
                        let _ = session(socket, acceptor, &identity, &cluster, &logins).await;
                    });
                }
            })
        };
        Node {
            accepts,
            logins,
            task,
        }
    }

    /// TCP connections accepted, whether or not TLS or the login completed.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn logins(&self) -> usize {
        self.logins.load(Ordering::SeqCst)
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn message(stream: &mut Box<dyn Io>, tag: u8, payload: &[u8]) -> io::Result<()> {
    let mut frame = vec![tag];
    frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    stream.flush().await
}

fn metadata_description() -> Vec<u8> {
    let columns = [
        ("host", 25u32, -1i16),
        ("port", 20, 8),
        ("cloud", 25, -1),
        ("region", 25, -1),
        ("zone", 25, -1),
        ("public_ip", 25, -1),
        ("node_type", 25, -1),
    ];
    let mut payload = (columns.len() as u16).to_be_bytes().to_vec();
    for (name, oid, size) in columns {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&size.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());
    }
    payload
}

fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut payload = (values.len() as u16).to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(bytes) => {
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend_from_slice(bytes);
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload
}

const SSL_REQUEST: u32 = 80877103;

async fn session(
    mut socket: TcpStream,
    acceptor: TlsAcceptor,
    identity: &str,
    cluster: &Cluster,
    logins: &AtomicUsize,
) -> io::Result<()> {
    let mut head = [0u8; 8];
    socket.read_exact(&mut head).await?;
    let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let code = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let mut stream: Box<dyn Io> = if length == 8 && code == SSL_REQUEST {
        socket.write_all(b"S").await?;
        let mut tls: Box<dyn Io> = Box::new(acceptor.accept(socket).await?);
        let length = tls.read_u32().await? as usize;
        let mut startup = vec![0; length - 4];
        tls.read_exact(&mut startup).await?;
        tls
    } else {
        let mut rest = vec![0; length - 8];
        socket.read_exact(&mut rest).await?;
        Box::new(socket)
    };
    logins.fetch_add(1, Ordering::SeqCst);
    message(&mut stream, b'R', &0u32.to_be_bytes()).await?;
    message(&mut stream, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut stream, b'S', b"client_encoding\0UTF8\0").await?;
    message(&mut stream, b'S', b"server_version\x0015.0\0").await?;
    message(&mut stream, b'Z', b"I").await?;

    loop {
        let tag = match stream.read_u8().await {
            Ok(tag) => tag,
            Err(_) => return Ok(()),
        };
        let length = stream.read_u32().await? as usize;
        let mut body = vec![0; length - 4];
        stream.read_exact(&mut body).await?;
        match tag {
            b'X' => return Ok(()),
            // `node`: which node served this session.
            b'Q' => {
                let mut description = 1u16.to_be_bytes().to_vec();
                description.extend_from_slice(b"node\0");
                description.extend_from_slice(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255, 255, 255, 255, 255, 255, 0, 0,
                ]);
                message(&mut stream, b'T', &description).await?;
                message(&mut stream, b'D', &data_row(&[Some(identity.as_bytes())])).await?;
                message(&mut stream, b'C', b"SELECT 1\0").await?;
                message(&mut stream, b'Z', b"I").await?;
            }
            // `select * from yb_servers()` over the extended protocol.
            b'P' => message(&mut stream, b'1', &[]).await?,
            b'D' => {
                message(&mut stream, b't', &0u16.to_be_bytes()).await?;
                message(&mut stream, b'T', &metadata_description()).await?;
            }
            b'B' => message(&mut stream, b'2', &[]).await?,
            b'E' => {
                let rows = cluster.rows.lock().unwrap().clone();
                for row in &rows {
                    let port = (row.port as i64).to_be_bytes();
                    let values = [
                        Some(row.host.as_bytes()),
                        Some(&port[..]),
                        Some(&b"qual"[..]),
                        Some(&b"r1"[..]),
                        Some(&b"z1"[..]),
                        row.public_ip.as_ref().map(|p| p.as_bytes()),
                        Some(row.node_type.as_bytes()),
                    ];
                    message(&mut stream, b'D', &data_row(&values)).await?;
                }
                message(
                    &mut stream,
                    b'C',
                    format!("SELECT {}\0", rows.len()).as_bytes(),
                )
                .await?;
            }
            b'S' => message(&mut stream, b'Z', b"I").await?,
            b'C' => message(&mut stream, b'3', &[]).await?,
            b'H' => {}
            other => panic!("unexpected frontend message {}", other as char),
        }
    }
}

// ---------------------------------------------------------------- client

fn config(seed: &str, port: u16, extra: &str) -> Config {
    format!(
        "host={seed} port={port} user=test dbname=test connect_timeout=2 yb_servers_refresh_interval=0 {extra}"
    )
    .parse()
    .unwrap()
}

struct Session {
    client: Client,
    _task: JoinHandle<Result<(), Error>>,
}

async fn connect<T>(config: &Config, realm: &Realm, tls: T) -> Result<Session, Error>
where
    T: MakeTlsConnect<Socket> + Send + 'static,
    T::Stream: Send + 'static,
{
    let mut config = config.clone();
    config.realm(realm.clone());
    let (client, connection) = config.connect(tls).await?;
    Ok(Session {
        client,
        _task: tokio::spawn(connection),
    })
}

async fn node_of(session: &Session) -> String {
    for message in session.client.simple_query("node").await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap().to_string();
        }
    }
    panic!("no node row");
}

#[track_caller]
fn expect_not_admitted(result: Result<Session, Error>, case: &str) {
    match result {
        Ok(_) => panic!("{case}: a node outside the trusted configuration was used"),
        Err(e) => assert!(
            e.to_string().contains("admitted"),
            "{case}: unexpected error: {e}"
        ),
    }
}

fn policy() -> EndpointPolicy {
    EndpointPolicy::new()
}

// ----------------------------------------------------------------- tests

#[tokio::test]
async fn discovered_host_outside_trusted_configuration_is_never_dialled() {
    let pki = Pki::new();
    let cluster = Cluster::default();
    let (seed_ip, unlisted_ip) = ("127.0.47.1", "127.0.47.2");
    let (port, mut ls) = listeners(&[seed_ip, unlisted_ip]).await;
    let _seed = Node::serve(ls.remove(0), &cluster, seed_ip, pki.server(&[seed_ip]));
    // The unlisted node presents a certificate the client would accept, so
    // only admission can keep it out.
    let unlisted = Node::serve(
        ls.remove(0),
        &cluster,
        unlisted_ip,
        pki.server(&[unlisted_ip]),
    );
    cluster.publish(vec![
        row(seed_ip, port, "primary"),
        row(unlisted_ip, port, "primary"),
    ]);
    let tls = pki.connector();

    // Unrestricted balancing uses only the admitted seed.
    let realm = Realm::new("unlisted");
    let balanced = config(seed_ip, port, "load_balance=true");
    let mut held = Vec::new();
    for _ in 0..6 {
        let s = connect(&balanced, &realm, tls.clone()).await.unwrap();
        assert_eq!(node_of(&s).await, seed_ip);
        held.push(s);
    }
    let identities: Vec<String> = realm
        .topology()
        .unwrap()
        .nodes()
        .iter()
        .map(|n| n.identity().to_string())
        .collect();
    assert!(
        identities.contains(&unlisted_ip.to_string()),
        "discovery must have reported it: {identities:?}"
    );
    assert_eq!(
        realm
            .connection_counts()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![seed_ip.to_string()]
    );
    assert_eq!(unlisted.accepts(), 0, "the unlisted node was dialled");

    // Restricted routing never falls back to the seed: with only the
    // unlisted node eligible by role, the acquisition fails closed.
    cluster.publish(vec![
        row(seed_ip, port, "read_replica"),
        row(unlisted_ip, port, "primary"),
    ]);
    let strict = config(seed_ip, port, "load_balance=only-primary");
    expect_not_admitted(
        connect(&strict, &Realm::new("unlisted-strict"), tls.clone()).await,
        "unlisted",
    );
    assert_eq!(unlisted.accepts(), 0, "the unlisted node was dialled");

    // An unrelated policy entry does not widen admission either.
    let mut other = strict.clone();
    other.endpoint_policy(
        policy()
            .admit_node("127.0.47.9", NodeEndpoint::new())
            .unwrap(),
    );
    expect_not_admitted(
        connect(&other, &Realm::new("unlisted-other"), tls.clone()).await,
        "unrelated policy",
    );
    assert_eq!(unlisted.accepts(), 0, "the unlisted node was dialled");

    // Control: the same node is used as soon as trusted configuration admits
    // it, so the refusals above come from admission and not from the fixture.
    let mut admitted = strict.clone();
    admitted.endpoint_policy(
        policy()
            .admit_node(unlisted_ip, NodeEndpoint::new())
            .unwrap(),
    );
    let s = connect(&admitted, &Realm::new("unlisted-admitted"), tls.clone())
        .await
        .unwrap();
    assert_eq!(node_of(&s).await, unlisted_ip);
    assert_eq!(unlisted.logins(), 1);
}

const SUFFIX: &str = "admit.qual.test";
const NODE_1: (&str, &str) = ("node-1.admit.qual.test", "127.0.48.1");
const NODE_2: (&str, &str) = ("node-2.admit.qual.test", "127.0.48.2");

async fn require_rig_names() {
    for (name, ip) in [NODE_1, NODE_2] {
        let resolved: std::collections::BTreeSet<String> = tokio::net::lookup_host((name, 1))
            .await
            .map(|addrs| addrs.map(|a| a.ip().to_string()).collect())
            .unwrap_or_default();
        assert_eq!(
            resolved.into_iter().collect::<Vec<_>>(),
            vec![ip.to_string()],
            "{name} must resolve to {ip} only; tls-qualification/rig/run.sh maps it in /etc/hosts"
        );
    }
}

#[tokio::test]
async fn suffix_admitted_host_is_dialled_and_verified_by_its_own_name() {
    require_rig_names().await;
    let pki = Pki::new();
    let cluster = Cluster::default();
    let seed_ip = "127.0.48.3";
    let (port, mut ls) = listeners(&[seed_ip, NODE_1.1, NODE_2.1]).await;
    let _seed = Node::serve(ls.remove(0), &cluster, seed_ip, pki.server(&[seed_ip]));
    // Valid for its DNS identity only: an IP-based verification would fail.
    let n1 = Node::serve(ls.remove(0), &cluster, NODE_1.0, pki.server(&[NODE_1.0]));
    // Valid for the seed and for its own address, but not for its identity.
    let n2 = Node::serve(
        ls.remove(0),
        &cluster,
        NODE_2.0,
        pki.server(&[seed_ip, NODE_2.1]),
    );
    let tls = pki.connector();
    let suffix = policy().admit_dns_suffix(SUFFIX).unwrap();

    cluster.publish(vec![
        row(seed_ip, port, "read_replica"),
        row(NODE_1.0, port, "primary"),
    ]);
    let strict = config(seed_ip, port, "load_balance=only-primary");

    // Without the suffix the node is not admitted.
    expect_not_admitted(
        connect(&strict, &Realm::new("suffix-absent"), tls.clone()).await,
        "no suffix",
    );
    assert_eq!(n1.accepts(), 0);

    let mut admitted = strict.clone();
    admitted.endpoint_policy(suffix.clone());
    let realm = Realm::new("suffix");
    let mut held = Vec::new();
    for _ in 0..3 {
        let s = connect(&admitted, &realm, tls.clone()).await.unwrap();
        assert_eq!(s.client.node_identity(), Some(NODE_1.0));
        assert_eq!(node_of(&s).await, NODE_1.0);
        held.push(s);
    }
    assert_eq!(n1.logins(), 3);
    assert_eq!(realm.connection_counts().get(NODE_1.0), Some(&3));

    // A suffix-admitted node is verified against its own name, never against
    // the seed's name or the address it resolved to.
    cluster.publish(vec![
        row(seed_ip, port, "read_replica"),
        row(NODE_2.0, port, "primary"),
    ]);
    let e = connect(&admitted, &Realm::new("suffix-mismatch"), tls.clone())
        .await
        .err()
        .expect("must be refused");
    assert_eq!(
        e.tls_failure(),
        Some(TlsFailureKind::IdentityMismatch),
        "{e}"
    );
    assert!(n2.accepts() >= 1, "the node must have been dialled by name");
    assert_eq!(n2.logins(), 0);
}

#[tokio::test]
async fn lookalike_names_are_not_admitted_by_a_suffix() {
    let pki = Pki::new();
    let cluster = Cluster::default();
    let (seed_ip, live_ip) = ("127.0.50.1", "127.0.50.2");
    let (port, mut ls) = listeners(&[seed_ip, live_ip]).await;
    let _seed = Node::serve(ls.remove(0), &cluster, seed_ip, pki.server(&[seed_ip]));
    let live = Node::serve(ls.remove(0), &cluster, live_ip, pki.server(&[live_ip]));
    let tls = pki.connector();
    let mut strict = config(seed_ip, port, "load_balance=only-primary");
    strict.endpoint_policy(policy().admit_dns_suffix(SUFFIX).unwrap());

    for lookalike in [
        "nodeadmit.qual.test",               // suffix without a label boundary
        "node-1.admit.qual.test.",           // trailing dot
        "admit.qual.test",                   // the suffix itself
        "node-1",                            // single label
        "node-1.admit.qual.test.other.test", // suffix in the middle
        "node-1.admit-qual.test",            // a different label
        live_ip,                             // IP literal of a live, valid node
    ] {
        cluster.publish(vec![
            row(seed_ip, port, "read_replica"),
            row(lookalike, port, "primary"),
        ]);
        let realm = Realm::new("lookalike");
        expect_not_admitted(connect(&strict, &realm, tls.clone()).await, lookalike);
        assert_eq!(
            realm.topology().unwrap().nodes().len(),
            2,
            "{lookalike}: discovery must have reported it"
        );
    }
    assert_eq!(
        live.accepts(),
        0,
        "an IP literal was admitted by a DNS suffix"
    );

    for invalid in ["test", "*.admit.qual.test", "admit..qual.test", ""] {
        assert!(
            policy().admit_dns_suffix(invalid).is_err(),
            "suffix {invalid:?} was accepted"
        );
    }
}

#[tokio::test]
async fn public_ip_is_never_a_dial_target_or_tls_name() {
    let pki = Pki::new();
    let cluster = Cluster::default();
    let (seed_ip, node_ip, public_ip) = ("127.0.51.1", "127.0.51.2", "127.0.51.3");
    let (port, mut ls) = listeners(&[seed_ip, node_ip, public_ip]).await;
    let _seed = Node::serve(ls.remove(0), &cluster, seed_ip, pki.server(&[seed_ip]));
    let node = Node::serve(ls.remove(0), &cluster, node_ip, pki.server(&[node_ip]));
    // Listens on the advertised public address with a certificate valid for
    // it: reaching it at all means `public_ip` was used.
    let public = Node::serve(ls.remove(0), &cluster, public_ip, pki.server(&[public_ip]));
    // The seed's own public address equals the control connection's host,
    // which is what switches legacy clients to public addresses.
    cluster.publish(vec![
        Row {
            public_ip: Some(seed_ip.to_string()),
            ..row(seed_ip, port, "read_replica")
        },
        Row {
            public_ip: Some(public_ip.to_string()),
            ..row(node_ip, port, "primary")
        },
    ]);
    let tls = pki.connector();
    let mut strict = config(seed_ip, port, "load_balance=only-primary");
    strict.endpoint_policy(policy().admit_node(node_ip, NodeEndpoint::new()).unwrap());

    let realm = Realm::new("public-ip");
    for _ in 0..4 {
        let s = connect(&strict, &realm, tls.clone()).await.unwrap();
        assert_eq!(node_of(&s).await, node_ip);
        assert_eq!(s.client.node_identity(), Some(node_ip));
    }
    assert_eq!(node.logins(), 4);
    assert_eq!(public.accepts(), 0, "verify-full dialled a public_ip");

    // Seed admission (no policy) behaves the same.
    let mut seeds_only = config(seed_ip, port, "load_balance=true");
    seeds_only.realm(Realm::new("public-ip-seed"));
    for _ in 0..4 {
        let (client, connection) = seeds_only.connect(tls.clone()).await.unwrap();
        tokio::spawn(connection);
        assert_eq!(client.node_identity(), Some(seed_ip));
    }
    assert_eq!(public.accepts(), 0, "verify-full dialled a public_ip");

    // Control: without verify-full and without a policy the legacy switch
    // does reach the public address, so the fixture exercises it.
    let legacy = config(seed_ip, port, "load_balance=only-primary sslmode=disable");
    let s = connect(&legacy, &Realm::new("public-ip-legacy"), NoTls)
        .await
        .unwrap();
    assert_eq!(node_of(&s).await, public_ip);
    assert!(public.logins() >= 1);
}
