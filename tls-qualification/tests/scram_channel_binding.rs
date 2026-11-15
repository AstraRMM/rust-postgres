//! SCRAM-SHA-256 with `channel_binding=require` and `require_auth` against
//! the real engines. Uses the rig from `tls-qualification/rig/run.sh`.
//!
//! YugabyteDB 2025.2.5.2-b5 offers `SCRAM-SHA-256-PLUS` over TLS only when
//! the YB-TServer flag `ysql_enable_scram_channel_binding` is true. The flag
//! is not runtime-settable and defaults to false. The rig sets it on:
//!
//! * yb-a (127.0.0.2), an ECDSA P-256 / SHA-256 certificate chain;
//! * universe C, an all-RSA (`sha256WithRSAEncryption`) chain with two
//!   tservers: yb-c (127.0.0.4, the seed) and yb-c2 (127.0.0.5, reachable
//!   only through discovery).
//!
//! yb-b (127.0.0.3, ECDSA) keeps the server default, so the fail-closed path
//! runs against a real server that does not offer channel binding. On every
//! YugabyteDB node only the role `qual_scram` uses SCRAM; every other role is
//! trusted over TLS. PostgreSQL 16 serves the ECDSA (55432) and RSA (55439)
//! chains.
//!
//! What is asserted rather than inferred:
//!
//! * the mechanisms each node advertises, read from its AuthenticationSASL
//!   message over a verified TLS session;
//! * that the server checks the binding: a hand-driven SCRAM-SHA-256-PLUS
//!   exchange succeeds with the RFC 5929 `tls-server-end-point` hash of the
//!   leaf the server presented, and is refused with any other value;
//! * that the driver, with `channel_binding=require`, connects to each node
//!   that advertises SCRAM-SHA-256-PLUS (it accepts a SCRAM exchange under
//!   `require` only when it selected SCRAM-SHA-256-PLUS) and fails closed,
//!   before sending a SCRAM message, against the node that does not.
//!
//! `tests/certificate_fields.rs` shows at byte level which mechanism and
//! binding data the driver sends.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use yb_postgres_pool::{Pool, PoolConfig};
use yb_tokio_postgres::endpoint::{EndpointPolicy, NodeEndpoint};
use yb_tokio_postgres::realm::Realm;
use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
use yb_tokio_postgres::{Client, Config, Error, SimpleQueryMessage};

const PASSWORD: &str = "qualification-only";
const PG_RSA: u16 = 55439;

#[derive(Clone, Copy, Debug)]
struct Node {
    host: &'static str,
    hostaddr: &'static str,
    ca: &'static str,
}

const YB_ECDSA: Node = Node {
    host: "yb-a.test",
    hostaddr: "127.0.0.2",
    ca: "ca-a.crt",
};
const YB_ECDSA_UNBOUND: Node = Node {
    host: "yb-b.test",
    hostaddr: "127.0.0.3",
    ca: "ca-a.crt",
};
const YB_RSA: Node = Node {
    host: "yb-c.test",
    hostaddr: "127.0.0.4",
    ca: "ca-rsa.crt",
};
const YB_RSA_DISCOVERED: Node = Node {
    host: "yb-c2.test",
    hostaddr: "127.0.0.5",
    ca: "ca-rsa.crt",
};

const BOUND_NODES: [Node; 3] = [YB_ECDSA, YB_RSA, YB_RSA_DISCOVERED];
const PLUS_AND_PLAIN: [&str; 2] = ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"];

const STRICT: &str = "channel_binding=require require_auth=scram-sha-256";

/// Provider under test, selected with `TLS_QUAL_PROVIDER` (default aws-lc-rs).
fn options() -> TlsOptions {
    let selected = std::env::var("TLS_QUAL_PROVIDER").unwrap_or_default();
    match selected.as_str() {
        "" | "aws-lc-rs" => TlsOptions::new(),
        #[cfg(feature = "ring")]
        "ring" => TlsOptions::new().provider(yb_tokio_postgres::rustls::Provider::Ring),
        #[cfg(feature = "fips")]
        "fips" => TlsOptions::new().provider(yb_tokio_postgres::rustls::Provider::AwsLcRsFips),
        other => panic!("provider {other} is not compiled in"),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let dir = PathBuf::from(std::env::var("TLS_QUAL_FIXTURES").expect("TLS_QUAL_FIXTURES"));
    std::fs::read(dir.join(name)).unwrap()
}

fn connector(ca: &str) -> MakeRustlsConnect {
    MakeRustlsConnect::new(&TlsMaterial::from_pem(fixture(ca)), options()).unwrap()
}

fn yb(node: Node, user: &str, password: &str, extra: &str) -> Config {
    format!(
        "host={} hostaddr={} port=5433 user={user} password={password} dbname=yugabyte \
         load_balance=false {extra}",
        node.host, node.hostaddr
    )
    .parse()
    .unwrap()
}

async fn open(config: &Config, tls: &MakeRustlsConnect) -> Result<Client, Error> {
    let (client, connection) = config.connect(tls.clone()).await?;
    tokio::spawn(connection);
    Ok(client)
}

async fn scalar(client: &Client, sql: &str) -> String {
    for message in client.simple_query(sql).await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap().to_string();
        }
    }
    panic!("no row for {sql}");
}

// ------------------------------------------------- protocol-level probe

type Session = tokio_rustls::client::TlsStream<TcpStream>;

/// A verified TLS session to `node` that has sent the startup message for
/// `qual_scram`, and the DER leaf certificate the server presented.
async fn startup(node: Node) -> (Session, Vec<u8>) {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&fixture(node.ca)) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut socket = TcpStream::connect((node.hostaddr, 5433)).await.unwrap();
    socket
        .write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])
        .await
        .unwrap();
    assert_eq!(
        socket.read_u8().await.unwrap(),
        b'S',
        "{node:?} refused TLS"
    );
    let name = ServerName::try_from(node.host.to_string()).unwrap();
    let mut session = TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .unwrap();
    let leaf = session.get_ref().1.peer_certificates().unwrap()[0].to_vec();

    let mut params = Vec::new();
    for (key, value) in [("user", "qual_scram"), ("database", "yugabyte")] {
        params.extend_from_slice(key.as_bytes());
        params.push(0);
        params.extend_from_slice(value.as_bytes());
        params.push(0);
    }
    params.push(0);
    let mut startup = ((params.len() + 8) as u32).to_be_bytes().to_vec();
    startup.extend_from_slice(&196_608u32.to_be_bytes());
    startup.extend_from_slice(&params);
    session.write_all(&startup).await.unwrap();
    (session, leaf)
}

async fn send(session: &mut (impl AsyncWrite + Unpin), tag: u8, payload: &[u8]) {
    let mut frame = vec![tag];
    frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    session.write_all(&frame).await.unwrap();
    session.flush().await.unwrap();
}

enum Reply {
    /// An authentication request: its code and the data after the code.
    Auth(u32, Vec<u8>),
    /// An ErrorResponse: SQLSTATE and message.
    Error(String, String),
}

async fn receive(session: &mut (impl AsyncRead + Unpin)) -> Reply {
    let tag = session.read_u8().await.unwrap();
    let length = session.read_u32().await.unwrap() as usize;
    let mut body = vec![0; length - 4];
    session.read_exact(&mut body).await.unwrap();
    match tag {
        b'R' => Reply::Auth(
            u32::from_be_bytes(body[..4].try_into().unwrap()),
            body[4..].to_vec(),
        ),
        b'E' => {
            let mut fields = BTreeMap::new();
            for field in body.split(|&b| b == 0).filter(|f| !f.is_empty()) {
                fields.insert(field[0], String::from_utf8_lossy(&field[1..]).into_owned());
            }
            Reply::Error(
                fields.remove(&b'C').unwrap_or_default(),
                fields.remove(&b'M').unwrap_or_default(),
            )
        }
        other => panic!("unexpected message {:?}", other as char),
    }
}

/// The SASL mechanisms `node` offers to `qual_scram`, in its order.
async fn advertised(node: Node) -> Vec<String> {
    let (mut session, _) = startup(node).await;
    match receive(&mut session).await {
        Reply::Auth(10, body) => body
            .split(|&b| b == 0)
            .filter(|m| !m.is_empty())
            .map(|m| String::from_utf8(m.to_vec()).unwrap())
            .collect(),
        Reply::Auth(code, _) => panic!("{node:?}: authentication request {code}, not SASL"),
        Reply::Error(code, message) => panic!("{node:?}: {code} {message}"),
    }
}

/// How the probe fills the GS2 header and channel-binding data.
enum Binding {
    /// SCRAM-SHA-256-PLUS with the SHA-256 hash of the presented leaf, the
    /// `tls-server-end-point` value for SHA-256-signed certificates.
    LeafSha256,
    /// SCRAM-SHA-256-PLUS with binding data that is not the leaf's hash.
    Other,
    /// SCRAM-SHA-256 with `n,,`: a client without channel-binding support.
    NotSupported,
    /// SCRAM-SHA-256 with `y,,`: a client that supports channel binding but
    /// believes the server does not.
    NotOffered,
}

/// Runs a SCRAM exchange by hand. `Ok` when the server sent
/// AuthenticationOk, otherwise the server's SQLSTATE and message.
async fn scram_by_hand(node: Node, binding: Binding) -> Result<(), (String, String)> {
    use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
    use sha2::{Digest, Sha256};

    let (mut session, leaf) = startup(node).await;
    assert!(matches!(receive(&mut session).await, Reply::Auth(10, _)));
    let (mechanism, binding) = match binding {
        Binding::LeafSha256 => (
            "SCRAM-SHA-256-PLUS",
            ChannelBinding::tls_server_end_point(Sha256::digest(leaf.as_slice()).to_vec()),
        ),
        Binding::Other => (
            "SCRAM-SHA-256-PLUS",
            ChannelBinding::tls_server_end_point(Sha256::digest(b"other").to_vec()),
        ),
        Binding::NotSupported => ("SCRAM-SHA-256", ChannelBinding::unsupported()),
        Binding::NotOffered => ("SCRAM-SHA-256", ChannelBinding::unrequested()),
    };
    let mut scram = ScramSha256::new(PASSWORD.as_bytes(), binding);
    let mut initial = mechanism.as_bytes().to_vec();
    initial.push(0);
    initial.extend_from_slice(&(scram.message().len() as u32).to_be_bytes());
    initial.extend_from_slice(scram.message());
    send(&mut session, b'p', &initial).await;
    match receive(&mut session).await {
        Reply::Auth(11, data) => scram.update(&data).unwrap(),
        Reply::Auth(code, _) => panic!("{node:?}: unexpected authentication request {code}"),
        Reply::Error(code, message) => return Err((code, message)),
    }
    send(&mut session, b'p', scram.message()).await;
    match receive(&mut session).await {
        Reply::Auth(12, data) => scram.finish(&data).unwrap(),
        Reply::Auth(code, _) => panic!("{node:?}: unexpected authentication request {code}"),
        Reply::Error(code, message) => return Err((code, message)),
    }
    match receive(&mut session).await {
        Reply::Auth(0, _) => Ok(()),
        Reply::Auth(code, _) => panic!("{node:?}: unexpected authentication request {code}"),
        Reply::Error(code, message) => Err((code, message)),
    }
}

// ------------------------------------------------------- YugabyteDB

#[tokio::test]
async fn yugabyte_advertises_channel_binding_only_with_the_flag() {
    for node in BOUND_NODES {
        assert_eq!(advertised(node).await, PLUS_AND_PLAIN, "{node:?}");
    }
    assert_eq!(advertised(YB_ECDSA_UNBOUND).await, ["SCRAM-SHA-256"]);
}

#[tokio::test]
async fn yugabyte_verifies_the_tls_server_end_point_binding() {
    for node in BOUND_NODES {
        scram_by_hand(node, Binding::LeafSha256)
            .await
            .unwrap_or_else(|e| panic!("{node:?}: correct binding refused: {e:?}"));
        let (code, message) = scram_by_hand(node, Binding::Other)
            .await
            .expect_err("a different binding must be refused");
        assert_eq!(code, "28000", "{node:?}: {message}");
        assert!(
            message.contains("channel binding check failed"),
            "{node:?}: {message}"
        );
    }
}

#[tokio::test]
async fn yugabyte_with_the_flag_still_accepts_clients_without_channel_binding() {
    for node in BOUND_NODES {
        scram_by_hand(node, Binding::NotSupported)
            .await
            .unwrap_or_else(|e| {
                panic!("{node:?}: a client without channel binding was refused: {e:?}")
            });
        // RFC 5802: a client that could bind but saw no -PLUS offer must be
        // refused by a server that offered it.
        let (code, message) = scram_by_hand(node, Binding::NotOffered)
            .await
            .expect_err("y,, must be refused");
        assert_eq!(code, "28000", "{node:?}: {message}");
        assert!(
            message.contains("channel binding negotiation error"),
            "{node:?}: {message}"
        );
    }
    scram_by_hand(YB_ECDSA_UNBOUND, Binding::NotSupported)
        .await
        .unwrap();
    scram_by_hand(YB_ECDSA_UNBOUND, Binding::NotOffered)
        .await
        .unwrap();
}

#[tokio::test]
async fn yugabyte_scram_with_required_channel_binding() {
    for node in BOUND_NODES {
        assert_eq!(advertised(node).await, PLUS_AND_PLAIN, "{node:?}");
        let client = open(
            &yb(node, "qual_scram", PASSWORD, STRICT),
            &connector(node.ca),
        )
        .await
        .unwrap_or_else(|e| panic!("{node:?}: SCRAM-SHA-256-PLUS: {e}"));
        assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
        assert_eq!(
            scalar(&client, "select host(inet_server_addr())").await,
            node.hostaddr
        );
    }
}

#[tokio::test]
async fn yugabyte_without_the_flag_fails_required_channel_binding_closed() {
    assert_eq!(advertised(YB_ECDSA_UNBOUND).await, ["SCRAM-SHA-256"]);
    let tls = connector(YB_ECDSA_UNBOUND.ca);
    let e = open(&yb(YB_ECDSA_UNBOUND, "qual_scram", PASSWORD, STRICT), &tls)
        .await
        .expect_err("no SCRAM-SHA-256-PLUS on offer");
    assert!(e.is_security_failure(), "{e}");
    assert!(
        e.code().is_none(),
        "the refusal must come from the driver, not the server: {e}"
    );
    assert!(
        e.to_string().contains("server did not use channel binding"),
        "{e}"
    );
    // The same role and password authenticate once binding is not required.
    let client = open(
        &yb(
            YB_ECDSA_UNBOUND,
            "qual_scram",
            PASSWORD,
            "channel_binding=prefer require_auth=scram-sha-256",
        ),
        &tls,
    )
    .await
    .unwrap();
    assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
}

#[tokio::test]
async fn yugabyte_scram_with_preferred_or_disabled_channel_binding() {
    for node in BOUND_NODES {
        for mode in ["prefer", "disable"] {
            let config = yb(
                node,
                "qual_scram",
                PASSWORD,
                &format!("channel_binding={mode} require_auth=scram-sha-256"),
            );
            let client = open(&config, &connector(node.ca))
                .await
                .unwrap_or_else(|e| panic!("{node:?} channel_binding={mode}: {e}"));
            assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
        }
    }
}

#[tokio::test]
async fn yugabyte_enforces_scram_for_the_scram_role() {
    // A wrong password is refused by the server, so the role really uses
    // SCRAM rather than the trust line.
    for node in BOUND_NODES {
        let e = open(
            &yb(node, "qual_scram", "wrong-password", STRICT),
            &connector(node.ca),
        )
        .await
        .expect_err("wrong password must fail");
        assert_eq!(e.code().map(|c| c.code()), Some("28P01"), "{node:?}: {e}");
    }
}

#[tokio::test]
async fn require_auth_refuses_trust_authentication_on_yugabyte() {
    // `yugabyte` is trusted over TLS: the server sends a bare
    // AuthenticationOk, which require_auth=scram-sha-256 refuses.
    for node in [YB_ECDSA, YB_RSA] {
        let tls = connector(node.ca);
        let e = open(
            &yb(node, "yugabyte", PASSWORD, "require_auth=scram-sha-256"),
            &tls,
        )
        .await
        .expect_err("trust must be refused");
        assert!(e.is_security_failure(), "{e}");
        assert!(e.to_string().contains("require_auth"), "{e}");
        // The same role connects without the restriction (permissive default).
        let client = open(&yb(node, "yugabyte", PASSWORD, ""), &tls)
            .await
            .unwrap();
        assert_eq!(scalar(&client, "select current_user").await, "yugabyte");
    }
}

#[tokio::test]
async fn discovered_nodes_negotiate_required_channel_binding() {
    let tls = connector(YB_RSA.ca);
    let realm = Realm::new("yb-c-channel-binding");
    let mut config: Config = format!(
        "host={} hostaddr={} port=5433 user=qual_scram password={PASSWORD} dbname=yugabyte \
         load_balance=true yb_servers_refresh_interval=0 {STRICT}",
        YB_RSA.host, YB_RSA.hostaddr
    )
    .parse()
    .unwrap();
    config.endpoint_policy(
        EndpointPolicy::new()
            .admit_node(YB_RSA_DISCOVERED.hostaddr, NodeEndpoint::new())
            .unwrap(),
    );
    config.realm(realm.clone());

    let mut clients = Vec::new();
    let mut servers = BTreeMap::<String, usize>::new();
    for _ in 0..6 {
        let client = open(&config, &tls).await.unwrap();
        *servers
            .entry(scalar(&client, "select host(inet_server_addr())").await)
            .or_default() += 1;
        clients.push(client);
    }
    println!("required channel binding, sessions per node: {servers:?}");
    let identities: Vec<String> = realm
        .topology()
        .unwrap()
        .nodes()
        .iter()
        .map(|n| n.identity().to_string())
        .collect();
    assert_eq!(identities.len(), 2, "{identities:?}");
    assert!(
        identities.iter().any(|i| i == YB_RSA_DISCOVERED.hostaddr),
        "{identities:?}"
    );
    assert!(
        servers
            .get(YB_RSA_DISCOVERED.hostaddr)
            .copied()
            .unwrap_or(0)
            > 0,
        "no session on the discovered node: {servers:?}"
    );
    assert!(
        servers.get(YB_RSA.hostaddr).copied().unwrap_or(0) > 0,
        "{servers:?}"
    );
    assert_eq!(realm.connection_counts().values().sum::<usize>(), 6);
    assert!(
        realm.failed_nodes().is_empty(),
        "{:?}",
        realm.failed_nodes()
    );
    assert_eq!(advertised(YB_RSA_DISCOVERED).await, PLUS_AND_PLAIN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_sessions_keep_required_channel_binding() {
    async fn pid(client: &Client) -> String {
        scalar(client, "select pg_backend_pid()::text").await
    }
    for node in [YB_ECDSA, YB_RSA] {
        let tls = connector(node.ca);
        let mut pool_config = PoolConfig::default();
        pool_config.max_size = 1;
        pool_config.acquire_timeout = Duration::from_secs(10);
        pool_config.connect_timeout = Duration::from_secs(10);
        pool_config.session.application_name = Some("qual_channel_binding".to_string());
        let pool = Pool::new(
            yb(node, "qual_scram", PASSWORD, STRICT),
            tls.clone(),
            pool_config,
        )
        .unwrap();

        let client = pool
            .get()
            .await
            .unwrap_or_else(|e| panic!("{node:?} checkout: {e}"));
        assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
        let first = pid(&client).await;
        drop(client);

        let client = pool.get().await.unwrap();
        assert_eq!(
            pid(&client).await,
            first,
            "{node:?}: the idle session was not reused"
        );
        assert_eq!(pool.state().stats.connects, 1);

        let mut client = client;
        client.retire();
        drop(client);
        let client = pool
            .get()
            .await
            .unwrap_or_else(|e| panic!("{node:?} reconnect: {e}"));
        let second = pid(&client).await;
        assert_ne!(second, first);
        assert_eq!(pool.state().stats.connects, 2);
        drop(client);

        let admin = open(&yb(node, "yugabyte", PASSWORD, ""), &tls)
            .await
            .unwrap();
        assert_eq!(
            scalar(
                &admin,
                &format!("select pg_terminate_backend({second})::text")
            )
            .await,
            "true"
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let third = loop {
            assert!(
                Instant::now() < deadline,
                "{node:?}: no session after the server closed the pooled one"
            );
            match pool.get().await {
                Ok(client) => match client.simple_query("select pg_backend_pid()::text").await {
                    Ok(_) => break pid(&client).await,
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                },
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        };
        assert_ne!(third, second);
        let stats = pool.state().stats;
        assert!(stats.connects >= 3, "{stats:?}");
        assert_eq!(stats.connect_failures, 0, "{stats:?}");
        pool.shutdown(Duration::from_secs(1)).await;
    }
}

// ------------------------------------------------------- PostgreSQL

#[tokio::test]
async fn postgres_scram_with_required_channel_binding_ecdsa() {
    let config: Config = format!(
        "host=localhost port=55432 user=postgres password={PASSWORD} dbname=postgres {STRICT}"
    )
    .parse()
    .unwrap();
    let client = open(&config, &connector("ca-a.crt"))
        .await
        .expect("SCRAM-SHA-256-PLUS against PostgreSQL with an ECDSA certificate");
    assert_eq!(scalar(&client, "select current_user").await, "postgres");
}

#[tokio::test]
async fn postgres_scram_with_required_channel_binding_rsa() {
    let config: Config = format!(
        "host=localhost port={PG_RSA} user=postgres password={PASSWORD} dbname=postgres {STRICT}"
    )
    .parse()
    .unwrap();
    let client = open(&config, &connector("ca-rsa.crt"))
        .await
        .expect("SCRAM-SHA-256-PLUS against PostgreSQL with an RSA certificate");
    assert_eq!(scalar(&client, "select current_user").await, "postgres");
}
