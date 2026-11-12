//! AST-2128 real-engine qualification of `sslmode=verify-full`.
//!
//! Requires the rig from `tls-qualification/rig/run.sh`: PostgreSQL 16
//! fixtures on 55432-55438 and two single-node YugabyteDB 2025.2.5.2-b5
//! universes ("realms") on 127.0.0.2 and 127.0.0.3. Fixtures are read from
//! `TLS_QUAL_FIXTURES`.

use rcgen::date_time_ymd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tls_qualification::{crl, load_ca, pem, CA_A_CN};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use yb_tokio_postgres::endpoint::{EndpointPolicy, NodeEndpoint};
use yb_tokio_postgres::realm::Realm;
use yb_tokio_postgres::rustls::{
    CrlExpiration, MakeRustlsConnect, ProtocolVersions, RevocationDepth, TlsConfigErrorKind,
    TlsMaterial, TlsOptions,
};
use yb_tokio_postgres::tls::TlsFailureKind;
use yb_tokio_postgres::{Client, Config, Error, NoTls, SimpleQueryMessage};

const PASSWORD: &str = "qualification-only";
const PG_VALID: u16 = 55432;
const PG_MTLS: u16 = 55433;
const PG_EXPIRED: u16 = 55434;
const PG_NOSSL: u16 = 55435;
const PG_TLS12: u16 = 55436;
const PG_ROTATED: u16 = 55437;
/// Serves leaf + intermediate CA C1, chaining to root CA C.
const PG_CHAINED: u16 = 55438;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(std::env::var("TLS_QUAL_FIXTURES").expect("TLS_QUAL_FIXTURES")).join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

fn roots(name: &str) -> TlsMaterial {
    TlsMaterial::from_pem(read(name))
}

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

fn connector(material: &TlsMaterial) -> MakeRustlsConnect {
    let tls = MakeRustlsConnect::new(material, options()).unwrap();
    if std::env::var("TLS_QUAL_PROVIDER").as_deref() == Ok("fips") {
        assert!(tls.current().fips(), "FIPS provider must report FIPS mode");
    }
    tls
}

fn connector_with(material: &TlsMaterial, f: impl FnOnce(TlsOptions) -> TlsOptions) -> MakeRustlsConnect {
    MakeRustlsConnect::new(material, f(options())).unwrap()
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn pg(port: u16, host: &str) -> String {
    format!("host={host} port={port} user=postgres password={PASSWORD} dbname=postgres")
}

struct Session {
    client: Client,
    generation: Option<u64>,
    protocol: Option<String>,
    task: JoinHandle<Result<(), Error>>,
}

async fn open_config(config: &Config, tls: &MakeRustlsConnect) -> Result<Session, Error> {
    let (client, connection) = config.connect(tls.clone()).await?;
    let generation = connection.tls_stream().map(|s| s.generation());
    let protocol = connection.tls_stream().and_then(|s| s.protocol_version());
    let task = tokio::spawn(connection);
    Ok(Session {
        client,
        generation,
        protocol,
        task,
    })
}

async fn open(conninfo: &str, tls: &MakeRustlsConnect) -> Result<Session, Error> {
    open_config(&conninfo.parse::<Config>()?, tls).await
}

async fn scalar(client: &Client, sql: &str) -> String {
    for message in client.simple_query(sql).await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            return row.get(0).unwrap_or("").to_string();
        }
    }
    panic!("no row for {sql}");
}

#[track_caller]
fn expect_tls(result: Result<Session, Error>, kind: TlsFailureKind) -> Error {
    match result {
        Ok(_) => panic!("expected {kind:?}, but the connection succeeded"),
        Err(e) => {
            assert_eq!(e.tls_failure(), Some(kind), "unexpected error: {e} / {e:?}");
            assert!(e.is_security_failure(), "{e}");
            e
        }
    }
}

/// A raw TCP peer that records everything the client sends and answers the
/// SSLRequest with `reply`.
async fn fake_server(reply: &'static [u8]) -> (u16, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        if let Ok(Ok(n)) = timeout(Duration::from_secs(3), socket.read(&mut buf)).await {
            seen.extend_from_slice(&buf[..n]);
            if n > 0 && !reply.is_empty() {
                let _ = socket.write_all(reply).await;
            }
        }
        while let Ok(Ok(n)) = timeout(Duration::from_millis(700), socket.read(&mut buf)).await {
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
        }
        seen
    });
    (port, task)
}

// ---------------------------------------------------------------- positive

#[tokio::test]
async fn valid_dns_san_tls13_and_pg_stat_ssl() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    assert_eq!(s.generation, Some(1));
    assert_eq!(s.protocol.as_deref(), Some("TLSv1_3"));
    assert_eq!(
        scalar(&s.client, "select ssl::text || ' ' || version from pg_stat_ssl where pid = pg_backend_pid()").await,
        "true TLSv1.3"
    );
    assert_eq!(s.client.node_identity(), Some("localhost"));
}

#[tokio::test]
async fn valid_ip_san() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&pg(PG_VALID, "127.0.0.1"), &tls).await.unwrap();
    assert_eq!(scalar(&s.client, "select 1").await, "1");
}

#[tokio::test]
async fn expected_name_is_separate_from_dial_address() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&format!("{} hostaddr=127.0.0.1", pg(PG_VALID, "pg.test")), &tls)
        .await
        .unwrap();
    assert_eq!(scalar(&s.client, "select 1").await, "1");
}

#[tokio::test]
async fn scram_channel_binding_required() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&format!("{} channel_binding=require", pg(PG_VALID, "localhost")), &tls)
        .await
        .unwrap();
    assert_eq!(scalar(&s.client, "select 1").await, "1");
}

#[tokio::test]
async fn mutual_tls_with_valid_client_certificate() {
    let tls = connector(
        &roots("ca-a.crt").with_client_identity(read("client-postgres.crt"), read("client-postgres.key")),
    );
    assert!(tls.current().has_client_identity());
    let s = open(&pg(PG_MTLS, "localhost"), &tls).await.unwrap();
    let dn = scalar(&s.client, "select client_dn from pg_stat_ssl where pid = pg_backend_pid()").await;
    assert!(dn.ends_with("CN=postgres"), "{dn}");
}

#[tokio::test]
async fn cancel_request_uses_verified_tls() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    let token = s.client.cancel_token();
    let canceller = {
        let tls = tls.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            token.cancel_query(tls).await
        })
    };
    let err = s.client.simple_query("select pg_sleep(30)").await.unwrap_err();
    assert_eq!(err.code().map(|c| c.code()), Some("57014"), "{err}");
    canceller.await.unwrap().unwrap();
}

// ---------------------------------------------------------------- negative

#[tokio::test]
async fn cancel_request_without_verified_tls_is_not_sent() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    let token = s.client.cancel_token();
    let wrong = connector(&roots("ca-b.crt"));
    let attempts = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let wrong_ca = token.cancel_query(wrong).await;
        let unverified = token.cancel_query(NoTls).await;
        (wrong_ca, unverified)
    };
    let (query, (wrong_ca, unverified)) =
        tokio::join!(s.client.simple_query("select pg_sleep(2)"), attempts);
    let e = wrong_ca.expect_err("a cancel request over an unverified channel succeeded");
    assert_eq!(e.tls_failure(), Some(TlsFailureKind::UnknownIssuer), "{e}");
    let e = unverified.expect_err("a cancel request without TLS succeeded");
    assert_eq!(e.tls_failure(), Some(TlsFailureKind::UnverifiedConnector), "{e}");
    // Neither attempt reached the server: the query ran to completion.
    query.expect("the query must not have been cancelled");
}

#[tokio::test]
async fn wrong_ca_is_unknown_issuer() {
    let tls = connector(&roots("ca-b.crt"));
    expect_tls(open(&pg(PG_VALID, "localhost"), &tls).await, TlsFailureKind::UnknownIssuer);
}

#[tokio::test]
async fn wrong_dns_san_is_identity_mismatch_and_redacted() {
    let tls = connector(&roots("ca-a.crt"));
    let e = expect_tls(
        open(&format!("{} hostaddr=127.0.0.1", pg(PG_VALID, "wrong.test")), &tls).await,
        TlsFailureKind::IdentityMismatch,
    );
    let rendered = format!("{e} {e:?}");
    assert!(!rendered.contains("wrong.test"), "endpoint name leaked: {rendered}");
    assert!(!rendered.contains("127.0.0.1"), "endpoint address leaked: {rendered}");
    assert!(rendered.contains("endpoint ep-"), "{rendered}");
}

#[tokio::test]
async fn security_failure_on_one_seed_is_not_hidden_by_another() {
    let tls = connector(&roots("ca-a.crt"));
    let conninfo = format!(
        "host=wrong.test,localhost hostaddr=127.0.0.1,127.0.0.1 port={PG_VALID} user=postgres password={PASSWORD} dbname=postgres"
    );
    expect_tls(open(&conninfo, &tls).await, TlsFailureKind::IdentityMismatch);
}

#[tokio::test]
async fn wrong_ip_san_is_identity_mismatch() {
    let tls = connector(&roots("ca-a.crt"));
    // PostgreSQL listens on every address; the certificate names only 127.0.0.1.
    expect_tls(open(&pg(PG_VALID, "127.0.0.2"), &tls).await, TlsFailureKind::IdentityMismatch);
}

#[tokio::test]
async fn expired_server_certificate() {
    let tls = connector(&roots("ca-a.crt"));
    expect_tls(open(&pg(PG_EXPIRED, "localhost"), &tls).await, TlsFailureKind::Expired);
}

#[tokio::test]
async fn revoked_server_certificate() {
    let tls = connector(&roots("ca-a.crt").with_crl(read("crl-a-revokes-server-valid.pem")));
    assert_eq!(tls.current().crls(), 1);
    expect_tls(open(&pg(PG_VALID, "localhost"), &tls).await, TlsFailureKind::Revoked);
    let clean = connector(&roots("ca-a.crt").with_crl(read("crl-a-empty.pem")));
    open(&pg(PG_VALID, "localhost"), &clean).await.unwrap();
}

// ------------------------------------------------------- CRL policy (ASTS-96)

#[tokio::test]
async fn crl_policy_defaults_are_unchanged() {
    assert_eq!(
        TlsOptions::new(),
        TlsOptions::new()
            .revocation_depth(RevocationDepth::EndEntity)
            .crl_expiration(CrlExpiration::Ignore)
    );
    let tls = connector(&roots("ca-a.crt"));
    assert_eq!(tls.current().revocation_depth(), RevocationDepth::EndEntity);
    assert_eq!(tls.current().crl_expiration(), CrlExpiration::Ignore);
    assert_eq!(tls.current().earliest_crl_next_update(), None);
}

#[tokio::test]
async fn crl_next_update_is_reported_for_alerting() {
    let utc = date_time_ymd(2035, 1, 1).unix_timestamp();
    let generalized = date_time_ymd(2051, 3, 1).unix_timestamp();
    let next = |m: TlsMaterial| unix(connector(&m).current().earliest_crl_next_update().unwrap());
    assert_eq!(next(roots("ca-a.crt").with_crl(read("crl-a-empty.pem"))), utc);
    assert_eq!(next(roots("ca-a.crt").with_crl(read("crl-a-empty-2051.pem"))), generalized);
    // The earliest across every loaded CRL, including several in one PEM.
    let both = [read("crl-a-empty-2051.pem"), read("crl-a-revokes-server-valid.pem")].concat();
    assert_eq!(next(roots("ca-a.crt").with_crl(both)), utc);
    let expired = date_time_ymd(2024, 6, 1).unix_timestamp();
    assert_eq!(
        next(roots("ca-a.crt").with_crl(read("crl-a-empty.pem")).with_crl(read("crl-a-expired.pem"))),
        expired
    );
}

#[tokio::test]
async fn stale_crl_is_still_used_by_default_and_reported() {
    let tls = connector(&roots("ca-a.crt").with_crl(read("crl-a-expired.pem")));
    let next_update = tls.current().earliest_crl_next_update().unwrap();
    assert!(next_update < SystemTime::now(), "the fixture CRL must be stale");
    open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
}

#[tokio::test]
async fn enforced_crl_expiry_rejects_stale_material_and_keeps_the_current_generation() {
    let enforce = |o: TlsOptions| o.crl_expiration(CrlExpiration::Enforce);
    let stale = roots("ca-a.crt").with_crl(read("crl-a-expired.pem"));
    let err = MakeRustlsConnect::new(&stale, enforce(options())).unwrap_err();
    assert_eq!(err.kind(), TlsConfigErrorKind::CrlExpired, "{err}");

    let tls = connector_with(&roots("ca-a.crt").with_crl(read("crl-a-empty.pem")), enforce);
    assert_eq!(tls.current().crl_expiration(), CrlExpiration::Enforce);
    let before = tls.current().id();
    let err = tls.reload(&stale).unwrap_err();
    assert_eq!(err.kind(), TlsConfigErrorKind::CrlExpired, "{err}");
    assert_eq!(tls.current().id(), before);
    open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
}

#[tokio::test]
async fn enforced_crl_expiry_applies_to_a_crl_that_expires_after_loading() {
    let (ca, key) = load_ca(CA_A_CN, std::str::from_utf8(&read("ca-a.key")).unwrap());
    let now = time::OffsetDateTime::now_utc();
    let short = crl(&ca, &key, 10, now - time::Duration::minutes(1), now + time::Duration::seconds(20), &[])
        .pem()
        .unwrap();
    let material = roots("ca-a.crt").with_crl(short);
    let enforced = connector_with(&material, |o| o.crl_expiration(CrlExpiration::Enforce));
    let ignored = connector(&material);
    open(&pg(PG_VALID, "localhost"), &enforced).await.unwrap();

    // Wait until the reported nextUpdate has passed (whole-second precision).
    let next_update = enforced.current().earliest_crl_next_update().unwrap();
    let wait = next_update.duration_since(SystemTime::now()).unwrap_or_default() + Duration::from_secs(2);
    tokio::time::sleep(wait).await;
    assert!(next_update < SystemTime::now());
    let e = expect_tls(open(&pg(PG_VALID, "localhost"), &enforced).await, TlsFailureKind::CrlExpired);
    let rendered = format!("{e} {e:?}");
    assert!(rendered.contains("nextUpdate"), "{rendered}");
    open(&pg(PG_VALID, "localhost"), &ignored).await.unwrap();
}

#[tokio::test]
async fn revoked_intermediate_is_refused_only_with_chain_depth() {
    let chain = |o: TlsOptions| o.revocation_depth(RevocationDepth::Chain);
    let revoked = || {
        roots("ca-c.crt")
            .with_crl(read("crl-c-revokes-int-c1.pem"))
            .with_crl(read("crl-c1-empty.pem"))
    };

    // Default: only the end-entity certificate is checked.
    let leaf_only = connector(&revoked());
    open(&pg(PG_CHAINED, "localhost"), &leaf_only).await.unwrap();

    let tls = connector_with(&revoked(), chain);
    assert_eq!(tls.current().revocation_depth(), RevocationDepth::Chain);
    let e = expect_tls(open(&pg(PG_CHAINED, "localhost"), &tls).await, TlsFailureKind::Revoked);
    let rendered = format!("{e} {e:?}");
    assert!(rendered.contains("has been revoked"), "{rendered}");

    // Clean CRLs from every issuer in the chain: accepted.
    let clean = connector_with(
        &roots("ca-c.crt").with_crl(read("crl-c-empty.pem")).with_crl(read("crl-c1-empty.pem")),
        chain,
    );
    open(&pg(PG_CHAINED, "localhost"), &clean).await.unwrap();

    // No CRL from the root that issued the intermediate: fails closed.
    let missing = connector_with(&roots("ca-c.crt").with_crl(read("crl-c1-empty.pem")), chain);
    let e = expect_tls(open(&pg(PG_CHAINED, "localhost"), &missing).await, TlsFailureKind::Revoked);
    let rendered = format!("{e} {e:?}");
    assert!(rendered.contains("unknown"), "{rendered}");
}

#[tokio::test]
async fn crl_der_reading_survives_truncation_and_corruption() {
    let (ca, key) = load_ca(CA_A_CN, std::str::from_utf8(&read("ca-a.key")).unwrap());
    let next_update = date_time_ymd(2035, 1, 1);
    let der = crl(&ca, &key, 11, date_time_ymd(2025, 1, 1), next_update, &[1001])
        .der()
        .to_vec();
    let load = |der: &[u8]| {
        MakeRustlsConnect::new(&roots("ca-a.crt").with_crl(pem("X509 CRL", der)), options())
    };
    let tls = load(&der).unwrap();
    assert_eq!(unix(tls.current().earliest_crl_next_update().unwrap()), next_update.unix_timestamp());

    for len in 0..der.len() {
        match load(&der[..len]) {
            Ok(_) => panic!("a CRL truncated to {len} of {} bytes was accepted", der.len()),
            Err(e) => assert_eq!(e.kind(), TlsConfigErrorKind::InvalidCrl, "len {len}: {e}"),
        }
    }
    for i in 0..der.len() {
        for value in [0x00, 0xff, der[i] ^ 0x01, der[i] ^ 0x80] {
            let mut corrupt = der.clone();
            corrupt[i] = value;
            match load(&corrupt) {
                Ok(tls) => {
                    assert_eq!(tls.current().crls(), 1);
                    assert!(tls.current().earliest_crl_next_update().is_some(), "byte {i}");
                }
                Err(e) => assert_eq!(e.kind(), TlsConfigErrorKind::InvalidCrl, "byte {i}: {e}"),
            }
        }
    }
}

#[tokio::test]
async fn real_server_refusing_tls() {
    let tls = connector(&roots("ca-a.crt"));
    expect_tls(open(&pg(PG_NOSSL, "localhost"), &tls).await, TlsFailureKind::ServerRefusedTls);
}

#[tokio::test]
async fn downgrade_answer_n_is_refused_without_plaintext() {
    let tls = connector(&roots("ca-a.crt"));
    let (port, peer) = fake_server(b"N").await;
    expect_tls(open(&pg(port, "localhost"), &tls).await, TlsFailureKind::ServerRefusedTls);
    let seen = peer.await.unwrap();
    assert_eq!(seen.len(), 8, "only the SSLRequest may be sent: {seen:?}");
}

#[tokio::test]
async fn downgrade_error_response_is_not_read() {
    let tls = connector(&roots("ca-a.crt"));
    let (port, peer) =
        fake_server(b"E\x00\x00\x00\x1eSFATAL\x00MDowngrade attempt\x00\x00").await;
    let e = expect_tls(open(&pg(port, "localhost"), &tls).await, TlsFailureKind::ServerRefusedTls);
    assert!(!e.to_string().contains("Downgrade attempt"), "{e}");
    assert_eq!(peer.await.unwrap().len(), 8);
}

#[tokio::test]
async fn garbage_after_tls_accept_fails_the_handshake() {
    let tls = connector(&roots("ca-a.crt"));
    let (port, peer) = fake_server(b"Sgarbage that is not a TLS record at all......").await;
    expect_tls(open(&pg(port, "localhost"), &tls).await, TlsFailureKind::HandshakeFailure);
    let seen = peer.await.unwrap();
    assert!(seen.len() > 8 && seen[8] == 0x16, "a ClientHello, never plaintext, follows: {seen:?}");
}

#[tokio::test]
async fn default_mode_refuses_unverified_connector_before_any_byte() {
    let (port, peer) = fake_server(b"S").await;
    let config: Config = format!("host=localhost port={port} user=postgres").parse().unwrap();
    assert_eq!(config.get_ssl_mode(), yb_tokio_postgres::config::SslMode::VerifyFull);
    let e = config.connect(NoTls).await.err().expect("NoTls must be refused");
    assert_eq!(e.tls_failure(), Some(TlsFailureKind::UnverifiedConnector), "{e}");
    assert!(peer.await.unwrap().is_empty());
}

#[tokio::test]
async fn verifying_connector_refuses_weaker_modes_before_any_byte() {
    let tls = connector(&roots("ca-a.crt"));
    for mode in ["require", "prefer", "disable"] {
        let (port, peer) = fake_server(b"S").await;
        let e = expect_tls(
            open(&format!("{} sslmode={mode}", pg(port, "localhost")), &tls).await,
            TlsFailureKind::ModeNotVerifyFull,
        );
        assert!(peer.await.unwrap().is_empty(), "{mode}: {e}");
    }
    for mode in ["verify-ca", "allow", "bogus"] {
        assert!(format!("host=x sslmode={mode}").parse::<Config>().is_err(), "{mode}");
    }
}

#[tokio::test]
async fn missing_expected_identity() {
    let tls = connector(&roots("ca-a.crt"));
    let conninfo =
        format!("hostaddr=127.0.0.1 port={PG_VALID} user=postgres password={PASSWORD} dbname=postgres");
    expect_tls(open(&conninfo, &tls).await, TlsFailureKind::NoExpectedIdentity);
}

#[tokio::test]
async fn tls12_only_server_needs_explicit_opt_in() {
    let tls = connector(&roots("ca-a.crt"));
    expect_tls(open(&pg(PG_TLS12, "localhost"), &tls).await, TlsFailureKind::ProtocolVersion);
    let tls12 = MakeRustlsConnect::new(
        &roots("ca-a.crt"),
        options().protocol_versions(ProtocolVersions::Tls12AndTls13),
    )
    .unwrap();
    let s = open(&pg(PG_TLS12, "localhost"), &tls12).await.unwrap();
    assert_eq!(s.protocol.as_deref(), Some("TLSv1_2"));
}

#[tokio::test]
async fn absent_required_client_certificate() {
    let tls = connector(&roots("ca-a.crt"));
    let e = open(&pg(PG_MTLS, "localhost"), &tls).await.err().expect("must fail");
    assert!(e.is_security_failure(), "{e}");
    assert_eq!(e.code().map(|c| c.code()), Some("28000"), "{e}");
}

#[tokio::test]
async fn client_certificate_from_untrusted_ca_is_rejected() {
    let tls = connector(
        &roots("ca-a.crt").with_client_identity(read("client-wrong-ca.crt"), read("client-wrong-ca.key")),
    );
    expect_tls(open(&pg(PG_MTLS, "localhost"), &tls).await, TlsFailureKind::ClientCertificateRejected);
}

// ----------------------------------------------------- configuration path

#[tokio::test]
async fn single_validated_configuration_path_from_files() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("tls-qual-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["ca-a.crt", "client-postgres.crt", "client-postgres.key"] {
        std::fs::copy(fixture(name), dir.join(name)).unwrap();
    }
    let key = dir.join("client-postgres.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let conninfo = format!(
        "host=localhost port={PG_MTLS} user=postgres dbname=postgres sslrootcert={} sslcert={} sslkey={}",
        dir.join("ca-a.crt").display(),
        dir.join("client-postgres.crt").display(),
        key.display()
    );
    let config: Config = conninfo.parse().unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(dir.to_str().unwrap()), "paths leaked: {debug}");
    assert!(!debug.contains("localhost"), "host leaked: {debug}");
    assert!(debug.contains("Tcp(ep-"), "{debug}");

    let tls = MakeRustlsConnect::from_config(&config, options()).unwrap();
    let s = open_config(&config, &tls).await.unwrap();
    assert_eq!(scalar(&s.client, "select current_user").await, "postgres");

    use std::os::unix::fs::MetadataExt;
    let root_owned = std::fs::metadata(&key).unwrap().uid() == 0;
    let rejected: &[u32] = if root_owned { &[0o644, 0o604, 0o660] } else { &[0o644, 0o640, 0o604, 0o660] };
    for &mode in rejected {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let e = MakeRustlsConnect::from_config(&config, options()).unwrap_err();
        assert_eq!(e.kind(), TlsConfigErrorKind::KeyPermissions, "{mode:o}");
        assert!(!e.to_string().contains(dir.to_str().unwrap()), "{e}");
    }

    let half: Config = format!("host=localhost sslrootcert={} sslcert={}", dir.join("ca-a.crt").display(), dir.join("client-postgres.crt").display()).parse().unwrap();
    assert_eq!(MakeRustlsConnect::from_config(&half, options()).unwrap_err().kind(), TlsConfigErrorKind::IncompleteClientIdentity);
    let require: Config = format!("host=localhost sslmode=require sslrootcert={}", dir.join("ca-a.crt").display()).parse().unwrap();
    assert_eq!(MakeRustlsConnect::from_config(&require, options()).unwrap_err().kind(), TlsConfigErrorKind::ModeNotVerifyFull);
    let missing: Config = "host=localhost".parse().unwrap();
    assert_eq!(MakeRustlsConnect::from_config(&missing, options()).unwrap_err().kind(), TlsConfigErrorKind::MissingRootCert);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------- rotation

#[tokio::test]
async fn invalid_reloads_keep_the_current_generation() {
    let tls = connector(&roots("ca-a.crt"));
    let keys = [read("client-postgres.key"), read("unrelated.key")].concat();
    let cases: Vec<(&str, TlsMaterial, TlsConfigErrorKind)> = vec![
        ("malformed root", TlsMaterial::from_pem(&b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"[..]), TlsConfigErrorKind::InvalidRootCertificate),
        ("empty root", TlsMaterial::from_pem(Vec::new()), TlsConfigErrorKind::NoRootCertificates),
        ("expired root", roots("server-expired.crt"), TlsConfigErrorKind::CertificateNotCurrentlyValid),
        ("key mismatch", roots("ca-a.crt").with_client_identity(read("client-postgres.crt"), read("unrelated.key")), TlsConfigErrorKind::KeyMismatch),
        ("expired client", roots("ca-a.crt").with_client_identity(read("client-expired.crt"), read("client-expired.key")), TlsConfigErrorKind::CertificateNotCurrentlyValid),
        ("two keys", roots("ca-a.crt").with_client_identity(read("client-postgres.crt"), keys), TlsConfigErrorKind::MultiplePrivateKeys),
        ("cert without key", roots("ca-a.crt").with_client_identity(read("client-postgres.crt"), Vec::new()), TlsConfigErrorKind::InvalidPrivateKey),
        ("garbage crl", roots("ca-a.crt").with_crl(&b"garbage"[..]), TlsConfigErrorKind::InvalidCrl),
    ];
    let total = cases.len() as u64;
    for (name, material, kind) in cases {
        let e = tls.reload(&material).unwrap_err();
        assert_eq!(e.kind(), kind, "{name}: {e}");
        assert_eq!(tls.current().id(), 1, "{name}");
    }
    assert_eq!(tls.reload_failures(), total);
    let s = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    assert_eq!(s.generation, Some(1));
}

#[tokio::test]
async fn rotation_keeps_old_sessions_until_revoked_and_revocation_is_prompt() {
    let tls = connector(&roots("ca-a.crt"));
    let old = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    assert_eq!(old.generation, Some(1));

    let info = tls.reload(&roots("ca-a2.crt")).unwrap();
    assert_eq!(info.id(), 2);
    assert!(!tls.is_current(1));
    // New connections use only the new generation's roots.
    expect_tls(open(&pg(PG_VALID, "localhost"), &tls).await, TlsFailureKind::UnknownIssuer);
    let new = open(&pg(PG_ROTATED, "localhost"), &tls).await.unwrap();
    assert_eq!(new.generation, Some(2));
    // The authenticated old session keeps working until it is retired.
    assert_eq!(scalar(&old.client, "select 1").await, "1");

    // Emergency revocation closes the idle, still-borrowed session promptly.
    let started = Instant::now();
    assert_eq!(tls.revoke_superseded(), 1);
    assert!(tls.is_revoked(1));
    let ended = timeout(Duration::from_secs(2), old.task).await.expect("revoked session must close").unwrap();
    let e = ended.unwrap_err();
    assert_eq!(e.tls_failure(), Some(TlsFailureKind::GenerationRevoked), "{e}");
    println!("revoked idle session closed after {:?}", started.elapsed());
    assert!(old.client.simple_query("select 1").await.unwrap_err().is_closed());
    assert_eq!(scalar(&new.client, "select 2").await, "2");

    // Overlapping roots during a CA rotation accept both servers.
    tls.reload(&roots("ca-a-and-a2.crt")).unwrap();
    open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    open(&pg(PG_ROTATED, "localhost"), &tls).await.unwrap();
}

#[tokio::test]
async fn reload_and_drain_bounds_old_sessions() {
    let tls = connector(&roots("ca-a.crt"));
    let old = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    let drain = Duration::from_millis(700);
    let started = Instant::now();
    tls.reload_and_drain(&roots("ca-a-and-a2.crt"), drain).unwrap();
    assert_eq!(scalar(&old.client, "select 1").await, "1");
    let ended = timeout(Duration::from_secs(5), old.task).await.expect("drain bound").unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= drain, "closed before the drain bound: {elapsed:?}");
    assert!(elapsed < drain + Duration::from_secs(2), "drain overran: {elapsed:?}");
    assert_eq!(ended.unwrap_err().tls_failure(), Some(TlsFailureKind::GenerationRevoked));
    println!("drained session closed after {elapsed:?} (bound {drain:?})");
    let fresh = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    assert_eq!(fresh.generation, Some(2));
}

#[tokio::test]
async fn revoking_the_current_generation_refuses_new_connections() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
    assert!(tls.revoke_generation(1));
    expect_tls(open(&pg(PG_VALID, "localhost"), &tls).await, TlsFailureKind::GenerationRevoked);
    timeout(Duration::from_secs(2), s.task).await.expect("revoked session must close").unwrap().unwrap_err();
    tls.reload(&roots("ca-a.crt")).unwrap();
    open(&pg(PG_VALID, "localhost"), &tls).await.unwrap();
}

// -------------------------------------------------- YugabyteDB smart driver

fn yb(host: &str, hostaddr: &str, extra: &str) -> Config {
    format!("host={host} hostaddr={hostaddr} port=5433 user=yugabyte dbname=yugabyte {extra}")
        .parse()
        .unwrap()
}

async fn servers(client: &Client) -> Vec<String> {
    let mut hosts = Vec::new();
    for message in client.simple_query("select host from yb_servers() order by host").await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            hosts.push(row.get(0).unwrap().to_string());
        }
    }
    hosts
}

#[tokio::test]
async fn yb_balancing_disabled_paths() {
    let tls = connector(&roots("ca-a.crt"));
    for config in [yb("yb-a.test", "127.0.0.2", ""), "host=127.0.0.2 port=5433 user=yugabyte dbname=yugabyte".parse().unwrap()] {
        let s = open_config(&config, &tls).await.unwrap();
        assert_eq!(servers(&s.client).await, vec!["127.0.0.2"]);
    }
    let wrong = connector(&roots("ca-b.crt"));
    expect_tls(open_config(&yb("yb-a.test", "127.0.0.2", ""), &wrong).await, TlsFailureKind::UnknownIssuer);
    expect_tls(open_config(&yb("yb-a.test", "127.0.0.3", ""), &tls).await, TlsFailureKind::IdentityMismatch);
}

#[tokio::test]
async fn yb_discovered_node_dialled_through_seed_mapping() {
    let tls = connector(&roots("ca-a.crt"));
    let s = open_config(&yb("yb-a.test", "127.0.0.2", "load_balance=true yb_servers_refresh_interval=0"), &tls)
        .await
        .unwrap();
    // Accounting uses the discovered canonical identity; TLS verified yb-a.test.
    assert_eq!(s.client.node_identity(), Some("127.0.0.2"));
}

#[tokio::test]
async fn yb_discovered_identity_mismatch_is_terminal() {
    let tls = connector(&roots("ca-a.crt"));
    let mut config = yb("yb-b.test", "127.0.0.3", "load_balance=true yb_servers_refresh_interval=0");
    // Admit the discovered identity but verify it as itself: realm B's
    // certificate has no IP SAN, so the node must be refused rather than
    // verified against the seed name or silently replaced by the seed.
    config.endpoint_policy(EndpointPolicy::new().admit_node("127.0.0.3", NodeEndpoint::new()).unwrap());
    expect_tls(open_config(&config, &tls).await, TlsFailureKind::IdentityMismatch);
}

#[tokio::test]
async fn yb_policy_maps_identity_to_tls_name() {
    let tls = connector(&roots("ca-a.crt"));
    let mut config = yb("yb-b.test", "127.0.0.3", "load_balance=true yb_servers_refresh_interval=0");
    config.endpoint_policy(
        EndpointPolicy::new()
            .admit_node("127.0.0.3", NodeEndpoint::new().dial("127.0.0.3").tls_name("yb-b.test").port(5433))
            .unwrap(),
    );
    let s = open_config(&config, &tls).await.unwrap();
    assert_eq!(s.client.node_identity(), Some("127.0.0.3"));

    let mut wrong = yb("yb-b.test", "127.0.0.3", "load_balance=true yb_servers_refresh_interval=0");
    wrong.endpoint_policy(
        EndpointPolicy::new()
            .admit_node("127.0.0.3", NodeEndpoint::new().tls_name("yb-a.test"))
            .unwrap(),
    );
    expect_tls(open_config(&wrong, &tls).await, TlsFailureKind::IdentityMismatch);
}

#[tokio::test]
async fn yb_discovery_never_crosses_realms() {
    use yb_tokio_postgres::realm::Realm;
    let tls = connector(&roots("ca-a.crt"));
    // One explicit realm shared by both configurations, so B's acquisitions
    // see the topology A discovered. 127.0.0.2 presents a certificate this
    // connector accepts; only B's trusted configuration keeps B away from it.
    let shared = Realm::new("shared-across-configurations");
    let with = |mut config: Config| {
        config.realm(shared.clone());
        config
    };
    let a = open_config(&with(yb("yb-a.test", "127.0.0.2", "load_balance=true yb_servers_refresh_interval=0")), &tls)
        .await
        .unwrap();
    assert_eq!(servers(&a.client).await, vec!["127.0.0.2"]);
    let snapshot: Vec<String> = shared.topology().unwrap().nodes().iter().map(|n| n.identity().to_string()).collect();
    assert_eq!(snapshot, vec!["127.0.0.2"]);

    // B reuses that snapshot (no refresh). Unrestricted balancing falls back
    // to B's own seed rather than dialling the unadmitted node.
    let b_conf = "load_balance=true yb_servers_refresh_interval=600";
    for _ in 0..5 {
        let b = open_config(&with(yb("yb-b.test", "127.0.0.3", b_conf)), &tls).await.unwrap();
        assert_ne!(b.client.node_identity(), Some("127.0.0.2"));
        assert_eq!(servers(&b.client).await, vec!["127.0.0.3"]);
    }
    // Restricted routing has no seed fallback and fails closed instead.
    let e = open_config(
        &with(yb("yb-b.test", "127.0.0.3", "load_balance=only-primary yb_servers_refresh_interval=600")),
        &tls,
    )
    .await
    .err()
    .expect("B must not be routed into A");
    assert!(e.to_string().contains("admitted"), "{e}");
    assert_eq!(shared.connection_counts().get("127.0.0.2"), Some(&1), "only A's session uses A");

    // Control: if B's trusted configuration admitted 127.0.0.2, the shared
    // snapshot would route B into A, so the checks above are not vacuous.
    let mut crossing = with(yb("yb-b.test", "127.0.0.3", "load_balance=only-primary yb_servers_refresh_interval=600"));
    crossing.endpoint_policy(EndpointPolicy::new().admit_node("127.0.0.2", NodeEndpoint::new()).unwrap());
    let crossed = open_config(&crossing, &tls).await.unwrap();
    assert_eq!(crossed.client.node_identity(), Some("127.0.0.2"));
    assert_eq!(servers(&crossed.client).await, vec!["127.0.0.2"]);
}

#[tokio::test]
async fn yb_discovery_tls_failure_does_not_fall_back() {
    let wrong = connector(&roots("ca-b.crt"));
    expect_tls(
        open_config(&yb("yb-a.test", "127.0.0.2", "load_balance=true yb_servers_refresh_interval=0"), &wrong).await,
        TlsFailureKind::UnknownIssuer,
    );
}

/// A plain TCP forwarder from an ephemeral port on `ip` to `ip:5433`, so the
/// seed's configured port differs from the port `yb_servers()` reports (as
/// with a connection manager or a port-mapped listener). Counts accepts.
async fn forwarder(ip: &'static str) -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect((ip, 5433)).await {
                    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (port, accepted, task)
}

#[tokio::test]
async fn yb_seed_identity_is_admitted_only_on_the_seed_port() {
    let tls = connector(&roots("ca-a.crt"));
    let (port, accepted, task) = forwarder("127.0.0.2").await;
    // yb_servers() reports 127.0.0.2:5433; the seed is configured on the
    // forwarder's port, so the discovered node is not admitted.
    let config = |load_balance: &str, realm: &str| {
        let mut config: Config = format!(
            "host=yb-a.test hostaddr=127.0.0.2 port={port} user=yugabyte dbname=yugabyte \
             load_balance={load_balance}"
        )
        .parse()
        .unwrap();
        config.realm(Realm::new(realm));
        config
    };

    let e = open_config(&config("only-primary", "port-restricted"), &tls)
        .await
        .err()
        .expect("restricted routing must fail closed");
    assert!(e.to_string().contains("no discovered node is admitted"), "{e}");
    assert!(!e.is_security_failure(), "{e}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "control connection only");

    // Unrestricted routing skips the node and connects through the seed.
    let s = open_config(&config("true", "port-unrestricted"), &tls).await.unwrap();
    assert_eq!(s.client.node_identity(), Some("yb-a.test"));
    assert_eq!(accepted.load(Ordering::SeqCst), 3, "control and data through the seed port");
    assert_eq!(scalar(&s.client, "select 1").await, "1");
    task.abort();
}
