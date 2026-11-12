//! ASTS-99: the adapter's own certificate field parsing, exercised through
//! the public API (the library crate is built without unit tests).
//!
//! * The validity window, read when credential material is loaded, is seen
//!   through `GenerationInfo::earliest_not_after` and the
//!   `CertificateNotCurrentlyValid` / `InvalidRootCertificate` rejections,
//!   with UTCTime and GeneralizedTime encodings, RSA certificates (long-form
//!   DER lengths) and malformed input.
//! * The RFC 5929 `tls-server-end-point` channel-binding hash is seen in the
//!   SCRAM client-final message received by a loopback TLS server, for RSA
//!   and ECDSA issuers with SHA-256/384/512 signatures, and the fail-closed
//!   path for an Ed25519 issuer (no defined hash).
//!
//! Every certificate is generated in-process; nothing here needs the rig.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, RsaKeySize,
    SanType, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsConfigErrorKind, TlsMaterial, TlsOptions};
use yb_tokio_postgres::Config;

fn at(year: i32, month: u8, day: u8, h: u8, m: u8, s: u8) -> OffsetDateTime {
    PrimitiveDateTime::new(
        Date::from_calendar_date(year, Month::try_from(month).unwrap(), day).unwrap(),
        Time::from_hms(h, m, s).unwrap(),
    )
    .assume_utc()
}

fn key(alg: &'static SignatureAlgorithm) -> KeyPair {
    if [&PKCS_RSA_SHA256, &PKCS_RSA_SHA384, &PKCS_RSA_SHA512].contains(&alg) {
        KeyPair::generate_rsa_for(alg, RsaKeySize::_2048).unwrap()
    } else {
        KeyPair::generate_for(alg).unwrap()
    }
}

fn ca_params(not_before: OffsetDateTime, not_after: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ASTS-99 certificate fields CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = not_before;
    params.not_after = not_after;
    params
}

fn ca(
    alg: &'static SignatureAlgorithm,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> (rcgen::Certificate, KeyPair) {
    let key = key(alg);
    let cert = ca_params(not_before, not_after).self_signed(&key).unwrap();
    (cert, key)
}

fn load(roots: &str) -> Result<MakeRustlsConnect, yb_tokio_postgres::rustls::TlsConfigError> {
    let tls = MakeRustlsConnect::new(
        &TlsMaterial::from_pem(roots.as_bytes().to_vec()),
        client_options(),
    )?;
    check_provider(&tls);
    Ok(tls)
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

fn expiry(not_after: OffsetDateTime) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(not_after.unix_timestamp() as u64)
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(input: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in input.bytes().filter(|&c| c != b'=') {
        let v = BASE64.iter().position(|&x| x == c).expect("base64") as u32;
        bits = (bits << 6) | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}

fn pem(der: &[u8]) -> String {
    let body = base64_encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

// ------------------------------------------------------- validity window

#[test]
fn generalized_time_validity_is_read_exactly() {
    // rcgen writes years outside 1950..2050 as GeneralizedTime (RFC 5280).
    let cases = [
        (at(2024, 1, 1, 0, 0, 0), at(2051, 3, 4, 5, 6, 7)),
        // Pre-1950 notBefore: GeneralizedTime on both sides, before the epoch.
        (at(1949, 12, 31, 23, 59, 59), at(2050, 1, 1, 0, 0, 0)),
        (at(1900, 2, 28, 12, 0, 0), at(2400, 2, 29, 23, 59, 59)),
    ];
    for (not_before, not_after) in cases {
        let (cert, _) = ca(&PKCS_ECDSA_P256_SHA256, not_before, not_after);
        let tls = load(&cert.pem()).unwrap_or_else(|e| panic!("{not_before} .. {not_after}: {e}"));
        assert_eq!(
            tls.current().earliest_not_after(),
            Some(expiry(not_after)),
            "{not_after}"
        );
    }
}

#[test]
fn utc_time_validity_and_its_century_window() {
    // UTCTime: YY >= 50 is 19YY, YY < 50 is 20YY.
    let (cert, _) = ca(
        &PKCS_ECDSA_P256_SHA256,
        at(1950, 1, 1, 0, 0, 0),
        at(2049, 12, 31, 23, 59, 59),
    );
    let tls = load(&cert.pem()).unwrap();
    assert_eq!(
        tls.current().earliest_not_after(),
        Some(expiry(at(2049, 12, 31, 23, 59, 59)))
    );
    let (cert, _) = ca(
        &PKCS_ECDSA_P256_SHA256,
        at(2024, 1, 1, 0, 0, 0),
        at(2048, 2, 29, 12, 30, 45),
    );
    let tls = load(&cert.pem()).unwrap();
    assert_eq!(
        tls.current().earliest_not_after(),
        Some(expiry(at(2048, 2, 29, 12, 30, 45)))
    );

    // Expired in 1999: read as 2099, it would be accepted.
    let (cert, _) = ca(
        &PKCS_ECDSA_P256_SHA256,
        at(1960, 1, 1, 0, 0, 0),
        at(1999, 12, 31, 23, 59, 59),
    );
    assert_eq!(
        load(&cert.pem()).unwrap_err().kind(),
        TlsConfigErrorKind::CertificateNotCurrentlyValid
    );
}

#[test]
fn certificates_outside_their_window_are_refused_in_either_encoding() {
    for (not_before, not_after) in [
        (at(2050, 6, 1, 0, 0, 0), at(2060, 1, 1, 0, 0, 0)), // GeneralizedTime, not yet valid
        (at(2049, 1, 1, 0, 0, 0), at(2051, 1, 1, 0, 0, 0)), // UTCTime notBefore in the future
        (at(1900, 1, 1, 0, 0, 0), at(1949, 1, 1, 0, 0, 0)), // GeneralizedTime, expired
        (at(2020, 1, 1, 0, 0, 0), at(2021, 1, 1, 0, 0, 0)), // UTCTime, expired
    ] {
        let (cert, _) = ca(&PKCS_ECDSA_P256_SHA256, not_before, not_after);
        let e = load(&cert.pem())
            .err()
            .unwrap_or_else(|| panic!("{not_before} .. {not_after} was accepted"));
        assert_eq!(
            e.kind(),
            TlsConfigErrorKind::CertificateNotCurrentlyValid,
            "{not_before} .. {not_after}: {e}"
        );
    }
}

#[test]
fn rsa_certificates_with_long_form_lengths() {
    for alg in [&PKCS_RSA_SHA256, &PKCS_RSA_SHA384, &PKCS_RSA_SHA512] {
        let not_after = at(2052, 7, 8, 9, 10, 11);
        let (cert, _) = ca(alg, at(2024, 1, 1, 0, 0, 0), not_after);
        assert!(
            cert.der().len() > 255,
            "an RSA-2048 certificate needs multi-byte lengths"
        );
        let tls = load(&cert.pem()).unwrap();
        assert_eq!(
            tls.current().earliest_not_after(),
            Some(expiry(not_after)),
            "{alg:?}"
        );
    }
    let (cert, _) = ca(
        &PKCS_RSA_SHA256,
        at(2020, 1, 1, 0, 0, 0),
        at(2021, 1, 1, 0, 0, 0),
    );
    assert_eq!(
        load(&cert.pem()).unwrap_err().kind(),
        TlsConfigErrorKind::CertificateNotCurrentlyValid
    );
}

#[test]
fn malformed_certificate_der_is_rejected_not_misread() {
    let (cert, _) = ca(
        &PKCS_RSA_SHA256,
        at(2024, 1, 1, 0, 0, 0),
        at(2051, 1, 1, 0, 0, 0),
    );
    let der = cert.der().to_vec();
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("tag only", der[..1].to_vec()),
        ("truncated length", der[..3].to_vec()),
        ("truncated body", der[..der.len() / 2].to_vec()),
        ("one byte short", der[..der.len() - 1].to_vec()),
        ("not a sequence", [&[0x31u8][..], &der[1..]].concat()),
        ("high-tag-number form", [&[0x3fu8][..], &der[1..]].concat()),
        (
            "indefinite length",
            [&[0x30u8, 0x80][..], &der[4..]].concat(),
        ),
        (
            "five length octets",
            [&[0x30u8, 0x85, 0, 0, 0, 0x01, 0x00][..], &der[4..]].concat(),
        ),
    ];
    // notBefore as UTCTime "240101000000Z"; replace the Z, or turn it into a
    // GeneralizedTime of the wrong length.
    let utc = b"\x17\x0d240101000000Z";
    let i = der
        .windows(utc.len())
        .position(|w| w == utc)
        .expect("notBefore UTCTime");
    let mut no_z = der.clone();
    no_z[i + 14] = b'0';
    cases.push(("validity without Z", no_z));
    let mut wrong_tag = der.clone();
    wrong_tag[i] = 0x18;
    cases.push(("13-byte GeneralizedTime", wrong_tag));
    for (name, bytes) in cases {
        let e = load(&pem(&bytes))
            .err()
            .unwrap_or_else(|| panic!("{name}: accepted"));
        assert_eq!(
            e.kind(),
            TlsConfigErrorKind::InvalidRootCertificate,
            "{name}: {e}"
        );
        assert!(
            e.to_string().contains("unparseable"),
            "{name}: rejected later than the DER reader: {e}"
        );
    }
    // The helper itself round-trips a valid certificate.
    load(&pem(&der)).unwrap();
}

// ----------------------------------------------- channel-binding hash

/// What a SCRAM server saw from the client.
#[derive(Debug, Default)]
struct Seen {
    mechanism: Option<String>,
    client_first: Option<String>,
    /// Decoded `c=` attribute of the client-final message.
    binding: Option<Vec<u8>>,
}

async fn message(
    stream: &mut (impl AsyncWriteExt + Unpin),
    tag: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut frame = vec![tag];
    frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    stream.flush().await
}

async fn read_message(stream: &mut (impl AsyncReadExt + Unpin)) -> io::Result<(u8, Vec<u8>)> {
    let tag = stream.read_u8().await?;
    let length = stream.read_u32().await? as usize;
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).await?;
    Ok((tag, body))
}

/// One TLS session that offers SCRAM-SHA-256-PLUS and SCRAM-SHA-256,
/// records the client's messages, and then fails authentication.
async fn scram_server(listener: TcpListener, tls: Arc<ServerConfig>) -> io::Result<Seen> {
    let mut seen = Seen::default();
    let (mut socket, _) = listener.accept().await?;
    let mut request = [0u8; 8];
    socket.read_exact(&mut request).await?;
    socket.write_all(b"S").await?;
    let mut stream = TlsAcceptor::from(tls).accept(socket).await?;
    let length = stream.read_u32().await? as usize;
    let mut startup = vec![0; length - 4];
    stream.read_exact(&mut startup).await?;

    let mut sasl = 10u32.to_be_bytes().to_vec();
    sasl.extend_from_slice(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
    message(&mut stream, b'R', &sasl).await?;

    let (tag, body) = match read_message(&mut stream).await {
        Ok(m) => m,
        Err(_) => return Ok(seen),
    };
    assert_eq!(tag, b'p');
    let nul = body.iter().position(|&b| b == 0).unwrap();
    seen.mechanism = Some(String::from_utf8(body[..nul].to_vec()).unwrap());
    let client_first = String::from_utf8(body[nul + 5..].to_vec()).unwrap();
    let nonce = client_first
        .split(',')
        .find_map(|a| a.strip_prefix("r="))
        .unwrap()
        .to_string();
    seen.client_first = Some(client_first);

    let mut cont = 11u32.to_be_bytes().to_vec();
    cont.extend_from_slice(
        format!("r={nonce}srv,s={},i=4096", base64_encode(b"asts-99 salt")).as_bytes(),
    );
    message(&mut stream, b'R', &cont).await?;

    let (tag, body) = read_message(&mut stream).await?;
    assert_eq!(tag, b'p');
    let client_final = String::from_utf8(body).unwrap();
    let c = client_final
        .split(',')
        .find_map(|a| a.strip_prefix("c="))
        .unwrap();
    seen.binding = Some(base64_decode(c));
    message(
        &mut stream,
        b'E',
        b"SFATAL\0VFATAL\0C28P01\0Mfixture ends here\0\0",
    )
    .await?;
    Ok(seen)
}

/// A certificate for 127.0.0.1 issued by a CA of `alg`, so the leaf's
/// signature algorithm is `alg`.
fn issued_by(alg: &'static SignatureAlgorithm) -> (String, Vec<u8>, Arc<ServerConfig>) {
    let (ca_cert, ca_key) = ca(alg, at(2024, 1, 1, 0, 0, 0), at(2036, 1, 1, 0, 0, 0));
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    params.not_before = at(2025, 1, 1, 0, 0, 0);
    params.not_after = at(2035, 1, 1, 0, 0, 0);
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    (ca_cert.pem(), leaf.der().to_vec(), Arc::new(server))
}

async fn bind(
    alg: &'static SignatureAlgorithm,
    channel_binding: &str,
) -> (Result<(), yb_tokio_postgres::Error>, Seen, Vec<u8>) {
    let (roots, leaf, server) = issued_by(alg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(scram_server(listener, server));
    let tls = load(&roots).unwrap();
    let config: Config = format!(
        "host=127.0.0.1 port={port} user=test password=fixture-only dbname=test channel_binding={channel_binding}"
    )
    .parse()
    .unwrap();
    let result = config.connect(tls).await.map(|_| ());
    let seen = finish(peer).await;
    (result, seen, leaf)
}

async fn finish(peer: JoinHandle<io::Result<Seen>>) -> Seen {
    tokio::time::timeout(Duration::from_secs(10), peer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_or_default()
}

#[tokio::test]
async fn channel_binding_hashes_the_leaf_with_its_signature_hash() {
    type Hash = fn(&[u8]) -> Vec<u8>;
    let cases: [(&'static SignatureAlgorithm, Hash); 5] = [
        (&PKCS_RSA_SHA256, |d| Sha256::digest(d).to_vec()),
        (&PKCS_RSA_SHA384, |d| Sha384::digest(d).to_vec()),
        (&PKCS_RSA_SHA512, |d| Sha512::digest(d).to_vec()),
        (&PKCS_ECDSA_P256_SHA256, |d| Sha256::digest(d).to_vec()),
        (&PKCS_ECDSA_P384_SHA384, |d| Sha384::digest(d).to_vec()),
    ];
    for (alg, hash) in cases {
        let (result, seen, leaf) = bind(alg, "require").await;
        let e = result.expect_err("the fixture always fails authentication");
        assert_eq!(e.code().map(|c| c.code()), Some("28P01"), "{alg:?}: {e}");
        assert_eq!(
            seen.mechanism.as_deref(),
            Some("SCRAM-SHA-256-PLUS"),
            "{alg:?}"
        );
        assert!(
            seen.client_first
                .as_deref()
                .unwrap()
                .starts_with("p=tls-server-end-point,,"),
            "{alg:?}: {seen:?}"
        );
        let mut expected = b"p=tls-server-end-point,,".to_vec();
        expected.extend_from_slice(&hash(&leaf));
        assert_eq!(
            seen.binding.as_deref(),
            Some(&expected[..]),
            "{alg:?}: wrong tls-server-end-point data"
        );
    }
}

#[tokio::test]
async fn channel_binding_without_a_defined_hash_fails_closed() {
    // Ed25519 signatures have no single hash, so there is no binding data:
    // `require` must stop before any SCRAM message is sent.
    let (result, seen, _) = bind(&PKCS_ED25519, "require").await;
    let e = result.expect_err("channel binding is required but unavailable");
    assert!(
        e.code().is_none(),
        "the server must not have been reached with a credential: {e}"
    );
    assert!(e.to_string().contains("channel binding"), "{e}");
    assert_eq!(seen.mechanism, None, "a SCRAM message was sent: {seen:?}");

    // `prefer` continues without binding, and says so in the GS2 header.
    let (result, seen, _) = bind(&PKCS_ED25519, "prefer").await;
    assert_eq!(result.unwrap_err().code().map(|c| c.code()), Some("28P01"));
    assert_eq!(seen.mechanism.as_deref(), Some("SCRAM-SHA-256"));
    assert!(
        seen.client_first.as_deref().unwrap().starts_with("n,,"),
        "{seen:?}"
    );
    assert_eq!(seen.binding.as_deref(), Some(&b"n,,"[..]));
}
