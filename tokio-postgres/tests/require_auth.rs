//! `require_auth`: the server may only use an allowed authentication method,
//! and a refused request fails the connection before any credential is sent.
//!
//! A loopback fixture speaks the PostgreSQL startup protocol, answers the
//! startup message with one chosen authentication request, and records every
//! byte the client sends afterwards.
#![cfg(feature = "runtime")]

use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use yb_tokio_postgres::config::{AuthMethod, Config};
use yb_tokio_postgres::{Error, NoTls};

const PASSWORD: &str = "fixture-password-not-a-secret";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Request {
    /// A bare AuthenticationOk: the server skips authentication.
    Ok,
    Cleartext,
    Md5,
    /// AuthenticationSASL offering SCRAM-SHA-256.
    Sasl,
}

fn frame(buf: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    buf.push(tag);
    buf.extend_from_slice(&(payload.len() as u32 + 4).to_be_bytes());
    buf.extend_from_slice(payload);
}

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    let mut buf = Vec::new();
    frame(&mut buf, tag, payload);
    socket.write_all(&buf).await
}

async fn read_message(socket: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let tag = socket.read_u8().await?;
    let length = socket.read_u32().await?;
    let mut payload = vec![0; length as usize - 4];
    socket.read_exact(&mut payload).await?;
    Ok((tag, payload))
}

async fn ready(socket: &mut TcpStream) -> io::Result<()> {
    let mut buf = Vec::new();
    frame(&mut buf, b'R', &0u32.to_be_bytes());
    frame(&mut buf, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]);
    frame(&mut buf, b'S', b"client_encoding\0UTF8\0");
    frame(&mut buf, b'S', b"server_version\x0015.0\0");
    frame(&mut buf, b'Z', b"I");
    socket.write_all(&buf).await
}

/// Serves one session and returns every byte the client sent after the
/// authentication request. Password requests are answered with
/// AuthenticationOk so that an allowed method yields a usable session.
async fn serve(listener: TcpListener, request: Request) -> io::Result<Vec<u8>> {
    let (mut socket, _) = listener.accept().await?;
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;

    match request {
        Request::Ok => {
            ready(&mut socket).await?;
        }
        Request::Cleartext => message(&mut socket, b'R', &3u32.to_be_bytes()).await?,
        Request::Md5 => {
            let mut payload = 5u32.to_be_bytes().to_vec();
            payload.extend_from_slice(&[1, 2, 3, 4]);
            message(&mut socket, b'R', &payload).await?
        }
        Request::Sasl => {
            let mut payload = 10u32.to_be_bytes().to_vec();
            payload.extend_from_slice(b"SCRAM-SHA-256\0\0");
            message(&mut socket, b'R', &payload).await?
        }
    }

    let mut sent = Vec::new();
    if matches!(request, Request::Cleartext | Request::Md5) {
        match read_message(&mut socket).await {
            Ok((tag, payload)) => {
                sent.push(tag);
                sent.extend_from_slice(&payload);
                if tag == b'p' {
                    ready(&mut socket).await?;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::UnexpectedEof
                    || e.kind() == io::ErrorKind::ConnectionReset =>
            {
                return Ok(sent)
            }
            Err(e) => return Err(e),
        }
    }
    // Collect whatever else arrives until the client closes the socket.
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(2), socket.read_to_end(&mut rest)).await;
    sent.extend_from_slice(&rest);
    Ok(sent)
}

struct Outcome {
    result: Result<(), Error>,
    sent: Vec<u8>,
}

async fn attempt(request: Request, require_auth: Option<&str>) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server: JoinHandle<io::Result<Vec<u8>>> = tokio::spawn(serve(listener, request));

    let mut conninfo = format!(
        "host=127.0.0.1 port={} user=u dbname=d password={} sslmode=disable connect_timeout=5",
        port, PASSWORD
    );
    if let Some(value) = require_auth {
        conninfo.push_str(&format!(" require_auth={}", value));
    }
    let config: Config = conninfo.parse().unwrap();
    let result = match timeout(Duration::from_secs(10), config.connect(NoTls))
        .await
        .expect("connect must not hang")
    {
        Ok((client, connection)) => {
            drop(client);
            drop(connection);
            Ok(())
        }
        Err(e) => Err(e),
    };
    let sent = server.await.unwrap().unwrap();
    Outcome { result, sent }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The connection failed with a require_auth refusal and the client sent no
/// password message, SASL response or password bytes.
fn assert_refused(outcome: &Outcome, case: &str) {
    let e = outcome
        .result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("{}: connection must fail", case));
    assert!(e.is_security_failure(), "{}: {}", case, e);
    assert!(e.to_string().contains("require_auth"), "{}: {}", case, e);
    assert_ne!(
        outcome.sent.first(),
        Some(&b'p'),
        "{}: client answered",
        case
    );
    assert!(
        !contains(&outcome.sent, PASSWORD.as_bytes()),
        "{}: password sent",
        case
    );
}

#[tokio::test]
async fn scram_only_refuses_cleartext_md5_and_skipped_authentication() {
    for request in [Request::Cleartext, Request::Md5, Request::Ok] {
        let outcome = attempt(request, Some("scram-sha-256")).await;
        assert_refused(&outcome, &format!("{:?}", request));
    }
}

#[tokio::test]
async fn scram_only_proceeds_with_scram() {
    let outcome = attempt(Request::Sasl, Some("scram-sha-256")).await;
    // The fixture does not finish the exchange, so the session fails, but
    // not because of require_auth: the client sent its SASLInitialResponse.
    let e = outcome.result.expect_err("fixture never completes SCRAM");
    assert!(!e.to_string().contains("require_auth"), "{}", e);
    assert_eq!(outcome.sent.first(), Some(&b'p'));
    assert!(contains(&outcome.sent, b"SCRAM-SHA-256\0"));
}

#[tokio::test]
async fn other_allow_lists_refuse_scram_and_admit_listed_methods() {
    let outcome = attempt(Request::Sasl, Some("md5")).await;
    assert_refused(&outcome, "md5 vs sasl");

    let outcome = attempt(Request::Cleartext, Some("password")).await;
    outcome.result.expect("password is allowed");
    assert_eq!(outcome.sent.first(), Some(&b'p'));
    assert!(contains(&outcome.sent, PASSWORD.as_bytes()));

    let outcome = attempt(Request::Ok, Some("none,scram-sha-256")).await;
    outcome.result.expect("none is allowed");
}

#[tokio::test]
async fn negated_lists_refuse_only_the_named_methods() {
    for request in [Request::Cleartext, Request::Md5] {
        let outcome = attempt(request, Some("!password,!md5")).await;
        assert_refused(&outcome, &format!("negated {:?}", request));
    }
    let outcome = attempt(Request::Ok, Some("!password,!md5")).await;
    outcome.result.expect("none is not forbidden");
}

#[tokio::test]
async fn unset_require_auth_keeps_the_permissive_default() {
    let outcome = attempt(Request::Cleartext, None).await;
    outcome.result.expect("default admits cleartext");
    let outcome = attempt(Request::Ok, None).await;
    outcome
        .result
        .expect("default admits skipped authentication");
}

#[test]
fn parses_key_value_and_url_forms() {
    let config: Config = "user=u require_auth=scram-sha-256".parse().unwrap();
    assert_eq!(
        config.get_require_auth(),
        Some(&[AuthMethod::ScramSha256][..])
    );

    let config: Config = "postgresql://u@h/db?require_auth=md5%2Cscram-sha-256"
        .parse()
        .unwrap();
    assert_eq!(
        config.get_require_auth(),
        Some(&[AuthMethod::Md5, AuthMethod::ScramSha256][..])
    );

    let config: Config = "postgresql://u@h/db?require_auth=!password,!md5"
        .parse()
        .unwrap();
    assert_eq!(
        config.get_require_auth(),
        Some(&[AuthMethod::None, AuthMethod::ScramSha256][..])
    );

    let config: Config = "user=u require_auth=''".parse().unwrap();
    assert_eq!(config.get_require_auth(), None);
    let config: Config = "user=u".parse().unwrap();
    assert_eq!(config.get_require_auth(), None);

    let mut built = Config::new();
    built
        .user("u")
        .require_auth(Some(&[AuthMethod::ScramSha256]));
    assert_eq!(
        built,
        "user=u require_auth=scram-sha-256"
            .parse::<Config>()
            .unwrap()
    );
}

#[test]
fn rejects_invalid_values() {
    for value in [
        "scram",
        "SCRAM-SHA-256",
        "gss",
        "md5,!password",
        "!md5,password",
        "md5,md5",
        "md5,",
        "!none,!password,!md5,!scram-sha-256",
    ] {
        let conninfo = format!("user=u require_auth='{}'", value);
        let e = conninfo
            .parse::<Config>()
            .err()
            .unwrap_or_else(|| panic!("`{}` must be rejected", value));
        assert!(e.to_string().contains("require_auth"), "{}: {}", value, e);
    }
}
