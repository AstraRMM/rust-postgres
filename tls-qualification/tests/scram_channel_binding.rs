//! SCRAM-SHA-256 with `channel_binding=require` and `require_auth` against
//! the real engines: YugabyteDB 2025.2.5.2-b5 with an ECDSA (yb-a, 127.0.0.2)
//! and an all-RSA (yb-c, 127.0.0.4) certificate chain, and PostgreSQL 16 with
//! the RSA chain (55439). On YugabyteDB only the role `qual_scram` uses SCRAM;
//! every other role is trusted over TLS. Uses the rig from
//! `tls-qualification/rig/run.sh`.

use std::path::PathBuf;
use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
use yb_tokio_postgres::{Client, Config, Error, SimpleQueryMessage};

const PASSWORD: &str = "qualification-only";
const PG_RSA: u16 = 55439;
const YB_ECDSA: (&str, &str) = ("yb-a.test", "127.0.0.2");
const YB_RSA: (&str, &str) = ("yb-c.test", "127.0.0.4");

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

fn connector(ca: &str) -> MakeRustlsConnect {
    let dir = PathBuf::from(std::env::var("TLS_QUAL_FIXTURES").expect("TLS_QUAL_FIXTURES"));
    let roots = std::fs::read(dir.join(ca)).unwrap();
    MakeRustlsConnect::new(&TlsMaterial::from_pem(roots), options()).unwrap()
}

fn yb((host, hostaddr): (&str, &str), user: &str, password: &str, extra: &str) -> Config {
    format!(
        "host={host} hostaddr={hostaddr} port=5433 user={user} password={password} dbname=yugabyte \
         load_balance=false {extra}"
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

const STRICT: &str = "channel_binding=require require_auth=scram-sha-256";

#[tokio::test]
async fn yugabyte_scram_with_required_channel_binding_ecdsa() {
    let client = open(&yb(YB_ECDSA, "qual_scram", PASSWORD, STRICT), &connector("ca-a.crt"))
        .await
        .expect("SCRAM-SHA-256-PLUS against YugabyteDB with an ECDSA certificate");
    assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
}

#[tokio::test]
async fn yugabyte_scram_with_required_channel_binding_rsa() {
    let client = open(&yb(YB_RSA, "qual_scram", PASSWORD, STRICT), &connector("ca-rsa.crt"))
        .await
        .expect("SCRAM-SHA-256-PLUS against YugabyteDB with an RSA certificate");
    assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
}

#[tokio::test]
async fn postgres_scram_with_required_channel_binding_rsa() {
    let config: Config = format!("host=localhost port={PG_RSA} user=postgres password={PASSWORD} dbname=postgres {STRICT}")
        .parse()
        .unwrap();
    let client = open(&config, &connector("ca-rsa.crt"))
        .await
        .expect("SCRAM-SHA-256-PLUS against PostgreSQL with an RSA certificate");
    assert_eq!(scalar(&client, "select current_user").await, "postgres");
}

#[tokio::test]
async fn yugabyte_scram_with_preferred_channel_binding() {
    // Separates SCRAM itself from the channel-binding requirement.
    for (node, ca) in [(YB_ECDSA, "ca-a.crt"), (YB_RSA, "ca-rsa.crt")] {
        let config = yb(node, "qual_scram", PASSWORD, "channel_binding=prefer require_auth=scram-sha-256");
        let client = open(&config, &connector(ca)).await.unwrap();
        assert_eq!(scalar(&client, "select current_user").await, "qual_scram");
    }
}

#[tokio::test]
async fn yugabyte_enforces_scram_for_the_scram_role() {
    // A wrong password is refused by the server, so the role really uses
    // SCRAM rather than the trust line.
    let e = open(&yb(YB_ECDSA, "qual_scram", "wrong-password", "require_auth=scram-sha-256"), &connector("ca-a.crt"))
        .await
        .err()
        .expect("wrong password must fail");
    assert_eq!(e.code().map(|c| c.code()), Some("28P01"), "{e}");
}

#[tokio::test]
async fn require_auth_refuses_trust_authentication_on_yugabyte() {
    // `yugabyte` is trusted over TLS: the server sends a bare
    // AuthenticationOk, which require_auth=scram-sha-256 refuses.
    for (node, ca) in [(YB_ECDSA, "ca-a.crt"), (YB_RSA, "ca-rsa.crt")] {
        let tls = connector(ca);
        let e = open(&yb(node, "yugabyte", PASSWORD, "require_auth=scram-sha-256"), &tls)
            .await
            .err()
            .expect("trust must be refused");
        assert!(e.is_security_failure(), "{e}");
        assert!(e.to_string().contains("require_auth"), "{e}");
        // The same role connects without the restriction (permissive default).
        let client = open(&yb(node, "yugabyte", PASSWORD, ""), &tls).await.unwrap();
        assert_eq!(scalar(&client, "select current_user").await, "yugabyte");
    }
}
