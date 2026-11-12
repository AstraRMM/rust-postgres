//! AST-2129 real-engine checks: explicit verify-full realms against two
//! independent YugabyteDB 2025.2.5.2-b5 universes in one process, and bounded
//! TLS-handshake stalls. Uses the rig from `tls-qualification/rig/run.sh`.

use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use yb_tokio_postgres::realm::Realm;
use yb_tokio_postgres::rustls::{MakeRustlsConnect, TlsMaterial, TlsOptions};
use yb_tokio_postgres::{Client, Config, SimpleQueryMessage};

fn connector() -> MakeRustlsConnect {
    let dir = PathBuf::from(std::env::var("TLS_QUAL_FIXTURES").expect("TLS_QUAL_FIXTURES"));
    let roots = std::fs::read(dir.join("ca-a.crt")).unwrap();
    MakeRustlsConnect::new(&TlsMaterial::from_pem(roots), TlsOptions::new()).unwrap()
}

fn yb(host: &str, hostaddr: &str, extra: &str) -> Config {
    format!("host={host} hostaddr={hostaddr} port=5433 user=yugabyte dbname=yugabyte load_balance=true {extra}")
        .parse()
        .unwrap()
}

async fn open(config: &Config, realm: &Realm, tls: &MakeRustlsConnect) -> Client {
    let mut config = config.clone();
    config.realm(realm.clone());
    let (client, connection) = config.connect(tls.clone()).await.unwrap();
    tokio::spawn(connection);
    client
}

async fn server_hosts(client: &Client) -> Vec<String> {
    let mut hosts = Vec::new();
    for message in client.simple_query("select host from yb_servers()").await.unwrap() {
        if let SimpleQueryMessage::Row(row) = message {
            hosts.push(row.get(0).unwrap().to_string());
        }
    }
    hosts
}

#[tokio::test]
async fn two_verified_realms_in_one_process_are_isolated() {
    let tls = connector();
    let (ra, rb) = (Realm::new("yb-a"), Realm::new("yb-b"));
    let conf_a = yb("yb-a.test", "127.0.0.2", "yb_servers_refresh_interval=0");
    let conf_b = yb("yb-b.test", "127.0.0.3", "yb_servers_refresh_interval=0");

    let mut tasks = Vec::new();
    for i in 0..16 {
        let (tls, realm, conf) = if i % 2 == 0 {
            (tls.clone(), ra.clone(), conf_a.clone())
        } else {
            (tls.clone(), rb.clone(), conf_b.clone())
        };
        tasks.push(tokio::spawn(async move {
            let client = open(&conf, &realm, &tls).await;
            let hosts = server_hosts(&client).await;
            (realm.key().name().to_string(), hosts, client)
        }));
    }
    let mut clients = Vec::new();
    for task in tasks {
        let (realm, hosts, client) = task.await.unwrap();
        let expected = if realm == "yb-a" { "127.0.0.2" } else { "127.0.0.3" };
        assert_eq!(hosts, vec![expected.to_string()], "{realm} reached another universe");
        clients.push(client);
    }
    assert_eq!(ra.connection_counts().into_iter().collect::<Vec<_>>(), vec![("127.0.0.2".to_string(), 8)]);
    // Realm B verifies 127.0.0.3 as yb-b.test through the seed mapping.
    assert_eq!(rb.connection_counts().into_iter().collect::<Vec<_>>(), vec![("127.0.0.3".to_string(), 8)]);
    assert!(ra.failed_nodes().is_empty() && rb.failed_nodes().is_empty());
    assert_eq!(ra.topology().unwrap().nodes().len(), 1);
    assert_eq!(rb.topology().unwrap().nodes()[0].identity(), "127.0.0.3");

    // Realm B loses its only endpoint; it must fail rather than reach A.
    let broken_b = yb("yb-b.test", "127.0.0.9", "yb_servers_refresh_interval=0 yb_acquire_timeout=5");
    let mut config = broken_b.clone();
    let lost = Realm::new("yb-b-lost");
    config.realm(lost.clone());
    assert!(config.connect(tls.clone()).await.is_err());
    assert!(lost.connection_counts().is_empty());
    assert_eq!(ra.connection_counts().get("127.0.0.2"), Some(&8));

    drop(clients);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(ra.connection_counts().is_empty() && rb.connection_counts().is_empty());
}

#[tokio::test]
async fn stalled_tls_handshake_is_bounded() {
    // Accepts TLS ('S') and then never sends a ServerHello.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 8];
                if socket.read_exact(&mut buf).await.is_ok() {
                    let _ = socket.write_all(b"S").await;
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });
    let tls = connector();
    for extra in ["load_balance=true", "load_balance=false"] {
        let config: Config = format!(
            "host=localhost port={port} user=yugabyte dbname=yugabyte {extra} yb_attempt_timeout=1 yb_acquire_timeout=3"
        )
        .parse()
        .unwrap();
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(10), config.connect(tls.clone())).await;
        let elapsed = started.elapsed();
        assert!(result.expect("the driver must bound the stall itself").is_err(), "{extra}");
        assert!(elapsed < Duration::from_millis(3500), "{extra}: {elapsed:?}");
        println!("{extra}: stalled TLS handshake abandoned after {elapsed:?}");
    }
}

#[tokio::test]
async fn established_sessions_refresh_the_topology_and_report_standing() {
    use yb_tokio_postgres::realm::NodeStanding;
    let tls = connector();
    let realm = Realm::new("yb-a-session-refresh");
    let conf = yb("yb-a.test", "127.0.0.2", "yb_servers_refresh_interval=0");
    let client = open(&conf, &realm, &tls).await;
    let discoveries = realm.discovery_count();
    let info = realm.refresh_with(&client, &conf).await.unwrap();
    assert_eq!(realm.discovery_count(), discoveries + 1);
    assert_eq!(info.nodes().len(), 1);
    assert_eq!(info.nodes()[0].identity(), "127.0.0.2");
    assert_eq!(client.node_standing(), NodeStanding::Preferred);
    client
        .batch_execute("CREATE SCHEMA IF NOT EXISTS shadow; CREATE OR REPLACE FUNCTION shadow.yb_servers() RETURNS TABLE(host text) LANGUAGE sql AS $$ SELECT 'forged'::text $$; SET search_path = shadow, pg_catalog")
        .await
        .unwrap();
    let info = realm.refresh_with(&client, &conf).await.unwrap();
    assert_eq!(info.nodes()[0].identity(), "127.0.0.2", "an unqualified lookup would reach shadow.yb_servers()");
    client.batch_execute("DROP SCHEMA shadow CASCADE").await.unwrap();
}
