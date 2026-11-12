use futures_util::{join, FutureExt};
use std::time::Duration;
use tokio::time;
use yb_tokio_postgres::error::SqlState;
use yb_tokio_postgres::{Client, NoTls};

async fn connect(s: &str) -> Client {
    let (client, connection) = yb_tokio_postgres::connect(s, NoTls).await.unwrap();
    let connection = connection.map(|e| e.unwrap());
    tokio::spawn(connection);

    client
}

async fn smoke_test(s: &str) {
    let client = connect(s).await;

    let stmt = client.prepare("SELECT $1::INT").await.unwrap();
    let rows = client.query(&stmt, &[&1i32]).await.unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 1i32);
}

#[tokio::test]
#[ignore] // FIXME doesn't work with our docker-based tests :(
async fn unix_socket() {
    smoke_test("host=/var/run/postgresql port=5433 user=postgres sslmode=disable").await;
}

#[tokio::test]
async fn tcp() {
    smoke_test("host=localhost port=5433 user=postgres sslmode=disable").await;
}

#[tokio::test]
async fn multiple_hosts_one_port() {
    smoke_test("host=foobar.invalid,localhost port=5433 user=postgres sslmode=disable").await;
}

#[tokio::test]
async fn multiple_hosts_multiple_ports() {
    smoke_test("host=foobar.invalid,localhost port=5432,5433 user=postgres sslmode=disable").await;
}

#[tokio::test]
async fn wrong_port_count() {
    yb_tokio_postgres::connect("host=localhost port=5433,5433 user=postgres sslmode=disable", NoTls)
        .await
        .err()
        .unwrap();
}

#[tokio::test]
async fn target_session_attrs_ok() {
    smoke_test("host=localhost port=5433 user=postgres target_session_attrs=read-write sslmode=disable").await;
}

#[tokio::test]
async fn target_session_attrs_err() {
    yb_tokio_postgres::connect(
        "host=localhost port=5433 user=postgres target_session_attrs=read-write sslmode=disable
         options='-c default_transaction_read_only=on'",
        NoTls,
    )
    .await
    .err()
    .unwrap();
}

#[tokio::test]
async fn host_only_ok() {
    let _ = yb_tokio_postgres::connect(
        "host=localhost port=5433 user=pass_user dbname=postgres password=password sslmode=disable",
        NoTls,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hostaddr_only_ok() {
    let _ = yb_tokio_postgres::connect(
        "hostaddr=127.0.0.1 port=5433 user=pass_user dbname=postgres password=password sslmode=disable",
        NoTls,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hostaddr_and_host_ok() {
    let _ = yb_tokio_postgres::connect(
        "hostaddr=127.0.0.1 host=localhost port=5433 user=pass_user dbname=postgres password=password sslmode=disable",
        NoTls,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hostaddr_host_mismatch() {
    let _ = yb_tokio_postgres::connect(
        "hostaddr=127.0.0.1,127.0.0.2 host=localhost port=5433 user=pass_user dbname=postgres password=password sslmode=disable",
        NoTls,
    )
    .await
    .err()
    .unwrap();
}

#[tokio::test]
async fn hostaddr_host_both_missing() {
    let _ = yb_tokio_postgres::connect(
        "port=5433 user=pass_user dbname=postgres password=password sslmode=disable",
        NoTls,
    )
    .await
    .err()
    .unwrap();
}

#[tokio::test]
async fn cancel_query() {
    let client = connect("host=localhost port=5433 user=postgres sslmode=disable").await;

    let cancel_token = client.cancel_token();
    let cancel = cancel_token.cancel_query(NoTls);
    let cancel = time::sleep(Duration::from_millis(100)).then(|()| cancel);

    let sleep = client.batch_execute("SELECT pg_sleep(100)");

    match join!(sleep, cancel) {
        (Err(ref e), Ok(())) if e.code() == Some(&SqlState::QUERY_CANCELED) => {}
        t => panic!("unexpected return: {:?}", t),
    }
}

/// How the fake cancel endpoint answers a cancel request.
#[derive(Clone, Copy)]
enum CancelReply {
    /// Closes the connection after a delay, as the server does.
    CloseAfter(Duration),
    /// Writes a byte instead of closing.
    Data,
}

/// A proxy to the test server that answers cancel requests itself.
async fn cancel_proxy(reply: CancelReply) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 8];
                socket.read_exact(&mut head).await.unwrap();
                if head[4..8] == [4, 210, 22, 46] {
                    let mut rest = [0u8; 8];
                    socket.read_exact(&mut rest).await.unwrap();
                    match reply {
                        CancelReply::CloseAfter(delay) => time::sleep(delay).await,
                        CancelReply::Data => {
                            socket.write_all(b"N").await.unwrap();
                            time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                    return;
                }
                let mut server = tokio::net::TcpStream::connect("127.0.0.1:5433")
                    .await
                    .unwrap();
                server.write_all(&head).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut server).await;
            });
        }
    });
    port
}

/// ASTS-97: `cancel_query` returns only once the server has closed the
/// cancel connection, and treats a reply instead of a close as a failure.
#[tokio::test]
async fn cancel_query_waits_for_the_server_to_close() {
    let port = cancel_proxy(CancelReply::CloseAfter(Duration::from_millis(300))).await;
    let client = connect(&format!(
        "host=127.0.0.1 port={} user=postgres sslmode=disable",
        port
    ))
    .await;
    let started = std::time::Instant::now();
    client.cancel_token().cancel_query(NoTls).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "returned before the server closed: {:?}",
        started.elapsed()
    );

    let port = cancel_proxy(CancelReply::Data).await;
    let client = connect(&format!(
        "host=127.0.0.1 port={} user=postgres sslmode=disable",
        port
    ))
    .await;
    client
        .cancel_token()
        .cancel_query(NoTls)
        .await
        .err()
        .expect("a reply is not a confirmation");
}
