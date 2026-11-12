use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yb_postgres_pool::yb_tokio_postgres::{Config, NoTls};
use yb_postgres_pool::{ErrorKind, Pool, PoolConfig};

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    socket.write_u8(tag).await?;
    socket.write_u32((payload.len() + 4) as u32).await?;
    socket.write_all(payload).await
}

async fn serve(mut socket: TcpStream, commits: Arc<AtomicUsize>) -> io::Result<()> {
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    message(&mut socket, b'R', &0u32.to_be_bytes()).await?;
    message(&mut socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut socket, b'Z', b"I").await?;
    let mut status = b'I';
    loop {
        let tag = socket.read_u8().await?;
        let length = socket.read_u32().await?;
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        match tag {
            b'X' => return Ok(()),
            b'Q' => match &body[..body.len() - 1] {
                query if query.starts_with(b"START TRANSACTION") => {
                    status = b'T';
                    message(&mut socket, b'C', b"BEGIN\0").await?;
                    message(&mut socket, b'Z', &[status]).await?;
                }
                b"fail" => {
                    status = b'E';
                    message(&mut socket, b'E', b"SERROR\0C22012\0Mdivision by zero\0\0").await?;
                    message(&mut socket, b'Z', &[status]).await?;
                }
                b"malformed" => {
                    message(&mut socket, b'I', b"").await?;
                    message(&mut socket, b'Z', &[status, 0]).await?;
                }
                b"COMMIT" => {
                    commits.fetch_add(1, Ordering::SeqCst);
                    let tag: &[u8] = if status == b'E' {
                        b"ROLLBACK\0"
                    } else {
                        b"COMMIT\0"
                    };
                    status = b'I';
                    message(&mut socket, b'C', tag).await?;
                    message(&mut socket, b'Z', &[status]).await?;
                }
                _ => {
                    status = b'I';
                    message(&mut socket, b'C', b"ROLLBACK\0").await?;
                    message(&mut socket, b'Z', &[status]).await?;
                }
            },
            _ => {}
        }
    }
}

#[tokio::test]
async fn unknown_status_after_an_aborted_transaction_is_never_committed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let commits = Arc::new(AtomicUsize::new(0));
    {
        let commits = commits.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(serve(socket, commits.clone()));
            }
        });
    }
    let pg: Config = format!(
        "host=127.0.0.1 port={port} user=test dbname=test sslmode=disable connect_timeout=2"
    )
    .parse()
    .unwrap();
    let mut config = PoolConfig::default();
    config.acquire_timeout = Duration::from_secs(2);
    let pool = Pool::new(pg, NoTls, config).unwrap();

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(tx.batch_execute("fail").await.is_err());
    let _ = tx.batch_execute("malformed").await;
    let error = tx.commit().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TransactionAborted, "{error}");
    assert_eq!(commits.load(Ordering::SeqCst), 0, "COMMIT was sent");
}
