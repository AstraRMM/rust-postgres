#![cfg(feature = "runtime")]

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yb_tokio_postgres::{Config, NoTls, TransactionStatus};

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    socket.write_u8(tag).await?;
    socket.write_u32((payload.len() + 4) as u32).await?;
    socket.write_all(payload).await
}

async fn serve(mut socket: TcpStream) -> io::Result<()> {
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    message(&mut socket, b'R', &0u32.to_be_bytes()).await?;
    message(&mut socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut socket, b'S', b"client_encoding\0UTF8\0").await?;
    message(&mut socket, b'Z', b"I").await?;
    loop {
        let tag = socket.read_u8().await?;
        let length = socket.read_u32().await?;
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        if tag != b'Q' {
            continue;
        }
        match &body[..body.len() - 1] {
            b"begin" => {
                message(&mut socket, b'C', b"BEGIN\0").await?;
                message(&mut socket, b'Z', b"T").await?;
            }
            b"commit" => {
                message(&mut socket, b'C', b"COMMIT\0").await?;
                message(&mut socket, b'Z', b"I").await?;
            }
            _ => {
                message(&mut socket, b'I', b"").await?;
                message(&mut socket, b'Z', b"I\0").await?;
            }
        }
    }
}

#[tokio::test]
async fn malformed_ready_for_query_leaves_the_status_unknown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(socket));
        }
    });
    let config: Config = format!(
        "host=127.0.0.1 port={port} user=test dbname=test sslmode=disable connect_timeout=2"
    )
    .parse()
    .unwrap();

    for prior in [None, Some("begin")] {
        let (client, connection) = config.connect(NoTls).await.unwrap();
        tokio::spawn(connection);
        if let Some(query) = prior {
            client.batch_execute(query).await.unwrap();
            assert_eq!(
                client.transaction_status(),
                TransactionStatus::InTransaction
            );
        } else {
            assert_eq!(client.transaction_status(), TransactionStatus::Idle);
        }
        let _ = client.batch_execute("malformed").await;
        assert_eq!(
            client.transaction_status(),
            TransactionStatus::Unknown,
            "after {:?}",
            prior
        );
        assert!(!client.is_closed());
    }
}
