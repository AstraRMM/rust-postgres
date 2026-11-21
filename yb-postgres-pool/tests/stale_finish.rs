use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yb_postgres_pool::yb_tokio_postgres::{Config, NoTls};
use yb_postgres_pool::{ErrorKind, Pool, PoolConfig, PoolError};

#[derive(Clone, Copy, PartialEq)]
enum Stale {
    Begin,
    Prepare,
    Commit,
    Rollback,
}

const CATALOG_MISMATCH: &[u8] = b"SERROR\0C40001\0Mcatalog version mismatch\0\0";
const SCHEMA_MISMATCH: &[u8] = b"SERROR\0CXX000\0Mschema version mismatch\0\0";

async fn message(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    socket.write_u8(tag).await?;
    socket.write_u32((payload.len() + 4) as u32).await?;
    socket.write_all(payload).await
}

async fn serve(mut socket: TcpStream, stale: Stale) -> io::Result<()> {
    let length = socket.read_u32().await?;
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await?;
    message(&mut socket, b'R', &0u32.to_be_bytes()).await?;
    message(&mut socket, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    message(&mut socket, b'Z', b"I").await?;
    let mut status = b'I';
    let mut discarding = false;
    loop {
        let tag = socket.read_u8().await?;
        let length = socket.read_u32().await?;
        let mut body = vec![0; length as usize - 4];
        socket.read_exact(&mut body).await?;
        if discarding && tag != b'S' {
            continue;
        }
        match tag {
            b'X' => return Ok(()),
            b'Q' => {
                let query = &body[..body.len() - 1];
                let (step, done, next): (Stale, &[u8], u8) = match query {
                    q if q.starts_with(b"START TRANSACTION") => (Stale::Begin, b"BEGIN\0", b'T'),
                    b"COMMIT" => (Stale::Commit, b"COMMIT\0", b'I'),
                    _ => (Stale::Rollback, b"ROLLBACK\0", b'I'),
                };
                status = if step == stale {
                    let error = if step == Stale::Rollback {
                        SCHEMA_MISMATCH
                    } else {
                        CATALOG_MISMATCH
                    };
                    message(&mut socket, b'E', error).await?;
                    b'I'
                } else {
                    message(&mut socket, b'C', done).await?;
                    next
                };
                message(&mut socket, b'Z', &[status]).await?;
            }
            b'P' => {
                let query = body.split(|b| *b == 0).nth(1).unwrap_or_default();
                if stale == Stale::Prepare && query == b"stale" {
                    message(&mut socket, b'E', SCHEMA_MISMATCH).await?;
                    discarding = true;
                    if status == b'T' {
                        status = b'E';
                    }
                } else {
                    message(&mut socket, b'1', b"").await?;
                }
            }
            b'D' => {
                message(&mut socket, b't', &[0, 0]).await?;
                message(&mut socket, b'n', b"").await?;
            }
            b'B' => message(&mut socket, b'2', b"").await?,
            b'E' => message(&mut socket, b'C', b"SELECT 0\0").await?,
            b'C' => message(&mut socket, b'3', b"").await?,
            b'S' => {
                discarding = false;
                message(&mut socket, b'Z', &[status]).await?;
            }
            _ => {}
        }
    }
}

async fn pool(stale: Stale) -> Pool<NoTls> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(socket, stale));
        }
    });
    let pg: Config = format!(
        "host=127.0.0.1 port={port} user=test dbname=test sslmode=disable connect_timeout=2"
    )
    .parse()
    .unwrap();
    let mut config = PoolConfig::default();
    config.acquire_timeout = Duration::from_secs(2);
    Pool::new(pg, NoTls, config).unwrap()
}

fn assert_stale(pool: &Pool<NoTls>, error: &PoolError, cached: usize) {
    assert_eq!(error.kind(), ErrorKind::StaleStatement, "{error}");
    assert_eq!(cached, 0, "the stale error left statements cached");
    assert_eq!(pool.state().stats.statement_invalidations, 1);
}

#[tokio::test]
async fn stale_commit_clears_the_statement_cache() {
    let pool = pool(Stale::Commit).await;
    let mut client = pool.get().await.unwrap();
    let mut tx = client.transaction().await.unwrap();
    tx.prepare_cached("SELECT 1").await.unwrap();
    tx.prepare_cached("SELECT 2").await.unwrap();
    let error = tx.commit().await.unwrap_err();
    assert_stale(&pool, &error, client.cached_statements());
}

#[tokio::test]
async fn stale_rollback_clears_the_statement_cache() {
    let pool = pool(Stale::Rollback).await;
    let mut client = pool.get().await.unwrap();
    let mut tx = client.transaction().await.unwrap();
    tx.prepare_cached("SELECT 1").await.unwrap();
    let error = tx.rollback().await.unwrap_err();
    assert_stale(&pool, &error, client.cached_statements());
}

#[tokio::test]
async fn stale_begin_clears_the_statement_cache() {
    let pool = pool(Stale::Begin).await;
    let mut client = pool.get().await.unwrap();
    client.prepare_cached("SELECT 1").await.unwrap();
    let error = match client.transaction().await {
        Ok(_) => panic!("BEGIN succeeded"),
        Err(error) => error,
    };
    assert_stale(&pool, &error, client.cached_statements());
}

#[tokio::test]
async fn stale_prepare_clears_the_statement_cache() {
    let pool = pool(Stale::Prepare).await;
    let mut client = pool.get().await.unwrap();
    client.prepare_cached("SELECT 1").await.unwrap();
    let error = match client.prepare_cached("stale").await {
        Ok(_) => panic!("the stale statement prepared"),
        Err(error) => error,
    };
    assert_stale(&pool, &error, client.cached_statements());
}
