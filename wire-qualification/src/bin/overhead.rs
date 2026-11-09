//! AST-2133 observation overhead: interleaved batches of warm prepared
//! single-row queries against real engines, with observation off, on but
//! unscoped (background), and on with one scope per query (the worst case:
//! a request that issues a single statement).
//!
//! usage: overhead <pg|yb> [batches] [queries-per-batch]

use std::time::Instant;
use wire_qualification::{env, open, pg_config};
use yb_tokio_postgres::config::SslMode;
use yb_tokio_postgres::observe;
use yb_tokio_postgres::Config;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Off,
    Unscoped,
    Scoped,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let engine = args.get(1).map(String::as_str).unwrap_or("pg");
    let batches: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(40);
    let per_batch: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(1000);
    let config = match engine {
        "pg" => pg_config(
            env("WQ_PG_ADDR")
                .rsplit(':')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
            "wq_overhead",
        ),
        "yb" => {
            let addr: std::net::SocketAddr = env("WQ_YB_ADDR").parse().unwrap();
            let mut config = Config::new();
            config
                .host(&addr.ip().to_string())
                .port(addr.port())
                .user("yugabyte")
                .dbname("yugabyte")
                .ssl_mode(SslMode::Disable);
            config
        }
        other => panic!("unknown engine {other}"),
    };
    let (client, _task) = open(&config).await.unwrap();
    let stmt = client.prepare("select $1::int4").await.unwrap();
    for i in 0..2000i32 {
        client.query_one(&stmt, &[&i]).await.unwrap();
    }

    let modes = [Mode::Off, Mode::Unscoped, Mode::Scoped];
    let mut means: Vec<Vec<f64>> = vec![Vec::new(); modes.len()];
    let mut scoped_cycles = 0u64;
    for batch in 0..batches {
        // Rotate the order so no mode always runs first.
        for k in 0..modes.len() {
            let index = (batch + k) % modes.len();
            let mode = modes[index];
            observe::set_enabled(!matches!(mode, Mode::Off));
            let start = Instant::now();
            for i in 0..per_batch as i32 {
                match mode {
                    Mode::Off | Mode::Unscoped => {
                        client.query_one(&stmt, &[&i]).await.unwrap();
                    }
                    Mode::Scoped => {
                        let (row, counts) =
                            observe::scope("overhead", client.query_one(&stmt, &[&i])).await;
                        row.unwrap();
                        scoped_cycles += counts.total().cycles_completed;
                    }
                }
            }
            means[index].push(start.elapsed().as_secs_f64() * 1e6 / per_batch as f64);
        }
    }
    observe::set_enabled(true);
    assert_eq!(
        scoped_cycles,
        (batches * per_batch) as u64,
        "every scoped query observed one cycle"
    );
    let off = median(&mut means[0].clone());
    for (index, mode) in modes.iter().enumerate() {
        let m = median(&mut means[index]);
        println!(
            "OVERHEAD engine={engine} mode={mode:?} batches={batches} per_batch={per_batch} median_batch_mean_us={m:.2} delta_vs_off_pct={:+.2}",
            (m - off) / off * 100.0
        );
    }
}
