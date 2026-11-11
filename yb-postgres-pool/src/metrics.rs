//! Prometheus text rendering of pool state and counters.

use crate::error::PoolError;
use crate::pool::PoolState;
use std::fmt::Write;
use std::time::Duration;

const RESERVED_LABELS: [&str; 2] = ["kind", "reason"];

enum Value {
    Count(u64),
    Seconds(Duration),
}

struct Family {
    name: &'static str,
    kind: &'static str,
    samples: Vec<(Option<(&'static str, &'static str)>, Value)>,
}

fn gauge(name: &'static str, value: impl Into<u64>) -> Family {
    Family {
        name,
        kind: "gauge",
        samples: vec![(None, Value::Count(value.into()))],
    }
}

fn counter(name: &'static str, value: u64) -> Family {
    Family {
        name,
        kind: "counter",
        samples: vec![(None, Value::Count(value))],
    }
}

fn labelled(
    name: &'static str,
    label: &'static str,
    samples: Vec<(&'static str, Value)>,
) -> Family {
    Family {
        name,
        kind: "counter",
        samples: samples
            .into_iter()
            .map(|(v, value)| (Some((label, v)), value))
            .collect(),
    }
}

fn families(state: &PoolState) -> Vec<Family> {
    let s = &state.stats;
    vec![
        gauge("physical_connections", state.physical),
        gauge("pooled_connections", state.pooled),
        gauge("idle_connections", state.idle),
        gauge("borrowed_connections", state.borrowed),
        gauge("opening_connections", state.opening),
        gauge("waiting_checkouts", state.waiting),
        gauge("limiter_in_use_connections", state.limiter_in_use),
        gauge("limiter_max_connections", state.limiter_max),
        gauge("warm_deficit_connections", s.warm_deficit),
        counter("connects_total", s.connects),
        counter("connect_failures_total", s.connect_failures),
        Family {
            name: "connect_seconds_total",
            kind: "counter",
            samples: vec![(None, Value::Seconds(s.connect_time))],
        },
        counter("session_init_round_trips_total", s.session_init_round_trips),
        counter("checkouts_total", s.checkouts),
        counter("acquire_timeouts_total", s.acquire_timeouts),
        labelled(
            "probes_total",
            "kind",
            vec![
                ("checkout", Value::Count(s.probes)),
                ("readiness", Value::Count(s.readiness_probes)),
            ],
        ),
        labelled(
            "probe_failures_total",
            "kind",
            vec![
                ("checkout", Value::Count(s.probe_failures)),
                ("readiness", Value::Count(s.readiness_probe_failures)),
            ],
        ),
        labelled(
            "probe_seconds_total",
            "kind",
            vec![
                ("checkout", Value::Seconds(s.probe_time)),
                ("readiness", Value::Seconds(s.readiness_probe_time)),
            ],
        ),
        counter("terminal_failures_total", s.terminal_failures),
        labelled(
            "retirements_total",
            "reason",
            vec![
                ("closed", Value::Count(s.retired_closed)),
                ("superseded_tls", Value::Count(s.retired_superseded_tls)),
                ("aged", Value::Count(s.retired_aged)),
                ("idle", Value::Count(s.retired_idle)),
                ("dirty_session", Value::Count(s.retired_dirty_session)),
                ("cleanup_failed", Value::Count(s.retired_cleanup_failed)),
                ("probe_failed", Value::Count(s.retired_probe_failed)),
                ("explicit", Value::Count(s.retired_explicit)),
                ("shutdown", Value::Count(s.retired_shutdown)),
                ("reaped", Value::Count(s.reaped)),
            ],
        ),
        counter("cleanups_total", s.cleanups),
        counter("cleanup_cancels_total", s.cleanup_cancels),
        counter("cleanup_rollbacks_total", s.cleanup_rollbacks),
        counter("statement_cache_hits_total", s.statement_cache_hits),
        counter("statement_prepares_total", s.statement_prepares),
        counter(
            "statement_cache_evictions_total",
            s.statement_cache_evictions,
        ),
        counter("statement_invalidations_total", s.statement_invalidations),
        counter("stale_statement_retries_total", s.stale_statement_retries),
        counter("warm_connects_total", s.warm_connects),
        counter("forced_closes_total", s.forced_closes),
    ]
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn label_set(labels: &[(&str, &str)]) -> Result<String, PoolError> {
    let mut sorted = labels.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut seen: Vec<&str> = Vec::new();
    let mut out = String::new();
    for (name, value) in &sorted {
        if !valid_name(name) || name.starts_with("__") || RESERVED_LABELS.contains(name) {
            return Err(PoolError::config(format!(
                "invalid or reserved pool metric label name {:?}",
                name
            )));
        }
        if seen.contains(name) {
            return Err(PoolError::config(format!(
                "pool metric label {:?} is repeated",
                name
            )));
        }
        seen.push(name);
        if !out.is_empty() {
            out.push(',');
        }
        let _ = write!(out, "{}=\"{}\"", name, escape(value));
    }
    Ok(out)
}

/// Renders several pools in the Prometheus text format under `namespace`,
/// one `# TYPE` line per metric family, so pools of one process can share
/// a scrape. Each pool carries its own `labels`, rendered sorted by name,
/// which must tell the pools apart and must come from a bounded set
/// (service, pool or realm names, never SQL text, tenant identifiers or
/// connection strings). Metric names are `{namespace}_pool_*`; the only
/// labels added are `kind` (probes) and `reason` (retirements), each with a
/// fixed set of values, after the pool's own.
///
/// The limiter gauges describe the process-wide limiter the pool shares, so
/// pools sharing one report the same values.
///
/// # Errors
///
/// [`ErrorKind::Config`](crate::ErrorKind::Config) if `namespace` is not a
/// valid metric name prefix, or if a label name is invalid, reserved
/// (`__*`, `kind`, `reason`) or repeated within a pool's labels, or if two
/// pools have the same label set in any order. Nothing is rendered then.
pub fn render_pools_prometheus(
    namespace: &str,
    pools: &[(&[(&str, &str)], &PoolState)],
) -> Result<String, PoolError> {
    if !valid_name(namespace) {
        return Err(PoolError::config(format!(
            "invalid metric namespace {:?}",
            namespace
        )));
    }
    let mut rendered: Vec<(String, Vec<Family>)> = Vec::with_capacity(pools.len());
    for (labels, state) in pools {
        let set = label_set(labels)?;
        if rendered.iter().any(|(other, _)| *other == set) {
            return Err(PoolError::config(format!(
                "two pools have the same metric labels {{{}}}",
                set
            )));
        }
        rendered.push((set, families(state)));
    }
    let mut out = String::new();
    let count = rendered.first().map_or(0, |(_, families)| families.len());
    for index in 0..count {
        let mut header = false;
        for (labels, families) in &rendered {
            let family = &families[index];
            if !header {
                let _ = writeln!(
                    out,
                    "# TYPE {}_pool_{} {}",
                    namespace, family.name, family.kind
                );
                header = true;
            }
            for (extra, value) in &family.samples {
                let mut set = labels.clone();
                if let Some((name, v)) = extra {
                    if !set.is_empty() {
                        set.push(',');
                    }
                    let _ = write!(set, "{}=\"{}\"", name, v);
                }
                let _ = write!(out, "{}_pool_{}", namespace, family.name);
                if !set.is_empty() {
                    let _ = write!(out, "{{{}}}", set);
                }
                let _ = match value {
                    Value::Count(n) => writeln!(out, " {}", n),
                    Value::Seconds(d) => writeln!(out, " {}", d.as_secs_f64()),
                };
            }
        }
    }
    Ok(out)
}

impl PoolState {
    /// Renders this pool in the Prometheus text format under `namespace`
    /// with `labels` on every series. See [`render_pools_prometheus`] for
    /// the metric names and for exporting several pools in one scrape.
    ///
    /// # Errors
    ///
    /// As [`render_pools_prometheus`].
    pub fn render_prometheus(
        &self,
        namespace: &str,
        labels: &[(&str, &str)],
    ) -> Result<String, PoolError> {
        render_pools_prometheus(namespace, &[(labels, self)])
    }
}
