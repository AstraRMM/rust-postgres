#!/usr/bin/env bash
# AST-2133 wire observation qualification rig. Runs on a disposable Linux host
# with Docker (scripts/aws-check.sh --rust --docker in git-platform), never on
# a shared workstation.
#
#   wire-qualification/rig/run.sh [lint|legacy|wire|overhead|all]
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
mode=${1:-all}
fix=${TLS_QUAL_FIXTURES:-/tmp/wq-fixtures}
pg_image=postgres:16.10
yb_image=yugabytedb/yugabyte:2025.2.5.2-b5
# Disposable-container credential, never used outside this rig.
export WQ_PG_PASSWORD=wq-qualification-only
export WQ_PG_ADDR=127.0.0.1:55440
export WQ_PG_TLS_PORT=55441
export WQ_YB_ADDR=127.0.0.4:5433
export TLS_QUAL_FIXTURES=$fix
status=0
cd "$root"

step() { printf '\n=== %s ===\n' "$*"; }
record() { local name=$1; shift; step "$name"; "$@"; local rc=$?; echo "RESULT $name rc=$rc"; [[ $rc == 0 ]] || status=1; }

wait_for() { # name timeout command...
  local name=$1 deadline=$((SECONDS + $2)); shift 2
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS > deadline)); then echo "timeout waiting for $name"; docker logs --tail 80 "$name" 2>&1 | tail -80; return 1; fi
    sleep 2
  done
  echo "$name ready after ${SECONDS}s"
}

lint() {
  record fmt rustfmt --edition 2018 --check tokio-postgres/src/observe.rs
  record fmt-qualification rustfmt --edition 2021 --check wire-qualification/src/lib.rs wire-qualification/src/bin/overhead.rs wire-qualification/tests/protocol.rs wire-qualification/tests/privacy.rs
  step clippy
  cargo clippy -p yb-tokio-postgres -p yb-postgres -p wire-qualification --all-targets --features yb-tokio-postgres/rustls-aws-lc-rs 2>&1 | tee /tmp/wq-clippy.log | tail -5
  # Upstream crates carry pre-existing lints; fail only on lints in files this change owns.
  if grep -E -A3 '^(warning|error)' /tmp/wq-clippy.log | grep -E -- '--> (tokio-postgres/src/(observe|connection|client|socket|query|prepare|codec|connect_raw|simple_query|statement|portal|transaction|to_statement|cancel_query|cancel_query_raw)\.rs|wire-qualification/)'; then
    echo "RESULT clippy rc=1"; status=1
  else
    echo "RESULT clippy rc=0"
  fi
  record docs cargo doc -q --no-deps -p yb-tokio-postgres
}

containers() {
  step "fixtures"
  rm -rf "$fix" && mkdir -p "$fix"
  cargo run -q -p tls-qualification --bin gen-fixtures -- "$fix" || return 1
  cp tls-qualification/rig/pg-entry.sh wire-qualification/rig/yb-plain-entry.sh "$fix/"
  chmod -R a+rX "$fix"; chmod 755 "$fix"/*.sh

  step "containers"
  docker rm -f wq-pg wq-pg-tls wq-yb >/dev/null 2>&1
  local log_args=(-c logging_collector=on -c log_directory=log -c log_filename=wq.log -c log_rotation_size=0
    -c log_min_duration_statement=0 -c 'log_line_prefix=%a|%e|' -c shared_preload_libraries=pg_stat_statements
    -c pg_stat_statements.track=all)
  # Host connections must authenticate (the image's initdb trusts loopback).
  docker run -d --name wq-pg --network host -e POSTGRES_PASSWORD="$WQ_PG_PASSWORD" \
    -e POSTGRES_INITDB_ARGS='--auth-host=scram-sha-256 --auth-local=trust' "$pg_image" \
    -c port=55440 -c listen_addresses='*' "${log_args[@]}" >/dev/null
  docker run -d --name wq-pg-tls --network host -e POSTGRES_PASSWORD="$WQ_PG_PASSWORD" \
    -v "$fix:/fixtures:ro" --entrypoint /fixtures/pg-entry.sh "$pg_image" 55441 server-valid scram >/dev/null
  docker run -d --name wq-yb --network host -v "$fix:/fixtures:ro" --entrypoint /fixtures/yb-plain-entry.sh "$yb_image" 127.0.0.4 >/dev/null
  wait_for wq-pg 180 docker exec wq-pg pg_isready -h 127.0.0.1 -p 55440 || {
    docker exec wq-pg sh -c 'tail -n 60 /var/lib/postgresql/data/log/*'; return 1; }
  wait_for wq-pg-tls 120 docker exec wq-pg-tls pg_isready -h 127.0.0.1 -p 55441 || return 1
  wait_for wq-yb 420 docker exec wq-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -U yugabyte -c 'select 1' || return 1
  sleep 3
  docker exec wq-pg psql -p 55440 -U postgres -c 'create extension if not exists pg_stat_statements' || return 1
  docker exec wq-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -U yugabyte -c 'create extension if not exists pg_stat_statements' || return 1
  docker exec wq-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -U yugabyte -c 'select host, port, node_type from yb_servers()'
  docker exec wq-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -U yugabyte -At -c 'select version()'
  docker exec wq-pg psql -p 55440 -U postgres -At -c 'select version()'
  docker image inspect --format '{{.Id}} {{index .RepoDigests 0}}' "$pg_image" "$yb_image"
}

wire() {
  containers || { status=1; return; }
  record wire-protocol cargo test -p wire-qualification --test protocol -- --test-threads=1 --nocapture
  record wire-privacy cargo test -p wire-qualification --test privacy -- --nocapture
}

overhead() {
  cargo build -q --release -p wire-qualification --bin overhead || { status=1; return; }
  for engine in pg yb; do
    for run in 1 2 3; do
      record "overhead-$engine-$run" target/release/overhead "$engine" 40 1000
    done
  done
}

case $mode in
  lint) lint ;;
  legacy) tls-qualification/rig/run.sh legacy || status=1 ;;
  wire) wire ;;
  overhead) docker ps --format '{{.Names}}' | grep -q '^wq-pg$' || containers; overhead ;;
  all) lint; tls-qualification/rig/run.sh legacy || status=1; wire; overhead ;;
esac
step "summary status=$status"
exit $status
