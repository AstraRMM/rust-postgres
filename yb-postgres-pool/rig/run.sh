#!/usr/bin/env bash
# AST-2130 native pool qualification rig. Runs on a disposable Linux host with
# Docker (scripts/aws-check.sh --rust --docker in git-platform), never on a
# shared workstation.
#
#   yb-postgres-pool/rig/run.sh [check|pool|legacy|all]
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
mode=${1:-all}
fix=${POOL_TEST_FIXTURES:-/tmp/pool-test-fixtures}
pg_image=postgres:16.10
yb_image=yugabytedb/yugabyte:2025.2.5.2-b5
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

check() {
  record fmt bash -c "cargo fmt --check -p yb-postgres-pool && rustfmt --check --edition 2018 tokio-postgres/src/session_status.rs tokio-postgres/src/client.rs tokio-postgres/src/connection.rs tokio-postgres/src/connect_raw.rs tokio-postgres/src/codec.rs"
  record clippy cargo clippy -p yb-postgres-pool --no-deps --all-targets --features rustls-aws-lc-rs -- -D warnings
  record clippy-fork cargo clippy -p yb-tokio-postgres --features rustls-aws-lc-rs --all-targets
  record build-fork cargo build -p yb-tokio-postgres --all-targets --features rustls-aws-lc-rs
  record unit cargo test -p yb-postgres-pool --lib --features rustls-aws-lc-rs
}

pool() {
  step "fixtures"
  rm -rf "$fix" && mkdir -p "$fix"
  cargo run -q -p tls-qualification --bin gen-fixtures -- "$fix" || return 1
  cp tls-qualification/rig/pg-entry.sh yb-postgres-pool/rig/yb-plain-entry.sh "$fix/"
  chmod -R a+rX "$fix" && chmod 755 "$fix"/*.sh

  step "containers"
  docker rm -f pool-pg pool-pg-tls pool-yb >/dev/null 2>&1
  docker run -d --name pool-pg --network host -e POSTGRES_PASSWORD=pool-test-only "$pg_image" \
    -c port=55440 -c listen_addresses=127.0.0.1 -c max_connections=300 >/dev/null
  docker run -d --name pool-pg-tls --network host -e POSTGRES_PASSWORD=pool-test-only \
    -v "$fix:/fixtures:ro" --entrypoint /fixtures/pg-entry.sh "$pg_image" 55441 server-valid scram >/dev/null
  docker run -d --name pool-yb --network host -v "$fix:/fixtures:ro" \
    --entrypoint /fixtures/yb-plain-entry.sh "$yb_image" 127.0.0.4 5434 >/dev/null
  wait_for pool-pg 120 docker exec pool-pg pg_isready -h 127.0.0.1 -p 55440 || return 1
  wait_for pool-pg-tls 120 docker exec pool-pg-tls pg_isready -h 127.0.0.1 -p 55441 || return 1
  wait_for pool-yb 420 docker exec pool-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -p 5434 -U yugabyte -c 'select 1' || { status=1; return 1; }
  docker exec pool-pg psql -U postgres -h 127.0.0.1 -p 55440 -Atc 'select version()'
  docker exec pool-yb /home/yugabyte/bin/ysqlsh -h 127.0.0.4 -p 5434 -U yugabyte -Atc 'select version()'
  docker image inspect --format '{{.Id}} {{index .RepoDigests 0}}' "$pg_image" "$yb_image"

  record pool-tests env POOL_TEST_PG=127.0.0.1:55440 POOL_TEST_YB=127.0.0.4:5434 \
    POOL_TEST_TLS_PG=55441 POOL_TEST_TLS_ROOTS="$fix/ca-a.crt" POOL_TEST_REQUIRE=1 \
    cargo test -p yb-postgres-pool --features rustls-aws-lc-rs -- --test-threads=1 --nocapture
  docker rm -f pool-pg pool-pg-tls pool-yb >/dev/null 2>&1
}

legacy() {
  step "legacy suites (plaintext opt-in, upstream fixtures)"
  docker rm -f legacy-pg >/dev/null 2>&1
  docker run -d --name legacy-pg -p 5433:5433 -e POSTGRES_PASSWORD=postgres \
    -v "$root/docker/sql_setup.sh:/docker-entrypoint-initdb.d/sql_setup.sh:ro" postgres:14 >/dev/null
  wait_for legacy-pg 120 docker exec legacy-pg psql -U postgres -p 5433 -h localhost -c 'select 1' || { status=1; return 1; }
  record legacy-tokio-postgres cargo test -p yb-tokio-postgres --test test
  record legacy-postgres cargo test -p yb-postgres
  docker rm -f legacy-pg >/dev/null
}

case $mode in
  check) check ;;
  pool) pool ;;
  legacy) legacy ;;
  all) check; pool; legacy ;;
esac
step "summary status=$status"
exit $status
