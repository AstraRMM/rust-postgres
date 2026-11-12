#!/usr/bin/env bash
# AST-2128 verify-full TLS qualification rig. Runs on a disposable Linux host
# with Docker (scripts/aws-check.sh --rust --docker in git-platform), never on
# a shared workstation.
#
#   tls-qualification/rig/run.sh [legacy|tls|all]
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
mode=${1:-all}
fix=${TLS_QUAL_FIXTURES:-/tmp/tls-qual-fixtures}
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

legacy() {
  step "legacy suites (plaintext opt-in, upstream fixtures)"
  docker rm -f legacy-pg >/dev/null 2>&1
  docker run -d --name legacy-pg -p 5433:5433 -e POSTGRES_PASSWORD=postgres \
    -v "$root/docker/sql_setup.sh:/docker-entrypoint-initdb.d/sql_setup.sh:ro" postgres:14 >/dev/null
  wait_for legacy-pg 120 docker exec legacy-pg psql -U postgres -p 5433 -h localhost -c 'select 1'
  record legacy-tokio-postgres cargo test -p yb-tokio-postgres --test test
  record legacy-postgres cargo test -p yb-postgres
  docker rm -f legacy-pg >/dev/null
}

tls() {
  step "fixtures"
  rm -rf "$fix" && mkdir -p "$fix"
  cargo run -q -p tls-qualification --bin gen-fixtures -- "$fix" || return 1
  chmod -R a+rX "$fix"
  cp tls-qualification/rig/*.sh "$fix/"
  chmod 755 "$fix"/*.sh

  step "containers"
  docker rm -f pg-valid pg-mtls pg-expired pg-nossl pg-tls12 pg-rotated pg-chained yb-a yb-b >/dev/null 2>&1
  pg() { local name=$1; shift; docker run -d --name "$name" --network host -e POSTGRES_PASSWORD=qualification-only \
    -v "$fix:/fixtures:ro" --entrypoint /fixtures/pg-entry.sh "$pg_image" "$@" >/dev/null; }
  pg pg-valid 55432 server-valid scram
  pg pg-mtls 55433 server-valid cert
  pg pg-expired 55434 server-expired scram
  pg pg-nossl 55435 none plain
  pg pg-tls12 55436 server-valid scram -c ssl_max_protocol_version=TLSv1.2
  pg pg-rotated 55437 server-rotated scram
  pg pg-chained 55438 server-chained scram
  yb() { docker run -d --name "$1" --network host -v "$fix:/fixtures:ro" --entrypoint /fixtures/yb-entry.sh "$yb_image" "$2" "$3" "$4" >/dev/null; }
  yb yb-a 127.0.0.2 yb-a 0
  yb yb-b 127.0.0.3 yb-b 1
  for name in pg-valid pg-mtls pg-expired pg-nossl pg-tls12 pg-rotated pg-chained; do
    wait_for "$name" 120 docker exec "$name" pg_isready -h 127.0.0.1 -p "$(docker inspect -f '{{index .Args 0}}' "$name")" || return 1
  done
  wait_for yb-a 420 docker exec -e PGSSLMODE=require yb-a /home/yugabyte/bin/ysqlsh -h 127.0.0.2 -U yugabyte -c 'select 1' || return 1
  wait_for yb-b 420 docker exec -e PGSSLMODE=require yb-b /home/yugabyte/bin/ysqlsh -h 127.0.0.3 -U yugabyte -c 'select 1' || return 1
  docker exec -e PGSSLMODE=require yb-a /home/yugabyte/bin/ysqlsh -h 127.0.0.2 -U yugabyte -c 'select host, port, node_type, cloud, region, zone, public_ip from yb_servers()'
  docker exec -e PGSSLMODE=require yb-b /home/yugabyte/bin/ysqlsh -h 127.0.0.3 -U yugabyte -c 'select host, port, node_type, cloud, region, zone, public_ip from yb_servers()'
  docker exec -e PGSSLMODE=require yb-a /home/yugabyte/bin/ysqlsh -h 127.0.0.2 -U yugabyte -c 'select version()'
  docker image inspect --format '{{.Id}} {{index .RepoDigests 0}}' "$pg_image" "$yb_image"

  record tls-qualification env TLS_QUAL_FIXTURES="$fix" cargo test -p tls-qualification -- --test-threads=1 --nocapture
}

case $mode in
  legacy) legacy || status=1 ;;
  tls) tls || status=1 ;;
  all) legacy || status=1; tls || status=1 ;;
esac
step "summary status=$status"
exit $status
