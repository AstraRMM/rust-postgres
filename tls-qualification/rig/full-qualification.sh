#!/usr/bin/env bash
# Complete AST-2128 qualification on a disposable Docker host:
# toolchain/dependency record, check/clippy, provider builds, legacy suites at
# the base revision and at HEAD, and the real-engine TLS suite under every
# compiled provider.
#
#   tls-qualification/rig/full-qualification.sh <base-rev>
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
base=${1:?base revision}
cd "$root"
status=0
step() { printf '\n=== %s ===\n' "$*"; }
record() { local name=$1; shift; step "$name"; "$@"; local rc=$?; echo "RESULT $name rc=$rc"; [[ $rc == 0 ]] || status=1; }

step "revisions"
git rev-parse HEAD "$base"
rustc -Vv; cargo -V
cargo tree -p yb-tokio-postgres --features rustls-aws-lc-rs -e normal -i rustls 2>/dev/null | head -5
cargo tree -p yb-tokio-postgres --features rustls-aws-lc-rs -e normal --depth 1

record check-workspace cargo check --workspace --all-targets
record clippy cargo clippy -p yb-tokio-postgres -p tls-qualification --features yb-tokio-postgres/rustls-aws-lc-rs --all-targets
record check-ring-only cargo check -p yb-tokio-postgres --no-default-features --features runtime,rustls-ring
record check-fips cargo check -p yb-tokio-postgres --features rustls-fips

step "legacy suites at base $base"
git worktree add -q /tmp/base "$base"
docker rm -f legacy-pg >/dev/null 2>&1
docker run -d --name legacy-pg -p 5433:5433 -e POSTGRES_PASSWORD=postgres \
  -v "$root/docker/sql_setup.sh:/docker-entrypoint-initdb.d/sql_setup.sh:ro" postgres:14 >/dev/null
until docker exec legacy-pg pg_isready -h 127.0.0.1 -p 5433 >/dev/null 2>&1; do sleep 2; done
# Recorded separately: the base revision's own failures are the comparison
# baseline for HEAD's legacy results, so they are reported, not hidden.
record base-legacy-tokio-postgres bash -o pipefail -c 'cd /tmp/base && CARGO_TARGET_DIR=/tmp/base-target cargo +1.96.1 test -p yb-tokio-postgres --test test 2>&1 | grep -E "^test .*FAILED|^test result|panicked"'
record base-legacy-postgres bash -o pipefail -c 'cd /tmp/base && CARGO_TARGET_DIR=/tmp/base-target cargo +1.96.1 test -p yb-postgres 2>&1 | grep -E "FAILED|^test result"'
docker rm -f legacy-pg >/dev/null

tls-qualification/rig/run.sh all || status=1
record tls-qualification-ring env TLS_QUAL_FIXTURES=/tmp/tls-qual-fixtures TLS_QUAL_PROVIDER=ring \
  cargo test -p tls-qualification --features ring -- --test-threads=1
record tls-qualification-fips env TLS_QUAL_FIXTURES=/tmp/tls-qual-fixtures TLS_QUAL_PROVIDER=fips \
  cargo test -p tls-qualification --features fips -- --test-threads=1
step "final status=$status"
exit $status
