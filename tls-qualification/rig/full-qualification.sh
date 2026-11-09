#!/usr/bin/env bash
# Complete AST-2128 qualification on a disposable Docker host:
# toolchain/dependency record, check/clippy, provider builds, legacy suites,
# and the real-engine TLS suite under every compiled provider.
#
#   tls-qualification/rig/full-qualification.sh
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
status=0
step() { printf '\n=== %s ===\n' "$*"; }
record() { local name=$1; shift; step "$name"; "$@"; local rc=$?; echo "RESULT $name rc=$rc"; [[ $rc == 0 ]] || status=1; }

step "revisions"
git rev-parse HEAD
rustc -Vv; cargo -V
cargo tree -p yb-tokio-postgres --features rustls-aws-lc-rs -e normal -i rustls 2>/dev/null | head -5
cargo tree -p yb-tokio-postgres --features rustls-aws-lc-rs -e normal --depth 1

record check-workspace cargo check --workspace --all-targets
record clippy cargo clippy -p yb-tokio-postgres -p tls-qualification --features yb-tokio-postgres/rustls-aws-lc-rs --all-targets
record check-ring-only cargo check -p yb-tokio-postgres --no-default-features --features runtime,rustls-ring
record check-fips cargo check -p yb-tokio-postgres --features rustls-fips

tls-qualification/rig/run.sh all || status=1
record tls-qualification-ring env TLS_QUAL_FIXTURES=/tmp/tls-qual-fixtures TLS_QUAL_PROVIDER=ring \
  cargo test -p tls-qualification --features ring -- --test-threads=1
record tls-qualification-fips env TLS_QUAL_FIXTURES=/tmp/tls-qual-fixtures TLS_QUAL_PROVIDER=fips \
  cargo test -p tls-qualification --features fips -- --test-threads=1
step "final status=$status"
exit $status
