#!/bin/bash
# Entry point for the PostgreSQL TLS fixtures.
# usage: pg-entry.sh <port> <server-cert-name|none> <hba: scram|cert|plain> [postgres -c args...]
set -euo pipefail
port=$1 cert=$2 hba=$3
shift 3
mkdir -p /etc/pgtls
args=(-c "port=$port" -c listen_addresses='*' -c hba_file=/etc/pgtls/hba.conf)
if [[ $cert != none ]]; then
  cp "/fixtures/$cert.crt" /etc/pgtls/server.crt
  cp "/fixtures/$cert.key" /etc/pgtls/server.key
  cp /fixtures/ca-a.crt /etc/pgtls/ca.crt
  args+=(-c ssl=on -c ssl_cert_file=/etc/pgtls/server.crt -c ssl_key_file=/etc/pgtls/server.key)
else
  args+=(-c ssl=off)
fi
case $hba in
  scram) printf 'local all all trust\nhostssl all all all scram-sha-256\nhost all all all reject\n' ;;
  cert)
    args+=(-c ssl_ca_file=/etc/pgtls/ca.crt)
    printf 'local all all trust\nhostssl all all all cert\nhost all all all reject\n' ;;
  plain) printf 'local all all trust\nhost all all all scram-sha-256\n' ;;
esac > /etc/pgtls/hba.conf
chown -R postgres:postgres /etc/pgtls
chmod 600 /etc/pgtls/server.key 2>/dev/null || true
export PGPORT=$port
exec docker-entrypoint.sh postgres "${args[@]}" "$@"
