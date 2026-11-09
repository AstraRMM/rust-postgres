#!/bin/bash
# Single-node plaintext YugabyteDB universe bound to one loopback address,
# for pool semantics tests (verify-full is covered against PostgreSQL and by
# tls-qualification).
# usage: yb-plain-entry.sh <bind-ip> <ysql-port>
set -euo pipefail
ip=$1 port=$2
bin=/home/yugabyte/bin
"$bin/yb-master" --fs_data_dirs=/mnt/master --master_addresses="$ip:7100" \
  --rpc_bind_addresses="$ip:7100" --webserver_interface="$ip" --webserver_port=7010 \
  --replication_factor=1 &
"$bin/yb-tserver" --fs_data_dirs=/mnt/tserver --tserver_master_addrs="$ip:7100" \
  --rpc_bind_addresses="$ip:9100" --webserver_interface="$ip" --webserver_port=9010 \
  --pgsql_proxy_bind_address="$ip:$port" --pgsql_proxy_webserver_port=13010 \
  --cql_proxy_bind_address="$ip:9042" --cql_proxy_webserver_port=12010 \
  --redis_proxy_webserver_port=11010 --start_redis_proxy=false \
  --ysql_hba_conf_csv='host all all all trust' &
wait -n
exit 1
