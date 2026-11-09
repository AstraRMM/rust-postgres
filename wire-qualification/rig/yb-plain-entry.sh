#!/bin/bash
# Single-node plaintext YugabyteDB universe bound to one loopback address.
# usage: yb-plain-entry.sh <bind-ip>
set -euo pipefail
ip=$1
bin=/home/yugabyte/bin
"$bin/yb-master" --fs_data_dirs=/mnt/master --master_addresses="$ip:7100" \
  --rpc_bind_addresses="$ip:7100" --webserver_interface="$ip" \
  --replication_factor=1 &
"$bin/yb-tserver" --fs_data_dirs=/mnt/tserver --tserver_master_addrs="$ip:7100" \
  --rpc_bind_addresses="$ip:9100" --webserver_interface="$ip" \
  --pgsql_proxy_bind_address="$ip:5433" --cql_proxy_bind_address="$ip:9042" \
  --start_redis_proxy=false --ysql_hba_conf_csv='host all all all trust' &
wait -n
exit 1
