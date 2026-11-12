#!/bin/bash
# Single-node YugabyteDB universe bound to one loopback address, with
# client-to-server TLS from the fixture PKI. The role qual_scram must
# authenticate with SCRAM-SHA-256; every other role is trusted over TLS.
# usage: yb-entry.sh <bind-ip> <node-cert-name> <port-offset> [ca-cert-name]
set -euo pipefail
ip=$1 node=$2 off=$3 ca=${4:-ca-a}
mkdir -p /certs
for name in yb "$ip"; do
  cp "/fixtures/$node.crt" "/certs/node.$name.crt"
  cp "/fixtures/$node.key" "/certs/node.$name.key"
done
cp "/fixtures/$ca.crt" /certs/ca.crt
chmod 600 /certs/*.key
bin=/home/yugabyte/bin
placement=(--placement_cloud=qual --placement_region="realm$off" --placement_zone=z1)
"$bin/yb-master" --fs_data_dirs=/mnt/master --master_addresses="$ip:7100" \
  --rpc_bind_addresses="$ip:7100" --webserver_interface="$ip" --webserver_port=$((7000 + off)) \
  --replication_factor=1 "${placement[@]}" &
"$bin/yb-tserver" --fs_data_dirs=/mnt/tserver --tserver_master_addrs="$ip:7100" \
  --rpc_bind_addresses="$ip:9100" --webserver_interface="$ip" --webserver_port=$((9000 + off)) \
  --pgsql_proxy_bind_address="$ip:5433" --pgsql_proxy_webserver_port=$((13000 + off)) \
  --cql_proxy_bind_address="$ip:9042" --cql_proxy_webserver_port=$((12000 + off)) \
  --redis_proxy_webserver_port=$((11000 + off)) --start_redis_proxy=false \
  --use_client_to_server_encryption=true --certs_for_client_dir=/certs \
  --ysql_hba_conf_csv='hostssl all qual_scram all scram-sha-256,hostssl all all all trust,host all all all reject' \
  "${placement[@]}" &
wait -n
exit 1
