#!/bin/sh
# Victim-side preparation: default TCP listener, SYN cookies on, RX packet
# steering spread over several CPUs (the race needs != 1 RX context).
set -e

ncpu=$(nproc)
mask=$(printf "%x" $(( (1 << ncpu) - 1 )))
echo "$mask" > /sys/class/net/eth0/queues/rx-0/rps_cpus 2>/dev/null || \
	echo "[victim] note: could not set rps_cpus on eth0"
echo 0 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true

sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true

echo "[victim] kernel      : $(uname -r)"
echo "[victim] syncookies  : $(cat /proc/sys/net/ipv4/tcp_syncookies)"
echo "[victim] max_syn_bl  : $(cat /proc/sys/net/ipv4/tcp_max_syn_backlog)"
echo "[victim] rps_cpus    : $(cat /sys/class/net/eth0/queues/rx-0/rps_cpus 2>/dev/null)"
echo "[victim] nproc       : $(nproc)"

exec nginx -g 'daemon off;'
