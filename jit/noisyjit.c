/*
 * noisytcp jitter - LAB INSTRUMENTATION ONLY
 *
 * CVE-2026-99288 needs the lockless ehash lookup to be interrupted between its
 * tuple check and refcount_inc_not_zero() for a few microseconds.  On a KVM
 * guest that happens by accident (vCPU preemption: 5 s - 2 min to hit).  Bare
 * metal never does it because no interrupt lands inside a ~1 ns window and
 * stays there long enough for the free + reallocation to complete.
 *
 * This module emulates exactly that preemption: one pinned hrtimer per CPU,
 * callback runs in hardirq context, burns a few microseconds and re-arms.  It
 * is a test harness for the race, not part of the exploit.
 *
 *   insmod noisyjit.ko period_us=50 burn_us=6
 */
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/stddef.h>
#include <net/sock.h>
#include <linux/smp.h>

static unsigned int period_us = 50;
static unsigned int burn_us = 6;
static int burn_cpu = -1;	/* -1: every CPU, >=0: only that CPU */
module_param(period_us, uint, 0644);
module_param(burn_us, uint, 0644);
module_param(burn_cpu, int, 0644);

static DEFINE_PER_CPU(struct hrtimer, jt);

static enum hrtimer_restart jt_fn(struct hrtimer *t)
{
	udelay(burn_us);
	hrtimer_forward_now(t, us_to_ktime(period_us));
	return HRTIMER_RESTART;
}

static void jt_start(void *info)
{
	struct hrtimer *t = this_cpu_ptr(&jt);

	(void)info;
	/*
	 * Freezing the CPU that frees the request socket and allocates the SYN
	 * cookie request would delay exactly the work we need to land inside the
	 * lookup window, so the jitter can be restricted to the reader's CPU.
	 */
	if (burn_cpu >= 0 && burn_cpu != smp_processor_id())
		return;
	hrtimer_setup(t, jt_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	hrtimer_start(t, us_to_ktime(period_us), HRTIMER_MODE_REL_PINNED);
}

static int __init jt_init(void)
{
	pr_info("noisytcp-jitter: offsets state=%zu nulls_node=%zu pprev=%zu listener=%zu\n",
		offsetof(struct sock_common, skc_state),
		offsetof(struct sock_common, skc_nulls_node),
		offsetof(struct sock_common, skc_nulls_node) +
			offsetof(struct hlist_nulls_node, pprev),
		offsetof(struct sock_common, skc_listener));
	on_each_cpu(jt_start, NULL, 1);
	pr_info("noisytcp-jitter: period %u us, burn %u us, cpu %d\n",
		period_us, burn_us, burn_cpu);
	return 0;
}

static void __exit jt_exit(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct hrtimer *t = per_cpu_ptr(&jt, cpu);

		/*
		 * With burn_cpu >= 0 only one CPU's timer was set up; the others
		 * were never initialised, so cancelling them would dereference a
		 * NULL hrtimer base.
		 */
		if (t->function)
			hrtimer_cancel(t);
	}
	pr_info("noisytcp-jitter: stopped\n");
}

module_init(jt_init);
module_exit(jt_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NoisyTCP lab: preemption emulator for the ABA race window");
