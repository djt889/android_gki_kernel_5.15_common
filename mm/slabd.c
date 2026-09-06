// SPDX-License-Identifier: GPL-2.0
/*
 * Built-in port of the Xiaomi kshrink_slabd module (piano-w-oss branch).
 *
 * Faithful translation of the original module's should_shrink_async()
 * decision path and worker to a built-in (no module_exit) kernel worker:
 *  - android_vh_shrink_slab_bypass hook with a single pending slot;
 *  - caller gate: plain foreground callers (oom_score_adj == 0, incl.
 *    com.miui.home) have their shrink_slab() call bypassed and dropped
 *    synchronously; only kswapd, the worker itself, and callers with a
 *    non-zero oom_score_adj reach the async path;
 *  - hook-side throttle (diff_jiffies < throttle window, tunable in ms)
 *    before waking the worker;
 *  - even when the 4-deep ring is already full, *bypass is still set and
 *    the request is dropped (the original ignored the queue return value);
 *  - the worker runs with PF_MEMALLOC | PF_KSWAPD and is affined to the
 *    NODE0 cpumask minus the related CPUs of the highest-frequency
 *    cpufreq policy (cpuinfo.max_freq), as in set_async_slabd_cpus();
 *  - the worker re-enters shrink_slab() with the same gfp/nid/memcg/
 *    priority passed by the caller.
 *
 * Lifecycle adaptation for built-in (deliberate fixes on top of the
 * original): the pending slot is spinlock-guarded; non-root memcgs are
 * pinned with css_tryget_online() across the queue and released after the
 * worker consumes them (the original leaked this reference); cpufreq
 * policies are released with cpufreq_cpu_put() (the original leaked them);
 * a /proc/kshrink_slabd counter is exported for diagnostics.
 */
#include <linux/cgroup.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/freezer.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/topology.h>
#include <linux/wait.h>

#include <trace/hooks/vmscan.h>

#include "slabd.h"

struct kshrink_slabd_request {
	gfp_t gfp_mask;
	int nid;
	int priority;
	struct mem_cgroup *memcg;
	bool memcg_pinned;
};

static DEFINE_SPINLOCK(kshrink_slabd_lock);
static DECLARE_WAIT_QUEUE_HEAD(kshrink_slabd_wait);
/*
 * R8.1: the original single pending slot became a 4-deep ring. One wake
 * of the worker now drains everything queued since the last pass, which
 * cuts the drop rate under reclaim bursts and raises async throughput.
 * head/tail are free-running counters; tail - head is the occupancy.
 */
#define KSHRINK_SLABD_RING	4
static struct kshrink_slabd_request kshrink_slabd_ring[KSHRINK_SLABD_RING];
static unsigned int kshrink_slabd_head;
static unsigned int kshrink_slabd_tail;
static struct task_struct *kshrink_slabd_task;
static bool kshrink_slabd_enabled;
static bool kshrink_slabd_affinity_done;
static unsigned long kshrink_slabd_queued;
static unsigned long kshrink_slabd_completed;
static unsigned long kshrink_slabd_dropped;
/*
 * Throttle timestamp, seeded with jiffies at init: jiffies starts at
 * INITIAL_JIFFIES on arm64, so a zero seed makes the first difference huge
 * and defers the very first slab shrink of the boot to the worker, exactly
 * when it should still run synchronously.
 */
static unsigned long kshrink_slabd_prev_jiffies;
static unsigned long kshrink_slabd_throttled;

/*
 * Throttle window in milliseconds, default 1000 (= the historical HZ*1
 * behaviour). A request arriving inside the window is not deferred to the
 * worker: the caller shrinks synchronously, so raising the value trades
 * worker wakeups for more direct reclaim, and 0 disables the throttle.
 * Runtime-tunable: /sys/module/slabd/parameters/throttle_ms (built-in
 * module params live under /sys/module/slabd, named after this object).
 */
static unsigned int kshrink_slabd_throttle_ms = 1000;
module_param_named(throttle_ms, kshrink_slabd_throttle_ms, uint, 0644);
MODULE_PARM_DESC(throttle_ms, "async-queue throttle window in ms (0 = off)");

extern unsigned long shrink_slab(gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg, int priority);

/*
 * Optional VIP check registered by the sew_unfairmem module (loaded
 * after boot). NULL means no module is present: nothing is exempted.
 * Safety of the clear-on-exit is NOT a "stale pointer is benign"
 * argument: it comes from the module's exit path clearing the pointer
 * first and then running tracepoint_synchronize_unregister(), which
 * guarantees no probe is still executing by the time module memory
 * goes away.
 */
bool (*sew_slabd_vip_check)(struct task_struct *t);
EXPORT_SYMBOL_GPL(sew_slabd_vip_check);

/*
 * Bind the worker to everything except the lowest-frequency cluster, the
 * same policy kshrink_lruvecd uses. Asynchronous memory reclaim is a
 * sustained load: leaving it on the little cores saturates them and drags
 * down whatever interactive work shares them. The original implementation
 * excluded the highest-frequency cluster instead, which does the opposite.
 * Runs once; policies are released with cpufreq_cpu_put().
 */
static void kshrink_slabd_set_affinity(void)
{
	struct cpufreq_policy *policy;
	struct cpufreq_policy *policy_min = NULL;
	unsigned int cpufreq_min_tmp = 0;
	cpumask_t allowed;
	int cpu;

	if (READ_ONCE(kshrink_slabd_affinity_done))
		return;

	for_each_possible_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;

		if (!cpufreq_min_tmp ||
		    policy->cpuinfo.max_freq < cpufreq_min_tmp) {
			cpufreq_min_tmp = policy->cpuinfo.max_freq;
			if (policy_min)
				cpufreq_cpu_put(policy_min);
			policy_min = policy;
		} else {
			cpufreq_cpu_put(policy);
		}
	}
	if (!policy_min)
		return;

	cpumask_copy(&allowed, cpumask_of_node(NODE_DATA(0)->node_id));
	cpumask_andnot(&allowed, &allowed, policy_min->related_cpus);
	cpufreq_cpu_put(policy_min);

	if (!cpumask_empty(&allowed) &&
	    !set_cpus_allowed_ptr(current, &allowed))
		WRITE_ONCE(kshrink_slabd_affinity_done, true);
}

/*
 * Frequency-aware shrink intensity (OS4 kshrink_slabd idea, conservative
 * port): when the cluster this worker currently runs on sits at a high
 * P-state the system is busy, so slab reclaim keeps the caller-provided
 * priority; when it sits below the policy mid-point, the machine is
 * likely idle and the pass can afford one step of a deeper scan (a
 * smaller priority value makes shrink_slab() scan more). Only applies
 * when the policy exposes at least four valid P-states, and the value
 * never goes below half the default priority so the change stays
 * bounded.
 */
static int kshrink_slabd_tune_priority(int priority)
{
	struct cpufreq_policy *policy;
	unsigned int freq, min_freq, max_freq, steps = 0;
	int i;

	if (priority <= 0 || priority > DEF_PRIORITY)
		return priority;

	policy = cpufreq_cpu_get(smp_processor_id());
	if (!policy)
		return priority;

	/*
	 * Snapshot everything needed, then drop the policy reference.
	 * 5.15 has no policy->table_len: the table ends with the
	 * CPUFREQ_TABLE_END sentinel, so count entries up to it.
	 */
	freq = policy->cur;
	min_freq = policy->cpuinfo.min_freq;
	max_freq = policy->cpuinfo.max_freq;
	if (policy->freq_table) {
		for (i = 0; policy->freq_table[i].frequency != CPUFREQ_TABLE_END; i++) {
			if (policy->freq_table[i].frequency != CPUFREQ_ENTRY_INVALID)
				steps++;
		}
	}
	cpufreq_cpu_put(policy);

	if (steps < 4)
		return priority;

	if (freq > (min_freq + max_freq) / 2)
		return priority;

	return max(priority - 1, DEF_PRIORITY / 2);
}

static bool kshrink_slabd_ring_nonempty(void)
{
	return READ_ONCE(kshrink_slabd_head) != READ_ONCE(kshrink_slabd_tail);
}

static int kshrink_slabd(void *unused)
{
	/*
	 * Same flags as the original worker: tell the memory management
	 * this is a "memory allocator" (PF_MEMALLOC) and that it should
	 * never be caught in the normal page-freeing logic (PF_KSWAPD).
	 */
	current->flags |= PF_MEMALLOC | PF_KSWAPD;
	set_freezable();

	while (!kthread_should_stop()) {
		struct kshrink_slabd_request request;

		wait_event_freezable(kshrink_slabd_wait,
			kthread_should_stop() || kshrink_slabd_ring_nonempty());
		if (kthread_should_stop())
			break;

		kshrink_slabd_set_affinity();

		/* Drain the whole ring in one wake: batched processing. */
		while (kshrink_slabd_ring_nonempty()) {
			spin_lock_irq(&kshrink_slabd_lock);
			request = kshrink_slabd_ring[kshrink_slabd_head %
						      KSHRINK_SLABD_RING];
			kshrink_slabd_head++;
			spin_unlock_irq(&kshrink_slabd_lock);

			request.priority = kshrink_slabd_tune_priority(request.priority);
			shrink_slab(request.gfp_mask, request.nid, request.memcg,
				    request.priority);
			if (request.memcg_pinned)
				css_put(&request.memcg->css);
			WRITE_ONCE(kshrink_slabd_completed,
				   READ_ONCE(kshrink_slabd_completed) + 1);
		}
	}
	current->flags &= ~(PF_MEMALLOC | PF_KSWAPD);

	return 0;
}

bool kshrink_slabd_queue(gfp_t gfp_mask, int nid,
				struct mem_cgroup *memcg, int priority)
{
	unsigned long flags;
	bool queued = false;

	if (!READ_ONCE(kshrink_slabd_task))
		return false;

	spin_lock_irqsave(&kshrink_slabd_lock, flags);
	if (kshrink_slabd_tail - kshrink_slabd_head < KSHRINK_SLABD_RING) {
		struct kshrink_slabd_request *slot;
		struct mem_cgroup *pinned = memcg;
		bool memcg_pinned = false;

		/* ko did not pin; built-in must keep the memcg alive. */
		if (pinned && !mem_cgroup_is_root(pinned)) {
			if (!css_tryget_online(&pinned->css))
				pinned = NULL;
			else
				memcg_pinned = true;
		}

		if (pinned || !memcg) {
			slot = &kshrink_slabd_ring[kshrink_slabd_tail %
						   KSHRINK_SLABD_RING];
			slot->gfp_mask = gfp_mask;
			slot->nid = nid;
			slot->priority = priority;
			slot->memcg = pinned;
			slot->memcg_pinned = memcg_pinned;
			kshrink_slabd_tail++;
			kshrink_slabd_queued++;
			queued = true;
		}
	} else {
		kshrink_slabd_dropped++;
	}
	spin_unlock_irqrestore(&kshrink_slabd_lock, flags);

	if (queued)
		wake_up_interruptible(&kshrink_slabd_wait);
	return queued;
}

/*
 * Original should_shrink_async(): first the caller gate - plain foreground
 * callers (oom_score_adj == 0, incl. com.miui.home) are bypassed and
 * dropped synchronously; kswapd, the worker itself (both PF_KSWAPD) and
 * non-zero-oom_score_adj callers proceed. Then, once enabled, a request is
 * only queued if at least throttle_ms milliseconds (default 1000, the
 * historical HZ*1) passed since the last accepted pass; inside the window
 * non-kswapd callers are dropped (R8.1), never pushed onto sync reclaim.
 * The worker and kswapd always run synchronously, and the queue's return
 * value is deliberately ignored (a full ring still bypasses).
 */
static void kshrink_slabd_bypass(void *data, gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg, int priority,
				 bool *bypass)
{
	unsigned long prev, curr, window;
	bool (*vip_check)(struct task_struct *t);

	/*
	 * sew_unfairmem VIP tasks (sf_pid / scene_tid): skip slab reclaim
	 * entirely, synchronously, without queueing the async worker. This
	 * is the single-consumer merge that avoids double registration.
	 * Single READ_ONCE load: avoids the NULL-then-call race window of
	 * a plain double read.
	 */
	vip_check = READ_ONCE(sew_slabd_vip_check);
	if (vip_check && vip_check(current)) {
		*bypass = true;
		return;
	}

	if (!current_is_kswapd() &&
	    current != READ_ONCE(kshrink_slabd_task) &&
	    (current->group_leader->signal->oom_score_adj == 0 ||
	     !strcmp(current->group_leader->comm, "com.miui.home"))) {
		*bypass = true;
		return;
	}

	if (!READ_ONCE(kshrink_slabd_enabled)) {
		*bypass = false;
		return;
	}

	/* The worker itself always shrinks synchronously. */
	if (current == READ_ONCE(kshrink_slabd_task)) {
		*bypass = false;
		return;
	}

	/*
	 * R8.1: kswapd is never throttled. Under real memory pressure it
	 * must keep reclaiming at full native rate; deferring or dropping
	 * its shrink_slab() call would stall the one thread whose job is
	 * to relieve that pressure.
	 */
	if (current_is_kswapd()) {
		*bypass = false;
		return;
	}

	/*
	 * Claim the throttle window atomically. Publishing the timestamp
	 * before deciding (the previous behaviour) let a second CPU read the
	 * just-written value, compute a near-zero difference and shrink
	 * synchronously, so concurrent callers defeated the throttle instead
	 * of being deferred by it. With cmpxchg only the CPU that wins the
	 * window defers work to the shrinker.
	 *
	 * R8.1: the losers are now DROPPED (*bypass = true), not pushed onto
	 * a synchronous shrink. Sync reclaim on the allocation path is the
	 * stall this whole feature exists to remove; a dropped pass costs at
	 * most one shrink_slab() round, which kswapd (exempt above) and the
	 * next accepted window both cover.
	 */
	window = msecs_to_jiffies(READ_ONCE(kshrink_slabd_throttle_ms));
	curr = jiffies;
	prev = READ_ONCE(kshrink_slabd_prev_jiffies);
	if (curr - prev < window) {
		kshrink_slabd_throttled++;
		*bypass = true;
		return;
	}
	if (cmpxchg(&kshrink_slabd_prev_jiffies, prev, curr) != prev) {
		*bypass = true;
		return;
	}

	*bypass = true;
	kshrink_slabd_queue(gfp_mask, nid, memcg, priority);
}

static int kshrink_slabd_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "enable = %d\nqueued = %lu\ncompleted = %lu\npending = %u\ndropped = %lu\nthrottle_ms = %u\nthrottled = %lu\n",
		   READ_ONCE(kshrink_slabd_enabled) ? 1 : 0,
		   READ_ONCE(kshrink_slabd_queued),
		   READ_ONCE(kshrink_slabd_completed),
		   READ_ONCE(kshrink_slabd_tail) - READ_ONCE(kshrink_slabd_head),
		   kshrink_slabd_dropped,
		   READ_ONCE(kshrink_slabd_throttle_ms),
		   kshrink_slabd_throttled);
	return 0;
}

static int __init kshrink_slabd_init(void)
{
	int ret;

	kshrink_slabd_task = kthread_run(kshrink_slabd, NULL,
					 "kshrink_slabd");
	if (IS_ERR(kshrink_slabd_task))
		return PTR_ERR(kshrink_slabd_task);

	ret = register_trace_android_vh_shrink_slab_bypass(
		kshrink_slabd_bypass, NULL);
	if (ret) {
		kthread_stop(kshrink_slabd_task);
		kshrink_slabd_task = NULL;
		return ret;
	}

	proc_create_single("kshrink_slabd", 0444, NULL,
			   kshrink_slabd_proc_show);
	WRITE_ONCE(kshrink_slabd_prev_jiffies, jiffies);
	WRITE_ONCE(kshrink_slabd_enabled, true);
	return 0;
}
module_init(kshrink_slabd_init);
