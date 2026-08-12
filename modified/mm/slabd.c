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
 *  - hook-side throttle (diff_jiffies < HZ*1) before waking the worker;
 *  - even when the single pending slot is already occupied, *bypass is
 *    still set and the request is dropped (the original ignores the
 *    wakeup_shrink_slabd return value);
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
static struct kshrink_slabd_request kshrink_slabd_request;
static struct task_struct *kshrink_slabd_task;
static bool kshrink_slabd_pending;
static bool kshrink_slabd_enabled;
static bool kshrink_slabd_affinity_done;
static unsigned long kshrink_slabd_queued;
static unsigned long kshrink_slabd_completed;

extern unsigned long shrink_slab(gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg, int priority);

/*
 * Original set_async_slabd_cpus(): walk possible CPUs, pick the policy
 * with the highest cpuinfo.max_freq, then bind the worker to the NODE0
 * cpumask minus that policy's related CPUs. Runs once. Unlike the
 * original, policies are released with cpufreq_cpu_put().
 */
static void kshrink_slabd_set_affinity(void)
{
	struct cpufreq_policy *policy;
	struct cpufreq_policy *policy_max = NULL;
	unsigned int cpufreq_max_tmp = 0;
	cpumask_t allowed;
	int cpu;

	if (READ_ONCE(kshrink_slabd_affinity_done))
		return;

	for_each_possible_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;

		if (policy->cpuinfo.max_freq >= cpufreq_max_tmp) {
			cpufreq_max_tmp = policy->cpuinfo.max_freq;
			if (policy_max)
				cpufreq_cpu_put(policy_max);
			policy_max = policy;
		} else {
			cpufreq_cpu_put(policy);
		}
	}
	if (!policy_max)
		return;

	cpumask_copy(&allowed, cpumask_of_node(NODE_DATA(0)->node_id));
	cpumask_andnot(&allowed, &allowed, policy_max->related_cpus);
	cpufreq_cpu_put(policy_max);

	if (!cpumask_empty(&allowed) &&
	    !set_cpus_allowed_ptr(current, &allowed))
		WRITE_ONCE(kshrink_slabd_affinity_done, true);
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
		bool pending;

		wait_event_freezable(kshrink_slabd_wait,
			kthread_should_stop() || READ_ONCE(kshrink_slabd_pending));
		if (kthread_should_stop())
			break;

		kshrink_slabd_set_affinity();

		spin_lock_irq(&kshrink_slabd_lock);
		pending = kshrink_slabd_pending;
		if (pending) {
			request = kshrink_slabd_request;
			kshrink_slabd_pending = false;
		}
		spin_unlock_irq(&kshrink_slabd_lock);

		if (!pending)
			continue;

		shrink_slab(request.gfp_mask, request.nid, request.memcg,
			    request.priority);
		if (request.memcg_pinned)
			css_put(&request.memcg->css);
		WRITE_ONCE(kshrink_slabd_completed,
			   READ_ONCE(kshrink_slabd_completed) + 1);
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
	if (!kshrink_slabd_pending) {
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
			kshrink_slabd_request.gfp_mask = gfp_mask;
			kshrink_slabd_request.nid = nid;
			kshrink_slabd_request.priority = priority;
			kshrink_slabd_request.memcg = pinned;
			kshrink_slabd_request.memcg_pinned = memcg_pinned;
			kshrink_slabd_pending = true;
			kshrink_slabd_queued++;
			queued = true;
		}
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
 * only queued if at least HZ*1 jiffies passed since the last accepted
 * pass. The worker itself always runs synchronously, and the queue's
 * return value is deliberately ignored (a full slot still bypasses).
 */
static void kshrink_slabd_bypass(void *data, gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg, int priority,
				 bool *bypass)
{
	static unsigned long prev_jiffies;
	unsigned long curr_jiffies, diff_jiffies;

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

	curr_jiffies = jiffies;
	diff_jiffies = curr_jiffies - READ_ONCE(prev_jiffies);
	WRITE_ONCE(prev_jiffies, curr_jiffies);

	if (current == READ_ONCE(kshrink_slabd_task) || (diff_jiffies < HZ * 1)) {
		*bypass = false;
	} else {
		*bypass = true;
		kshrink_slabd_queue(gfp_mask, nid, memcg, priority);
	}
}

static int kshrink_slabd_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "enable = %d\nqueued = %lu\ncompleted = %lu\npending = %u\nthrottle_jiffies = %u\n",
		   READ_ONCE(kshrink_slabd_enabled) ? 1 : 0,
		   READ_ONCE(kshrink_slabd_queued),
		   READ_ONCE(kshrink_slabd_completed),
		   READ_ONCE(kshrink_slabd_pending),
		   HZ * 1);
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
	WRITE_ONCE(kshrink_slabd_enabled, true);
	return 0;
}
module_init(kshrink_slabd_init);
