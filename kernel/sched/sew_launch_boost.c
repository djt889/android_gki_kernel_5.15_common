// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_launch_boost: give freshly-forked app processes a short uclamp_min
 * floor to speed up cold starts.
 *
 * Mechanism: the sched_process_fork tracepoint fires in kernel_clone(),
 * after copy_process() has fully built the child and BEFORE
 * wake_up_new_task() places it on a runqueue. At that moment the child has
 * never run and cannot be exiting, and the caller is the forking thread
 * itself in preemptible process context (no tasklist lock is held there;
 * the lock is taken and dropped inside copy_process). That context can
 * safely call sched_setattr_nocheck(), whose uclamp path takes
 * cpus_read_lock() and must not run with preemption disabled -- the same
 * constraint binder_sched_opt already satisfies at its own hook.
 *
 * When the parent is the zygote, the child is a brand-new app process:
 * the definition of a cold start. Writing uclamp_min there means the
 * process's very first seconds -- process init, class loading, first
 * frames -- run with a frequency floor, without being pinned anywhere:
 * 384-level floors keep EAS placement free, and unlike an RT promotion
 * the task stays in CFS under the cgroup clamps.
 *
 * Every fork from zygote is boosted, including the early-boot batch;
 * those are cold starts too, and the burst is bounded by the window.
 * zygote forks are also the only parents matched, so kthreads and daemon
 * re-forks are untouched.
 *
 * Bookkeeping uses a bounded hash table keyed by task pointer: overflow
 * drops the boost (losing a boost is harmless), the reference from
 * get_task_struct() keeps the task_struct alive until the restore work
 * has run, so a slot can never hold a dangling pointer and a task_struct
 * can never be reused while a slot references it.
 */
#define pr_fmt(fmt) "sew_launch_boost: " fmt

#include <linux/hash.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/topology.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <uapi/linux/sched.h>
#include <uapi/linux/sched/types.h>

#include <trace/events/sched.h>

/* Master switch, runtime-tunable: /sys/module/sew_launch_boost/parameters */
static bool sew_launch_boost_enabled = true;
module_param_named(enabled, sew_launch_boost_enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable zygote-fork launch boost (default 1)");

/*
 * uclamp_min floor written onto the fresh process, task-level scale
 * 0..1024. 768 is deliberately above the little cluster's capacity
 * (~460 on this SoC) -- a launch is a short burst, and steering it away
 * from the little cores for its first window is the point -- while
 * staying below SCHED_CAPACITY_SCALE so the floor is a floor, not a
 * max-frequency demand. 0 disables the write entirely.
 */
static unsigned int sew_launch_boost_min = 768;
module_param_named(boost_min, sew_launch_boost_min, uint, 0644);
MODULE_PARM_DESC(boost_min, "uclamp_min floor for launched processes, 0..1024 (0 = off)");

/*
 * How long the floor stays, in milliseconds. After the window the
 * pre-boost value is restored and the task goes back to following its
 * cgroup. 2500ms covers process init + first frames of a cold start
 * without spilling into the app's steady state.
 */
static unsigned int sew_launch_boost_window_ms = 2500;
module_param_named(window_ms, sew_launch_boost_window_ms, uint, 0644);
MODULE_PARM_DESC(window_ms, "boost window in ms (default 2500)");

/*
 * Thermal guard: when the CPU the launch runs on is being throttled by the
 * thermal power allocator (cpufreq_cooling publishes the lost capacity
 * through arch_set_thermal_pressure), raising the frequency floor makes the
 * launch slower, not faster -- the clamp just fights the governor for the
 * same power budget. Skip the boost once more than half the CPU capacity is
 * thermally lost. Set thermal_skip=0 to disable the guard.
 */
static bool sew_launch_thermal_skip = true;
module_param_named(thermal_skip, sew_launch_thermal_skip, bool, 0644);
MODULE_PARM_DESC(thermal_skip, "Skip boost under severe thermal pressure (default 1)");

#define SEW_LAUNCH_SLOTS	128
#define SEW_LAUNCH_MAX_RETRIES	5
/*
 * Group-restore bound: uclamp_req is inherited across clone(), so every
 * thread the boosted leader spawns INSIDE the window is born with the 768
 * floor. Restoring only the leader would strand those threads at the floor
 * forever -- the frequency-pinned / battery-drain bug. At window end the
 * whole live thread group is swept back to the saved value; threads spawned
 * after the sweep inherit the already-restored leader, so one straggler
 * re-sweep 750ms later closes the race. Capped: an app spawning more than
 * this many threads inside the window loses the excess threads' restore
 * (they die with the process anyway).
 */
#define SEW_LAUNCH_GROUP_MAX	48

struct sew_launch_slot {
	struct task_struct	*task;
	unsigned int		saved_min;
	bool			saved_user_defined;
	bool			swept;
	int			retries;
	struct delayed_work	work;
};

static struct sew_launch_slot sew_launch_tbl[SEW_LAUNCH_SLOTS];
static DEFINE_SPINLOCK(sew_launch_lock);

static unsigned long sew_launch_hits;
static unsigned long sew_launch_restores;
static unsigned long sew_launch_skipped;	/* uclamp write failed */
static unsigned long sew_launch_rejects;	/* table full */
static unsigned long sew_launch_retries;	/* restore write failed, re-armed */
static unsigned long sew_launch_leaked;		/* retries exhausted, boost kept */
static unsigned long sew_launch_thermal;	/* skipped under thermal pressure */

static inline unsigned int sew_launch_hash(const struct task_struct *task)
{
	return hash_ptr((void *)task, ilog2(SEW_LAUNCH_SLOTS));
}

/* Caller holds sew_launch_lock. */
static struct sew_launch_slot *sew_launch_find(struct task_struct *task,
					       bool for_insert)
{
	unsigned int h = sew_launch_hash(task);
	int i;

	for (i = 0; i < SEW_LAUNCH_SLOTS; i++) {
		struct sew_launch_slot *slot =
			&sew_launch_tbl[(h + i) % SEW_LAUNCH_SLOTS];

		if (slot->task == task)
			return slot;
		if (for_insert && !slot->task)
			return slot;
	}

	return NULL;
}

/*
 * uclamp_min write on @task. Returns false when the current context or
 * the value forbids it. Mirrors binder_sched_opt's write helper: the
 * sched_setattr_nocheck() uclamp path takes cpus_read_lock(), so it must
 * only run where sleeping is allowed.
 */
static bool sew_launch_uclamp_write(struct task_struct *task,
				    unsigned int value, bool user_defined)
{
	struct sched_attr attr = {};

	if (!preemptible())
		return false;

	attr.sched_flags = SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP_MIN;
	attr.sched_util_min = value;
	if (sched_setattr_nocheck(task, &attr))
		return false;

	task->uclamp_req[UCLAMP_MIN].user_defined = user_defined;
	return true;
}

/*
 * Restore every live thread of the boosted process back to the saved value.
 * uclamp_req is inherited across clone(), so threads spawned by the leader
 * INSIDE the boost window are born with the floor; restoring only the
 * leader would strand them at it for their whole lifetime (the
 * frequency-pinned / battery-drain bug). Threads that exited meanwhile are
 * skipped; threads spawned after the sweep inherit the already-restored
 * leader, which is why one straggler re-sweep is enough to close the race.
 * Collect references under RCU (atomic), then write outside the RCU-side
 * -- sched_setattr_nocheck() may sleep, so it must not run under
 * rcu_read_lock().
 */
static void sew_launch_sweep_group(struct task_struct *leader,
				   unsigned int saved_min,
				   bool saved_user_defined)
{
	struct task_struct *group[SEW_LAUNCH_GROUP_MAX];
	struct task_struct *t;
	int n = 0;
	int i;

	rcu_read_lock();
	for_each_thread(leader, t) {
		if (n >= SEW_LAUNCH_GROUP_MAX)
			break;
		if (READ_ONCE(t->flags) & PF_EXITING)
			continue;
		get_task_struct(t);
		group[n++] = t;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		if (sew_launch_uclamp_write(group[i], saved_min,
					    saved_user_defined))
			sew_launch_restores++;
		put_task_struct(group[i]);
	}
}

static void sew_launch_restore(struct work_struct *work)
{
	struct sew_launch_slot *slot =
		container_of(work, struct sew_launch_slot, work.work);
	struct task_struct *task;
	unsigned int saved_min;
	bool saved_user_defined;
	unsigned long flags;

	spin_lock_irqsave(&sew_launch_lock, flags);
	task = slot->task;
	saved_min = slot->saved_min;
	saved_user_defined = slot->saved_user_defined;
	spin_unlock_irqrestore(&sew_launch_lock, flags);

	/* Slot already released by a previous successful run. */
	if (!task)
		return;

	/*
	 * The reference keeps the task_struct memory alive, but the process
	 * itself may have exited inside the window. A dead task's uclamp is
	 * irrelevant and __sched_setscheduler() is not meant to be pointed
	 * at one, so release the slot without restoring.
	 */
	if (READ_ONCE(task->flags) & PF_EXITING) {
		spin_lock_irqsave(&sew_launch_lock, flags);
		if (slot->task == task)
			slot->task = NULL;
		spin_unlock_irqrestore(&sew_launch_lock, flags);
		put_task_struct(task);
		return;
	}

	/*
	 * Restore FIRST, release the slot only on success. Clearing the slot
	 * before the write (the original shape of this function) leaked the
	 * boost permanently whenever the write failed: the task kept
	 * user_defined uclamp_min and never followed its cgroup again. On
	 * failure the slot stays claimed and the work re-arms shortly; after
	 * SEW_LAUNCH_MAX_RETRIES the boost is given up as leaked (counted,
	 * visible in /proc) rather than retried forever.
	 */
	if (!sew_launch_uclamp_write(task, saved_min, saved_user_defined)) {
		if (++slot->retries < SEW_LAUNCH_MAX_RETRIES) {
			sew_launch_retries++;
			mod_delayed_work(system_wq, &slot->work, HZ / 2);
		} else {
			sew_launch_leaked++;
			spin_lock_irqsave(&sew_launch_lock, flags);
			if (slot->task == task)
				slot->task = NULL;
			spin_unlock_irqrestore(&sew_launch_lock, flags);
			put_task_struct(task);
		}
		return;
	}

	sew_launch_restores++;

	/*
	 * Sweep the whole thread group, then keep the slot for one straggler
	 * re-sweep 750ms later: threads spawned between the leader's restore
	 * and the sweep are caught by it, and threads spawned after the sweep
	 * inherit the already-restored leader. After the second sweep the
	 * boost lifetime is over and the slot (and reference) is released.
	 */
	sew_launch_sweep_group(task, saved_min, saved_user_defined);

	if (!slot->swept) {
		slot->swept = true;
		mod_delayed_work(system_wq, &slot->work,
				 msecs_to_jiffies(750));
		return;
	}

	spin_lock_irqsave(&sew_launch_lock, flags);
	if (slot->task == task)
		slot->task = NULL;
	spin_unlock_irqrestore(&sew_launch_lock, flags);
	put_task_struct(task);
}

static void sew_launch_boost_fork(void *unused,
				  struct task_struct *parent,
				  struct task_struct *child)
{
	struct sew_launch_slot *slot;
	unsigned int target;
	unsigned long flags;

	if (!sew_launch_boost_enabled)
		return;
	if (!parent || !child)
		return;

	/*
	 * comm is TASK_COMM_LEN and the zygote processes are named exactly
	 * "zygote" (32-bit) and "zygote64" (64-bit). Exact match, not
	 * prefix: a prefix would also catch unrelated "zygoteX" names.
	 */
	if (strcmp(parent->comm, "zygote") && strcmp(parent->comm, "zygote64"))
		return;

	target = READ_ONCE(sew_launch_boost_min);
	if (!target || target > SCHED_CAPACITY_SCALE)
		return;

	if (READ_ONCE(sew_launch_thermal_skip) &&
	    arch_scale_thermal_pressure(smp_processor_id()) >
		    SCHED_CAPACITY_SCALE / 2) {
		sew_launch_thermal++;
		return;
	}

	spin_lock_irqsave(&sew_launch_lock, flags);
	slot = sew_launch_find(child, true);
	if (slot) {
		slot->task = child;
		slot->saved_min = child->uclamp_req[UCLAMP_MIN].value;
		slot->saved_user_defined =
			child->uclamp_req[UCLAMP_MIN].user_defined;
		slot->retries = 0;
		slot->swept = false;
		get_task_struct(child);
	} else {
		sew_launch_rejects++;
	}
	spin_unlock_irqrestore(&sew_launch_lock, flags);

	if (!slot)
		return;

	/*
	 * The child has never run (wake_up_new_task() is after this
	 * tracepoint), so it cannot be exiting and the write is safe. On
	 * the write's failure path the slot must give the reference back.
	 */
	if (!sew_launch_uclamp_write(child, target, true)) {
		spin_lock_irqsave(&sew_launch_lock, flags);
		slot->task = NULL;
		spin_unlock_irqrestore(&sew_launch_lock, flags);
		put_task_struct(child);
		sew_launch_skipped++;
		return;
	}

	sew_launch_hits++;
	mod_delayed_work(system_wq, &slot->work,
			 msecs_to_jiffies(READ_ONCE(sew_launch_boost_window_ms)));
}

static int sew_launch_proc_show(struct seq_file *m, void *v)
{
	int live = 0;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&sew_launch_lock, flags);
	for (i = 0; i < SEW_LAUNCH_SLOTS; i++)
		if (sew_launch_tbl[i].task)
			live++;
	spin_unlock_irqrestore(&sew_launch_lock, flags);

	seq_printf(m, "enabled %d\n", sew_launch_boost_enabled ? 1 : 0);
	seq_printf(m, "boost_min %u\n", READ_ONCE(sew_launch_boost_min));
	seq_printf(m, "window_ms %u\n", READ_ONCE(sew_launch_boost_window_ms));
	seq_printf(m, "boosted %lu\n", sew_launch_hits);
	seq_printf(m, "restored %lu\n", sew_launch_restores);
	seq_printf(m, "live %d\n", live);
	seq_printf(m, "skipped %lu\n", sew_launch_skipped);
	seq_printf(m, "rejected %lu\n", sew_launch_rejects);
	seq_printf(m, "retries %lu\n", sew_launch_retries);
	seq_printf(m, "leaked %lu\n", sew_launch_leaked);
	seq_printf(m, "thermal_skips %lu\n", sew_launch_thermal);
	return 0;
}

static int __init sew_launch_boost_init(void)
{
	int i, ret;

	for (i = 0; i < SEW_LAUNCH_SLOTS; i++)
		INIT_DELAYED_WORK(&sew_launch_tbl[i].work,
				  sew_launch_restore);

	ret = register_trace_sched_process_fork(sew_launch_boost_fork, NULL);
	if (ret) {
		pr_err("sched_process_fork registration failed: %d\n", ret);
		return ret;
	}

	proc_create_single("sew_launch_boost", 0444, NULL,
			   sew_launch_proc_show);
	pr_info("zygote fork launch boost active (min=%u window=%ums)\n",
		sew_launch_boost_min, sew_launch_boost_window_ms);
	return 0;
}
late_initcall(sew_launch_boost_init);
