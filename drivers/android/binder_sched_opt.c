// SPDX-License-Identifier: GPL-2.0-only
/*
 * Built-in port of the Moon Binder scheduling policy.
 *
 * The original module used three vendor hooks. R7.6 uses transaction_received
 * for the boost and restore_priority for the matching restore; the dangerous
 * trans hook is intentionally not registered:
 *  - android_vh_binder_trans: the ko wrote FIFO/98 into
 *    binder_proc.default_priority at offset 0x198. R7.5 deliberately leaves
 *    this hook unregistered: that default is consumed by binder_thread_read()
 *    on the process-work path and can turn every SurfaceFlinger binder thread
 *    into a permanent RT thread. R7.6 does not restore it; it boosts only the
 *    specific thread that has actually received a composition transaction.
 *  - transaction_received (replacement for android_vh_binder_set_priority): the ko
 *    moved matching binder threads to the RT class ((old_policy & 0x3) | SCHED_RESET_ON_FORK, prio
 *    99 - normal_prio). R7.6 raises uclamp_min instead. The RT switch was
 *    both unsafe and, as it turned out, inert: the "policy & 0x3" gate
 *    rejected SCHED_NORMAL (0 & 3 = 0 fails the "< 1" test) and every RT
 *    policy was rejected by rt_task(), so the only policy it ever admitted
 *    was SCHED_IDLE(5) -- i.e. it promoted exactly the threads userspace had
 *    deliberately deprioritised, and never touched the CFS threads in its own
 *    name table. Boosting uclamp_min keeps the thread in CFS, so EAS
 *    placement and the cgroup clamps still apply and a thread blocking on a
 *    userspace futex cannot invert priority.
 *  - restore_priority (replacement for android_vh_binder_proc_transaction_finish):
 *    restores the floor. The ko
 *    used this hook to apply another RT promotion; here it is the other half
 *    of a matched pair, and it deliberately runs for every thread rather than
 *    re-checking target/name, because a boost that is never restored would
 *    persist for the lifetime of the thread.
 */
#define pr_fmt(fmt) "binder_sched_opt: " fmt

#include <linux/hash.h>
#include <linux/init.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/minmax.h>
#include <linux/sched.h>
#include <linux/sched/prio.h>
#include <linux/spinlock.h>
#include <uapi/linux/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <trace/hooks/binder.h>

#include "binder_internal.h"

/*
 * Runtime master switch (R7.3): /sys/module/binder_sched_opt/parameters/enabled
 * 0 disables the registered hooks without reflashing.
 */
static bool binder_sched_opt_enabled = true;
module_param_named(enabled, binder_sched_opt_enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable binder_sched_opt hooks (default 1)");

/*
 * uclamp_min floor applied to a matched binder thread for the duration of a
 * transaction targeting SurfaceFlinger. 0 disables the boost entirely.
 *
 * Units are the task-level scale (0..SCHED_CAPACITY_SCALE, i.e. 0..1024).
 * Note this is NOT the same unit as the cgroup files under /dev/cpuctl, which
 * take a percentage. Values above the little cluster's capacity (~460 on
 * this SoC) also act as a cluster gate: util_fits_cpu() refuses to place the
 * thread on a little core while the floor is raised. The historical default
 * of 512 exploited that as an implicit "no little cores during binder
 * transactions" rule.
 *
 * R7.8: default lowered to 256 so placement stays fully with EAS (every core,
 * including little, satisfies the floor; only extreme thermal pressure on the
 * little cluster can gate it), while keeping a modest frequency floor for the
 * duration of the transaction. Raise it back per-device at runtime via
 * /sys/module/binder_sched_opt/parameters/uclamp_min.
 */
static unsigned int binder_sched_opt_uclamp_min = 256;
module_param_named(uclamp_min, binder_sched_opt_uclamp_min, uint, 0644);
MODULE_PARM_DESC(uclamp_min,
	"uclamp_min floor for boosted binder threads, 0..1024 (0 = off)");

/*
 * Boost strategy.
 *
 *   0 - no boost at all.
 *   1 - raise uclamp_min for the duration of the transaction (default).
 *   2 - the ko's original behaviour: switch the thread to the RT class.
 *
 * Mode 2 exists so the historical behaviour can be A/B tested, but it is not
 * the default and it is not equivalent to mode 1 plus "more". Going RT means:
 *   - uclamp_min is implicitly forced to
 *     sysctl_sched_uclamp_util_min_rt_default, which is SCHED_CAPACITY_SCALE,
 *     so the CPU is pinned at full frequency whenever the thread runs;
 *   - the thread leaves CFS, so find_energy_efficient_cpu() no longer places
 *     it and the cgroup uclamp caps no longer bound it;
 *   - blocking on a userspace futex held by a CFS task inverts priority,
 *     because userspace futexes have no priority inheritance;
 *   - it counts against the RT bandwidth limit (sysctl_sched_rt_runtime
 *     950000 of period 1000000).
 * Mode 1 takes the part that actually helps -- the frequency floor -- and
 * makes it adjustable, without any of the above.
 */
static unsigned int binder_sched_opt_mode = 1;
module_param_named(mode, binder_sched_opt_mode, uint, 0644);
MODULE_PARM_DESC(mode, "0 = off, 1 = uclamp floor (default), 2 = RT promotion");

/*
 * Threads eligible for the boost, matched by comm prefix.
 *
 * comm is TASK_COMM_LEN = 16 and Android names processes with the LAST 15
 * characters of the package name, so "com.android.systemui" (20 chars) shows
 * up as "ndroid.systemui" and "miui.systemui.plugin" as "systemui.plugin".
 * The ko's own table encoded this exact truncation ("rsonalassistant" for
 * "personalassistant", "ndroid.systemui"), which confirms the rule.
 *
 * The island (灵动岛) and control centre live inside the miui.systemui.plugin
 * process, so matching its comm covers both without guessing thread names.
 * "surfaceflinger" is the SF main thread; "android.anim" is its animation
 * thread, which is where the composition-critical work actually is.
 */
static const char * const binder_sched_opt_workers[] = {
	"surfaceflinger",	/* SF main thread */
	"android.anim",		/* animation engine */
	"com.miui.home",	/* MIUI launcher */
	"ndroid.systemui",	/* com.android.systemui, truncated to 15 chars */
	"systemui.plugin",	/* miui.systemui.plugin: island + control centre */
};

static bool binder_sched_opt_match(const char *comm)
{
	int i;

	if (!comm)
		return false;

	for (i = 0; i < ARRAY_SIZE(binder_sched_opt_workers); i++) {
		if (!strncmp(comm, binder_sched_opt_workers[i],
			     strlen(binder_sched_opt_workers[i])))
			return true;
	}

	return false;
}

static bool binder_sched_opt_is_sf(const struct binder_proc *proc)
{
	return proc && proc->tsk &&
		!strncmp(proc->tsk->comm, "surfaceflinger",
			 strlen("surfaceflinger"));
}

/*
 * Boost bookkeeping.
 *
 * A boosted thread has to be restored when the transaction finishes, so the
 * pre-boost uclamp_min must be remembered somewhere. task_struct is not an
 * option: its ANDROID_KABI_RESERVE slots are the vendor ABI's own expansion
 * space (upstream already consumed reserved1 for user_dumpable at 5.15.211) and
 * adding a field would change the struct layout the KMI declares.
 *
 * A small open-addressed table keyed by task pointer is enough: the number of
 * SurfaceFlinger binder threads concurrently inside a transaction is bounded by
 * the pool size, so 64 slots leave a lot of headroom. On overflow the boost is
 * simply skipped -- losing a boost is harmless, leaking one is not.
 */
#define BINDER_BOOST_SLOTS	64

struct binder_boost_slot {
	struct task_struct	*task;
	unsigned int		saved_min;
	bool			saved_user_defined;
	bool			rt_promoted;
	int			saved_policy;
	int			saved_rt_priority;
};

static struct binder_boost_slot binder_boost_tbl[BINDER_BOOST_SLOTS];
static DEFINE_SPINLOCK(binder_boost_lock);
static unsigned long binder_boost_applied;
static unsigned long binder_boost_restored;
static unsigned long binder_boost_overflow;

static inline unsigned int binder_boost_hash(const struct task_struct *task)
{
	return hash_ptr((void *)task, ilog2(BINDER_BOOST_SLOTS));
}

/* Caller holds binder_boost_lock. Returns NULL when the table is full. */
static struct binder_boost_slot *binder_boost_find(struct task_struct *task,
						   bool for_insert)
{
	unsigned int h = binder_boost_hash(task);
	int i;

	for (i = 0; i < BINDER_BOOST_SLOTS; i++) {
		struct binder_boost_slot *slot =
			&binder_boost_tbl[(h + i) % BINDER_BOOST_SLOTS];

		if (slot->task == task)
			return slot;
		if (for_insert && !slot->task)
			return slot;
	}

	return NULL;
}

/*
 * Mode 2 only. Mirrors the ko: keep the low policy bits, add
 * SCHED_RESET_ON_FORK, priority 99 - normal_prio. Unlike the ko this rejects
 * anything that is not plain SCHED_NORMAL -- the ko's "policy & 0x3" test let
 * SCHED_IDLE through (5 & 3 == 1) and rejected SCHED_NORMAL outright
 * (0 & 3 == 0), so it only ever promoted threads userspace had deliberately
 * deprioritised. R7.6 records the pre-RT policy and priority and restores them
 * at restore_priority, so mode 2 is a bounded A/B test rather than a permanent
 * policy mutation.
 */
static bool binder_sched_opt_promote_rt(struct task_struct *task,
					struct binder_boost_slot *slot)
{
	struct sched_param param;

	if (task->policy != SCHED_NORMAL)
		return false;

	slot->saved_policy = task->policy;
	slot->saved_rt_priority = task->rt_priority;
	param.sched_priority = clamp(99 - task->normal_prio, 1,
				     MAX_RT_PRIO - 1);
	if (sched_setscheduler_nocheck(task, SCHED_FIFO | SCHED_RESET_ON_FORK,
				       &param))
		return false;

	slot->rt_promoted = true;
	return true;
}

/*
 * Write a uclamp_min floor onto @task. Returns false when the caller's context
 * does not permit it.
 *
 * sched_setattr_nocheck() routes through uclamp_validate() ->
 * static_branch_enable() -> cpus_read_lock(), which is
 * percpu_down_read(&cpu_hotplug_lock); its slow path blocks while a CPU hotplug
 * writer is active. So this must not run with preemption disabled.
 *
 * That is cheap to satisfy because the atomic call site is redundant.
 * android_vh_binder_set_priority fires from binder_transaction_priority(),
 * which is reached twice for the same transaction:
 *
 *   binder_proc_transaction()  binder.c:2965  binder_inner_proc_lock() held
 *   binder_thread_read()       binder.c:5033  inner lock already dropped
 *
 * The second runs when the binder thread actually picks the transaction up --
 * precisely when the floor needs to be in effect -- so declining the first
 * loses nothing.
 */
static bool binder_uclamp_write(struct task_struct *task, unsigned int value,
				bool user_defined)
{
	struct sched_attr attr = {};

	if (!preemptible())
		return false;

	attr.sched_flags = SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP_MIN;
	attr.sched_util_min = value;
	if (sched_setattr_nocheck(task, &attr))
		return false;

	/*
	 * Restore the marker explicitly. With user_defined set the thread stays
	 * pinned to the value we wrote instead of following its task group, so
	 * the unboost path has to be able to clear it again.
	 */
	task->uclamp_req[UCLAMP_MIN].user_defined = user_defined;
	return true;
}

static void binder_sched_opt_boost(struct task_struct *task)
{
	unsigned int target = READ_ONCE(binder_sched_opt_uclamp_min);
	unsigned int mode = READ_ONCE(binder_sched_opt_mode);
	struct binder_boost_slot *slot;
	unsigned int saved_min = 0;
	bool saved_user_defined = false;
	unsigned long flags;

	if (!task || !mode)
		return;

	if (mode != 2) {
		if (!target)
			return;
		if (target > SCHED_CAPACITY_SCALE)
			target = SCHED_CAPACITY_SCALE;

		/* Only boost fair-class threads; SCHED_IDLE is a deliberate demotion. */
		if (task->policy != SCHED_NORMAL && task->policy != SCHED_BATCH)
			return;

		saved_min = task->uclamp_req[UCLAMP_MIN].value;
		saved_user_defined = task->uclamp_req[UCLAMP_MIN].user_defined;
		if (saved_min >= target)
			return;
	} else if (task->policy != SCHED_NORMAL) {
		return;
	}

	/* Reserve the restore slot before changing task state. */
	spin_lock_irqsave(&binder_boost_lock, flags);
	slot = binder_boost_find(task, true);
	if (!slot) {
		binder_boost_overflow++;
		spin_unlock_irqrestore(&binder_boost_lock, flags);
		return;
	}
	if (slot->task == task) {
		/* Nested transaction on this thread keeps the first saved state. */
		spin_unlock_irqrestore(&binder_boost_lock, flags);
		return;
	}
	slot->task = task;
	slot->saved_min = saved_min;
	slot->saved_user_defined = saved_user_defined;
	slot->rt_promoted = false;
	slot->saved_policy = task->policy;
	slot->saved_rt_priority = task->rt_priority;
	spin_unlock_irqrestore(&binder_boost_lock, flags);

	if (mode == 2) {
		if (!binder_sched_opt_promote_rt(task, slot))
			goto rollback;
	} else if (!binder_uclamp_write(task, target, true)) {
		goto rollback;
	}

	spin_lock_irqsave(&binder_boost_lock, flags);
	slot = binder_boost_find(task, false);
	if (slot)
		binder_boost_applied++;
	spin_unlock_irqrestore(&binder_boost_lock, flags);
	return;

rollback:
	spin_lock_irqsave(&binder_boost_lock, flags);
	slot = binder_boost_find(task, false);
	if (slot)
		slot->task = NULL;
	spin_unlock_irqrestore(&binder_boost_lock, flags);
}
/*
 * Restores whatever binder_sched_opt_boost() saved. Deliberately not gated on
 * the current mode: if the mode is flipped at runtime while boosts are live,
 * those boosts still have to be undone.
 */
static void binder_sched_opt_unboost(struct task_struct *task)
{
	struct binder_boost_slot *slot;
	unsigned int saved_min;
	bool saved_user_defined;
	bool rt_promoted;
	int saved_policy;
	int saved_rt_priority;
	unsigned long flags;

	if (!task)
		return;

	spin_lock_irqsave(&binder_boost_lock, flags);
	slot = binder_boost_find(task, false);
	if (!slot) {
		spin_unlock_irqrestore(&binder_boost_lock, flags);
		return;
	}
	saved_min = slot->saved_min;
	saved_user_defined = slot->saved_user_defined;
	rt_promoted = slot->rt_promoted;
	saved_policy = slot->saved_policy;
	saved_rt_priority = slot->saved_rt_priority;
	spin_unlock_irqrestore(&binder_boost_lock, flags);

	/*
	 * Keep the slot if the restore could not run, so a later call still
	 * knows this thread owes one. boost_live in /proc therefore also counts
	 * threads waiting to be restored, which is what makes a stuck boost
	 * visible.
	 */
	if (rt_promoted) {
		struct sched_param param = {
			.sched_priority = saved_rt_priority,
		};

		if (sched_setscheduler_nocheck(task, saved_policy, &param))
			return;
	} else if (!binder_uclamp_write(task, saved_min, saved_user_defined)) {
		return;
	}

	spin_lock_irqsave(&binder_boost_lock, flags);
	slot = binder_boost_find(task, false);
	if (slot)
		slot->task = NULL;
	binder_boost_restored++;
	spin_unlock_irqrestore(&binder_boost_lock, flags);
}

/*
 * The binder thread is handed a transaction: raise its floor for the work it
 * is about to do.
 *
 * Runs from android_vh_binder_transaction_received (binder_thread_read, right
 * after copy_to_user), which is preemptible, unlike the set_priority hook this
 * replaced -- that one fires from binder_transaction_priority(), which is
 * called under binder_inner_proc_lock() and guarded by set_priority_called,
 * so the common case (a free thread is available at enqueue time) never
 * reached the preemptible path.
 */
static void binder_sched_opt_transaction_received(void *unused,
						  struct binder_transaction *t,
						  struct binder_proc *proc,
						  struct binder_thread *thread,
						  uint32_t cmd)
{
	struct task_struct *task;

	if (!binder_sched_opt_enabled)
		return;
	if (cmd != BR_TRANSACTION && cmd != BR_TRANSACTION_SEC_CTX)
		return;
	if (!t || !thread)
		return;
	/* t->to_proc is the process that owns this thread. */
	if (!binder_sched_opt_is_sf(t->to_proc))
		return;
	task = thread->task;
	if (!task)
		return;
	if (!binder_sched_opt_match(task->comm))
		return;

	binder_sched_opt_boost(task);
}

/*
 * The thread is done and goes back to waiting for work: drop the floor.
 *
 * Runs from android_vh_binder_restore_priority, the same path the binder core
 * itself uses to put a thread back at its base priority. All three call sites
 * (binder.c:3753 / 3875 / 4752) run after binder_inner_proc_unlock or with no
 * proc lock held. The hook this replaced (proc_transaction_finish) fired under
 * binder_inner_proc_lock() at binder.c:2990, so its restores never ran.
 *
 * Deliberately unconditional: binder_sched_opt_unboost() is a no-op when the
 * thread has no slot, and filtering by target/name here would strand the boost
 * on any thread whose transaction ends through a non-matching path.
 */
static void binder_sched_opt_restore_priority(void *unused,
					      struct binder_transaction *t,
					      struct task_struct *task)
{
	if (!task)
		return;

	binder_sched_opt_unboost(task);
}

static int binder_sched_opt_proc_show(struct seq_file *m, void *unused)
{
	unsigned long applied, restored, overflow;
	unsigned long flags;
	int live = 0;
	int i;

	spin_lock_irqsave(&binder_boost_lock, flags);
	applied = binder_boost_applied;
	restored = binder_boost_restored;
	overflow = binder_boost_overflow;
	for (i = 0; i < BINDER_BOOST_SLOTS; i++)
		if (binder_boost_tbl[i].task)
			live++;
	spin_unlock_irqrestore(&binder_boost_lock, flags);

	seq_printf(m, "enabled %d\n", binder_sched_opt_enabled ? 1 : 0);
	seq_printf(m, "mode %u\n", READ_ONCE(binder_sched_opt_mode));
	seq_printf(m, "uclamp_min %u\n", READ_ONCE(binder_sched_opt_uclamp_min));
	seq_printf(m, "boost_applied %lu\n", applied);
	seq_printf(m, "boost_restored %lu\n", restored);
	seq_printf(m, "boost_live %d\n", live);
	seq_printf(m, "boost_overflow %lu\n", overflow);
	return 0;
}

/*
 * uclamp_validate() enables the sched_uclamp_used static branch on the first
 * SCHED_FLAG_UTIL_CLAMP setattr. Do that here, from late_initcall (process
 * context), rather than leaving it to the first boost.
 *
 * This is not what makes the boost safe -- binder_uclamp_write()'s
 * preemptible() gate is -- but it does mean the first boost does not pay for a
 * jump_label patch, and the branch is live before any transaction is seen.
 *
 * The write targets the init thread with its own current uclamp_min, so it is a
 * no-op as far as scheduling behaviour is concerned.
 */
static void __init binder_sched_opt_prime_uclamp(void)
{
	struct sched_attr attr = {};

	attr.sched_flags = SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP_MIN;
	attr.sched_util_min = current->uclamp_req[UCLAMP_MIN].value;

	if (sched_setattr_nocheck(current, &attr))
		pr_warn("uclamp priming failed; boost will be skipped\n");
	else if (!current->uclamp_req[UCLAMP_MIN].user_defined)
		/* Undo the user_defined marker the priming write just set. */
		current->uclamp_req[UCLAMP_MIN].user_defined = false;
}

static int __init binder_sched_opt_init(void)
{
	int ret;

	binder_sched_opt_prime_uclamp();

	ret = register_trace_android_vh_binder_transaction_received(
		binder_sched_opt_transaction_received, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_binder_restore_priority(
		binder_sched_opt_restore_priority, NULL);
	if (ret)
		goto unregister_set;

	proc_create_single("binder_sched_opt_status", 0444, NULL,
			   binder_sched_opt_proc_show);
	return 0;

unregister_set:
	unregister_trace_android_vh_binder_transaction_received(
		binder_sched_opt_transaction_received, NULL);
	return ret;
}
late_initcall(binder_sched_opt_init);
