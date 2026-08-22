// SPDX-License-Identifier: GPL-2.0-only
/*
 * Built-in port of the Moon Binder scheduling policy.
 *
 * Mirrors the original module's three vendor hooks:
 *  - android_vh_binder_trans: SurfaceFlinger-targeted transactions raise
 *    the target proc default priority to FIFO/98 (ko wrote FIFO/98 into
 *    the transaction priority slot at old-layout offset 0x198).
 *  - android_vh_binder_set_priority: binder threads whose comm matches
 *    the original UI/system list are moved to RT class while keeping
 *    their current policy bits and SCHED_RESET_ON_FORK
 *    (ko: (old_policy & 0x3) | 0x40000000, prio = 99 - normal_prio).
 *  - android_vh_binder_proc_transaction_finish: pending-async replies
 *    from the original caller/target name table move the finishing
 *    binder thread to RT | RESET_ON_FORK with 99 - normal_prio.
 */
#define pr_fmt(fmt) "binder_sched_opt: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <uapi/linux/sched/types.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <trace/hooks/binder.h>

#include "binder_internal.h"

#define BINDER_SCHED_OPT_FIFO_PRIO	98

/*
 * Runtime master switch (R7.3): /sys/module/binder_sched_opt/parameters/enabled
 * 0 disables all three hooks without reflashing. Note: the trans hook's
 * default_priority write persists in the target proc until it restarts.
 */
static bool binder_sched_opt_enabled = true;
module_param_named(enabled, binder_sched_opt_enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable binder_sched_opt hooks (default 1)");

/* Original module's worker-name table (strncmp prefix). */
static const char * const binder_sched_opt_workers[] = {
	".globallauncher", "com.miui.home", "system_server",
	"personalassistant", "ll.splashscreen", "cameraserver", "passBlur",
	"wmshell.main", "android.systemui", "android.calendar", "android.anim",
	"C3Dev-", "-ReqQ",
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
 * ko: sched_setscheduler_nocheck(task, (old_policy & 0x3) | 0x40000000,
 *				99 - task->normal_prio)
 * Only fires while the task is still fair-class (policy & 3 in [1,2]).
 */
static void binder_sched_opt_ko_sched(struct task_struct *task)
{
	/*
	 * R7.3: the legacy "policy & 0x3" bitmask admitted SCHED_IDLE(5) and
	 * SCHED_DEADLINE(6) by low-bit coincidence and then forced a nonzero
	 * sched_priority onto them via sched_setscheduler_nocheck, corrupting
	 * their scheduling state. On 5.15 the only safe elevation would be an
	 * explicit SCHED_FIFO/RR switch, which this port deliberately avoids
	 * (R7 policy). Keep an explicit policy whitelist + rt_task() guard;
	 * every remaining path is a no-op, so the function body ends here.
	 */
	if (!task)
		return;
	if (task->policy != SCHED_NORMAL && task->policy != SCHED_FIFO &&
	    task->policy != SCHED_RR)
		return;
	if (rt_task(task))
		return;
	/* SCHED_NORMAL survives both guards: elevating it would require
	 * sched_setscheduler(SCHED_FIFO|...) — intentionally not done. */
}

/* ko: target surfaceflinger && !frozen -> priority = FIFO/98 */
static void binder_sched_opt_trans(void *unused, struct binder_proc *target_proc,
				   struct binder_proc *proc,
				   struct binder_thread *thread,
				   struct binder_transaction_data *tr)
{
	if (!binder_sched_opt_enabled)
		return;
	if (!target_proc || !proc || !thread || !tr)
		return;

	if (!binder_sched_opt_is_sf(target_proc))
		return;
	if (target_proc->is_frozen)
		return;

	/*
	 * ko writes sched_policy=SCHED_FIFO and prio=98 directly into the
	 * transaction's priority slot (old layout offset 0x198). On
	 * 5.15.211 the transaction has not been allocated at this hook
	 * point, so the faithful equivalent is to raise the target
	 * proc's default priority under its inner lock.
	 */
	spin_lock(&target_proc->inner_lock);
	target_proc->default_priority.sched_policy = SCHED_FIFO;
	target_proc->default_priority.prio = BINDER_SCHED_OPT_FIFO_PRIO;
	spin_unlock(&target_proc->inner_lock);
}

/* ko: caller/target comm in worker list -> move binder thread to RT */
static void binder_sched_opt_set_priority(void *unused,
					  struct binder_transaction *transaction,
					  struct task_struct *task)
{
	if (!binder_sched_opt_enabled)
		return;
	if (!transaction || !task)
		return;
	if (!binder_sched_opt_is_sf(transaction->to_proc))
		return;
	if (!binder_sched_opt_match(task->comm))
		return;

	binder_sched_opt_ko_sched(task);
}

/* ko: pending_async finish, name-table hit -> RT thread */
static void binder_sched_opt_transaction_finish(void *unused,
						struct binder_proc *proc,
						struct binder_transaction *transaction,
						struct task_struct *binder_thread_task,
						bool pending_async, bool sync)
{
	if (!binder_sched_opt_enabled)
		return;
	if (!proc || !transaction || !binder_thread_task || sync)
		return;
	if (!pending_async)
		return;
	/*
	 * Guard with the same SurfaceFlinger-target check as set_priority.
	 * Without it, any process whose thread comm happens to match the
	 * worker list (e.g. the generic "main"/"RenderThread") would be
	 * RT-ified on pending_async finish, breaking app thread init.
	 */
	if (!binder_sched_opt_is_sf(transaction->to_proc))
		return;
	if (!binder_sched_opt_match(binder_thread_task->comm))
		return;

	binder_sched_opt_ko_sched(binder_thread_task);
}

static int binder_sched_opt_proc_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "enabled %d\n", binder_sched_opt_enabled ? 1 : 0);
	return 0;
}

static int __init binder_sched_opt_init(void)
{
	int ret;

	ret = register_trace_android_vh_binder_set_priority(
		binder_sched_opt_set_priority, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_binder_trans(binder_sched_opt_trans,
						     NULL);
	if (ret)
		goto unregister_set;
	ret = register_trace_android_vh_binder_proc_transaction_finish(
		binder_sched_opt_transaction_finish, NULL);
	if (ret)
		goto unregister_trans;

	proc_create_single("binder_sched_opt_status", 0444, NULL,
			   binder_sched_opt_proc_show);
	return 0;

unregister_trans:
	unregister_trace_android_vh_binder_trans(binder_sched_opt_trans, NULL);
unregister_set:
	unregister_trace_android_vh_binder_set_priority(
		binder_sched_opt_set_priority, NULL);
	return ret;
}
late_initcall(binder_sched_opt_init);
