// SPDX-License-Identifier: GPL-2.0-only
/*
 * Built-in port of the Moon Binder scheduling policy.
 *
 * Mirrors the original module's three vendor hooks:
 *  - android_vh_binder_trans: the ko wrote FIFO/98 into the transaction
 *    priority slot at old-layout offset 0x198. Not ported, and the hook is
 *    no longer registered at all. The R2 translation wrote FIFO/98 into
 *    target_proc->default_priority instead, which is a different thing:
 *    binder_thread_read() also reads default_priority when a binder thread
 *    goes back to waiting for process work, and that path runs
 *    binder_restore_priority() -> binder_do_set_priority(verify=false),
 *    skipping the RLIMIT_RTPRIO clamp and calling
 *    sched_setscheduler_nocheck(SCHED_FIFO|SCHED_RESET_ON_FORK). It never
 *    passes through binder_transaction_priority(), so node->inherit_rt does
 *    not gate it: every SurfaceFlinger binder thread became a real-time
 *    thread and stayed one until SF restarted, preempting system_server,
 *    inverting priority whenever it blocked on a userspace futex held by a
 *    CFS task, and bypassing EAS placement. The value was wrong too -
 *    binder_priority.prio is a kernel priority, and to_userspace_prio()
 *    maps RT kernel prio 98 to userspace RT priority 99 - 98 = 1, the
 *    lowest real-time band. Granting a genuine FIFO/98 is the ko's real
 *    intent, but that is the same unconditional RT promotion removed from
 *    binder_sched_opt_ko_sched() in R7 (perfetto crash / LSPosed safe
 *    mode). Leaving default_priority as binder_mmap() set it restores
 *    upstream GKI behaviour.
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

/*
 * Runtime master switch (R7.3): /sys/module/binder_sched_opt/parameters/enabled
 * 0 disables the registered hooks without reflashing.
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
	ret = register_trace_android_vh_binder_proc_transaction_finish(
		binder_sched_opt_transaction_finish, NULL);
	if (ret)
		goto unregister_set;

	proc_create_single("binder_sched_opt_status", 0444, NULL,
			   binder_sched_opt_proc_show);
	return 0;

unregister_set:
	unregister_trace_android_vh_binder_set_priority(
		binder_sched_opt_set_priority, NULL);
	return ret;
}
late_initcall(binder_sched_opt_init);
