// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_oem_cgroup: freeze-cgroup migration gatekeeper for the millet
 * frozen control subsystem, ported from millet_oem_cgroup.ko (dada
 * OS4).
 *
 * Binary behavior (disasm .text, 0xc8 can_attach trampoline + 0x04
 * millet_can_attach + init_module):
 * - millet_can_attach(tset): iterate cgroup_taskset_first/next; skip
 *   tasks in the same thread-group as current (condition 1); skip
 *   tasks whose uid (current-cred-derived +24 path, compared against
 *   1000) is a system uid (condition 2); skip when
 *   capable(CAP_SYS_NICE=21) (condition 3); else print
 *   "millet-oem_cgroup: Permission problem" and return 1 (deny the
 *   whole migration). Returns 0 when every task passes.
 * - init_module: printk "enter oem_cgrp_init func!", save the
 *   freezer subsys' can_attach/cancel_attach pair into the module's
 *   hook record, install millet_can_attach + the cancel trampoline
 *   into freezer_cgrp_subsys. exit restores the saved pair.
 * - No millet_core dependency (official UND: capable,
 *   cgroup_taskset_first/next, freezer_cgrp_subsys only).
 *
 * 5.15 hardening vs the binary: the slot address is derived with
 * offsetof(struct cgroup_subsys, can_attach) (cgroup-defs.h:637-638)
 * instead of the 6.6 +48 hard code, and the previous callbacks are
 * chained (called first) rather than overwritten, so a co-resident
 * MIUI gatekeeper keeps working (X7).
 */

#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uidgid.h>

#define SEW_MILLET_OEM_SYSTEM_UID_MAX	1000

/*
 * Saved freezer-subsys callbacks, chained on entry and restored on
 * exit (X7: never overwrite a co-resident gatekeeper).
 *
 * F1-D1R7: install/uninstall are serialized by sew_millet_oem_gate_lock so
 * concurrent insmod/rmmod (or a second writer) cannot interleave the
 * save/install/restore sequence and lose a co-resident gatekeeper's
 * pointers. can_attach itself takes NO lock (it runs on the cgroup
 * migration path; the saved pointer is loaded once with READ_ONCE and
 * a NULL/stable value is all it needs).
 */
static int (*sew_millet_saved_can_attach)(struct cgroup_taskset *tset);
static void (*sew_millet_saved_cancel_attach)(struct cgroup_taskset *tset);
static DEFINE_MUTEX(sew_millet_oem_gate_lock);
static bool sew_millet_oem_installed;

/*
 * can_attach gate: deny (return -EPERM) the migration when any task in
 * the set is (a) outside current's thread-group, (b) above the
 * system-uid floor, and (c) the mover lacks CAP_SYS_NICE. A prior
 * gatekeeper's verdict runs first and sticks.
 *
 * F1-D1R7: returns -EPERM (standard errno) instead of the binary's bare
 * 1: cgroup core treats any non-zero as deny, but errno form keeps
 * dmesg/audit attribution correct on 5.15.
 */
int millet_can_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *task;
	struct task_struct *self = current;
	kuid_t self_uid;
	int (*saved)(struct cgroup_taskset *tset);
	int ret;

	/* Single stable snapshot; the installer side changes this only
	 * under sew_millet_oem_gate_lock at insmod/rmmod. */
	saved = READ_ONCE(sew_millet_saved_can_attach);
	if (saved) {
		ret = saved(tset);
		if (ret)
			return ret;
	}

	self_uid = task_uid(self);

	task = cgroup_taskset_first(tset, &css);
	while (task) {
		/* Condition 1: same thread-group as the mover passes. */
		if (same_thread_group(task, self))
			goto next;
		/* Condition 2: system uids (<=1000) always pass. */
		if (from_kuid(&init_user_ns, task_uid(task)) <=
		    SEW_MILLET_OEM_SYSTEM_UID_MAX)
			goto next;
		/* Condition 3: privileged mover passes. */
		if (capable(CAP_SYS_NICE))
			goto next;

		pr_info("millet-millet-oem_cgroup: Permission problem\n");
		(void)self_uid;
		return -EPERM;
next:
		task = cgroup_taskset_next(tset, &css);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(millet_can_attach);

static void sew_millet_cancel_attach(struct cgroup_taskset *tset)
{
	void (*saved)(struct cgroup_taskset *tset);

	saved = READ_ONCE(sew_millet_saved_cancel_attach);
	if (saved)
		saved(tset);
}

int __init sew_millet_oem_cgroup_init(void)
{
	pr_info("millet-millet-oem_cgroup: enter oem_cgrp_init func!\n");

	/*
	 * Slot access via the struct, never a hard offset: the binary's
	 * +48 constant is a 6.6 layout artifact (B4存疑4). Compile-time
	 * assertion documents the historical value without depending on
	 * it.
	 */
	BUILD_BUG_ON(offsetof(struct cgroup_subsys, can_attach) !=
		     offsetof(struct cgroup_subsys, cancel_attach) -
		     sizeof(void *));

	mutex_lock(&sew_millet_oem_gate_lock);
	sew_millet_saved_can_attach = freezer_cgrp_subsys.can_attach;
	sew_millet_saved_cancel_attach = freezer_cgrp_subsys.cancel_attach;
	freezer_cgrp_subsys.can_attach = millet_can_attach;
	freezer_cgrp_subsys.cancel_attach = sew_millet_cancel_attach;
	sew_millet_oem_installed = true;
	mutex_unlock(&sew_millet_oem_gate_lock);
	return 0;
}

void __exit sew_millet_oem_cgroup_exit(void)
{
	mutex_lock(&sew_millet_oem_gate_lock);
	if (sew_millet_oem_installed) {
		/* F1-D1R7: restore only if our hooks are still installed.
		 * If someone overwrote the slots after us (a co-resident
		 * gatekeeper loaded later without chaining), blindly
		 * restoring would amputate THEIR gate; warn and leave the
		 * current values in place instead. */
		if (freezer_cgrp_subsys.can_attach == millet_can_attach)
			freezer_cgrp_subsys.can_attach =
				sew_millet_saved_can_attach;
		else
			pr_warn("millet-millet-oem_cgroup: can_attach overwritten, skip restore\n");
		if (freezer_cgrp_subsys.cancel_attach == sew_millet_cancel_attach)
			freezer_cgrp_subsys.cancel_attach =
				sew_millet_saved_cancel_attach;
		else
			pr_warn("millet-millet-oem_cgroup: cancel_attach overwritten, skip restore\n");
		sew_millet_saved_can_attach = NULL;
		sew_millet_saved_cancel_attach = NULL;
		sew_millet_oem_installed = false;
	}
	mutex_unlock(&sew_millet_oem_gate_lock);
}

