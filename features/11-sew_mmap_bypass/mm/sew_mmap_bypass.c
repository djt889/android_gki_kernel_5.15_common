// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_mmap_bypass: bypass direct-reclaim throttling for userspace allocation
 * paths to reduce mmap/page-fault latency under memory pressure.
 *
 * Backported hook (android_vh_throttle_direct_reclaim_bypass). It fires in
 * throttle_direct_reclaim() after kthreads and fatal-signal tasks are already
 * excluded. The only remaining guard we need is PF_MEMALLOC: memory reclaimers
 * must not bypass their own throttling, or kswapd progress could stall.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <trace/hooks/vmscan.h>

static bool sew_mmap_bypass_enabled = true;

/*
 * R7.3: bypass is scoped to interactive cpuset groups (Android /dev/cpuset
 * layout). background/restricted tasks keep the upstream throttle queue so
 * heavy reclaim pressure can no longer put every CPU into an unproductive
 * reclaim storm. Exact-match names; unknown/root groups fall back to
 * throttled (conservative).
 */
static const char * const sew_bypass_cpuset[] = {
	"top-app", "foreground", "system", "system-background", NULL
};

/*
 * R7.3.1: must stay lock-free. The previous version called
 * task_cgroup_path(), which takes cgroup_mutex + css_set_lock; doing that
 * from the direct-reclaim slow path deadlocks against other holders and
 * hung the device during boot. Read the cpuset css name under RCU instead:
 * task_css_check(..., true) is safe without any lock, and kernfs_node::name
 * is stable for the lifetime of the node.
 */
#if IS_ENABLED(CONFIG_CPUSETS)
static bool sew_task_in_bypass_cpuset(struct task_struct *t)
{
	struct cgroup_subsys_state *css;
	struct kernfs_node *kn;
	const char *name;
	bool ret = false;
	int i;

	rcu_read_lock();
	css = task_css_check(t, cpuset_cgrp_id, true);
	if (!css || !css->cgroup)
		goto out;
	kn = css->cgroup->kn;
	if (!kn)
		goto out;
	/* kernfs_node::name is a plain const char * (not __rcu); stable while
	 * the node is alive, and we hold rcu_read_lock across the compare. */
	name = kn->name;
	if (!name)
		goto out;
	for (i = 0; sew_bypass_cpuset[i]; i++) {
		if (!strcmp(name, sew_bypass_cpuset[i])) {
			ret = true;
			break;
		}
	}
out:
	rcu_read_unlock();
	return ret;
}
#else
static bool sew_task_in_bypass_cpuset(struct task_struct *t) { return false; }
#endif
module_param_named(enabled, sew_mmap_bypass_enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable direct-reclaim throttle bypass (default 1)");

static void sew_mmap_throttle_bypass(void *data, bool *bypass)
{
	if (!sew_mmap_bypass_enabled)
		return;

	/* Reclaimers (PF_MEMALLOC) must never bypass: they would recurse into
	 * the allocator instead of making reclaim progress.
	 */
	if (current->flags & PF_MEMALLOC)
		return;

	if (!sew_task_in_bypass_cpuset(current))
		return;

	*bypass = true;
}

static int __init sew_mmap_bypass_init(void)
{
	int ret;

	ret = register_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mmap_throttle_bypass, NULL);
	if (ret)
		return ret;

	pr_info("sew_mmap_bypass: registered (enabled=%d, cpuset-scoped)\n",
		sew_mmap_bypass_enabled ? 1 : 0);
	return 0;
}

static void __exit sew_mmap_bypass_exit(void)
{
	unregister_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mmap_throttle_bypass, NULL);
	pr_info("sew_mmap_bypass: unregistered\n");
}

module_init(sew_mmap_bypass_init);
module_exit(sew_mmap_bypass_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew mmap direct-reclaim throttle bypass");
MODULE_AUTHOR("Sew");
