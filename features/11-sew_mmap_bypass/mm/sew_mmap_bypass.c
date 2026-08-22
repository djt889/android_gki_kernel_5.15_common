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
	"/top-app", "/foreground", "/system", "/system-background", NULL
};

#if IS_ENABLED(CONFIG_CGROUPS)
static bool sew_task_in_bypass_cpuset(struct task_struct *t)
{
	char path[64];
	int ret;
	int i;

	/* task_cgroup_path() reports the task's primary (cpuset) v1
	 * hierarchy path. It takes cgroup_mutex — acceptable here: this
	 * hook only fires on the allocation slow path under pressure. */
	ret = task_cgroup_path(t, path, sizeof(path));
	if (ret < 0)
		return false;

	for (i = 0; sew_bypass_cpuset[i]; i++)
		if (!strcmp(path, sew_bypass_cpuset[i]))
			return true;
	return false;
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
