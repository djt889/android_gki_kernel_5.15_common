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
#include <trace/hooks/vmscan.h>

static bool sew_mmap_bypass_enabled = true;
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

	*bypass = true;
}

static int __init sew_mmap_bypass_init(void)
{
	int ret;

	ret = register_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mmap_throttle_bypass, NULL);
	if (ret)
		return ret;

	pr_info("sew_mmap_bypass: registered (enabled=%d)\n",
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
