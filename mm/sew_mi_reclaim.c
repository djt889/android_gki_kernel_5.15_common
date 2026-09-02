// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_mi_reclaim: reclaim-path observability, conservative port of the
 * Xiaomi OS4 mi_reclaim module idea ("Memory reclaim optimization").
 *
 * This first cut is observe-only: it counts slow-path entries and
 * direct-reclaim outcomes via the two new hooks, and reports the
 * distribution through a proc file. No scan_control field is modified.
 * The OS4 module's tuning decisions (which hook payloads would adjust
 * reclaim behaviour) are deliberately not ported until the numbers from
 * real hardware say which knob is worth moving; see the plan T-009.
 *
 * Hooks: android_vh_alloc_pages_slowpath_start (page_alloc.c slowpath
 * entry), android_vh_direct_reclaim_end (try_to_free_pages result).
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <trace/hooks/vmscan.h>

static atomic64_t sew_slowpath_total;
static atomic64_t sew_slowpath_highorder;
static atomic64_t sew_reclaim_end_calls;
static atomic64_t sew_reclaim_reclaimed_pages;
static atomic64_t sew_reclaim_zero_progress;

static void sew_mr_slowpath(void *data, gfp_t gfp_mask, unsigned int order)
{
	atomic64_inc(&sew_slowpath_total);
	if (order > PAGE_ALLOC_COSTLY_ORDER)
		atomic64_inc(&sew_slowpath_highorder);
}

static void sew_mr_reclaim_end(void *data, unsigned long nr_reclaimed)
{
	atomic64_inc(&sew_reclaim_end_calls);
	atomic64_add(nr_reclaimed, &sew_reclaim_reclaimed_pages);
	if (!nr_reclaimed)
		atomic64_inc(&sew_reclaim_zero_progress);
}

static int sew_mr_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "slowpath_total=%lld\n"
		   "slowpath_highorder=%lld\n"
		   "reclaim_end_calls=%lld\n"
		   "reclaimed_pages=%lld\n"
		   "zero_progress=%lld\n",
		   atomic64_read(&sew_slowpath_total),
		   atomic64_read(&sew_slowpath_highorder),
		   atomic64_read(&sew_reclaim_end_calls),
		   atomic64_read(&sew_reclaim_reclaimed_pages),
		   atomic64_read(&sew_reclaim_zero_progress));
	return 0;
}

static int sew_mr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_mr_proc_show, NULL);
}

static const struct proc_ops sew_mr_proc_ops = {
	.proc_open	= sew_mr_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init sew_mi_reclaim_init(void)
{
	int ret;

	ret = register_trace_android_vh_alloc_pages_slowpath_start(
		sew_mr_slowpath, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_direct_reclaim_end(
		sew_mr_reclaim_end, NULL);
	if (ret) {
		unregister_trace_android_vh_alloc_pages_slowpath_start(
			sew_mr_slowpath, NULL);
		return ret;
	}
	if (!proc_create("sew_mi_reclaim", 0444, NULL, &sew_mr_proc_ops)) {
		unregister_trace_android_vh_alloc_pages_slowpath_start(
			sew_mr_slowpath, NULL);
		unregister_trace_android_vh_direct_reclaim_end(
			sew_mr_reclaim_end, NULL);
		return -ENOMEM;
	}
	return 0;
}

static void __exit sew_mi_reclaim_exit(void)
{
	unregister_trace_android_vh_alloc_pages_slowpath_start(
		sew_mr_slowpath, NULL);
	unregister_trace_android_vh_direct_reclaim_end(
		sew_mr_reclaim_end, NULL);
	tracepoint_synchronize_unregister();
	remove_proc_entry("sew_mi_reclaim", NULL);
}

module_init(sew_mi_reclaim_init);
module_exit(sew_mi_reclaim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew reclaim-path observability (mi_reclaim idea, observe-only first cut)");
