// SPDX-License-Identifier: GPL-2.0-only
/* Asynchronous reclaim for pages skipped because rmap locking contended. */
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/kshrink_lruvecd.h>
#include <linux/mm.h>
#include <linux/page_ext.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/tracepoint.h>
#include <trace/hooks/mm.h>
#include <trace/hooks/vmscan.h>

#define SHRINK_LRUVECD_HIGH	4096

enum kshrink_page_ext_flags {
	KSHRINK_SKIP_TRYLOCK,
	KSHRINK_TRYLOCK_DELAY,
};

struct kshrink_page_ext {
	unsigned long flags;
};

static bool kshrink_page_ext_need(void)
{
	return true;
}

struct page_ext_operations kshrink_page_ext_ops = {
	.size = sizeof(struct kshrink_page_ext),
	.need = kshrink_page_ext_need,
};

static LIST_HEAD(lru_inactive);
static DEFINE_SPINLOCK(l_inactive_lock);
static DECLARE_WAIT_QUEUE_HEAD(shrink_lruvec_wait);
static struct task_struct *shrink_lruvec_tsk;
static bool async_shrink_lruvec_setup;
static bool shrink_lruvec_runnable;
static bool shrink_lruvec_affinity_set;
static unsigned long shrink_lruvec_pages;
static unsigned long shrink_lruvec_pages_max;
static unsigned long shrink_lruvec_handle_pages;

static struct kshrink_page_ext *kshrink_page_ext_get(struct page *page,
						     struct page_ext **page_ext)
{
	*page_ext = page_ext_get(page);
	if (!*page_ext)
		return NULL;

	return (void *)*page_ext + kshrink_page_ext_ops.offset;
}

static void page_trylock_set(void *unused, struct page *page)
{
	struct page_ext *page_ext;
	struct kshrink_page_ext *ext;

	if (!READ_ONCE(async_shrink_lruvec_setup))
		return;

	ext = kshrink_page_ext_get(page, &page_ext);
	if (!ext)
		return;

	clear_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags);
	if (current == READ_ONCE(shrink_lruvec_tsk))
		clear_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags);
	else
		set_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags);
	page_ext_put(page_ext);
}

static void page_trylock_clear(void *unused, struct page *page)
{
	struct page_ext *page_ext;
	struct kshrink_page_ext *ext;

	ext = kshrink_page_ext_get(page, &page_ext);
	if (!ext)
		return;

	clear_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags);
	clear_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags);
	page_ext_put(page_ext);
}

static void page_trylock_get_result(void *unused, struct page *page,
				    bool *trylock_fail)
{
	struct page_ext *page_ext;
	struct kshrink_page_ext *ext;

	ext = kshrink_page_ext_get(page, &page_ext);
	if (!ext)
		return;

	clear_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags);
	if (READ_ONCE(async_shrink_lruvec_setup) &&
	    current != READ_ONCE(shrink_lruvec_tsk) &&
	    test_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags))
		*trylock_fail = true;
	page_ext_put(page_ext);
}

static void do_page_trylock(void *unused, struct page *page,
			    struct rw_semaphore *sem, bool *got_lock, bool *success)
{
	struct page_ext *page_ext;
	struct kshrink_page_ext *ext;

	*success = false;
	if (!READ_ONCE(async_shrink_lruvec_setup))
		return;

	ext = kshrink_page_ext_get(page, &page_ext);
	if (!ext)
		return;

	if (test_and_clear_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags)) {
		if (sem && down_read_trylock(sem)) {
			if (got_lock)
				*got_lock = true;
			*success = true;
		} else if (sem) {
			set_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags);
		}
	}
	page_ext_put(page_ext);
}

/* This is the original hook's transfer point, before vmscan LRU completion. */
static void handle_failed_page_trylock(void *unused, struct list_head *page_list)
{
	LIST_HEAD(local_list);
	struct page *page, *next;
	unsigned long queued = 0;

	if (!READ_ONCE(async_shrink_lruvec_setup))
		return;

	list_for_each_entry_safe(page, next, page_list, lru) {
		struct page_ext *page_ext;
		struct kshrink_page_ext *ext;
		unsigned long nr_pages = thp_nr_pages(page);
		bool delayed;

		ext = kshrink_page_ext_get(page, &page_ext);
		if (!ext)
			continue;

		delayed = test_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags);
		clear_bit(KSHRINK_SKIP_TRYLOCK, &ext->flags);
		clear_bit(KSHRINK_TRYLOCK_DELAY, &ext->flags);
		page_ext_put(page_ext);

		if (!delayed)
			continue;
		if (queued + nr_pages > SHRINK_LRUVECD_HIGH)
			break;

		list_move_tail(&page->lru, &local_list);
		queued += nr_pages;
	}

	if (!queued)
		return;

	spin_lock_irq(&l_inactive_lock);
	if (shrink_lruvec_pages + queued > SHRINK_LRUVECD_HIGH) {
		list_splice_tail_init(&local_list, page_list);
		spin_unlock_irq(&l_inactive_lock);
		return;
	}
	list_splice_tail_init(&local_list, &lru_inactive);
	shrink_lruvec_pages += queued;
	shrink_lruvec_pages_max = max(shrink_lruvec_pages_max,
				      shrink_lruvec_pages);
	shrink_lruvec_runnable = true;
	spin_unlock_irq(&l_inactive_lock);
	wake_up_interruptible(&shrink_lruvec_wait);
}

static void kshrink_lruvecd_set_affinity(void)
{
	struct cpufreq_policy *policy;
	cpumask_t allowed;
	unsigned int cpu;
	unsigned int target_cpu = nr_cpu_ids;
	unsigned int target_max = 0;

	for_each_online_cpu(cpu) {
		unsigned int max = cpufreq_quick_get_max(cpu);

		if (max && (!target_max || max < target_max)) {
			target_cpu = cpu;
			target_max = max;
		}
	}
	if (target_cpu == nr_cpu_ids)
		return;

	policy = cpufreq_cpu_get(target_cpu);
	if (!policy)
		return;
	cpumask_andnot(&allowed, cpu_online_mask, policy->related_cpus);
	cpufreq_cpu_put(policy);

	if (cpumask_empty(&allowed))
		return;

	if (!set_cpus_allowed_ptr(current, &allowed))
		shrink_lruvec_affinity_set = true;
}

static int shrink_lruvecd(void *unused)
{
	set_freezable();

	while (!kthread_should_stop()) {
		LIST_HEAD(local_list);
		struct page *page;
		unsigned long nr_pages = 0;

		wait_event_freezable(shrink_lruvec_wait,
			READ_ONCE(shrink_lruvec_runnable) || kthread_should_stop());
		if (kthread_should_stop())
			break;

		spin_lock_irq(&l_inactive_lock);
		list_splice_init(&lru_inactive, &local_list);
		shrink_lruvec_runnable = false;
		spin_unlock_irq(&l_inactive_lock);

		if (list_empty(&local_list))
			continue;

		if (!shrink_lruvec_affinity_set)
			kshrink_lruvecd_set_affinity();
		list_for_each_entry(page, &local_list, lru)
			nr_pages += thp_nr_pages(page);

		spin_lock_irq(&l_inactive_lock);
		shrink_lruvec_handle_pages += nr_pages;
		spin_unlock_irq(&l_inactive_lock);
		reclaim_pages(&local_list);

		spin_lock_irq(&l_inactive_lock);
		shrink_lruvec_pages -= nr_pages;
		spin_unlock_irq(&l_inactive_lock);
	}

	return 0;
}

static int kshrink_lruvecd_status_show(struct seq_file *m, void *unused)
{
	unsigned long pages;
	unsigned long pages_max;
	unsigned long handled;

	spin_lock_irq(&l_inactive_lock);
	pages = shrink_lruvec_pages;
	pages_max = shrink_lruvec_pages_max;
	handled = shrink_lruvec_handle_pages;
	spin_unlock_irq(&l_inactive_lock);

	seq_printf(m, "kshrink_lruvecd_setup: %s\n"
		   "shrink_lruvec_pages: %lu\n"
		   "shrink_lruvec_handle_pages: %lu\n"
		   "shrink_lruvec_pages_max: %lu\n",
		   READ_ONCE(async_shrink_lruvec_setup) ? "enable" : "disable",
		   pages, handled, pages_max);
	return 0;
}

static int __init kshrink_lruvecd_init(void)
{
	int ret;

	shrink_lruvec_tsk = kthread_run(shrink_lruvecd, NULL, "kshrink_lruvecd");
	if (IS_ERR(shrink_lruvec_tsk))
		return PTR_ERR(shrink_lruvec_tsk);

	ret = register_trace_android_vh_handle_failed_page_trylock(
		handle_failed_page_trylock, NULL);
	if (ret)
		goto stop_thread;
	ret = register_trace_android_vh_page_trylock_set(page_trylock_set, NULL);
	if (ret)
		goto unregister_failed_page_trylock;
	ret = register_trace_android_vh_page_trylock_clear(page_trylock_clear, NULL);
	if (ret)
		goto unregister_page_trylock_set;
	ret = register_trace_android_vh_page_trylock_get_result(
		page_trylock_get_result, NULL);
	if (ret)
		goto unregister_page_trylock_clear;
	ret = register_trace_android_vh_do_page_trylock(do_page_trylock, NULL);
	if (ret)
		goto unregister_page_trylock_get_result;

	if (!proc_create_single("kshrink_lruvecd", 0444, NULL,
				kshrink_lruvecd_status_show)) {
		ret = -ENOMEM;
		goto unregister_do_page_trylock;
	}

	WRITE_ONCE(async_shrink_lruvec_setup, true);
	return 0;

unregister_do_page_trylock:
	unregister_trace_android_vh_do_page_trylock(do_page_trylock, NULL);
unregister_page_trylock_get_result:
	unregister_trace_android_vh_page_trylock_get_result(page_trylock_get_result,
						       NULL);
unregister_page_trylock_clear:
	unregister_trace_android_vh_page_trylock_clear(page_trylock_clear, NULL);
unregister_page_trylock_set:
	unregister_trace_android_vh_page_trylock_set(page_trylock_set, NULL);
unregister_failed_page_trylock:
	unregister_trace_android_vh_handle_failed_page_trylock(
		handle_failed_page_trylock, NULL);
	tracepoint_synchronize_unregister();
stop_thread:
	kthread_stop(shrink_lruvec_tsk);
	return ret;
}
module_init(kshrink_lruvecd_init);
