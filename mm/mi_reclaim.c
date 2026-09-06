// SPDX-License-Identifier: GPL-2.0-only
/*
 * mi_reclaim: reclaim-path observability + bounded tuning, port of the
 * Xiaomi OS4 mi_reclaim module ("Memory reclaim optimization module",
 * cang from MI Performance Team).
 *
 * RE evidence: /root/work/os4_dada/ko/mi_reclaim.ko
 *   (modinfo: depends=xr_qi, parm refill_cpus; nm -u: 9 hook tracepoints,
 *   try_to_free_mem_cgroup_pages, is_qos_task/kern_qi_set_qos from xr_qi;
 *   strings: the sysfs command set reproduced below).  Raw dump:
 *   .omz/research/.../raw/ (this session, mi_reclaim recon).
 *
 * What the OS4 module does
 * ------------------------
 * A proactive-reclaim executor driven by userspace: an "important pid"
 * list and an on-demand "event" trigger reclaim against the listed
 * processes' memcgs ("echo <reclaim_mb> > event"), a page pool with a
 * CPU-pinned refill worker (refill_cpus) served through
 * android_vh_alloc_pages_reclaim_bypass, a watermark boost (raise the
 * fast-path mark so reclaim engages earlier under stress),
 * direct-reclaim throttle/shrink-slab bypasses and a scan-type steer
 * (0x1=RECLAIM_FILE, 0x2=RECLAIM_ANON), all QOS-gated through xr_qi's
 * is_qos_task()/kern_qi_set_qos().
 *
 * Sew 5.15 scope of this port ([PORT-DELTA] items marked)
 * -------------------------------------------------------
 * Ported (all tuning channels default OFF; the observe counters of the
 * previous first cut are kept verbatim, /proc/mi_reclaim unchanged so
 * existing addon readers are not broken):
 *   1. important pid list + event node: reclaim from the listed pids'
 *      memcgs via try_to_free_mem_cgroup_pages() (EXPORT_SYMBOL_GPL in
 *      this tree).  may_swap=false implements the dada "FILE flag"
 *      (no anon scan => file-only reclaim).
 *   2. [REMOVED] wmark boost: the original plan raised the per-
 *      allocation MIN-watermark check via android_vh_get_page_wmark
 *      after reclaim stress.  Real-device testing (fuxi freeze: "boots,
 *      UI stalls, watchdog reboots, stable after 3 reboots") killed it:
 *      direct reclaim allocates with ALLOC_WMARK_MIN, so +4096 pages on
 *      the fast-path check stalls every allocation once free sits above
 *      min by < 16MB, and the stress trigger re-arms forever -> reclaim
 *      livelock.  Same direction lesson unfairmem already documents;
 *      the dada module likely targeted a different watermark.
 *   3. throttle bypass (android_vh_throttle_direct_reclaim_bypass):
 *      skip direct-reclaim throttling only while node file pages are
 *      above throttle_file_threshold (plenty of cheap file pages).
 *   4. scan steer (android_vh_tune_scan_type): write the scan_balance
 *      enum (SCAN_FILE=3 / SCAN_ANON=2, mm/vmscan.c) for global
 *      (non-kswapd) reclaim only, FILE steer additionally guarded by
 *      the file-pages threshold.
 *   5. reclaim efficiency stats: slowpath -> direct_reclaim_end wall
 *      time and per-event reclaimed/duration ("real reclaimed %lu time
 *      %lld ms").
 *
 * Not ported (no evidence / too thin RE to reach the confidence bar):
 *   - page pool + refill worker + prefill + android_vh_alloc_pages_
 *     reclaim_bypass (the pool semantics are not recoverable from the
 *     binary strings with confidence; a wrong bypass hands out foreign
 *     pages).  [PORT-DELTA]
 *   - shrink_slab_bypass: the binary only shows the stat name
 *     "kswapd_shrink_slab"; no recoverable bypass condition.  The hook
 *     exists in-tree but stays unregistered here (single-consumer
 *     discipline with mm/slabd.c which already consumes it). [PORT-DELTA]
 *   - free_task purge: replaced by a struct pid* reference model - the
 *     list holds pid references, so pids cannot recycle under us and
 *     dead tasks resolve to NULL in get_pid_task().  [PORT-DELTA]
 *   - is_qos_task/kern_qi_set_qos gating (xr_qi exports): replaced by
 *     explicit sysfs switches; when xr_qi grows the export face the
 *     gate can be wired in.  [PORT-DELTA]
 *   - sysfs command surface is the dada subset {pid,event,info,usage,
 *     reset_stats}; the "pool" node and the info-write keys of skipped
 *     subsystems (refill_max_runtime, wmark_boost_*, boost_background,
 *     prefill) are absent.  dada's exact event encoding is not visible
 *     in the binary ("echo 257 > event  # 100MB + FILE flag" does not
 *     decode unambiguously), so this port defines: "echo <mb> > event"
 *     reclaims <mb> MB with swap allowed, "echo <mb> file > event"
 *     reclaims file-only.  [PORT-DELTA]
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/vmstat.h>
#include <linux/swap.h>
#include <linux/memcontrol.h>
#include <linux/sched/clock.h>
#include <trace/hooks/vmscan.h>
#include <trace/hooks/mm.h>

/* ---- observe counters (first cut, kept verbatim) ---------------------- */
static atomic64_t sew_slowpath_total;
static atomic64_t sew_slowpath_highorder;
static atomic64_t sew_reclaim_end_calls;
static atomic64_t sew_reclaim_reclaimed_pages;
static atomic64_t sew_reclaim_zero_progress;

/* ---- tuning state (all default OFF) ----------------------------------- */
/* scan steer: 0x1=RECLAIM_FILE (SCAN_FILE), 0x2=RECLAIM_ANON (SCAN_ANON) */
#define MIR_FLAG_RECLAIM_FILE	0x1
#define MIR_FLAG_RECLAIM_ANON	0x2
static unsigned int mir_enable_flags;

/* throttle bypass */
static unsigned int mir_skip_throttle_enabled;
static unsigned int mir_throttle_file_threshold; /* node file pages */

/* scan steer guard */
static unsigned int mir_file_scan_enabled;
static unsigned int mir_fg_file_scan_threshold;	/* node file pages */

/* important pid list */
#define MIR_MAX_PIDS	32
static struct pid *mir_pids[MIR_MAX_PIDS];
static int mir_pid_count;
static DEFINE_MUTEX(mir_pid_lock);

/* event worker */
static struct task_struct *mir_worker;
static DECLARE_WAIT_QUEUE_HEAD(mir_waitq);
static atomic_t mir_event_mb = ATOMIC_INIT(0);
static atomic_t mir_event_flags = ATOMIC_INIT(0);

/* tuning stats */
static atomic64_t mir_total_reclaim_pages;
static atomic64_t mir_total_reclaim_ms;
static atomic64_t mir_reclaim_times;
static atomic64_t mir_refill_fail_count;	/* pid with no task/memcg */
static atomic64_t mir_skip_throttle_count;
static DEFINE_PER_CPU(u64, mir_slowpath_t0);

/* scan_balance values: enum scan_balance { SCAN_EQUAL, SCAN_FRACT,
 * SCAN_ANON, SCAN_FILE }; (mm/vmscan.c).  The hook hands us a char*
 * aliasing that enum. */
#define MIR_SCAN_ANON	2
#define MIR_SCAN_FILE	3

/* ---- hooks ------------------------------------------------------------ */

static void mir_slowpath(void *data, gfp_t gfp_mask, unsigned int order)
{
	atomic64_inc(&sew_slowpath_total);
	if (order > PAGE_ALLOC_COSTLY_ORDER)
		atomic64_inc(&sew_slowpath_highorder);
	*this_cpu_ptr(&mir_slowpath_t0) = local_clock();
}

static void mir_reclaim_end(void *data, unsigned long nr_reclaimed)
{
	u64 t0 = *this_cpu_ptr(&mir_slowpath_t0);

	atomic64_inc(&sew_reclaim_end_calls);
	atomic64_add(nr_reclaimed, &sew_reclaim_reclaimed_pages);
	if (!nr_reclaimed)
		atomic64_inc(&sew_reclaim_zero_progress);
	if (t0)
		atomic64_add(div_u64(local_clock() - t0, 1000000),
			     &mir_total_reclaim_ms);
}

static void mir_throttle_bypass(void *data, bool *bypass)
{
	unsigned long file_pages;

	if (!bypass || !mir_skip_throttle_enabled)
		return;

	file_pages = node_page_state(numa_node_id(), NR_FILE_PAGES);
	if (mir_throttle_file_threshold &&
	    file_pages > mir_throttle_file_threshold) {
		*bypass = true;
		atomic64_inc(&mir_skip_throttle_count);
	}
}

static void mir_tune_scan_type(void *data, char *scan_type)
{
	unsigned long file_pages;

	if (!scan_type || !mir_enable_flags || current_is_kswapd())
		return;

	if ((mir_enable_flags & MIR_FLAG_RECLAIM_FILE) &&
	    mir_file_scan_enabled) {
		file_pages = node_page_state(numa_node_id(), NR_FILE_PAGES);
		if (mir_fg_file_scan_threshold &&
		    file_pages > mir_fg_file_scan_threshold) {
			WRITE_ONCE(*(int *)scan_type, MIR_SCAN_FILE);
			return;
		}
	}
	if (mir_enable_flags & MIR_FLAG_RECLAIM_ANON)
		WRITE_ONCE(*(int *)scan_type, MIR_SCAN_ANON);
}

/* ---- event worker ------------------------------------------------------ */

static unsigned long mir_reclaim_one(struct pid *pid, unsigned long pages,
				     bool may_swap)
{
	struct task_struct *task;
	struct mem_cgroup *memcg;
	unsigned long reclaimed;

	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task) {
		atomic64_inc(&mir_refill_fail_count);
		return 0;
	}
	memcg = mem_cgroup_from_task(task);
	reclaimed = 0;
	if (memcg)
		reclaimed = try_to_free_mem_cgroup_pages(memcg, pages,
							 GFP_KERNEL,
							 may_swap);
	put_task_struct(task);
	return reclaimed;
}

static int mir_worker_fn(void *unused)
{
	while (!kthread_should_stop()) {
		int mb, flags;
		unsigned long pages;
		bool may_swap;
		u64 t0;
		int i;

		wait_event_interruptible(mir_waitq,
					 atomic_read(&mir_event_mb) ||
					 kthread_should_stop());
		mb = atomic_xchg(&mir_event_mb, 0);
		if (!mb || kthread_should_stop())
			continue;
		flags = atomic_xchg(&mir_event_flags, 0);
		pages = (unsigned long)mb << (20 - PAGE_SHIFT);
		may_swap = !(flags & MIR_FLAG_RECLAIM_FILE);

		t0 = local_clock();
		mutex_lock(&mir_pid_lock);
		for (i = 0; i < mir_pid_count; i++)
			atomic64_add(mir_reclaim_one(mir_pids[i], pages,
						     may_swap),
				     &mir_total_reclaim_pages);
		mutex_unlock(&mir_pid_lock);
		atomic64_inc(&mir_reclaim_times);
		atomic64_add(div_u64(local_clock() - t0, 1000000),
			     &mir_total_reclaim_ms);
	}
	return 0;
}

/* ---- sysfs -------------------------------------------------------------- */

static void mir_pid_clear_locked(void)
{
	int i;

	for (i = 0; i < mir_pid_count; i++)
		put_pid(mir_pids[i]);
	mir_pid_count = 0;
}

static ssize_t mir_pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	ssize_t off = 0;
	int i;

	mutex_lock(&mir_pid_lock);
	for (i = 0; i < mir_pid_count; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off, "%d\n",
				 pid_nr(mir_pids[i]));
	mutex_unlock(&mir_pid_lock);
	return off;
}

static ssize_t mir_pid_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	char tok[16];
	int val, ret;

	if (sscanf(buf, "%15s", tok) != 1)
		return -EINVAL;
	if (!strcmp(tok, "clear")) {
		mutex_lock(&mir_pid_lock);
		mir_pid_clear_locked();
		mutex_unlock(&mir_pid_lock);
		pr_info("mi_reclaim: important list cleared\n");
		return count;
	}
	ret = kstrtoint(tok, 0, &val);
	if (ret || val <= 0)
		return ret ? ret : -EINVAL;

	mutex_lock(&mir_pid_lock);
	if (mir_pid_count >= MIR_MAX_PIDS) {
		mutex_unlock(&mir_pid_lock);
		return -ENOSPC;
	}
	mir_pids[mir_pid_count] = find_get_pid(val);
	if (!mir_pids[mir_pid_count]) {
		mutex_unlock(&mir_pid_lock);
		return -ESRCH;
	}
	mir_pid_count++;
	mutex_unlock(&mir_pid_lock);
	pr_info("mi_reclaim: added pid %d to important list (count=%d)\n",
		val, mir_pid_count);
	return count;
}

static ssize_t mir_event_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	char tok[24];
	int val, ret, flags = 0;

	if (sscanf(buf, "%23s", tok) != 1)
		return -EINVAL;
	ret = kstrtoint(tok, 0, &val);
	if (ret || val <= 0 || val > 4096)
		return ret ? ret : -EINVAL;
	/* optional second token: "file" requests file-only reclaim */
	if (sscanf(buf, "%*s %23s", tok) == 1 && !strcmp(tok, "file"))
		flags = MIR_FLAG_RECLAIM_FILE;

	atomic_set(&mir_event_flags, flags);
	atomic_set(&mir_event_mb, val);
	wake_up(&mir_waitq);
	return count;
}

static ssize_t mir_info_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	ssize_t off = 0;

	off += scnprintf(buf + off, PAGE_SIZE - off,
		"| [Reclaim Statistics]      |\n"
		"| reclaim_times: %lld\n"
		"| total_reclaim: %lld pages\n"
		"| total_reclaim_time: %lld ms\n"
		"| pid_miss_count: %lld\n"
		"| [Skip Throttle Statistics]|\n"
		"| skip_throttle_enabled: %u\n"
		"| skip_throttle_count: %lld\n"
		"| [Observe Statistics]      |\n"
		"| slowpath_total: %lld\n"
		"| slowpath_highorder: %lld\n"
		"| reclaim_end_calls: %lld\n"
		"| reclaimed_pages: %lld\n"
		"| zero_progress: %lld\n"
		"| [Switches]                |\n"
		"| enable_flags: 0x%x (0x1=RECLAIM_FILE 0x2=RECLAIM_ANON)\n"
		"| file_scan_enabled: %u fg_file_scan_threshold: %u\n"
		"| throttle_file_threshold: %u\n"
		"| important_pids: %d\n",
		atomic64_read(&mir_reclaim_times),
		atomic64_read(&mir_total_reclaim_pages),
		atomic64_read(&mir_total_reclaim_ms),
		atomic64_read(&mir_refill_fail_count),
		mir_skip_throttle_enabled,
		atomic64_read(&mir_skip_throttle_count),
		atomic64_read(&sew_slowpath_total),
		atomic64_read(&sew_slowpath_highorder),
		atomic64_read(&sew_reclaim_end_calls),
		atomic64_read(&sew_reclaim_reclaimed_pages),
		atomic64_read(&sew_reclaim_zero_progress),
		mir_enable_flags,
		mir_file_scan_enabled, mir_fg_file_scan_threshold,
		mir_throttle_file_threshold,
		mir_pid_count);
	return off;
}

/* info writes: the dada tunable keys of the ported subsystems */
static ssize_t mir_info_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	char key[32];
	int val = 0, n;

	n = sscanf(buf, "%31s %d", key, &val);
	if (n < 1)
		return -EINVAL;

	if (!strcmp(key, "enable_flags") && n == 2 && val >= 0 &&
	    val <= 3) {
		mir_enable_flags = val;
	} else if (!strcmp(key, "skip_throttle_enabled") && n == 2) {
		mir_skip_throttle_enabled = !!val;
	} else if (!strcmp(key, "throttle_file_threshold") && n == 2 &&
		   val >= 0) {
		mir_throttle_file_threshold = val;
	} else if (!strcmp(key, "file_scan_enabled") && n == 2) {
		mir_file_scan_enabled = !!val;
	} else if (!strcmp(key, "fg_file_scan_threshold") && n == 2 &&
		   val >= 0) {
		mir_fg_file_scan_threshold = val;
	} else {
		return -EINVAL;
	}
	return count;
}

static ssize_t mir_reset_stats_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	atomic64_set(&mir_total_reclaim_pages, 0);
	atomic64_set(&mir_total_reclaim_ms, 0);
	atomic64_set(&mir_reclaim_times, 0);
	atomic64_set(&mir_refill_fail_count, 0);
	atomic64_set(&mir_skip_throttle_count, 0);
	atomic64_set(&sew_slowpath_total, 0);
	atomic64_set(&sew_slowpath_highorder, 0);
	atomic64_set(&sew_reclaim_end_calls, 0);
	atomic64_set(&sew_reclaim_reclaimed_pages, 0);
	atomic64_set(&sew_reclaim_zero_progress, 0);
	return count;
}

static ssize_t mir_usage_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE,
		"mi_reclaim (Sew 5.15 port of the Xiaomi OS4 module)\n"
		"[pid Node Commands]\n"
		"  echo \"<pid>\" > pid     - Add pid (default)\n"
		"  echo \"clear\" > pid     - Clear all pids\n"
		"[event Node Commands]\n"
		"  echo \"<mb>\" > event          - Reclaim <mb> MB from all\n"
		"                                 important pids (swap ok)\n"
		"  echo \"<mb> file\" > event     - File-only reclaim (no swap)\n"
		"[info Node Commands]\n"
		"  cat info - statistics and switches\n"
		"  echo \"enable_flags <0-3>\" > info\n"
		"  echo \"skip_throttle_enabled <0|1>\" > info\n"
		"  echo \"throttle_file_threshold <pages>\" > info\n"
		"  echo \"file_scan_enabled <0|1>\" > info\n"
		"  echo \"fg_file_scan_threshold <pages>\" > info\n"
		"[Other]\n"
		"  echo 1 > reset_stats\n"
		"  cat /proc/mi_reclaim       # observe-only counters (legacy)\n");
}

static struct kobj_attribute mir_pid_attr =
	__ATTR(pid, 0644, mir_pid_show, mir_pid_store);
static struct kobj_attribute mir_event_attr =
	__ATTR(event, 0200, NULL, mir_event_store);
static struct kobj_attribute mir_info_attr =
	__ATTR(info, 0644, mir_info_show, mir_info_store);
static struct kobj_attribute mir_usage_attr =
	__ATTR(usage, 0444, mir_usage_show, NULL);
static struct kobj_attribute mir_reset_attr =
	__ATTR(reset_stats, 0200, NULL, mir_reset_stats_store);

static struct attribute *mir_attrs[] = {
	&mir_pid_attr.attr,
	&mir_event_attr.attr,
	&mir_info_attr.attr,
	&mir_usage_attr.attr,
	&mir_reset_attr.attr,
	NULL,
};
static const struct attribute_group mir_attr_group = {
	.attrs = mir_attrs,
};
static struct kobject *mir_kobj;

/* ---- legacy /proc observe node (unchanged first-cut interface) --------- */

static int mir_proc_show(struct seq_file *m, void *v)
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

static int mir_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mir_proc_show, NULL);
}

static const struct proc_ops mir_proc_ops = {
	.proc_open	= mir_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ---- module ------------------------------------------------------------ */

static void mir_hooks_unregister(void)
{
	unregister_trace_android_vh_alloc_pages_slowpath_start(
		mir_slowpath, NULL);
	unregister_trace_android_vh_direct_reclaim_end(mir_reclaim_end, NULL);
	unregister_trace_android_vh_throttle_direct_reclaim_bypass(
		mir_throttle_bypass, NULL);
	unregister_trace_android_vh_tune_scan_type(mir_tune_scan_type, NULL);
	tracepoint_synchronize_unregister();
}

static int __init mi_reclaim_init(void)
{
	int ret;

	ret = register_trace_android_vh_alloc_pages_slowpath_start(
		mir_slowpath, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_direct_reclaim_end(
		mir_reclaim_end, NULL);
	if (ret)
		goto err_slowpath;
	ret = register_trace_android_vh_throttle_direct_reclaim_bypass(
		mir_throttle_bypass, NULL);
	if (ret)
		goto err_reclaim_end;
	ret = register_trace_android_vh_tune_scan_type(
		mir_tune_scan_type, NULL);
	if (ret)
		goto err_throttle;

	if (!proc_create("mi_reclaim", 0444, NULL, &mir_proc_ops)) {
		ret = -ENOMEM;
		goto err_scan;
	}

	mir_kobj = kobject_create_and_add("mi_reclaim", kernel_kobj);
	if (!mir_kobj) {
		ret = -ENOMEM;
		goto err_proc;
	}
	ret = sysfs_create_group(mir_kobj, &mir_attr_group);
	if (ret)
		goto err_kobj;

	mir_worker = kthread_run(mir_worker_fn, NULL, "mireclaimd");
	if (IS_ERR(mir_worker)) {
		ret = PTR_ERR(mir_worker);
		mir_worker = NULL;
		goto err_group;
	}
	return 0;

err_group:
	sysfs_remove_group(mir_kobj, &mir_attr_group);
err_kobj:
	kobject_put(mir_kobj);
err_proc:
	remove_proc_entry("mi_reclaim", NULL);
err_scan:
	unregister_trace_android_vh_tune_scan_type(mir_tune_scan_type, NULL);
err_throttle:
	unregister_trace_android_vh_throttle_direct_reclaim_bypass(
		mir_throttle_bypass, NULL);
err_reclaim_end:
	unregister_trace_android_vh_direct_reclaim_end(mir_reclaim_end, NULL);
err_slowpath:
	unregister_trace_android_vh_alloc_pages_slowpath_start(
		mir_slowpath, NULL);
	tracepoint_synchronize_unregister();
	return ret;
}

static void __exit mi_reclaim_exit(void)
{
	if (mir_worker)
		kthread_stop(mir_worker);
	atomic_set(&mir_event_mb, 0);
	wake_up(&mir_waitq);

	mutex_lock(&mir_pid_lock);
	mir_pid_clear_locked();
	mutex_unlock(&mir_pid_lock);

	sysfs_remove_group(mir_kobj, &mir_attr_group);
	kobject_put(mir_kobj);
	remove_proc_entry("mi_reclaim", NULL);

	mir_hooks_unregister();
}

module_init(mi_reclaim_init);
module_exit(mi_reclaim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew port of the Xiaomi OS4 mi_reclaim (observe + bounded tuning, defaults off)");
