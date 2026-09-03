// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_rss_monitor: observe RSS and accumulated runtime of a tgid
 * allowlist via a dynamic probe on the "sched_stat_runtime" tracepoint
 * (located by name with for_each_kernel_tracepoint; chosen over
 * sched_switch because it provides the per-task runtime delta directly,
 * and it covers CFS tasks - the population relevant for app monitoring;
 * if the tracepoint is missing from the build, init fails cleanly).
 * Runtime is accumulated per tgid: per-task entries would need a
 * reclaimable hash for thread churn, not worth it for an observer. RSS
 * is sampled at most once per sample_ms per tgid; crossing
 * rss_threshold_kb is reported with printk_ratelimited. An empty
 * tgid_list keeps the callback at one zero-entry scan (idle).
 *
 * Controls: tgid_list (comma-separated pids; writable at
 * /sys/module/sew_rss_monitor/parameters/tgid_list, rewritable at
 * runtime, resets stats), rss_threshold_kb, sample_ms. Stats are read
 * from /dev/sew_rss_monitor.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/time64.h>
#include <linux/tracepoint.h>

#define SEW_RSS_MAX_TGIDS 8

static ulong sew_rss_threshold_kb = 512UL * 1024UL;
module_param_named(rss_threshold_kb, sew_rss_threshold_kb, ulong, 0644);
MODULE_PARM_DESC(rss_threshold_kb,
	"RSS report threshold in KB (default 524288)");

static uint sew_sample_ms = 1000;
module_param_named(sample_ms, sew_sample_ms, uint, 0644);
MODULE_PARM_DESC(sample_ms,
	"min ms between RSS samples per tgid (default 1000)");

struct sew_rss_tgid {
	int tgid;
	atomic64_t runtime_ns;	/* sum of tracepoint runtime deltas */
	atomic64_t events;
	atomic64_t rss_kb;	/* last sample */
	atomic64_t next_sample;	/* jiffies deadline of next sample */
	atomic64_t reports;
};

static struct sew_rss_tgid sew_tgids[SEW_RSS_MAX_TGIDS];
static int sew_tgid_count;
/* serializes list rewrites against each other; the probe reads the
 * list locklessly (see the race note above the probe) */
static DEFINE_SPINLOCK(sew_tgids_lock);

static struct tracepoint *sew_stat_runtime_tp;

/* all-or-nothing parse: a malformed, range-syntax, or over-long list
 * (> SEW_RSS_MAX_TGIDS entries) is rejected and the previous list
 * stays armed; the whole parse happens on a stack copy */
static int sew_tgid_list_set(const char *val, const struct kernel_param *kp)
{
	int parsed[SEW_RSS_MAX_TGIDS];
	int n = 0, rc, i;
	char buf[128];
	char *p;
	unsigned long flags;

	if (!val)
		return -EINVAL;
	if (strlen(val) >= sizeof(buf))
		return -EINVAL;
	strscpy(buf, val, sizeof(buf));
	p = strim(buf);

	while (n < SEW_RSS_MAX_TGIDS && *p) {
		rc = get_option(&p, &parsed[n]);
		if (rc == 0) {
			if (*p)
				return -EINVAL;
			break;
		}
		if (rc == 3)
			return -EINVAL;	/* range syntax unsupported */
		if (parsed[n] <= 0)
			return -EINVAL;
		n++;
		if (rc == 1)
			break;	/* no comma follows */
	}
	if (*p)
		return -EINVAL;	/* more than SEW_RSS_MAX_TGIDS entries */

	spin_lock_irqsave(&sew_tgids_lock, flags);
	memset(sew_tgids, 0, sizeof(sew_tgids));
	for (i = 0; i < n; i++)
		sew_tgids[i].tgid = parsed[i];
	sew_tgid_count = n;
	spin_unlock_irqrestore(&sew_tgids_lock, flags);
	return 0;
}

static int sew_tgid_list_get(char *buffer, const struct kernel_param *kp)
{
	int i, len = 0;
	unsigned long flags;

	spin_lock_irqsave(&sew_tgids_lock, flags);
	for (i = 0; i < sew_tgid_count && i < SEW_RSS_MAX_TGIDS; i++)
		len += scnprintf(buffer + len, PAGE_SIZE - len, "%s%d",
				 i ? "," : "", sew_tgids[i].tgid);
	spin_unlock_irqrestore(&sew_tgids_lock, flags);
	buffer[len] = '\0';
	return len;
}

static const struct kernel_param_ops sew_tgid_list_ops = {
	.set = sew_tgid_list_set,
	.get = sew_tgid_list_get,
};
module_param_cb(tgid_list, &sew_tgid_list_ops, NULL, 0644);
MODULE_PARM_DESC(tgid_list,
	"comma-separated tgid allowlist, e.g. \"1234,5678\" (empty = idle)");

/* task_lock() is a spinlock, safe in the preempt-disabled probe; it
 * pins p->mm against exit_mmap() teardown racing on another CPU */
static unsigned long sew_task_rss_kb(struct task_struct *p)
{
	struct mm_struct *mm;
	unsigned long pages;

	task_lock(p);
	mm = p->mm;
	if (!mm) {
		task_unlock(p);
		return 0;
	}
	pages = get_mm_rss(mm);
	task_unlock(p);

	return pages << (PAGE_SHIFT - 10);
}

/*
 * Runs with preemption disabled (tracepoint core), possibly from timer
 * interrupt context: atomic work only. The allowlist scan is lockless:
 * tgid/count are aligned ints and READ_ONCE'd, so a concurrent
 * tgid_list rewrite can at worst make the probe briefly miss brand-new
 * entries or skip just-cleared ones; stat counters are atomics, so a
 * rewrite only races the intentional counter reset.
 */
static void sew_sched_stat_runtime_probe(void *data, struct task_struct *p,
					 u64 runtime, u64 vruntime)
{
	struct sew_rss_tgid *e = NULL;
	unsigned long rss_kb;
	u64 now, old, period;
	int count, i, tgid;

	count = READ_ONCE(sew_tgid_count);
	if (!count)
		return;

	tgid = p->tgid;
	for (i = 0; i < count && i < SEW_RSS_MAX_TGIDS; i++) {
		if (READ_ONCE(sew_tgids[i].tgid) == tgid) {
			e = &sew_tgids[i];
			break;
		}
	}
	if (!e)
		return;

	atomic64_add(runtime, &e->runtime_ns);
	atomic64_inc(&e->events);

	/* throttle RSS sampling: at most one check per sample_ms per tgid
	 * (minimum one jiffy); cmpxchg arbitrates between CPUs running
	 * tasks of the same tgid */
	period = msecs_to_jiffies(sew_sample_ms);
	if (period == 0)
		period = 1;
	now = (u64)jiffies;
	old = atomic64_read(&e->next_sample);
	if (time_after64(now, old) &&
	    atomic64_cmpxchg(&e->next_sample, old, now + period) == old) {
		rss_kb = sew_task_rss_kb(p);
		atomic64_set(&e->rss_kb, (u64)rss_kb);
		if (rss_kb > sew_rss_threshold_kb) {
			atomic64_inc(&e->reports);
			printk_ratelimited(KERN_INFO
				"sew_rss_monitor: tgid=%d comm=%s pid=%d "
				"rss=%luKB runtime=%llums threshold=%luKB\n",
				tgid, p->comm, p->pid, rss_kb,
				(unsigned long long)div64_u64(
					atomic64_read(&e->runtime_ns),
					NSEC_PER_MSEC),
				sew_rss_threshold_kb);
		}
	}
}

static void sew_find_stat_runtime_tp(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sched_stat_runtime"))
		sew_stat_runtime_tp = tp;
}

static int sew_rss_show(struct seq_file *m, void *v)
{
	unsigned long long runtime_ms;
	int count, i;

	seq_printf(m, "threshold_kb: %lu\n", sew_rss_threshold_kb);
	seq_printf(m, "sample_ms: %u\n", sew_sample_ms);
	count = READ_ONCE(sew_tgid_count);
	seq_printf(m, "tgid_count: %d\n", count);

	for (i = 0; i < count && i < SEW_RSS_MAX_TGIDS; i++) {
		runtime_ms = div64_u64(
			atomic64_read(&sew_tgids[i].runtime_ns), NSEC_PER_MSEC);
		seq_printf(m,
			   "tgid=%d runtime_ms=%llu events=%llu rss_kb=%llu reports=%llu\n",
			   READ_ONCE(sew_tgids[i].tgid), runtime_ms,
			   (unsigned long long)atomic64_read(&sew_tgids[i].events),
			   (unsigned long long)atomic64_read(&sew_tgids[i].rss_kb),
			   (unsigned long long)atomic64_read(&sew_tgids[i].reports));
	}
	return 0;
}

static int sew_rss_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_rss_show, NULL);
}

static const struct file_operations sew_rss_fops = {
	.owner = THIS_MODULE,
	.open = sew_rss_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct miscdevice sew_rss_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sew_rss_monitor",
	.fops = &sew_rss_fops,
};

static int __init sew_rss_monitor_init(void)
{
	int ret;

	for_each_kernel_tracepoint(sew_find_stat_runtime_tp, NULL);
	if (!sew_stat_runtime_tp) {
		pr_err("sew_rss_monitor: sched_stat_runtime tracepoint not found\n");
		return -ENOENT;
	}

	ret = misc_register(&sew_rss_misc);
	if (ret) {
		pr_err("sew_rss_monitor: misc_register failed: %d\n", ret);
		return ret;
	}

	ret = tracepoint_probe_register(sew_stat_runtime_tp,
					sew_sched_stat_runtime_probe, NULL);
	if (ret) {
		pr_err("sew_rss_monitor: tracepoint probe registration failed: %d\n",
			ret);
		misc_deregister(&sew_rss_misc);
		return ret;
	}

	pr_info("sew_rss_monitor: armed, %d tgid(s), threshold %luKB\n",
		sew_tgid_count, sew_rss_threshold_kb);
	return 0;
}

static void __exit sew_rss_monitor_exit(void)
{
	tracepoint_probe_unregister(sew_stat_runtime_tp,
				    sew_sched_stat_runtime_probe, NULL);
	/* guarantee no CPU is still inside our probe before the code and
	 * the stat storage go away */
	tracepoint_synchronize_unregister();
	misc_deregister(&sew_rss_misc);
	sew_stat_runtime_tp = NULL;
	pr_info("sew_rss_monitor: unregistered\n");
}

module_init(sew_rss_monitor_init);
module_exit(sew_rss_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew RSS/runtime monitor for a tgid allowlist");
MODULE_AUTHOR("Sew");
