// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_qos_inherit: minimal QOS-inheritance on the futex wait chain,
 * reduced port of the Xiaomi OS4 xr_qi module idea ("MI QOS inherit
 * Driver": propagate importance from a lock holder to waiters).
 *
 * Scope reduction vs OS4: only the futex side, and only a uclamp_min
 * hint. The existing android_vh_futex_wait_start / _wait_end hooks are
 * consumed (no new call sites needed). When a waiter we flagged blocks
 * on a futex, we remember its tgid; when it wakes, the hint is dropped.
 * The hint itself is applied to waiters of a single configured "vip"
 * tgid: those waiters get a small uclamp_min floor while blocked, so
 * the EAS places them on capable cores when they wake.
 *
 * NOT ported from OS4 (deliberately): rwsem/percpu-rwsem/mmap_lock/rcu/
 * fuse hooks (10 additional call sites, month-scale audit), RT priority
 * migration, and the full group bookkeeping.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/uaccess.h>
#include <trace/hooks/futex.h>

#define SEW_QI_UCLAMP_MIN_DEFAULT 256 /* 25% of 1024 */

/* Mirror of kernel/sched/core.c uclamp_bucket_id() (static there). */
#define SEW_QI_BUCKET_DELTA \
	DIV_ROUND_CLOSEST(SCHED_CAPACITY_SCALE, UCLAMP_BUCKETS)

static pid_t sew_qi_vip_tgid;
static unsigned int sew_qi_uclamp_min = SEW_QI_UCLAMP_MIN_DEFAULT;
static atomic64_t sew_qi_hinted_waits;

/*
 * Save/restore slots keyed by tid (not tgid): if the user re-points
 * vip_tgid while a hinted task is still blocked, wait_end must still
 * restore that task (reviewer finding). Bounded ring of slots; a full
 * table refuses further hints rather than corrupting state.
 *
 * The uclamp_req write itself stays lock-free, mirroring the OS4
 * original: a torn bitfield read self-corrects on the next bucket
 * update, and rq aggregation catches up at the next enqueue/dequeue.
 */
#define SEW_QI_HINT_SLOTS 16
struct sew_qi_hint {
	int		tid;
	unsigned int	prev_value;
};
static struct sew_qi_hint sew_qi_hints[SEW_QI_HINT_SLOTS];
static DEFINE_SPINLOCK(sew_qi_hint_lock);

static void sew_qi_wait_start(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;
	unsigned long irqflags;
	int i, slot = -1;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * Tracepoint probes run with preemption disabled, so only
	 * non-sleeping work happens here (spinlock is fine).
	 */
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].tid == t->pid) {
			slot = i;
			break;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot >= 0) {
		sew_qi_hints[slot].tid = t->pid;
		sew_qi_hints[slot].prev_value =
			t->uclamp_req[UCLAMP_MIN].value;
		/* uclamp_bucket_id() is core.c-static; same mapping inline. */
		t->uclamp_req[UCLAMP_MIN].value = sew_qi_uclamp_min;
		t->uclamp_req[UCLAMP_MIN].bucket_id =
			min_t(unsigned int,
			      sew_qi_uclamp_min / SEW_QI_BUCKET_DELTA,
			      (unsigned int)(UCLAMP_BUCKETS - 1));
		atomic64_inc(&sew_qi_hinted_waits);
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

static void sew_qi_wait_end(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;
	unsigned long irqflags;
	int i;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].tid == t->pid) {
			t->uclamp_req[UCLAMP_MIN].value =
				sew_qi_hints[i].prev_value;
			t->uclamp_req[UCLAMP_MIN].bucket_id =
				min_t(unsigned int,
				      sew_qi_hints[i].prev_value / SEW_QI_BUCKET_DELTA,
				      (unsigned int)(UCLAMP_BUCKETS - 1));
			sew_qi_hints[i].tid = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

static int sew_qi_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "vip_tgid=%d\nuclamp_min=%u\nhinted_waits=%lld\n",
		   sew_qi_vip_tgid, sew_qi_uclamp_min,
		   atomic64_read(&sew_qi_hinted_waits));
	return 0;
}

static int sew_qi_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_qi_proc_show, NULL);
}

static ssize_t sew_qi_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[64];
	long val;
	int field;

	if (count >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';

	if (sscanf(tmp, "vip_tgid %ld", &val) == 1)
		field = 0;
	else if (sscanf(tmp, "uclamp_min %ld", &val) == 1)
		field = 1;
	else
		return -EINVAL;

	/*
	 * pid_max is not exported to modules on 5.15; pid_t is a signed
	 * int and the hook side re-checks against real tasks, so a plain
	 * non-negative bound is enough here.
	 */
	if (field == 0) {
		if (val < 0)
			return -EINVAL;
		WRITE_ONCE(sew_qi_vip_tgid, (pid_t)val);
	} else {
		if (val < 0 || val > 1024)
			return -EINVAL;
		WRITE_ONCE(sew_qi_uclamp_min, (unsigned int)val);
	}
	return count;
}

static const struct proc_ops sew_qi_proc_ops = {
	.proc_open	= sew_qi_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= sew_qi_proc_write,
};

static int __init sew_qos_inherit_init(void)
{
	int ret;

	ret = register_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	if (ret) {
		unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
		return ret;
	}
	if (!proc_create("sew_qos_inherit", 0644, NULL, &sew_qi_proc_ops)) {
		unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
		unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
		return -ENOMEM;
	}
	return 0;
}

static void __exit sew_qos_inherit_exit(void)
{
	unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	tracepoint_synchronize_unregister();
	remove_proc_entry("sew_qos_inherit", NULL);
}

module_init(sew_qos_inherit_init);
module_exit(sew_qos_inherit_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew minimal futex QOS-inheritance (xr_qi reduced port, uclamp hint only)");
