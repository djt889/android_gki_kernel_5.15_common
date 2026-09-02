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
static u64 sew_qi_hinted_waits;

static void sew_qi_wait_start(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;

	if (!sew_qi_vip_tgid)
		return;
	if (task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	sew_qi_hinted_waits++;
	/*
	 * Apply the floor while this waiter sleeps on the futex.
	 * uclamp_bucket_id() is static in kernel/sched/core.c, so inline
	 * the same mapping (see core.c:1328 in this tree).
	 */
	t->uclamp_req[UCLAMP_MIN].value = sew_qi_uclamp_min;
	t->uclamp_req[UCLAMP_MIN].bucket_id =
		min_t(unsigned int,
		      sew_qi_uclamp_min / SEW_QI_BUCKET_DELTA,
		      (unsigned int)(UCLAMP_BUCKETS - 1));
}

static void sew_qi_wait_end(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;

	if (!sew_qi_vip_tgid)
		return;
	if (task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/* Drop the hint on wake. */
	t->uclamp_req[UCLAMP_MIN].value = 0;
	t->uclamp_req[UCLAMP_MIN].bucket_id = 0;
}

static int sew_qi_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "vip_tgid=%d\nuclamp_min=%u\nhinted_waits=%llu\n",
		   sew_qi_vip_tgid, sew_qi_uclamp_min, sew_qi_hinted_waits);
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
