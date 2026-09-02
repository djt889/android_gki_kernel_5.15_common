// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_rtload: count RT policy requests passing through
 * __sched_setscheduler() via a kprobe; counters are exposed through
 * /dev/sew_rtload. The pre_handler buckets SCHED_FIFO / SCHED_RR
 * requests, tracks non-RT->RT ("enter") and RT->non-RT ("leave")
 * transitions, and records the last RT requester (tgid/comm/policy)
 * for triage. Observation only; no scheduling decision is changed.
 *
 * Argument extraction is arm64-specific (args in x0..x7 =
 * regs->regs[0..7]), hence the Kconfig "depends on ARM64". attr is a
 * kernel-side copy, but every dereference goes through
 * copy_from_kernel_nofault() so a garbage pointer cannot fault the
 * probe.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <uapi/linux/sched/types.h>

static atomic64_t sew_fifo_requests;
static atomic64_t sew_rr_requests;
static atomic64_t sew_rt_enter;	/* non-RT -> RT */
static atomic64_t sew_rt_leave;	/* RT -> non-RT */

static int sew_last_tgid;
static int sew_last_policy;
static char sew_last_comm[TASK_COMM_LEN];
static DEFINE_SPINLOCK(sew_last_lock);

static int sew_setsched_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct task_struct *p;
	struct sched_attr attr;
	char comm[TASK_COMM_LEN];
	unsigned int old_policy = 0;
	unsigned long flags;
	int policy, tgid;

	p = (struct task_struct *)regs->regs[0];
	if (!p)
		return 0;
	if (copy_from_kernel_nofault(&attr, (const void *)regs->regs[1],
				     sizeof(attr)))
		return 0;

	policy = attr.sched_policy;

	/* p->policy still holds the OLD policy at function entry; on read
	 * failure treat it as unknown (0) */
	if (copy_from_kernel_nofault(&old_policy,
				     (const char *)p +
					offsetof(struct task_struct, policy),
				     sizeof(old_policy)))
		old_policy = 0;

	if (policy != SCHED_FIFO && policy != SCHED_RR) {
		/* RT -> non-RT transition */
		if (old_policy == SCHED_FIFO || old_policy == SCHED_RR)
			atomic64_inc(&sew_rt_leave);
		return 0;
	}

	if (policy == SCHED_FIFO)
		atomic64_inc(&sew_fifo_requests);
	else
		atomic64_inc(&sew_rr_requests);
	if (old_policy != SCHED_FIFO && old_policy != SCHED_RR)
		atomic64_inc(&sew_rt_enter);

	tgid = 0;
	if (copy_from_kernel_nofault(&tgid,
				     (const char *)p +
					offsetof(struct task_struct, tgid),
				     sizeof(tgid)))
		tgid = -1;
	if (copy_from_kernel_nofault(comm,
				     (const char *)p +
					offsetof(struct task_struct, comm),
				     sizeof(comm)))
		comm[0] = '\0';
	comm[TASK_COMM_LEN - 1] = '\0';

	spin_lock_irqsave(&sew_last_lock, flags);
	sew_last_tgid = tgid;
	sew_last_policy = policy;
	memcpy(sew_last_comm, comm, sizeof(comm));
	spin_unlock_irqrestore(&sew_last_lock, flags);

	return 0;
}

static struct kprobe sew_setsched_kp = {
	.symbol_name = "__sched_setscheduler",
	.pre_handler = sew_setsched_pre,
};

static int sew_rtload_show(struct seq_file *m, void *v)
{
	char comm[TASK_COMM_LEN];
	unsigned long flags;
	int tgid, policy;

	spin_lock_irqsave(&sew_last_lock, flags);
	memcpy(comm, sew_last_comm, sizeof(comm));
	tgid = sew_last_tgid;
	policy = sew_last_policy;
	spin_unlock_irqrestore(&sew_last_lock, flags);
	comm[TASK_COMM_LEN - 1] = '\0';

	seq_printf(m, "fifo_requests: %lld\n",
		   (long long)atomic64_read(&sew_fifo_requests));
	seq_printf(m, "rr_requests: %lld\n",
		   (long long)atomic64_read(&sew_rr_requests));
	seq_printf(m, "rt_enter: %lld\n",
		   (long long)atomic64_read(&sew_rt_enter));
	seq_printf(m, "rt_leave: %lld\n",
		   (long long)atomic64_read(&sew_rt_leave));
	seq_printf(m, "last_rt_tgid: %d\n", tgid);
	seq_printf(m, "last_rt_comm: %s\n", comm);
	seq_printf(m, "last_rt_policy: %d\n", policy);
	seq_printf(m, "sched_fifo: %d sched_rr: %d\n", SCHED_FIFO, SCHED_RR);
	return 0;
}

static int sew_rtload_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_rtload_show, NULL);
}

static const struct file_operations sew_rtload_fops = {
	.owner = THIS_MODULE,
	.open = sew_rtload_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct miscdevice sew_rtload_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sew_rtload",
	.fops = &sew_rtload_fops,
};

static int __init sew_rtload_init(void)
{
	int ret;

	ret = register_kprobe(&sew_setsched_kp);
	if (ret) {
		pr_err("sew_rtload: kprobe on __sched_setscheduler failed: %d\n",
			ret);
		sew_setsched_kp.addr = NULL;
		return ret;
	}

	ret = misc_register(&sew_rtload_misc);
	if (ret) {
		pr_err("sew_rtload: misc_register failed: %d\n", ret);
		unregister_kprobe(&sew_setsched_kp);
		sew_setsched_kp.addr = NULL;
		return ret;
	}

	pr_info("sew_rtload: kprobe armed at %pS\n", sew_setsched_kp.addr);
	return 0;
}

static void __exit sew_rtload_exit(void)
{
	unregister_kprobe(&sew_setsched_kp);
	/* symbol address record cleared: the kprobe is disarmed and the
	 * cached resolution must not be reused without re-registration */
	sew_setsched_kp.addr = NULL;
	misc_deregister(&sew_rtload_misc);
	pr_info("sew_rtload: unregistered\n");
}

module_init(sew_rtload_init);
module_exit(sew_rtload_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew RT load observer (kprobe on __sched_setscheduler)");
MODULE_AUTHOR("Sew");
