// SPDX-License-Identifier: GPL-2.0-only
/*
 * hangdetect: Sew 5.15 port of the Xiaomi OS4 hangdetect module
 * (drivers/xiaomi/hangdetect/hang_detect.c upstream path).
 *
 * RE evidence: /root/work/os4_dada/ko/hangdetect.ko (vermagic 6.6.57,
 * depends=minidump).  Raw dump in this session's research raw/ dir.
 *
 * What the OS4 module does
 * ------------------------
 * Userspace (system_server watchdog / monkey / whitelisted actors)
 * "kicks" the driver through a misc device.  A monitor thread checks
 * the kick age: on timeout it dumps the offending processes' thread
 * backtraces ("Dump the %d time process bt", throttled: "first dump was
 * blocked"), tracks system_server watchdog pid changes ("watchdog pid
 * changed"), and can signal offenders.  Dumps persist through a qcom
 * minidump region (msm_minidump_add_region + kimage_voffset /
 * memstart_addr phys translation); native fp/pc walking is done from
 * user memory via access_process_vm.
 *
 * Sew 5.15 port ([PORT-DELTA] items marked)
 * -----------------------------------------
 * - minidump -> console-ramoops: the dump path is sched_show_task()
 *   through printk; with CONFIG_PSTORE_RAM the console-ramoops record
 *   captures it on the next reboot, and the optional "panic" action
 *   makes persistence immediate.  No msm_minidump, no phys-translate
 *   closures (kimage_voffset/memstart_addr unused).  [PORT-DELTA]
 * - control ABI is redefined as a text interface on the misc device
 *   (the original binary struct ABI is not recoverable to the 98% bar
 *   from the binary alone, and the consuming userspace on Sew is our
 *   addon module): write "start <threshold_ms>", "stop", "kick",
 *   "whitelist add <comm>", "whitelist del <comm>", "action dump|panic".
 *   [PORT-DELTA]
 * - process iteration: for_each_process/while_each_thread instead of
 *   the 6.6 maple-tree walk (mas_find).  [PORT-DELTA]
 * - user-memory fp/pc walking (access_process_vm, mmap_lock tracepoints)
 *   is not ported: kernel-side sched_show_task covers the scheduling
 *   stall signature this module exists for.  [PORT-DELTA]
 * - boot self-monitor mode (monitor_hang_boot_up_enable) not ported.
 *   [PORT-DELTA]
 * - whitelist matches task comm (original matches process names from
 *   userspace, e.g. system_server; default whitelist is system_server).
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/signal.h>
#include <linux/jiffies.h>
#include <linux/reboot.h>
#include <linux/string.h>

#define HD_MAX_WHITELIST	8
#define HD_COMM_LEN		16
#define HD_DEFAULT_THRESHOLD_MS	60000	/* one minute without a kick */
#define HD_DUMP_MIN_INTERVAL_MS	30000	/* "first dump was blocked" */
#define HD_DUMP_MAX		3	/* dumps before the action fires */

enum hd_action {
	HD_ACTION_DUMP_ONLY = 0,
	HD_ACTION_PANIC = 1,
};

static struct {
	bool running;
	unsigned int threshold_ms;
	unsigned int action;	/* enum hd_action */
	unsigned long last_kick_jiffies;
	unsigned long last_dump_jiffies;
	unsigned int dump_count;
	char whitelist[HD_MAX_WHITELIST][HD_COMM_LEN];
	int whitelist_len;
	struct task_struct *worker;
} hd = {
	.threshold_ms = HD_DEFAULT_THRESHOLD_MS,
	.action = HD_ACTION_DUMP_ONLY,
	.whitelist_len = 1,
	/* original watches system_server's watchdog above all */
	.whitelist = { "system_server" },
};

static DEFINE_MUTEX(hd_lock);
static DECLARE_WAIT_QUEUE_HEAD(hd_waitq);

static bool hd_whitelisted(const char *comm)
{
	int i;

	for (i = 0; i < hd.whitelist_len; i++)
		if (!strncmp(comm, hd.whitelist[i], HD_COMM_LEN))
			return true;
	return false;
}

/* dump every thread of every whitelisted process, kernel-side state */
static unsigned int hd_dump_whitelisted(void)
{
	struct task_struct *g, *p;
	unsigned int dumped = 0;

	rcu_read_lock();
	for_each_process(g) {
		if (!hd_whitelisted(g->comm))
			continue;
		p = g;
		do {
			sched_show_task(p);
			dumped++;
		} while_each_thread(g, p);
	}
	rcu_read_unlock();
	return dumped;
}

static int hd_worker_fn(void *unused)
{
	while (!kthread_should_stop()) {
		wait_event_interruptible_timeout(hd_waitq,
						 kthread_should_stop(),
						 msecs_to_jiffies(5000));
		if (kthread_should_stop())
			break;

		mutex_lock(&hd_lock);
		if (!hd.running) {
			mutex_unlock(&hd_lock);
			continue;
		}
		if ((u64)jiffies_to_msecs(jiffies - hd.last_kick_jiffies) <
		    hd.threshold_ms) {
			mutex_unlock(&hd_lock);
			continue;
		}

		hd.last_kick_jiffies = jiffies;	/* arm for the next window */
		if (hd.last_dump_jiffies &&
		    (u64)jiffies_to_msecs(jiffies - hd.last_dump_jiffies) <
		    HD_DUMP_MIN_INTERVAL_MS) {
			pr_info("hang_detect: first dump was blocked\n");
			mutex_unlock(&hd_lock);
			continue;
		}
		hd.last_dump_jiffies = jiffies;
		hd.dump_count++;

		pr_info("hang_detect: hang_detect HANG_KICK ( %d)\n",
			hd.dump_count);
		pr_info("hang_detect: ================================================\n");
		hd_dump_whitelisted();
		pr_info("hang_detect: dump done (%u of %d)\n",
			hd.dump_count, HD_DUMP_MAX);

		if (hd.action == HD_ACTION_PANIC &&
		    hd.dump_count >= HD_DUMP_MAX) {
			mutex_unlock(&hd_lock);
			panic("hangdetect: %d dumps with no kick, persisting via ramoops",
			      HD_DUMP_MAX);
		}
		if (hd.dump_count >= HD_DUMP_MAX)
			hd.dump_count = 0;	/* keep cycling, dump-only */
		mutex_unlock(&hd_lock);
	}
	return 0;
}

/* ---- misc device: text control ABI ------------------------------------- */

static ssize_t hd_write(struct file *file, const char __user *ubuf,
			size_t len, loff_t *ppos)
{
	char buf[96];
	char cmd[24], arg1[24], arg2[HD_COMM_LEN];
	int n;

	if (len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	n = sscanf(buf, "%23s %23s %15s", cmd, arg1, arg2);
	if (n < 1)
		return -EINVAL;

	if (!strcmp(cmd, "kick")) {
		mutex_lock(&hd_lock);
		hd.last_kick_jiffies = jiffies;
		hd.dump_count = 0;
		mutex_unlock(&hd_lock);
		return len;
	}
	if (!strcmp(cmd, "start")) {
		unsigned int ms = HD_DEFAULT_THRESHOLD_MS;

		if (n >= 2 && kstrtouint(arg1, 0, &ms))
			return -EINVAL;
		mutex_lock(&hd_lock);
		hd.threshold_ms = ms;
		hd.last_kick_jiffies = jiffies;
		hd.dump_count = 0;
		hd.running = true;
		mutex_unlock(&hd_lock);
		pr_info("hang_detect: hang_detect enabled %d (threshold_ms=%u)\n",
			1, ms);
		return len;
	}
	if (!strcmp(cmd, "stop")) {
		mutex_lock(&hd_lock);
		hd.running = false;
		mutex_unlock(&hd_lock);
		pr_info("hang_detect: disable by stop cmd\n");
		return len;
	}
	if (!strcmp(cmd, "whitelist") && n >= 3) {
		int i;

		mutex_lock(&hd_lock);
		if (!strcmp(arg1, "add")) {
			if (hd.whitelist_len < HD_MAX_WHITELIST) {
				strncpy(hd.whitelist[hd.whitelist_len++],
					arg2, HD_COMM_LEN - 1);
				pr_info("hang_detect: add white list %s\n",
					arg2);
			}
		} else if (!strcmp(arg1, "del")) {
			for (i = 0; i < hd.whitelist_len; i++) {
				if (strncmp(hd.whitelist[i], arg2,
					    HD_COMM_LEN))
					continue;
				memmove(&hd.whitelist[i], &hd.whitelist[i + 1],
					(hd.whitelist_len - i - 1) *
					HD_COMM_LEN);
				hd.whitelist_len--;
				pr_info("hang_detect: del white list %s\n",
					arg2);
				break;
			}
		}
		mutex_unlock(&hd_lock);
		return len;
	}
	if (!strcmp(cmd, "action") && n >= 2) {
		if (!strcmp(arg1, "panic")) {
			hd.action = HD_ACTION_PANIC;
			return len;
		}
		if (!strcmp(arg1, "dump")) {
			hd.action = HD_ACTION_DUMP_ONLY;
			return len;
		}
		return -EINVAL;
	}
	pr_info("hang_detect: invalid control msg\n");
	return -EINVAL;
}

static const struct file_operations hd_fops = {
	.owner = THIS_MODULE,
	.write = hd_write,
};

static struct miscdevice hd_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hangdetect",
	.fops = &hd_fops,
	.mode = 0600,
};

/* ---- module ------------------------------------------------------------ */

static int __init hang_detect_init(void)
{
	int ret;

	hd.last_kick_jiffies = jiffies;

	hd.worker = kthread_run(hd_worker_fn, NULL, "hangdetectd");
	if (IS_ERR(hd.worker))
		return PTR_ERR(hd.worker);

	ret = misc_register(&hd_misc);
	if (ret) {
		kthread_stop(hd.worker);
		hd.worker = NULL;
		return ret;
	}
	pr_info("hang_detect: hang_detect enabled %d\n", 0);
	return 0;
}

static void __exit hang_detect_exit(void)
{
	misc_deregister(&hd_misc);
	if (hd.worker) {
		kthread_stop(hd.worker);
		hd.worker = NULL;
	}
}

module_init(hang_detect_init);
module_exit(hang_detect_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew port of the Xiaomi OS4 hangdetect (kicker watchdog, console-ramoops persistence)");
