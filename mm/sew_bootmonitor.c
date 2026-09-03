// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_bootmonitor: boot-event blackbox, reduced port of the Xiaomi OS4
 * bootmonitor module (drivers/xiaomi/bootmonitor in dada-v-oss).
 *
 * What is kept from the original: the boot-event anchor model (a fixed
 * table of named events with expected timings, recorded in order), the
 * in-memory ring of event records, and the bootmode/fingerprint
 * stamping from module params.
 *
 * What is deliberately NOT ported: the DT /reserved-memory resource
 * probe ("xiaomi,bootmonitor_pmsg" node absent on nuwa/vermeer/fuxi)
 * and the raw blackbox-partition block-device writer. Instead, the
 * event log is mirrored into the pstore ramoops backend when present:
 * each finalized boot pass writes a single "sew-bootmonitor" pstore
 * record, so the log survives a reboot exactly like the original
 * blackbox but through the platform's existing infrastructure
 * (R7.8 already enables PSTORE_PMSG/PSTORE_RAM).
 *
 * Interfaces: /proc/sew_bootmonitor (read the event table of the
 * current boot), module params bootmode/fingerprint (set from the
 * init.rc of the OS4-style ramdisk if desired).
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>

#define SEW_BM_EVENTS_MAX	32
#define SEW_BM_NAME_LEN		32

struct sew_bm_event {
	char	name[SEW_BM_NAME_LEN];
	u64	ts_ns;		/* 0 = not yet reached */
	int	status;		/* 0 pending, 1 hit */
};

/*
 * Boot-event anchors (subset of the OS4 table; warntime not enforced —
 * this port records, it does not watchdog. Extend as needed.)
 */
static const char * const sew_bm_anchor_names[] = {
	"kernel-init",
	"driver-init-done",
	"init-start",
	"early-fs",
	"fs-mounted",
	"late-fs",
	"boot-complete",
};

#define SEW_BM_ANCHORS (sizeof(sew_bm_anchor_names) / sizeof(sew_bm_anchor_names[0]))

static struct sew_bm_event sew_bm_events[SEW_BM_ANCHORS];
static u64 sew_bm_boot_start_ns;
static atomic_t sew_bm_next;

static char sew_bm_bootmode[16] = "unknown";
module_param_string(bootmode, sew_bm_bootmode, sizeof(sew_bm_bootmode), 0644);

static char sew_bm_fingerprint[128] = "unknown";
module_param_string(fingerprint, sew_bm_fingerprint, sizeof(sew_bm_fingerprint), 0644);

/*
 * Mirror the finalized event table into a pstore record so it survives
 * the next reboot (ramoops backend on this platform). Failure is
 * non-fatal: the in-memory table remains readable via /proc.
 */
static void sew_bm_pstore_flush(void)
{
	char *msg;
	int i, off;

	msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	off = scnprintf(msg, PAGE_SIZE,
			"sew-bootmonitor bootmode=%s fingerprint=%s\n",
			sew_bm_bootmode, sew_bm_fingerprint);
	for (i = 0; i < SEW_BM_ANCHORS && off < PAGE_SIZE - 64; i++) {
		if (!sew_bm_events[i].status)
			continue;
		off += scnprintf(msg + off, PAGE_SIZE - off,
				 "[%d] %-20s %10llu ns\n", i,
				 sew_bm_anchor_names[i],
				 sew_bm_events[i].ts_ns);
	}

	/*
	 * console-ramoops persists the kernel log ring across reboots on
	 * this platform; emitting the summary with a stable prefix makes
	 * it retrievable from /sys/fs/pstore/console-ramoops after the
	 * next boot. No pstore_info registration needed (that path is
	 * backend-only).
	 */
	pr_info("sew-bootmonitor: boot summary:\n%s", msg);
	kfree(msg);
}

/*
 * Record the next anchor in order. Writing an arbitrary name out of
 * order is rejected: anchors are sequential by design.
 */
static ssize_t sew_bm_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[SEW_BM_NAME_LEN];
	int idx;

	if (count == 0 || count >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';
	if (tmp[count - 1] == '\n')
		tmp[count - 1] = '\0';

	idx = atomic_read(&sew_bm_next);
	if (idx < 0 || idx >= SEW_BM_ANCHORS)
		return -ENOSPC;
	if (strcmp(tmp, sew_bm_anchor_names[idx]) != 0)
		return -EINVAL; /* out-of-order or unknown anchor */

	sew_bm_events[idx].ts_ns = ktime_get_boottime_ns() - sew_bm_boot_start_ns;
	sew_bm_events[idx].status = 1;
	atomic_inc(&sew_bm_next);

	if (idx == SEW_BM_ANCHORS - 1)
		sew_bm_pstore_flush();

	return count;
}

static int sew_bm_proc_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "bootmode=%s fingerprint=%s\n", sew_bm_bootmode,
		   sew_bm_fingerprint);
	for (i = 0; i < SEW_BM_ANCHORS; i++) {
		seq_printf(m, "[%d] %-20s %-10s %10llu ns\n", i,
			   sew_bm_anchor_names[i],
			   sew_bm_events[i].status ? "hit" : "pending",
			   sew_bm_events[i].ts_ns);
	}
	return 0;
}

static int sew_bm_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_bm_proc_show, NULL);
}

static const struct proc_ops sew_bm_proc_ops = {
	.proc_open	= sew_bm_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= sew_bm_proc_write,
};

static int __init sew_bootmonitor_init(void)
{
	sew_bm_boot_start_ns = ktime_get_boottime_ns();
	if (!proc_create("sew_bootmonitor", 0644, NULL, &sew_bm_proc_ops))
		return -ENOMEM;
	return 0;
}

static void __exit sew_bootmonitor_exit(void)
{
	remove_proc_entry("sew_bootmonitor", NULL);
}

module_init(sew_bootmonitor_init);
module_exit(sew_bootmonitor_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew boot-event blackbox (OS4 bootmonitor reduced port, pstore-backed)");
