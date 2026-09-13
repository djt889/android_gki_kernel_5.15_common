// SPDX-License-Identifier: GPL-2.0-only
/*
 * bootmonitor: boot-event logger, reduced port of the Xiaomi OS4
 * bootmonitor module (drivers/xiaomi/bootmonitor in dada-v-oss).
 *
 * What is kept from the original: the ordered boot-event anchor model
 * and the bootmode/fingerprint stamping from module params. The anchor
 * table below is a RENAMED, shorter table inspired by the original
 * (the OS4 table is early-init/late-init/late-fs/zygote-start/.../
 * boot_completed in boot_monitor.c:31-41); names here match what a
 * GKI ramdisk init.rc can realistically report.
 *
 * What is deliberately NOT ported (D5 decision, see C3 plan s3.2):
 * the DT /reserved-memory resource probe ("xiaomi,bootmonitor_pmsg"
 * node absent on nuwa/vermeer/fuxi), the raw blackbox-partition
 * block-device writer, the monitor_main kthread timeout watchdog
 * (this port records, it does not watchdog), and the netlink RECEIVE
 * command face. Persistence is MUCH weaker than the original
 * blackbox: the summary is emitted via pr_info into the kernel log
 * ring, and console-ramoops (enabled in this kernel) persists only
 * the TAIL of that ring across a reboot. In practice: a boot-loop or
 * a reboot shortly after boot keeps the summary; a long-running
 * session that reboots may have evicted it. A failed boot that never
 * reaches the last anchor also produces no summary at all - the
 * per-anchor hits are still visible in the console log itself.
 *
 * Built as a module the anchor timestamps are relative to modprobe
 * time, not kernel start: use CONFIG_BOOTMONITOR=y for real
 * kernel-relative timings.
 *
 * Interfaces: /proc/bootmonitor (read the anchor table, write
 * anchor names strictly in order), module params bootmode/fingerprint.
 *
 * D5 addition - netlink SEND face (default unit 30, module param
 * netlink_unit to override; official bootmonitor used 31 but that unit
 * is owned by millet_core on this tree, see below): when the final
 * anchor ("boot-complete") is hit, a
 * text summary of the anchor table is unicast to the last-registered
 * userspace pid (learned from the receive path below). Best effort
 * only: no listener means no send, no queueing, no retransmit; the
 * /proc table and the console-ramoops summary remain authoritative.
 *
 * D5 addition - netlink RECEIVE face (minimal registration only):
 * the input hook accepts a payload of at least 16 bytes from userspace
 * and records NETLINK_CB(skb).portid as the unicast target; shorter
 * payloads are dropped (official semantic, nl_data_ready compares the
 * length against 16). No commands are interpreted - any other incoming
 * content is ignored after pid registration.
 *
 * D5 addition - boottime reconnect: when CONFIG_MI_BOOT_TIME is set,
 * the summary lines (proc show, pstore flush, netlink unicast) carry
 * the boottime log_count via extern get_log_count(). The link is
 * read-only and non-blocking: the extern is guarded by ifdef, never
 * hard-required, so CONFIG_BOOTMONITOR without CONFIG_MI_BOOT_TIME
 * still builds.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/netlink.h>

/*
 * Netlink unit: the official bootmonitor (bm_netlink_init "mov w1, #0x1f")
 * uses 31, but unit 31 on this tree is owned by millet_core
 * (drivers/xiaomi/millet/millet_core.c MILLET_NETLINK_UNIT=31, kept for
 * vendor-daemon protocol compat - that side must NOT move). Two kernel
 * sockets cannot share one unit (the second netlink_kernel_create fails
 * on the portid-0 insert), so bootmonitor defaults to 30: the highest
 * unit free in-tree (23-30 all unused; upstream assigns upward from
 * NETLINK_SMC=22, so 30 sits farthest from future collisions).
 * Override with netlink_unit=<0-31> if the board needs otherwise.
 */
#define SEW_BM_NETLINK_UNIT_DEFAULT	30
static int sew_bm_netlink_unit = SEW_BM_NETLINK_UNIT_DEFAULT;
module_param_named(netlink_unit, sew_bm_netlink_unit, int, 0444);
MODULE_PARM_DESC(netlink_unit, "netlink unit for bootmonitor unicast (default 30; 31 is owned by millet_core)");
/* Official alloc: bm_sendnlmsg __alloc_skb(144, GFP_KERNEL|__GFP_ZERO). */
#define SEW_BM_NLMSG_SIZE	144
/* Official gate: nl_data_ready drops payloads shorter than 16 bytes. */
#define SEW_BM_NLREG_MINLEN	16

#define SEW_BM_EVENTS_MAX	32
#define SEW_BM_NAME_LEN		32

struct sew_bm_event {
	char	name[SEW_BM_NAME_LEN];
	u64	ts_ns;		/* 0 = not yet reached */
	int	status;		/* 0 pending, 1 hit */
};

/*
 * Boot-event anchors (renamed table inspired by the OS4 original;
 * warntime not enforced - this port records, it does not watchdog.
 * Extend as needed.)
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

/* ---- boottime reconnect (read-only, optional) ---- */
#ifdef CONFIG_MI_BOOT_TIME
extern unsigned long get_log_count(void);
#endif

static unsigned long sew_bm_boottime_logcount(void)
{
#ifdef CONFIG_MI_BOOT_TIME
	return get_log_count();
#else
	return 0;
#endif
}

/* ---- netlink send/receive face ---- */
static struct sock *sew_bm_nl_sk;
static u32 sew_bm_nl_pid; /* last-registered userspace portid, 0 = none */
/* Serializes nl_sk/nl_pid access against concurrent anchor writes. */
static DEFINE_MUTEX(sew_bm_nl_lock);

/*
 * Minimal receive face: register the sender portid when the payload
 * is at least 16 bytes (official gate), otherwise drop. The skb is
 * NEVER freed here: af_netlink keeps ownership - netlink_unicast_kernel
 * calls consume_skb(skb) unconditionally after the input hook returns,
 * so freeing here would double-free (cf. millet_recv_handler, which
 * correctly never frees). Runs in netlink softirq context - take no
 * sleeping locks here and
 * do no blocking allocation. A mutex in softirq context would risk
 * deadlock, so pid registration uses WRITE_ONCE/READ_ONCE only; the
 * proc show path reads it the same way.
 */
static void sew_bm_nl_recv(struct sk_buff *skb)
{
	u32 pid;

	if (!skb)
		return;
	if (skb->len < SEW_BM_NLREG_MINLEN) {
		pr_info("sew-bootmonitor: netlink socket, pid =%d, msg = %d\n",
			NETLINK_CB(skb).portid, skb->len);
		return;
	}
	pid = NETLINK_CB(skb).portid;
	WRITE_ONCE(sew_bm_nl_pid, pid);
	pr_info("sew-bootmonitor: netlink socket, pid =%d, msg = %d\n",
		pid, skb->len);
}

/*
 * Unicast a NUL-terminated text message to the registered pid.
 * No-op when no pid registered or the socket is gone. Best effort:
 * allocation or unicast failures are logged and dropped, never
 * retried. Called from process context (proc write), may sleep.
 */
static void sew_bm_nl_send(const char *msg)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	size_t len;
	u32 pid;
	struct sock *sk;
	int ret;

	if (!msg)
		return;

	mutex_lock(&sew_bm_nl_lock);
	sk = sew_bm_nl_sk;
	pid = READ_ONCE(sew_bm_nl_pid);
	mutex_unlock(&sew_bm_nl_lock);

	if (!sk || !pid)
		return;

	len = strlen(msg) + 1;
	if (len > SEW_BM_NLMSG_SIZE)
		len = SEW_BM_NLMSG_SIZE;

	skb = nlmsg_new(len, GFP_KERNEL);
	if (!skb) {
		pr_err("sew-bootmonitor: alloc_skb error\n");
		return;
	}
	nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, len, 0);
	if (!nlh) {
		nlmsg_free(skb);
		pr_err("sew-bootmonitor: nlmsg_put error\n");
		return;
	}
	memcpy(nlmsg_data(nlh), msg, len);
	((char *)nlmsg_data(nlh))[len - 1] = 0;

	ret = netlink_unicast(sk, skb, pid, MSG_DONTWAIT);
	if (ret < 0)
		pr_err("sew-bootmonitor: send msg from kernel to userspace failed ret 0x%x\n",
		       ret);
	else
		pr_info("sew-bootmonitor: netlink unicast %zu bytes to pid %u\n",
			len, pid);
}

static int sew_bm_nl_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input	= sew_bm_nl_recv,
	};

	/* 32 == MAX_LINKS; a bad value must not fail module load. */
	if (sew_bm_netlink_unit < 0 || sew_bm_netlink_unit >= 32) {
		pr_warn("sew-bootmonitor: bad netlink unit %d (want 0-31), netlink down; pass netlink_unit=<0-31>\n",
			sew_bm_netlink_unit);
		return 0; /* non-fatal: proc/pstore faces still work */
	}
	if (sew_bm_netlink_unit == 31)
		pr_warn("sew-bootmonitor: netlink unit 31 is owned by millet_core (vendor daemon compat), create will likely fail; use netlink_unit=<other>\n");
	sew_bm_nl_sk = netlink_kernel_create(&init_net, sew_bm_netlink_unit,
					    &cfg);
	if (!sew_bm_nl_sk) {
		pr_warn("sew-bootmonitor: create netlink socket error (unit %d conflict?), netlink down but proc/pstore faces still work\n",
			sew_bm_netlink_unit);
		return 0; /* non-fatal: proc/pstore faces still work */
	}
	pr_info("sew-bootmonitor: netlink up on unit %d\n", sew_bm_netlink_unit);
	return 0;
}

static void sew_bm_nl_exit(void)
{
	struct sock *sk;

	mutex_lock(&sew_bm_nl_lock);
	sk = sew_bm_nl_sk;
	sew_bm_nl_sk = NULL;
	WRITE_ONCE(sew_bm_nl_pid, 0);
	mutex_unlock(&sew_bm_nl_lock);

	if (sk)
		netlink_kernel_release(sk);
}

/*
 * Render the one-shot summary text shared by the pstore flush and the
 * netlink unicast. Returns a buffer the caller frees, or NULL when the
 * allocation fails.
 */
static char *sew_bm_build_summary(void)
{
	char *msg;
	int i, off;

	msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!msg)
		return NULL;

	off = scnprintf(msg, PAGE_SIZE,
			"sew-bootmonitor: bootmode=%s fingerprint=%s bootprof_logcount=%lu\n",
			sew_bm_bootmode, sew_bm_fingerprint,
			sew_bm_boottime_logcount());
	for (i = 0; i < SEW_BM_ANCHORS && off < PAGE_SIZE - 64; i++) {
		if (!sew_bm_events[i].status)
			continue;
		off += scnprintf(msg + off, PAGE_SIZE - off,
				 "sew-bootmonitor: [%d] %-20s %10llu ns\n", i,
				 sew_bm_anchor_names[i],
				 sew_bm_events[i].ts_ns);
	}
	return msg;
}

/*
 * Mirror the finalized event table into the kernel log ring so it survives
 * the next reboot (console-ramoops tail on this platform). Failure is
 * non-fatal: the in-memory table remains readable via /proc.
 */
static void sew_bm_pstore_flush(void)
{
	char *msg = sew_bm_build_summary();

	if (!msg)
		return;
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
/* Serializes anchor writes; init is the only expected writer, but a
 * stray second writer must not be able to double-advance the index.
 */
static DEFINE_MUTEX(sew_bm_write_lock);

static ssize_t sew_bm_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[SEW_BM_NAME_LEN];
	int idx;
	bool last = false;

	if (count == 0 || count >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';
	if (tmp[count - 1] == '\n')
		tmp[count - 1] = '\0';

	mutex_lock(&sew_bm_write_lock);
	idx = atomic_read(&sew_bm_next);
	if (idx < 0 || idx >= SEW_BM_ANCHORS) {
		mutex_unlock(&sew_bm_write_lock);
		return -ENOSPC;
	}
	if (strcmp(tmp, sew_bm_anchor_names[idx]) != 0) {
		mutex_unlock(&sew_bm_write_lock);
		return -EINVAL; /* out-of-order or unknown anchor */
	}

	sew_bm_events[idx].ts_ns = ktime_get_boottime_ns() - sew_bm_boot_start_ns;
	sew_bm_events[idx].status = 1;
	atomic_inc(&sew_bm_next);
	last = (idx == SEW_BM_ANCHORS - 1);
	mutex_unlock(&sew_bm_write_lock);

	/*
	 * Final anchor: emit the ramoops summary and unicast it via
	 * netlink (best effort). All sleepable work happens outside
	 * both locks, so concurrent writers cannot deadlock here.
	 */
	if (last) {
		char *summary = sew_bm_build_summary();

		if (summary) {
			pr_info("sew-bootmonitor: boot summary:\n%s", summary);
			sew_bm_nl_send(summary);
			kfree(summary);
		}
	}

	return count;
}

static int sew_bm_proc_show(struct seq_file *m, void *v)
{
	int i;
	u32 pid;

	seq_printf(m, "bootmode=%s fingerprint=%s bootprof_logcount=%lu\n",
		   sew_bm_bootmode, sew_bm_fingerprint,
		   sew_bm_boottime_logcount());
	for (i = 0; i < SEW_BM_ANCHORS; i++) {
		seq_printf(m, "[%d] %-20s %-10s %10llu ns\n", i,
			   sew_bm_anchor_names[i],
			   sew_bm_events[i].status ? "hit" : "pending",
			   sew_bm_events[i].ts_ns);
	}
	pid = READ_ONCE(sew_bm_nl_pid);
	mutex_lock(&sew_bm_nl_lock);
	seq_printf(m, "netlink: unit=%d pid=%u %s\n", sew_bm_netlink_unit,
		   pid, sew_bm_nl_sk ? "up" : "down");
	mutex_unlock(&sew_bm_nl_lock);
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

static int __init sew_bm_init(void)
{
	sew_bm_boot_start_ns = ktime_get_boottime_ns();
	if (!proc_create("bootmonitor", 0644, NULL, &sew_bm_proc_ops))
		return -ENOMEM;
	sew_bm_nl_init(); /* best effort: never fails module load */
	return 0;
}

static void __exit sew_bm_exit(void)
{
	/*
	 * Partial-table bailout: if the module is unloaded (manual or
	 * debug rmmod) before the last anchor was hit, emit whatever was
	 * recorded so the console-ramoops tail at least carries it.
	 */
	if (atomic_read(&sew_bm_next) < SEW_BM_ANCHORS) {
		mutex_lock(&sew_bm_write_lock);
		sew_bm_pstore_flush();
		mutex_unlock(&sew_bm_write_lock);
	}
	sew_bm_nl_exit();
	remove_proc_entry("bootmonitor", NULL);
}

module_init(sew_bm_init);
module_exit(sew_bm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew boot-event logger (OS4 bootmonitor reduced port, console-ramoops-tailed, netlink send face)");
