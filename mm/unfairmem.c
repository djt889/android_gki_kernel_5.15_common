// SPDX-License-Identifier: GPL-2.0-only
/*
 * unfairmem: Xiaomi OS4 "adjust min watermark for important task" port.
 *
 * Official interface shape (recovered from dada 0.8 unfairmem.ko, 42400 B;
 * full disassembly evidence in G5-unfairmem.md):
 *   /proc/mi_mem_engine            proc dir (mimem_rootdir)
 *   /proc/mi_mem_engine/scene_tid  scene mode + pid list (0644)
 *   /proc/mi_mem_engine/sf_pid     surfaceflinger pid (0644)
 * Hook: android_vh_get_page_wmark (mi_get_page_wmark_boost). The shrink
 * side (official try_shrink_skip) is NOT registered here: mm/slabd.c
 * consumes the only 5.15 shrink hook and the VIP check is merged into its
 * callback via slabd_vip_check below (single-consumer discipline; avoids
 * double registration and matches the same pid set).
 *
 * Legacy compat: /proc/unfair_mem and /proc/sew_unfairmem keep the old
 * single-node "sf_pid %d / scene_tid %d / relax_pct %u" format and share
 * the same storage (dual-name compat, see DIVERGENCE NOTEs).
 *
 * DIVERGENCE NOTE 1 (scene write arity): official scene_tid_write runs a
 * second multi-%d sscanf and returns -EINVAL when fewer than 2 pids follow
 * the mode (a bare "1" fails). Ours accepts "mode [pid...]": mode-only
 * writes stage the previous sf pid into slot 0 instead of failing, so the
 * addon control plane cannot wedge itself with a simple write.
 * DIVERGENCE NOTE 2 (relax_pct): official has no relax knob (fixed
 * x0.75/x0.875/x1.125 factors). The legacy relax_pct (default 50) is kept
 * as an upper bound on the total reduction only; at default 50 it never
 * binds, so default behaviour is bit-identical to official.
 * DIVERGENCE NOTE 3 (legacy kick): the legacy contract is "these tasks get
 * relaxed watermarks". A legacy write that installs a nonzero identity
 * while boost is UNDEFINE lifts boost to APP_START_EXIT_MIN_BOOST, because
 * official UNDEFINE *pressures every task* (mark x1.125, matched or not;
 * 1/2 is what creates the VIP-vs-others unfair gap) and would otherwise
 * invert the legacy promise. Official nodes are unaffected.
 * DIVERGENCE NOTE 4 (exit cleanup): official cleanup_module shows no proc
 * removal; ours removes all five entries (no residue, no leak).
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <trace/hooks/mm.h>

#define SEW_UNFAIRMEM_PID_SLOTS	6
#define SEW_UNFAIRMEM_WRITE_MAX	126	/* official: count > 0x7e rejected */

enum {
	SEW_BOOST_UNDEFINE = 0,
	SEW_BOOST_APP_START_EXIT = 1,	/* official APP_START_EXIT_MIN_BOOST */
	SEW_BOOST_APP_SCROLL = 2,		/* official APP_SCROLL_MIN_BOOST */
};

static struct proc_dir_entry *sew_mimem_rootdir;
/*
 * Default BOOST_APP_START_EXIT (1) instead of the official 0.
 *
 * Rationale (decision 2026-09-12): with flag 0 every task is pressured
 * x1.125 uniformly (official UNDEFINE semantics), which yields no VIP
 * advantage at all -- the whole point of unfairmem is to relax the VIP
 * (SurfaceFlinger / render threads) so it keeps its allocations during
 * a scene. The addon already writes sf_pid, so flag 1 makes the module
 * effective out of the box with no extra userspace.
 *
 * Power/background note: relative to flag 0 this is neutral-to-better --
 * the only difference is that the VIP stops being pressured; every
 * non-VIP task sees exactly the same x1.125 as before. Higher watermarks
 * mean earlier reclaim, which keeps free memory higher and therefore
 * gives LMKD *less* reason to kill cached apps.
 */
static int boost_flag = SEW_BOOST_APP_START_EXIT;

static pid_t sew_pid_array[SEW_UNFAIRMEM_PID_SLOTS];
static pid_t sew_msf_pid;

/* Legacy relax knob: upper bound (percent) on watermark reduction. */
static unsigned int sew_unfair_relax_pct = 50;

/*
 * VIP check for mm/slabd.c, registered through the slabd_vip_check
 * function pointer (slabd is built-in; direct symbol reference would
 * not link when this is a module). Matches the official hook/try_shrink
 * pid set: msf_pid plus every nonzero pid_array slot, by pid or tgid.
 * Used by the slab side and (negatively) by the wmark side: the wmark
 * hook relaxes only matched VIPs and pressures everyone else (see
 * sew_unfair_wmark). Lockless by design (official uses plain accesses
 * too); WRITE_ONCE on the store side and READ_ONCE here keep it
 * race-sane.
 */
static bool sew_unfair_mem_is_vip(struct task_struct *t)
{
	pid_t pid, tgid, slot;
	int i;

	if (!t)
		return false;
	pid = t->pid;
	tgid = task_tgid_nr(t);
	slot = READ_ONCE(sew_msf_pid);
	if (slot && (slot == pid || slot == tgid))
		return true;
	for (i = 0; i < SEW_UNFAIRMEM_PID_SLOTS; i++) {
		slot = READ_ONCE(sew_pid_array[i]);
		if (slot && (slot == pid || slot == tgid))
			return true;
	}
	return false;
}

/*
 * Official semantics (mi_get_page_wmark_boost disassembly): flag 0 or >=3
 * pressures EVERY task (mark x1.125, no pid lookup); flag 1/2 relaxes only
 * the pid-matched VIP (x0.75 / x0.875) and pressures everyone else
 * (x1.125). Runs on the alloc path: lockless, no sleep, no allocation
 * (READ_ONCE only).
 */
static void sew_unfair_wmark(void *data, unsigned int alloc_flags,
			     unsigned long *page_wmark)
{
	unsigned long mark, out, floor;
	unsigned int flag, pct;

	if (!page_wmark)
		return;

	mark = *page_wmark;
	flag = READ_ONCE(boost_flag);
	if ((flag == SEW_BOOST_APP_START_EXIT || flag == SEW_BOOST_APP_SCROLL) &&
	    sew_unfair_mem_is_vip(current)) {
		/* matched VIP: relax by flag. */
		out = (flag == SEW_BOOST_APP_START_EXIT) ? mark - (mark >> 2)
						      : mark - (mark >> 3);
		/* Legacy cap bounds reductions only (see NOTE 2). */
		pct = READ_ONCE(sew_unfair_relax_pct);
		floor = mark - mark * pct / 100;
		if (out < floor)
			out = floor;
	} else {
		/* x1.125: flag 0/>=3, or flag 1/2 with no pid match. */
		out = mark + (mark >> 3);
	}
	*page_wmark = out;
}

/* ---- /proc/mi_mem_engine/scene_tid ---- */

static int mimem_scene_show(struct seq_file *m, void *v)
{
	int i;
	pid_t slot;

	seq_printf(m, "BOOST_SCENE: %d\n", READ_ONCE(boost_flag));
	seq_printf(m, "%lu PID Array:\n", (unsigned long)SEW_UNFAIRMEM_PID_SLOTS);
	for (i = 0; i < SEW_UNFAIRMEM_PID_SLOTS; i++) {
		slot = READ_ONCE(sew_pid_array[i]);
		if (slot)
			seq_printf(m, "%d", slot);
	}
	seq_printf(m, "\n");
	return 0;
}

static int mimem_scene_open(struct inode *inode, struct file *file)
{
	return single_open(file, mimem_scene_show, NULL);
}

static ssize_t mimem_scene_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[SEW_UNFAIRMEM_WRITE_MAX + 2];
	int mode, n, i;
	pid_t pids[SEW_UNFAIRMEM_PID_SLOTS];

	if (count > SEW_UNFAIRMEM_WRITE_MAX)
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';

	if (sscanf(tmp, "%d", &mode) != 1)
		return -EINVAL;
	if (mode < SEW_BOOST_UNDEFINE || mode > SEW_BOOST_APP_SCROLL)
		return -EINVAL;
	WRITE_ONCE(boost_flag, mode);

	n = sscanf(tmp, "%d %d %d %d %d %d %d", &mode,
		   &pids[0], &pids[1], &pids[2],
		   &pids[3], &pids[4], &pids[5]);
	for (i = 0; i < SEW_UNFAIRMEM_PID_SLOTS; i++)
		WRITE_ONCE(sew_pid_array[i], 0);
	if (n >= 2) {
		for (i = 0; i < n - 1 && i < SEW_UNFAIRMEM_PID_SLOTS; i++) {
			if (pids[i] < 0)
				pids[i] = 0;
			WRITE_ONCE(sew_pid_array[i], pids[i]);
		}
	} else if (mode != SEW_BOOST_UNDEFINE && READ_ONCE(sew_msf_pid)) {
		/* Mode-only write: stage previous sf pid (see NOTE 1). */
		WRITE_ONCE(sew_pid_array[0], READ_ONCE(sew_msf_pid));
	}
	return count;
}

static const struct proc_ops mimem_scene_proc_ops = {
	.proc_open	= mimem_scene_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= mimem_scene_write,
};

/* ---- /proc/mi_mem_engine/sf_pid ---- */

static int mimem_sf_pid_show(struct seq_file *m, void *v)
{
	seq_printf(m, "surfaceflinger PID :\n");
	seq_printf(m, "%d", READ_ONCE(sew_msf_pid));
	seq_printf(m, "\n");
	return 0;
}

static int mimem_sf_pid_open(struct inode *inode, struct file *file)
{
	return single_open(file, mimem_sf_pid_show, NULL);
}

static ssize_t mimem_sf_pid_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char tmp[SEW_UNFAIRMEM_WRITE_MAX + 2];
	pid_t pid;

	if (count > SEW_UNFAIRMEM_WRITE_MAX)
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';

	if (sscanf(tmp, "%d", &pid) != 1)
		return -EINVAL;
	if (pid < 0)
		return -EINVAL;
	WRITE_ONCE(sew_msf_pid, pid);
	return count;
}

static const struct proc_ops mimem_sf_pid_proc_ops = {
	.proc_open	= mimem_sf_pid_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= mimem_sf_pid_write,
};

/* ---- legacy compat: /proc/unfair_mem + /proc/sew_unfairmem ---- */

static int sew_unfair_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "sf_pid=%d\nscene_tid=%d\nrelax_pct=%u\n",
		   READ_ONCE(sew_msf_pid), READ_ONCE(sew_pid_array[0]),
		   READ_ONCE(sew_unfair_relax_pct));
	return 0;
}

static int sew_unfair_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_unfair_proc_show, NULL);
}

static ssize_t sew_unfair_proc_write(struct file *file,
				     const char __user *buf, size_t count,
				     loff_t *ppos)
{
	char tmp[64];
	long val;
	int field;

	if (count >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';

	if (sscanf(tmp, "sf_pid %ld", &val) == 1)
		field = 0;
	else if (sscanf(tmp, "scene_tid %ld", &val) == 1)
		field = 1;
	else if (sscanf(tmp, "relax_pct %ld", &val) == 1)
		field = 2;
	else
		return -EINVAL;

	switch (field) {
	/*
	 * pid_max is not exported to modules on 5.15; pid_t is a signed
	 * int and the hook side re-checks against real tasks, so a plain
	 * non-negative bound is enough here.
	 */
	case 0:
		if (val < 0)
			return -EINVAL;
		WRITE_ONCE(sew_msf_pid, (pid_t)val);
		if (val && READ_ONCE(boost_flag) == SEW_BOOST_UNDEFINE)
			WRITE_ONCE(boost_flag, SEW_BOOST_APP_START_EXIT);
		break;
	case 1:
		if (val < 0)
			return -EINVAL;
		WRITE_ONCE(sew_pid_array[0], (pid_t)val);
		if (val && READ_ONCE(boost_flag) == SEW_BOOST_UNDEFINE)
			WRITE_ONCE(boost_flag, SEW_BOOST_APP_START_EXIT);
		break;
	case 2:
		if (val < 0 || val > 50)
			return -EINVAL;
		WRITE_ONCE(sew_unfair_relax_pct, (unsigned int)val);
		break;
	}
	return count;
}

static const struct proc_ops sew_unfair_proc_ops = {
	.proc_open	= sew_unfair_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= sew_unfair_proc_write,
};

extern bool (*slabd_vip_check)(struct task_struct *t);

static int __init sew_unfair_mem_init(void)
{
	int ret;

	sew_mimem_rootdir = proc_mkdir("mi_mem_engine", NULL);
	if (!sew_mimem_rootdir)
		return -ENOMEM;
	if (!proc_create("scene_tid", 0644, sew_mimem_rootdir,
			 &mimem_scene_proc_ops)) {
		pr_err("unfair_mem: create /proc/mi_mem_engine/scene_tid failed\n");
		goto err_dir;
	}
	if (!proc_create("sf_pid", 0644, sew_mimem_rootdir,
			 &mimem_sf_pid_proc_ops)) {
		pr_err("unfair_mem: create /proc/mi_mem_engine/sf_pid failed\n");
		goto err_scene;
	}
	if (!proc_create("unfair_mem", 0644, NULL, &sew_unfair_proc_ops))
		goto err_sf;
	if (!proc_create("sew_unfairmem", 0644, NULL, &sew_unfair_proc_ops))
		goto err_legacy;
	ret = register_trace_android_vh_get_page_wmark(sew_unfair_wmark, NULL);
	if (ret) {
		int hook_ret = ret;
		remove_proc_entry("sew_unfairmem", NULL);
		remove_proc_entry("unfair_mem", NULL);
		remove_proc_entry("sf_pid", sew_mimem_rootdir);
		remove_proc_entry("scene_tid", sew_mimem_rootdir);
		remove_proc_entry("mi_mem_engine", NULL);
		return hook_ret;
	}
	WRITE_ONCE(slabd_vip_check, sew_unfair_mem_is_vip);
	return 0;

err_legacy:
	remove_proc_entry("unfair_mem", NULL);
err_sf:
	remove_proc_entry("sf_pid", sew_mimem_rootdir);
err_scene:
	remove_proc_entry("scene_tid", sew_mimem_rootdir);
err_dir:
	remove_proc_entry("mi_mem_engine", NULL);
	return -ENOMEM;
}

static void __exit sew_unfair_mem_exit(void)
{
	WRITE_ONCE(slabd_vip_check, NULL);
	unregister_trace_android_vh_get_page_wmark(sew_unfair_wmark, NULL);
	tracepoint_synchronize_unregister();
	remove_proc_entry("sew_unfairmem", NULL);
	remove_proc_entry("unfair_mem", NULL);
	remove_proc_entry("sf_pid", sew_mimem_rootdir);
	remove_proc_entry("scene_tid", sew_mimem_rootdir);
	remove_proc_entry("mi_mem_engine", NULL);
}

module_init(sew_unfair_mem_init);
module_exit(sew_unfair_mem_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew unfairmem: bounded watermark relax for flagged (sf/scene) tasks");
MODULE_AUTHOR("huzhongyang");
