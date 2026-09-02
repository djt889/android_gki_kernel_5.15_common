// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_scene_swappiness: select the reclaim swappiness value by scene.
 *
 * Hooks android_vh_tune_swappiness, which fires at both swappiness
 * decision points in mm/vmscan.c (classic-LRU get_scan_count() and the
 * MGLRU path). Both call sites pass the value they already computed;
 * a callback may rewrite it in place or leave it untouched.
 *
 * The scene is selected by writing its name to
 * /proc/sew_scene_swappiness/scene ("default"/"game"/"camera"/"browser");
 * hook counters are in /proc/sew_scene_swappiness/stats.
 *
 * PASSTHROUGH CONTRACT: scene "default" (the boot state) must never
 * write *swappiness. The additional modules set vm.swappiness=1 as the
 * standing policy; that stays authoritative only if we leave the hook
 * value untouched unless a non-default scene is explicitly armed. The
 * early return in the callback below is the coexistence lifeline.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <trace/hooks/vmscan.h>

/*
 * Scene -> swappiness table. -1 = do not intervene (passthrough).
 * This is the tuning surface: adjust values and rebuild. game=0 keeps
 * anon pages out of swap for the foreground game; camera=10 and
 * browser=20 allow mild anon reclaim to absorb allocation bursts.
 */
struct sew_scene_entry {
	const char *name;
	int swappiness;
};

static const struct sew_scene_entry sew_scenes[] = {
	{ "default",	-1 },
	{ "game",	 0 },
	{ "camera",	10 },
	{ "browser",	20 },
};

/* atomic index into sew_scenes; 0 == "default" == passthrough */
static atomic_t sew_scene_idx = ATOMIC_INIT(0);
static atomic64_t sew_stat_reads;
static atomic64_t sew_stat_tunes;

static void sew_tune_swappiness(void *data, int *swappiness)
{
	int idx;

	atomic64_inc(&sew_stat_reads);

	/* PASSTHROUGH CONTRACT (see file comment): no write to
	 * *swappiness unless a non-default scene is armed. An out-of-range
	 * index also falls through as passthrough.
	 */
	idx = atomic_read(&sew_scene_idx);
	if (idx <= 0 || idx >= (int)ARRAY_SIZE(sew_scenes))
		return;

	*swappiness = sew_scenes[idx].swappiness;
	atomic64_inc(&sew_stat_tunes);
}

static int sew_scene_show(struct seq_file *m, void *v)
{
	int idx = atomic_read(&sew_scene_idx);

	if (idx < 0 || idx >= (int)ARRAY_SIZE(sew_scenes))
		idx = 0;
	seq_printf(m, "%s %d\n", sew_scenes[idx].name,
		   sew_scenes[idx].swappiness);
	return 0;
}

static int sew_scene_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_scene_show, NULL);
}

static ssize_t sew_scene_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	char kbuf[16];
	int i, idx = -1;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	strim(kbuf);

	for (i = 0; i < (int)ARRAY_SIZE(sew_scenes); i++) {
		if (!strcmp(kbuf, sew_scenes[i].name)) {
			idx = i;
			break;
		}
	}
	if (idx < 0)
		return -EINVAL;

	atomic_set(&sew_scene_idx, idx);
	return count;
}

static const struct proc_ops sew_scene_proc_ops = {
	.proc_open	= sew_scene_open,
	.proc_read	= seq_read,
	.proc_write	= sew_scene_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int sew_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "reads: %lld\n",
		   (long long)atomic64_read(&sew_stat_reads));
	seq_printf(m, "tunes: %lld\n",
		   (long long)atomic64_read(&sew_stat_tunes));
	return 0;
}

static int sew_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_stats_show, NULL);
}

static const struct proc_ops sew_stats_proc_ops = {
	.proc_open	= sew_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *sew_proc_dir;

static int __init sew_scene_swappiness_init(void)
{
	int ret;

	ret = -ENOMEM;
	sew_proc_dir = proc_mkdir("sew_scene_swappiness", NULL);
	if (!sew_proc_dir)
		return ret;

	if (!proc_create("scene", 0644, sew_proc_dir, &sew_scene_proc_ops) ||
	    !proc_create("stats", 0444, sew_proc_dir, &sew_stats_proc_ops))
		goto err_proc;

	ret = register_trace_android_vh_tune_swappiness(sew_tune_swappiness,
							NULL);
	if (ret)
		goto err_proc;

	pr_info("sew_scene_swappiness: registered (scene=default, passthrough)\n");
	return 0;

err_proc:
	remove_proc_subtree("sew_scene_swappiness", NULL);
	return ret;
}

static void __exit sew_scene_swappiness_exit(void)
{
	unregister_trace_android_vh_tune_swappiness(sew_tune_swappiness,
						    NULL);
	/* guarantee no CPU is still inside our callback before the code
	 * goes away */
	tracepoint_synchronize_unregister();
	remove_proc_subtree("sew_scene_swappiness", NULL);
	pr_info("sew_scene_swappiness: unregistered\n");
}

module_init(sew_scene_swappiness_init);
module_exit(sew_scene_swappiness_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew scene-based reclaim swappiness tuning");
MODULE_AUTHOR("Sew");
