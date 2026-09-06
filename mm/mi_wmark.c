// SPDX-License-Identifier: GPL-2.0-only
/*
 * mi_wmark: static watermark rescale, port of the Xiaomi dada OS4
 * mi_wmark.ko ("A moudle to adjust kswapd watermark", zhouwenhao).
 *
 * RE evidence: /root/work/os4_dada/ko/mi_wmark.ko (vermagic
 * 6.6.57-android15, depends empty, no hooks, no tracepoints).
 * Raw: .omz/research/.../raw/re-mi-wmark.txt (this session).
 *
 * What the OS4 module does
 * ------------------------
 * At init: walks all pgdat zones, recomputes totalreserve_pages itself
 * (init sums free - high - (lowmem-reserve + managed) per zone into its
 * bss) and snapshots three persistent values: the adding min_free_kbytes
 * (bss+0), the adding watermark_scale_factor (bss+4) and the adding
 * extra_free_kbytes (bss+8), plus two u64 ratio slots (.data).
 * Exposes one sysfs node, extra_free_kbytes (sysfs_create_files, mode
 * parsed from the attr: store logs "extra_free_kbytes_store pid=%d,
 * comm=%s", show prints "min_free_kbytes: %d watermark_scale_factor:
 * %d extra_free_kbytes: %d").
 * On store "m n e": min_free_kbytes = m and watermark_scale_factor = n
 * (each skipped when the parsed value is -1; the disasm is pure str, no
 * add - absolute assignment, not +=); extra_free_kbytes = e.  Then it
 * recomputes every zone's _watermark array itself (the 6.6 built-in
 * pokes zone->_watermark directly; it does NOT call setup_per_zone_wmarks)
 * - i.e. it moves the MIN/LOW/HIGH waterlines themselves (kswapd wakeup
 * thresholds), not the per-allocation fast-path check.  A spinlock
 * guards the three values.
 *
 * Why this is safe where mi_reclaim's wmark_boost was not
 * --------------------------------------------------------
 * mi_reclaim raised the per-allocation MIN check at page_alloc.c:4441
 * (every allocation, ALLOC_WMARK_MIN for direct reclaim): once free sat
 * within the boost band above min, all fast-path checks failed and the
 * stress trigger re-armed forever -> reclaim livelock, removed after a
 * real-device freeze.  mi_wmark instead moves the static waterlines
 * (WMARK_MIN/LOW/HIGH via setup_per_zone_wmarks()) exactly like writing
 * /proc/sys/vm/min_free_kbytes by hand: the fast-path margin shrinks
 * uniformly, kswapd wakes earlier, and there is no self-re-arming
 * feedback (direct reclaim keeps allocating from min upward).  Same
 * safety profile as the proc knob admins already use.
 *
 * Sew 5.15 port ([PORT-DELTA] items marked)
 * -----------------------------------------
 * - The 6.6 binary pokes kernel data directly (min_free_kbytes_,
 *   watermark_scale_factor_, its own extra_free_kbytes).  The 5.15 GKI
 *   tree keeps none of {min_free_kbytes, watermark_scale_factor,
 *   user_min_free_kbytes, setup_per_zone_wmarks} in ksymtab (verified:
 *   T/D in vmlinux, zero EXPORT_SYMBOL), so a loadable module cannot
 *   link.  This port therefore can only work BUILT-IN (=y): it reads
 *   and writes the in-tree variables directly.  If built as a module
 *   the link fails at modpost - that is the guard, not a bug.
 * - setup_per_zone_wmarks() is called after every change, exactly like
 *   the proc sysctl handlers (min_free_kbytes_sysctl_handler /
 *   watermark_scale_factor_sysctl_handler in 5.15 mm/page_alloc.c), so
 *   zone->_watermark[], totalreserve_pages and the stat thresholds stay
 *   consistent.
 * - -1 means "leave unchanged" per parsed slot (6.6 cmn #-1 checks);
 *   the store still recomputes watermarks unconditionally (6.6 does).
 * - extra_free_kbytes is stored but has no further consumer on 5.15:
 *   the 6.6 binary computes two u64 ratio slots (.data) but no caller
 *   of the shown store path consumes them (no accounting hook on 5.15
 *   to feed).  Kept as a reported value for userspace parity.
 * - Node name kept: /sys/kernel/mi_wmark/extra_free_kbytes.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/mm.h>

/* in-tree page_alloc.c state (built-in only: no ksymtab exports) */
extern int min_free_kbytes;
extern int watermark_scale_factor;
extern void setup_per_zone_wmarks(void);

static int mi_extra_free_kbytes;
static DEFINE_SPINLOCK(mi_wmark_lock);

static ssize_t extra_free_kbytes_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	int mfk, wsf, efk;
	unsigned long flags;

	spin_lock_irqsave(&mi_wmark_lock, flags);
	mfk = min_free_kbytes;
	wsf = watermark_scale_factor;
	efk = mi_extra_free_kbytes;
	spin_unlock_irqrestore(&mi_wmark_lock, flags);

	return sysfs_emit(buf, "min_free_kbytes: %d watermark_scale_factor:"
			       " %d extra_free_kbytes: %d\n", mfk, wsf, efk);
}

static ssize_t extra_free_kbytes_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int m = -1, n = -1, e = -1;
	unsigned long flags;
	int rc;

	rc = sscanf(buf, "%d %d %d", &m, &n, &e);
	if (rc != 3 && rc != 1)
		return -EINVAL;

	pr_info("extra_free_kbytes_store pid=%d, comm=%s",
		task_pid_nr(current), current->comm);

	spin_lock_irqsave(&mi_wmark_lock, flags);
	if (m != -1)
		min_free_kbytes = m;
	if (n != -1)
		watermark_scale_factor = n;
	if (e != -1)
		mi_extra_free_kbytes = e;
	spin_unlock_irqrestore(&mi_wmark_lock, flags);

	/*
	 * [PORT-DELTA] the 6.6 built-in recomputes zone->_watermark[]
	 * inline; on 5.15 the correct equivalent is setup_per_zone_wmarks()
	 * (what both proc sysctl handlers call) - it also refreshes
	 * totalreserve_pages and the stat thresholds, so the waterlines
	 * stay consistent with the rest of the VM.
	 */
	setup_per_zone_wmarks();
	return count;
}

static struct kobj_attribute mi_extra_free_kbytes_attr =
	__ATTR(extra_free_kbytes, 0644,
	       extra_free_kbytes_show, extra_free_kbytes_store);

static struct attribute *mi_wmark_attrs[] = {
	&mi_extra_free_kbytes_attr.attr,
	NULL,
};

static const struct attribute_group mi_wmark_attr_group = {
	.attrs = mi_wmark_attrs,
};

static struct kobject *mi_wmark_kobj;

static int __init mi_wmark_init(void)
{
	int ret;

	mi_wmark_kobj = kobject_create_and_add("mi_wmark", kernel_kobj);
	if (!mi_wmark_kobj) {
		pr_err("failed to create mi_wmark node.\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(mi_wmark_kobj, &mi_wmark_attr_group);
	if (ret) {
		pr_err("failed to create mi_wmark attrs.\n");
		kobject_put(mi_wmark_kobj);
		mi_wmark_kobj = NULL;
		return ret;
	}

	pr_info("mi_wmark init ok.\n");
	return 0;
}

static void __exit mi_wmark_exit(void)
{
	sysfs_remove_group(mi_wmark_kobj, &mi_wmark_attr_group);
	kobject_put(mi_wmark_kobj);
	mi_wmark_kobj = NULL;
}

module_init(mi_wmark_init);
module_exit(mi_wmark_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhouwenhao");
MODULE_DESCRIPTION("Sew port of the Xiaomi OS4 mi_wmark (static kswapd watermark rescale)");
