// SPDX-License-Identifier: GPL-2.0-only
/*
 * MI rmap efficiency: protect high-mapcount pages from reclaim.
 *
 * Faithful port of Xiaomi's mi_rmap_efficiency module (piano-w-oss branch,
 * drivers/staging/mi_rmap_efficiency/mi_rmap_efficiency.c) adapted to this
 * 5.15 kernel's page-based vmscan and the page-based
 * android_vh_page_should_be_protected hook.
 *
 * Core logic preserved 1:1:
 *  - mapcount >= mi_mapcount_thres (32)  -> ACTIVATE (protect, rotate)
 *  - mapcount >= dynamic keep threshold  -> KEEP    (protect, no rotate)
 *  - otherwise                           -> RECLAIM
 *  - nr_skipped accounting, reset when nr_scanned < nr_skipped
 *  - "too many skipped" guard flips to RECLAIM so a pathological workload
 *    cannot starve reclaim.
 *
 * The original uses folio_mapcount()/folio_nr_pages(); this port uses
 * page_mapcount()/thp_nr_pages() because this kernel (5.15.211) has no folio
 * subsystem. vmscan passes the compound head for THP, so page_mapcount(head)
 * is equivalent to folio_mapcount() for the THP head. nr_skipped state is
 * carried in scan_control::android_vendor_data1 (added for this hook).
 *
 * Unlike the original module, the sysfs controls are attached to
 * /sys/kernel/ (kernel_kobj) since a built-in has no THIS_MODULE kobject.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mmzone.h>
#include <linux/sysfs.h>
#include <linux/swap.h>
#include <trace/hooks/mm.h>

/* Same values as the original enum; vmscan only tests != 0. */
enum mi_page_references {
	MI_PAGEREF_RECLAIM,
	MI_PAGEREF_RECLAIM_CLEAN,
	MI_PAGEREF_KEEP,
	MI_PAGEREF_ACTIVATE,
};

static unsigned int mi_mapcount_thres __read_mostly = 32;
static bool mi_rmap_efficiency_setup __read_mostly = true;
static struct kobject *kobj;

#define MI_TOO_MANY_SKIPPED_SHIFT 4
#define MI_SKIP_THRES_MIN 3
#define MI_SKIP_THRES_LOW 2
#define MI_SKIP_THRES_HIGH 1

static int get_dynamic_mapcount_thres(s8 priority)
{
	if (priority <= DEF_PRIORITY / 4)
		return max(mi_mapcount_thres >> MI_SKIP_THRES_MIN, 2u);
	else if (priority <= DEF_PRIORITY / 2)
		return max(mi_mapcount_thres >> MI_SKIP_THRES_LOW, 2u);
	else
		return max(mi_mapcount_thres >> MI_SKIP_THRES_HIGH, 2u);
}

static void mi_check_mapcount(void *data, struct page *page,
			      unsigned long nr_scanned, s8 priority,
			      u64 *ext, int *should_protect)
{
	unsigned int nr_pages;
	unsigned long *nr_skipped = (unsigned long *)ext;
	int mapcount = 0;
	int activate_thres = 0;
	int keep_thres = 0;
	bool too_many_skipped = false;

	if (unlikely(!page || !nr_skipped || !should_protect))
		return;

	if (!mi_rmap_efficiency_setup) {
		*should_protect = MI_PAGEREF_RECLAIM;
		return;
	}

	/*
	 * Reset the skipped page counter if the number of scanned pages is
	 * less than the number of skipped pages. This ensures that the
	 * skipped page count does not exceed the scanned page count, which
	 * could happen due to interruptions in the scanning process (e.g.
	 * high system load or priority adjustments). Resetting the counter
	 * prevents incorrect behaviour in subsequent logic, such as
	 * determining whether too many pages have been skipped.
	 */
	if (nr_scanned < *nr_skipped)
		*nr_skipped = 0;

	if ((priority < DEF_PRIORITY - 2) &&
	    (nr_scanned >> MI_TOO_MANY_SKIPPED_SHIFT > 0)) {
		too_many_skipped =
			*nr_skipped > (nr_scanned >> MI_TOO_MANY_SKIPPED_SHIFT);
		if (too_many_skipped) {
			*should_protect = MI_PAGEREF_RECLAIM;
			return;
		}
	}

	activate_thres = mi_mapcount_thres;
	if (priority != DEF_PRIORITY)
		keep_thres = get_dynamic_mapcount_thres(priority);

	mapcount = page_mapcount(page);
	if (mapcount >= activate_thres) {
		nr_pages = thp_nr_pages(page);
		*nr_skipped += nr_pages;
		*should_protect = MI_PAGEREF_ACTIVATE;
		return;
	} else if (keep_thres >= 2 && mapcount >= keep_thres) {
		*should_protect = MI_PAGEREF_KEEP;
		return;
	}

	*should_protect = MI_PAGEREF_RECLAIM;
}

static ssize_t show_mi_mapcount_thres(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", mi_mapcount_thres);
}

static ssize_t store_mi_mapcount_thres(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t len)
{
	unsigned int thres;

	if (kstrtouint(buf, 0, &thres))
		return -EINVAL;

	if (thres < 2)
		return -EINVAL;

	mi_mapcount_thres = thres;

	return len;
}

static struct kobj_attribute mi_mapcount_thres_attr = __ATTR(
	mapcount_thres, 0644, show_mi_mapcount_thres, store_mi_mapcount_thres);

static ssize_t show_mi_rmap_efficiency_setup(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  mi_rmap_efficiency_setup ? "true" : "false");
}

static ssize_t store_mi_rmap_efficiency_setup(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      const char *buf, size_t len)
{
	ssize_t ret;

	ret = kstrtobool(buf, &mi_rmap_efficiency_setup);
	if (ret)
		return ret;

	return len;
}

static struct kobj_attribute mi_rmap_check_enable_attr = __ATTR(
	enabled, 0644, show_mi_rmap_efficiency_setup,
	store_mi_rmap_efficiency_setup);

static struct attribute *mi_rmap_check_attrs[] = {
	&mi_mapcount_thres_attr.attr,
	&mi_rmap_check_enable_attr.attr,
	NULL,
};

static struct attribute_group mi_rmap_check_attr_group = {
	.name = "mi_rmap_efficiency_check",
	.attrs = mi_rmap_check_attrs,
};

static int init_mi_rmap_efficiency_sysfs(void)
{
	/*
	 * Built-in: attach to /sys/kernel/ so userspace can see
	 * /sys/kernel/mi_rmap_efficiency/{enabled,mapcount_thres}.
	 */
	kobj = kobject_create_and_add("mi_rmap_efficiency", kernel_kobj);
	if (kobj) {
		if (sysfs_create_group(kobj, &mi_rmap_check_attr_group))
			pr_err("mi_rmap_efficiency: failed to create sysfs group\n");
	}

	return 0;
}

static int __init mi_rmap_efficiency_init(void)
{
	int ret;

	init_mi_rmap_efficiency_sysfs();

	ret = register_trace_android_vh_page_should_be_protected(
		mi_check_mapcount, NULL);
	if (ret) {
		pr_err("mi_rmap_efficiency: register hook failed ret=%d\n", ret);
		if (kobj) {
			sysfs_remove_group(kobj, &mi_rmap_check_attr_group);
			kobject_put(kobj);
			kobj = NULL;
		}
		return ret;
	}

	pr_info("mi_rmap_efficiency: initialized\n");
	return 0;
}
late_initcall(mi_rmap_efficiency_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaomi <maminghui5@xiaomi.com> (ported)");
