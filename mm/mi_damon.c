// SPDX-License-Identifier: GPL-2.0
/*
 * mm/mi_damon.c - Xiaomi mi_damon virtual-address cold-page reclaim,
 * direct port to Sew 5.15 experimental branch (r8-os4-residual-port).
 *
 * Provenance
 * ----------
 * Source artifact: dada OS4 mi_damon.ko (aarch64, kernel 6.6.57,
 * scmversion g32a50a34de2b, 96 undefined symbols, closure gap 13).
 * That module is a self-contained fork of the 6.6 DAMON stack (core +
 * vaddr primitive + damon_sysfs + DAMOS) plus Xiaomi-specific additions:
 *   - nr_accesses_permil / age_permil / sz_permil access-pattern units
 *   - watermarks (free_mem_rate) and DAMOS "pageout" cold reclaim
 *   - tried_regions reporting (sysfs snapshot of monitored regions)
 *   - damon_set_regions_with_vmas / damon_min_vma region filtering
 *   - debug_log verbosity knob, "mi_damon:damon_aggregated" trace event
 *     ("target_id=%lu nr_regions=%u %lu-%lu: %u %u") consumed by dada BPF
 *
 * Port strategy (user decision: direct port, not a native-DAMOS substitute)
 * -------------------------------------------------------------------------
 * The in-tree 5.15 DAMON stack already contains the same machinery the
 * module embeds (CONFIG_DAMON=y core, DAMOS backport, and vaddr primitive
 * in mm/damon/vaddr.c which walks VMAs via rbtree find_vma - no maple
 * tree).  This module therefore:
 *   1. copies the vaddr primitive via damon_va_set_primitives() and
 *      re-mounts it with our own reset_aggregated() hook, instead of
 *      carrying a maple-tree (mas_find) based VMA walker from 6.6;
 *   2. adds the Xiaomi layer: permil access-rate reporting, min_vma
 *      pruning, debug_log, watermarks + PAGEOUT scheme (cold reclaim),
 *      tried-regions snapshot, and the mi_damon tracepoint.
 *
 * 13 closure gaps, each resolved as follows
 * -----------------------------------------
 * Mechanical (9), resolved by writing against 5.15 APIs directly:
 *  1. alt_cb_patch_nops   - 6.6 arm64 alternative-callback helper used by
 *     module glue; the 5.15 port performs no runtime alternative patching,
 *     nothing to shim.
 *  2. kmalloc_trace       - 6.6 kmalloc profiling wrapper; plain kmalloc()
 *     (this file) / in-tree DAMON allocations are used instead.
 *  3. __list_add_valid_or_report - 6.6 rename of __list_add_valid; the
 *     port uses standard list_head helpers, 5.15 list debug hooks apply.
 *  4. __list_del_entry_valid_or_report - same as (3) for deletion.
 *  5. __trace_trigger_soft_disabled - 6.6 tracepoint macro internals;
 *     5.15 tracepoint infra handles trigger gating inside its own macros.
 *  6. get_random_u8       - not needed by the 5.15 port (the 6.6 module
 *     used it in region split jitter; 5.15 core kdamond_split_regions has
 *     its own logic).
 *  7. __get_random_u32_below - same as (6), not needed on 5.15.
 *  8. kthread_stop_put    - 6.6 helper; damon_stop() in 5.15 core does
 *     kthread_stop + put_task_struct internally, no shim needed.
 *  9. __folio_put         - folio dropping used by the embedded 6.6
 *     prmtv-common; the 5.15 port delegates access checking to in-tree
 *     mm/damon/vaddr.c + prmtv-common.c, no direct folio drops here.
 * Structural (3 symbols, page_pinner counts two):
 * 10. mas_find            - 6.6 maple-tree VMA iterator. Eliminated: VMA
 *     traversal is done by in-tree vaddr primitive (rbtree find_vma).
 * 11. contpte_ptep_test_and_clear_young - 6.9+ arm64 contiguous-PTE young
 *     propagation, called from the embedded prmtv-common page walk.
 *     STUBBED OUT by delegation: the 5.15 arm64 port has no contpte
 *     machinery; in-tree walk_page_range-based young testing handles
 *     block mappings at PMD/PTE level.  Impact: none on 5.15 semantics;
 *     we lose the 6.6 optimization of clearing young bits across a whole
 *     contiguous block in one go (slightly more page-table walking).
 * 12. page_pinner_inited  - Xiaomi private page-pinning debug framework.
 *     STUBBED OUT: the original damon_get_folio() consulted page_pinner
 *     to track pages held during monitoring.  Impact: purely diagnostic;
 *     page lifecycle and reclaim decisions are unaffected, pin-debug
 *     accounting for monitored pages is not available on 5.15.
 * 13. __page_pinner_put_page - companion of (12).  STUBBED OUT with the
 *     same impact: the pin-debug put hook is gone, normal folio_put path
 *     (inside in-tree vaddr/prmtv-common) remains.
 *
 * Known behavioral deltas (documented, accepted for the experimental branch)
 * --------------------------------------------------------------------------
 * - VMA-name based sampling skip ("damon_vma_need_sample", e.g. skipping
 *   "dalvik-" VMAs) of the original is not ported: the in-tree vaddr
 *   three-regions machinery cannot be name-filtered without forking it.
 *   Dalvik regions will be monitored and may be pageouted under quota;
 *   watermarks + quotas bound the effect.
 * - min_vma pruning happens at each aggregation (inside the kdamond
 *   thread) instead of at region-creation time.
 * - The trace event nr_accesses field carries the permil access rate.
 * - Region snapshot reads from sysfs are per-aggregation snapshots (no
 *   live region-list locking in 5.15 core).
 */

#define pr_fmt(fmt) "mi_damon: " fmt

#include <linux/damon.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#define CREATE_TRACE_POINTS
#include "mi_damon_trace.h"

/* ---- module state ------------------------------------------------------ */

static DEFINE_MUTEX(mi_damon_lock);
static struct damon_ctx *mi_damon_ctx;
static bool mi_damon_running;

/* vaddr primitive copy with our reset_aggregated override installed */
static struct damon_primitive mi_va_primitive;

/* config: applied on next start */
static unsigned long mi_sample_us = 5000;
static unsigned long mi_aggr_us = 100000;
static unsigned long mi_update_us = 1000000;
static unsigned long mi_min_nr_regions = 10;
static unsigned long mi_max_nr_regions = 1000;
static unsigned long mi_pid_target;	/* pid to monitor; vaddr ops semantics */
static unsigned long mi_min_vma;	/* prune regions with end <= min_vma */
static unsigned int mi_debug_log;	/* >0: verbose aggregation logging */

/* scheme (cold reclaim) config */
static int mi_action = DAMOS_PAGEOUT;
static unsigned long mi_cold_max_permil;	/* access-rate ceiling (permil) */
static unsigned long mi_cold_min_age;		/* in aggregation intervals */
static unsigned long mi_quota_ms = 100;
static unsigned long mi_quota_sz = 32UL * 1024 * 1024;
static unsigned long mi_wmarks_high = 500;	/* free-mem-rate permil */
static unsigned long mi_wmarks_mid = 400;
static unsigned long mi_wmarks_low = 200;

/* ---- per-aggregation snapshot (mirrors original tried_regions) --------- */

#define MI_SNAPSHOT_MAX	256

struct mi_snap_region {
	unsigned long start;
	unsigned long end;
	unsigned int nr_accesses_permil;
	unsigned int age;
};

static struct {
	struct mi_snap_region regions[MI_SNAPSHOT_MAX];
	unsigned int nr;
	unsigned int nr_total;		/* nr of regions before truncation */
	unsigned long target_id;
	unsigned long max_accesses;	/* aggr/sample, for context */
	unsigned long nr_applied, sz_applied, nr_tried, sz_tried, qt_exceeds;
} mi_snapshot;

static DEFINE_SPINLOCK(mi_snapshot_lock);

/* ---- kdamond-side hook -------------------------------------------------- */

static unsigned int mi_permil(unsigned int last_nr_accesses,
			      unsigned long max_accesses)
{
	if (!max_accesses)
		return 0;
	if (last_nr_accesses >= max_accesses)
		return 1000;
	return (unsigned long)last_nr_accesses * 1000 / max_accesses;
}

/*
 * Runs in the kdamond thread, after core kdamond_reset_aggregated() has
 * moved nr_accesses into last_nr_accesses.  Emits the mi_damon tracepoint,
 * refreshes the tried-regions snapshot, and applies Xiaomi min_vma rule.
 */
static void mi_damon_reset_aggregated(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct damon_region *r, *next;
	unsigned long max_accesses = 0;
	unsigned int nr_total = 0, nr_snap = 0;
	unsigned long nr_applied = 0, sz_applied = 0, nr_tried = 0;
	unsigned long sz_tried = 0, qt_exceeds = 0;
	struct damos *s, *s_next;

	if (ctx->sample_interval)
		max_accesses = ctx->aggr_interval / ctx->sample_interval;

	damon_for_each_scheme_safe(s, s_next, ctx) {
		nr_tried += s->stat.nr_tried;
		sz_tried += s->stat.sz_tried;
		nr_applied += s->stat.nr_applied;
		sz_applied += s->stat.sz_applied;
		qt_exceeds += s->stat.qt_exceeds;
	}

	spin_lock(&mi_snapshot_lock);
	mi_snapshot.max_accesses = max_accesses;
	mi_snapshot.nr_applied = nr_applied;
	mi_snapshot.sz_applied = sz_applied;
	mi_snapshot.nr_tried = nr_tried;
	mi_snapshot.sz_tried = sz_tried;
	mi_snapshot.qt_exceeds = qt_exceeds;
	spin_unlock(&mi_snapshot_lock);

	damon_for_each_target(t, ctx) {
		nr_total = 0;
		damon_for_each_region(r, t)
			nr_total++;

		damon_for_each_region(r, t) {
			unsigned int permil = mi_permil(r->last_nr_accesses,
							max_accesses);

			trace_mi_damon_aggregated(t->id, nr_total, r->ar.start,
					r->ar.end, permil, r->age);
			if (mi_debug_log)
				pr_info("agg: target %lu region %lu-%lu permil %u age %u\n",
					t->id, r->ar.start, r->ar.end,
					permil, r->age);

			spin_lock(&mi_snapshot_lock);
			if (nr_snap < MI_SNAPSHOT_MAX) {
				mi_snapshot.regions[nr_snap].start = r->ar.start;
				mi_snapshot.regions[nr_snap].end = r->ar.end;
				mi_snapshot.regions[nr_snap].nr_accesses_permil = permil;
				mi_snapshot.regions[nr_snap].age = r->age;
				nr_snap++;
			}
			spin_unlock(&mi_snapshot_lock);
		}

		spin_lock(&mi_snapshot_lock);
		mi_snapshot.target_id = t->id;
		mi_snapshot.nr = nr_snap;
		mi_snapshot.nr_total = nr_total;
		spin_unlock(&mi_snapshot_lock);

		/*
		 * Xiaomi damon_min_vma semantics: regions that lie entirely
		 * below min_vma are dropped.  Runs inside the kdamond thread,
		 * so region destruction here is safe.
		 */
		if (mi_min_vma) {
			damon_for_each_region_safe(r, next, t)
				if (r->ar.end <= mi_min_vma)
					damon_destroy_region(r, t);
		}
	}
}

/* ---- start / stop ------------------------------------------------------- */

static struct damos *mi_damon_new_scheme(void)
{
	struct damos_quota quota = {
		.ms = mi_quota_ms,
		.sz = mi_quota_sz,
		.reset_interval = 1000,
	};
	struct damos_watermarks wmarks = {
		.metric = DAMOS_WMARK_FREE_MEM_RATE,
		.interval = mi_aggr_us,
		.high = mi_wmarks_high,
		.mid = mi_wmarks_mid,
		.low = mi_wmarks_low,
	};
	unsigned long max_accesses = mi_sample_us ?
					mi_aggr_us / mi_sample_us : 0;
	unsigned int cold_max_accesses;

	/* permil threshold -> raw nr_accesses used by 5.15 scheme matching */
	cold_max_accesses = (unsigned int)min(mi_cold_max_permil * max_accesses / 1000,
					      (unsigned long)UINT_MAX);

	return damon_new_scheme(0, ULONG_MAX,
				0, cold_max_accesses,
				(unsigned int)mi_cold_min_age, UINT_MAX,
				mi_action, &quota, &wmarks);
}

static int mi_damon_do_start(void)
{
	struct damon_ctx *ctx;
	struct damos *scheme;
	unsigned long pid = mi_pid_target;
	int ret;

	if (mi_damon_ctx)
		return -EALREADY;
	if (!mi_pid_target)
		return -EINVAL;

	ctx = damon_new_ctx();
	if (!ctx)
		return -ENOMEM;

	ctx->primitive = mi_va_primitive;

	ret = damon_set_attrs(ctx, mi_sample_us, mi_aggr_us, mi_update_us,
			      mi_min_nr_regions, mi_max_nr_regions);
	if (ret)
		goto err_ctx;

	ret = damon_set_targets(ctx, &pid, 1);
	if (ret)
		goto err_ctx;

	scheme = mi_damon_new_scheme();
	if (!scheme) {
		ret = -ENOMEM;
		goto err_ctx;
	}
	ret = damon_set_schemes(ctx, &scheme, 1);
	if (ret)
		goto err_ctx;	/* scheme owned by ctx once added */

	ret = damon_start(&ctx, 1);
	if (ret)
		goto err_ctx;

	mi_damon_ctx = ctx;
	mi_damon_running = true;
	if (mi_debug_log)
		pr_info("started: pid %lu sample %luus aggr %luus min_vma %lu\n",
			mi_pid_target, mi_sample_us, mi_aggr_us, mi_min_vma);
	return 0;

err_ctx:
	damon_destroy_ctx(ctx);
	return ret;
}

static void mi_damon_do_stop(void)
{
	if (!mi_damon_ctx)
		return;

	damon_stop(&mi_damon_ctx, 1);
	damon_destroy_ctx(mi_damon_ctx);
	mi_damon_ctx = NULL;
	mi_damon_running = false;
	if (mi_debug_log)
		pr_info("stopped\n");
}

/* ---- sysfs --------------------------------------------------------------- */

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	return sysfs_emit(buf, "%s\n", mi_damon_running ? "on" : "off");
}

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	int ret = 0;

	mutex_lock(&mi_damon_lock);
	if (sysfs_streq(buf, "on"))
		ret = mi_damon_do_start();
	else if (sysfs_streq(buf, "off"))
		mi_damon_do_stop();
	else
		ret = -EINVAL;
	mutex_unlock(&mi_damon_lock);

	return ret ? ret : count;
}

static ssize_t pid_target_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", mi_pid_target);
}

static ssize_t pid_target_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	int err;

	mutex_lock(&mi_damon_lock);
	err = kstrtoul(buf, 0, &mi_pid_target);
	mutex_unlock(&mi_damon_lock);
	return err ? err : count;
}

static struct kobj_attribute state_attr =
	__ATTR(state, 0644, state_show, state_store);

static struct kobj_attribute pid_target_attr =
	__ATTR(pid_target, 0644, pid_target_show, pid_target_store);

#define MI_ULONG_ATTR(attrname, name)					\
static ssize_t name##_show(struct kobject *kobj,			\
			   struct kobj_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%lu\n", name);				\
}									\
static ssize_t name##_store(struct kobject *kobj,			\
			    struct kobj_attribute *attr,		\
			    const char *buf, size_t count)		\
{									\
	int err;							\
	mutex_lock(&mi_damon_lock);					\
	err = kstrtoul(buf, 0, &name);					\
	mutex_unlock(&mi_damon_lock);					\
	return err ? err : count;					\
}									\
static struct kobj_attribute name##_attr =				\
	__ATTR(attrname, 0644, name##_show, name##_store)

MI_ULONG_ATTR(sample_us, mi_sample_us);
MI_ULONG_ATTR(aggr_us, mi_aggr_us);
MI_ULONG_ATTR(update_us, mi_update_us);
MI_ULONG_ATTR(min_nr_regions, mi_min_nr_regions);
MI_ULONG_ATTR(max_nr_regions, mi_max_nr_regions);
MI_ULONG_ATTR(min_vma, mi_min_vma);
MI_ULONG_ATTR(cold_max_permil, mi_cold_max_permil);
MI_ULONG_ATTR(cold_min_age, mi_cold_min_age);
MI_ULONG_ATTR(quota_ms, mi_quota_ms);
MI_ULONG_ATTR(quota_sz, mi_quota_sz);
MI_ULONG_ATTR(wmarks_high, mi_wmarks_high);
MI_ULONG_ATTR(wmarks_mid, mi_wmarks_mid);
MI_ULONG_ATTR(wmarks_low, mi_wmarks_low);

static ssize_t debug_log_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", mi_debug_log);
}

static ssize_t debug_log_store(struct kobject *kobj,
			       struct kobj_attribute *attr, const char *buf,
			       size_t count)
{
	int err;

	mutex_lock(&mi_damon_lock);
	err = kstrtouint(buf, 0, &mi_debug_log);
	mutex_unlock(&mi_damon_lock);
	return err ? err : count;
}

static struct kobj_attribute debug_log_attr =
	__ATTR(debug_log, 0644, debug_log_show, debug_log_store);

static ssize_t action_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	const char *s = "unknown";

	switch (mi_action) {
	case DAMOS_WILLNEED:	s = "willneed";	break;
	case DAMOS_COLD:	s = "cold";	break;
	case DAMOS_PAGEOUT:	s = "pageout";	break;
	case DAMOS_HUGEPAGE:	s = "hugepage";	break;
	case DAMOS_NOHUGEPAGE:	s = "nohugepage"; break;
	case DAMOS_STAT:	s = "stat";	break;
	}
	return sysfs_emit(buf, "%s\n", s);
}

static ssize_t action_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	int new_action;

	if (sysfs_streq(buf, "willneed"))
		new_action = DAMOS_WILLNEED;
	else if (sysfs_streq(buf, "cold"))
		new_action = DAMOS_COLD;
	else if (sysfs_streq(buf, "pageout"))
		new_action = DAMOS_PAGEOUT;
	else if (sysfs_streq(buf, "hugepage"))
		new_action = DAMOS_HUGEPAGE;
	else if (sysfs_streq(buf, "nohugepage"))
		new_action = DAMOS_NOHUGEPAGE;
	else if (sysfs_streq(buf, "stat"))
		new_action = DAMOS_STAT;
	else
		return -EINVAL;

	mutex_lock(&mi_damon_lock);
	mi_action = new_action;
	mutex_unlock(&mi_damon_lock);
	return count;
}

static struct kobj_attribute action_attr =
	__ATTR(action, 0644, action_show, action_store);

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	unsigned long nr_tried, sz_tried, nr_applied, sz_applied, qt_exceeds;

	spin_lock(&mi_snapshot_lock);
	nr_tried = mi_snapshot.nr_tried;
	sz_tried = mi_snapshot.sz_tried;
	nr_applied = mi_snapshot.nr_applied;
	sz_applied = mi_snapshot.sz_applied;
	qt_exceeds = mi_snapshot.qt_exceeds;
	spin_unlock(&mi_snapshot_lock);

	return sysfs_emit(buf, "nr_tried %lu\nsz_tried %lu\nnr_applied %lu\nsz_applied %lu\nqt_exceeds %lu\n",
			  nr_tried, sz_tried, nr_applied, sz_applied,
			  qt_exceeds);
}

static struct kobj_attribute stats_attr =
	__ATTR_RO(stats);

static ssize_t regions_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	unsigned int i, printed;
	ssize_t len = 0;
	unsigned long target_id, max_accesses;

	spin_lock(&mi_snapshot_lock);
	target_id = mi_snapshot.target_id;
	max_accesses = mi_snapshot.max_accesses;
	printed = mi_snapshot.nr;
	len += sysfs_emit_at(buf, len, "target_id %lu max_accesses %lu total %u\n",
			     target_id, max_accesses, mi_snapshot.nr_total);
	for (i = 0; i < printed && len < PAGE_SIZE - 64; i++) {
		struct mi_snap_region *r = &mi_snapshot.regions[i];

		len += sysfs_emit_at(buf, len, "%lu-%lu permil %u age %u\n",
				     r->start, r->end,
				     r->nr_accesses_permil, r->age);
	}
	spin_unlock(&mi_snapshot_lock);

	return len;
}

static struct kobj_attribute regions_attr =
	__ATTR_RO(regions);

static struct attribute *mi_damon_attrs[] = {
	&state_attr.attr,
	&pid_target_attr.attr,
	&mi_sample_us_attr.attr,
	&mi_aggr_us_attr.attr,
	&mi_update_us_attr.attr,
	&mi_min_nr_regions_attr.attr,
	&mi_max_nr_regions_attr.attr,
	&mi_min_vma_attr.attr,
	&debug_log_attr.attr,
	&action_attr.attr,
	&mi_cold_max_permil_attr.attr,
	&mi_cold_min_age_attr.attr,
	&mi_quota_ms_attr.attr,
	&mi_quota_sz_attr.attr,
	&mi_wmarks_high_attr.attr,
	&mi_wmarks_mid_attr.attr,
	&mi_wmarks_low_attr.attr,
	&stats_attr.attr,
	&regions_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mi_damon);

/* ---- init / exit -------------------------------------------------------- */

static struct kobject *mi_damon_kobj;

static int __init mi_damon_init(void)
{
	struct damon_ctx *probe;
	int ret;

	/*
	 * Capture the in-tree vaddr primitive once, then re-mount it with
	 * our reset_aggregated hook.  This replaces the 6.6 module embedded
	 * maple-tree (mas_find) VMA walker with the 5.15 rbtree find_vma
	 * implementation (mm/damon/vaddr.c).
	 */
	probe = damon_new_ctx();
	if (!probe)
		return -ENOMEM;
	damon_va_set_primitives(probe);
	mi_va_primitive = probe->primitive;
	damon_destroy_ctx(probe);
	mi_va_primitive.reset_aggregated = mi_damon_reset_aggregated;

	mi_damon_kobj = kobject_create_and_add("mi_damon", kernel_kobj);
	if (!mi_damon_kobj)
		return -ENOMEM;

	ret = sysfs_create_groups(mi_damon_kobj, mi_damon_groups);
	if (ret) {
		kobject_put(mi_damon_kobj);
		return ret;
	}

	pr_info("loaded (port of dada OS4 mi_damon.ko 6.6.57 on DAMON vaddr)\n");
	return 0;
}

static void __exit mi_damon_exit(void)
{
	mutex_lock(&mi_damon_lock);
	mi_damon_do_stop();
	mutex_unlock(&mi_damon_lock);
	sysfs_remove_groups(mi_damon_kobj, mi_damon_groups);
	kobject_put(mi_damon_kobj);
	pr_info("unloaded\n");
}

module_init(mi_damon_init);
module_exit(mi_damon_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xiaomi mi_damon cold-page reclaim, ported to 5.15 DAMON vaddr (experimental)");
MODULE_AUTHOR("Sew experimental branch");
