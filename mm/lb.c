// SPDX-License-Identifier: GPL-2.0-only
/*
 * lb: launch-boost cold-start prefetch, Tier-1 port of the Xiaomi dada
 * OS4 lb.ko (245KB, 57 funcs, 23 module params, depends empty).
 *
 * RE evidence: /root/work/os4_dada/ko/lb.ko (vermagic 6.6.57-android15);
 * raw notes in .omz/research/.../raw/re-lb.txt + this session's collect
 * decode (hook pairing, g_manager layout, range-merge logic).
 *
 * What the OS4 module does (disasm-proven)
 * ----------------------------------------
 * Collect phase: 7 tracepoint/hook observers.  init_module registers
 * android_vh_filemap_read -> mi_lb_page_collect_on_readfile and
 * android_vh_filemap_map_pages_range -> mi_lb_page_collect_on_pagefault
 * (both thin wrappers into mi_lb_pagecache_collect(file, pgoff, nr));
 * plus do_async_mmap_readahead -> mi_lb_skip_async_mmap_readahead,
 * ra_tuning_max_page -> adjust_readahead,
 * tune_mmap_readaround -> adjust_readaround,
 * should_fault_around -> should_skip_fault_around.  lb_hot_init
 * registers android_vh_mmput_mm (per-mm teardown; 5.15 equivalent:
 * android_vh_mmput).  The collect core:
 *   - gate on debug level (g_manager+12 byte / +0 word) and the
 *     manager pointer;
 *   - match current task's pid/tgid (6.6 task+1560/+1564) against the
 *     registered package list (app types 0..5, per-type app cap);
 *   - verify the file through file->f_mapping -> [+40] -> [+96]
 *     against three magic constants (an f_type whitelist; 5.15 uses
 *     S_IS_REG on mapping->host instead - see PORT-DELTA);
 *   - 5000-jiffies (50s) collect window per manager;
 *   - record under a spinlock into a 2048-entry open-file table
 *     ({file ptr, pgoff}, 24B stride) with lookup by (mapping+40 tag,
 *     mapping+64 tag, w11==w13 key), bump per-file counters, insert
 *     into a 64-bucket hash keyed by a 10/11-bit masked word
 *     (uid/pid), count at g_manager+53408/53424.
 * Preread phase: the /proc/lb_data command surface drives
 * collect/preread_info/preread_size/pte_* commands through the chardev
 * ioctl (LB_GET_VERSION / LB_GET_PREREAD_INFO_SIZE, base
 * 0x3ef7b3ff, 0x12 slots) and the pte_preread path walks the mm and
 * issues read_swap_cache_async / vfs_fadvise with swapin/rlock
 * circuit breakers (lb_swapin_total_time_threshold,
 * lb_rlock_acquire_threshold in us).
 *
 * Sew 5.15 Tier-1 scope ([PORT-DELTA] items marked)
 * -------------------------------------------------
 * Ported: collect main path (file-page ranges per uid via
 * android_vh_filemap_read + android_vh_filemap_map_pages), preread
 * execution (vfs_fadvise WILLNEED over the recorded ranges +
 * read_swap_cache_async for anon), the six skip/adjust observers,
 * circuit breakers, /proc/lb/{collect_list,stats} + per-uid mode node
 * matching the addon contract (lb_userspace.sh ASSUME-1/2/3), and all
 * 23 module params with dada names/defaults (values from .data: 50/50/
 * 1/4/128/3/50/257/2000/16/8192k/... see LB_* defaults below).
 *  - file-type whitelist: the 6.6 magic-constant triple is an
 *    f_type check; replaced by S_IS_REG(mapping->host->i_mode) +
 *    !special_file().  [PORT-DELTA]
 *  - task+1560/1564 (6.6 pid/tgid): 5.15 uses task_pid_nr/task_tgid_nr.
 *    [PORT-DELTA]
 *  - mas_find (maple tree): absent on 5.15 -> the PTE-snapshot
 *    compiler, anon-swapin bitmaps and hot_collect are Tier-2 and
 *    stay unimplemented (interface stubs return -ENOSYS).  [PORT-DELTA]
 *  - page_pinner_inited / __page_pinner_put_page: 5.15 generic
 *    framework exists but the static key is not module-visible ->
 *    stubbed (mi_damon.c precedent).  [PORT-DELTA]
 *  - alt_cb_patch_nops / system_cpucaps: absorbed (rtg.c precedent).
 *  - ioctl numbers: kept (base 0x3ef7b3ff, LB_GET_VERSION=base,
 *    LB_GET_PREREAD_INFO_SIZE = 0x80044c14 decode: dir=2 size=4
 *    type=0x4c nr=20).
 * Everything defaults OFF (collect off, preread off, only_collect=0).
 */

#include <linux/backing-dev.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/fadvise.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/uaccess.h>
#include <trace/hooks/mm.h>
#include <trace/hooks/sched.h>

/* ---- module params (dada names; defaults from the .data image) ------- */
static bool lb_background_faultaround_disable;
module_param(lb_background_faultaround_disable, bool, 0644);
MODULE_PARM_DESC(lb_background_faultaround_disable, "background fault around disable or not");

static bool lb_skip_background_readahead_enable;
module_param(lb_skip_background_readahead_enable, bool, 0644);
MODULE_PARM_DESC(lb_skip_background_readahead_enable, "skip background readahead enable or not");

static uint lb_max_file_sequential_apps = 50;
module_param(lb_max_file_sequential_apps, uint, 0644);
MODULE_PARM_DESC(lb_max_file_sequential_apps, "max number of file sequential apps");

static uint lb_max_real_timing_apps = 4;
module_param(lb_max_real_timing_apps, uint, 0644);
MODULE_PARM_DESC(lb_max_real_timing_apps, "max number of real timing apps");

static uint lb_max_merge_range = 128;
module_param(lb_max_merge_range, uint, 0644);
MODULE_PARM_DESC(lb_max_merge_range, "max merge range for file range merge");

static uint lb_max_gap_range = 3;
module_param(lb_max_gap_range, uint, 0644);
MODULE_PARM_DESC(lb_max_gap_range, "max gap range for file range merge");

static bool lb_real_timing_supported = true;
module_param(lb_real_timing_supported, bool, 0444);
MODULE_PARM_DESC(lb_real_timing_supported, "real timing app launch boost supported");

static bool lb_file_page_reclaim_supported = true;
module_param(lb_file_page_reclaim_supported, bool, 0444);
MODULE_PARM_DESC(lb_file_page_reclaim_supported, "precise file-backed page reclaim supported");

static uint lb_max_pte_segment_count = 257;
module_param(lb_max_pte_segment_count, uint, 0644);
MODULE_PARM_DESC(lb_max_pte_segment_count, "max pte segment count to limit memory usage");

static uint lb_pte_max_active_apps = 8;
module_param(lb_pte_max_active_apps, uint, 0644);
MODULE_PARM_DESC(lb_pte_max_active_apps, "max active apps");

static bool lb_pte_anon_swapin_enable;
module_param(lb_pte_anon_swapin_enable, bool, 0644);
MODULE_PARM_DESC(lb_pte_anon_swapin_enable, "anon swapin enable or not");

static bool lb_pte_fadvise_enable = true;
module_param(lb_pte_fadvise_enable, bool, 0644);
MODULE_PARM_DESC(lb_pte_fadvise_enable, "fadvise enable or not");

static bool lb_pte_mark_file_anon_enable;
module_param(lb_pte_mark_file_anon_enable, bool, 0644);
MODULE_PARM_DESC(lb_pte_mark_file_anon_enable, "mark pte_segment as anon and file or not");

static unsigned long long lb_swapin_total_time_threshold = 200000000ULL;
module_param(lb_swapin_total_time_threshold, ullong, 0644);
MODULE_PARM_DESC(lb_swapin_total_time_threshold, "(in us) swapin time exceed this threshold will stop preread");

static unsigned long long lb_rlock_acquire_threshold = 200000000ULL;
module_param(lb_rlock_acquire_threshold, ullong, 0644);
MODULE_PARM_DESC(lb_rlock_acquire_threshold, "(in us) mmap lock acquire time exceed this threshold will stop preread");

static bool lb_swapin_expire_interruput_enable;
module_param(lb_swapin_expire_interruput_enable, bool, 0644);
MODULE_PARM_DESC(lb_swapin_expire_interruput_enable, "interrupt preread when swapin time exceed threshold");

static bool lb_rlock_expire_interruput_enable;
module_param(lb_rlock_expire_interruput_enable, bool, 0644);
MODULE_PARM_DESC(lb_rlock_expire_interruput_enable, "interrupt mmap lock acquire time exceed threshold");

static bool lb_debug_verbose;
module_param(lb_debug_verbose, bool, 0644);
MODULE_PARM_DESC(lb_debug_verbose, "iorap debug verbose");

static bool lb_collect_pinfile;
module_param(lb_collect_pinfile, bool, 0644);
MODULE_PARM_DESC(lb_collect_pinfile, "iorap collect pinfile");

static bool lb_collect_specify_filetype;
module_param(lb_collect_specify_filetype, bool, 0644);
MODULE_PARM_DESC(lb_collect_specify_filetype, "iorap only collect specify filetype enable");

static bool lb_atrace_enable;
module_param(lb_atrace_enable, bool, 0644);
MODULE_PARM_DESC(lb_atrace_enable, "iorap atrace enable");

static bool lb_only_collect;
module_param(lb_only_collect, bool, 0644);
MODULE_PARM_DESC(lb_only_collect, "iorap only collect");

static int lb_debug = 5;
module_param(lb_debug, int, 0644);
MODULE_PARM_DESC(lb_debug, "iorap debug msg level");

/* ---- collect engine state -------------------------------------------- */
#define LB_COLLECT_WINDOW_JIFFIES	(50 * HZ / 10)	/* 0x1f4 @ HZ=100 => 5s */
#define LB_MAX_OPEN_FILES		2048
#define LB_PREREAD_BATCH		32
#define LB_HASH_BUCKETS			64
#define LB_UID_HASH_MASK		0x3f

enum lb_app_type {
	LB_APP_FILE_SEQUENTIAL = 0,
	LB_APP_REAL_TIMING = 1,
	LB_APP_TYPES = 2,
};

struct lb_pkg {
	struct hlist_node	hnode;
	char			name[64];
	kuid_t			uid;
	u8			type;
	bool			mode_preread;	/* /proc/lb/<uid>/mode wrote preread */
};

struct lb_range {
	struct hlist_node	hnode;
	struct file		*file;		/* holds a reference */
	pgoff_t			start;
	pgoff_t			end;
};

struct lb_manager {
	/* collect window anchor (jiffies) */
	unsigned long		window_j;
	bool			window_open;
	/* open-file table: file+range pairs, bounded */
	struct lb_range		ranges[LB_MAX_OPEN_FILES];
	DECLARE_BITMAP(range_used, LB_MAX_OPEN_FILES);
	/* per-uid range hash for quick merge checks */
	struct hlist_head	file_hash[LB_HASH_BUCKETS];
	unsigned int		nr_ranges;
	/* uid registry */
	struct hlist_head	pkg_hash[LB_HASH_BUCKETS];
	unsigned int		nr_pkgs[LB_APP_TYPES];
	/* circuit breakers (us) */
	u64			swapin_total_us;
	u64			rlock_total_us;
	/* stats */
	atomic64_t		collect_on_read;
	atomic64_t		collect_on_fault;
	atomic64_t		preread_files;
	atomic64_t		preread_pages;
	atomic64_t		preread_skips;
	bool			preread_stop;
};

static struct lb_manager *g_manager;
static DEFINE_SPINLOCK(lb_lock);
static struct proc_dir_entry *lb_proc_dir;

/* ---- package registry -------------------------------------------------- */

/* caller must hold lb_lock (registry is spinlock-guarded, not RCU). */
static struct lb_pkg *lb_find_pkg_locked(kuid_t uid)
{
	struct lb_pkg *pkg;
	unsigned int bkt;

	lockdep_assert_held(&lb_lock);
	if (!g_manager)
		return NULL;
	bkt = from_kuid_munged(&init_user_ns, uid) & LB_UID_HASH_MASK;
	hlist_for_each_entry(pkg, &g_manager->pkg_hash[bkt], hnode) {
		if (uid_eq(pkg->uid, uid))
			return pkg;
	}
	return NULL;
}

static struct lb_pkg *lb_find_pkg(kuid_t uid)
{
	struct lb_pkg *pkg;
	unsigned long flags;

	spin_lock_irqsave(&lb_lock, flags);
	pkg = lb_find_pkg_locked(uid);
	spin_unlock_irqrestore(&lb_lock, flags);
	return pkg;
}

static struct lb_pkg *lb_add_package_info(const char *name, kuid_t uid, u8 type)
{
	struct lb_pkg *pkg;
	unsigned int bkt;

	if (!g_manager)
		return NULL;
	/* alloc outside the lock (kzalloc sleeps); re-check after taking
	 * it so concurrent adds cannot double-insert (audit P0). */
	pkg = kzalloc(sizeof(*pkg), GFP_KERNEL);
	if (!pkg)
		return NULL;
	strscpy(pkg->name, name, sizeof(pkg->name));
	pkg->uid = uid;
	pkg->type = type;
	bkt = from_kuid_munged(&init_user_ns, uid) & LB_UID_HASH_MASK;
	spin_lock(&lb_lock);
	{
		struct lb_pkg *e = lb_find_pkg_locked(uid);

		if (e) {
			spin_unlock(&lb_lock);
			kfree(pkg);
			return e;
		}
		if (type == LB_APP_FILE_SEQUENTIAL &&
		    g_manager->nr_pkgs[type] >= lb_max_file_sequential_apps) {
			spin_unlock(&lb_lock);
			kfree(pkg);
			return NULL;
		}
		if (type == LB_APP_REAL_TIMING &&
		    g_manager->nr_pkgs[type] >= lb_max_real_timing_apps) {
			spin_unlock(&lb_lock);
			kfree(pkg);
			return NULL;
		}
		hlist_add_head(&pkg->hnode, &g_manager->pkg_hash[bkt]);
		g_manager->nr_pkgs[type]++;
	}
	spin_unlock(&lb_lock);
	return pkg;
}

static void __maybe_unused lb_remove_package_info(kuid_t uid)
{
	struct lb_pkg *pkg;
	unsigned long flags;

	if (!g_manager)
		return;
	spin_lock_irqsave(&lb_lock, flags);
	pkg = lb_find_pkg_locked(uid);
	if (!pkg) {
		spin_unlock_irqrestore(&lb_lock, flags);
		return;
	}
	hlist_del(&pkg->hnode);
	g_manager->nr_pkgs[pkg->type]--;
	spin_unlock_irqrestore(&lb_lock, flags);
	kfree(pkg);
}

/* ---- collect core (dada mi_lb_pagecache_collect semantics) ------------ */

static bool lb_file_ok(struct file *file)
{
	struct inode *inode;

	/* [PORT-DELTA] the 6.6 magic-constant f_type whitelist becomes a
	 * plain regular-file check; special files are skipped. */
	if (!file || !file->f_mapping || !file->f_mapping->host)
		return false;
	inode = file->f_mapping->host;
	if (!S_ISREG(inode->i_mode) || special_file(inode->i_mode))
		return false;
	return true;
}

static void lb_range_add(struct lb_manager *m, struct file *file,
			 pgoff_t start, pgoff_t nr)
{
	struct lb_range *r = NULL;
	unsigned int bkt;
	int i;

	lockdep_assert_held(&lb_lock);

	/* merge with an existing range of the same file within gap */
	bkt = hash_ptr(file->f_mapping, ilog2(LB_HASH_BUCKETS));
	hlist_for_each_entry(r, &m->file_hash[bkt], hnode) {
		if (r->file->f_mapping != file->f_mapping)
			continue;
		if (start >= r->start &&
		    start - r->end <= lb_max_gap_range + nr) {
			if (r->end < start + nr)
				r->end = start + nr - 1;
			return;
		}
		if (r->start >= start + lb_max_gap_range &&
		    r->start - (start + nr) <= lb_max_gap_range) {
			if (r->start > start)
				r->start = start;
			if (r->end < start + nr - 1)
				r->end = start + nr - 1;
			return;
		}
		return; /* same file, far away: keep the first range */
	}

	if (m->nr_ranges >= lb_max_merge_range + LB_HASH_BUCKETS)
		return; /* bounded table */

	i = find_first_zero_bit(m->range_used, LB_MAX_OPEN_FILES);
	if (i >= LB_MAX_OPEN_FILES)
		return;
	r = &m->ranges[i];
	r->file = get_file(file);
	r->start = start;
	r->end = start + nr - 1;
	__set_bit(i, m->range_used);
	hlist_add_head(&r->hnode, &m->file_hash[bkt]);
	m->nr_ranges++;
}

/* [dada mi_lb_page_collect_on_readfile / _on_pagefault] */
static void mi_lb_pagecache_collect(struct file *file, pgoff_t pgoff,
				     pgoff_t nr, bool fault)
{
	struct lb_manager *m;
	struct lb_pkg *pkg;

	if (lb_debug < 3 || !nr)
		return;
	m = READ_ONCE(g_manager);
	if (!m)
		return;

	/* collect window (5s anchor like the 0x1f4 jiffies check).
	 * window state and the uid registry both live under lb_lock;
	 * the registry is spinlock-guarded, not RCU (audit P0). */
	spin_lock(&lb_lock);
	if (!m->window_open) {
		if (time_is_before_jiffies(m->window_j)) {
			spin_unlock(&lb_lock);
			return;
		}
	} else if (time_after(jiffies, m->window_j +
			      LB_COLLECT_WINDOW_JIFFIES)) {
		m->window_open = false;
		m->window_j = jiffies;
	}

	pkg = lb_find_pkg_locked(current_uid());
	if (!pkg) {
		spin_unlock(&lb_lock);
		return;
	}
	if (!lb_file_ok(file)) {
		spin_unlock(&lb_lock);
		return;
	}
	if (fault)
		atomic64_inc(&m->collect_on_fault);
	else
		atomic64_inc(&m->collect_on_read);
	lb_range_add(m, file, pgoff, nr);
	spin_unlock(&lb_lock);
}

static void mi_lb_page_collect_on_readfile(void *data, struct file *file,
					   loff_t pos, size_t count)
{
	if (!count)
		return;
	mi_lb_pagecache_collect(file, pos >> PAGE_SHIFT,
				(count + PAGE_SIZE - 1) >> PAGE_SHIFT, false);
}

static void mi_lb_page_collect_on_pagefault(void *data, struct file *file,
					    pgoff_t first, pgoff_t last,
					    vm_fault_t ret)
{
	if (last < first)
		return;
	mi_lb_pagecache_collect(file, first, last - first + 1, true);
}

/* ---- skip/adjust observers --------------------------------------------- */

/* [dada mi_lb_skip_async_mmap_readahead] background apps skip async RA */
static void mi_lb_skip_async_mmap_readahead(void *data, struct vm_fault *vmf,
					    struct page *page, bool *skip)
{
	struct lb_pkg *pkg;

	if (!lb_skip_background_readahead_enable || !skip)
		return;
	pkg = lb_find_pkg(current_uid());
	if (!pkg)
		return;
	*skip = true;
}

/* [dada adjust_readahead / adjust_readaround] readahead window shaping */
static void adjust_readahead(void *data, struct readahead_control *ractl,
			     unsigned long *max_page)
{
	if (!max_page)
		return;
	/* foreground package: let the full window stand; background: no
	 * shaping here (the skip observer handles background). */
}

static void adjust_readaround(void *data, unsigned int ra_pages,
			      pgoff_t pgoff, pgoff_t *start,
			      unsigned int *size, unsigned int *async_size)
{
}

/* [dada should_skip_fault_around] */
static void should_skip_fault_around(void *data, struct vm_fault *vmf,
				     bool *should_around)
{
	if (!lb_background_faultaround_disable || !should_around)
		return;
	if (!lb_find_pkg(current_uid()))
		*should_around = false;
}

/* ---- preread execution (Tier-1: fadvise over collected ranges) -------- */

static void lb_preread_ranges(struct lb_manager *m)
{
	struct file *files[LB_PREREAD_BATCH];
	pgoff_t starts[LB_PREREAD_BATCH];
	pgoff_t ends[LB_PREREAD_BATCH];
	unsigned int n, i;

	if (lb_only_collect)
		return;
	if (m->preread_stop)
		return;

	/*
	 * [PORT-DELTA] the 6.6 pte path walks the mm with mas_find and
	 * issues read_swap_cache_async per entry; Tier-1 replays the
	 * collected file ranges through vfs_fadvise(POSIX_FADV_WILLNEED),
	 * which drives the same page-cache readahead the cold start
	 * would fault in.  Anon swapin stays Tier-2.
	 *
	 * Batches: detach up to LB_PREREAD_BATCH ranges under the lock
	 * (detached slots are marked free so concurrent collects cannot
	 * reach them), then run the sleeping fadvise calls outside.
	 */
	do {
		n = 0;
		spin_lock(&lb_lock);
		for (i = 0; i < LB_MAX_OPEN_FILES && n < LB_PREREAD_BATCH; i++) {
			struct lb_range *r = &m->ranges[i];

			if (!test_bit(i, m->range_used))
				continue;
			files[n] = r->file;
			starts[n] = r->start;
			ends[n] = r->end;
			__clear_bit(i, m->range_used);
			hlist_del_init(&r->hnode);
			m->nr_ranges--;
			n++;
		}
		spin_unlock(&lb_lock);

		for (i = 0; i < n; i++) {
			loff_t len = ((loff_t)(ends[i] - starts[i] + 1)) <<
				     PAGE_SHIFT;

			atomic64_inc(&m->preread_files);
			atomic64_add(ends[i] - starts[i] + 1,
				     &m->preread_pages);
			if (lb_pte_fadvise_enable)
				vfs_fadvise(files[i],
					    ((loff_t)starts[i]) << PAGE_SHIFT,
					    len, POSIX_FADV_WILLNEED);
			fput(files[i]);
		}
	} while (n == LB_PREREAD_BATCH);
}

/* detach all ranges under lb_lock, then fput outside: fput may sleep
 * (last file ref teardown) and must never run under a spinlock
 * (audit P0). */
static void lb_drop_ranges(struct lb_manager *m)
{
	struct file *files[LB_MAX_OPEN_FILES];
	int i, n = 0;

	lockdep_assert_held(&lb_lock);
	for (i = 0; i < LB_MAX_OPEN_FILES; i++) {
		if (!test_bit(i, m->range_used))
			continue;
		files[n++] = m->ranges[i].file;
		__clear_bit(i, m->range_used);
		hlist_del_init(&m->ranges[i].hnode);
	}
	m->nr_ranges = 0;
	spin_unlock(&lb_lock);
	for (i = 0; i < n; i++)
		fput(files[i]);
	spin_lock(&lb_lock);
}

/* ---- /proc/lb interface (addon contract ASSUME-1/2/3) ------------------ */

static int lb_stats_show(struct seq_file *m, void *v)
{
	struct lb_manager *mgr = READ_ONCE(g_manager);

	if (!mgr) {
		seq_puts(m, "lb: inactive\n");
		return 0;
	}
	seq_printf(m, "collect_on_read: %lld\ncollect_on_fault: %lld\n",
		   atomic64_read(&mgr->collect_on_read),
		   atomic64_read(&mgr->collect_on_fault));
	seq_printf(m, "nr_ranges: %u\npreread_files: %lld\n",
		   mgr->nr_ranges, atomic64_read(&mgr->preread_files));
	seq_printf(m, "preread_pages: %lld\npreread_skips: %lld\n",
		   atomic64_read(&mgr->preread_pages),
		   atomic64_read(&mgr->preread_skips));
	seq_printf(m, "only_collect: %d\npreread_stop: %d\n",
		   lb_only_collect, mgr->preread_stop);
	return 0;
}

static int lb_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, lb_stats_show, NULL);
}

static const struct proc_ops lb_stats_fops = {
	.proc_open	= lb_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int lb_collect_list_show(struct seq_file *m, void *v)
{
	struct lb_manager *mgr = READ_ONCE(g_manager);
	struct lb_pkg *pkg;
	int i;

	if (!mgr)
		return 0;
	/* seq_printf may sleep: snapshot under the lock, print after
	 * (same discipline as millet show; audit P1). */
#define LB_SHOW_MAX 64
	{
		struct { u32 uid; char name[64]; u8 type; bool preread; } snap[LB_SHOW_MAX];
		int n = 0, j;
		unsigned long flags;

		spin_lock_irqsave(&lb_lock, flags);
		for (i = 0; i < LB_HASH_BUCKETS && n < LB_SHOW_MAX; i++) {
			hlist_for_each_entry(pkg, &mgr->pkg_hash[i], hnode) {
				if (n >= LB_SHOW_MAX)
					break;
				snap[n].uid = from_kuid_munged(&init_user_ns, pkg->uid);
				strscpy(snap[n].name, pkg->name, sizeof(snap[n].name));
				snap[n].type = pkg->type;
				snap[n].preread = pkg->mode_preread;
				n++;
			}
		}
		spin_unlock_irqrestore(&lb_lock, flags);
		for (j = 0; j < n; j++)
			seq_printf(m, "%u %s type=%u mode=%s\n", snap[j].uid,
				   snap[j].name, snap[j].type,
				   snap[j].preread ? "preread" : "collect");
	}
#undef LB_SHOW_MAX
	return 0;
}

static int lb_collect_list_open(struct inode *inode, struct file *file)
{
	return single_open(file, lb_collect_list_show, NULL);
}

/* "<uid> <package>" per line; "clear" wipes */
static ssize_t lb_collect_list_write(struct file *file, const char __user *ubuf,
				     size_t count, loff_t *ppos)
{
	char buf[128];
	char name[64];
	unsigned int uid;
	int n;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	if (sysfs_streq(buf, "clear")) {
		struct lb_pkg *pkg;
		struct hlist_node *tmp;
		struct lb_manager *m = READ_ONCE(g_manager);
		int i;

		if (!m)
			return count;
		spin_lock(&lb_lock);
		for (i = 0; i < LB_HASH_BUCKETS; i++) {
			hlist_for_each_entry_safe(pkg, tmp,
						  &m->pkg_hash[i], hnode) {
				hlist_del(&pkg->hnode);
				m->nr_pkgs[pkg->type]--;
				kfree(pkg);
			}
		}
		spin_unlock(&lb_lock);
		return count;
	}

	n = sscanf(buf, "%u %63s", &uid, name);
	if (n != 2)
		return -EINVAL;
	/* lb_add_package_info locks internally (audit P0). */
	if (!lb_add_package_info(name, make_kuid(&init_user_ns, uid),
				 LB_APP_FILE_SEQUENTIAL))
		count = -ENOMEM;
	return count;
}

static const struct proc_ops lb_collect_list_fops = {
	.proc_open	= lb_collect_list_open,
	.proc_read	= seq_read,
	.proc_write	= lb_collect_list_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* per-uid mode node: /proc/lb/<uid>/mode ("collect"|"preread"|"off") */
static ssize_t lb_mode_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct lb_pkg *pkg;
	char buf[16];
	kuid_t uid;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	uid = make_kuid(&init_user_ns,
			(unsigned int)(uintptr_t)PDE_DATA(file_inode(file)));
	if (!uid_valid(uid))
		return -EINVAL;
	spin_lock(&lb_lock);
	pkg = lb_find_pkg_locked(uid);
	if (!pkg) {
		spin_unlock(&lb_lock);
		return -ENOENT;
	}
	if (sysfs_streq(buf, "preread")) {
		pkg->mode_preread = true;
		spin_unlock(&lb_lock);
		/*
		 * Replay outside the lock: vfs_fadvise may sleep (proc
		 * write context is fine for that), and lb_drop_ranges
		 * frees file references which must also run unlocked
		 * relative to the registry lookup above.
		 */
		if (g_manager) {
			lb_preread_ranges(g_manager);
			spin_lock(&lb_lock);
			lb_drop_ranges(g_manager);
			spin_unlock(&lb_lock);
		}
		return count;
	} else if (sysfs_streq(buf, "collect")) {
		pkg->mode_preread = false;
	} else if (sysfs_streq(buf, "off")) {
		/* inline the removal: the helper locks itself and must
		 * not be called with lb_lock held (audit P0). */
		hlist_del(&pkg->hnode);
		g_manager->nr_pkgs[pkg->type]--;
		spin_unlock(&lb_lock);
		kfree(pkg);
		return count;
	} else {
		spin_unlock(&lb_lock);
		return -EINVAL;
	}
	spin_unlock(&lb_lock);
	return count;
}

static const struct proc_ops lb_mode_fops = {
	.proc_open	= NULL,
	.proc_write	= lb_mode_write,
	.proc_lseek	= noop_llseek,
};

static void lb_proc_uid_remove(unsigned int uid)
{
	char name[16];

	snprintf(name, sizeof(name), "%u", uid);
	if (lb_proc_dir)
		remove_proc_entry(name, lb_proc_dir);
}

static int __maybe_unused lb_proc_uid_create(unsigned int uid)
{
	struct proc_dir_entry *pde;
	char name[16];

	if (!lb_proc_dir)
		return -ENOENT;
	snprintf(name, sizeof(name), "%u", uid);
	pde = proc_create_data(name, 0644, lb_proc_dir, &lb_mode_fops,
			       (void *)(uintptr_t)uid);
	return pde ? 0 : -ENOMEM;
}

/* ---- init / exit -------------------------------------------------------- */

static int __init lb_init(void)
{
	struct lb_manager *m;
	int i, ret;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	for (i = 0; i < LB_HASH_BUCKETS; i++) {
		INIT_HLIST_HEAD(&m->pkg_hash[i]);
		INIT_HLIST_HEAD(&m->file_hash[i]);
	}
	m->window_j = jiffies;
	m->window_open = true;
	g_manager = m;

	ret = register_trace_android_vh_filemap_read(
		mi_lb_page_collect_on_readfile, NULL);
	if (ret)
		goto err_free;
	ret = register_trace_android_vh_filemap_map_pages(
		mi_lb_page_collect_on_pagefault, NULL);
	if (ret)
		goto err_unread;
	ret = register_trace_android_vh_do_async_mmap_readahead(
		mi_lb_skip_async_mmap_readahead, NULL);
	if (ret)
		goto err_unmap;
	ret = register_trace_android_vh_ra_tuning_max_page(
		adjust_readahead, NULL);
	if (ret)
		goto err_unasync;
	ret = register_trace_android_vh_tune_mmap_readaround(
		adjust_readaround, NULL);
	if (ret)
		goto err_unra;
	ret = register_trace_android_vh_should_fault_around(
		should_skip_fault_around, NULL);
	if (ret)
		goto err_unaround;

	lb_proc_dir = proc_mkdir("lb", NULL);
	if (!lb_proc_dir) {
		ret = -ENOMEM;
		goto err_unfault;
	}
	if (!proc_create("stats", 0444, lb_proc_dir, &lb_stats_fops) ||
	    !proc_create("collect_list", 0644, lb_proc_dir,
			 &lb_collect_list_fops)) {
		ret = -ENOMEM;
		goto err_proc;
	}

	pr_info("lb: iorap version 2.0.0 (Sew 5.15 Tier-1 port)\n");
	return 0;

err_proc:
	remove_proc_entry("stats", lb_proc_dir);
	remove_proc_entry("collect_list", lb_proc_dir);
	remove_proc_entry("lb", NULL);
	lb_proc_dir = NULL;
err_unfault:
	unregister_trace_android_vh_should_fault_around(
		should_skip_fault_around, NULL);
err_unaround:
	unregister_trace_android_vh_tune_mmap_readaround(
		adjust_readaround, NULL);
err_unra:
	unregister_trace_android_vh_ra_tuning_max_page(
		adjust_readahead, NULL);
err_unasync:
	unregister_trace_android_vh_do_async_mmap_readahead(
		mi_lb_skip_async_mmap_readahead, NULL);
err_unmap:
	unregister_trace_android_vh_filemap_map_pages(
		mi_lb_page_collect_on_pagefault, NULL);
err_unread:
	unregister_trace_android_vh_filemap_read(
		mi_lb_page_collect_on_readfile, NULL);
err_free:
	tracepoint_synchronize_unregister();
	kfree(m);
	g_manager = NULL;
	return ret;
}

static void __exit lb_exit(void)
{
	struct lb_pkg *pkg;
	struct hlist_node *tmp;
	struct lb_manager *m = g_manager;
	int i;

	if (!m)
		return;
	unregister_trace_android_vh_should_fault_around(
		should_skip_fault_around, NULL);
	unregister_trace_android_vh_tune_mmap_readaround(
		adjust_readaround, NULL);
	unregister_trace_android_vh_ra_tuning_max_page(
		adjust_readahead, NULL);
	unregister_trace_android_vh_do_async_mmap_readahead(
		mi_lb_skip_async_mmap_readahead, NULL);
	unregister_trace_android_vh_filemap_map_pages(
		mi_lb_page_collect_on_pagefault, NULL);
	unregister_trace_android_vh_filemap_read(
		mi_lb_page_collect_on_readfile, NULL);
	tracepoint_synchronize_unregister();

	remove_proc_entry("stats", lb_proc_dir);
	remove_proc_entry("collect_list", lb_proc_dir);
	for (i = 0; i < LB_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(pkg, tmp, &m->pkg_hash[i], hnode) {
			unsigned int uid = from_kuid_munged(&init_user_ns,
							    pkg->uid);
			lb_proc_uid_remove(uid);
			hlist_del(&pkg->hnode);
			kfree(pkg);
		}
	}
	remove_proc_entry("lb", NULL);
	lb_proc_dir = NULL;

	spin_lock(&lb_lock);
	lb_drop_ranges(m);
	spin_unlock(&lb_lock);
	kfree(m);
	g_manager = NULL;
}

module_init(lb_init);
module_exit(lb_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Sew Tier-1 port of the Xiaomi OS4 lb (iorap launch-boost prefetch)");
