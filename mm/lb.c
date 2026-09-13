// SPDX-License-Identifier: GPL-2.0-only
/*
 * lb: launch-boost cold-start prefetch, Tier-1 port of the Xiaomi dada
 * OS4 lb.ko (245KB, 57 funcs, 23 module params, depends empty).
 *
 * RE evidence: /root/work/os4_dada/ko/lb.ko (vermagic 6.6.57-android15);
 * raw notes in .omz/research/.../raw/re-lb.txt + this session's collect
 * decode (hook pairing, sew_g_manager layout, range-merge logic).
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
 *   - gate on debug level (sew_g_manager+12 byte / +0 word) and the
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
 *     (uid/pid), count at sew_g_manager+53408/53424.
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
 * execution (vfs_fadvise WILLNEED over the recorded ranges), the
 * six skip/adjust observers, Tier-2 PTE snapshot (per-uid VMA
 * segments via find_vma_intersection + walk_page_range) with
 * gated anon swapin (read_swap_cache_async, built-in direct
 * call),
 * circuit breakers, /proc/lb/{collect_list,stats} + per-uid mode node
 * matching the addon contract (lb_userspace.sh ASSUME-1/2/3), and all
 * 23 module params with dada names/defaults (values from .data: 50/50/
 * 1/4/128/3/50/257/2000/16/8192k/... see LB_* defaults below).
 *  - file-type whitelist: the 6.6 magic-constant triple is an
 *    f_type check; replaced by S_IS_REG(mapping->host->i_mode) +
 *    !special_file().  [PORT-DELTA]
 *  - task+1560/1564 (6.6 pid/tgid): 5.15 uses task_pid_nr/task_tgid_nr.
 *    [PORT-DELTA]
 *  - mas_find (maple tree): absent on 5.15 -> Tier-2 PTE snapshot
 *    enumerates VMAs with find_vma_intersection and walks true
 *    PTEs with walk_page_range (EXPORT_SYMBOL_GPL on 5.15).
 *    [PORT-DELTA]
 *  - page_pinner_inited / __page_pinner_put_page: 5.15 generic
 *    framework exists; the static key is not module-visible, so call
 *    sew_lb_put_page() which uses page_pinner_put_page() only under
 *    CONFIG_PAGE_PINNER and always falls back to put_page().
 *    [PORT-DELTA]
 *  - alt_cb_patch_nops / system_cpucaps: absorbed (rtg.c precedent).
 *  - ioctl numbers: kept (base 0x3ef7b3ff, LB_GET_VERSION=base,
 *    LB_GET_PREREAD_INFO_SIZE = 0x80044c14 decode: dir=2 size=4
 *    type=0x4c nr=20).
 * Everything defaults OFF (collect off, preread off, only_collect=0).
 *
 * G6收尾 (compiler thread + hot_stat, 2026-09-11):
 *  - mi_lb_compiler_thread / mi_lb_do_compile NOT ported. Evidence:
 *    official lb.ko disasm (thread 0x25ec size 0xfe4, do_compile 0x2574
 *    size 0x74): do_compile only __wake_up's the compiler waitqueue when
 *    the package count passes a threshold; the thread itself is a
 *    dex/oat-driven compile pipeline (dex_files_for_bitmap_record does
 *    strstr x3 over .odex/oat names + bitmap_zalloc/__bitmap_set, then
 *    list_sort + kvmalloc_node persisting a ~5MB-capped compiled preread
 *    plan with "compiler finish, compile_time/total_apps/total_memory"
 *    accounting). Our Tier-2 snapshot path (sew_lb_snapshot_mm +
 *    walk_page_range + sew_lb_do_anon_swapin) already walks TRUE PTEs per VMA
 *    and issues swapin directly - the compiler's bitmap/sort/persist
 *    layer would duplicate that with zero incremental hit-rate value, and
 *    would need the official package/range/bitmap stores we deliberately
 *    did not port (different collect table design). A kthread + waitqueue
 *    with no consumer would be dead weight + a lifecycle risk, so the
 *    honest call is: do not implement.
 *  - lb_hot_stat (official rodata 0x664 block) mirrored as READ-ONLY
 *    counters in /proc/lb/stats (see sew_lb_stats_show): avg-time +
 *    interrupt-by-* + snapshot/prepage/err lines share the official
 *    numerators; min/max print cumulative totals with app "-" because we
 *    keep no per-round app-name store; per-uid segs/pages/pre/hit lines
 *    are NOT mirrored (our hot_collect node counts mmput teardowns per
 *    uid by design, documented above). No new behavior, display only.
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
#include <linux/pagewalk.h>
#include <linux/page_pinner.h>
#include <linux/swapops.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>
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
MODULE_PARM_DESC(lb_pte_anon_swapin_enable,
		     "anon swapin sub-gate, needs lb_anon_enable=1");

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

/* Tier-2 snapshot + anon swapin (D2b): master gate, default OFF. */
static bool lb_anon_enable;
module_param(lb_anon_enable, bool, 0644);
MODULE_PARM_DESC(lb_anon_enable, "tier-2 pte snapshot and anon swapin enable");

static int lb_debug = 5;
module_param(lb_debug, int, 0644);
MODULE_PARM_DESC(lb_debug, "iorap debug msg level");

/* ---- collect engine state -------------------------------------------- */
/* Collect bursts on demand: userspace registers a package (or the manager
 * starts), the 5s window opens, it closes on expiry (~5s, matching the
 * 0x1f4-jiffies check: the 6.6 code compares a 5000ms anchor, NOT 50s),
 * and the NEXT collect after the close re-arms a fresh window.  This keeps
 * cold-start collection continuous across launches without an open-ended
 * always-on tap. */
#define SEW_LB_COLLECT_WINDOW_JIFFIES	(50 * HZ / 10)	/* 0x1f4 @ HZ=100 => 5s */
/* Breaker cool-down: preread_stop self-clears only after this much quiet
 * time with no new trip, so a hot loop cannot flap I/O on/off (each
 * re-arm needs a full quiet window first). */
#define SEW_LB_PREREAD_COOLDOWN_JIFFIES	(10 * HZ)	/* 10s quiet window */
#define SEW_LB_MAX_OPEN_FILES		2048
#define SEW_LB_PREREAD_BATCH		32
#define SEW_LB_HASH_BUCKETS			64
#define SEW_LB_UID_HASH_MASK		0x3f

enum sew_lb_app_type {
	SEW_LB_APP_FILE_SEQUENTIAL = 0,
	SEW_LB_APP_REAL_TIMING = 1,
	SEW_LB_APP_TYPES = 2,
};

struct sew_lb_pkg {
	struct hlist_node	hnode;
	char			name[64];
	kuid_t			uid;
	pid_t			pid;		/* last seen tgid, for snapshot task lookup */
	u8			type;
	bool			mode_preread;	/* /proc/lb/<uid>/mode wrote preread */
};

struct sew_lb_range {
	struct hlist_node	hnode;
	struct file		*file;		/* holds a reference */
	pgoff_t			start;
	pgoff_t			end;
};

struct sew_lb_manager {
	/* collect window anchor (jiffies) */
	unsigned long		window_j;
	bool			window_open;
	/* preread breaker: sticky stop + last-trip anchor (jiffies).  The
	 * stop self-clears only after SEW_LB_PREREAD_COOLDOWN_JIFFIES of
	 * quiet (see sew_lb_preread_gate); the anchor is refreshed on
	 * every trip so a hot loop cannot flap I/O on/off. */
	unsigned long		stop_j;
	/* open-file table: file+range pairs, bounded */
	struct sew_lb_range		ranges[SEW_LB_MAX_OPEN_FILES];
	DECLARE_BITMAP(range_used, SEW_LB_MAX_OPEN_FILES);
	/* per-uid range hash for quick merge checks */
	struct hlist_head	file_hash[SEW_LB_HASH_BUCKETS];
	unsigned int		nr_ranges;
	/* uid registry */
	struct hlist_head	pkg_hash[SEW_LB_HASH_BUCKETS];
	unsigned int		nr_pkgs[SEW_LB_APP_TYPES];
	/* circuit breakers (us) */
	u64			swapin_total_us;
	u64			rlock_total_us;
	/* stats */
	atomic64_t		collect_on_read;
	atomic64_t		collect_on_fault;
	atomic64_t		preread_files;
	atomic64_t		preread_pages;
	atomic64_t		preread_skips;
	atomic64_t		hot_total;	/* D2a: mmput observations */
	bool			preread_stop;
	/* G6 hot_stat (official rodata 0x664 display block, read-only): the
	 * official lb_hot_collect_show prints "avg time,
	 * rlock/swapin/fadvise/total" + "interrupt, by ioctl/rlock/swapin"
	 * + "min/max_swapin, time/app". We keep the same numerators
	 * (cumulative us + round count) and derive averages at show time.
	 * min/max per-app lines need a stored app name we do not keep, so
	 * those print cumulative totals with app "-" (see sew_lb_stats_show).
	 * hot_fadvise_us stays 0: the uid snapshot path has no file-WILLNEED
	 * segment (that timing lives in the collect preread path, untimed).
	 * All writers hold sew_lb_lock; show path snapshots under sew_lb_lock. */
	u64			hot_rounds;	/* completed snapshot rounds */
	u64			hot_swapin_us;	/* sum of per-round swapin us */
	u64			hot_rlock_us;	/* sum of mmap-lock wait us */
	u64			hot_fadvise_us;	/* always 0 (see above) */
	u64			hot_total_us;	/* sum of per-round wall us */
	u64			hot_int_ioctl;	/* EBUSY from io-breaker triage */
	u64			hot_int_rlock;	/* rlock熔断 exits */
	u64			hot_int_swapin;	/* swapin over-threshold exits */
	u64			hot_snap_ok;	/* rounds reaching walk completion */
	u64			hot_snap_err;	/* rounds failing before completion */
	u64			hot_prepage;	/* swap entries issued (nr_swaps sum) */
};

/* D2a hot_collect: independent xarray record table guarded by sew_hot_lock.
 * sew_hot_lock NEVER nests with sew_lb_lock (no path takes both); both are
 * leaf-level spinlocks. */
struct sew_lb_hot_rec {
	u32	uid;
	u64	count;
};

static struct xarray sew_lb_hot_xa __maybe_unused = XARRAY_INIT(sew_lb_hot_xa, 0);
static spinlock_t sew_hot_lock __maybe_unused = __SPIN_LOCK_UNLOCKED(sew_hot_lock);

static struct sew_lb_manager *sew_g_manager;
static DEFINE_SPINLOCK(sew_lb_lock);
static struct proc_dir_entry *sew_lb_proc_dir;

/* ---- package registry -------------------------------------------------- */

/* caller must hold sew_lb_lock (registry is spinlock-guarded, not RCU). */
static struct sew_lb_pkg *sew_lb_find_pkg_locked(kuid_t uid)
{
	struct sew_lb_pkg *pkg;
	unsigned int bkt;

	lockdep_assert_held(&sew_lb_lock);
	if (!sew_g_manager)
		return NULL;
	bkt = from_kuid_munged(&init_user_ns, uid) & SEW_LB_UID_HASH_MASK;
	hlist_for_each_entry(pkg, &sew_g_manager->pkg_hash[bkt], hnode) {
		if (uid_eq(pkg->uid, uid))
			return pkg;
	}
	return NULL;
}

static struct sew_lb_pkg *sew_lb_find_pkg(kuid_t uid)
{
	struct sew_lb_pkg *pkg;
	unsigned long flags;

	spin_lock_irqsave(&sew_lb_lock, flags);
	pkg = sew_lb_find_pkg_locked(uid);
	spin_unlock_irqrestore(&sew_lb_lock, flags);
	return pkg;
}

static struct sew_lb_pkg *sew_lb_add_package_info(const char *name, kuid_t uid, u8 type)
{
	struct sew_lb_pkg *pkg;
	unsigned int bkt;

	if (!sew_g_manager)
		return NULL;
	/* alloc outside the lock (kzalloc sleeps); re-check after taking
	 * it so concurrent adds cannot double-insert (audit P0). */
	pkg = kzalloc(sizeof(*pkg), GFP_KERNEL);
	if (!pkg)
		return NULL;
	strscpy(pkg->name, name, sizeof(pkg->name));
	pkg->uid = uid;
	pkg->type = type;
	bkt = from_kuid_munged(&init_user_ns, uid) & SEW_LB_UID_HASH_MASK;
	spin_lock(&sew_lb_lock);
	{
		struct sew_lb_pkg *e = sew_lb_find_pkg_locked(uid);

		if (e) {
			spin_unlock(&sew_lb_lock);
			kfree(pkg);
			return e;
		}
		if (type == SEW_LB_APP_FILE_SEQUENTIAL &&
		    sew_g_manager->nr_pkgs[type] >= lb_max_file_sequential_apps) {
			spin_unlock(&sew_lb_lock);
			kfree(pkg);
			return NULL;
		}
		if (type == SEW_LB_APP_REAL_TIMING &&
		    sew_g_manager->nr_pkgs[type] >= lb_max_real_timing_apps) {
			spin_unlock(&sew_lb_lock);
			kfree(pkg);
			return NULL;
		}
		hlist_add_head(&pkg->hnode, &sew_g_manager->pkg_hash[bkt]);
		sew_g_manager->nr_pkgs[type]++;
	}
	spin_unlock(&sew_lb_lock);
	return pkg;
}

/* ---- collect core (dada mi_lb_pagecache_collect semantics) ------------ */

/* D2a atrace: wired to the existing lb_atrace_enable param. Two prints:
 * file path (file_path snapshot of the collected file) + pr_info when
 * verbose. Lock rule: file_path may sleep -> never under sew_lb_lock. The
 * collect path snapshots the path BEFORE taking sew_lb_lock and only
 * pr_infos after unlock (audit E1 #7). This helper takes no lock itself
 * (printk-safe) and must only be called with a pre-snapshotted path. */
static void sew_lb_atrace_collect(const char *path, pgoff_t pgoff, pgoff_t nr,
			      bool fault)
{
	if (!lb_atrace_enable)
		return;
	pr_info("lb: atrace %s pgoff=%lu nr=%lu path=%s\n",
		fault ? "fault" : "read", (unsigned long)pgoff,
		(unsigned long)nr, path ? path : "?");
}

/* Pre-lock path snapshot for atrace (E1 #7): file_path uses
 * d_path+symlink resolution which requires sleepable context, so this
 * runs BEFORE sew_lb_lock is taken; the caller prints after unlock. */
static void sew_lb_atrace_snap_path(struct file *file, char *buf, size_t len)
{
	char *path;

	buf[0] = '\0';
	if (!lb_atrace_enable || !file)
		return;
	path = file_path(file, buf, len);
	if (IS_ERR(path))
		buf[0] = '\0';
	else if (path != buf)
		memmove(buf, path, strlen(path) + 1);
}

static bool sew_lb_file_ok(struct file *file)
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

static void sew_lb_range_add(struct sew_lb_manager *m, struct file *file,
			 pgoff_t start, pgoff_t nr)
{
	struct sew_lb_range *r = NULL;
	unsigned int bkt;
	int i;

	lockdep_assert_held(&sew_lb_lock);

	/* merge with an existing range of the same file within gap.
	 * No-overlap-before-subtract (E1 #9): new range [start, start+nr)
	 * vs existing [r->start, r->end] (inclusive). The old unsigned test
	 * `start - r->end <= gap+nr` wraps to ~ULONG_MAX when the ranges
	 * overlap (start <= r->end), silently dropping the add; and
	 * `start + nr` below can itself overflow for huge pgoff. Test the
	 * disjoint cases first, subtract only on the known-safe side. */
	bkt = hash_ptr(file->f_mapping, ilog2(SEW_LB_HASH_BUCKETS));
	hlist_for_each_entry(r, &m->file_hash[bkt], hnode) {
		pgoff_t new_end;
		bool disjoint_before, disjoint_after;

		if (r->file->f_mapping != file->f_mapping)
			continue;
		/* saturate the new end: overflowed start+nr clamps to -1 so a
		 * wrapped-around interval can never compare "before". */
		new_end = start + nr - 1;
		if (new_end < start)
			new_end = (pgoff_t)-1;
		disjoint_before = new_end < r->start &&
			r->start - new_end - 1 > lb_max_gap_range;
		disjoint_after = start > r->end &&
			start - r->end - 1 > lb_max_gap_range;
		if (disjoint_before || disjoint_after)
			return; /* same file, far away: keep the first range */
		if (start < r->start)
			r->start = start;
		if (new_end > r->end)
			r->end = new_end;
		return;
	}

	if (m->nr_ranges >= lb_max_merge_range + SEW_LB_HASH_BUCKETS)
		return; /* bounded table */

	i = find_first_zero_bit(m->range_used, SEW_LB_MAX_OPEN_FILES);
	if (i >= SEW_LB_MAX_OPEN_FILES)
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
	struct sew_lb_manager *m;
	struct sew_lb_pkg *pkg;
	/* atrace path snapshot (E1 #7): file_path may sleep, so resolve it
	 * here in sleepable hook context, before sew_lb_lock is taken. */
	char atrace_path[256];

	if (lb_debug < 3 || !nr)
		return;
	m = READ_ONCE(sew_g_manager);
	if (!m)
		return;
	sew_lb_atrace_snap_path(file, atrace_path, sizeof(atrace_path));

	/* collect window (5s anchor like the 0x1f4 jiffies check).
	 * window state and the uid registry both live under sew_lb_lock;
	 * the registry is spinlock-guarded, not RCU (audit P0).  A closed
	 * window re-arms on the next collect (fresh 5s), so collection
	 * stays continuous across launches instead of firing once. */
	spin_lock(&sew_lb_lock);
	if (!m->window_open) {
		if (time_is_before_jiffies(m->window_j)) {
			spin_unlock(&sew_lb_lock);
			return;
		}
		/* close quarantine expired: re-arm a fresh window. */
		m->window_open = true;
		m->window_j = jiffies;
	} else if (time_after(jiffies, m->window_j +
			      SEW_LB_COLLECT_WINDOW_JIFFIES)) {
		m->window_open = false;
		m->window_j = jiffies;
	}

	pkg = sew_lb_find_pkg_locked(current_uid());
	if (!pkg) {
		spin_unlock(&sew_lb_lock);
		return;
	}
	pkg->pid = task_tgid_nr(current);
	if (!sew_lb_file_ok(file)) {
		spin_unlock(&sew_lb_lock);
		return;
	}
	if (fault)
		atomic64_inc(&m->collect_on_fault);
	else
		atomic64_inc(&m->collect_on_read);
	sew_lb_range_add(m, file, pgoff, nr);
	spin_unlock(&sew_lb_lock);
	/* atrace print after unlock (E1 #7): path was snapshotted above. */
	sew_lb_atrace_collect(atrace_path[0] ? atrace_path : NULL,
			  pgoff, nr, fault);
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
	struct sew_lb_pkg *pkg;

	if (!lb_skip_background_readahead_enable || !skip)
		return;
	pkg = sew_lb_find_pkg(current_uid());
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
	if (!sew_lb_find_pkg(current_uid()))
		*should_around = false;
}

/* ---- D2a hot_collect (mm teardown observer, 5.15: android_vh_mmput) -----
 * Registered in sew_lb_init as android_vh_mmput (5.15 single-arg hook; 6.6
 * was android_vh_mmput_mm). Counts teardowns per uid into sew_lb_hot_xa.
 * Lock order (E1 #8): sew_hot_lock -> xa_lock(leafmost). The fast-path
 * count++ RMW is NOT done under bare xa_load: xa_load is only legal in
 * contexts that pin the entry against erase, so the whole load-bump is
 * wrapped in xa_lock; concurrent sew_lb_exit drain cannot free under us
 * because drain holds xa_lock across erase (exit holds no sew_hot_lock, and
 * insert/drop paths use sew_hot_lock outer + xa_lock inner, never reverse).
 * Lockdep: sew_hot_lock is a leaf vs sew_lb_lock (no path takes both). */
static void sew_lb_hot_on_mmput(void *data, struct mm_struct *mm)
{
	struct sew_lb_hot_rec *rec;
	unsigned long uid32;
	void *entry;
	unsigned long flags;

	if (!READ_ONCE(sew_g_manager) || !mm)
		return;
	/* Attribute to current uid: mm->owner->cred would need RCU/task
	 * lock and owner may already be torn down at mmput time; the
	 * exiting task (current) is the safe attribution here. */
	uid32 = (unsigned long)from_kuid_munged(&init_user_ns, current_uid());
	spin_lock_irqsave(&sew_hot_lock, flags);
	xa_lock(&sew_lb_hot_xa);
	entry = xa_load(&sew_lb_hot_xa, uid32);
	if (entry) {
		((struct sew_lb_hot_rec *)entry)->count++;
		xa_unlock(&sew_lb_hot_xa);
		spin_unlock_irqrestore(&sew_hot_lock, flags);
	} else {
		xa_unlock(&sew_lb_hot_xa);
		spin_unlock_irqrestore(&sew_hot_lock, flags);
		rec = kzalloc(sizeof(*rec), GFP_ATOMIC);
		if (!rec)
			return;
		rec->uid = (u32)uid32;
		rec->count = 1;
		xa_lock(&sew_lb_hot_xa);
		entry = __xa_cmpxchg(&sew_lb_hot_xa, uid32, NULL, rec, GFP_ATOMIC);
		xa_unlock(&sew_lb_hot_xa);
		if (entry) {
			/* lost the race: another CPU inserted first; re-bump
			 * under xa_lock so the winner cannot be erased
			 * mid-RMW (the exit drain erases only under
			 * xa_lock, after unregister+sync leaves no new
			 * writers). */
			kfree(rec);
			spin_lock_irqsave(&sew_hot_lock, flags);
			xa_lock(&sew_lb_hot_xa);
			entry = xa_load(&sew_lb_hot_xa, uid32);
			if (entry)
				((struct sew_lb_hot_rec *)entry)->count++;
			xa_unlock(&sew_lb_hot_xa);
			spin_unlock_irqrestore(&sew_hot_lock, flags);
		}
	}
	if (sew_g_manager)
		atomic64_inc(&sew_g_manager->hot_total);
}

/* ---- Tier-2: PTE snapshot + anon swapin (D2b) -------------------------- *
 * B3 conclusions applied: enumerate VMAs with find_vma_intersection (5.15
 * has no mas_find), walk true PTEs with walk_page_range (EXPORT_SYMBOL_GPL
 * on 5.15).  __pte_offset_map_lock is a macro on 5.15 (mm.h) so the anon
 * swapin path uses the pte_offset_map_lock/pte_unmap_unlock macros only
 * where a direct PTE dereference is needed (the walker already holds the
 * PTE table lock in pte_entry).  read_swap_cache_async has the same
 * signature on 5.15 but no EXPORT; lb is built-in (obj-$(CONFIG_LB)) so a
 * direct call is fine.
 * Lock order: mm->mmap_lock is ALWAYS outermost; sew_lb_lock is never held
 * across mmap_lock (snapshot alloc + task/mm lookup run outside sew_lb_lock).
 * Both gates must be on: lb_anon_enable (master, default 0) and
 * lb_pte_anon_swapin_enable (sub-gate). */

#define SEW_LB_SNAP_MAX_SEG		257	/* == lb_max_pte_segment_count default */
#define SEW_LB_SNAP_MAX_SWAP	512	/* bounded anon swap-entry buffer */
#define SEW_LB_IO_MAX_COUNT		1024	/* snapshot count threshold per window */
#define SEW_LB_IO_WINDOW_JIFFIES	(HZ)	/* 1s window for the dual thresholds */

struct sew_lb_seg {
	unsigned long	start;
	unsigned long	end;
	bool		is_file;	/* false = anon VMA */
};

struct sew_lb_snap {
	struct sew_lb_seg	segs[SEW_LB_SNAP_MAX_SEG];
	unsigned int	nr_segs;
	swp_entry_t	swaps[SEW_LB_SNAP_MAX_SWAP];
	unsigned int	nr_swaps;
	pid_t		pid;
	u32		uid;
};

/* I/O circuit breaker: dual thresholds (count + time window); when the
 * windowed snapshot count exceeds SEW_LB_IO_MAX_COUNT, new snapshots pause
 * until the window rolls over. */
struct sew_lb_io_brk {
	unsigned long	win_j;
	unsigned int	count;
	bool		tripped;
};

static struct sew_lb_io_brk sew_lb_io = {
	.win_j = 0,
	.count = 0,
	.tripped = false,
};

/* Central trip point: set sticky stop AND refresh the cool-down anchor.
 * sew_lb_lock must be held by caller. */
static void sew_lb_trip_stop_locked(void)
{
	lockdep_assert_held(&sew_lb_lock);
	if (READ_ONCE(sew_g_manager)) {
		sew_g_manager->preread_stop = true;
		sew_g_manager->stop_j = jiffies;
	}
}

/* Entry gate for preread work: self-clears a stale stop only after a full
 * quiet cool-down with no new trip (anchor refreshed on every trip, so a
 * hot loop never sees quiet).  sew_lb_lock must be held by caller. */
static bool sew_lb_preread_gate_locked(void)
{
	struct sew_lb_manager *m = READ_ONCE(sew_g_manager);

	lockdep_assert_held(&sew_lb_lock);
	if (!m)
		return false;
	if (m->preread_stop &&
	    time_after(jiffies, m->stop_j + SEW_LB_PREREAD_COOLDOWN_JIFFIES)) {
		m->preread_stop = false;
		m->swapin_total_us = 0;
		m->rlock_total_us = 0;
	}
	return !m->preread_stop;
}

static bool sew_lb_io_allow(void)
{
	/* sew_lb_lock held by caller (breaker state lives next to manager). */
	lockdep_assert_held(&sew_lb_lock);
	if (time_after(jiffies, sew_lb_io.win_j + SEW_LB_IO_WINDOW_JIFFIES)) {
		sew_lb_io.win_j = jiffies;
		sew_lb_io.count = 0;
		sew_lb_io.tripped = false;
	}
	if (sew_lb_io.tripped)
		return false;
	if (++sew_lb_io.count > SEW_LB_IO_MAX_COUNT) {
		sew_lb_io.tripped = true;
		sew_lb_trip_stop_locked();
		return false;
	}
	return true;
}

/* single-track page release: pin-debug hook when available, else put_page */
static inline void sew_lb_put_page(struct page *page)
{
#ifdef CONFIG_PAGE_PINNER
	page_pinner_put_page(page);
#endif
	put_page(page);
}

struct sew_lb_walk_priv {
	struct sew_lb_snap	*snap;
};

/* pte_entry: called with the PTE table lock held by walk_pte_range, so no
 * extra pte_offset_map_lock is needed here; just classify the entry. */
static int sew_lb_snap_pte_entry(pte_t *pte, unsigned long addr,
			     unsigned long next, struct mm_walk *walk)
{
	struct sew_lb_walk_priv *priv = walk->private;
	struct sew_lb_snap *snap = priv->snap;
	pte_t ptent = *pte;

	if (pte_present(ptent))
		return 0;
	if (!is_swap_pte(ptent))
		return 0;
	/* skip migration/device/private markers: swapin only real swap */
	if (non_swap_entry(pte_to_swp_entry(ptent)))
		return 0;
	if (snap->nr_swaps >= SEW_LB_SNAP_MAX_SWAP ||
	    snap->nr_swaps >= lb_max_pte_segment_count)
		return 1; /* stop: bounded buffer full */
	snap->swaps[snap->nr_swaps++] = pte_to_swp_entry(ptent);
	return 0;
}

static int sew_lb_snap_pmd_entry(pmd_t *pmd, unsigned long addr,
			     unsigned long next, struct mm_walk *walk)
{
	/* THP pmd: present huge pages need no swapin; walker splits the
	 * rest as needed. */
	if (pmd_trans_huge(*pmd) && pmd_present(*pmd))
		return 0;
	return 0;
}

static const struct mm_walk_ops sew_lb_snap_ops = {
	.pmd_entry	= sew_lb_snap_pmd_entry,
	.pte_entry	= sew_lb_snap_pte_entry,
};

/*
 * sew_lb_snapshot_mm - enumerate VMAs with find_vma_intersection (mmap_lock
 * must be held by caller), record segments, and run walk_page_range per
 * segment for anon VMAs (or all when lb_pte_mark_file_anon_enable set).
 */
static int sew_lb_snapshot_mm(struct mm_struct *mm, struct sew_lb_snap *snap)
{
	unsigned long addr = 0;
	struct vm_area_struct *vma;
	int ret = 0;

	mmap_assert_locked(mm);
	while (snap->nr_segs < SEW_LB_SNAP_MAX_SEG &&
	       snap->nr_segs < lb_max_pte_segment_count) {
		/* lock is already held on entry (official order swapped:
		 * lock first, find after). */
		vma = find_vma_intersection(mm, addr, TASK_SIZE);
		if (!vma)
			break;
		if (vma->vm_end <= addr)
			break; /* no forward progress: stop */
		snap->segs[snap->nr_segs].start = vma->vm_start;
		snap->segs[snap->nr_segs].end = vma->vm_end;
		snap->segs[snap->nr_segs].is_file = !vma_is_anonymous(vma);
		snap->nr_segs++;
		addr = vma->vm_end;
		if (addr >= TASK_SIZE)
			break;
		/* walk true PTEs of this segment while still under the
		 * outer mmap_lock (walk_page_range requires it). */
		if (!snap->segs[snap->nr_segs - 1].is_file ||
		    lb_pte_mark_file_anon_enable) {
			struct sew_lb_walk_priv priv = { .snap = snap };

			ret = walk_page_range(mm, vma->vm_start, vma->vm_end,
					      &sew_lb_snap_ops, &priv);
			if (ret < 0)
				return ret;
			if (ret > 0) {
				ret = 0; /* buffer-full stop is not an error */
				break;
			}
		}
	}
	return ret;
}

/*
 * sew_lb_do_anon_swapin - issue read_swap_cache_async over the bounded swap
 * buffer collected during the snapshot.  Runs WITHOUT mmap_lock and
 * without sew_lb_lock (swap I/O sleeps); vma is NULL and addr 0 because the
 * snapshot only guarantees the entry, and alloc_page_vma tolerates a
 * NULL vma (node-local fallback).  Double-gated on lb_anon_enable and
 * lb_pte_anon_swapin_enable.
 */
static void sew_lb_do_anon_swapin(struct sew_lb_snap *snap)
{
	unsigned int i;
	ktime_t t0, t1;
	u64 delta_us;

	if (!lb_anon_enable || !lb_pte_anon_swapin_enable)
		return;
	if (!snap->nr_swaps || !sew_g_manager)
		return;
	t0 = ktime_get();
	for (i = 0; i < snap->nr_swaps; i++) {
		struct page *page;

		page = read_swap_cache_async(snap->swaps[i], GFP_KERNEL,
					     NULL, 0, false);
		if (IS_ERR_OR_NULL(page))
			continue;
		sew_lb_put_page(page);
		if (lb_swapin_expire_interruput_enable) {
			delta_us = (u64)ktime_to_us(ktime_sub(ktime_get(), t0));
			if (delta_us > lb_swapin_total_time_threshold)
				break;
		}
	}
	t1 = ktime_get();
	delta_us = (u64)ktime_to_us(ktime_sub(t1, t0));
	/* concurrent pte-writes for different uids share these counters */
	spin_lock(&sew_lb_lock);
	sew_g_manager->swapin_total_us += delta_us;
	if (sew_g_manager->swapin_total_us > lb_swapin_total_time_threshold)
		sew_lb_trip_stop_locked();
	/* G6 hot_stat: this round's swapin share + issued prepage count. */
	sew_g_manager->hot_swapin_us += delta_us;
	sew_g_manager->hot_prepage += snap->nr_swaps;
	if (lb_swapin_expire_interruput_enable &&
	    delta_us > lb_swapin_total_time_threshold)
		sew_g_manager->hot_int_swapin++;
	spin_unlock(&sew_lb_lock);
	atomic64_add(snap->nr_swaps, &sew_g_manager->preread_pages);
}

/* proc-triggered snapshot for one uid: resolve pkg->task->mm outside
 * sew_lb_lock, then snapshot under mmap_lock, then swapin unlocked. */
static int sew_lb_snapshot_uid(u32 uid)
{
	struct sew_lb_manager *m = READ_ONCE(sew_g_manager);
	struct task_struct *task;
	struct mm_struct *mm;
	struct sew_lb_snap *snap;
	kuid_t kuid;
	pid_t pid = 0;
	unsigned long flags;
	ktime_t round_t0;
	int ret = -ENOENT;

	if (!m)
		return -ENODEV;
	if (!lb_anon_enable)
		return -EPERM;
	kuid = make_kuid(&init_user_ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	/* resolve pid under sew_lb_lock, then drop it before task lookup.
	 * The preread gate runs first: a stale stop self-clears only after
	 * a full quiet cool-down; a hot loop stays stopped here. */
	spin_lock_irqsave(&sew_lb_lock, flags);
	if (!sew_lb_preread_gate_locked()) {
		m = READ_ONCE(sew_g_manager);
		if (m) {
			m->hot_int_ioctl++;
			m->hot_snap_err++;
		}
		spin_unlock_irqrestore(&sew_lb_lock, flags);
		return -EBUSY;
	}
	{
		struct sew_lb_pkg *pkg = sew_lb_find_pkg_locked(kuid);

		if (pkg)
			pid = pkg->pid;
		/* G6: io-breaker triage maps to official "interrupt, by ioctl". */
		if (!sew_lb_io_allow()) {
			/* sew_lb_lock held: count the triage here; the shared
			 * -EBUSY tail below cannot tell triage apart. */
			m = READ_ONCE(sew_g_manager);
			if (m) {
				m->hot_int_ioctl++;
				m->hot_snap_err++;
			}
			spin_unlock_irqrestore(&sew_lb_lock, flags);
			return -EBUSY;
		}
	}
	spin_unlock_irqrestore(&sew_lb_lock, flags);
	if (!pid)
		return -ENOENT;

	snap = kzalloc(sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;
	snap->pid = pid;
	snap->uid = uid;

	/* G6 hot_stat: round wall clock starts after the pid resolve. */
	round_t0 = ktime_get();
	task = find_get_task_by_vpid(pid);
	if (!task) {
		ret = -ESRCH;
		goto out_hot_err;
	}
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) {
		ret = -ESRCH;
		goto out_hot_err;
	}
	if (!mmap_read_trylock(mm)) {
		u64 wait_us;
		ktime_t t0 = ktime_get();

		mmap_read_lock(mm);
		wait_us = (u64)ktime_to_us(ktime_sub(ktime_get(), t0));
		spin_lock(&sew_lb_lock);
		m->rlock_total_us += wait_us;
		if (m->rlock_total_us > lb_rlock_acquire_threshold)
			sew_lb_trip_stop_locked();
		/* G6 hot_stat: rlock share of this round. */
		m->hot_rlock_us += wait_us;
		spin_unlock(&sew_lb_lock);
		if (lb_rlock_expire_interruput_enable &&
		    wait_us > lb_rlock_acquire_threshold) {
			mmap_read_unlock(mm);
			mmput(mm);
			ret = -EBUSY;
			/* G6 hot_stat: rlock熔断 exit. */
			spin_lock(&sew_lb_lock);
			m->hot_int_rlock++;
			m->hot_snap_err++;
			m->hot_total_us += (u64)ktime_to_us(ktime_sub(
				ktime_get(), round_t0));
			spin_unlock(&sew_lb_lock);
			goto out_hot_done;
		}
	}
	/* lock first, find after (find_vma requires the lock held) */
	ret = sew_lb_snapshot_mm(mm, snap);
	mmap_read_unlock(mm);
	mmput(mm);
	if (ret)
		goto out_hot_err;
	sew_lb_do_anon_swapin(snap);
	/* G6 hot_stat: completed round; wall time covers walk + swapin. */
	spin_lock(&sew_lb_lock);
	m->hot_rounds++;
	m->hot_snap_ok++;
	m->hot_total_us += (u64)ktime_to_us(ktime_sub(ktime_get(), round_t0));
	spin_unlock(&sew_lb_lock);
	ret = (int)snap->nr_segs;
	goto out_hot_done;
out_hot_err:
	/* G6 hot_stat: round failed before walk completion. The io-breaker
	 * triage (-EBUSY without pid/task/mm) maps to the official
	 * "interrupt, by ioctl" line; other errors just count snap_err. */
	spin_lock(&sew_lb_lock);
	if (ret == -EBUSY)
		m->hot_int_ioctl++;
	m->hot_snap_err++;
	m->hot_total_us += (u64)ktime_to_us(ktime_sub(ktime_get(), round_t0));
	spin_unlock(&sew_lb_lock);
out_hot_done:
	kfree(snap);
	return ret;
}

/* ---- preread execution (Tier-1: fadvise over collected ranges) -------- */

static void sew_lb_preread_ranges(struct sew_lb_manager *m)
{
	struct file *files[SEW_LB_PREREAD_BATCH];
	pgoff_t starts[SEW_LB_PREREAD_BATCH];
	pgoff_t ends[SEW_LB_PREREAD_BATCH];
	unsigned int n, i;

	if (lb_only_collect)
		return;
	/* Self-healing gate (K7-FIX-K3 P1-1): a stale stop clears only
	 * after a full quiet cool-down (see sew_lb_preread_gate_locked);
	 * hot loops stay stopped.  Lock is taken/released inside to
	 * check-and-clear. */
	spin_lock(&sew_lb_lock);
	if (!sew_lb_preread_gate_locked()) {
		spin_unlock(&sew_lb_lock);
		return;
	}
	spin_unlock(&sew_lb_lock);

	/*
	 * [PORT-DELTA] the 6.6 pte path walks the mm with mas_find and
	 * issues read_swap_cache_async per entry; Tier-1 replays the
	 * collected file ranges through vfs_fadvise(POSIX_FADV_WILLNEED),
	 * which drives the same page-cache readahead the cold start
	 * would fault in.  True-PTE snapshot + anon swapin is Tier-2
	 * (D2b): sew_lb_snapshot_mm/sew_lb_do_anon_swapin above, gated on
	 * lb_anon_enable + lb_pte_anon_swapin_enable.
	 *
	 * Batches: detach up to SEW_LB_PREREAD_BATCH ranges under the lock
	 * (detached slots are marked free so concurrent collects cannot
	 * reach them), then run the sleeping fadvise calls outside.
	 */
	do {
		n = 0;
		spin_lock(&sew_lb_lock);
		for (i = 0; i < SEW_LB_MAX_OPEN_FILES && n < SEW_LB_PREREAD_BATCH; i++) {
			struct sew_lb_range *r = &m->ranges[i];

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
		spin_unlock(&sew_lb_lock);

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
	} while (n == SEW_LB_PREREAD_BATCH);
}

/* detach all ranges under sew_lb_lock, then fput outside: fput may sleep
 * (last file ref teardown) and must never run under a spinlock
 * (audit P0). */
static void sew_lb_drop_ranges(struct sew_lb_manager *m)
{
/* Batched: a full SEW_LB_MAX_OPEN_FILES (2048) pointer array would be 16K on
 * the stack, over the 2K frame limit. 32 entries (256B) per round, and
 * every round clears bits so the loop makes progress. */
#define SEW_LB_DROP_BATCH 32
	struct file *files[SEW_LB_DROP_BATCH];
	int i, n;

	lockdep_assert_held(&sew_lb_lock);
	m->nr_ranges = 0;
	do {
		n = 0;
		for (i = 0; i < SEW_LB_MAX_OPEN_FILES && n < SEW_LB_DROP_BATCH; i++) {
			if (!test_bit(i, m->range_used))
				continue;
			files[n++] = m->ranges[i].file;
			__clear_bit(i, m->range_used);
			hlist_del_init(&m->ranges[i].hnode);
		}
		if (!n)
			break;
		spin_unlock(&sew_lb_lock);
		for (i = 0; i < n; i++)
			fput(files[i]);
		spin_lock(&sew_lb_lock);
	} while (n == SEW_LB_DROP_BATCH);
#undef SEW_LB_DROP_BATCH
}

/* ---- /proc/lb interface (addon contract ASSUME-1/2/3) ------------------ */

static int sew_lb_stats_show(struct seq_file *m, void *v)
{
	struct sew_lb_manager *mgr = READ_ONCE(sew_g_manager);

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
	seq_printf(m, "hot_total: %lld\n",
		   atomic64_read(&mgr->hot_total));
	seq_printf(m, "anon_enable: %d\nswapin_total_us: %llu\nrlock_total_us: %llu\n",
		   lb_anon_enable, mgr->swapin_total_us, mgr->rlock_total_us);
	/* G6 hot_stat (official rodata 0x664 display block, read-only view).
	 * Averages are derived (total/rounds, 0 when no rounds yet) so the
	 * output matches the official "avg time, rlock/swapin/fadvise/total"
	 * line shape. min/max_swapin need a stored per-round app name which
	 * we deliberately do not keep (no new allocs on the snapshot path),
	 * so those lines print cumulative totals with app "-". hot_fadvise
	 * stays 0: the uid snapshot path has no file-WILLNEED segment (file
	 * replay timing lives in the collect preread path, untimed). The
	 * per-uid "segs/pages/pre/hit" lines and the "anon/pre_anon/file/
	 * pre_file" line live in the official hot_collect node; ours counts
	 * mmput teardowns per uid instead (D2a design decision, documented
	 * in the file header), so only the aggregate "snapshot/prepage/err"
	 * line is mirrored here. Counters are snapshotted under sew_lb_lock;
	 * seq_printf runs after unlock (may sleep). */
	{
		u64 rounds, sw_us, rl_us, fa_us, tot_us, i_ioctl, i_rlock,
		    i_swap, snap_ok, snap_err, prepage;
		u64 avg_rl = 0, avg_sw = 0, avg_fa = 0, avg_tot = 0;

		spin_lock(&sew_lb_lock);
		rounds = mgr->hot_rounds;
		sw_us = mgr->hot_swapin_us;
		rl_us = mgr->hot_rlock_us;
		fa_us = mgr->hot_fadvise_us;
		tot_us = mgr->hot_total_us;
		i_ioctl = mgr->hot_int_ioctl;
		i_rlock = mgr->hot_int_rlock;
		i_swap = mgr->hot_int_swapin;
		snap_ok = mgr->hot_snap_ok;
		snap_err = mgr->hot_snap_err;
		prepage = mgr->hot_prepage;
		spin_unlock(&sew_lb_lock);
		if (rounds) {
			avg_rl = div_u64(rl_us, rounds);
			avg_sw = div_u64(sw_us, rounds);
			avg_fa = div_u64(fa_us, rounds);
			avg_tot = div_u64(tot_us, rounds);
		}
		seq_printf(m, "min_swapin, time: %llu, app: -\n", sw_us);
		seq_printf(m, "max_swapin, time: %llu, app: -\n", sw_us);
		seq_printf(m,
			   "avg time, rlock: %llu, swapin: %llu, fadvise: %llu, total: %llu, total count: %llu\n",
			   avg_rl, avg_sw, avg_fa, avg_tot, rounds);
		seq_printf(m, "interrupt, by ioctl: %llu, by rlock: %llu, by swapin: %llu\n",
			   i_ioctl, i_rlock, i_swap);
		seq_printf(m, "snapshot: %llu prepage: %llu err: %llu\n",
			   snap_ok, prepage, snap_err);
	}
	return 0;
}

static int sew_lb_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_lb_stats_show, NULL);
}

static const struct proc_ops sew_lb_stats_fops = {
	.proc_open	= sew_lb_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

#define SEW_LB_SHOW_MAX 64
struct sew_lb_show_ent {
	u32 uid;
	char name[64];
	u8 type;
	bool preread;
};

static int sew_lb_collect_list_show(struct seq_file *m, void *v)
{
	struct sew_lb_manager *mgr = READ_ONCE(sew_g_manager);
	struct sew_lb_pkg *pkg;
	struct sew_lb_show_ent *snap;
	int i, n = 0, j;
	unsigned long flags;

	if (!mgr)
		return 0;
	/* seq_printf may sleep: snapshot under the lock, print after
	 * (same discipline as millet show; audit P1). Heap snapshot: the
	 * 64-entry struct would be ~4.6K on the stack, over the frame
	 * limit. */
	snap = kmalloc_array(SEW_LB_SHOW_MAX, sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	spin_lock_irqsave(&sew_lb_lock, flags);
	for (i = 0; i < SEW_LB_HASH_BUCKETS && n < SEW_LB_SHOW_MAX; i++) {
		hlist_for_each_entry(pkg, &mgr->pkg_hash[i], hnode) {
			if (n >= SEW_LB_SHOW_MAX)
				break;
			snap[n].uid = from_kuid_munged(&init_user_ns, pkg->uid);
			strscpy(snap[n].name, pkg->name, sizeof(snap[n].name));
			snap[n].type = pkg->type;
			snap[n].preread = pkg->mode_preread;
			n++;
		}
	}
	spin_unlock_irqrestore(&sew_lb_lock, flags);
	for (j = 0; j < n; j++)
		seq_printf(m, "%u %s type=%u mode=%s\n", snap[j].uid,
			   snap[j].name, snap[j].type,
			   snap[j].preread ? "preread" : "collect");
	kfree(snap);
	return 0;
}

static int sew_lb_collect_list_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_lb_collect_list_show, NULL);
}

/* "<uid> <package>" per line; "clear" wipes */
static const struct proc_ops sew_lb_mode_fops;
static int sew_lb_proc_uid_create(unsigned int uid);
static void sew_lb_proc_uid_ensure(kuid_t uid);

static ssize_t sew_lb_collect_list_write(struct file *file, const char __user *ubuf,
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

	/* NOTE (L1-FINALIZE K10): per-uid removal is inlined in the "off"
	 * branch of sew_lb_mode_write below (it must run under sew_lb_lock);
	 * the former sew_lb_remove_package_info helper was deleted after a
	 * full-tree grep proved zero callers (2026-09-13). "clear" keeps its
	 * inline batch delete here. */
	if (sysfs_streq(buf, "clear")) {
		struct sew_lb_pkg *pkg;
		struct hlist_node *tmp;
		struct sew_lb_manager *m = READ_ONCE(sew_g_manager);
		int i;

		if (!m)
			return count;
		spin_lock(&sew_lb_lock);
		for (i = 0; i < SEW_LB_HASH_BUCKETS; i++) {
			hlist_for_each_entry_safe(pkg, tmp,
						  &m->pkg_hash[i], hnode) {
				hlist_del(&pkg->hnode);
				m->nr_pkgs[pkg->type]--;
				kfree(pkg);
			}
		}
		/* Manual clear of the preread breaker (sticky stop): resets
		 * stop + accumulated time + io-breaker triage so the next
		 * preread starts from a clean slate. */
		m->preread_stop = false;
		m->stop_j = jiffies;
		m->swapin_total_us = 0;
		m->rlock_total_us = 0;
		sew_lb_io.tripped = false;
		sew_lb_io.count = 0;
		sew_lb_io.win_j = jiffies;
		/* Re-arm the collect window so collection resumes at once. */
		m->window_open = true;
		m->window_j = jiffies;
		spin_unlock(&sew_lb_lock);
		return count;
	}

	n = sscanf(buf, "%u %63s", &uid, name);
	if (n != 2)
		return -EINVAL;
	/* sew_lb_add_package_info locks internally (audit P0). */
	if (!sew_lb_add_package_info(name, make_kuid(&init_user_ns, uid),
				 SEW_LB_APP_FILE_SEQUENTIAL))
		count = -ENOMEM;
	else
		sew_lb_proc_uid_ensure(make_kuid(&init_user_ns, uid));
	return count;
}

static const struct proc_ops sew_lb_collect_list_fops = {
	.proc_open	= sew_lb_collect_list_open,
	.proc_read	= seq_read,
	.proc_write	= sew_lb_collect_list_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* D2a hot_collect proc node: read-only per-uid teardown counts.
 * Snapshot under sew_hot_lock + xa_lock (same order as the mmput fast path)
 * into a bounded stack buffer, print after (seq_printf may sleep; same
 * discipline as collect_list). xa_lock pins entries against a racing
 * exit-drain erase while we copy (E1 #8). */
#define SEW_LB_HOT_SHOW_MAX 64
static int sew_lb_hot_show(struct seq_file *m, void *v)
{
	struct {
		u32 uid;
		u64 count;
	} snap[SEW_LB_HOT_SHOW_MAX];
	unsigned long index = 0;
	struct sew_lb_hot_rec *rec;
	unsigned long flags;
	int n = 0, j;

	spin_lock_irqsave(&sew_hot_lock, flags);
	xa_lock(&sew_lb_hot_xa);
	xa_for_each(&sew_lb_hot_xa, index, rec) {
		if (n >= SEW_LB_HOT_SHOW_MAX)
			break;
		snap[n].uid = rec->uid;
		snap[n].count = rec->count;
		n++;
	}
	xa_unlock(&sew_lb_hot_xa);
	spin_unlock_irqrestore(&sew_hot_lock, flags);
	for (j = 0; j < n; j++)
		seq_printf(m, "%u %llu\n", snap[j].uid, snap[j].count);
	seq_printf(m, "hot_total: %lld\n",
		   sew_g_manager ? atomic64_read(&sew_g_manager->hot_total) : 0LL);
	return 0;
}
#undef SEW_LB_HOT_SHOW_MAX

static int sew_lb_hot_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_lb_hot_show, NULL);
}

static const struct proc_ops sew_lb_hot_fops = {
	.proc_open	= sew_lb_hot_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* D2a dead-code fix: sew_lb_proc_uid_create was never called. Wire it into
 * the package-add path: sew_lb_add_package_info returns the pkg (existing
 * or new); create the per-uid mode node for both cases so userspace
 * always finds /proc/lb/<uid>. Duplicate creates are harmless
 * (proc_create_data on an existing name just fails). */
static int sew_lb_proc_uid_create(unsigned int uid)
{
	struct proc_dir_entry *pde;
	char name[16];

	if (!sew_lb_proc_dir)
		return -ENOENT;
	snprintf(name, sizeof(name), "%u", uid);
	pde = proc_create_data(name, 0644, sew_lb_proc_dir, &sew_lb_mode_fops,
			       (void *)(uintptr_t)uid);
	return pde ? 0 : -ENOMEM;
}

static void sew_lb_proc_uid_ensure(kuid_t uid)
{
	unsigned int uid32 = from_kuid_munged(&init_user_ns, uid);

	/* proc_create may sleep: never call under sew_lb_lock. All callers
	 * of this helper run in sleepable context (proc write / init). */
	sew_lb_proc_uid_create(uid32);
}

/* per-uid mode node: /proc/lb/<uid>/mode ("collect"|"preread"|"off") */
static ssize_t sew_lb_mode_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct sew_lb_pkg *pkg;
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
	spin_lock(&sew_lb_lock);
	pkg = sew_lb_find_pkg_locked(uid);
	if (!pkg) {
		spin_unlock(&sew_lb_lock);
		return -ENOENT;
	}
	if (sysfs_streq(buf, "pte")) {
		u32 uid32 = from_kuid_munged(&init_user_ns, uid);

		spin_unlock(&sew_lb_lock);
		/* Tier-2 on-demand snapshot for this uid */
		sew_lb_snapshot_uid(uid32);
		return count;
	}
	if (sysfs_streq(buf, "preread")) {
		pkg->mode_preread = true;
		spin_unlock(&sew_lb_lock);
		/*
		 * Replay outside the lock: vfs_fadvise may sleep (proc
		 * write context is fine for that), and sew_lb_drop_ranges
		 * frees file references which must also run unlocked
		 * relative to the registry lookup above.
		 */
		if (sew_g_manager) {
			sew_lb_preread_ranges(sew_g_manager);
			spin_lock(&sew_lb_lock);
			sew_lb_drop_ranges(sew_g_manager);
			spin_unlock(&sew_lb_lock);
		}
		return count;
	} else if (sysfs_streq(buf, "collect")) {
		pkg->mode_preread = false;
	} else if (sysfs_streq(buf, "off")) {
		/* inline the removal: the helper locks itself and must
		 * not be called with sew_lb_lock held (audit P0). */
		hlist_del(&pkg->hnode);
		sew_g_manager->nr_pkgs[pkg->type]--;
		spin_unlock(&sew_lb_lock);
		kfree(pkg);
		return count;
	} else {
		spin_unlock(&sew_lb_lock);
		return -EINVAL;
	}
	spin_unlock(&sew_lb_lock);
	return count;
}

static const struct proc_ops sew_lb_mode_fops = {
	.proc_open	= NULL,
	.proc_write	= sew_lb_mode_write,
	.proc_lseek	= noop_llseek,
};

static void sew_lb_proc_uid_remove(unsigned int uid)
{
	char name[16];

	snprintf(name, sizeof(name), "%u", uid);
	if (sew_lb_proc_dir)
		remove_proc_entry(name, sew_lb_proc_dir);
}


/* ---- init / exit -------------------------------------------------------- */

static int __init sew_lb_init(void)
{
	struct sew_lb_manager *m;
	int i, ret;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	for (i = 0; i < SEW_LB_HASH_BUCKETS; i++) {
		INIT_HLIST_HEAD(&m->pkg_hash[i]);
		INIT_HLIST_HEAD(&m->file_hash[i]);
	}
	m->window_j = jiffies;
	m->window_open = true;
	m->stop_j = jiffies;
	WRITE_ONCE(sew_g_manager, m);

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
	/* D2a hot_collect: per-mm teardown observer (5.15 single-arg
	 * android_vh_mmput; 6.6 was android_vh_mmput_mm). */
	ret = register_trace_android_vh_mmput(sew_lb_hot_on_mmput, NULL);
	if (ret)
		goto err_unfault;

	sew_lb_proc_dir = proc_mkdir("lb", NULL);
	if (!sew_lb_proc_dir) {
		ret = -ENOMEM;
		goto err_unmmput;
	}
	if (!proc_create("stats", 0444, sew_lb_proc_dir, &sew_lb_stats_fops) ||
	    !proc_create("collect_list", 0644, sew_lb_proc_dir,
			 &sew_lb_collect_list_fops) ||
	    !proc_create("hot_collect", 0444, sew_lb_proc_dir, &sew_lb_hot_fops)) {
		ret = -ENOMEM;
		goto err_proc;
	}

	pr_info("lb: iorap version 2.0.0 (Sew 5.15 Tier-1 port)\n");
	return 0;

err_proc:
	remove_proc_entry("hot_collect", sew_lb_proc_dir);
	remove_proc_entry("stats", sew_lb_proc_dir);
	remove_proc_entry("collect_list", sew_lb_proc_dir);
	remove_proc_entry("lb", NULL);
	sew_lb_proc_dir = NULL;
err_unmmput:
	unregister_trace_android_vh_mmput(sew_lb_hot_on_mmput, NULL);
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
	WRITE_ONCE(sew_g_manager, NULL);
	return ret;
}

static void __exit sew_lb_exit(void)
{
	struct sew_lb_pkg *pkg;
	struct hlist_node *tmp;
	struct sew_lb_manager *m = sew_g_manager;
	struct sew_lb_hot_rec *rec;
	unsigned long index = 0;
	void *entry;
	int i;

	if (!m)
		return;
	unregister_trace_android_vh_mmput(sew_lb_hot_on_mmput, NULL);
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

	remove_proc_entry("hot_collect", sew_lb_proc_dir);
	remove_proc_entry("stats", sew_lb_proc_dir);
	remove_proc_entry("collect_list", sew_lb_proc_dir);
	for (i = 0; i < SEW_LB_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(pkg, tmp, &m->pkg_hash[i], hnode) {
			unsigned int uid = from_kuid_munged(&init_user_ns,
							    pkg->uid);
			sew_lb_proc_uid_remove(uid);
			hlist_del(&pkg->hnode);
			kfree(pkg);
		}
	}
	remove_proc_entry("lb", NULL);
	sew_lb_proc_dir = NULL;

	/* D2a: drain the hot xarray. Unregister + tracepoint sync above
	 * guarantee no NEW mmput writers; hold xa_lock across each
	 * find+erase pair so a racing fast-path RMW (which bumps only
	 * under xa_lock, E1 #8) cannot be freed mid-count. sew_hot_lock is
	 * NOT held here (writers take sew_hot_lock outer + xa_lock inner;
	 * taking the reverse order would ABBA). */
	xa_lock(&sew_lb_hot_xa);
	xa_for_each(&sew_lb_hot_xa, index, entry) {
		rec = entry;
		__xa_erase(&sew_lb_hot_xa, index);
		kfree(rec);
	}
	xa_unlock(&sew_lb_hot_xa);
	xa_destroy(&sew_lb_hot_xa);

	spin_lock(&sew_lb_lock);
	sew_lb_drop_ranges(m);
	spin_unlock(&sew_lb_lock);
	kfree(m);
	WRITE_ONCE(sew_g_manager, NULL);
}

#ifndef MODULE
/* Built-in: no exit registration; keep sew_lb_exit for code clarity but
 * never register it (matches the "builtin need not register exit"
 * rule while retaining the teardown path for readability). */
subsys_initcall(sew_lb_init);
#else
module_init(sew_lb_init);
module_exit(sew_lb_exit);
#endif
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Sew Tier-1 port of the Xiaomi OS4 lb (iorap launch-boost prefetch)");
