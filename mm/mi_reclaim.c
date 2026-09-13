// SPDX-License-Identifier: GPL-2.0-only
/*
 * mi_reclaim: reclaim-path observability + bounded tuning, port of the
 * Xiaomi OS4 mi_reclaim module ("Memory reclaim optimization module",
 * cang from MI Performance Team).
 *
 * RE evidence: /root/work/os4_dada/ko/mi_reclaim.ko
 *   (modinfo: depends=xr_qi, parm refill_cpus; nm -u: 9 hook tracepoints,
 *   try_to_free_mem_cgroup_pages, is_qos_task/kern_qi_set_qos from xr_qi;
 *   strings: the sysfs command set reproduced below).  Raw dump:
 *   .omz/research/.../raw/ (this session, mi_reclaim recon).
 *
 * What the OS4 module does
 * ------------------------
 * A proactive-reclaim executor driven by userspace: an "important pid"
 * list and an on-demand "event" trigger reclaim against the listed
 * processes' memcgs ("echo <reclaim_mb> > event"), a page pool with a
 * CPU-pinned refill worker (refill_cpus) served through
 * android_vh_alloc_pages_reclaim_bypass, a watermark boost (raise the
 * fast-path mark so reclaim engages earlier under stress),
 * direct-reclaim throttle/shrink-slab bypasses and a scan-type steer
 * (0x1=RECLAIM_FILE, 0x2=RECLAIM_ANON), all QOS-gated through xr_qi's
 * is_qos_task()/kern_qi_set_qos().
 *
 * Sew 5.15 scope of this port ([PORT-DELTA] items marked)
 * -------------------------------------------------------
 * Ported (all tuning channels default OFF; the observe counters of the
 * previous first cut are kept verbatim, /proc/mi_reclaim unchanged so
 * existing addon readers are not broken):
 *   1. important pid list + event node: reclaim from the listed pids'
 *      memcgs via try_to_free_mem_cgroup_pages() (EXPORT_SYMBOL_GPL in
 *      this tree).  may_swap=false implements the dada "FILE flag"
 *      (no anon scan => file-only reclaim).
 *   2. [REMOVED] wmark boost: the original plan raised the per-
 *      allocation MIN-watermark check via android_vh_get_page_wmark
 *      after reclaim stress.  Real-device testing (fuxi freeze: "boots,
 *      UI stalls, watchdog reboots, stable after 3 reboots") killed it:
 *      direct reclaim allocates with ALLOC_WMARK_MIN, so +4096 pages on
 *      the fast-path check stalls every allocation once free sits above
 *      min by < 16MB, and the stress trigger re-arms forever -> reclaim
 *      livelock.  Same direction lesson unfairmem already documents;
 *      the dada module likely targeted a different watermark.
 *   3. throttle bypass (android_vh_throttle_direct_reclaim_bypass):
 *      skip direct-reclaim throttling only while node file pages are
 *      above throttle_file_threshold (plenty of cheap file pages).
 *   4. scan steer (android_vh_tune_scan_type): write the scan_balance
 *      enum (SCAN_FILE=3 / SCAN_ANON=2, mm/vmscan.c) for global
 *      (non-kswapd) reclaim only, FILE steer additionally guarded by
 *      the file-pages threshold.
 *   5. reclaim efficiency stats: slowpath -> direct_reclaim_end wall
 *      time and per-event reclaimed/duration ("real reclaimed %lu time
 *      %lld ms").
 *
 * Not ported (no evidence / too thin RE to reach the confidence bar):
 *   - page pool + refill worker + prefill + android_vh_alloc_pages_
 *     reclaim_bypass (the pool semantics are not recoverable from the
 *     binary strings with confidence; a wrong bypass hands out foreign
 *     pages).  [PORT-DELTA]
 *     Re-audit 2026-09-06 (mi_reclaim.ko 6.6.57, dis in
 *     outputs/subsys-fix): bypass/refill/pool_add/pool_remove/cleanup
 *     control flow decodes, but five items block a 98%-confidence port:
 *     1. mi_pool bss layout has no named symbols (offsets only), so the
 *     low/high/critical-mark and count field mapping is inferred, not
 *     proven; 2. bypass gfp->migratetype decode (ubfiz/lsr/csel on
 *     constant 0x252115) has no source counterpart, match rule not provable;
 *     3. is_important_process keys off 6.6 task_struct vendor-private
 *     offsets task+1568/1624 (5.15 sched.h has no equivalent field) and
 *     the qi vendor pad (task+0x12c0/q+0x38), so the pool membership
 *     test cannot be mapped; 4. low_mark trigger chain mixes refill
 *     interval/urgent-wakeup/qos gates whose sysfs value semantics are
 *     not recoverable; 5. refill/prefill allocate order-0 via
 *     __alloc_pages(GFP 0x112DC2) and return via __free_pages, but the
 *     order/migratetype/zone contract the bypass promises is unknown.
 *     Verdict: keep unported; evidence above replaces guessing.
 *     C4-MIR12 re-confirms (6.12 popsicle, 14 vh hooks): refill/pool are
 *     NOT ELF FUNC symbols (only info command keys + refill_worker_fn
 *     LOCAL FUNC), and scheme A (auto_reclaim_*) below already covers the
 *     "keep free pages high" benefit -> refill/pool stay OUT this round.
 *   - shrink_slab_bypass: the binary only shows the stat name
 *     "kswapd_shrink_slab"; no recoverable bypass condition.  The hook
 *     exists in-tree but stays unregistered here (single-consumer
 *     discipline with mm/slabd.c which already consumes it). [PORT-DELTA]
 *   - free_task purge: replaced by a struct pid* reference model - the
 *     list holds pid references, so pids cannot recycle under us and
 *     dead tasks resolve to NULL in get_pid_task().  [PORT-DELTA]
 *   - is_qos_task/kern_qi_set_qos gating (xr_qi exports): replaced by
 *     explicit sysfs switches; when xr_qi grows the export face the
 *     gate can be wired in.  [PORT-DELTA]
 *   - sysfs command surface is the dada subset {pid,event,info,usage,
 *     reset_stats}; the "pool" node and the info-write keys of skipped
 *     subsystems (refill_max_runtime, wmark_boost_*, boost_background,
 *     prefill) are absent.  dada's exact event encoding is not visible
 *     in the binary ("echo 257 > event  # 100MB + FILE flag" does not
 *     decode unambiguously), so this port defines: "echo <mb> > event"
 *     reclaims <mb> MB with swap allowed, "echo <mb> file > event"
 *     reclaims file-only.  [PORT-DELTA]
 *
 * C4-MIR12 (6.12 popsicle -> 5.15) newly ported, all default OFF:
 *   6. P0 drain_all_pages bypass + unreserve_highatomic bypass
 *      (android_vh_drain_all_pages_bypass / unreserve_highatomic_bypass):
 *      skip PCP drain / highatomic unreserve for marked tasks so the
 *      mireclaimd worker's own allocations do not churn PCP lists and
 *      marked allocations keep the high-atomic reserve intact.
 *   7. P1 gfp customize (android_vh_alloc_pages_entry): for marked tasks,
 *      clear __GFP_KSWAPD_RECLAIM so their allocations do not wake kswapd
 *      (direct reclaim only), suppressing kswapd storms.  The mark is set
 *      in sew_mir_slowpath (start of slowpath storm) and cleared in
 *      sew_mir_reclaim_end (also the slowpath_end equivalent: 5.15 has no
 *      android_vh_alloc_pages_slowpath_end, so direct_reclaim_end doubles
 *      as the lifecycle end).
 *   8. P2 proc exit nice normalize (android_vh_mmput): .android.camera
 *      owner gets nice -20, other exiting tasks with nice>0归0.
 *   9. P3 tune swappiness follower (android_vh_tune_swappiness): must run
 *      AFTER scene_swappiness (mm/Makefile links scene_swappiness.o
 *      before mi_reclaim.o; same device_initcall level, so link order
 *      decides registration order: scene's callback first, ours
 *      second).  Writes only when its own gate is armed and its
 *      file-pressure condition holds, otherwise passes through so the
 *      scene value (or upstream value) survives untouched.  K7-FIX-K3
 *      P1-2: this order is LOAD-BEARING, do not reorder the Makefile.
 *  10. wmark_boost stays DELETED in mi_reclaim (fuxi reclaim-livelock
 *      evidence, see item 2 above).  Static watermarks are mi_wmark's job
 *      (mm/mi_wmark.c, /sys/kernel/mi_wmark).  Do NOT resurrect.
 *
 * G6收尾 (official 4 refill info keys -> read-only compat, 2026-09-11):
 *  verdict per key (evidence: popsicle mi_reclaim.ko strings; the usage
 *  "echo ..." list documents every write key, and NEITHER bare "refill"
 *  NOR "refill_pool" has an echo line, so both are display-only
 *  officially too):
 *   - refill_pool: DONE (read-only). No pool carrier here, so the value
 *     is the scheme-A armed state (auto_reclaim_threshold != 0 AND pid
 *     list non-empty): the pool's job ("keep free pages high") is exactly
 *     what scheme A does, and "armed" is its on/off front. See info_show.
 *   - refill_low_file_threshold_mb: DONE (read-only). Official is
 *     display-only MB ("| refill_low_file_threshold_mb: %lu"); ours is
 *     sew_mir_throttle_file_threshold converted pages->MB (>>8). Caveat in
 *     code: same file-floor family, different gated object (theirs skips
 *     pool-refill, ours gates throttle-bypass). No new knob created.
 *   - refill (bare): DONE (read-only). Official heads the refill-activity
 *     block (total_count/time); ours reports scheme-A auto-event count
 *     (sew_mir_auto_reclaim_count). Manual events stay in reclaim_times.
 *   - refill_prio_boost: DONE by H2 (2026-09-12) as a 0|1 switch +
 *     refill_prio_duration ms value on the scheme-A event worker
 *     (mireclaimd), mirroring the official two-key face. Official
 *     semantics (popsicle strings): writable "echo <0|1>" switch +
 *     "refill_prio_duration <ms>" + boost/set-once/skip-once
 *     counters, "priority boost for refill worker (default 1)",
 *     "priority duration (default 100ms)".
 *     No sched_setscheduler/SCHED_FIFO import exists in the official
 *     ko; its only prio primitive is set_user_nice
 *     (mi_proc_exit_handler), so the lift is a nice step, not RT.
 *     Port mapping: "refill_prio_boost <0|1>" (0 = off = this port's
 *     default, unlike official default 1; 1 = on, window =
 *     refill_prio_duration) + "refill_prio_duration <ms>" (default
 *     100, range 1..60000, takes effect while boost=1). Writing 1
 *     arms a duration-ms window from now; each auto-reclaim trigger
 *     re-arms it the same way. Events starting inside it run
 *     mireclaimd at nice -10 via set_user_nice on ITSELF
 *     (current-only, same rule as sew_mir_proc_exit E1 #6), restored at
 *     event end. Stats: boost_count / boost_time_ms in info_show.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/vmstat.h>
#include <linux/swap.h>
#include <linux/memcontrol.h>
#include <linux/sched/clock.h>
#include <linux/preempt.h>
#include <trace/hooks/vmscan.h>
#include <trace/hooks/mm.h>
#include <trace/hooks/sched.h>

/* ---- observe counters (first cut, kept verbatim) ---------------------- */
static atomic64_t sew_slowpath_total;
static atomic64_t sew_slowpath_highorder;
static atomic64_t sew_reclaim_end_calls;
static atomic64_t sew_reclaim_reclaimed_pages;
static atomic64_t sew_reclaim_zero_progress;

/* ---- tuning state (all default OFF) ----------------------------------- */
/* scan steer: 0x1=RECLAIM_FILE (SCAN_FILE), 0x2=RECLAIM_ANON (SCAN_ANON) */
#define SEW_MIR_FLAG_RECLAIM_FILE	0x1
#define SEW_MIR_FLAG_RECLAIM_ANON	0x2
static unsigned int sew_mir_enable_flags;

/* throttle bypass */
static unsigned int sew_mir_skip_throttle_enabled;
static unsigned int sew_mir_throttle_file_threshold; /* node file pages */

/* auto reclaim on low free (pool-substitute scheme A):
 * when a slowpath allocation observes free pages below
 * sew_mir_auto_reclaim_threshold (pages, 0 = disabled), queue an automatic
 * file-only reclaim of sew_mir_auto_reclaim_mb over the important pid list.
 * Throttled to at most one auto event per sew_mir_auto_reclaim_interval_ms.
 * This recovers the "keep free high so important allocations stay on the
 * fast path" benefit of the unported page pool without guessing any
 * binary layout: it reuses the verified event worker + pid list. */
static unsigned int sew_mir_auto_reclaim_threshold;	/* free pages, 0 = off */
static unsigned int sew_mir_auto_reclaim_mb = 256;
static unsigned int sew_mir_auto_reclaim_interval_ms = 60000;
static unsigned long sew_mir_auto_reclaim_last_j;
static atomic64_t sew_mir_auto_reclaim_count;

/* scan steer guard */
static unsigned int sew_mir_file_scan_enabled;
static unsigned int sew_mir_fg_file_scan_threshold;	/* node file pages */

/* P0 bypass gates (default OFF; C4-MIR12 direct port of
 * mi_drain_all_pages_bypass + mi_unreserve_highatomic_bypass) */
static unsigned int sew_mir_bypass_pcp_enabled;
static unsigned int sew_mir_bypass_highatomic_enabled;
static atomic64_t sew_mir_bypass_pcp_count;
static atomic64_t sew_mir_bypass_highatomic_count;

/* P1 gfp customize gate (default OFF; C4-MIR12 equivalent design of
 * mi_customize_alloc_gfp).  For marked tasks, allocations clear
 * __GFP_KSWAPD_RECLAIM (0x800, gfp bit11) so they only direct-reclaim
 * and never wake kswapd.  The mark lifecycle: set in sew_mir_slowpath
 * (slowpath storm entry), consumed by sew_mir_customize_gfp /
 * sew_mir_drain_bypass / sew_mir_unreserve_bypass, cleared in sew_mir_reclaim_end
 * (direct_reclaim_end doubles as the slowpath_end equivalent because
 * 5.15 has no android_vh_alloc_pages_slowpath_end).  Storage is a
 * per-CPU pid snapshot: no task_struct private offsets (6.12's
 * task+3392 layout does not exist on 5.15) and no extra locking on
 * the allocation fast path.
 */
static unsigned int sew_mir_gfp_customize_enabled;
static atomic64_t sew_mir_gfp_cleared_count;
static DEFINE_PER_CPU(pid_t, sew_mir_slowpath_mark);

/* P2 proc exit nice (default OFF; C4-MIR12 direct port of
 * mi_proc_exit_handler on android_vh_mmput) */
static unsigned int sew_mir_proc_exit_enabled;
static int sew_mir_proc_exit_nice;			/* default 0, non-camera归0 */
static atomic64_t sew_mir_proc_exit_count;
static atomic64_t sew_mir_proc_exit_camera_count;
#define SEW_MIR_CAMERA_COMM	".android.camera"

/* P3 swappiness follower (default OFF; C4-MIR12 equivalent design of
 * mi_tune_swappiness with scene_swappiness arbitration).  ORDER (K7-FIX-K3
 * P1-2, load-bearing): mm/Makefile links scene_swappiness.o BEFORE
 * mi_reclaim.o, same device_initcall level, so scene's callback registers
 * first and ours second; this comment states the REQUIREMENT, and the
 * Makefile enforces it.  RULE: never write *swappiness unless (a) our
 * gate is armed AND (b) the observed file pressure satisfies the
 * threshold.  Otherwise pass through so the value left by
 * scene_swappiness (registered before us) or upstream survives untouched.
 * Writing 180 steers toward file reclaim when file pages are abundant;
 * writing sew_mir_balance_swappiness keeps anon pressure bounded when
 * files are thin.
 */
static unsigned int sew_mir_swappiness_enabled;
static unsigned int sew_mir_balance_file_threshold;	/* node file pages */
static int sew_mir_balance_swappiness = 60;
static atomic64_t sew_mir_swappiness_write_count;
static atomic64_t sew_mir_swappiness_passthru_count;

/* H2 refill_prio_boost window (see header verdict). Switch +
 * duration config + arm timestamp; stats count boosted events and
 * their wall time. Zero behavior when off: no set_user_nice ever
 * runs and neither counter moves. */
#define SEW_MIR_BOOST_NICE		(-10)
#define SEW_MIR_BOOST_MAX_MS	60000
static unsigned int sew_mir_boost_enabled;	/* 0 = off (default) */
static unsigned int sew_mir_boost_duration_ms = 100;	/* official default */
static unsigned long sew_mir_boost_until;	/* jiffies: window end */
static atomic64_t sew_mir_boost_count;
static atomic64_t sew_mir_boost_time_ms;

/* important pid list */
#define SEW_MIR_MAX_PIDS	32
static struct pid *sew_mir_pids[SEW_MIR_MAX_PIDS];
static int sew_mir_pid_count;
static DEFINE_MUTEX(sew_mir_pid_lock);

/* event worker */
static struct task_struct *sew_mir_worker;
static DECLARE_WAIT_QUEUE_HEAD(sew_mir_waitq);
static atomic_t sew_mir_event_mb = ATOMIC_INIT(0);
static atomic_t sew_mir_event_flags = ATOMIC_INIT(0);

/* tuning stats */
static atomic64_t sew_mir_total_reclaim_pages;
static atomic64_t sew_mir_total_reclaim_ms;
static atomic64_t sew_mir_reclaim_times;
static atomic64_t sew_mir_refill_fail_count;	/* pid with no task/memcg */
static atomic64_t sew_mir_skip_throttle_count;
static DEFINE_PER_CPU(u64, sew_mir_slowpath_t0);

/* scan_balance values: enum scan_balance { SCAN_EQUAL, SCAN_FRACT,
 * SCAN_ANON, SCAN_FILE }; (mm/vmscan.c).  The hook hands us a char*
 * aliasing that enum. */
#define SEW_MIR_SCAN_ANON	2
#define SEW_MIR_SCAN_FILE	3

/* ---- hooks ------------------------------------------------------------ */

/* Marked-task test shared by P0/P1.  A task is "marked" when it is the
 * mireclaimd worker itself (whose own allocations must not churn PCP /
 * highatomic reserves) or when its pid equals the slowpath mark left by
 * sew_mir_slowpath on this CPU (allocation storm in progress).  Lock-free and
 * RCU-free: the per-CPU pid is only a hint, a stale match merely skips one
 * drain/unreserve or clears one kswapd bit, never a correctness issue. */
static bool sew_mir_task_is_marked(void)
{
	if (sew_mir_worker && current == sew_mir_worker)
		return true;
	/* a nonzero slowpath mark means sew_mir_slowpath ran on this CPU and
	 * sew_mir_reclaim_end has not cleared it yet.  Preemption is disabled
	 * across the read so the current task cannot migrate between the
	 * per-CPU deref and the pid compare (same-CPU, E1 #13). */
	preempt_disable();
	if (*this_cpu_ptr(&sew_mir_slowpath_mark) == task_pid_nr(current) &&
	    task_pid_nr(current) != 0) {
		preempt_enable();
		return true;
	}
	preempt_enable();
	return false;
}

static void sew_mir_slowpath(void *data, gfp_t gfp_mask, unsigned int order)
{
	atomic64_inc(&sew_slowpath_total);
	if (order > PAGE_ALLOC_COSTLY_ORDER)
		atomic64_inc(&sew_slowpath_highorder);
	/* Per-CPU mark+t0 are a same-CPU pair with sew_mir_task_is_marked /
	 * sew_mir_reclaim_end: hold preemption so writer and reader observe
	 * one CPU (E1 #13). */
	preempt_disable();
	*this_cpu_ptr(&sew_mir_slowpath_t0) = local_clock();
	/* P1 mark lifecycle (start): remember the storm task per CPU.
	 * No alloc_flags test needed: the hook only fires inside
	 * __alloc_pages_slowpath, so arrival here IS the storm signal. */
	*this_cpu_ptr(&sew_mir_slowpath_mark) = task_pid_nr(current);
	preempt_enable();

	/* pool-substitute auto trigger: cheap stat read on the already-slow
	 * path; the worker does the real work asynchronously. */
	if (sew_mir_auto_reclaim_threshold && sew_mir_pid_count &&
	    global_zone_page_state(NR_FREE_PAGES) < sew_mir_auto_reclaim_threshold &&
	    time_after(jiffies, sew_mir_auto_reclaim_last_j +
		       msecs_to_jiffies(sew_mir_auto_reclaim_interval_ms))) {
		sew_mir_auto_reclaim_last_j = jiffies;
		/* H2: every auto trigger (re)arms the boost window so the
		 * event it queues - and any event starting within N ms -
		 * runs boosted. */
		if (READ_ONCE(sew_mir_boost_enabled))
			WRITE_ONCE(sew_mir_boost_until, jiffies +
				   msecs_to_jiffies(READ_ONCE(sew_mir_boost_duration_ms)));
		/* worker consumes both atomics with xchg: only arm a new
		 * event when the previous one was consumed, otherwise a
		 * manual trigger's flags/mb would be overwritten (audit P1). */
		if (!atomic_read(&sew_mir_event_mb)) {
			atomic_set(&sew_mir_event_flags, SEW_MIR_FLAG_RECLAIM_FILE);
			atomic_set(&sew_mir_event_mb, (int)sew_mir_auto_reclaim_mb);
			atomic64_inc(&sew_mir_auto_reclaim_count);
			wake_up(&sew_mir_waitq);
		}
	}
}

static void sew_mir_reclaim_end(void *data, unsigned long nr_reclaimed)
{
	u64 t0;

	/* Same-CPU write-then-clear of the per-CPU pair (E1 #13). */
	preempt_disable();
	t0 = *this_cpu_ptr(&sew_mir_slowpath_t0);

	atomic64_inc(&sew_reclaim_end_calls);
	atomic64_add(nr_reclaimed, &sew_reclaim_reclaimed_pages);
	if (!nr_reclaimed)
		atomic64_inc(&sew_reclaim_zero_progress);
	if (t0)
		atomic64_add(div_u64(local_clock() - t0, 1000000),
			     &sew_mir_total_reclaim_ms);
	/* P1 mark lifecycle (end): direct_reclaim_end is the closest 5.15
	 * equivalent of the missing alloc_pages_slowpath_end.  Clearing here
	 * (rather than in a new failure hook) keeps mark lifetime bounded to
	 * one reclaim round; a stale mark only ever skips a drain or clears
	 * a kswapd bit, never corrupts.  t0 is cleared too so the next storm
	 * starts with a clean wall-clock base. */
	*this_cpu_ptr(&sew_mir_slowpath_t0) = 0;
	*this_cpu_ptr(&sew_mir_slowpath_mark) = 0;
	preempt_enable();
}

/* LAYER NOTE (L1-FINALIZE K11-K3): this hook shares
 * android_vh_throttle_direct_reclaim_bypass with sew_mmap_bypass
 * (mm/sew_mmap_bypass.c, enabled=1, interactive-cpuset scoped). Both only
 * ever write true (monotonic OR, chain-safe, no clobber). Policy layering:
 * sew_mmap_bypass is the baseline (interactive tasks always skip the
 * throttle); this gate additionally covers NON-interactive tasks when file
 * pages are plentiful. So on an interactive task the "thin files keep the
 * throttle" intent below is superseded by the baseline -- by design, not a
 * defect. 服务移植优化目标: 定向回收 throttle 门 (scheme-A 调参面). */
static void sew_mir_throttle_bypass(void *data, bool *bypass)
{
	unsigned long file_pages;

	if (!bypass || !sew_mir_skip_throttle_enabled)
		return;

	file_pages = node_page_state(numa_node_id(), NR_FILE_PAGES);
	/* Direction: bypass throttling (skip the wait) only when file pages
	 * are ABOVE threshold, i.e. cheap file reclaim is plentiful; thin
	 * file state keeps the throttle so anon pressure is not ignored. */
	if (sew_mir_throttle_file_threshold &&
	    file_pages > sew_mir_throttle_file_threshold) {
		*bypass = true;
		atomic64_inc(&sew_mir_skip_throttle_count);
	}
}

static void sew_mir_tune_scan_type(void *data, char *scan_type)
{
	unsigned long file_pages;

	if (!scan_type || !sew_mir_enable_flags || current_is_kswapd())
		return;

	if ((sew_mir_enable_flags & SEW_MIR_FLAG_RECLAIM_FILE) &&
	    sew_mir_file_scan_enabled) {
		file_pages = node_page_state(numa_node_id(), NR_FILE_PAGES);
		if (sew_mir_fg_file_scan_threshold &&
		    file_pages > sew_mir_fg_file_scan_threshold) {
			WRITE_ONCE(*(int *)scan_type, SEW_MIR_SCAN_FILE);
			return;
		}
	}
	if (sew_mir_enable_flags & SEW_MIR_FLAG_RECLAIM_ANON)
		WRITE_ONCE(*(int *)scan_type, SEW_MIR_SCAN_ANON);
}

/* P0: drain_all_pages bypass (mi_drain_all_pages_bypass direct port).
 * mm.h:81, call site page_alloc.c:4995 (after unreserve_highatomic, before
 * drain_all_pages, inside the !page && !drained branch).  Marked tasks skip
 * the PCP drain: the mireclaimd worker's own allocations must not disturb
 * PCP lists, and storm tasks keep their pages on-CPU instead of draining.
 * Gate default OFF; never writes bypass unless the gate is armed. */
static void sew_mir_drain_bypass(void *data, gfp_t gfp_mask, unsigned int order,
			     unsigned long alloc_flags, int migratetype,
			     unsigned long did_some_progress, bool *bypass)
{
	if (!bypass || !sew_mir_bypass_pcp_enabled)
		return;
	if (sew_mir_task_is_marked()) {
		*bypass = true;
		atomic64_inc(&sew_mir_bypass_pcp_count);
	}
}

/* P0: unreserve_highatomic bypass (mi_unreserve_highatomic_bypass direct
 * port).  mm.h:117, call site page_alloc.c:3020 (per-zone loop inside
 * unreserve_highatomic_pageblock, "if (skip) continue").  Same marked-task
 * rule: keep the high-atomic reserve intact for the worker / storm tasks. */
static void sew_mir_unreserve_bypass(void *data, bool force, struct zone *zone,
				 bool *skip_unreserve_highatomic)
{
	if (!skip_unreserve_highatomic || !sew_mir_bypass_highatomic_enabled)
		return;
	if (sew_mir_task_is_marked()) {
		*skip_unreserve_highatomic = true;
		atomic64_inc(&sew_mir_bypass_highatomic_count);
	}
}

/* P1: gfp customize (mi_customize_alloc_gfp equivalent design).
 * mm.h:315 android_vh_alloc_pages_entry, call site __alloc_pages entry
 * (page_alloc.c:5796, before the sanity checks), gfp is a writable
 * pointer: the only hook on 5.15 that can rewrite gfp at alloc entry.
 * 6.12 semantics: enable-gated, gfp has bit11 (__GFP_KSWAPD_RECLAIM,
 * 0x800) set, task is marked -> clear bit11 so the allocation never
 * wakes kswapd (direct reclaim only).  SIDE-EFFECT note: clearing the bit
 * only suppresses the kswapd wakeup for THIS allocation; if direct reclaim
 * then frees enough pages, later allocations proceed on the fast path
 * unchanged.  High-order / atomic callers that need kswapd still get it
 * whenever the gate is off or the task is unmarked (default state). */
static void sew_mir_customize_gfp(void *data, gfp_t *gfp, unsigned int order,
			      int preferred_nid, nodemask_t *nodemask)
{
	gfp_t g;

	if (!gfp || !sew_mir_gfp_customize_enabled)
		return;
	g = READ_ONCE(*gfp);
	if (!(g & __GFP_KSWAPD_RECLAIM))
		return;
	if (!sew_mir_task_is_marked())
		return;
	WRITE_ONCE(*gfp, g & ~__GFP_KSWAPD_RECLAIM);
	atomic64_inc(&sew_mir_gfp_cleared_count);
}

/* P2: proc exit nice normalize (mi_proc_exit_handler direct port).
 * sched.h:439 android_vh_mmput, call site kernel/fork.c:1207 inside mmput()
 * on the atomic_dec_and_test true-release branch: the mm is going away,
 * so mm->owner is the exiting owner (or NULL for kernel threads / already
 * reaped owners).  rcu_dereference is required: owner is __rcu and may be
 * swapped by mm_update_owner during exec/exit races.  Camera processes
 * (comm ".android.camera") get nice -20 (boost for quick restart), every
 * other exiting task with nice > 0归0 so inherited low priority does not
 * leak into reparented children or the OOM score baseline.
 * E1 #6: set_user_nice takes the target rq lock + dequeue/enqueue, so it
 * is only ever called here when owner == current.  Touching a *different*
 * exiting task's scheduling state from inside mmput() is a lock-order and
 * latency hazard (the peer is concurrently walking its own exit path);
 * when owner != current we skip without touching it.  (Option (a): option (b),
 * an async mireclaimd worker via find_get_task_by_vpid, would add a worker
 * wakeup + pid lookup to every process exit for bookkeeping that only
 * matters when the exiting task itself is reaped - the smaller,
 * synchronous current-only write preserves the original intent.)
 * E1 #12: comm/nice are sampled INSIDE the RCU critical section:
 * get_task_struct() pins the struct but not comm (concurrent exec can
 * rewrite it), so the copy must happen before rcu_read_unlock(). */
static void sew_mir_proc_exit(void *data, struct mm_struct *mm)
{
	struct task_struct *owner;
	char comm[TASK_COMM_LEN];
	int nice;

	if (!mm || !sew_mir_proc_exit_enabled)
		return;
	rcu_read_lock();
	owner = rcu_dereference(mm->owner);
	if (!owner || (owner->flags & PF_KTHREAD)) {
		rcu_read_unlock();
		return;
	}
	/* E1 #12: copy comm + nice while still under RCU. */
	__get_task_comm(comm, TASK_COMM_LEN, owner);
	nice = task_nice(owner);
	/* E1 #6: never set_user_nice() on a task other than current. */
	if (owner != current) {
		rcu_read_unlock();
		return;
	}
	get_task_struct(owner);
	rcu_read_unlock();

	if (!strncmp(comm, SEW_MIR_CAMERA_COMM, sizeof(SEW_MIR_CAMERA_COMM) - 1)) {
		set_user_nice(owner, -20);
		atomic64_inc(&sew_mir_proc_exit_camera_count);
	} else if (nice > sew_mir_proc_exit_nice) {
		set_user_nice(owner, sew_mir_proc_exit_nice);
		atomic64_inc(&sew_mir_proc_exit_count);
	}
	put_task_struct(owner);
}

/* P3: swappiness follower with scene arbitration (mi_tune_swappiness
 * equivalent design).  vmscan.h:57, call sites vmscan.c:2786
 * (get_scan_count) and vmscan.c:3047 (get_swappiness).  ORDER (K7-FIX-K3
 * P1-2, load-bearing): mm/Makefile links scene_swappiness.o BEFORE
 * mi_reclaim.o; same device_initcall level, so link order decides
 * registration order: scene's callback first, OURS second.  Tracepoint
 * callbacks run in registration order, so OUR write would clobber
 * scene's: RULE is pass through untouched unless our gate is armed AND
 * our file-pressure condition holds.  When files are abundant (>
 * threshold) write 180 to steer toward file reclaim (the 0xb4 branch in
 * the 6.12 disasm); when files are thin write sew_mir_balance_swappiness
 * (default 60) so anon pressure stays bounded.  Otherwise do nothing:
 * the scene value (or the upstream mem_cgroup_swappiness value when
 * scene is default/passthrough) survives. */
static void sew_mir_tune_swappiness(void *data, int *swappiness)
{
	unsigned long file_pages;

	if (!swappiness)
		return;
	if (!sew_mir_swappiness_enabled || !sew_mir_balance_file_threshold) {
		atomic64_inc(&sew_mir_swappiness_passthru_count);
		return;
	}
	file_pages = node_page_state(numa_node_id(), NR_FILE_PAGES);
	if (file_pages > sew_mir_balance_file_threshold) {
		WRITE_ONCE(*swappiness, 180);
		atomic64_inc(&sew_mir_swappiness_write_count);
	} else {
		WRITE_ONCE(*swappiness, sew_mir_balance_swappiness);
		atomic64_inc(&sew_mir_swappiness_write_count);
	}
}

/* H2: boost enter/exit for the event worker (mireclaimd ITSELF).
 * Worker process context only (may sleep: set_user_nice takes rq
 * locks) - never call from hook/atomic context. No timer/hrtimer: the
 * window is a jiffies compare at event start, so there is no timer
 * lifetime to manage; a store racing an event start only shifts that
 * one event's decision. rmmod safety: kthread_stop waits for the
 * in-flight event, so exit (restore) always runs before the thread
 * returns. Cross-context scalars use READ/WRITE_ONCE; stats are
 * atomic64. */
static int sew_mir_boost_enter(bool *boosted)
{
	int prev = 0;

	*boosted = false;
	if (!READ_ONCE(sew_mir_boost_enabled))
		return 0;
	if (!time_before(jiffies, READ_ONCE(sew_mir_boost_until)))
		return 0;
	prev = task_nice(current);
	set_user_nice(current, SEW_MIR_BOOST_NICE);
	*boosted = true;
	return prev;
}

static void sew_mir_boost_exit(bool boosted, int prev, u64 t0)
{
	if (!boosted)
		return;
	set_user_nice(current, prev);
	atomic64_inc(&sew_mir_boost_count);
	atomic64_add(div_u64(local_clock() - t0, 1000000), &sew_mir_boost_time_ms);
}

/* ---- event worker ------------------------------------------------------ */

static unsigned long sew_mir_reclaim_one(struct pid *pid, unsigned long pages,
				     bool may_swap)
{
	struct task_struct *task;
	struct mem_cgroup *memcg;
	unsigned long reclaimed;

	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task) {
		atomic64_inc(&sew_mir_refill_fail_count);
		return 0;
	}
	/* never reclaim exiting tasks or the init/root memcg: freeing
	 * those pages destabilises the device instead of relieving
	 * pressure (audit P0). */
	if (task->flags & PF_EXITING) {
		put_task_struct(task);
		return 0;
	}
	memcg = mem_cgroup_from_task(task);
	if (memcg && (memcg == root_mem_cgroup || task->pid == 1)) {
		put_task_struct(task);
		return 0;
	}
	reclaimed = 0;
	if (memcg)
		reclaimed = try_to_free_mem_cgroup_pages(memcg, pages,
							 GFP_KERNEL,
							 may_swap);
	put_task_struct(task);
	return reclaimed;
}

static int sew_mir_worker_fn(void *unused)
{
	while (!kthread_should_stop()) {
		int mb, flags;
		unsigned long pages;
		bool may_swap;
		u64 t0;
		int i;
		bool boosted;
		int prev_nice;

		wait_event_interruptible(sew_mir_waitq,
					 atomic_read(&sew_mir_event_mb) ||
					 kthread_should_stop());
		mb = atomic_xchg(&sew_mir_event_mb, 0);
		if (!mb || kthread_should_stop())
			continue;
		flags = atomic_xchg(&sew_mir_event_flags, 0);
		pages = (unsigned long)mb << (20 - PAGE_SHIFT);
		may_swap = !(flags & SEW_MIR_FLAG_RECLAIM_FILE);

		t0 = local_clock();
		prev_nice = sew_mir_boost_enter(&boosted);
		mutex_lock(&sew_mir_pid_lock);
		for (i = 0; i < sew_mir_pid_count; i++)
			atomic64_add(sew_mir_reclaim_one(sew_mir_pids[i], pages,
						     may_swap),
				     &sew_mir_total_reclaim_pages);
		mutex_unlock(&sew_mir_pid_lock);
		sew_mir_boost_exit(boosted, prev_nice, t0);
		atomic64_inc(&sew_mir_reclaim_times);
		atomic64_add(div_u64(local_clock() - t0, 1000000),
			     &sew_mir_total_reclaim_ms);
	}
	return 0;
}

/* ---- sysfs -------------------------------------------------------------- */

static void sew_mir_pid_clear_locked(void)
{
	int i;

	for (i = 0; i < sew_mir_pid_count; i++)
		put_pid(sew_mir_pids[i]);
	sew_mir_pid_count = 0;
}

static ssize_t sew_mir_pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	ssize_t off = 0;
	int i;

	mutex_lock(&sew_mir_pid_lock);
	for (i = 0; i < sew_mir_pid_count; i++)
		off += scnprintf(buf + off, PAGE_SIZE - off, "%d\n",
				 pid_nr(sew_mir_pids[i]));
	mutex_unlock(&sew_mir_pid_lock);
	return off;
}

static ssize_t sew_mir_pid_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	char tok[16];
	int val, ret;

	if (sscanf(buf, "%15s", tok) != 1)
		return -EINVAL;
	if (!strcmp(tok, "clear")) {
		mutex_lock(&sew_mir_pid_lock);
		sew_mir_pid_clear_locked();
		mutex_unlock(&sew_mir_pid_lock);
		pr_info("mi_reclaim: important list cleared\n");
		return count;
	}
	ret = kstrtoint(tok, 0, &val);
	if (ret || val <= 0)
		return ret ? ret : -EINVAL;

	mutex_lock(&sew_mir_pid_lock);
	if (sew_mir_pid_count >= SEW_MIR_MAX_PIDS) {
		mutex_unlock(&sew_mir_pid_lock);
		return -ENOSPC;
	}
	sew_mir_pids[sew_mir_pid_count] = find_get_pid(val);
	if (!sew_mir_pids[sew_mir_pid_count]) {
		mutex_unlock(&sew_mir_pid_lock);
		return -ESRCH;
	}
	sew_mir_pid_count++;
	mutex_unlock(&sew_mir_pid_lock);
	pr_info("mi_reclaim: added pid %d to important list (count=%d)\n",
		val, sew_mir_pid_count);
	return count;
}

static ssize_t sew_mir_event_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	char tok[24];
	int val, ret, flags = 0;

	if (sscanf(buf, "%23s", tok) != 1)
		return -EINVAL;
	ret = kstrtoint(tok, 0, &val);
	if (ret || val <= 0 || val > 4096)
		return ret ? ret : -EINVAL;
	/* optional second token: "file" requests file-only reclaim */
	if (sscanf(buf, "%*s %23s", tok) == 1 && !strcmp(tok, "file"))
		flags = SEW_MIR_FLAG_RECLAIM_FILE;

	atomic_set(&sew_mir_event_flags, flags);
	atomic_set(&sew_mir_event_mb, val);
	wake_up(&sew_mir_waitq);
	return count;
}

static ssize_t sew_mir_info_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	ssize_t off = 0;

	off += scnprintf(buf + off, PAGE_SIZE - off,
		"| [Reclaim Statistics]      |\n"
		"| reclaim_times: %lld\n"
		"| total_reclaim: %lld pages\n"
		"| total_reclaim_time: %lld ms\n"
		"| pid_miss_count: %lld\n"
		"| [Skip Throttle Statistics]|\n"
		"| skip_throttle_enabled: %u\n"
		"| skip_throttle_count: %lld\n"
		"| [Observe Statistics]      |\n"
		"| slowpath_total: %lld\n"
		"| slowpath_highorder: %lld\n"
		"| reclaim_end_calls: %lld\n"
		"| reclaimed_pages: %lld\n"
		"| zero_progress: %lld\n"
		"| [Switches]                |\n"
		"| enable_flags: 0x%x (0x1=RECLAIM_FILE 0x2=RECLAIM_ANON)\n"
		"| file_scan_enabled: %u fg_file_scan_threshold: %u\n"
		"| throttle_file_threshold: %u\n"
		"| auto_reclaim_threshold: %u auto_mb: %u auto_interval_ms: %u\n"
		"| auto_events: %lld\n"
		"| [Bypass/PCP]              |\n"
		"| bypass_pcp_enabled: %u bypass_pcp_count: %lld\n"
		"| bypass_highatomic_enabled: %u bypass_highatomic_count: %lld\n"
		"| [GFP Customize]           |\n"
		"| gfp_customize_enabled: %u gfp_cleared: %lld\n"
		"| [Proc Exit]               |\n"
		"| proc_exit_enabled: %u proc_exit_nice: %d\n"
		"| proc_exit_normalized: %lld proc_exit_camera: %lld\n"
		"| [Swappiness Follower]     |\n"
		"| swappiness_enabled: %u balance_file_threshold: %u\n"
		"| balance_swappiness: %d swappiness_writes: %lld\n"
		"| swappiness_passthru: %lld\n"
		"| [Boost Window]            |\n"
		"| refill_prio_boost: %u refill_prio_duration: %u ms\n"
		"| boost_count: %lld\n"
		"| boost_time_ms: %lld\n"
		/* G6 refill-compat (official popsicle info keys, read-only view).
		 * Official 6.12 semantics (strings evidence): refill_pool is a
		 * pool-subsystem front (no "echo refill_pool" write line in
		 * usage, bare display token); refill_low_file_threshold_mb is
		 * display-only ("| refill_low_file_threshold_mb: %lu", MB
		 * unit, gates refill-skip when file pages run thin);
		 * bare "refill" heads the refill-activity stats block
		 * (refill_total_count/time). The pool/refill worker carrier was
		 * deliberately not ported (header: 5 blockers + scheme A
		 * substitute), so these three lines report the scheme-A
		 * counterparts; the first three stay read-only (store
		 * rejects them with -EINVAL: acknowledging a write we would
		 * ignore would be a false promise). refill_prio_boost is
		 * writable (H2 boost window, see header). */
		"| [Refill Compat (read-only)]  |\n"
		"| refill_pool: %u (scheme-A armed)\n"
		"| refill_low_file_threshold_mb: %lu\n"
		"| refill: %lld (scheme-A auto events)\n"
		"| important_pids: %d\n",
		atomic64_read(&sew_mir_reclaim_times),
		atomic64_read(&sew_mir_total_reclaim_pages),
		atomic64_read(&sew_mir_total_reclaim_ms),
		atomic64_read(&sew_mir_refill_fail_count),
		sew_mir_skip_throttle_enabled,
		atomic64_read(&sew_mir_skip_throttle_count),
		atomic64_read(&sew_slowpath_total),
		atomic64_read(&sew_slowpath_highorder),
		atomic64_read(&sew_reclaim_end_calls),
		atomic64_read(&sew_reclaim_reclaimed_pages),
		atomic64_read(&sew_reclaim_zero_progress),
		sew_mir_enable_flags,
		sew_mir_file_scan_enabled, sew_mir_fg_file_scan_threshold,
		sew_mir_throttle_file_threshold,
		sew_mir_auto_reclaim_threshold, sew_mir_auto_reclaim_mb,
		sew_mir_auto_reclaim_interval_ms,
		atomic64_read(&sew_mir_auto_reclaim_count),
		sew_mir_bypass_pcp_enabled,
		atomic64_read(&sew_mir_bypass_pcp_count),
		sew_mir_bypass_highatomic_enabled,
		atomic64_read(&sew_mir_bypass_highatomic_count),
		sew_mir_gfp_customize_enabled,
		atomic64_read(&sew_mir_gfp_cleared_count),
		sew_mir_proc_exit_enabled, sew_mir_proc_exit_nice,
		atomic64_read(&sew_mir_proc_exit_count),
		atomic64_read(&sew_mir_proc_exit_camera_count),
		sew_mir_swappiness_enabled, sew_mir_balance_file_threshold,
		sew_mir_balance_swappiness,
		atomic64_read(&sew_mir_swappiness_write_count),
		atomic64_read(&sew_mir_swappiness_passthru_count),
		READ_ONCE(sew_mir_boost_enabled),
		READ_ONCE(sew_mir_boost_duration_ms),
		atomic64_read(&sew_mir_boost_count),
		atomic64_read(&sew_mir_boost_time_ms),
		/* G6: refill_pool = scheme-A armed (auto threshold set AND at
		 * least one important pid; pid count read lock-free, same
		 * benign-racy practice as the important_pids line below). */
		(sew_mir_auto_reclaim_threshold && sew_mir_pid_count) ? 1u : 0u,
		/* G6: official MB unit vs our pages unit; the gated object
		 * differs (theirs: skip pool-refill; ours: throttle-bypass
		 * file floor, same file-pages-floor family), hence the value
		 * is the pages threshold converted, not an identical knob. */
		(unsigned long)(sew_mir_throttle_file_threshold >> 8),
		/* G6: official refill-activity (pool cycles) <-> our scheme-A
		 * automatic file-only events (manual events stay in
		 * reclaim_times above). */
		atomic64_read(&sew_mir_auto_reclaim_count),
		sew_mir_pid_count);
	return off;
}

/* info writes: the dada tunable keys of the ported subsystems */
static ssize_t sew_mir_info_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	char key[32];
	int val = 0, n;

	n = sscanf(buf, "%31s %d", key, &val);
	if (n < 1)
		return -EINVAL;

	if (!strcmp(key, "enable_flags") && n == 2 && val >= 0 &&
	    val <= 3) {
		sew_mir_enable_flags = val;
	} else if (!strcmp(key, "skip_throttle_enabled") && n == 2) {
		sew_mir_skip_throttle_enabled = !!val;
	} else if (!strcmp(key, "throttle_file_threshold") && n == 2 &&
		   val >= 0) {
		sew_mir_throttle_file_threshold = val;
	} else if (!strcmp(key, "file_scan_enabled") && n == 2) {
		sew_mir_file_scan_enabled = !!val;
	} else if (!strcmp(key, "fg_file_scan_threshold") && n == 2 &&
		   val >= 0) {
		sew_mir_fg_file_scan_threshold = val;
	} else if (!strcmp(key, "auto_reclaim_threshold") && n == 2 &&
		   val >= 0) {
		sew_mir_auto_reclaim_threshold = val;
	} else if (!strcmp(key, "auto_reclaim_mb") && n == 2 &&
		   val > 0 && val <= 4096) {
		sew_mir_auto_reclaim_mb = val;
	} else if (!strcmp(key, "auto_reclaim_interval_ms") && n == 2 &&
		   val >= 1000) {
		sew_mir_auto_reclaim_interval_ms = val;
	} else if (!strcmp(key, "bypass_pcp_enabled") && n == 2) {
		sew_mir_bypass_pcp_enabled = !!val;
	} else if (!strcmp(key, "bypass_highatomic_enabled") && n == 2) {
		sew_mir_bypass_highatomic_enabled = !!val;
	} else if (!strcmp(key, "gfp_customize_enabled") && n == 2) {
		sew_mir_gfp_customize_enabled = !!val;
	} else if (!strcmp(key, "proc_exit_enabled") && n == 2) {
		sew_mir_proc_exit_enabled = !!val;
	} else if (!strcmp(key, "proc_exit_nice") && n == 2 &&
		   val >= -20 && val <= 19) {
		sew_mir_proc_exit_nice = val;
	} else if (!strcmp(key, "swappiness_enabled") && n == 2) {
		sew_mir_swappiness_enabled = !!val;
	} else if (!strcmp(key, "balance_file_threshold") && n == 2 &&
		   val >= 0) {
		sew_mir_balance_file_threshold = val;
	} else if (!strcmp(key, "balance_swappiness") && n == 2 &&
		   val >= 0 && val <= 200) {
		sew_mir_balance_swappiness = val;
	} else if (!strcmp(key, "refill_prio_boost") && n == 2 &&
		   (val == 0 || val == 1)) {
		/* H2: official 0|1 switch. 1 = on, arms a duration-ms
		 * window from now (auto triggers re-arm it); 0 = off. */
		WRITE_ONCE(sew_mir_boost_enabled, (unsigned int)val);
		if (val)
			WRITE_ONCE(sew_mir_boost_until, jiffies +
				   msecs_to_jiffies(
					   READ_ONCE(sew_mir_boost_duration_ms)));
	} else if (!strcmp(key, "refill_prio_duration") && n == 2 &&
		   val >= 1 && val <= SEW_MIR_BOOST_MAX_MS) {
		/* H2: official duration value (default 100); effective
		 * while boost=1. Writing it while on re-arms the window
		 * so the new duration applies immediately. */
		WRITE_ONCE(sew_mir_boost_duration_ms, (unsigned int)val);
		if (READ_ONCE(sew_mir_boost_enabled))
			WRITE_ONCE(sew_mir_boost_until,
				   jiffies + msecs_to_jiffies(val));
	} else {
		return -EINVAL;
	}
	return count;
}

static ssize_t sew_mir_reset_stats_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	atomic64_set(&sew_mir_total_reclaim_pages, 0);
	atomic64_set(&sew_mir_total_reclaim_ms, 0);
	atomic64_set(&sew_mir_reclaim_times, 0);
	atomic64_set(&sew_mir_refill_fail_count, 0);
	atomic64_set(&sew_mir_skip_throttle_count, 0);
	atomic64_set(&sew_mir_auto_reclaim_count, 0);
	atomic64_set(&sew_mir_bypass_pcp_count, 0);
	atomic64_set(&sew_mir_bypass_highatomic_count, 0);
	atomic64_set(&sew_mir_gfp_cleared_count, 0);
	atomic64_set(&sew_mir_proc_exit_count, 0);
	atomic64_set(&sew_mir_proc_exit_camera_count, 0);
	atomic64_set(&sew_mir_swappiness_write_count, 0);
	atomic64_set(&sew_mir_swappiness_passthru_count, 0);
	atomic64_set(&sew_mir_boost_count, 0);
	atomic64_set(&sew_mir_boost_time_ms, 0);
	atomic64_set(&sew_slowpath_total, 0);
	atomic64_set(&sew_slowpath_highorder, 0);
	atomic64_set(&sew_reclaim_end_calls, 0);
	atomic64_set(&sew_reclaim_reclaimed_pages, 0);
	atomic64_set(&sew_reclaim_zero_progress, 0);
	return count;
}

static ssize_t sew_mir_usage_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE,
		"mi_reclaim (Sew 5.15 port of the Xiaomi OS4 module)\n"
		"[pid Node Commands]\n"
		"  echo \"<pid>\" > pid     - Add pid (default)\n"
		"  echo \"clear\" > pid     - Clear all pids\n"
		"[event Node Commands]\n"
		"  echo \"<mb>\" > event          - Reclaim <mb> MB from all\n"
		"                                 important pids (swap ok)\n"
		"  echo \"<mb> file\" > event     - File-only reclaim (no swap)\n"
		"[info Node Commands]\n"
		"  cat info - statistics and switches\n"
		"  echo \"enable_flags <0-3>\" > info\n"
		"  echo \"skip_throttle_enabled <0|1>\" > info\n"
		"  echo \"throttle_file_threshold <pages>\" > info\n"
		"  echo \"file_scan_enabled <0|1>\" > info\n"
		"  echo \"fg_file_scan_threshold <pages>\" > info\n"
		"  echo \"auto_reclaim_threshold <free-pages,0=off>\" > info\n"
		"  echo \"auto_reclaim_mb <1-4096>\" > info\n"
		"  echo \"auto_reclaim_interval_ms <>=1000>\" > info\n"
		"  echo \"bypass_pcp_enabled <0|1>\" > info          # P0 drain\n"
		"  echo \"bypass_highatomic_enabled <0|1>\" > info   # P0 hireserve\n"
		"  echo \"gfp_customize_enabled <0|1>\" > info       # P1 kswapd\n"
		"  echo \"proc_exit_enabled <0|1>\" > info           # P2 exit nice\n"
		"  echo \"proc_exit_nice <-20..19>\" > info          # P2歸0 target\n"
		"  echo \"swappiness_enabled <0|1>\" > info          # P3 follower\n"
		"  echo \"balance_file_threshold <pages>\" > info    # P3 file gate\n"
		"  echo \"balance_swappiness <0-200>\" > info        # P3 thin branch\n"
		"  echo \"refill_prio_boost <0|1>\" > info           # H2 boost switch\n"
		"  echo \"refill_prio_duration <1-60000ms>\" > info # H2 window (def 100)\n"
		"[Refill Compat (read-only, cat info)]\n"
		"  refill_pool / refill_low_file_threshold_mb / refill - scheme-A view\n"
		"  refill_prio_boost 0|1 + refill_prio_duration <ms>: boost window\n"
		"[Other]\n"
		"  echo 1 > reset_stats\n"
		"  cat /proc/mi_reclaim       # observe-only counters (legacy)\n");
}

static struct kobj_attribute sew_mir_pid_attr =
	__ATTR(pid, 0644, sew_mir_pid_show, sew_mir_pid_store);
static struct kobj_attribute sew_mir_event_attr =
	__ATTR(event, 0200, NULL, sew_mir_event_store);
static struct kobj_attribute sew_mir_info_attr =
	__ATTR(info, 0644, sew_mir_info_show, sew_mir_info_store);
static struct kobj_attribute sew_mir_usage_attr =
	__ATTR(usage, 0444, sew_mir_usage_show, NULL);
static struct kobj_attribute sew_mir_reset_attr =
	__ATTR(reset_stats, 0200, NULL, sew_mir_reset_stats_store);

static struct attribute *sew_mir_attrs[] = {
	&sew_mir_pid_attr.attr,
	&sew_mir_event_attr.attr,
	&sew_mir_info_attr.attr,
	&sew_mir_usage_attr.attr,
	&sew_mir_reset_attr.attr,
	NULL,
};
static const struct attribute_group sew_mir_attr_group = {
	.attrs = sew_mir_attrs,
};
static struct kobject *sew_mir_kobj;

/* ---- legacy /proc observe node (unchanged first-cut interface) --------- */

static int sew_mir_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "slowpath_total=%lld\n"
		   "slowpath_highorder=%lld\n"
		   "reclaim_end_calls=%lld\n"
		   "reclaimed_pages=%lld\n"
		   "zero_progress=%lld\n",
		   atomic64_read(&sew_slowpath_total),
		   atomic64_read(&sew_slowpath_highorder),
		   atomic64_read(&sew_reclaim_end_calls),
		   atomic64_read(&sew_reclaim_reclaimed_pages),
		   atomic64_read(&sew_reclaim_zero_progress));
	return 0;
}

static int sew_mir_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_mir_proc_show, NULL);
}

static const struct proc_ops sew_mir_proc_ops = {
	.proc_open	= sew_mir_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ---- module ------------------------------------------------------------ */

static void sew_mir_hooks_unregister(void)
{
	unregister_trace_android_vh_alloc_pages_slowpath_start(
		sew_mir_slowpath, NULL);
	unregister_trace_android_vh_direct_reclaim_end(sew_mir_reclaim_end, NULL);
	unregister_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mir_throttle_bypass, NULL);
	unregister_trace_android_vh_tune_scan_type(sew_mir_tune_scan_type, NULL);
	unregister_trace_android_vh_drain_all_pages_bypass(
		sew_mir_drain_bypass, NULL);
	unregister_trace_android_vh_unreserve_highatomic_bypass(
		sew_mir_unreserve_bypass, NULL);
	unregister_trace_android_vh_alloc_pages_entry(
		sew_mir_customize_gfp, NULL);
	unregister_trace_android_vh_mmput(sew_mir_proc_exit, NULL);
	unregister_trace_android_vh_tune_swappiness(
		sew_mir_tune_swappiness, NULL);
	tracepoint_synchronize_unregister();
}

static int __init mi_reclaim_init(void)
{
	int ret;

	ret = register_trace_android_vh_alloc_pages_slowpath_start(
		sew_mir_slowpath, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_direct_reclaim_end(
		sew_mir_reclaim_end, NULL);
	if (ret)
		goto err_slowpath;
	ret = register_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mir_throttle_bypass, NULL);
	if (ret)
		goto err_reclaim_end;
	ret = register_trace_android_vh_tune_scan_type(
		sew_mir_tune_scan_type, NULL);
	if (ret)
		goto err_throttle;
	/* P0: both hooks exist in-tree and were unregistered before. */
	ret = register_trace_android_vh_drain_all_pages_bypass(
		sew_mir_drain_bypass, NULL);
	if (ret)
		goto err_scan;
	ret = register_trace_android_vh_unreserve_highatomic_bypass(
		sew_mir_unreserve_bypass, NULL);
	if (ret)
		goto err_drain;
	/* P1: alloc entry gfp rewrite point. */
	ret = register_trace_android_vh_alloc_pages_entry(
		sew_mir_customize_gfp, NULL);
	if (ret)
		goto err_unreserve;
	/* P2: mmput true-release branch. */
	ret = register_trace_android_vh_mmput(sew_mir_proc_exit, NULL);
	if (ret)
		goto err_entry;
	/* P3 (K7-FIX-K3 P1-2, load-bearing): scene_swappiness.o links BEFORE
	 * mi_reclaim.o in mm/Makefile (=y both, same device_initcall
	 * level => link order decides registration order), so scene's
	 * callback runs FIRST and ours runs SECOND as the follower.  The
	 * passthrough rule inside sew_mir_tune_swappiness guarantees we
	 * only overwrite when armed.  Do NOT reorder the Makefile. */
	ret = register_trace_android_vh_tune_swappiness(
		sew_mir_tune_swappiness, NULL);
	if (ret)
		goto err_mmput;

	if (!proc_create("mi_reclaim", 0444, NULL, &sew_mir_proc_ops)) {
		ret = -ENOMEM;
		goto err_swappiness;
	}

	sew_mir_kobj = kobject_create_and_add("mi_reclaim", kernel_kobj);
	if (!sew_mir_kobj) {
		ret = -ENOMEM;
		goto err_proc;
	}
	ret = sysfs_create_group(sew_mir_kobj, &sew_mir_attr_group);
	if (ret)
		goto err_kobj;

	sew_mir_worker = kthread_run(sew_mir_worker_fn, NULL, "mireclaimd");
	if (IS_ERR(sew_mir_worker)) {
		ret = PTR_ERR(sew_mir_worker);
		sew_mir_worker = NULL;
		goto err_group;
	}
	return 0;

err_group:
	sysfs_remove_group(sew_mir_kobj, &sew_mir_attr_group);
err_kobj:
	kobject_put(sew_mir_kobj);
err_proc:
	remove_proc_entry("mi_reclaim", NULL);
err_swappiness:
	unregister_trace_android_vh_tune_swappiness(
		sew_mir_tune_swappiness, NULL);
err_mmput:
	unregister_trace_android_vh_mmput(sew_mir_proc_exit, NULL);
err_entry:
	unregister_trace_android_vh_alloc_pages_entry(
		sew_mir_customize_gfp, NULL);
err_unreserve:
	unregister_trace_android_vh_unreserve_highatomic_bypass(
		sew_mir_unreserve_bypass, NULL);
err_drain:
	unregister_trace_android_vh_drain_all_pages_bypass(
		sew_mir_drain_bypass, NULL);
err_scan:
	unregister_trace_android_vh_tune_scan_type(sew_mir_tune_scan_type, NULL);
err_throttle:
	unregister_trace_android_vh_throttle_direct_reclaim_bypass(
		sew_mir_throttle_bypass, NULL);
err_reclaim_end:
	unregister_trace_android_vh_direct_reclaim_end(sew_mir_reclaim_end, NULL);
err_slowpath:
	unregister_trace_android_vh_alloc_pages_slowpath_start(
		sew_mir_slowpath, NULL);
	tracepoint_synchronize_unregister();
	return ret;
}

static void __exit mi_reclaim_exit(void)
{
	if (sew_mir_worker)
		kthread_stop(sew_mir_worker);
	atomic_set(&sew_mir_event_mb, 0);
	wake_up(&sew_mir_waitq);

	mutex_lock(&sew_mir_pid_lock);
	sew_mir_pid_clear_locked();
	mutex_unlock(&sew_mir_pid_lock);

	sysfs_remove_group(sew_mir_kobj, &sew_mir_attr_group);
	kobject_put(sew_mir_kobj);
	remove_proc_entry("mi_reclaim", NULL);

	sew_mir_hooks_unregister();
}

module_init(mi_reclaim_init);
module_exit(mi_reclaim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew port of the Xiaomi OS4 mi_reclaim (observe + bounded tuning, defaults off)");
