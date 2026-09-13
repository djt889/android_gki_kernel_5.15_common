// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/flt.c - FLT frame-load engine
 *
 * H1a-MIGAME-S3 stage 3: frame load tracking -> target frequency.
 * Official shape (B2): flt_cal_freq main computation + SF/GPU/fence/
 * frame-time inputs + uclamp linkage. ~40 official funcs condensed to
 * the framework surface below; unrecovered internals use the documented
 * conservative formula.
 *
 * DIVERGENCE NOTE 1 (flt_cal_freq formula): official per-frame weighting
 * unrecovered. Port: frame_avg over last N frames -> target =
 * base_freq * clamp(frame_avg / target_frame_ms, 0.5, 2.0). base_freq
 * is the lowest non-zero flt_low_freq[] entry (fallback: lowest
 * glk_minfreq, else 0 = report only).
 * DIVERGENCE NOTE 2 (uclamp write path): official wrote the task clamp
 * via the WALT-side path. Port uses uclamp_eff_value() for the audit
 * read; the write goes through uclamp_req with task_rq_lock held where
 * available — here via get_task_struct + task_rq_lock(p) pinning, with
 * the value clamped into [0, SCHED_CAPACITY_SCALE]. Snapshot/restore
 * discipline per D6: save only on first write, restore only own value.
 * DIVERGENCE NOTE 3 (SF/GPU/fence payloads): official wire formats
 * unrecovered. Port exposes registerable callbacks with default empty
 * implementations; real HAL formats plug in at bring-up without ABI
 * churn here.
 */

#include <linux/irq_work.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "mi_game.h"

/* uclamp_eff_value: EXPORT_SYMBOL_GPL in core.c, declared only in the
 * private kernel/sched/sched.h; local redeclaration (the enum
 * uclamp_id itself is public in include/linux/sched.h). */
extern unsigned long uclamp_eff_value(struct task_struct *p,
				      enum uclamp_id clamp_id);

/* MI_GAME_ARR_SZ lives in mi_game_ca.c; local copy for table bounds. */
#define SEW_FLT_ARR_SZ	8

/* Bucket ids must match kernel/sched/core.c:1323
 * (UCLAMP_BUCKET_DELTA = DIV_ROUND_CLOSEST(SCHED_CAPACITY_SCALE,
 * UCLAMP_BUCKETS) = 51 at CONFIG_UCLAMP_BUCKETS_COUNT=20). Core's macro
 * is file-private, so recompute it here with the identical expression;
 * callers clamp with min_t(..., UCLAMP_BUCKETS - 1) exactly like
 * uclamp_bucket_id(). A wrong divisor (e.g. 16) skews bucket_id high
 * for almost every value and desyncs rq-side aggregation until the next
 * core update recomputes it. */
#define SEW_FLT_UCLAMP_BUCKET_DELTA \
	DIV_ROUND_CLOSEST(SCHED_CAPACITY_SCALE, UCLAMP_BUCKETS)

/* ---- frame ring: 8 entries {start,end,duration}, spinlock-guarded ----
 * Single global ring (frame events are system-wide vsync markers, not
 * per-CPU). Writers: slot14 path + ioctl path (process context) and any
 * future vsync hook; spinlock covers all since critical section is a
 * few stores. Readers: flt_cal_freq under the same lock.
 */
#define SEW_FLT_RING_NR	8

struct sew_flt_frame {
	u64 start;
	u64 end;
	u64 duration;
};

static struct sew_flt_frame sew_flt_ring[SEW_FLT_RING_NR];
static unsigned int sew_flt_ring_idx;
static bool sew_flt_ring_open;
static u64 sew_flt_open_ts;
static DEFINE_SPINLOCK(sew_flt_ring_lock);

/* ---- SF/GPU/fence input callbacks (default: empty) ---- */
static void sew_flt_sf_default(u64 a, u64 b) { (void)a; (void)b; }
static void sew_flt_gpu_default(unsigned long load) { (void)load; }
static void sew_flt_fence_default(void) { }

static sew_flt_sf_cb_t sew_flt_sf_cb = sew_flt_sf_default;
static sew_flt_gpu_cb_t sew_flt_gpu_cb = sew_flt_gpu_default;
static sew_flt_fence_cb_t sew_flt_fence_cb = sew_flt_fence_default;

int sew_flt_register_sf_cb(sew_flt_sf_cb_t cb)
{
	if (!cb)
		return -EINVAL;
	WRITE_ONCE(sew_flt_sf_cb, cb);
	return 0;
}

int sew_flt_register_gpu_cb(sew_flt_gpu_cb_t cb)
{
	if (!cb)
		return -EINVAL;
	WRITE_ONCE(sew_flt_gpu_cb, cb);
	return 0;
}

int sew_flt_register_fence_cb(sew_flt_fence_cb_t cb)
{
	if (!cb)
		return -EINVAL;
	WRITE_ONCE(sew_flt_fence_cb, cb);
	return 0;
}

void sew_migame_flt_input_sf(u64 a, u64 b)
{
	if (!sew_migame_get_enable())
		return;
	READ_ONCE(sew_flt_sf_cb)(a, b);
}

void sew_migame_flt_input_gpu(unsigned long load)
{
	if (!sew_migame_get_enable())
		return;
	READ_ONCE(sew_flt_gpu_cb)(load);
}

void sew_migame_flt_input_fence(void)
{
	if (!sew_migame_get_enable())
		return;
	READ_ONCE(sew_flt_fence_cb)();
}

/* ---- frame boundaries ---- */
void flt_frame_begin(u64 ts)
{
	unsigned long flags;

	if (!sew_migame_get_enable())
		return;
	spin_lock_irqsave(&sew_flt_ring_lock, flags);
	sew_flt_open_ts = ts ? ts : sched_clock();
	sew_flt_ring_open = true;
	spin_unlock_irqrestore(&sew_flt_ring_lock, flags);
}

void flt_frame_end(u64 ts)
{
	unsigned long flags;
	u64 end = ts ? ts : sched_clock();
	struct sew_flt_frame *f;

	if (!sew_migame_get_enable())
		return;
	spin_lock_irqsave(&sew_flt_ring_lock, flags);
	if (!sew_flt_ring_open) {
		spin_unlock_irqrestore(&sew_flt_ring_lock, flags);
		return;
	}
	f = &sew_flt_ring[sew_flt_ring_idx % SEW_FLT_RING_NR];
	f->start = sew_flt_open_ts;
	f->end = end;
	f->duration = (end >= sew_flt_open_ts) ? (end - sew_flt_open_ts) : 0;
	sew_flt_ring_idx++;
	sew_flt_ring_open = false;
	spin_unlock_irqrestore(&sew_flt_ring_lock, flags);
}

/* Frame average in ms (fixed-point x1000) over the last n frames. */
static u64 sew_flt_frame_avg_ms_x1000(unsigned int n)
{
	unsigned long flags;
	u64 sum = 0;
	unsigned int i, cnt = 0;

	if (n == 0 || n > SEW_FLT_RING_NR)
		n = SEW_FLT_RING_NR;
	spin_lock_irqsave(&sew_flt_ring_lock, flags);
	for (i = 0; i < n && i < sew_flt_ring_idx; i++) {
		unsigned int slot = (sew_flt_ring_idx - 1 - i) % SEW_FLT_RING_NR;

		if (!sew_flt_ring[slot].duration)
			continue;
		/* ns -> ms x1000: duration / 1000 = us, keep x1000 ms */
		sum += sew_flt_ring[slot].duration / 1000;
		cnt++;
	}
	spin_unlock_irqrestore(&sew_flt_ring_lock, flags);
	if (!cnt)
		return 0;
	return sum / cnt;
}

/* Lowest non-zero entry of an 8-wide kHz table, 0 if all zero. */
static unsigned int sew_flt_table_floor(const unsigned int *tbl, int n)
{
	unsigned int best = 0;
	int i;

	for (i = 0; i < n; i++) {
		if (!tbl[i])
			continue;
		if (!best || tbl[i] < best)
			best = tbl[i];
	}
	return best;
}

/* ---- core computation ---- */
unsigned long flt_cal_freq(unsigned int base_khz_hint)
{
	u64 avg_x1000, tgt_x1000;
	unsigned int base, target;
	unsigned int fps;
	u64 ratio_x1000;

	if (!sew_migame_get_enable())
		return 0;
	/* DIVERGENCE NOTE 1: conservative frame-average scaling. */
	avg_x1000 = sew_flt_frame_avg_ms_x1000(SEW_FLT_RING_NR);
	if (!avg_x1000)
		return 0;
	fps = sew_migame_flt_target_fps();
	if (!fps)
		fps = 60;
	/* target frame ms x1000 = 1000000 / fps */
	tgt_x1000 = 1000000ULL / fps;
	if (!tgt_x1000)
		return 0;
	/* ratio x1000 = avg / target, clamped to [0.5, 2.0] */
	ratio_x1000 = avg_x1000 * 1000 / tgt_x1000;
	if (ratio_x1000 < 500)
		ratio_x1000 = 500;
	if (ratio_x1000 > 2000)
		ratio_x1000 = 2000;

	base = base_khz_hint;
	if (!base)
		base = sew_flt_table_floor(sew_migame_flt_low_tbl(), SEW_FLT_ARR_SZ);
	if (!base)
		base = sew_flt_table_floor(sew_migame_glk_min_tbl(), SEW_FLT_ARR_SZ);
	if (!base)
		return 0;
	target = (unsigned int)((u64)base * ratio_x1000 / 1000);
	return target;
}

/* ---- uclamp apply with snapshot save/restore (D6 discipline) ----
 * Per-task snapshot (single outstanding writer assumed: the game
 * policy owner). save records uclamp_req values only on the first
 * write while !saved; restore writes back the saved values only if the
 * current values still equal what we set (last-writer-wins: never
 * clear a value owned by xr_qs or a later writer). Clamp values are
 * carried in util units [0, SCHED_CAPACITY_SCALE].
 *
 * xr_qs arbitration (stage-4 rule, C5 §4.1 + D6 charter §5/R5):
 * xr_qs (kernel/sched/xr_qs.c) writes the SAME field
 * (p->uclamp_req[UCLAMP_MIN].value) through its own static channel
 * (qs_uclamp_write: value + bucket_id, guarded by qs_state_lock and
 * QS_ST_VIP ownership). There is no cross-module lock, so the two
 * writers arbitrate by value, not by exclusion:
 *   - apply: when a snapshot is already armed for @p, the saved
 *     baseline is kept (first-writer baseline wins) and only the
 *     set_* record advances; when NO snapshot is armed, the current
 *     register value -- possibly xr_qs's floor -- is saved as the
 *     baseline, so restore returns the task to xr_qs's value.
 *   - restore: each side is written back only if the live register
 *     still equals what THIS side set (last-writer-wins). If xr_qs
 *     overwrote us in between, its value survives (we only release
 *     the record). If we overwrote xr_qs, restore returns the
 *     xr_qs-saved baseline. Either way only-ours-is-cleared.
 *   - bucket_id: uclamp_req.value is the effective field (core
 *     clamps from .value); bucket_id is a lookup cache recomputed
 *     by the next uclamp update. Both writers update it after the
 *     value store (same pattern as xr_qs qs_uclamp_write), so a
 *     stale bucket never outlives the next effective update.
 *
 * NOTE on locking: uclamp_req.value is a bit-field (unsigned int value
 * : bits_per(SCHED_CAPACITY_SCALE)) so READ_ONCE/WRITE_ONCE cannot be
 * used on it (address-of-bitfield error). All accesses here run under
 * sew_flt_snap_lock (irqsave), which is the single writer path for our own
 * writes; concurrent readers use uclamp_eff_value() (the exported,
 * properly-locked audit path). Plain accesses under our spinlock are
 * therefore race-free against our own save/set/restore sequence.
 * Against xr_qs there is intentionally no shared lock (see above);
 * the value-compare protocol is the arbitration.
 */
/* Snapshot ownership (P1 fix): @p is held with a task reference
 * (get_task_struct on arm, put_task_struct on release), so the pointer
 * stays valid until restore/exit drops it. A bare pointer would dangle
 * if the task exited before restore/exit ran (UAF on the restore write).
 * Single global slot on purpose: one outstanding task at a time, a
 * second task gets -EBUSY (fail-closed). Per-task snapshots would widen
 * the concurrent-write surface against xr_qs for no in-tree caller. */
struct sew_flt_uclamp_snap {
	struct task_struct *p;
	unsigned int saved_min;
	unsigned int saved_max;
	unsigned int set_min;
	unsigned int set_max;
	bool saved;
};

static struct sew_flt_uclamp_snap sew_flt_snap;
static DEFINE_SPINLOCK(sew_flt_snap_lock);

static unsigned int sew_flt_util_to_uclamp(unsigned int v)
{
	return clamp_val(v, 0U, (unsigned int)SCHED_CAPACITY_SCALE);
}

int sew_flt_uclamp_apply(struct task_struct *p, unsigned int min,
		     unsigned int max)
{
	unsigned long flags;
	unsigned int cur_min, cur_max;

	if (!p)
		return -EINVAL;
	if (!sew_migame_get_enable())
		return 0;
	min = sew_flt_util_to_uclamp(min);
	max = sew_flt_util_to_uclamp(max);
	if (min > max)
		min = max;

	spin_lock_irqsave(&sew_flt_snap_lock, flags);
	if (sew_flt_snap.saved && sew_flt_snap.p != p) {
		/* Owned by another task; refuse rather than corrupt. */
		spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
		return -EBUSY;
	}
	cur_min = p->uclamp_req[UCLAMP_MIN].value;
	cur_max = p->uclamp_req[UCLAMP_MAX].value;
	if (!sew_flt_snap.saved) {
		/* Hold a reference so the snapshot pointer cannot dangle
		 * (released in restore and in flt_exit). */
		get_task_struct(p);
		sew_flt_snap.p = p;
		sew_flt_snap.saved_min = cur_min;
		sew_flt_snap.saved_max = cur_max;
		sew_flt_snap.saved = true;
	}
	/* Audit read via the effective-value path (DIVERGENCE NOTE 2). */
	(void)uclamp_eff_value(p, UCLAMP_MIN);
	p->uclamp_req[UCLAMP_MIN].value = min;
	p->uclamp_req[UCLAMP_MIN].bucket_id =
		min_t(unsigned int, min / SEW_FLT_UCLAMP_BUCKET_DELTA,
		      (unsigned int)(UCLAMP_BUCKETS - 1));
	p->uclamp_req[UCLAMP_MAX].value = max;
	p->uclamp_req[UCLAMP_MAX].bucket_id =
		min_t(unsigned int, max / SEW_FLT_UCLAMP_BUCKET_DELTA,
		      (unsigned int)(UCLAMP_BUCKETS - 1));
	sew_flt_snap.set_min = min;
	sew_flt_snap.set_max = max;
	spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
	return 0;
}

void sew_flt_uclamp_restore(struct task_struct *p)
{
	unsigned long flags;
	unsigned int cur_min, cur_max;

	if (!p)
		return;
	spin_lock_irqsave(&sew_flt_snap_lock, flags);
	if (!sew_flt_snap.saved || sew_flt_snap.p != p) {
		spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
		return;
	}
	/* Last-writer-wins: only clear what still equals our set value
	 * (xr_qs arbitration: a foreign overwrite survives, we just
	 * release the record). bucket_id follows .value (same pattern
	 * as xr_qs qs_uclamp_write). */
	cur_min = p->uclamp_req[UCLAMP_MIN].value;
	cur_max = p->uclamp_req[UCLAMP_MAX].value;
	if (cur_min == sew_flt_snap.set_min) {
		p->uclamp_req[UCLAMP_MIN].value = sew_flt_snap.saved_min;
		p->uclamp_req[UCLAMP_MIN].bucket_id =
			min_t(unsigned int,
			      sew_flt_snap.saved_min / SEW_FLT_UCLAMP_BUCKET_DELTA,
			      (unsigned int)(UCLAMP_BUCKETS - 1));
	}
	if (cur_max == sew_flt_snap.set_max) {
		p->uclamp_req[UCLAMP_MAX].value = sew_flt_snap.saved_max;
		p->uclamp_req[UCLAMP_MAX].bucket_id =
			min_t(unsigned int,
			      sew_flt_snap.saved_max / SEW_FLT_UCLAMP_BUCKET_DELTA,
			      (unsigned int)(UCLAMP_BUCKETS - 1));
	}
	/* Release the record while still holding the lock, BEFORE the
	 * unlocked put below: a concurrent exit draining the same
	 * snapshot in the put window must see saved == false. */
	{
		struct task_struct *held = sew_flt_snap.p;

		sew_flt_snap.p = NULL;
		sew_flt_snap.saved = false;
		spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
		/* May sleep when this was the last reference (task free),
		 * so it runs after the unlock. Paired with the get in apply. */
		put_task_struct(held);
		return;
	}
}

/* ---- engine init/exit (wired into sew_migame_flt_engine_init/exit) ---- */
int sew_migame_flt_init(void)
{
	unsigned long flags;

	spin_lock_irqsave(&sew_flt_ring_lock, flags);
	memset(sew_flt_ring, 0, sizeof(sew_flt_ring));
	sew_flt_ring_idx = 0;
	sew_flt_ring_open = false;
	sew_flt_open_ts = 0;
	spin_unlock_irqrestore(&sew_flt_ring_lock, flags);

	spin_lock_irqsave(&sew_flt_snap_lock, flags);
	memset(&sew_flt_snap, 0, sizeof(sew_flt_snap));
	spin_unlock_irqrestore(&sew_flt_snap_lock, flags);

	sew_flt_sf_cb = sew_flt_sf_default;
	sew_flt_gpu_cb = sew_flt_gpu_default;
	sew_flt_fence_cb = sew_flt_fence_default;
	return 0;
}

void sew_migame_flt_exit(void)
{
	unsigned long flags;

	/* Restore any outstanding uclamp snapshot before dropping it:
	 * if the module unloads while a task still carries our uclamp
	 * request, clearing the record alone would strand that value on
	 * the task forever (N6). snap_p is safe to touch here: the arm
	 * path took a task reference, so the task_struct cannot be freed
	 * while the snapshot is armed (released below, and in restore). */
	spin_lock_irqsave(&sew_flt_snap_lock, flags);
	if (sew_flt_snap.saved && sew_flt_snap.p) {
		struct task_struct *snap_p = sew_flt_snap.p;
		unsigned int set_min = sew_flt_snap.set_min;
		unsigned int set_max = sew_flt_snap.set_max;
		unsigned int saved_min = sew_flt_snap.saved_min;
		unsigned int saved_max = sew_flt_snap.saved_max;

		/* Clear the record while still holding the lock, BEFORE the
		 * unlocked put below: a concurrent apply arming a new
		 * snapshot in the put window must not be wiped by us. */
		memset(&sew_flt_snap, 0, sizeof(sew_flt_snap));
		spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
		/* last-writer-wins: only undo the values we still own */
		if (snap_p->uclamp_req[UCLAMP_MIN].value == set_min) {
			snap_p->uclamp_req[UCLAMP_MIN].value = saved_min;
			snap_p->uclamp_req[UCLAMP_MIN].bucket_id =
				min_t(unsigned int,
				      saved_min / SEW_FLT_UCLAMP_BUCKET_DELTA,
				      (unsigned int)(UCLAMP_BUCKETS - 1));
		}
		if (snap_p->uclamp_req[UCLAMP_MAX].value == set_max) {
			snap_p->uclamp_req[UCLAMP_MAX].value = saved_max;
			snap_p->uclamp_req[UCLAMP_MAX].bucket_id =
				min_t(unsigned int,
				      saved_max / SEW_FLT_UCLAMP_BUCKET_DELTA,
				      (unsigned int)(UCLAMP_BUCKETS - 1));
		}
		/* May sleep when this was the last reference; runs unlocked
		 * (process-context exit path only). */
		put_task_struct(snap_p);
	} else {
		memset(&sew_flt_snap, 0, sizeof(sew_flt_snap));
		spin_unlock_irqrestore(&sew_flt_snap_lock, flags);
	}

	spin_lock_irqsave(&sew_flt_ring_lock, flags);
	memset(sew_flt_ring, 0, sizeof(sew_flt_ring));
	sew_flt_ring_idx = 0;
	sew_flt_ring_open = false;
	spin_unlock_irqrestore(&sew_flt_ring_lock, flags);
}
