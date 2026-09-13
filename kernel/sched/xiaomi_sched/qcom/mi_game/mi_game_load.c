// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/mi_game_load.c - game_load engine
 *
 * G3R-MIGAME-S2 stage 2: per-CPU game-load history state machine +
 * irq_work driver + policy online/offline listener.
 *
 * Known facts used (no re-RE; see report for evidence pointers):
 * - G4: slot14 provider = update_pkg_load(task,u32,u32,u64,u64);
 *   arg4 wallclock is nominal (body uses sched_clock()); arg5 is an
 *   opaque walt fixed-point increment passed through opaquely.
 * - Prior agent RE: game_load_reset zeroes an 80-byte per-CPU struct
 *   (5x16B, spinlock at per-cpu+0x60); game_load_history_update keeps
 *   an 80-byte-stride history array, computes deltas, and runs a jump
 *   table state machine (default state 0x21, (old-8) upper bound 0x19,
 *   state values <<10 i.e. x1024 timer-resolution multiplier).
 *
 * DIVERGENCE NOTEs below mark every place the official body could not
 * be recovered; all such places use the conservative (default-off /
 * behaviour-neutral) choice.
 */
#include <linux/build_bug.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/irq_work.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "mi_game.h"

/* DIVERGENCE NOTE (glk params): official glk_* tunables already exist as
 * module params in mi_game_ca.c (glk_minfreq/glk_maxfreq arrays,
 * glk_freq_limit_walt, glk_freq_limit_start, glk_fbreak_enable,
 * glk_disable). This file consumes them via the sew_migame_glk_* accessors
 * declared in mi_game.h; it does not redeclare them (no param shadow).
 */

/* ---- per-CPU game-load state ----
 * 80 bytes total in the official layout (5 x 16B entries, [RE] lock at
 * +0x60 belongs to a wider struct). DIVERGENCE NOTE (layout): the exact
 * official field assignment inside the 80 bytes is unrecovered, so this
 * port keeps an explicit struct of identical size whose fields carry the
 * documented semantics (history ring + accumulators + state + lock).
 * sizeof is asserted to 80 at build time.
 */
#define SEW_MIGAME_LOAD_HIST_NR	5

/* Load levels (MIGAME_LOAD_LVL_*) are shared via mi_game.h.
 * DIVERGENCE NOTE (states): official default state 0x21 and the
 * (old-8)<=0x19 jump-table bound are reproduced as those symbolic load
 * levels; the exact official per-state actions are unrecovered, so
 * each level maps conservatively onto min/max freq break requests
 * (see migame_freq_apply mapping in mi_game_freq.c). */

struct sew_migame_cpu_load {
	/* 5 x 16B history entries: {u64 time; u64 load} each = 80 B,
	 * the zeroed region matching recovered game_load_reset. */
	u64 hist_time[SEW_MIGAME_LOAD_HIST_NR];
	u64 hist_load[SEW_MIGAME_LOAD_HIST_NR];
};
static_assert(sizeof(struct sew_migame_cpu_load) == 80);

struct sew_migame_pcpu_state {
	struct sew_migame_cpu_load load;	/* +0x00, 80 B */
	u64 hist_idx;			/* +0x50 */
	u64 last_update;		/* +0x58 */
	spinlock_t lock;		/* +0x60 (recovered offset) */
	u64 acc;			/* opaque arg5 accumulator */
	u32 state;			/* current load level */
	u32 pad;
};
static_assert(offsetof(struct sew_migame_pcpu_state, lock) == 0x60);

static DEFINE_PER_CPU(struct sew_migame_pcpu_state, sew_migame_pcpu);

/* ---- irq_work driver ----
 * No new kthread (task requirement). irq_work folds per-CPU deltas and
 * forwards the aggregated level to the freq layer from process-context
 * work (freq_qos_* may sleep -> never called from irq_work directly).
 */
static DEFINE_IRQ_WORK(sew_migame_load_irqwork, NULL);
static struct work_struct sew_migame_load_work;
static bool sew_migame_load_work_init;

/* Agg level written by irq_work (hardirq-safe u32 store), consumed by
 * the process-context worker. Gate snapshot avoids TOCTOU churn.
 */
static u32 sew_migame_agg_level;
static u32 sew_migame_agg_seq;

/* DIVERGENCE NOTE (thresholds): the official delta->state jump-table
 * edges are unrecovered. Thresholds below are conservative opaque-unit
 * guesses: small deltas stay IDLE/LOW (no freq request), only large
 * sustained deltas reach HIGH/BOOST. Tunable at runtime via the
 * read-only debugfs/proc counters plus glk_* params; behaviour-neutral
 * while sew_migame_enable==0 or glk_disable!=0.
 */
#define SEW_MIGAME_DELTA_LOW	1000000ULL	/* ~1ms in ns-scale units */
#define SEW_MIGAME_DELTA_HIGH	4000000ULL
#define SEW_MIGAME_DELTA_BOOST	8000000ULL

static u32 sew_migame_level_for_delta(u64 delta)
{
	if (delta >= SEW_MIGAME_DELTA_BOOST)
		return MIGAME_LOAD_LVL_BOOST;
	if (delta >= SEW_MIGAME_DELTA_HIGH)
		return MIGAME_LOAD_LVL_HIGH;
	if (delta >= SEW_MIGAME_DELTA_LOW)
		return MIGAME_LOAD_LVL_LOW;
	return MIGAME_LOAD_LVL_IDLE;
}

/* Forward from mi_game_freq.c (avoids cross-include of cpufreq guts). */
extern void sew_migame_freq_kick(u32 level, u32 seq);

static void sew_migame_load_irqwork_fn(struct irq_work *work)
{
	int cpu;
	u64 max_delta = 0;
	unsigned long flags;

	/* DIVERGENCE NOTE (aggregation): official cross-CPU reduction is
	 * unrecovered; max-wins is the conservative choice (a single hot
	 * game thread still boosts, idle CPUs never veto it). */
	for_each_possible_cpu(cpu) {
		struct sew_migame_pcpu_state *st = per_cpu_ptr(&sew_migame_pcpu, cpu);
		u64 d;

		spin_lock_irqsave(&st->lock, flags);
		d = st->load.hist_load[(st->hist_idx + SEW_MIGAME_LOAD_HIST_NR - 1) %
					SEW_MIGAME_LOAD_HIST_NR];
		spin_unlock_irqrestore(&st->lock, flags);
		if (d > max_delta)
			max_delta = d;
	}
	sew_migame_agg_level = sew_migame_level_for_delta(max_delta);
	sew_migame_agg_seq++;
	if (sew_migame_load_work_init)
		schedule_work(&sew_migame_load_work);
}

static void sew_migame_load_work_fn(struct work_struct *work)
{
	/* Disabled path: clear any outstanding request so a stale BOOST
	 * can never pin frequencies after the feature is turned off. */
	if (!sew_migame_get_enable() || sew_migame_glk_disabled()) {
		sew_migame_freq_clear();
		return;
	}
	if (!sew_migame_glk_fbreak_enabled()) {
		sew_migame_freq_clear();
		return;
	}
	sew_migame_freq_kick(sew_migame_agg_level, sew_migame_agg_seq);
}

/* ---- public engine API (mi_game.h) ---- */

void sew_migame_load_reset_cpu(int cpu)
{
	struct sew_migame_pcpu_state *st = per_cpu_ptr(&sew_migame_pcpu, cpu);
	unsigned long flags;

	/* Matches recovered game_load_reset: per-CPU 80-byte zeroing (the
	 * two u64 history arrays). The index/state/lock live outside the
	 * zeroed region: index+state reset explicitly, lock untouched. */
	spin_lock_irqsave(&st->lock, flags);
	memset(&st->load, 0, sizeof(st->load));
	st->hist_idx = 0;
	st->last_update = 0;
	st->state = MIGAME_LOAD_LVL_IDLE;
	st->acc = 0;
	spin_unlock_irqrestore(&st->lock, flags);
}

void sew_migame_load_reset_all(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		sew_migame_load_reset_cpu(cpu);
	sew_migame_agg_level = MIGAME_LOAD_LVL_IDLE;
	sew_migame_agg_seq++;
}

void sew_migame_load_history_update(int cpu, u64 delta)
{
	struct sew_migame_pcpu_state *st = per_cpu_ptr(&sew_migame_pcpu, cpu);
	unsigned long flags;
	u64 idx;

	/* DIVERGENCE NOTE (history rule): official per-entry update rule
	 * is unrecovered beyond "80-byte stride array keeps history, delta
	 * computed, state machine via jump table". Ring-store + latest-
	 * delta level mapping preserves the documented shape. */
	spin_lock_irqsave(&st->lock, flags);
	idx = st->hist_idx % SEW_MIGAME_LOAD_HIST_NR;
	st->load.hist_time[idx] = sched_clock();
	st->load.hist_load[idx] = delta;
	st->hist_idx++;
	st->last_update = sched_clock();
	st->state = sew_migame_level_for_delta(delta);
	spin_unlock_irqrestore(&st->lock, flags);

	irq_work_queue(&sew_migame_load_irqwork);
}

u32 sew_migame_load_level_cpu(int cpu)
{
	struct sew_migame_pcpu_state *st = per_cpu_ptr(&sew_migame_pcpu, cpu);
	unsigned long flags;
	u32 lvl;

	spin_lock_irqsave(&st->lock, flags);
	lvl = st->state;
	spin_unlock_irqrestore(&st->lock, flags);
	return lvl;
}

void sew_migame_pkg_load_update(struct task_struct *p, u32 event, u32 flag,
			      u64 wallclock, u64 arg5)
{
	struct sew_migame_pcpu_state *st;
	unsigned long flags;
	u64 delta, now;
	int cpu;

	/* G4 recovered signature; wallclock nominal (use sched_clock()).
	 * event/flag/arg5 pass through opaquely (units unrecovered). */
	(void)wallclock;
	(void)event;
	(void)flag;
	if (!p)
		return;
	if (!sew_migame_get_enable() || sew_migame_glk_disabled())
		return;

	cpu = raw_smp_processor_id();
	if (!cpu_possible(cpu))
		return;
	st = per_cpu_ptr(&sew_migame_pcpu, cpu);

	/* DIVERGENCE NOTE (delta): official delta source mixes
	 * sched_clock()-last_update_time with the walt fixed-point arg5.
	 * Port: accumulate opaque arg5, fold with the local clock delta,
	 * keep the max so neither source can starve the other. */
	now = sched_clock();
	spin_lock_irqsave(&st->lock, flags);
	st->acc += arg5;
	delta = (now >= st->last_update) ?
		(now - st->last_update) : 0;
	if (st->acc > delta)
		delta = st->acc;
	st->acc = 0;
	spin_unlock_irqrestore(&st->lock, flags);

	sew_migame_load_history_update(cpu, delta);
}

/* ravg window (slot16): WALT window has no 5.15 meaning; report 0 so
 * consumers take the PELT path (STAGE3 defines the real window mapping).
 * DIVERGENCE NOTE: official game_get_ravg_window body unrecovered; 0 is
 * the behaviour-neutral value (no consumer can act on an unknown window).
 * Gate: when the feature is off, leave the caller's value untouched so
 * the disabled state is truly zero-behaviour (matches the wrapper's
 * no-provider path, which never writes). */
void sew_migame_ravg_window_get(u64 *old_ravg_window)
{
	if (!sew_migame_get_enable())
		return;
	if (old_ravg_window)
		*old_ravg_window = 0;
}

/* scheduler_tick input: throttle to one sample per CPU per ~8ms so the
 * tick path (100-1000 Hz) cannot irq_work-storm. Uses sched_clock deltas
 * against the per-CPU last_update already maintained by history_update.
 */
void sew_migame_scheduler_tick_account(struct rq *rq)
{
	struct sew_migame_pcpu_state *st;
	unsigned long flags;
	u64 now, last;
	int cpu;

	(void)rq;
	if (!sew_migame_get_enable() || sew_migame_glk_disabled())
		return;
	cpu = raw_smp_processor_id();
	if (!cpu_possible(cpu))
		return;
	st = per_cpu_ptr(&sew_migame_pcpu, cpu);
	spin_lock_irqsave(&st->lock, flags);
	last = st->last_update;
	spin_unlock_irqrestore(&st->lock, flags);
	now = sched_clock();
	if (now - last < 8000000ULL)
		return;
	sew_migame_load_history_update(cpu, now - last);
}

/* ---- policy online/offline listener ----
 * DIVERGENCE NOTE (official hook): official update_policy_online also
 * touched core_ctl (no 5.15 equivalent; C5 decision = decouple). The
 * portable equivalent is a cpufreq policy notifier that resets the
 * per-CPU state of coming/going CPUs so stale history can never drive
 * freq requests on the wrong policy. Registered in init, unregistered
 * in exit (self-check: notifier refcount balanced).
 */
static int sew_migame_policy_nb_fn(struct notifier_block *nb,
			       unsigned long action, void *data)
{
	struct cpufreq_policy *policy = data;

	(void)nb;
	if (!policy)
		return NOTIFY_OK;
	switch (action) {
	case CPUFREQ_CREATE_POLICY:
	case CPUFREQ_REMOVE_POLICY:
		sew_migame_load_reset_cpu(policy->cpu);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block sew_migame_policy_nb = {
	.notifier_call = sew_migame_policy_nb_fn,
};

int sew_migame_load_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct sew_migame_pcpu_state *st = per_cpu_ptr(&sew_migame_pcpu, cpu);

		spin_lock_init(&st->lock);
	}
	sew_migame_load_reset_all();
	init_irq_work(&sew_migame_load_irqwork, sew_migame_load_irqwork_fn);
	INIT_WORK(&sew_migame_load_work, sew_migame_load_work_fn);
	sew_migame_load_work_init = true;
	return cpufreq_register_notifier(&sew_migame_policy_nb,
					 CPUFREQ_POLICY_NOTIFIER);
}

void sew_migame_load_exit(void)
{
	cpufreq_unregister_notifier(&sew_migame_policy_nb,
				    CPUFREQ_POLICY_NOTIFIER);
	sew_migame_load_work_init = false;
	/* irq_work first: it can re-queue load_work, so draining the work
	 * first would leave a re-queued instance behind. */
	irq_work_sync(&sew_migame_load_irqwork);
	cancel_work_sync(&sew_migame_load_work);
	sew_migame_freq_clear();
	sew_migame_load_reset_all();
}
