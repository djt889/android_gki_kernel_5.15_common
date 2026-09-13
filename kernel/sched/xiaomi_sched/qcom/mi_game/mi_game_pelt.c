// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/mi_game_pelt.c - PELT signal provider
 *
 * H1a-MIGAME-S3 stage 3: PELT-side load signals for the FLT engine.
 * Replaces the WALT ravg reads the official (dada 6.6) build used with
 * in-tree 5.15 equivalents (no WALT dependency).
 *
 * DIVERGENCE NOTE (task demand source, D1): official used WALT ravg
 * (walt_update_task_ravg fixed-window accumulation, burst smoothing).
 * Port reads READ_ONCE(p->se.avg.util_avg) — struct sched_avg is public
 * in include/linux/sched.h. PELT snapshots are noisier than ravg; the
 * FLT engine compensates with the flt_up/down_thresh_margin params.
 * task_util()/task_util_est() are NOT used: neither is exported to
 * modules on 5.15 (fair.c exports only sched trace helpers); the direct
 * util_avg read is the only in-tree-feasible path.
 * DIVERGENCE NOTE (cpu aggregate, D2): official read the WALT rq
 * aggregate; rq->cfs.avg.util_avg lives in private kernel/sched/sched.h
 * and cpu_curr/cpu_util() are unavailable to modules, so no true
 * whole-CPU aggregate is readable. sew_migame_pelt_cpu_util() therefore
 * returns 0 (documented conservative default); whole-CPU decisions flow
 * through the FLT ring (flt.c) which aggregates frame samples itself.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched/topology.h>

#include "mi_game.h"

/* uclamp_eff_value is EXPORT_SYMBOL_GPL from kernel/sched/core.c but
 * only declared in the private kernel/sched/sched.h; redeclare locally
 * (the enum uclamp_id itself is public in include/linux/sched.h). */
extern unsigned long uclamp_eff_value(struct task_struct *p,
				      enum uclamp_id clamp_id);

/* PELT half-life window: util_avg decays with ~32ms half-life on 5.15. */
#define SEW_MIGAME_PELT_WINDOW_MS	32

unsigned long sew_migame_pelt_task_demand(struct task_struct *p)
{
	unsigned long util;

	if (!p)
		return 0;
	/* DIVERGENCE D1: single advisory snapshot, no rq lock. */
	util = READ_ONCE(p->se.avg.util_avg);
	if (util > SCHED_CAPACITY_SCALE)
		util = SCHED_CAPACITY_SCALE;
	return util;
}

unsigned long sew_migame_pelt_cpu_util(int cpu)
{
	struct task_struct *p;
	unsigned long util;

	/* DIVERGENCE D2: conservative default 0 (see file header).
	 * The cpu parameter is still validated so callers get a defined
	 * value for any input. */
	if (!cpu_possible(cpu))
		return 0;
	p = current;
	util = (task_cpu(p) == cpu) ? sew_migame_pelt_task_demand(p) : 0;
	return util;
}

unsigned int sew_migame_pelt_window_ms(void)
{
	return SEW_MIGAME_PELT_WINDOW_MS;
}

u64 sew_migame_pelt_now(void)
{
	return sched_clock();
}

unsigned long sew_migame_cpu_capacity(unsigned int cpu)
{
	return arch_scale_cpu_capacity(cpu);
}
