// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/mi_game_freq.c - freq_qos layer
 *
 * G3R-MIGAME-S2 stage 2: freq_qos wrapper replacing the official mist
 * exit (mist_perf_api_enable / mist_set_next_freq_hook /
 * mist_update_ddr_freq have no 5.15 equivalent; C5 decision = rewrite
 * the outlet onto in-tree freq_qos).
 *
 * Design:
 * - per-policy struct freq_qos_request MIN/MAX pair, added on
 *   CPUFREQ_CREATE_POLICY, removed on CPUFREQ_REMOVE_POLICY.
 * - freq_qos_* may sleep -> all updates run from a dedicated
 *   process-context workqueue, never from irq_work/hrtimer/RVH.
 * - slot17 (sew_migame_set_next_freq) only records the latest request and
 *   kicks the worker (9553 = slot17 path, 9554 = game_load path).
 */

#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pm_qos.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "mi_game.h"

#define SEW_MIGAME_FREQ_REQ_MIN	9553
#define SEW_MIGAME_FREQ_REQ_MAX	9554

struct sew_migame_freq_req {
	struct freq_qos_request min_req;
	struct freq_qos_request max_req;
	struct cpufreq_policy *policy;
	bool active;
	struct list_head node;
};

static LIST_HEAD(sew_migame_freq_list);
static DEFINE_MUTEX(sew_migame_freq_lock);
static struct workqueue_struct *sew_migame_freq_wq;
static struct work_struct sew_migame_freq_work;

/* Latest requested level + source; written under lock by both kick
 * paths, consumed by the worker. */
static u32 sew_migame_want_level;
static u32 sew_migame_want_seq;
static bool sew_migame_want_valid;

/* DIVERGENCE NOTE (mapping): official glk_minfreq_break /
 * glk_maxfreq_break tables are unrecovered. Mapping is conservative:
 * IDLE/LOW clear constraints; MID applies per-policy glk_minfreq floor
 * only; HIGH/BOOST apply floor + ceiling. glk_minfreq/maxfreq arrays
 * (kHz, per-policy index) come from the existing module params via the
 * sew_migame_glk_* accessors; out-of-range entries clamp to
 * policy->min/policy->max.
 */
static void sew_migame_freq_apply_one(struct sew_migame_freq_req *fr, u32 level)
{
	struct cpufreq_policy *policy = fr->policy;
	s32 qmin = FREQ_QOS_MIN_DEFAULT_VALUE;
	s32 qmax = FREQ_QOS_MAX_DEFAULT_VALUE;
	unsigned int fmin, fmax;

	if (!policy)
		return;
	fmin = sew_migame_glk_minfreq_khz(policy->cpu);
	fmax = sew_migame_glk_maxfreq_khz(policy->cpu);
	if (fmin > (unsigned int)policy->max)
		fmin = policy->max;
	if (fmax > (unsigned int)policy->max || !fmax)
		fmax = policy->max;
	if (fmin < (unsigned int)policy->min)
		fmin = policy->min;
	if (fmax < (unsigned int)policy->min)
		fmax = policy->min;

	switch (level) {
	case MIGAME_LOAD_LVL_HIGH:
	case MIGAME_LOAD_LVL_BOOST:
		qmin = (s32)fmin;
		qmax = (s32)fmax;
		break;
	case MIGAME_LOAD_LVL_MID:
		qmin = (s32)fmin;
		break;
	default:
		break;
	}
	freq_qos_update_request(&fr->min_req, qmin);
	freq_qos_update_request(&fr->max_req, qmax);
}

static void sew_migame_freq_work_fn(struct work_struct *work)
{
	struct sew_migame_freq_req *fr;
	u32 level;
	bool valid;

	(void)work;
	mutex_lock(&sew_migame_freq_lock);
	level = sew_migame_want_level;
	valid = sew_migame_want_valid;
	mutex_unlock(&sew_migame_freq_lock);

	if (!valid)
		return;
	/* Disabled snapshot at apply time: never pin freq after off. */
	if (!sew_migame_get_enable() || sew_migame_glk_disabled() ||
	    !sew_migame_glk_fbreak_enabled()) {
		sew_migame_freq_clear();
		return;
	}
	mutex_lock(&sew_migame_freq_lock);
	list_for_each_entry(fr, &sew_migame_freq_list, node) {
		if (fr->active)
			sew_migame_freq_apply_one(fr, level);
	}
	mutex_unlock(&sew_migame_freq_lock);
}

static void sew_migame_freq_kick_locked(u32 level)
{
	sew_migame_want_level = level;
	sew_migame_want_valid = true;
	sew_migame_want_seq++;
	if (sew_migame_freq_wq)
		queue_work(sew_migame_freq_wq, &sew_migame_freq_work);
}

/* game_load path (called from process-context worker in mi_game_load.c;
 * u32-safe to also call from plain process context). */
void sew_migame_freq_kick(u32 level, u32 seq)
{
	(void)seq;
	mutex_lock(&sew_migame_freq_lock);
	sew_migame_freq_kick_locked(level);
	mutex_unlock(&sew_migame_freq_lock);
}

/* Slot17 path: a1 = level hint (opaque official units), a2 = on/off.
 * DIVERGENCE NOTE (slot17 args): the 8-word official payload is
 * unrecovered; the conservative reading is (level, enable, ...).
 * Unknown words are ignored; enable==0 clears. Out-of-range levels
 * clamp to the nearest known level (never boost on garbage).
 */
/* Process context only: takes sew_migame_freq_lock (mutex) and may sleep in
 * freq_qos via sew_migame_freq_clear. Callers: plat slot17 provider
 * (sew_migame_slot17_freq) and the game_load work path; never call from
 * atomic/irq context. */
void sew_migame_set_next_freq(unsigned long a1, unsigned long a2,
			  unsigned long a3, unsigned long a4,
			  unsigned long a5, unsigned long a6,
			  unsigned long a7, unsigned long a8)
{
	u32 level;

	(void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8;
	mutex_lock(&sew_migame_freq_lock);
	if (!sew_migame_get_enable() || sew_migame_glk_disabled() ||
	    !sew_migame_glk_fbreak_enabled() || a2 == 0) {
		sew_migame_want_valid = false;
		mutex_unlock(&sew_migame_freq_lock);
		sew_migame_freq_clear();
		return;
	}
	if (a1 >= MIGAME_LOAD_LVL_BOOST)
		level = MIGAME_LOAD_LVL_BOOST;
	else if (a1 >= MIGAME_LOAD_LVL_HIGH)
		level = MIGAME_LOAD_LVL_HIGH;
	else if (a1 >= MIGAME_LOAD_LVL_MID)
		level = MIGAME_LOAD_LVL_MID;
	else if (a1 >= MIGAME_LOAD_LVL_LOW)
		level = MIGAME_LOAD_LVL_LOW;
	else
		level = MIGAME_LOAD_LVL_IDLE;
	sew_migame_freq_kick_locked(level);
	mutex_unlock(&sew_migame_freq_lock);
}

/* Release every outstanding constraint (process context only). The
 * requests stay added (policy lifetime owns add/remove); values return
 * to DEFAULT so other QoS voters are unaffected. */
void sew_migame_freq_clear(void)
{
	struct sew_migame_freq_req *fr;

	if (!sew_migame_freq_wq)
		return;
	mutex_lock(&sew_migame_freq_lock);
	sew_migame_want_valid = false;
	list_for_each_entry(fr, &sew_migame_freq_list, node) {
		if (fr->active) {
			freq_qos_update_request(&fr->min_req,
						FREQ_QOS_MIN_DEFAULT_VALUE);
			freq_qos_update_request(&fr->max_req,
						FREQ_QOS_MAX_DEFAULT_VALUE);
		}
	}
	mutex_unlock(&sew_migame_freq_lock);
}

static struct sew_migame_freq_req *sew_migame_freq_find(struct cpufreq_policy *p)
{
	struct sew_migame_freq_req *fr;

	list_for_each_entry(fr, &sew_migame_freq_list, node) {
		if (fr->policy == p)
			return fr;
	}
	return NULL;
}

static int sew_migame_freq_add_policy(struct cpufreq_policy *policy)
{
	struct sew_migame_freq_req *fr;
	int ret;

	mutex_lock(&sew_migame_freq_lock);
	if (sew_migame_freq_find(policy)) {
		mutex_unlock(&sew_migame_freq_lock);
		return 0;
	}
	mutex_unlock(&sew_migame_freq_lock);

	fr = kzalloc(sizeof(*fr), GFP_KERNEL);
	if (!fr)
		return -ENOMEM;
	fr->policy = policy;
	ret = freq_qos_add_request(&policy->constraints, &fr->min_req,
				   FREQ_QOS_MIN, FREQ_QOS_MIN_DEFAULT_VALUE);
	if (ret) {
		kfree(fr);
		return ret;
	}
	ret = freq_qos_add_request(&policy->constraints, &fr->max_req,
				   FREQ_QOS_MAX, FREQ_QOS_MAX_DEFAULT_VALUE);
	if (ret) {
		freq_qos_remove_request(&fr->min_req);
		kfree(fr);
		return ret;
	}
	mutex_lock(&sew_migame_freq_lock);
	fr->active = true;
	list_add(&fr->node, &sew_migame_freq_list);
	mutex_unlock(&sew_migame_freq_lock);
	return 0;
}

static void sew_migame_freq_del_policy(struct cpufreq_policy *policy)
{
	struct sew_migame_freq_req *fr;

	mutex_lock(&sew_migame_freq_lock);
	fr = sew_migame_freq_find(policy);
	if (fr)
		list_del(&fr->node);
	mutex_unlock(&sew_migame_freq_lock);
	if (!fr)
		return;
	fr->active = false;
	freq_qos_remove_request(&fr->max_req);
	freq_qos_remove_request(&fr->min_req);
	kfree(fr);
}

static int sew_migame_freq_nb_fn(struct notifier_block *nb,
			     unsigned long action, void *data)
{
	struct cpufreq_policy *policy = data;

	(void)nb;
	if (!policy)
		return NOTIFY_OK;
	switch (action) {
	case CPUFREQ_CREATE_POLICY:
		/* Best effort: a failed add leaves the policy unconstrained
		 * (conservative), never fails the policy itself. */
		sew_migame_freq_add_policy(policy);
		break;
	case CPUFREQ_REMOVE_POLICY:
		sew_migame_freq_del_policy(policy);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block sew_migame_freq_nb = {
	.notifier_call = sew_migame_freq_nb_fn,
};

int sew_migame_freq_init(void)
{
	sew_migame_freq_wq = alloc_workqueue("sew_migame_freq_wq",
					 WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!sew_migame_freq_wq)
		return -ENOMEM;
	INIT_WORK(&sew_migame_freq_work, sew_migame_freq_work_fn);
	mutex_lock(&sew_migame_freq_lock);
	sew_migame_want_valid = false;
	sew_migame_want_level = MIGAME_LOAD_LVL_IDLE;
	mutex_unlock(&sew_migame_freq_lock);
	return cpufreq_register_notifier(&sew_migame_freq_nb,
					 CPUFREQ_POLICY_NOTIFIER);
}

void sew_migame_freq_exit(void)
{
	struct sew_migame_freq_req *fr, *tmp;

	cpufreq_unregister_notifier(&sew_migame_freq_nb, CPUFREQ_POLICY_NOTIFIER);
	if (sew_migame_freq_wq) {
		cancel_work_sync(&sew_migame_freq_work);
		destroy_workqueue(sew_migame_freq_wq);
		sew_migame_freq_wq = NULL;
	}
	/* Self-check: every added request is removed exactly once here
	 * (policy notifier only removes on REMOVE_POLICY, which may never
	 * fire before rmmod; this drain guarantees no freq_qos leak). */
	mutex_lock(&sew_migame_freq_lock);
	list_for_each_entry_safe(fr, tmp, &sew_migame_freq_list, node) {
		list_del(&fr->node);
		mutex_unlock(&sew_migame_freq_lock);
		fr->active = false;
		freq_qos_remove_request(&fr->max_req);
		freq_qos_remove_request(&fr->min_req);
		kfree(fr);
		mutex_lock(&sew_migame_freq_lock);
	}
	sew_migame_want_valid = false;
	mutex_unlock(&sew_migame_freq_lock);
}
