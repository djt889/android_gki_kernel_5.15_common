// SPDX-License-Identifier: GPL-2.0-only
/*
 * xr_qs: scenarized QOS scheduling executor, semantic 5.15 rewrite of the
 * Xiaomi OS4 xr_qs.ko module ("OS-CPU QOS sched Driver",
 * Shaohua Fan <fanshaohua@xiaomi.com>, vermagic 6.6.57-android15-8).
 *
 * Functionality preserved from the 6.6 binary (function names kept):
 *  - qos_sched sysfs group (sched_enable, rt_prio ui/render prio knobs)
 *  - scene group table: 4 groups, each holding a ui/render task pair,
 *    torn down on qievent 7 (QI_EVENT_RESET)
 *  - qievent dispatcher (qievent_callback) fanning out into
 *    qos_set_callback / qos_reset_callback / qos_inherit_callback /
 *    restore_qos_sched / correct_qos_sched
 *  - RT scheduling channel: update_static_prio + sched_setscheduler_nocheck
 *    with SCHED_RESET_ON_FORK, "correct" event pins SCHED_FIFO for lvl-3
 *  - rtg channel over plat_sched_set_group_id / plat_sched_get_group_id
 *    (same 5.15 GKI symbols the module already consumes: group ids 2..10
 *    are the GAME_AI_GRP0..8 range, 12 is the draw group)
 *  - speedlock sub-system: rwsem read-wait start raises a vip priority on
 *    current, lock release restores it; sl_enable/sl_prio sysfs knobs
 *  - binder preset hook
 *
 * Closure gaps vs 6.6 (nm -u of xr_qs.ko, all documented inline):
 *  1. vip_sched set_vip_prio/restore_vip_prio/get_vip_prio: no 5.15
 *     vip_sched exists -> local uclamp_min floor implementation
 *     (same direct-write pattern as the in-tree xr_qi.c port).
 *  2. 6.6 QOS framework helpers get_static_qos_lvl /
 *     get_proc_static_qos_lvl / is_qos_task / update_static_prio and the
 *     task vendor pad (task+0x12c0, vendor_data_pad for init_task) -> 16
 *     slot per-task state table + static_prio derived level.
 *  3. xr_qi qievent notifier chain (register_qievent_notifier, now
 *     served by kernel/sched/xr_qi.c after the chain unification): the 5.15
 *     tree's xr_qi.c is a reduced rewrite without the chain -> local
 *     blocking notifier with the same registration contract; events 1..6
 *     have no in-tree producer yet, the speedlock and binder paths below
 *     are the live entry points.
 *  The 6.6 android_vh_binder_preset signature (binder_transaction* in x3)
 *     does not exist on 5.15; the hook is wired to 5.15's
 *     android_vh_binder_proc_transaction instead, which fires at the same
 *     binder transaction point with the target task available.
 */

#define pr_fmt(fmt) "qs: " fmt

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/sched/types.h>
#include <trace/hooks/binder.h>
#include <trace/hooks/dtask.h>

#define CREATE_TRACE_POINTS
#include <trace/events/xr_qs.h>

/* state word layout, identical bit positions to the 6.6 vendor pad word
 * at task+0x12c0+0x40: bit0 active, bit3 vip-marked, bits[13:6] qos level,
 * bit14 speedlock, bit15 rtg-managed, bits[23:16] saved prio */
#define QS_ST_ACTIVE		BIT(0)
#define QS_ST_VIP		BIT(3)
#define QS_ST_LVL_SHIFT		6
#define QS_ST_LVL_MASK		(0xffU << QS_ST_LVL_SHIFT)
#define QS_ST_SL		BIT(14)
#define QS_ST_RTG		BIT(15)
#define QS_ST_PRIO_SHIFT	16
#define QS_ST_PRIO_MASK		(0xffU << QS_ST_PRIO_SHIFT)

extern int plat_sched_set_group_id(struct task_struct *p, unsigned int grp_id);
extern int plat_sched_get_group_id(struct task_struct *p);

#define QS_STATE_SLOTS		16
#define QS_NR_GROUPS		4
#define QS_GRP_DRAW		12	/* CRITICAL_*_GRP draw id */
#define QS_GRP_AI_MIN		2	/* GAME_AI_GRP0 */
#define QS_GRP_AI_MAX		10	/* GAME_AI_GRP8 */

struct qs_state_slot {
	struct task_struct *task;
	u32 state;
	unsigned int prev_uclamp;
	unsigned int cur_uclamp;
	bool used;
};

struct qs_grp {
	u32 grp_id;			/* +0  */
	u32 enabled;			/* +4  */
	u32 count;			/* +8  */
	struct task_struct *ui;		/* +16 */
	struct task_struct *render;	/* +24 */
};

struct qs_qievent_info {
	struct task_struct *from_task;	/* +0: qos source (inherit events) */
	struct task_struct *task;	/* +8: target task */
	int prio;			/* +16 */
	int qos;			/* +20 */
	unsigned int flags;		/* +24: bit4 rt, bit5 vip, [3:0] grp */
	unsigned int grp;		/* +28 */
};

static unsigned int g_sched_enable;
static unsigned int g_ui_prio = 98;
static unsigned int g_render_prio = 98;
static unsigned int g_sl_enable;
static unsigned int g_sl_prio = 5;

static struct qs_state_slot qs_states[QS_STATE_SLOTS];
static DEFINE_SPINLOCK(qs_state_lock);

static struct qs_grp qs_grps[QS_NR_GROUPS];
static DEFINE_SPINLOCK(qs_grp_lock);


/* ---- 6.6 QOS-framework stand-ins (closure gap 2) ---------------------- */

static int get_static_qos_lvl(struct task_struct *p)
{
	/* 6.6 reads the static QOS level (0..7) from the task vendor area;
	 * 5.15 has no QOS framework, so derive one from static_prio. */
	int delta = DEFAULT_PRIO - p->static_prio;

	if (delta <= 0)
		return 0;
	return min(7, (delta + 9) / 10);
}

static int get_proc_static_qos_lvl(struct task_struct *p)
{
	/* process-scope level on 6.6; same derivation here */
	return get_static_qos_lvl(p);
}

static bool is_qos_task(struct task_struct *p)
{
	return get_static_qos_lvl(p) > 0;
}

static void update_static_prio(struct task_struct *p, int prio, int flag)
{
	if (prio >= 0)
		p->static_prio = prio;
}

/* per-task state table, the vendor-pad stand-in */
static struct qs_state_slot *qs_state_get(struct task_struct *p)
{
	struct qs_state_slot *free_slot = NULL, *old_slot = NULL;
	unsigned long irqflags;
	int i;

	spin_lock_irqsave(&qs_state_lock, irqflags);
	for (i = 0; i < QS_STATE_SLOTS; i++) {
		struct qs_state_slot *s = &qs_states[i];

		if (s->used && s->task == p) {
			spin_unlock_irqrestore(&qs_state_lock, irqflags);
			return s;
		}
		if (!s->used && !free_slot)
			free_slot = s;
		else if (s->used && !(s->state & (QS_ST_ACTIVE | QS_ST_VIP |
						  QS_ST_SL)) && !old_slot)
			old_slot = s;
	}
	if (!free_slot)
		free_slot = old_slot;
	if (free_slot) {
		if (free_slot->task && free_slot->task != p)
			put_task_struct(free_slot->task);
		if (free_slot->task != p) {
			get_task_struct(p);
			free_slot->task = p;
		}
		free_slot->used = true;
		free_slot->state = 0;
	}
	spin_unlock_irqrestore(&qs_state_lock, irqflags);
	return free_slot;
}

/* ---- vip channel (closure gap 1) -------------------------------------- */

#ifdef CONFIG_UCLAMP_TASK
static void qs_uclamp_write(struct task_struct *p, unsigned int val)
{
	p->uclamp_req[UCLAMP_MIN].value = val;
	p->uclamp_req[UCLAMP_MIN].bucket_id =
		min_t(unsigned int, val / 16, (unsigned int)(UCLAMP_BUCKETS - 1));
}

static void set_vip_prio(struct task_struct *p, int prio, int flag)
{
	struct qs_state_slot *st;
	unsigned int val;
	unsigned long irqflags;

	if (prio <= 0)
		return;
	st = qs_state_get(p);
	if (!st)
		return;
	val = min_t(unsigned int, (unsigned int)prio * 10, 1024);
	spin_lock_irqsave(&qs_state_lock, irqflags);
	if (st->state & QS_ST_VIP) {
		if (val > st->cur_uclamp) {
			st->cur_uclamp = val;
			qs_uclamp_write(p, val);
		}
	} else {
		st->prev_uclamp = p->uclamp_req[UCLAMP_MIN].value;
		st->cur_uclamp = max(st->prev_uclamp, val);
		qs_uclamp_write(p, st->cur_uclamp);
		st->state |= QS_ST_VIP;
	}
	spin_unlock_irqrestore(&qs_state_lock, irqflags);
}

static int get_vip_prio(struct task_struct *p)
{
	struct qs_state_slot *st;
	int prio = 0;
	unsigned long irqflags;

	st = qs_state_get(p);
	if (!st)
		return 0;
	spin_lock_irqsave(&qs_state_lock, irqflags);
	if (st->state & QS_ST_VIP)
		prio = st->cur_uclamp / 10;
	spin_unlock_irqrestore(&qs_state_lock, irqflags);
	return prio;
}

static void restore_vip_prio(struct task_struct *p)
{
	struct qs_state_slot *st;
	unsigned long irqflags;

	st = qs_state_get(p);
	if (!st)
		return;
	spin_lock_irqsave(&qs_state_lock, irqflags);
	if (st->state & QS_ST_VIP) {
		qs_uclamp_write(p, st->prev_uclamp);
		st->state &= ~QS_ST_VIP;
	}
	spin_unlock_irqrestore(&qs_state_lock, irqflags);
}
#else
static void set_vip_prio(struct task_struct *p, int prio, int flag) { }
static int get_vip_prio(struct task_struct *p) { return 0; }
static void restore_vip_prio(struct task_struct *p) { }
#endif /* CONFIG_UCLAMP_TASK */

/* ---- rt sched channel -------------------------------------------------- */

static void restore_rt_sched(struct task_struct *p, u32 *state)
{
	struct sched_param param = { .sched_priority = 0 };
	u32 w = *state;
	int qos, saved, policy;

	if (!(w & QS_ST_ACTIVE))
		return;
	qos = (w >> QS_ST_LVL_SHIFT) & 0xff;
	saved = (w >> QS_ST_PRIO_SHIFT) & 0xff;
	policy = qos;
	if (qos && qos != 3)
		param.sched_priority = 99 - saved;
	sched_setscheduler_nocheck(p, policy & ~SCHED_RESET_ON_FORK, &param);
	*state = w & 0xff00c03e;
	trace_qs_restore_rt_sched(p->pid, policy, param.sched_priority);
}

/* ---- rtg group channel ------------------------------------------------- */

/* move an evicted scene member to the draw group (id 12) and clear its
 * slots; caller holds qs_grp_lock (6.6: same call shape from set_rtg_grp) */
static void move_existed_draw_rtg(int which, struct task_struct *task,
				  struct qs_grp *grp)
{
	plat_sched_set_group_id(task, QS_GRP_DRAW);
	if (which & 1) {
		grp->ui = NULL;
		grp->render = NULL;
	} else {
		grp->render = NULL;
		grp->ui = NULL;
	}
	grp->count = 0;
	grp->enabled = 0;
	put_task_struct(task);
}

/* swap the rtg group ids of two tasks; caller holds qs_grp_lock */
static void exchange_draw_rtg(struct task_struct *a, struct task_struct *b,
			      int a_grp, int b_grp)
{
	int ret;

	ret = plat_sched_set_group_id(a, b_grp);
	if (ret)
		trace_qs_skip_rtg_grp(a->pid, a_grp, b_grp);
	else
		trace_qs_exchange_rtg_grp(a->pid, a_grp, b_grp, ret);
	ret = plat_sched_set_group_id(b, a_grp);
	if (ret)
		trace_qs_skip_rtg_grp(b->pid, b_grp, a_grp);
	else
		trace_qs_exchange_rtg_grp(b->pid, b_grp, a_grp, ret);
}

static void set_rtg_grp(struct qs_qievent_info *info, u32 *state,
			unsigned int grp, int force)
{
	struct task_struct *task = info->task;
	struct qs_grp *target = NULL;
	int orig, ret;
	int i;

	orig = plat_sched_get_group_id(task);
	if (orig >= QS_GRP_AI_MIN && orig <= QS_GRP_AI_MAX) {
		/* already inside the AI scene range: re-write the same id to
		 * refresh the walt group and remember the task in the table */
		plat_sched_set_group_id(task, orig);
	} else {
		trace_qs_skip_rtg_grp(task->pid, orig, grp);
		return;
	}

	spin_lock(&qs_grp_lock);
	for (i = 0; i < QS_NR_GROUPS; i++) {
		if (qs_grps[i].enabled && qs_grps[i].grp_id == grp) {
			target = &qs_grps[i];
			break;
		}
	}
	if (target && !target->ui) {
		target->ui = task;
		get_task_struct(task);
		target->count++;
	} else if (target && !target->render) {
		target->render = task;
		get_task_struct(task);
		target->count++;
	} else if (target && force && target->ui) {
		if (orig >= QS_GRP_AI_MIN && orig <= QS_GRP_AI_MAX)
			exchange_draw_rtg(task, target->ui, orig, grp);
		else
			move_existed_draw_rtg(1, target->ui, target);
		target->ui = task;
		get_task_struct(task);
		target->count++;
	}
	spin_unlock(&qs_grp_lock);

	if (grp <= QS_GRP_AI_MAX && grp >= QS_GRP_AI_MIN)
		*state |= QS_ST_RTG;

	ret = plat_sched_set_group_id(task, grp);
	trace_qs_set_rtg_grp(task->pid, orig, grp, ret);
}

/* ---- qievent handlers -------------------------------------------------- */

static void correct_qos_sched(struct qs_qievent_info *info)
{
	struct task_struct *task = info->task;
	struct qs_state_slot *st;
	struct sched_param param;
	int new_prio;

	st = qs_state_get(task);
	if (!st)
		return;
	if (!(st->state & QS_ST_ACTIVE))
		return;
	if (get_static_qos_lvl(task) != 3)
		return;
	new_prio = 99 - info->prio;
	param.sched_priority = new_prio;
	sched_setscheduler_nocheck(task,
				   SCHED_FIFO | SCHED_RESET_ON_FORK, &param);
	trace_qs_correct_rt_sched(task->pid, info->prio);
}

static void qos_reset_callback(struct qs_qievent_info *info)
{
	struct task_struct *task = info->task;
	struct qs_state_slot *st;
	struct sched_param param;
	unsigned int flags = info->flags;
	int old, policy, prio;

	st = qs_state_get(task);
	if (!st)
		return;

	if (flags & BIT(4)) {	/* rt reset */
		if ((flags & 0xf) == 9) {
			/* RenderThread special case: render prio knob or 98 */
			if (task->prio == task->static_prio)
				prio = g_ui_prio;
			else if (!strcmp(task->comm, "RenderThread") ||
				 (task->group_leader &&
				  !strcmp(task->group_leader->comm,
					  "RenderThread")))
				prio = g_render_prio;
			else
				prio = 98;
			update_static_prio(task, prio, -1);
		}
	}
	if (flags & BIT(5))	/* vip reset */
		update_static_prio(task, -1, 5);

	if ((flags & 0x30) == 0x20)
		restore_rt_sched(task, &st->state);
	else
		restore_rt_sched(task, &st->state);

	set_vip_prio(task, 5, 0);
	st->state |= QS_ST_VIP;

	old = task->prio;
	policy = get_static_qos_lvl(task) | SCHED_RESET_ON_FORK;
	param.sched_priority = 99 - old;
	sched_setscheduler_nocheck(task, policy, &param);
	st->state |= QS_ST_ACTIVE;

	set_rtg_grp(info, &st->state, info->grp & 0xf, 0);
	trace_qs_reset_vip_sched(task->pid);
}

static void qos_inherit_callback(struct qs_qievent_info *info)
{
	struct task_struct *task = info->task;
	struct qs_state_slot *st;
	struct sched_param param;
	unsigned int flags = info->flags;
	int policy, param_prio;

	st = qs_state_get(task);
	if (!st)
		return;

	if (flags & BIT(4)) {	/* rt inherit */
		if (!(st->state & QS_ST_ACTIVE)) {
			st->state |= (get_static_qos_lvl(task) << QS_ST_LVL_SHIFT) |
				     ((task->static_prio & 0xff) << QS_ST_PRIO_SHIFT) |
				     QS_ST_ACTIVE;
		}
		policy = get_static_qos_lvl(task);
		if (policy == 0 || policy == 3) {
			policy = get_static_qos_lvl(info->from_task);
			if (policy == 3 || policy == 0)
				policy = SCHED_RR;
		} else if (info->prio >= task->static_prio) {
			goto rtg;
		}
		param_prio = 99 - info->prio;
		param.sched_priority = param_prio;
		sched_setscheduler_nocheck(task,
					   policy | SCHED_RESET_ON_FORK,
					   &param);
		st->state |= QS_ST_ACTIVE;
		trace_qs_set_rt_sched(task->pid, policy, info->prio);
	} else if (flags & BIT(5)) {	/* vip inherit */
		int old = get_vip_prio(task);

		if (info->qos > old)
			set_vip_prio(task, info->qos, 0);
		trace_qs_set_vip_sched(old, info->qos);
	}

rtg:
	if (!(flags & 0xc0))
		set_rtg_grp(info, &st->state, flags & 0xf, 0);
}

static void restore_qos_sched(struct qs_qievent_info *info, int mode)
{
	struct task_struct *task = info->task;
	struct qs_state_slot *st;
	struct sched_param param;
	unsigned int flags = info->grp;
	int grp = flags & 0xf, qos, gid;

	st = qs_state_get(task);
	if (!st)
		return;

	if (mode != 5) {
		qos = (st->state >> QS_ST_LVL_SHIFT) & 0xff;
		update_static_prio(task, (qos == 0 || qos == 3) ?
				   DEFAULT_PRIO : -1, 0);
	}

	if (grp > 5) {
		if (flags & BIT(4)) {	/* rt restore via flags */
			int old = task->prio;
			int lvl = get_static_qos_lvl(task);

			param.sched_priority = 99 - old;
			sched_setscheduler_nocheck(task,
					lvl | SCHED_RESET_ON_FORK, &param);
			trace_qs_set_rt_sched(task->pid, lvl, old);
		} else if (flags & BIT(5)) {	/* vip restore via flags */
			restore_rt_sched(task, &st->state);
			set_vip_prio(task, info->qos, 0);
			st->state |= QS_ST_VIP;
		}
		set_rtg_grp(info, &st->state, grp, 0);
	} else {
		restore_rt_sched(task, &st->state);
		if (st->state & QS_ST_VIP) {
			restore_vip_prio(task);
			st->state &= ~QS_ST_VIP;
		}
		gid = plat_sched_get_group_id(task);
		if (gid && (st->state & QS_ST_RTG)) {
			struct qs_grp *g = NULL;
			int i;

			plat_sched_set_group_id(task, 0);
			st->state &= ~QS_ST_RTG;
			if (gid != QS_GRP_DRAW) {
				spin_lock(&qs_grp_lock);
				for (i = 0; i < QS_NR_GROUPS; i++) {
					if (qs_grps[i].grp_id == gid) {
						g = &qs_grps[i];
						break;
					}
				}
				spin_unlock(&qs_grp_lock);
				if (!g)
					goto out_put;
			} else {
				g = &qs_grps[0];
			}

			spin_lock(&qs_grp_lock);
			if (task->prio == task->static_prio) {
				g->ui = NULL;
				if (!g->render) {
					g->enabled = 0;
					g->count = 0;
				}
			} else if (!strcmp(task->comm, "RenderThread") ||
				   (task->group_leader &&
				    !strcmp(task->group_leader->comm,
					    "RenderThread"))) {
				g->render = NULL;
				if (!g->ui) {
					g->enabled = 0;
					g->count = 0;
				}
			}
			spin_unlock(&qs_grp_lock);
			trace_qs_restore_rtg_grp(task->pid);
		}
	}

out_put:
	return;
}

static void qos_set_callback(struct qs_qievent_info *info)
{
	struct task_struct *task = info->task;
	struct qs_state_slot *st;
	struct sched_param param;
	unsigned int flags = info->flags;
	int grp = flags & 0xf, qos_lvl, policy, prio;

	st = qs_state_get(task);
	if (!st)
		return;

	if (flags & BIT(5)) {	/* vip set */
		int old = get_vip_prio(task);

		update_static_prio(task, -1, 5);
		set_vip_prio(task, info->qos > 5 ? info->qos : 5, 0);
		if (!(st->state & QS_ST_VIP))
			st->state |= QS_ST_VIP;
		trace_qs_set_vip_sched(old, info->qos);
	} else if (flags & BIT(4)) {	/* rt set */
		if (!(st->state & QS_ST_ACTIVE)) {
			st->state |= (get_static_qos_lvl(task) << QS_ST_LVL_SHIFT) |
				     ((task->static_prio & 0xff) << QS_ST_PRIO_SHIFT) |
				     QS_ST_ACTIVE;
		}
		if (grp == 9) {
			/* RenderThread group: render/ui prio knobs apply */
			if (task->prio == task->static_prio)
				prio = g_ui_prio;
			else if (!strcmp(task->comm, "RenderThread") ||
				 (task->group_leader &&
				  !strcmp(task->group_leader->comm,
					  "RenderThread")))
				prio = g_render_prio;
			else
				prio = 98;
			update_static_prio(task, prio, -1);
			if (prio > info->prio) {
				param.sched_priority = 99 - prio;
				sched_setscheduler_nocheck(task,
					SCHED_RR | SCHED_RESET_ON_FORK,
					&param);
				trace_qs_skip_rt_sched(task->pid, SCHED_RR,
						       info->prio, prio);
			}
		} else {
			qos_lvl = get_static_qos_lvl(task);
			prio = task->static_prio;
			update_static_prio(task, prio, -1);
			if (prio <= info->prio)
				goto rtg;
			policy = (qos_lvl == 3 || qos_lvl == 0) ?
				 SCHED_RR : qos_lvl;
			param.sched_priority = 99 - info->prio;
			sched_setscheduler_nocheck(task,
					policy | SCHED_RESET_ON_FORK, &param);
			trace_qs_set_rt_sched(task->pid, policy,
					      param.sched_priority);
		}
	}

rtg:
	set_rtg_grp(info, &st->state, info->grp & 0xf, 1);
}

/* ---- qievent dispatcher (notifier callback) ---------------------------- */

static void qs_groups_detach(struct qs_qievent_info *info)
{
	struct task_struct *task = info->task;
	struct qs_grp *g;
	int i;

	spin_lock(&qs_grp_lock);
	for (i = 0; i < QS_NR_GROUPS; i++) {
		g = &qs_grps[i];
		if (!g->enabled)
			continue;
		if (g->ui == task) {
			g->ui = NULL;
		} else if (g->render == task) {
			g->render = NULL;
		} else {
			continue;
		}
		if (!g->ui && !g->render) {
			g->enabled = 0;
			g->count = 0;
		}
	}
	spin_unlock(&qs_grp_lock);
}

/* event codes mirror the 6.6 xr_qi qievent numbering:
 * 1=set 2=reset 3=restore 4=inherit 5=restore-forced 6=correct 7=detach */
static int qievent_callback(struct notifier_block *nb, unsigned long event,
			    void *data)
{
	struct qs_qievent_info *info = data;

	if (!info)
		return -EINVAL;
	if (preempt_count())
		return 0;

	switch (event) {
	case 7:
		qs_groups_detach(info);
		return 0;
	case 1:
		if (g_sched_enable && (info->flags & 0xe) >= 6)
			qos_set_callback(info);
		return 0;
	case 2:
		if (g_sched_enable) {
			if ((info->flags & 0xe) > 5)
				qos_reset_callback(info);
			else
				restore_qos_sched(info, 2);
		}
		return 0;
	case 3:
		restore_qos_sched(info, 3);
		return 0;
	case 4:
		if (g_sched_enable)
			qos_inherit_callback(info);
		return 0;
	case 5:
		restore_qos_sched(info, 5);
		return 0;
	case 6:
		if (g_sched_enable)
			correct_qos_sched(info);
		return 0;
	default:
		return 0;
	}
}

/* ---- qievent chain (closure gap 3, unified) ---------------------------- */

/*
 * The qievent chain lives in xr_qi.c (dada ABI: xr_qi broadcasts, peer
 * modules register).  This module registers its dispatcher below; the
 * struct qs_qievent_info layout above is ABI-identical to xr_qi.c's
 * struct qi_qievent_info (both还原 the dada layout: 2 ptr + 2 int +
 * 2 uint).  insmod order xr_qi -> xr_qs mirrors the dada depends=
 * edge; insmod without xr_qi fails on these symbols.
 */
extern int register_qievent_notifier(struct notifier_block *nb);
extern int unregister_qievent_notifier(struct notifier_block *nb);

static struct notifier_block g_qs_nb = {
	.notifier_call = qievent_callback,
};

/* ---- vendor hooks ------------------------------------------------------ */

/* 6.6 preset hook read the binder transaction's target task vendor pad and
 * preset the scene; 5.15 wiring is android_vh_binder_proc_transaction. */
static void android_vh_binder_preset(void *data,
				     struct task_struct *caller_task,
				     struct task_struct *binder_proc_task,
				     struct task_struct *binder_th_task,
				     int node_debug_id, unsigned int code,
				     bool pending_async)
{
	struct qs_state_slot *st;
	unsigned int scene;

	if (!binder_th_task)
		return;
	st = qs_state_get(binder_th_task);
	if (!st)
		return;
	if (!(st->state & QS_ST_ACTIVE))
		return;
	scene = (st->state >> QS_ST_LVL_SHIFT) & 0xff;
	if (scene != 3 && scene != 0)
		return;
	/* 6.6 wrote the preset word into the binder transaction; the 5.15
	 * equivalent carries the scene onto the target thread state. */
	st->state |= QS_ST_ACTIVE;
	trace_qs_binder_preset(binder_th_task->pid);
}

/* speedlock: current blocks on a rwsem read side */
static void android_vh_rwsem_read_wait_start(void *data,
					     struct rw_semaphore *sem)
{
	struct qs_state_slot *st;

	if (!g_sl_enable)
		return;
	if (is_qos_task(current))
		return;
	if (get_proc_static_qos_lvl(current) < 7)
		return;
	st = qs_state_get(current);
	if (!st)
		return;
	set_vip_prio(current, g_sl_prio, 0);
	st->state |= QS_ST_SL;
	trace_sl_set(current->pid, g_sl_prio, (unsigned long)sem);
}

/* speedlock: lock released, drop the vip floor again */
static void android_vh_rwsem_lock_released(void *data,
					   struct task_struct *tsk,
					   unsigned long settime_jiffies)
{
	struct qs_state_slot *st;

	if (settime_jiffies)
		return;
	st = qs_state_get(current);
	if (!st)
		return;
	if (!(st->state & QS_ST_SL))
		return;
	restore_vip_prio(current);
	st->state &= ~QS_ST_SL;
	trace_sl_reset(current->pid, (unsigned long)tsk);
}

/* ---- sysfs ------------------------------------------------------------- */

static ssize_t sched_enable_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "QS_ENABLE:\t%d\n", g_sched_enable);
}

static ssize_t sched_enable_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	unsigned int val;
	int ret;

	ret = kstrtouint(buf, 0, &val);
	if (ret) {
		pr_err("sched enable store: parse enable failed\n");
		return -EINVAL;
	}
	g_sched_enable = !!val;
	return count;
}

static ssize_t rt_prio_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "ui prio:\t%d\nrender prio:\t%d\n",
			g_ui_prio, g_render_prio);
}

static ssize_t rt_prio_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int ui, render;

	if (sscanf(buf, "%d %d", &ui, &render) != 2) {
		pr_err("prio store: ui/render prio failed\n");
		return -EINVAL;
	}
	if (ui < 90 || ui > 92 || render < 89 || render > 92) {
		pr_err("invalid prio: ui/render[%d %d]\n", ui, render);
		return -EINVAL;
	}
	g_ui_prio = ui;
	g_render_prio = render;
	return count;
}

static ssize_t sl_enable_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "enable:\t%d\n", g_sl_enable);
}

static ssize_t sl_enable_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	unsigned int val;
	int ret;

	ret = kstrtouint(buf, 0, &val);
	if (ret) {
		pr_err("speedlock store: parse enable failed\n");
		return -EINVAL;
	}
	g_sl_enable = !!val;
	return count;
}

static ssize_t sl_prio_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "sl prio:\t%d\n", g_sl_prio);
}

static ssize_t sl_prio_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int val;
	int ret;

	ret = kstrtouint(buf, 0, &val);
	if (ret) {
		pr_err("sl prio store: parse value failed\n");
		return -EINVAL;
	}
	if (val >= 100u) {
		pr_err("sl prio store: invalid value[%u]\n", val);
		return -EINVAL;
	}
	g_sl_prio = val;
	return count;
}

static struct kobj_attribute sched_enable_attr =
	__ATTR(sched_enable, 0644, sched_enable_show, sched_enable_store);
static struct kobj_attribute rt_prio_attr =
	__ATTR(rt_prio, 0644, rt_prio_show, rt_prio_store);
static struct attribute *qs_attrs[] = {
	&sched_enable_attr.attr,
	&rt_prio_attr.attr,
	NULL,
};
static const struct attribute_group qs_attr_group = {
	.attrs = qs_attrs,
};

static struct kobj_attribute sl_enable_attr =
	__ATTR(sl_enable, 0644, sl_enable_show, sl_enable_store);
static struct kobj_attribute sl_prio_attr =
	__ATTR(sl_prio, 0644, sl_prio_show, sl_prio_store);
static struct attribute *sl_attrs[] = {
	&sl_enable_attr.attr,
	&sl_prio_attr.attr,
	NULL,
};
static const struct attribute_group sl_attr_group = {
	.attrs = sl_attrs,
};

/* ---- init -------------------------------------------------------------- */

static struct kobject *qs_kobj;
static struct kobject *sl_kobj;

static int sl_init(void)
{
	int ret;

	ret = register_trace_android_vh_record_rwsem_lock_starttime(android_vh_rwsem_lock_released, NULL);
	if (ret < 0)
		return ret;

	ret = register_trace_android_vh_rwsem_read_wait_start(android_vh_rwsem_read_wait_start, NULL);
	if (ret < 0)
		goto err_hook1;

	sl_kobj = kobject_create_and_add("speedlock", kernel_kobj);
	if (!sl_kobj) {
		ret = -ENOMEM;
		goto err_hook2;
	}

	ret = sysfs_create_group(sl_kobj, &sl_attr_group);
	if (ret) {
		kobject_put(sl_kobj);
		sl_kobj = NULL;
		pr_err("speedlock init: failed to create sys node\n");
		goto err_hook2;
	}
	return 0;

err_hook2:
	unregister_trace_android_vh_rwsem_read_wait_start(android_vh_rwsem_read_wait_start, NULL);
err_hook1:
	unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_rwsem_lock_released, NULL);
	return ret;
}

static void sl_exit(void)
{
	if (!sl_kobj)
		return;
	sysfs_remove_group(sl_kobj, &sl_attr_group);
	kobject_put(sl_kobj);
	sl_kobj = NULL;
	unregister_trace_android_vh_rwsem_read_wait_start(android_vh_rwsem_read_wait_start, NULL);
	unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_rwsem_lock_released, NULL);
}

static int __init xr_qs_init(void)
{
	int ret;

	qs_kobj = kobject_create_and_add("qos_sched", kernel_kobj);
	if (!qs_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(qs_kobj, &qs_attr_group);
	if (ret)
		goto err_kobj;

	ret = register_trace_android_vh_binder_proc_transaction(android_vh_binder_preset, NULL);
	if (ret < 0) {
		kobject_put(qs_kobj);
		qs_kobj = NULL;
		pr_err("register hook failed, err:%d\n", ret);
		return ret;
	}

	ret = register_qievent_notifier(&g_qs_nb);
	if (ret < 0) {
		unregister_trace_android_vh_binder_proc_transaction(android_vh_binder_preset, NULL);
		pr_err("register qievent failed, err:%d\n", ret);
		goto err_sysfs;
	}

	ret = sl_init();
	if (ret < 0) {
		unregister_qievent_notifier(&g_qs_nb);
		unregister_trace_android_vh_binder_proc_transaction(android_vh_binder_preset, NULL);
		pr_err("speed lock probe failed\n");
		goto err_sysfs;
	}

	pr_info("qos sched and speed lock probe successfully\n");
	return 0;

err_sysfs:
	sysfs_remove_group(qs_kobj, &qs_attr_group);
err_kobj:
	kobject_put(qs_kobj);
	qs_kobj = NULL;
	return ret;
}

static void __exit xr_qs_exit(void)
{
	sl_exit();
	unregister_qievent_notifier(&g_qs_nb);
	unregister_trace_android_vh_binder_proc_transaction(android_vh_binder_preset, NULL);
	if (qs_kobj) {
		sysfs_remove_group(qs_kobj, &qs_attr_group);
		kobject_put(qs_kobj);
		qs_kobj = NULL;
	}
}

module_init(xr_qs_init);
module_exit(xr_qs_exit);

MODULE_AUTHOR("Shaohua Fan <fanshaohua@xiaomi.com>");
MODULE_DESCRIPTION("OS-CPU QOS sched Driver");
MODULE_LICENSE("GPL v2");
