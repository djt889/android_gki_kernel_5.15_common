// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/vip_sched.c - Sew 5.15 rewrite of Xiaomi dada OS4
 *                            vip_sched.ko ("MI QOS sched Driver")
 *
 * Reverse-engineered from:
 *   /root/work/os4_dada/ko/vip_sched.ko
 *   vermagic 6.6.57-android15-8-g32a50a34de2b-4k SMP preempt mod_unload
 *   modversions aarch64, license "GPL v2", name "vip_sched", intree=Y,
 *   depends=plat_common,perf_actuator, author
 *   Shaohua Fan <fanshaohua@xiaomi.com>, description "MI QOS sched Driver".
 *   Source path recorded in the module string table:
 *   kernel/sched/xiaomi_sched/common/vip_sched/vip_sched.c
 *
 * Evidence: E:/AI/SewKernel/.omz/research/
 *   sess_d9452f03-b737-460b-bd27-aff04c01b561-os4-force-port/raw/re-vip-sched.txt
 *   (modinfo, nm -u, nm --defined-only, full llvm-objdump -dr with
 *   relocations, strings, .data hexdump) plus the earlier per-function
 *   notes in the same directory (re-vip-btf-task_struct.txt etc., dada
 *   BTF-verified struct offsets) and the prior analysis
 *   .../re-vip_sched.md.
 *
 * What the module does
 * --------------------
 * A user-configurable per-task "VIP" integer priority (0 = not vip) with
 * a two-slot model: current prio and a baseline (orig) prio.  On dada
 * the state lives in the vendor extension appended to every task_struct
 * (task + 0x12c0; +0x48 current prio, +0x4c baseline, +0x50 list node);
 * this port keeps an RCU hash table keyed by task_struct* instead
 * ([PORT-DELTA] below).  Every CPU owns a struct vip_rq holding a
 * priority-sorted list of its queued vip tasks (top_prio / nr_queued /
 * a level 0/1/2 starvation state machine).  Six layers of mechanism:
 *
 *   1. per-task prio API    - set/get/inherit/restore_vip_prio;
 *                             set_vip_prio_locked() dequeues/requeues the
 *                             task on its cpu vip queue under the rq lock
 *                             so list order follows priority updates
 *   2. wake placement       - find_vip_cpu(): park a waking vip on an
 *                             idle cpu inside the rtg prefer mask (first
 *                             pass) or the full allowed mask with a
 *                             capacity >= group-util filter (repick pass)
 *   3. wakeup preemption    - vip_sched_check_preempt_wakeup(): a vip
 *                             with a better prio than the current task
 *                             forces preemption; a queued vip marks the
 *                             cpu nopreempt for later wakeups
 *   4. CFS pick replacement - vip_sched_replace_next_task_fair(): swap
 *                             the picked next for the cpu's highest-prio
 *                             queued vip, gated by staleness windows
 *                             (50 ms / 3 ms, runtime-tunable through
 *                             SET_VIP_WAIT_THRES)
 *   5. starvation level     - vip_sched_schedule()/scheduler_tick(): the
 *                             per-cpu level state machine escalates to 2
 *                             when a vip is preempted by a heavy-util
 *                             task or starved with >=2 queued vips
 *   6. active migration     - kick_vip_balance() IPI + vip_balance_commit()
 *                             pull: deactivate on the congested source
 *                             cpu, activate + check_preempt_curr here,
 *                             subject to the five can_migrate_vip rules
 *                             (cpus_ptr / on_cpu / prio-vs-dst-top /
 *                             capacity-vs-util / group-prefer).
 *
 * Userspace interface: two perf_actuator ioctls (misc device bridge,
 * mm/perf_actuator.c), command words recovered from init_module:
 *   SET_VIP_PRIO       0x4008781e  {int pid; int prio}             8B
 *   SET_VIP_WAIT_THRES 0x40107824  {u64 wait_thres; u64 vip_thres} 16B
 * The SET_VIP_PRIO handler is the entry xr_qs.ko / mi_game.ko style
 * consumers drive; in-tree modules call set_vip_prio /
 * restore_vip_prio / get_vip_prio / is_vip_task directly (xr_qs.ko
 * depends=vip_sched on dada; this port provides the same exports).
 *
 * dada call topology and why we register vendor hooks
 * ---------------------------------------------------
 * On dada the vip_sched_* functions below are NOT hook callbacks: the
 * built-in dada scheduler core calls them directly (the module exports
 * them via __ksymtab and its nm -u shows *no* register_trace symbols).
 * 5.15 GKI has no such call sites, so each dada call site is re-wired
 * to the equivalent vendor hook, all verified present in
 * include/trace/hooks/sched.h of this tree with matching arity:
 *
 *   dada call site                     -> 5.15 hook (this file)
 *   core enqueue_task(rq,p)            -> android_rvh_enqueue_task(rq,p,flags)
 *   core dequeue_task(rq,p)            -> android_rvh_dequeue_task(rq,p,flags)
 *   fair select_task_rq_fair(p,...)    -> android_rvh_select_task_rq_fair
 *                                          (p, prev_cpu, sd, wake, *new_cpu)
 *   fair check_preempt_wakeup          -> android_rvh_check_preempt_wakeup
 *                                          (rq, p, *preempt, *nopreempt, ...)
 *   fair pick_next_task_fair           -> android_rvh_replace_next_task_fair
 *                                          (rq, &p, &se, &repick, simple, prev)
 *   core schedule(prev,next,rq)        -> android_rvh_schedule(prev, next, rq)
 *   core scheduler_tick(rq)            -> android_vh_scheduler_tick(rq)
 *   fair newidle_balance(rq,rf)        -> android_rvh_sched_newidle_balance
 *                                          (rq, rf, *pulled, *done)
 *   (dada task-init in copy_process)   -> android_rvh_finish_prio_fork(p)
 *   (dada pad is per-task; n/a)        -> android_vh_free_task(p) for entry
 *                                          reclaim
 *
 * Closure gaps vs 6.6 (nm -u of vip_sched.ko)
 * -------------------------------------------
 *  1. alt_cb_patch_nops - 6.6 arm64 alternative-callback helper used by
 *     the module's static-branch plumbing; 5.15 uses native jump_label,
 *     nothing to patch.
 *  2. system_cpucaps - 6.6 CPU capacity framework.  The dada module
 *     reads capacity only through plat_common (plat_capacity_orig_of),
 *     so the same indirect layer closes the gap here; no direct
 *     cpu_scale/system_cpucaps use remains.
 *  3. vendor_data_pad / task+0x12c0 - the 6.6 vendor pad appended to
 *     every task_struct (init_task aliased to the global pad).  5.15
 *     task_struct has no vendor extension: replaced by the vip_task RCU
 *     hash table below; init_task simply has no entry, which reproduces
 *     the always-zero global-pad reads of is_vip_task/get_vip_prio.
 *  4. android_vendor_data1[26]/[28] (task+0xc90/+0xca0) - walt-written
 *     "last runnable / last ran" timestamp pair consumed by the replace
 *     staleness window (max() of the pair).  No walt on 5.15: replaced
 *     by our own rq->clock stamps (ts_enq recorded by the enqueue hook,
 *     ts_run by the schedule hook) combined with max() the same way.
 *  5. RQCF_DEACT_SKIP rq-flag propagation after task_rq_lock'd priority
 *     writes (6.6 core.c idiom, dead write in the dada build).  5.15
 *     has no such consumer; plain update_rq_clock() + task_rq_unlock()
 *     matches the in-tree set_user_nice() pattern.
 *
 * [PORT-DELTA] list (deliberate deviations, all load-bearing):
 *  - per-task state: hash table keyed by task_struct* with kfree_rcu
 *    reclaim (android_vh_free_task), bounded by VIP_TASK_MAX entries;
 *    dada keeps unbounded state in the vendor pad.
 *  - enqueue/dequeue hook adapters gain the hooks' extra int flags
 *    parameter; the exported functions keep the dada (rq, p) shape.
 *  - vip_sched_check_preempt_wakeup: dada's 4th out-param is wired to
 *    5.15's *nopreempt - consumption verified in fair.c (preempt wins
 *    first, then ignore returns early).  The extra hook params
 *    (wake_flags, se, pse, granularity) are ignored, as dada ignores
 *    them.
 *  - vip_sched_scheduler_tick: dada wraps its body in
 *    raw_spin_lock(rq)/raw_spin_unlock(rq) because its built-in caller
 *    invokes it without the rq lock; 5.15's android_vh_scheduler_tick
 *    fires inside scheduler_tick() with the lock already held, so the
 *    lock pair is dropped.
 *  - vip_sched_newidle_balance: same - 5.15's
 *    android_rvh_sched_newidle_balance fires at the top of
 *    sched_balance_newidle() with this_rq locked, so the dst-rq lock is
 *    only taken when not already held (__vip_balance_commit @dst_locked).
 *  - plat_find_idle_cpu_in_freq_domain: the in-tree plat_common takes
 *    struct task_struct *p while dada's tick call site passed a cpu
 *    number; we pass rq->curr.
 *  - rq+0x9d0 skip filter inside find_vip_cpu's congestion scan: the
 *    dada field could not be matched to a named 5.15 struct rq member
 *    with certainty ([RE-AMBIG]); it only feeds the trace-only
 *    congestion candidate set (see find_vip_cpu comment), implemented
 *    as the uclamp idle flag under CONFIG_UCLAMP_TASK.
 *  - find_vip_cpu's congestion-source scan origin: dada walks online
 *    cpus ascending from self; we walk all online cpus excluding the
 *    destination ([RE-AMBIG] on the exact origin semantics).
 *  - tracepoints: the ten dada TRACE_EVENTs are reproduced field-for-
 *    field in include/trace/events/vip_sched.h (CREATE_TRACE_POINTS
 *    here).  The vip_replace_next_task mask argument could not be
 *    pinned to an exact source expression ([RE-AMBIG]) and carries the
 *    candidate task's cpus_mask.
 *  - perf_actuator_set_vip_prio: the payload is {pid, prio}; dada's
 *    third set_vip_prio_locked argument (write-the-baseline flag) is
 *    not derivable from the 8-byte payload ([RE-AMBIG]) - we set the
 *    baseline when prio > 0 and adjust the current value only when
 *    prio <= 0, matching the mi_game/xr_qs set/restore usage.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/clock.h>
#include <linux/sched/topology.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/cpumask.h>
#include <linux/errno.h>

#include "sched.h"
#include <trace/hooks/sched.h>

/*
 * Hook slot words from mm/perf_actuator.c (register_perf_actuator keeps
 * the low byte as the table slot; full words recovered from
 * init_module's immediates).
 */
#define SET_VIP_PRIO			0x4008781e
#define SET_VIP_WAIT_THRES		0x40107824

struct vip_rq;

extern int register_perf_actuator(int idx, int (*func)(unsigned long arg));
extern int unregister_perf_actuator(int idx);
extern unsigned long plat_task_util(struct task_struct *p);
extern bool plat_cpu_halted(int cpu);
extern struct cpumask *plat_cpu_halt_mask(void);
extern unsigned long plat_capacity_orig_of(int cpu);
extern int plat_find_idle_cpu_in_freq_domain(struct task_struct *p);
extern void plat_get_group_prefer_cpus(struct task_struct *p,
				       struct cpumask *prefer_cpus);
extern unsigned long plat_get_group_prefer_util(struct task_struct *p);
extern int plat_migt_enable(void);
/* 5.15 GKI fair.c export (not declared in sched.h). */
extern void set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se);

static void vip_csd_func(void *info);
static void kick_vip_balance(struct vip_rq *vrq, struct task_struct *p);
static int vip_balance_commit(struct vip_rq *vrq);

/*
 * Per-cpu vip scheduler state.  dada's struct vip_rq is 128 bytes; every
 * field below was mapped from vip_init_rq()/enqueue/dequeue disassembly
 * (offsets 0x00..0x68; the remainder is padding).
 *
 *   +0x00 cpu         +0x04 top_prio    +0x08 nr_queued   +0x0c (unused)
 *   +0x10 level       +0x18 queue       +0x28 busy
 *   +0x40 csd (func@+0x50, info@+0x58)
 *   +0x60 kick_pending +0x68 last (replace 1ms retry window)
 */
struct vip_rq {
	int				cpu;
	u32				top_prio;
	u32				nr_queued;
	u8				__pad0;
	u32				level;
	struct list_head		queue;
	bool				busy;
	call_single_data_t		csd;
	u32				kick_pending;
	u64				last;
};

/*
 * Per-task vip state.  dada: the vendor pad at task+0x12c0
 * (+0x48 current prio, +0x4c baseline prio, +0x50 queue node).  ts_enq /
 * ts_run replace the walt android_vendor_data1[26]/[28] pair (closure
 * gap 4): rq->clock snapshots of "last became runnable" and "last was
 * picked to run".
 */
struct vip_task {
	struct task_struct		*task;
	u32				vip_prio;
	u32				orig_prio;
	u64				ts_enq;
	u64				ts_run;
	struct list_head		queue_node;
	struct hlist_node		hash_node;
	struct rcu_head		rcu;
};

/* The ten dada TRACE_EVENTs (field-for-field port, see the header). */
#define CREATE_TRACE_POINTS
/*
 * GKI vendor-hook headers leak "#define TRACE_INCLUDE_PATH trace/hooks"
 * (they never include define_trace.h, so the define is never cleaned
 * up); drop it or define_trace.h would look for the wrong file.
 */
#undef TRACE_INCLUDE_PATH
#include <trace/events/vip_sched.h>

/*
 * dada exports vip_rq and vip_update_lock as (non-EXPORTed) global data
 * symbols; keep the names and visibility.
 */
DEFINE_PER_CPU(struct vip_rq, vip_rq);
DEFINE_MUTEX(vip_update_lock);

/*
 * dada: .bss u32 "sys_vip_stats" - number of vip tasks currently on the
 * per-cpu queues, maintained atomically inside enqueue_vip_task /
 * dequeue_vip_task and used as the fast bail-out in vip_balance_commit.
 */
atomic_t sys_vip_stats = ATOMIC_INIT(0);

/*
 * Replace-window thresholds (ns).  dada defaults recovered from .data:
 *   +0x1348 g_wait_time_thres     = 0x02FAF080 = 50 ms
 *   +0x1350 g_vip_wait_time_thres = 0x002DC6C0 =  3 ms
 * both writable from userspace via SET_VIP_WAIT_THRES.
 */
static u64 g_wait_time_thres		= 50000000; /* 50ms */
static u64 g_vip_wait_time_thres	= 3000000;  /* 3ms  */

/* Replace retry window: re-evaluate the same pick after 1ms. */
#define VIP_REPLACE_RETRY_NS			1000000ULL

/* level 2 trigger: incoming task util above 25% capacity (dada: >0xff). */
#define VIP_HPRIO_UTIL_MAX			255UL

/* Congested source cpu: at least this many vips queued. */
#define VIP_EMERG_NR_MIN			2

/*
 * Side-table bounds.  dada carries state for every task; we bound the
 * allocation to keep worst-case memory finite ([PORT-DELTA]).
 */
#define VIP_TASK_MAX				512
#define VIP_HASH_BITS				6
#define VIP_HASH_SIZE				(1U << VIP_HASH_BITS)

static struct hlist_head vip_task_hash[VIP_HASH_SIZE];
static raw_spinlock_t vip_hash_lock =
					__RAW_SPIN_LOCK_UNLOCKED(vip_hash_lock);
static atomic_t vip_task_nr = ATOMIC_INIT(0);

/* ------------------------------------------------------------------ */
/* Side table helpers                                                  */
/* ------------------------------------------------------------------ */

/* RCU reader side: entry safe while the task is alive. */
static struct vip_task *vip_task_find_rcu(struct task_struct *p)
{
	struct vip_task *v;

	hlist_for_each_entry_rcu(v,
				 &vip_task_hash[hash_ptr(p, VIP_HASH_BITS)],
				 hash_node) {
		if (v->task == p)
			return v;
	}
	return NULL;
}

/* Lock holder side: only valid under vip_hash_lock. */
static struct vip_task *vip_task_find_locked(struct task_struct *p)
{
	struct vip_task *v;

	hlist_for_each_entry(v,
			     &vip_task_hash[hash_ptr(p, VIP_HASH_BITS)],
			     hash_node) {
		if (v->task == p)
			return v;
	}
	return NULL;
}

/*
 * Look up p's vip state, allocating it if absent.  Usable under rq->lock
 * with gfp = GFP_NOWAIT; callers in sleepable context pre-create with
 * GFP_KERNEL so the rq-lock-held section rarely allocates.
 */
static struct vip_task *vip_task_get_create(struct task_struct *p, gfp_t gfp)
{
	struct vip_task *v, *old;
	unsigned long flags;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	rcu_read_unlock();
	if (v)
		return v;

	if (atomic_read(&vip_task_nr) >= VIP_TASK_MAX)
		return NULL;

	v = kzalloc(sizeof(*v), gfp | __GFP_NOWARN);
	if (!v)
		return NULL;

	v->task = p;
	INIT_LIST_HEAD(&v->queue_node);
	INIT_HLIST_NODE(&v->hash_node);

	raw_spin_lock_irqsave(&vip_hash_lock, flags);
	old = vip_task_find_locked(p);
	if (!old) {
		hlist_add_head_rcu(&v->hash_node,
				   &vip_task_hash[hash_ptr(p, VIP_HASH_BITS)]);
		atomic_inc(&vip_task_nr);
	}
	raw_spin_unlock_irqrestore(&vip_hash_lock, flags);

	if (old) {
		kfree(v);
		return old;
	}
	return v;
}

static void vip_task_remove(struct task_struct *p)
{
	struct vip_task *v;
	unsigned long flags;

	raw_spin_lock_irqsave(&vip_hash_lock, flags);
	v = vip_task_find_locked(p);
	if (v)
		hlist_del_init_rcu(&v->hash_node);
	raw_spin_unlock_irqrestore(&vip_hash_lock, flags);

	if (v) {
		atomic_dec(&vip_task_nr);
		/*
		 * v may still be referenced by rq-lock-held readers on
		 * other cpus; the RCU grace period outlives them.
		 * Its queue node is expected to be free: task exit
		 * dequeues before free_task fires.
		 */
		WARN_ON_ONCE(!list_empty(&v->queue_node));
		kfree_rcu(v, rcu);
	}
}

/* ------------------------------------------------------------------ */
/* dada: is_vip_task / get_vip_prio (pad reads, exported)              */
/* ------------------------------------------------------------------ */

/**
 * is_vip_task - [dada .text+0x1b7c] true when the task carries a
 * non-zero vip prio.  The original's init_task case reads the global
 * vendor pad (always zero); the side table reproduces that by simply
 * not containing init_task.
 */
noinline bool is_vip_task(struct task_struct *p)
{
	struct vip_task *v;
	bool ret = false;

	if (!p)
		return false;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v)
		ret = v->vip_prio != 0;
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(is_vip_task);

/**
 * get_vip_prio - [dada .text+0x2288] current vip prio, 0 when not vip
 * or @p is NULL.
 */
noinline u32 get_vip_prio(struct task_struct *p)
{
	struct vip_task *v;
	u32 prio = 0;

	if (!p)
		return 0;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v)
		prio = v->vip_prio;
	rcu_read_unlock();

	return prio;
}
EXPORT_SYMBOL_GPL(get_vip_prio);

/* ------------------------------------------------------------------ */
/* dada: enqueue_vip_task / dequeue_vip_task (rq lock held)            */
/* ------------------------------------------------------------------ */

static void vip_top_prio_update(struct vip_rq *vrq)
{
	struct vip_task *first;

	if (list_empty(&vrq->queue)) {
		vrq->top_prio = 0;
		return;
	}
	first = list_first_entry(&vrq->queue, struct vip_task, queue_node);
	vrq->top_prio = first->vip_prio;
}

/*
 * [dada enqueue_vip_task @ .text+0x2024] Add p to its cpu's vip queue,
 * priority-ordered (ascending prio value; equal prio appends FIFO).
 * Caller must hold p's rq lock.  No-op unless p is a configured vip and
 * not already on a queue.  The entry pointer is safe across the list
 * operations: entries are only freed through kfree_rcu after the task
 * itself is dead (android_vh_free_task).
 */
static void enqueue_vip_task(struct rq *rq, struct task_struct *p)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	struct vip_task *v = NULL, *pos;
	int prio = 0;

	if (!rq || !p)
		return;
	/*
	 * Audit P0-2: the hook fires for every sched class; only fair
	 * tasks belong in the vip queue (an RT promotion of a queued vip
	 * must not re-enter it).
	 */
	if (p->prio < MAX_RT_PRIO)
		return;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v) {
		prio = v->vip_prio;
		/* mirrors the walt "task became runnable" stamp (gap 4). */
		v->ts_enq = rq->clock;
	}
	rcu_read_unlock();
	if (!prio || !v)
		return;

	if (!list_empty(&v->queue_node))
		return;

	list_for_each_entry(pos, &vrq->queue, queue_node) {
		if (prio > pos->vip_prio)
			break;
	}
	list_add_tail(&v->queue_node, &pos->queue_node);

	vrq->nr_queued++;
	vip_top_prio_update(vrq);
	atomic_inc(&sys_vip_stats);

	trace_queue_vip_task(true, vrq, v->vip_prio, p->pid);
}

/*
 * [dada dequeue_vip_task @ .text+0x1df4] Remove p from its cpu's vip
 * queue.  Caller must hold p's rq lock.
 */
static void dequeue_vip_task(struct rq *rq, struct task_struct *p)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	struct vip_task *v = NULL;
	int prio = 0;

	if (!rq || !p)
		return;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v)
		prio = v->vip_prio;
	rcu_read_unlock();
	if (!prio || !v)
		return;

	if (list_empty(&v->queue_node))
		return;

	list_del_init(&v->queue_node);

	vrq->nr_queued--;
	vip_top_prio_update(vrq);
	atomic_dec(&sys_vip_stats);

	trace_queue_vip_task(false, vrq, vrq->top_prio, p->pid);
}

/*
 * [dada .text+0x2538 / .text+0x2558] Hook adapters ([PORT-DELTA]: dada's
 * scheduler core called these directly with (rq, p); 5.15 provides them
 * as restricted hooks with an extra flags argument).
 */
void vip_sched_enqueue_task_fair(struct rq *rq, struct task_struct *p)
{
	enqueue_vip_task(rq, p);
}
EXPORT_SYMBOL_GPL(vip_sched_enqueue_task_fair);

void vip_sched_dequeue_task_fair(struct rq *rq, struct task_struct *p)
{
	dequeue_vip_task(rq, p);
}
EXPORT_SYMBOL_GPL(vip_sched_dequeue_task_fair);

/* ------------------------------------------------------------------ */
/* dada: set_vip_prio_locked (exported, rq lock held)                  */
/* ------------------------------------------------------------------ */

/**
 * set_vip_prio_locked - [dada .text+0x1c24] write p's vip prio while
 * holding p's rq lock, re-queueing it on the cpu vip list so the list
 * stays priority-ordered.  @set_orig additionally writes the baseline
 * slot (the target of restore_vip_prio()).
 *
 * Returns 0, or -ENOMEM when no side-table entry can be materialised
 * (dada returns -EINVAL for a missing pad, which cannot happen there).
 */
int set_vip_prio_locked(struct task_struct *p, int prio, bool set_orig)
{
	struct rq *rq = task_rq(p);
	struct vip_task *v;
	bool moved = false;

	v = vip_task_get_create(p, GFP_NOWAIT);
	if (!v)
		return -ENOMEM;

	/*
	 * dada guard: only fair-class queued tasks sit on the vip queue
	 * (prio >= 100), never the idle task, and only while actually
	 * TASK_ON_RQ_QUEUED.
	 */
	if (p->prio >= 100 && !(p->flags & PF_IDLE) &&
	    p->on_rq == TASK_ON_RQ_QUEUED) {
		update_rq_clock(rq);
		dequeue_vip_task(rq, p);
		moved = true;
	}

	v->vip_prio = prio;
	if (set_orig)
		v->orig_prio = prio;

	if (moved)
		enqueue_vip_task(rq, p);

	trace_set_vip_prio(p->pid, v->vip_prio, v->orig_prio);
	return 0;
}
EXPORT_SYMBOL_GPL(set_vip_prio_locked);

/**
 * set_vip_prio - [dada .text+0x22c8] rq-lock-taking variant.
 * @set_orig propagates to set_vip_prio_locked.
 */
int set_vip_prio(struct task_struct *p, int prio, bool set_orig)
{
	struct rq_flags rf;
	struct rq *rq;
	int ret;

	if (!p)
		return -EINVAL;

	/* Pre-create the entry outside the lock when we may sleep. */
	if (preemptible())
		vip_task_get_create(p, GFP_KERNEL);

	rq = task_rq_lock(p, &rf);
	ret = set_vip_prio_locked(p, prio, set_orig);
	task_rq_unlock(rq, p, &rf);

	return ret;
}
EXPORT_SYMBOL_GPL(set_vip_prio);

/**
 * inherit_vip_prio - [dada .text+0x2378] copy @src's current vip prio
 * onto @dst (baseline untouched).  A non-vip src is a no-op, mirroring
 * the original's early return.
 */
void inherit_vip_prio(struct task_struct *src, struct task_struct *dst)
{
	struct rq_flags rf;
	struct rq *rq;
	u32 prio;

	if (!src || !dst)
		return;

	prio = get_vip_prio(src);
	if (!prio)
		return;

	if (preemptible())
		vip_task_get_create(dst, GFP_KERNEL);

	rq = task_rq_lock(dst, &rf);
	set_vip_prio_locked(dst, prio, false);
	task_rq_unlock(rq, dst, &rf);
}
EXPORT_SYMBOL_GPL(inherit_vip_prio);

/**
 * restore_vip_prio - [dada .text+0x245c] reset the current vip prio to
 * the baseline slot (0 when never set = clear vip).
 */
void restore_vip_prio(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;
	struct vip_task *v;
	u32 orig = 0;

	if (!p)
		return;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v)
		orig = v->orig_prio;
	rcu_read_unlock();

	if (preemptible())
		vip_task_get_create(p, GFP_KERNEL);

	rq = task_rq_lock(p, &rf);
	set_vip_prio_locked(p, orig, false);
	task_rq_unlock(rq, p, &rf);
}
EXPORT_SYMBOL_GPL(restore_vip_prio);

/* ------------------------------------------------------------------ */
/* dada: find_vip_preempt_cpu / is_vip_cpu / vip_cpu_hprio (exported)  */
/* ------------------------------------------------------------------ */

/**
 * find_vip_preempt_cpu - [dada .text+0x1bc0] first cpu in @mask whose
 * vip rq carries a non-zero level (i.e. a queued/starved vip that wants
 * attention).  Returns -1 when none qualifies.
 */
noinline int find_vip_preempt_cpu(const struct cpumask *mask)
{
	int cpu;

	for_each_cpu(cpu, mask) {
		struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu);

		if (vrq->level)
			return cpu;
	}
	return -1;
}
EXPORT_SYMBOL_GPL(find_vip_preempt_cpu);

/**
 * is_vip_cpu - [dada .text+0x3f20] true when the cpu has vip tasks
 * queued (dada: nr_queued > 0 - a dynamic property, not capacity).
 */
noinline bool is_vip_cpu(int cpu)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu);

	return vrq->nr_queued > 0;
}
EXPORT_SYMBOL_GPL(is_vip_cpu);

/**
 * vip_cpu_hprio - [dada .text+0x3f58] the best (lowest-valued) vip prio
 * queued on @cpu, 0 when none.
 */
noinline int vip_cpu_hprio(int cpu)
{
	struct vip_rq *vrq;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return 0;
	vrq = per_cpu_ptr(&vip_rq, cpu);
	return vrq->top_prio;
}
EXPORT_SYMBOL_GPL(vip_cpu_hprio);

/* ------------------------------------------------------------------ */
/* dada: vip_init_rq / vip_init_task (exported)                        */
/* ------------------------------------------------------------------ */

/**
 * vip_init_rq - [dada .text+0x3e18] initialise the per-cpu vip rq,
 * including the csd used by the balance IPI (dada writes
 * csd.func/.info at +0x50/+0x58, matching call_single_data_t layout).
 */
noinline void vip_init_rq(int cpu)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu);

	vrq->cpu = cpu;
	vrq->top_prio = 0;
	vrq->nr_queued = 0;
	vrq->level = 0;
	vrq->busy = false;
	vrq->kick_pending = 0;
	vrq->last = 0;
	INIT_LIST_HEAD(&vrq->queue);
	INIT_CSD(&vrq->csd, vip_csd_func, vrq);
}
EXPORT_SYMBOL_GPL(vip_init_rq);

/**
 * vip_init_task - [dada .text+0x3edc] zero a fresh task's vip state.
 * [PORT-DELTA] with the side table a new task simply has no entry;
 * drop any stale one defensively and keep the symbol for consumers.
 */
noinline void vip_init_task(struct task_struct *p)
{
	if (p)
		vip_task_remove(p);
}
EXPORT_SYMBOL_GPL(vip_init_task);

/* ------------------------------------------------------------------ */
/* dada: find_vip_cpu (local, wake placement)                          */
/* ------------------------------------------------------------------ */

/*
 * [dada find_vip_cpu @ .text+0x25e8]
 *
 * Two-pass scan.  Pass 0 restricts to the rtg group prefer mask (when
 * it intersects the allowed mask); on failure the repick pass scans the
 * full allowed mask filtered by capacity >= plat_get_group_prefer_util.
 * Within a pass only an *idle* cpu is picked (available_idle_cpu);
 * otherwise a congestion candidate set is built (cpus whose resident
 * vip top_prio is not weaker than ours, skipping uclamp-idle-flagged
 * rqs, minimising top_prio) and reported through trace_find_vip_cpu but
 * never returned - the disassembly's exit (tbz w9,#0 -> mov w20,#-1)
 * returns -1 whenever no idle cpu was found.  Wake placement therefore
 * only steals idle cpus; contention is resolved by the balance engine
 * (kick_vip_balance / vip_balance_commit).
 */
static int find_vip_cpu(struct task_struct *p)
{
	cpumask_t allowed, mask, prefer, cand, trace_mask;
	struct vip_task *v;
	int prio = 0, cpu, ret = -1;
	int pass = 0;
	unsigned long rtg_mask = 0;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	if (v)
		prio = v->vip_prio;
	rcu_read_unlock();
	if (!prio)
		return ret;

	cpumask_and(&allowed, p->cpus_ptr, cpu_online_mask);
	cpumask_andnot(&allowed, &allowed, plat_cpu_halt_mask());

retry:
	cpumask_copy(&trace_mask, &allowed);
	if (pass == 0) {
		cpumask_clear(&prefer);
		plat_get_group_prefer_cpus(p, &prefer);
		rtg_mask = *cpumask_bits(&prefer);
		if (cpumask_intersects(&prefer, &allowed)) {
			cpumask_and(&mask, &prefer, &allowed);
		} else {
			pass = 1;
			goto retry;
		}
	} else {
		/* repick pass: capacity filter (>= group prefer util). */
		unsigned long util = plat_get_group_prefer_util(p);

		cpumask_clear(&mask);
		for_each_cpu(cpu, &allowed) {
			if (plat_capacity_orig_of(cpu) >= util)
				cpumask_set_cpu(cpu, &mask);
		}
		if (cpumask_empty(&mask))
			goto out_trace;
	}
	cpumask_copy(&trace_mask, &mask);

	/* Idle pick: first available idle cpu inside the scan mask. */
	for_each_cpu(cpu, &mask) {
		if (available_idle_cpu(cpu)) {
			ret = cpu;
			goto out_trace;
		}
	}

	/* Congestion candidate set: trace-only (see function comment). */
	cpumask_clear(&cand);
	{
		unsigned long best = UINT_MAX;
		struct vip_rq *vrq;

		for_each_cpu(cpu, &mask) {
			vrq = per_cpu_ptr(&vip_rq, cpu);
			if (vrq->top_prio > (unsigned long)prio)
				continue;
#ifdef CONFIG_UCLAMP_TASK
			/* [RE-AMBIG] dada rq+0x9d0 filter. */
			if (cpu_rq(cpu)->uclamp_flags & UCLAMP_FLAG_IDLE)
				continue;
#endif
			if (vrq->top_prio < best) {
				best = vrq->top_prio;
				cpumask_clear(&cand);
			}
			cpumask_set_cpu(cpu, &cand);
		}
	}
	cpumask_copy(&trace_mask, &cand);

out_trace:
	trace_find_vip_cpu(p->pid, *cpumask_bits(&trace_mask), ret, pass & 1,
			   *cpumask_bits(p->cpus_ptr), *cpumask_bits(plat_cpu_halt_mask()),
			   rtg_mask);
	return ret;
}

/*
 * [dada vip_sched_select_task_rq_fair @ .text+0x2578] wake/select
 * placement for vip tasks.  dada's built-in caller tolerated
 * find_vip_cpu()'s -1 by checking the value before applying it; the
 * check is folded in here.
 */
void vip_sched_select_task_rq_fair(struct task_struct *p, int prev_cpu,
				   int sd_flag, int wake_flags, int *new_cpu)
{
	int cpu;

	if (plat_migt_enable())
		return;
	if (!is_vip_task(p))
		return;

	cpu = find_vip_cpu(p);
	if (cpu >= 0)
		*new_cpu = cpu;
}
EXPORT_SYMBOL_GPL(vip_sched_select_task_rq_fair);

/* ------------------------------------------------------------------ */
/* dada: vip_sched_check_preempt_wakeup (wakeup preemption)            */
/* ------------------------------------------------------------------ */

/*
 * [dada vip_sched_check_preempt_wakeup @ .text+0x2f44]
 *  - when a vip is queued on this cpu (top_prio != 0) later wakeups must
 *    not preempt: dada's 4th out-param, wired to 5.15's *nopreempt
 *    (fair.c: "if (preempt) goto preempt; if (ignore) return;").
 *  - a waking vip with a better prio than the running task forces
 *    preemption and traces.
 */
void vip_sched_check_preempt_wakeup(struct rq *rq, struct task_struct *p,
				    bool *preempt, bool *nopreempt)
{
	struct task_struct *curr = rq->curr;
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	u32 p_prio, c_prio;

	if (vrq->top_prio)
		*nopreempt = true;

	p_prio = get_vip_prio(p);
	c_prio = get_vip_prio(curr);

	if (p_prio > c_prio) {
		*preempt = true;
		trace_vip_preempt_curr(curr->pid, p->pid, p_prio);
	}
}
EXPORT_SYMBOL_GPL(vip_sched_check_preempt_wakeup);

/* ------------------------------------------------------------------ */
/* dada: vip_sched_replace_next_task_fair (CFS pick replacement)       */
/* ------------------------------------------------------------------ */

static u64 vip_task_last_stamp(struct vip_task *v)
{
	return max(v->ts_enq, v->ts_run);
}

static u64 vip_task_stamp_now(struct task_struct *p)
{
	struct vip_task *v;
	u64 ts;

	rcu_read_lock();
	v = vip_task_find_rcu(p);
	ts = v ? vip_task_last_stamp(v) : 0;
	rcu_read_unlock();
	return ts;
}

/*
 * [dada vip_sched_replace_next_task_fair @ .text+0x2a10] Replace the
 * fair pick with this cpu's highest-priority queued vip, subject to
 * staleness: the displaced pick must have become runnable no longer
 * than g_wait_time_thres (50ms) ago, or the vip must have waited at
 * least g_vip_wait_time_thres (3ms).  A 1ms retry window (vrq->last)
 * stops repeated identical attempts while curr keeps running.
 *
 * 5.15 wiring: fair.c calls the hook on the full-pick path (simple =
 * false; fair.c itself runs the put_prev/set_next entity dance for the
 * replacement) and on the simple path (simple = true; when we repick,
 * fair.c skips its pick loop and WE must run the set_next_entity chain,
 * exactly dada's "if (set_next) walk se->parent" behaviour).
 */
bool vip_sched_replace_next_task_fair(struct rq *rq, struct task_struct **pnext,
				      struct sched_entity **pse,
				      bool *repick_done, bool simple,
				      struct task_struct *prev)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	struct vip_task *chosen_v;
	struct task_struct *orig, *chosen;
	u64 now, d_orig = 0, d_chosen = 0, ts;
	u64 thres_wait, thres_vip;
	int orig_pid, chosen_prio;

	if (list_empty(&vrq->queue))
		return false;

	orig = *pnext;
	if (orig && orig->nr_cpus_allowed == 1)
		return false;

	chosen_v = list_first_entry(&vrq->queue, struct vip_task, queue_node);
	chosen = chosen_v->task;

	/*
	 * Audit P0-2: the enqueue/dequeue hooks fire for every sched
	 * class (core.c enqueue_task/dequeue_task), so a vip task promoted
	 * to RT/DL by another channel (xr_qs rt channel) must never be
	 * handed into the CFS pick path - set_next_entity() on a non-CFS
	 * se corrupts the scheduler.
	 */
	if (chosen->prio < MAX_RT_PRIO)
		return false;

	/* dada BUG chain; skipped when the chosen task is the current one. */
	if (chosen != prev) {
		if (chosen->on_cpu == 1 || chosen->on_rq == 0 ||
		    task_cpu(chosen) != cpu_of(rq))
			panic("replace task error, pid=%d, on_cpu=%d, on_rq=%d, task_cpu=%d, cpu=%d",
			      chosen->pid, chosen->on_cpu, chosen->on_rq,
			      task_cpu(chosen), cpu_of(rq));
	}

#ifdef CONFIG_SCHED_DEBUG
	WARN_ONCE(rq->clock_update_flags < RQCF_ACT_SKIP,
		  "rq->clock_update_flags < RQCF_ACT_SKIP");
#endif

	now = rq->clock;
	thres_wait = READ_ONCE(g_wait_time_thres);
	thres_vip = READ_ONCE(g_vip_wait_time_thres);

	/* d_orig: staleness of the displaced pick (window rules of dada). */
	if (orig) {
		if (rq->curr == orig) {
			if (now - vrq->last <= VIP_REPLACE_RETRY_NS) {
				ts = vip_task_stamp_now(orig);
				d_orig = now > ts ? now - ts : 0;
			}
			/* stale retry window: d_orig stays 0 */
		} else {
			ts = vip_task_stamp_now(orig);
			d_orig = now > ts ? now - ts : 0;
		}
	}

	/* d_chosen: wait time of the vip candidate. */
	if (chosen != orig) {
		ts = vip_task_last_stamp(chosen_v);
		d_chosen = now > ts ? now - ts : 0;
	} else if (rq->curr == chosen) {
		if (now - vrq->last <= VIP_REPLACE_RETRY_NS) {
			ts = vip_task_last_stamp(chosen_v);
			d_chosen = now > ts ? now - ts : 0;
		}
	} else {
		ts = vip_task_last_stamp(chosen_v);
		d_chosen = now > ts ? now - ts : 0;
	}

	/*
	 * Replace when the displaced pick has not been waiting long
	 * (d_orig <= 50ms) or the vip has genuinely waited (d_chosen >=
	 * 3ms).
	 */
	if (d_orig > thres_wait && d_chosen < thres_vip) {
		if (rq->curr != orig)
			vrq->last = now;
		trace_vip_replace_next_task(orig, 0, 0,
					    orig ? orig->pid : -1, d_orig);
		return false;
	}

	chosen_prio = chosen_v->vip_prio;
	orig_pid = orig ? orig->pid : -1;

	*pnext = chosen;
	*pse = &chosen->se;
	*repick_done = true;

	if (simple) {
		struct sched_entity *se = *pse;

		while (se) {
			set_next_entity(se->cfs_rq, se);
			se = se->parent;
		}
	}

	trace_vip_replace_next_task(chosen, chosen_prio,
				    *cpumask_bits(&chosen->cpus_mask),
				    orig_pid, d_orig);
	return true;
}
EXPORT_SYMBOL_GPL(vip_sched_replace_next_task_fair);

/* ------------------------------------------------------------------ */
/* dada: vip_sched_schedule (level state machine)                      */
/* ------------------------------------------------------------------ */

/*
 * [dada vip_sched_schedule @ .text+0x30f4] context-switch bookkeeping.
 * level: 0 = nothing queued / no vip involvement; 1 = a vip was
 * preempted (prev is a vip, stays queued, next is not heavy enough);
 * 2 = a vip is starving (next util > 25% capacity) - at level 2 the
 * tail (lowest-prio) queued vip is kicked towards another cpu.  When
 * prev goes to sleep (on_rq == 0) the stored level is kept.
 */
void vip_sched_schedule(struct task_struct *prev, struct task_struct *next,
			struct rq *rq)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	struct vip_task *v;
	u32 prev_prio = 0, next_prio = 0;
	struct task_struct *tail;
	int level = 0;

	if (!prev || !next)
		return;

	rcu_read_lock();
	v = vip_task_find_rcu(prev);
	if (v)
		prev_prio = v->vip_prio;
	v = vip_task_find_rcu(next);
	if (v) {
		next_prio = v->vip_prio;
		/* mirrors the walt "task started running" stamp (gap 4). */
		v->ts_run = rq->clock;
	}
	rcu_read_unlock();

	if (prev != next && vrq->nr_queued) {
		if (next_prio || next->prio <= 99) {
			if (!prev->on_rq)
				level = vrq->level;	/* keep */
			else if (!prev_prio)
				level = 1;
			else if (plat_task_util(next) > VIP_HPRIO_UTIL_MAX)
				level = 2;
			else if (!prev->on_rq)
				level = vrq->level;	/* keep */
			else
				level = 1;
		} else {
			level = 0;
		}
	} else {
		level = 0;
	}

	vrq->level = level;

	trace_vip_schedule(prev->pid, prev_prio, next->pid, next_prio,
			   level, plat_task_util(next));

	if (vrq->level != 2 || list_empty(&vrq->queue))
		return;

	tail = list_last_entry(&vrq->queue, struct vip_task,
			       queue_node)->task;
	kick_vip_balance(vrq, tail);
}
EXPORT_SYMBOL_GPL(vip_sched_schedule);

/* ------------------------------------------------------------------ */
/* dada: kick_vip_balance / vip_csd_func / vip_balance_commit          */
/* ------------------------------------------------------------------ */

/*
 * [dada can_migrate_vip, inlined in vip_balance_commit] The five
 * migration rules; all must pass for a candidate to move to dst_cpu.
 */
static bool __can_migrate_vip(struct vip_task *v, int dst_cpu,
			      struct vip_rq *src_vrq)
{
	struct task_struct *p = v->task;
	struct cpumask prefer;
	int dst_top = vip_cpu_hprio(dst_cpu);
	int reason = 0;

	if (!cpumask_test_cpu(dst_cpu, p->cpus_ptr))
		reason = 1;		/* not allowed on dst */
	else if (p->on_cpu)
		reason = 2;		/* currently running */
	else if (dst_top && v->vip_prio <= dst_top)
		reason = 3;		/* weak vip must not invade */
	else if (plat_capacity_orig_of(dst_cpu) < plat_task_util(p))
		reason = 4;		/* dst too small for the task */
	else {
		cpumask_clear(&prefer);
		plat_get_group_prefer_cpus(p, &prefer);
		if (!cpumask_empty(&prefer) &&
		    !cpumask_test_cpu(dst_cpu, &prefer) &&
		    src_vrq->level != 2)
			reason = 5;	/* group prefer mismatch */
	}

	trace_can_migrate_vip(dst_cpu, p->pid, v->vip_prio, !reason, reason);
	return !reason;
}

/*
 * [dada vip_balance_commit @ .text+0x369c + inlined find_emerg_cpu]
 * Migration engine.  Called with the *destination* cpu's vip_rq; pulls
 * one vip from the most congested source cpu.  @dst_locked says the dst
 * rq lock is already held (newidle hook context) - [PORT-DELTA].
 */
static int __vip_balance_commit(struct vip_rq *vrq, bool dst_locked)
{
	struct rq *dst_rq = cpu_rq(vrq->cpu), *src_rq;
	unsigned long flags;
	struct vip_task *pos, *victim = NULL;
	struct vip_rq *src_vrq;
	int src_cpu = -1, dst_cpu = vrq->cpu, cpu;

	if (atomic_read(&sys_vip_stats) == 0)
		return false;
	if (vrq->busy)
		return false;
	vrq->busy = true;

	/* find_emerg_cpu scan: highest-numbered congested source. */
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		if (!cpu_online(cpu) || cpu == dst_cpu)
			continue;
		src_vrq = per_cpu_ptr(&vip_rq, cpu);
		if (src_vrq->level == 2 ||
		    src_vrq->nr_queued < VIP_EMERG_NR_MIN)
			continue;
		src_cpu = cpu;
	}

	if (src_cpu < 0) {
		vrq->busy = false;
		return false;
	}
	src_vrq = per_cpu_ptr(&vip_rq, src_cpu);
	trace_find_emerg_cpu(src_cpu, src_vrq->level, src_vrq->nr_queued);

	src_rq = cpu_rq(src_cpu);
	/*
	 * Trylock (audit P0-1): the tick and newidle callers already hold
	 * their own rq lock while other cpus run the same pull against us,
	 * so a plain lock can form dst->src / src->dst rq-lock cycles and
	 * freeze the scheduler.  Migration is best-effort: fail the pull
	 * instead of waiting.  Returning here also keeps vrq->busy honest
	 * (audit P0-3 - a stuck busy flag silently kills the pull channel).
	 */
	if (!raw_spin_trylock_irqsave(&src_rq->__lock, flags)) {
		vrq->busy = false;
		return false;
	}
	/* victim = lowest-prio (tail) source vip that may migrate. */
	list_for_each_entry_reverse(pos, &src_vrq->queue, queue_node) {
		if (__can_migrate_vip(pos, dst_cpu, src_vrq)) {
			victim = pos;
			break;
		}
	}
	if (victim) {
		struct task_struct *chosen = victim->task;

		deactivate_task(src_rq, chosen, 0);
		set_task_cpu(chosen, dst_cpu);
	}
	raw_spin_unlock_irqrestore(&src_rq->__lock, flags);

	if (victim) {
		struct task_struct *chosen = victim->task;

		if (!dst_locked)
			raw_spin_lock_irqsave(&dst_rq->__lock, flags);
		activate_task(dst_rq, chosen, 0);
		check_preempt_curr(dst_rq, chosen, 0);
		if (!dst_locked)
			raw_spin_unlock_irqrestore(&dst_rq->__lock, flags);
	}

	vrq->busy = false;
	trace_vip_balance(src_cpu, dst_cpu,
			  victim ? victim->task->pid : -1);
	return victim != NULL;
}

/* [dada vip_balance_commit] plain shape: dst rq not locked. */
static int vip_balance_commit(struct vip_rq *vrq)
{
	return __vip_balance_commit(vrq, false);
}

/*
 * [dada kick_vip_balance @ .text+0x3370] IPI @target so it pulls one of
 * our queued vips.  Idempotent per target via kick_pending + csd.
 */
static void kick_vip_balance(struct vip_rq *vrq, struct task_struct *p)
{
	struct vip_rq *target_vrq;
	int target, src_cpu;

	if (!vrq || !p)
		return;
	if (!get_vip_prio(p))
		return;

	src_cpu = vrq->cpu;
	if (!cpu_active(src_cpu))
		return;

	target = find_vip_cpu(p);
	if (target < 0 || target == src_cpu)
		return;

	target_vrq = per_cpu_ptr(&vip_rq, target);
	if (test_and_set_bit(0, (unsigned long *)&target_vrq->kick_pending))
		return;

	smp_call_function_single_async(target, &target_vrq->csd);
	trace_kick_vip_balance(src_cpu, target, p->pid, false);
}

/* [dada vip_csd_func @ .text+0x3e7c] runs on the kicked cpu. */
static void vip_csd_func(void *info)
{
	struct vip_rq *vrq = info;

	if (test_and_clear_bit(0, (unsigned long *)&vrq->kick_pending))
		vip_balance_commit(vrq);
}

/* ------------------------------------------------------------------ */
/* dada: vip_sched_scheduler_tick / vip_sched_newidle_balance          */
/* ------------------------------------------------------------------ */

/*
 * [dada vip_sched_scheduler_tick @ .text+0x3568] Per-tick vip upkeep:
 *  - nothing queued: reset level, and (if this cpu is not halted) pull
 *    a vip from a congested cpu; dada re-reads the queue state after
 *    the pull and we do the same.
 *  - a non-vip, non-idle task running while vips are queued: escalate
 *    to level 2.
 *  - >= 2 vips queued and no idle cpu in the freq domain: escalate to
 *    level 2 and kick the tail vip away.
 * [PORT-DELTA] dada wraps the body in raw_spin_lock(rq)/unlock because
 * its built-in caller runs without the rq lock; 5.15's
 * android_vh_scheduler_tick fires inside scheduler_tick() with the lock
 * held, so the lock pair is omitted here.
 */
void vip_sched_scheduler_tick(struct rq *rq)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	struct task_struct *curr;

	if (vrq->nr_queued == 0) {
		vrq->level = 0;
		if (!plat_cpu_halted(cpu_of(rq)))
			vip_balance_commit(vrq);
		if (vrq->nr_queued == 0)
			return;
	}

	curr = rq->curr;
	if (curr && !get_vip_prio(curr) && !(curr->flags & PF_IDLE))
		vrq->level = 2;

	if (vrq->nr_queued < VIP_EMERG_NR_MIN)
		return;

	if (plat_find_idle_cpu_in_freq_domain(rq->curr) < 0)
		vrq->level = 2;

	if (vrq->level != 2 || list_empty(&vrq->queue))
		return;

	kick_vip_balance(vrq,
			 list_last_entry(&vrq->queue, struct vip_task,
					 queue_node)->task);
}
EXPORT_SYMBOL_GPL(vip_sched_scheduler_tick);

/*
 * [dada vip_sched_newidle_balance @ .text+0x3dd0] about to go idle:
 * pull a vip from a congested cpu right now.  dada tail-calls
 * vip_balance_commit(rq's vrq) and returns its result; here the dst rq
 * lock is already held by the hook context ([PORT-DELTA]).
 */
int vip_sched_newidle_balance(struct rq *rq, struct rq_flags *rf,
			      int *pulled_task, int *done)
{
	struct vip_rq *vrq = per_cpu_ptr(&vip_rq, cpu_of(rq));
	int ret;

	ret = __vip_balance_commit(vrq, true);
	if (ret > 0) {
		*pulled_task = ret;
		*done = 1;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(vip_sched_newidle_balance);

/* ------------------------------------------------------------------ */
/* perf_actuator ioctls (userspace front end)                          */
/* ------------------------------------------------------------------ */

struct vip_prio_arg {
	int pid;
	int prio;
};

struct vip_thres_arg {
	u64 wait_thres;
	u64 vip_wait_thres;
};

/* [dada perf_actuator_set_vip_prio @ .text+0x43e0] */
static int perf_actuator_set_vip_prio(unsigned long arg)
{
	struct vip_prio_arg data = { 0, 0 };
	struct task_struct *p;
	struct rq_flags rf;
	struct rq *rq;
	int ret;

	mutex_lock(&vip_update_lock);

	if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
		ret = -EFAULT;
		goto out_unlock;
	}

	rcu_read_lock();
	p = find_task_by_vpid(data.pid);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();
	if (!p) {
		ret = -ESRCH;
		goto out_unlock;
	}

	rq = task_rq_lock(p, &rf);
	ret = set_vip_prio_locked(p, data.prio, data.prio > 0);
	task_rq_unlock(rq, p, &rf);

	put_task_struct(p);
out_unlock:
	mutex_unlock(&vip_update_lock);
	return ret;
}

/* [dada perf_actuator_set_vip_wait_thres @ .text+0x4588] */
static int perf_actuator_set_vip_wait_thres(unsigned long arg)
{
	struct vip_thres_arg data = { 0, 0 };
	int ret;

	mutex_lock(&vip_update_lock);

	if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
		ret = -EFAULT;
		goto out_unlock;
	}

	WRITE_ONCE(g_wait_time_thres, data.wait_thres);
	WRITE_ONCE(g_vip_wait_time_thres, data.vip_wait_thres);
	ret = 0;

out_unlock:
	mutex_unlock(&vip_update_lock);
	return ret;
}

/* ------------------------------------------------------------------ */
/* vendor hook adapters                                                */
/* ------------------------------------------------------------------ */

static void vip_hook_enqueue_task(void *data, struct rq *rq,
				  struct task_struct *p, int flags)
{
	enqueue_vip_task(rq, p);
}

static void vip_hook_dequeue_task(void *data, struct rq *rq,
				  struct task_struct *p, int flags)
{
	dequeue_vip_task(rq, p);
}

static void vip_hook_select_task_rq_fair(void *data, struct task_struct *p,
					 int prev_cpu, int sd_flag,
					 int wake_flags, int *new_cpu)
{
	vip_sched_select_task_rq_fair(p, prev_cpu, sd_flag, wake_flags,
				      new_cpu);
}

static void vip_hook_check_preempt_wakeup(void *data, struct rq *rq,
					  struct task_struct *p,
					  bool *preempt, bool *nopreempt,
					  int wake_flags,
					  struct sched_entity *se,
					  struct sched_entity *pse,
					  int next_buddy_marked,
					  unsigned int granularity)
{
	vip_sched_check_preempt_wakeup(rq, p, preempt, nopreempt);
}

static void vip_hook_replace_next_task_fair(void *data, struct rq *rq,
					    struct task_struct **pnext,
					    struct sched_entity **pse,
					    bool *repick_done, bool simple,
					    struct task_struct *prev)
{
	vip_sched_replace_next_task_fair(rq, pnext, pse, repick_done, simple,
					 prev);
}

static void vip_hook_schedule(void *data, struct task_struct *prev,
			      struct task_struct *next, struct rq *rq)
{
	vip_sched_schedule(prev, next, rq);
}

static void vip_hook_scheduler_tick(void *data, struct rq *rq)
{
	vip_sched_scheduler_tick(rq);
}

static void vip_hook_newidle_balance(void *data, struct rq *this_rq,
				     struct rq_flags *rf, int *pulled_task,
				     int *done)
{
	vip_sched_newidle_balance(this_rq, rf, pulled_task, done);
}

static void vip_hook_free_task(void *data, struct task_struct *p)
{
	/*
	 * Exit always dequeued the task first (dequeue hook), so its
	 * queue node is expected to be free here; reclaim the entry.
	 */
	vip_task_remove(p);
}

static void vip_hook_finish_prio_fork(void *data, struct task_struct *p)
{
	vip_init_task(p);
}

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */

static int __init vip_sched_init(void)
{
	int cpu, ret;

	for_each_possible_cpu(cpu)
		vip_init_rq(cpu);

	ret = register_perf_actuator(SET_VIP_PRIO,
				     perf_actuator_set_vip_prio);
	if (ret) {
		pr_err("vip_sched: register_perf_actuator(SET_VIP_PRIO) %d\n",
		       ret);
		return ret;
	}

	ret = register_perf_actuator(SET_VIP_WAIT_THRES,
				     perf_actuator_set_vip_wait_thres);
	if (ret) {
		unregister_perf_actuator(SET_VIP_PRIO);
		pr_err("vip_sched: register_perf_actuator(SET_VIP_WAIT_THRES) %d\n",
		       ret);
		return ret;
	}

	ret = register_trace_android_rvh_enqueue_task(vip_hook_enqueue_task,
						      NULL);
	if (ret)
		goto err;
	ret |= register_trace_android_rvh_dequeue_task(vip_hook_dequeue_task,
						       NULL);
	ret |= register_trace_android_rvh_select_task_rq_fair(
			vip_hook_select_task_rq_fair, NULL);
	ret |= register_trace_android_rvh_check_preempt_wakeup(
			vip_hook_check_preempt_wakeup, NULL);
	ret |= register_trace_android_rvh_replace_next_task_fair(
			vip_hook_replace_next_task_fair, NULL);
	ret |= register_trace_android_rvh_schedule(vip_hook_schedule, NULL);
	ret |= register_trace_android_vh_scheduler_tick(
			vip_hook_scheduler_tick, NULL);
	ret |= register_trace_android_rvh_sched_newidle_balance(
			vip_hook_newidle_balance, NULL);
	ret |= register_trace_android_vh_free_task(vip_hook_free_task, NULL);
	ret |= register_trace_android_rvh_finish_prio_fork(
			vip_hook_finish_prio_fork, NULL);
	if (ret)
		goto err;

	/*
	 * DECLARE_RESTRICTED_HOOK probes have no unregister API and
	 * android_rvh_probe_register() does not pin the module (verified:
	 * kernel/tracepoint.c:843 has no refcounting), so the module must
	 * pin itself: without this, rmmod leaves the rq-lock-path probes
	 * dangling into freed module memory (reviewer blocker 1).
	 */
	if (THIS_MODULE)
		__module_get(THIS_MODULE);
	pr_info("vip_sched: MI QOS sched Driver (Sew 5.15 port) ready\n");
	return 0;

err:
	unregister_trace_android_vh_free_task(vip_hook_free_task, NULL);
	unregister_trace_android_vh_scheduler_tick(vip_hook_scheduler_tick,
						   NULL);
	tracepoint_synchronize_unregister();
	unregister_perf_actuator(SET_VIP_WAIT_THRES);
	unregister_perf_actuator(SET_VIP_PRIO);
	pr_err("vip_sched: vendor hook registration failed %d\n", ret);
	return ret;
}
module_init(vip_sched_init);

static void __exit vip_sched_exit(void)
{
	/*
	 * DECLARE_HOOK (android_vh_*) tracepoints generate standard
	 * unregister helpers; DECLARE_RESTRICTED_HOOK (android_rvh_*)
	 * vendor hooks cannot be unregistered (vendor_hooks.h: "vendor
	 * hooks cannot be unregistered") and android_rvh_probe_register()
	 * does not pin the module - init pins it with __module_get(), so
	 * this exit is only reachable for the refcount held by module
	 * removal itself failing; in practice the module stays loaded.
	 */
	unregister_trace_android_vh_free_task(vip_hook_free_task, NULL);
	unregister_trace_android_vh_scheduler_tick(vip_hook_scheduler_tick,
						   NULL);

	unregister_perf_actuator(SET_VIP_WAIT_THRES);
	unregister_perf_actuator(SET_VIP_PRIO);
	/* probe arrays are read under preempt_disable (RCU-sched), the
	 * pairing API is tracepoint_synchronize_unregister() (reviewer
	 * major 7; same pattern as rtg/mi_reclaim exits) */
	tracepoint_synchronize_unregister();
}
module_exit(vip_sched_exit);

MODULE_AUTHOR("Shaohua Fan <fanshaohua@xiaomi.com>");
MODULE_DESCRIPTION("MI QOS sched Driver");
MODULE_LICENSE("GPL v2");
