// SPDX-License-Identifier: GPL-2.0-only
/*
 * xr_qi: QOS-inheritance on the futex/mutex/rtmutex/rwsem/binder wait
 * chains, port of the Xiaomi OS4 xr_qi module ("MI QOS inherit Driver",
 * Shaohua Fan <fanshaohua@xiaomi.com>; binary RE'd from
 * os4_dada/ko/xr_qi.ko, vermagic 6.6.57-android15-8, deps
 * perf_actuator/vip_sched/plat_common).  Propagate importance from a
 * lock holder to waiters: waiters of the configured "vip" tgid get a
 * uclamp_min floor while blocked, and the floor is handed to the lock
 * owner until it releases, so the EAS places both on capable cores.
 *
 * RE basis (see .omz/research/.../raw/re-xr-qi-full.txt): the dada
 * module consumes 42 android_vh_* tracepoints, defines 32 qi_/qos_
 * tracepoints of its own and exports 50 symbols (qievent notifier
 * chain, per-chain vh register switches qi_vh_*_register, QoS query/
 * operation family, iter_* per-chain hook callbacks, GPU-blocked and
 * stats/sysctl APIs).  Of its 42 hooks, 33 exist on the 5.15 GKI tree;
 * the rtmutex hook family (absent from the dada hook set because 6.6
 * mutex hooks cover that path there) exists here in full and is ported
 * as a first-class chain.
 *
 * Hook closure vs dada (40 registered = 33 dada hooks present on 5.15
 * + the Sew futex wait_start channel dada does not consume + 6
 * 5.15-only rtmutex hooks):
 *  - futex 4/5 (wait_queue_start missing on 5.15 -> PORT-DELTA)
 *  - mutex 8/8 (incl. alter_mutex_list_add as the exported dada
 *    callback os_cpu_android_vh_alter_mutex_list_add)
 *  - rtmutex 6/6 (5.15-only chain: wait_start/finish,
 *    task_blocks_on_rtmutex, waiter_prio, rt_mutex_steal,
 *    record_rtmutex_lock_starttime)
 *  - rwsem 10/10 + percpu-rwsem 2/3 (percpu_rwsem_init missing)
 *  - binder 6/6, task lifecycle 3/5 (mmap_lock_init/free missing)
 *  - fuse 0/2, rcu 0/4 (hooks missing on 5.15 -> PORT-DELTA)
 *
 * Exported interface (41 symbols, aligned with the dada nm list):
 *  - call_qievent_notifiers + struct qi_qievent_info (event codes
 *    mirror xr_qs.c: 1=set 2=reset 3=restore 4=inherit 5/6=... 7=detach)
 *  - QoS queries: get_task_qi/get_alloc_task_qi (NULL - no vendor pad),
 *    get_static_qos_lvl/get_proc_static_qos_lvl (static_prio derived,
 *    same formula as the xr_qs.c stand-in), get_dyn_qos_lvl
 *    (uclamp_req derived), get_qos_lvl/get_task_qos/get_task_qos_lvl
 *    (max of both), get_task_prio (update_static_prio table, dada
 *    default 120), is_qi_feat_enabled/is_qos_task (lvl > 5)/
 *    is_qos_rt_task
 *  - operations: kern_qi_set_qos (qos 0..10, dada range check),
 *    do_qos_inherit/undo_qos_inherit (qievent 4/3 producers),
 *    update_static_prio(task, prio, rt_prio; negatives skipped)
 *  - chain switches: qi_vh_{futex,mutex,rwsem,percpu_rwsem,binder,
 *    comm,fuse,rcu}_register/_unregister (dada: whole-chain register
 *    switches; comm carries the task-lifecycle hooks, fuse/rcu are
 *    empty because their upstream hooks are missing on 5.15)
 *  - stats/sysctl/GPU stubs aligned with the dada symbol list
 *
 * PORT-DELTA vs dada (5.15 not supportable, documented not stubbed):
 *  - register_qievent_notifier/unregister_qievent_notifier are exported
 *    here (dada names): kernel/sched/xr_qs.c migrated onto this chain,
 *    dropping its local stand-in.  Load order xr_qi -> xr_qs mirrors
 *    the dada depends= edge.
 *  - iter_{futex,mutex,rwsem,percpu_rwsem,binder,fuse,qos}_qos_inherit:
 *    in dada these are the per-chain hook callback bodies (addresses
 *    adjacent to the matching qi_vh_*_register).  Here the callbacks
 *    are private sew_qi_* functions; the symbols are not re-exported
 *    as empty shells.
 *  - qi_/qos_ tracepoints (32): no kbuild trace-header plumbing for
 *    in-tree modules here; the peer-module event channel is the
 *    qievent notifier chain, the BPF channel is absent.
 *  - 9 hooks missing on 5.15: percpu_rwsem_init, futex_wait_queue_
 *    start, fuse_request_end_ext/fetch, rcu_boost_start/end,
 *    sync_rcu_wait_start/end, mmap_lock_init/free.
 *  - qi task vendor pad (task+0x12c0, qi at pad+0x38): no 5.15
 *    equivalent - QoS levels are derived (see queries above), the
 *    qi struct accessors return NULL, the 6.6 refcounted set/dyn
 *    level store collapses to the uclamp hint slots.
 *  - qi_sysctl/qi_stats register: dada registers a 2-entry sysctl
 *    table (mutex qos/normal opt-spin time); opt-spin tuning is out of
 *    scope here (can_spin/opt_spin hooks are counted, not tuned), so
 *    both register pairs are no-op success stubs.
 *  - GPU-blocked queries: dada marks them via its own qi_gpu_blocked/
 *    unblocked tracepoints, which have no in-kernel producer here;
 *    the query interface is exported and reports "not blocked".
 *  - rt_mutex_steal / rtmutex_waiter_prio: no lock context to locate
 *    the vip waiter, so they are counted only and never veto.
 *  - binder_transaction/proc/buffer hook parameters stay opaque (the
 *    struct definitions are not exported); inheritance keys off the
 *    task_struct parameters only.
 *  - The 6.6 reader-owner re-target on rwsem release (per-sem reader
 *    list) stays unported: the floor is dropped when the tracked owner
 *    releases (pre-R11 behaviour of this port).
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/mutex.h>
#include <linux/rtmutex.h>
#include <linux/rwsem.h>
#include <linux/futex.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <trace/hooks/futex.h>
#include <trace/hooks/dtask.h>
#include <trace/hooks/rwsem.h>
#include <trace/hooks/binder.h>
#include <trace/hooks/sched.h>

#define SEW_QI_UCLAMP_MIN_DEFAULT 256 /* 25% of 1024 */

/* Mirror of kernel/sched/core.c uclamp_bucket_id() (static there). */
#define SEW_QI_BUCKET_DELTA \
	DIV_ROUND_CLOSEST(SCHED_CAPACITY_SCALE, UCLAMP_BUCKETS)

/*
 * kernel/locking/mutex.c keeps MUTEX_FLAG_WAITERS|HANDOFF|PICKUP in the
 * low three bits of lock->owner (private define there); strip them the
 * same way the dada module does (ands #~0x7).
 */
#define SEW_QI_MUTEX_OWNER_MASK	~0x07UL

/*
 * kernel/locking/rwsem.c keeps RWSEM_READER_OWNED (bit 0) and
 * RWSEM_NONSPINNABLE (bit 1) in sem->owner and RWSEM_FLAG_HANDOFF
 * (bit 2) in sem->count (private defines there); mask/set them the
 * same way the dada module does (owner ands #~0x3, handoff ors #0x4).
 */
#define SEW_QI_RWSEM_OWNER_MASK	~0x03UL
#define SEW_QI_RWSEM_HANDOFF	(1UL << 2)

/* kern_qi_set_qos range (dada: cmp #0xb on the masked level). */
#define SEW_QI_QOS_MAX		10
/* qos level -> uclamp_min floor for the API channels. */
#define SEW_QI_QOS_FLOOR(lvl)	min(1024U, ((unsigned int)(lvl)) << 7)

/*
 * Hint slot kinds. Futex slots are keyed by tid only; the lock-chain
 * waiter kinds carry lock_ptr so the rspin/steal veto paths can ask
 * "does a vip waiter sit on THIS lock".  Owner kinds hold a
 * task_struct reference instead.
 */
#define SEW_QI_HINT_FUTEX	1
#define SEW_QI_HINT_MWAITER	2
#define SEW_QI_HINT_DOWNER	3
#define SEW_QI_HINT_RWWAITER	4
#define SEW_QI_HINT_ROWNER	5
#define SEW_QI_HINT_RTMWAITER	6
#define SEW_QI_HINT_RTMOWNER	7
#define SEW_QI_HINT_BWAITER	8
#define SEW_QI_HINT_INHERIT	9
#define SEW_QI_HINT_PWAITER	10

/* forward decl: the dada-named alter callback feature-gates on this */
bool is_qi_feat_enabled(int feat);

static pid_t sew_qi_vip_tgid;
static unsigned int sew_qi_uclamp_min = SEW_QI_UCLAMP_MIN_DEFAULT;
static atomic64_t sew_qi_hinted_waits;
static atomic64_t sew_qi_mutex_hints;
static atomic64_t sew_qi_rwsem_hints;
static atomic64_t sew_qi_rtmutex_hints;
static atomic64_t sew_qi_binder_hints;
/* passive (count-only) hook firings across all chains */
static atomic64_t sew_qi_passive_events;

/*
 * Save/restore slots. Futex/API slots are keyed by tid (not tgid): if
 * the user re-points vip_tgid while a hinted task is still blocked,
 * the undo path must still restore that task (reviewer finding).  Lock
 * waiter slots are also keyed by tid and additionally remember the
 * lock pointer.  Owner slots are keyed by task pointer on the owner
 * side (which keeps a reference).  Bounded ring of slots; a full table
 * refuses further hints rather than corrupting state.
 *
 * The uclamp_req write itself stays lock-free, mirroring the OS4
 * original: a torn bitfield read self-corrects on the next bucket
 * update, and rq aggregation catches up at the next enqueue/dequeue.
 */
#define SEW_QI_HINT_SLOTS 32
struct sew_qi_hint {
	int			tid;		/* waiter-kind key; -1 on owner slots */
	unsigned int		prev_value;
	struct task_struct	*owner_task;	/* owner slots hold a reference */
	void			*lock_ptr;	/* waiter kinds: lock waited on */
	unsigned char		kind;
};
static struct sew_qi_hint sew_qi_hints[SEW_QI_HINT_SLOTS];
static DEFINE_SPINLOCK(sew_qi_hint_lock);
static atomic_t sew_qi_active_hints;

/* update_static_prio / get_task_prio backing table (dada qi+0x98/0x9c). */
#define SEW_QI_PRIO_SLOTS 16
struct sew_qi_prio {
	struct task_struct	*task;
	int			prio;
	int			rt_prio;
};
static struct sew_qi_prio sew_qi_prio_tbl[SEW_QI_PRIO_SLOTS];

/* dada is_qi_feat_enabled: feature bitmap gate (default: all on). */
static u32 sew_qi_feat_bitmap = 0xffffffffu;

/* qievent notifier chain (dada: blocking notifier, event codes in xr_qs.c). */
struct qi_qievent_info {
	struct task_struct	*from_task;
	struct task_struct	*task;
	int			prio;
	int			qos;
	unsigned int		flags;
	unsigned int		grp;
};
static BLOCKING_NOTIFIER_HEAD(sew_qi_qievent_chain);

static void sew_qi_wait_start(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;
	unsigned long irqflags;
	bool reuse = false;
	int i, slot = -1;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * Tracepoint probes run with preemption disabled, so only
	 * non-sleeping work happens here (spinlock is fine).
	 */
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	/*
	 * Kind-filtered search (reviewer major 1): an unfiltered tid
	 * match would hijack another chain's slot (INHERIT/MWAITER/...),
	 * flipping its kind and leaking its undo channel.
	 */
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].tid == t->pid &&
		    sew_qi_hints[i].kind == SEW_QI_HINT_FUTEX) {
			slot = i;
			reuse = true;
			break;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot >= 0) {
		sew_qi_hints[slot].tid = t->pid;
		if (!reuse)
			/* fresh slot: snapshot the baseline.  On reuse the
			 * existing baseline is the original pre-boost value;
			 * re-snapshotting would capture the floor itself
			 * and the floor would never restore (audit P1). */
			sew_qi_hints[slot].prev_value =
				t->uclamp_req[UCLAMP_MIN].value;
		sew_qi_hints[slot].owner_task = NULL;
		sew_qi_hints[slot].lock_ptr = NULL;
		sew_qi_hints[slot].kind = SEW_QI_HINT_FUTEX;
		if (!reuse)
			atomic_inc(&sew_qi_active_hints);
		/* uclamp_bucket_id() is core.c-static; same mapping inline. */
		t->uclamp_req[UCLAMP_MIN].value = sew_qi_uclamp_min;
		t->uclamp_req[UCLAMP_MIN].bucket_id =
			min_t(unsigned int,
			      sew_qi_uclamp_min / SEW_QI_BUCKET_DELTA,
			      (unsigned int)(UCLAMP_BUCKETS - 1));
		atomic64_inc(&sew_qi_hinted_waits);
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

static void sew_qi_wait_end(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;
	unsigned long irqflags;
	int i;

	/* Fast exit: no hinted task in flight (common case). */
	if (!atomic_read(&sew_qi_active_hints))
		return;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].tid == t->pid &&
		    sew_qi_hints[i].kind == SEW_QI_HINT_FUTEX) {
			t->uclamp_req[UCLAMP_MIN].value =
				sew_qi_hints[i].prev_value;
			t->uclamp_req[UCLAMP_MIN].bucket_id =
				min_t(unsigned int,
				      sew_qi_hints[i].prev_value / SEW_QI_BUCKET_DELTA,
				      (unsigned int)(UCLAMP_BUCKETS - 1));
			sew_qi_hints[i].tid = 0;
			sew_qi_hints[i].kind = 0;
			atomic_dec(&sew_qi_active_hints);
			break;
		}
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

/*
 * Raise uclamp_min for @target and remember the previous value in
 * @slot. Caller holds sew_qi_hint_lock and has already filled
 * tid/owner_task/lock_ptr/kind.
 */
static void sew_qi_mhint_apply(struct sew_qi_hint *slot,
			       struct task_struct *target)
{
	slot->prev_value = target->uclamp_req[UCLAMP_MIN].value;
	atomic_inc(&sew_qi_active_hints);
	target->uclamp_req[UCLAMP_MIN].value = sew_qi_uclamp_min;
	target->uclamp_req[UCLAMP_MIN].bucket_id =
		min_t(unsigned int,
		      sew_qi_uclamp_min / SEW_QI_BUCKET_DELTA,
		      (unsigned int)(UCLAMP_BUCKETS - 1));
}

/* Same floor write with an explicit value (API channels, per-level). */
static void sew_qi_mhint_apply_val(struct sew_qi_hint *slot,
				   struct task_struct *target,
				   unsigned int floor)
{
	slot->prev_value = target->uclamp_req[UCLAMP_MIN].value;
	atomic_inc(&sew_qi_active_hints);
	target->uclamp_req[UCLAMP_MIN].value = floor;
	target->uclamp_req[UCLAMP_MIN].bucket_id =
		min_t(unsigned int,
		      floor / SEW_QI_BUCKET_DELTA,
		      (unsigned int)(UCLAMP_BUCKETS - 1));
}

/*
 * Drop the first live hint of kind @kind held by task @t and restore its
 * uclamp_min. For owner slots the stored task_struct reference is put
 * back here.
 */
static void sew_qi_mhint_restore(struct task_struct *t, unsigned char kind)
{
	unsigned long irqflags;
	int i;

	if (!atomic_read(&sew_qi_active_hints))
		return;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		struct sew_qi_hint *h = &sew_qi_hints[i];

		if (h->kind != kind)
			continue;
		if (h->owner_task) {
			if (h->owner_task != t)
				continue;
			put_task_struct(h->owner_task);
			h->owner_task = NULL;
		} else if (h->tid != t->pid) {
			continue;
		}
		t->uclamp_req[UCLAMP_MIN].value = h->prev_value;
		t->uclamp_req[UCLAMP_MIN].bucket_id =
			min_t(unsigned int,
			      h->prev_value / SEW_QI_BUCKET_DELTA,
			      (unsigned int)(UCLAMP_BUCKETS - 1));
		h->tid = 0;
		h->lock_ptr = NULL;
		h->kind = 0;
		atomic_dec(&sew_qi_active_hints);
		break;
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

/*
 * Waiter-side floor for a lock-chain waiter: find the slot keyed by the
 * waiter's tid for @kind (reuse it when re-queueing on the same lock
 * class), apply the floor and remember @lock_ptr.  Returns true when a
 * hint was placed.  Caller must have gated on vip_tgid already.
 */
static bool sew_qi_waiter_floor(struct task_struct *t, void *lock_ptr,
				unsigned char kind, atomic64_t *ctr)
{
	unsigned long irqflags;
	int i, slot = -1;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == kind &&
		    sew_qi_hints[i].tid == t->pid) {
			sew_qi_hints[i].lock_ptr = lock_ptr;
			spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
			return true; /* already hinted: keep original floor */
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot < 0) {
		spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
		return false; /* table full */
	}
	sew_qi_hints[slot].tid = t->pid;
	sew_qi_hints[slot].owner_task = NULL;
	sew_qi_hints[slot].lock_ptr = lock_ptr;
	sew_qi_hints[slot].kind = kind;
	sew_qi_mhint_apply(&sew_qi_hints[slot], t);
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	atomic64_inc(ctr);
	return true;
}

/*
 * Owner-side inheritance (dada: do_*_qos_inherit(owner)): a vip waiter
 * hands its floor to whoever currently holds the lock, so the holder
 * reaches unlock faster.  The reference keeps the owner task alive
 * until the undo channel runs.  Idempotent per (kind, owner).
 */
static void sew_qi_owner_inherit(struct task_struct *owner, unsigned char kind,
				 atomic64_t *ctr)
{
	unsigned long irqflags;
	int i, slot = -1;

	if (!owner)
		return;
	get_task_struct(owner);

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == kind &&
		    sew_qi_hints[i].owner_task == owner) {
			slot = -1; /* already hinted: drop extra ref */
			goto out_owner;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot < 0)
		goto out_owner; /* table full */
	sew_qi_hints[slot].tid = -1;
	sew_qi_hints[slot].owner_task = owner; /* reference transferred */
	sew_qi_hints[slot].lock_ptr = NULL;
	sew_qi_hints[slot].kind = kind;
	sew_qi_mhint_apply(&sew_qi_hints[slot], owner);
	atomic64_inc(ctr);
	owner = NULL;
out_owner:
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	if (owner)
		put_task_struct(owner);
}

/* Combined waiter-floor + owner-inherit entry for the lock chains. */
static void sew_qi_pair_inherit(struct task_struct *t, void *lock_ptr,
				struct task_struct *owner,
				unsigned char wkind, unsigned char okind,
				atomic64_t *ctr)
{
	sew_qi_waiter_floor(t, lock_ptr, wkind, ctr);
	if (owner && owner != t)
		sew_qi_owner_inherit(owner, okind, ctr);
}

/* Is a vip waiter of kind @kind currently queued on @lock? */
static bool sew_qi_waiter_on_lock(void *lock_ptr, unsigned char kind)
{
	unsigned long irqflags;
	bool found = false;
	int i;

	if (!atomic_read(&sew_qi_active_hints))
		return false;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == kind &&
		    sew_qi_hints[i].lock_ptr == lock_ptr &&
		    sew_qi_hints[i].tid >= 0) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	return found;
}

/* ---- passive (count-only) hook body ------------------------------------ */

static void sew_qi_passive(void)
{
	atomic64_inc(&sew_qi_passive_events);
}

/*
 * ---- mutex chain: handlers keep the dada xr_qi.ko symbol names where
 * ---- they are hook callbacks of the OS4 module.
 */

static void sew_qi_mutex_wait_start(void *data, struct mutex *lock)
{
	struct task_struct *t = current, *owner;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * Waiter-side floor, same record/restore pattern as the futex
	 * chain (dada records the wait on the waiter's vendor data),
	 * then owner-side inheritance from lock->owner minus the
	 * MUTEX_FLAGS (dada: do_mutex_qos_inherit(owner)).
	 */
	owner = lock ? (struct task_struct *)
		(atomic_long_read(&lock->owner) & SEW_QI_MUTEX_OWNER_MASK) :
		NULL;
	sew_qi_pair_inherit(t, lock, owner, SEW_QI_HINT_MWAITER,
			    SEW_QI_HINT_DOWNER, &sew_qi_mutex_hints);
}

static void sew_qi_mutex_wait_finish(void *data, struct mutex *lock)
{
	/* Drop the waiter-side floor (dada clears the wait record here). */
	sew_qi_mhint_restore(current, SEW_QI_HINT_MWAITER);
}

/* Owner released a mutex: undo its inherited floor. */
static void sew_qi_mutex_unlock(void *data, struct mutex *lock)
{
	sew_qi_mhint_restore(current, SEW_QI_HINT_DOWNER);
}

/*
 * mutex_unlock() fires this on both exit paths with settime_jiffies==0
 * (dada treats it as "lock released"). Second undo channel for owners
 * that leave via __mutex_unlock_fast(); restore is idempotent because
 * the slowpath channel has usually emptied the slot already.
 */
static void sew_qi_mutex_lock_released(void *data, struct task_struct *tsk,
				       unsigned long settime_jiffies)
{
	if (settime_jiffies)
		return;
	sew_qi_mhint_restore(tsk, SEW_QI_HINT_DOWNER);
}

/*
 * dada's alter_mutex_list_add callback (exported as
 * os_cpu_android_vh_alter_mutex_list_add in both trees): exact
 * enqueue-time channel for the mutex chain.  On 6.6 it reads
 * waiter+0x10 (= waiter->task); struct mutex_waiter is private to
 * kernel/locking/mutex.c on 5.15, and both call sites run in the
 * caller's context, so current IS the waiter task here.  Semantics
 * mirror the dada body: feature-gated waiter floor + owner inherit.
 * Registered through qi_vh_mutex_register().
 */
void os_cpu_android_vh_alter_mutex_list_add(void *data, struct mutex *lock,
					    struct mutex_waiter *waiter,
					    struct list_head *list,
					    bool *already_on_list)
{
	struct task_struct *t = current, *owner;

	if (!is_qi_feat_enabled(3))
		return;
	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	owner = lock ? (struct task_struct *)
		(atomic_long_read(&lock->owner) & SEW_QI_MUTEX_OWNER_MASK) :
		NULL;
	sew_qi_pair_inherit(t, lock, owner, SEW_QI_HINT_MWAITER,
			    SEW_QI_HINT_DOWNER, &sew_qi_mutex_hints);
}
EXPORT_SYMBOL_GPL(os_cpu_android_vh_alter_mutex_list_add);

/*
 * dada tunes the owner-spin budget here via its mutex qos sysctls
 * (sysctl_mutex_{qos,normal}_opt_spin_time_ns); the tuning framework is
 * a PORT-DELTA, so the three opt-spin channels are counted only.
 */
static void sew_qi_mutex_can_spin(void *data, struct mutex *lock, int *retval)
{
	sew_qi_passive();
}

static void sew_qi_mutex_opt_spin_start(void *data, struct mutex *lock,
					bool *time_out, int *cnt)
{
	sew_qi_passive();
}

static void sew_qi_mutex_opt_spin_finish(void *data, struct mutex *lock,
					 bool taken)
{
	sew_qi_passive();
}

/*
 * ---- rtmutex chain (5.15-only hook family; on 6.6 this path is
 * ---- covered by the dada mutex hooks because mutex sits on
 * ---- rt_mutex_base there).  rt_mutex_base.owner is a plain
 * ---- task_struct pointer - no flag bits to mask.
 */

static void sew_qi_rtmutex_wait_start(void *data, struct rt_mutex_base *lock)
{
	struct task_struct *t = current, *owner;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid || !lock)
		return;

	owner = READ_ONCE(lock->owner);
	sew_qi_pair_inherit(t, lock, owner, SEW_QI_HINT_RTMWAITER,
			    SEW_QI_HINT_RTMOWNER, &sew_qi_rtmutex_hints);
}

static void sew_qi_rtmutex_wait_finish(void *data, struct rt_mutex_base *lock)
{
	sew_qi_mhint_restore(current, SEW_QI_HINT_RTMWAITER);
}

/*
 * rtmutex_api.c fires this with jiffies on the acquire paths and with
 * 0 from rt_mutex_unlock()'s common exit - the release channel for
 * RTMOWNER, same shape as the mutex chain.
 */
static void sew_qi_rtmutex_lock_released(void *data, struct task_struct *tsk,
					 unsigned long settime_jiffies)
{
	if (settime_jiffies)
		return;
	sew_qi_mhint_restore(tsk, SEW_QI_HINT_RTMOWNER);
}

/*
 * Second, idempotent inheritance entry: task_blocks_on_rtmutex runs
 * under lock->wait_lock with the enqueuing task in hand (PI futex and
 * in-kernel rt_mutex users reach here even when the slowlock loop's
 * wait_start fired earlier - the waiter slot is reused, the owner is
 * re-read at the exact enqueue point).
 */
static void sew_qi_task_blocks_on_rtmutex(void *data,
					  struct rt_mutex_base *lock,
					  struct rt_mutex_waiter *waiter,
					  struct task_struct *task,
					  struct ww_acquire_ctx *ww_ctx,
					  unsigned int *chwalk)
{
	struct task_struct *owner;

	if (!sew_qi_vip_tgid || !lock || !task ||
	    task_tgid_nr(task) != sew_qi_vip_tgid)
		return;

	owner = READ_ONCE(lock->owner);
	sew_qi_pair_inherit(task, lock, owner, SEW_QI_HINT_RTMWAITER,
			    SEW_QI_HINT_RTMOWNER, &sew_qi_rtmutex_hints);
}

/* No lock context to locate a vip waiter: counted, never vetoes. */
static void sew_qi_rt_mutex_steal(void *data, int waiter_prio,
				  int top_waiter_prio, bool *ret)
{
	sew_qi_passive();
}

static void sew_qi_rtmutex_waiter_prio(void *data, struct task_struct *task,
				       int *waiter_prio)
{
	sew_qi_passive();
}

/*
 * ---- rwsem chain: handlers keep the dada xr_qi.ko symbol names. ----
 */

/*
 * android_vh_alter_rwsem_list_add: @waiter (waiter->task == current at
 * both kernel call sites) is about to be queued on @sem, which the
 * call sites hold under sem->wait_lock. A vip waiter takes the
 * waiter-side floor and hands its floor to the current owner (dada:
 * do_rwsem_qos_inherit(owner)); a vip WRITE waiter also pins the
 * handoff bit and the first waiter's handoff_set (dada feat13).
 */
static void android_vh_alter_rwsem_list_add(void *data,
					    struct rwsem_waiter *waiter,
					    struct rw_semaphore *sem,
					    bool *already_on_list)
{
	struct task_struct *t = waiter ? waiter->task : NULL, *owner;

	if (!sew_qi_vip_tgid || !t || !sem ||
	    task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * dada: pin RWSEM_FLAG_HANDOFF so the lock is transferred to the
	 * front waiter instead of being stolen by readers that keep
	 * arriving, and mark the first waiter handoff_set (core only
	 * honors handoff_set on the first waiter). The call sites hold
	 * sem->wait_lock, so touching the wait list here is safe.
	 */
	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (!(atomic_long_read(&sem->count) & SEW_QI_RWSEM_HANDOFF))
			atomic_long_or(SEW_QI_RWSEM_HANDOFF, &sem->count);
		if (list_empty(&sem->wait_list)) {
			waiter->handoff_set = true;
		} else {
			struct rwsem_waiter *first = list_first_entry(
				&sem->wait_list, struct rwsem_waiter, list);

			if (first->type == RWSEM_WAITING_FOR_WRITE)
				first->handoff_set = true;
		}
	}

	/* waiter-side floor records the sem pointer for the rspin veto */
	sew_qi_waiter_floor(t, sem, SEW_QI_HINT_RWWAITER, &sew_qi_rwsem_hints);

	/*
	 * Owner-side inheritance. rwsem.c leaves the last owning reader
	 * in sem->owner behind RWSEM_READER_OWNED, so the masked owner
	 * is a writer or that reader (dada tracks per-sem reader lists
	 * and re-targets on release; this port drops the floor when the
	 * tracked owner releases instead). The reference keeps the
	 * owner task alive until an undo channel runs.
	 */
	owner = (struct task_struct *)
		(atomic_long_read(&sem->owner) & SEW_QI_RWSEM_OWNER_MASK);
	if (owner && owner != t)
		sew_qi_owner_inherit(owner, SEW_QI_HINT_ROWNER,
				     &sew_qi_rwsem_hints);
}

static void android_vh_rwsem_read_wait_finish(void *data,
					      struct rw_semaphore *sem)
{
	/* Drop the waiter-side floor (acquired and aborted waits alike). */
	sew_qi_mhint_restore(current, SEW_QI_HINT_RWWAITER);
}

static void android_vh_rwsem_write_wait_finish(void *data,
					       struct rw_semaphore *sem)
{
	sew_qi_mhint_restore(current, SEW_QI_HINT_RWWAITER);
}

/* The writer released the sem: undo its inherited floor. */
static void android_vh_clear_rwsem_writer_owned(void *data,
						struct rw_semaphore *sem)
{
	sew_qi_mhint_restore(current, SEW_QI_HINT_ROWNER);
}

/*
 * Reader release. dada hands the inherit to the next reader owner
 * here; this port only undoes the floor when the tracked owner (the
 * last owning reader kept in sem->owner) is the one releasing.
 */
static void android_vh_clear_rwsem_reader_owned(void *data,
						struct rw_semaphore *sem)
{
	sew_qi_mhint_restore(current, SEW_QI_HINT_ROWNER);
}

/*
 * dada (feat13): a reader optimistic steal would bypass the vip wait
 * chain, so veto it whenever the sem's wait_lock is (about to be)
 * busy. [sem+0x10] in the dada disassembly is sem->wait_lock; its raw
 * value is nonzero exactly when the qspinlock is not idle.
 */
static void android_vh_rwsem_direct_rsteal(void *data,
					   struct rw_semaphore *sem,
					   bool *steal)
{
	if (!sew_qi_vip_tgid || !steal || !sem)
		return;
	if (raw_spin_is_locked(&sem->wait_lock))
		*steal = false;
}

/*
 * Same veto family as rwsem_direct_rsteal: a reader optimistic spin in
 * rwsem_down_read_trylock's caller must not bypass a queued vip
 * waiter.  The waiter slot's lock_ptr makes the "vip waiter on THIS
 * sem" query exact (dada consults its per-sem vendor list).
 */
static void sew_qi_rwsem_optimistic_rspin(void *data, struct rw_semaphore *sem,
					  long *adjustment, bool *rspin)
{
	if (!sew_qi_vip_tgid || !sem || !rspin || !*rspin)
		return;
	if (sew_qi_waiter_on_lock(sem, SEW_QI_HINT_RWWAITER))
		*rspin = false;
}

static void sew_qi_rwsem_init(void *data, struct rw_semaphore *sem)
{
	/* dada zeroes its per-sem vendor fields; we only count inits. */
	sew_qi_passive();
}

static void sew_qi_rwsem_read_trylock_failed(void *data,
					     struct rw_semaphore *sem,
					     long *cntp, int *ret)
{
	sew_qi_passive();
}

/*
 * settime != 0 is the lock-acquired channel (dada records hold-time
 * statistics there, out of scope). settime == 0 fires from
 * __up_read() / __up_write() and is the second, idempotent release
 * channel for the owner-side floor, same shape as the mutex chain.
 */
static void android_vh_record_rwsem_lock_starttime(void *data,
						   struct task_struct *tsk,
						   unsigned long settime_jiffies)
{
	if (settime_jiffies)
		return;
	sew_qi_mhint_restore(tsk, SEW_QI_HINT_ROWNER);
}

/*
 * percpu-rwsem channels. dada registers percpu_rwsem_init too (missing
 * on 5.15).  The writer wait-queue channel takes the waiter-side floor
 * (percpu_down_write blocks in that queue); the release channel
 * (settime == 0 from percpu_up_write) undoes waiter and owner floors
 * idempotently - the pcpu owner is not separately inherited because no
 * 5.15 hook exposes it at acquire time.
 */
static void sew_qi_percpu_rwsem_wq_add(void *data,
				       struct percpu_rw_semaphore *sem,
				       bool reader)
{
	struct task_struct *t = current;

	if (reader || !sew_qi_vip_tgid ||
	    task_tgid_nr(t) != sew_qi_vip_tgid)
		return;
	sew_qi_waiter_floor(t, sem, SEW_QI_HINT_PWAITER, &sew_qi_rwsem_hints);
}

static void android_vh_record_pcpu_rwsem_starttime(void *data,
						   struct task_struct *tsk,
						   unsigned long settime_jiffies)
{
	if (settime_jiffies)
		return;
	/* PWAITER only (reviewer major 3): the pcpu-rwsem chain never
	 * creates ROWNER slots, and a blanket restore here would clear a
	 * plain-rwsem owner floor held by the same task. */
	sew_qi_mhint_restore(tsk, SEW_QI_HINT_PWAITER);
}

/*
 * ---- futex chain extras (dada consumes do_futex + the two wake
 * ---- channels for its own bookkeeping; the inheritance itself runs
 * ---- on wait_start/wait_end above). futex_wait_queue_start is a
 * ---- PORT-DELTA (hook missing on 5.15).
 */
static void sew_qi_do_futex(void *data, int cmd, unsigned int *flags,
			    u32 __user *uaddr2)
{
	sew_qi_passive();
}

static void sew_qi_futex_wake_traverse(void *data, struct plist_head *chain,
				       int *target_nr, union futex_key key,
				       u32 bitset)
{
	sew_qi_passive();
}

static void sew_qi_futex_wake_up_q_finish(void *data, int nr_wake,
					  int target_nr)
{
	sew_qi_passive();
}

/*
 * ---- binder chain. The transaction/proc/buffer hook parameters stay
 * ---- opaque (struct binder_* is not exported to modules); semantics
 * ---- key off the task_struct parameters: a vip caller hands its
 * ---- floor to the target binder thread (or proc task) for as long
 * ---- as the transaction is being serviced, undone at
 * ---- restore_priority.  dada's set_priority keeps a floor that is
 * ---- already correct (idempotent), the other three channels are
 * ---- counted.
 */
static void sew_qi_binder_transaction_init(void *data,
					   struct binder_transaction *t)
{
	sew_qi_passive();
}

static void sew_qi_binder_proc_transaction(void *data,
					   struct task_struct *caller_task,
					   struct task_struct *binder_proc_task,
					   struct task_struct *binder_th_task,
					   int node_debug_id,
					   unsigned int code, bool pending_async)
{
	struct task_struct *target = binder_th_task ? binder_th_task
						    : binder_proc_task;

	if (!sew_qi_vip_tgid || !caller_task || !target ||
	    task_tgid_nr(caller_task) != sew_qi_vip_tgid)
		return;
	sew_qi_waiter_floor(target, NULL, SEW_QI_HINT_BWAITER,
			    &sew_qi_binder_hints);
}

static void sew_qi_binder_set_priority(void *data, struct binder_transaction *t,
				       struct task_struct *task)
{
	/* Floor already placed at proc_transaction; keep it. */
	sew_qi_passive();
}

static void sew_qi_binder_restore_priority(void *data,
					   struct binder_transaction *t,
					   struct task_struct *task)
{
	if (!task)
		return;
	sew_qi_mhint_restore(task, SEW_QI_HINT_BWAITER);
}

static void sew_qi_binder_buffer_release(void *data, struct binder_proc *proc,
					 struct binder_thread *thread,
					 struct binder_buffer *buffer,
					 bool has_transaction)
{
	sew_qi_passive();
}

static void sew_qi_free_oem_binder_struct(void *data,
					  struct binder_transaction *t)
{
	sew_qi_passive();
}

/*
 * ---- task lifecycle (dada carries these under its comm chain). ----
 * dup_task_struct only counts (the uclamp_req of the child is reset by
 * core fork paths afterwards, so pre-seeding it would be lost); exit
 * and free are the slot-hygiene channels: they clear every slot that
 * references the dying task - owner slots release the pinned
 * reference, waiter slots (keyed by pid) and prio-table rows are
 * dropped.  exit_check runs early in do_exit with the task alive;
 * free_task runs before the TYPESAFE_BY_RCU slab object can be reused
 * (same guarantee the in-tree rtg.c hook consumer relies on), so the
 * pointer comparisons stay safe without dereferencing a freed task.
 */
static void sew_qi_dup_task_struct(void *data, struct task_struct *tsk,
				   struct task_struct *orig)
{
	sew_qi_passive();
}

static void sew_qi_purge_task(struct task_struct *p)
{
	unsigned long irqflags;
	bool busy;
	int i;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	busy = atomic_read(&sew_qi_active_hints) != 0;
	for (i = 0; i < SEW_QI_HINT_SLOTS && busy; i++) {
		struct sew_qi_hint *h = &sew_qi_hints[i];
		bool hit = false;

		if (h->owner_task == p) {
			put_task_struct(p);
			h->owner_task = NULL;
			hit = true;
		} else if (h->owner_task == NULL && h->tid >= 0 &&
			   h->tid == p->pid) {
			hit = true;
		}
		if (hit) {
			h->tid = 0;
			h->lock_ptr = NULL;
			h->kind = 0;
			atomic_dec(&sew_qi_active_hints);
		}
	}
	for (i = 0; i < SEW_QI_PRIO_SLOTS; i++) {
		if (sew_qi_prio_tbl[i].task == p)
			sew_qi_prio_tbl[i].task = NULL;
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

static void sew_qi_exit_check(void *data, struct task_struct *p)
{
	if (atomic_read(&sew_qi_active_hints))
		sew_qi_purge_task(p);
}

static void sew_qi_free_task(void *data, struct task_struct *p)
{
	sew_qi_purge_task(p);
}

/* ---- qievent notifier chain (dada: blocking_notifier wrappers) ------- */

/*
 * Event codes mirror the 6.6 xr_qi numbering (see xr_qs.c):
 * 1=set 2=reset 3=restore 4=inherit 5=restore-forced 6=correct
 * 7=detach.  @info is a struct qi_qievent_info *.
 */
int call_qievent_notifiers(unsigned long event, void *info)
{
	return blocking_notifier_call_chain(&sew_qi_qievent_chain, event,
					    info);
}
EXPORT_SYMBOL_GPL(call_qievent_notifiers);

int register_qievent_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&sew_qi_qievent_chain, nb);
}
EXPORT_SYMBOL_GPL(register_qievent_notifier);

int unregister_qievent_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&sew_qi_qievent_chain, nb);
}
EXPORT_SYMBOL_GPL(unregister_qievent_notifier);

/* ---- QoS query family (5.15 stand-ins, dada symbol names) ------------ */

bool is_qi_feat_enabled(int feat)
{
	if (feat < 0 || feat >= 32)
		return false;
	return READ_ONCE(sew_qi_feat_bitmap) & (1u << feat);
}
EXPORT_SYMBOL_GPL(is_qi_feat_enabled);

/*
 * dada reads the static QOS level (0..7) from the task vendor area;
 * 5.15 has no QOS framework, so derive one from static_prio - same
 * formula as the xr_qs.c stand-in: (DEFAULT_PRIO - static_prio)/10,
 * clamped to 0..7.
 */
static int sew_qi_static_lvl(struct task_struct *p)
{
	int delta = DEFAULT_PRIO - p->static_prio;

	if (delta <= 0)
		return 0;
	return min(7, (delta + 9) / 10);
}

int get_static_qos_lvl(struct task_struct *p)
{
	return p ? sew_qi_static_lvl(p) : 0;
}
EXPORT_SYMBOL_GPL(get_static_qos_lvl);

int get_proc_static_qos_lvl(struct task_struct *p)
{
	/* process-scope level on 6.6; same derivation here */
	return get_static_qos_lvl(p);
}
EXPORT_SYMBOL_GPL(get_proc_static_qos_lvl);

/*
 * Dynamic level stand-in: dada reads qi+0xc while qi+0x4 says the
 * dynamic channel is enabled.  Here the dynamic channel is the uclamp
 * hint machinery, so the level is derived from the effective requested
 * floor (128 per level, dada's kern_qi_set_qos range is 0..10).
 */
int get_dyn_qos_lvl(struct task_struct *p)
{
	if (!p)
		return 0;
	return min(10, (int)(p->uclamp_req[UCLAMP_MIN].value >> 7));
}
EXPORT_SYMBOL_GPL(get_dyn_qos_lvl);

int get_qos_lvl(struct task_struct *p)
{
	/* dada: max(dyn, static) */
	return max(get_dyn_qos_lvl(p), get_static_qos_lvl(p));
}
EXPORT_SYMBOL_GPL(get_qos_lvl);

int get_task_qos(struct task_struct *p)
{
	/*
	 * dada merges static and dynamic nibbles into one word; the
	 * consumers only branch on the magnitude, so max() suffices.
	 */
	return get_qos_lvl(p);
}
EXPORT_SYMBOL_GPL(get_task_qos);

int get_task_qos_lvl(struct task_struct *p)
{
	return get_qos_lvl(p);
}
EXPORT_SYMBOL_GPL(get_task_qos_lvl);

/* is_qos_task: dada compares the merged level against 5 ("> 5"). */
bool is_qos_task(struct task_struct *p)
{
	return get_qos_lvl(p) > 5;
}
EXPORT_SYMBOL_GPL(is_qos_task);

bool is_qos_rt_task(struct task_struct *p)
{
	return p && is_qos_task(p) && rt_task(p);
}
EXPORT_SYMBOL_GPL(is_qos_rt_task);

/*
 * 6.6 returns the per-task qi structure from the vendor pad; 5.15 has
 * no pad, so there is nothing to hand out (callers must tolerate NULL,
 * exactly like the missing-task case in dada).
 */
void *get_task_qi(struct task_struct *p)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(get_task_qi);

void *get_alloc_task_qi(struct task_struct *p)
{
	/* dada pre-allocates the qi at fork; nothing to allocate here. */
	return NULL;
}
EXPORT_SYMBOL_GPL(get_alloc_task_qi);

/* ---- QoS operation family --------------------------------------------- */

/*
 * Shared API floor: place (lvl > 0) or drop (lvl == 0) an INHERIT-kind
 * uclamp hint on @t, then fan the qievent out.  Returns -EINVAL on the
 * same conditions as dada (NULL task / level out of 0..10).
 */
static int sew_qi_api_set(struct task_struct *t, int lvl)
{
	unsigned long irqflags;
	unsigned int floor;
	int i, slot = -1;

	if (!t || lvl < 0 || lvl > SEW_QI_QOS_MAX)
		return -EINVAL;

	if (lvl == 0) {
		sew_qi_mhint_restore(t, SEW_QI_HINT_INHERIT);
		return 0;
	}

	floor = SEW_QI_QOS_FLOOR(lvl);
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == SEW_QI_HINT_INHERIT &&
		    sew_qi_hints[i].tid == t->pid) {
			/* refresh in place (idempotent); keep the FIRST
			 * baseline - apply_val() snapshots the current
			 * uclamp as prev_value, which after one apply is
			 * the floor itself, and overwriting it would make
			 * undo restore the floor instead of the original
			 * value (reviewer major 2) */
			{
				const unsigned int prev =
					sew_qi_hints[i].prev_value;

				sew_qi_mhint_apply_val(&sew_qi_hints[i], t,
						       floor);
				sew_qi_hints[i].prev_value = prev;
			}
			spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
			return 0;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot < 0) {
		spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
		return -EBUSY; /* table full */
	}
	sew_qi_hints[slot].tid = t->pid;
	sew_qi_hints[slot].owner_task = NULL;
	sew_qi_hints[slot].lock_ptr = NULL;
	sew_qi_hints[slot].kind = SEW_QI_HINT_INHERIT;
	sew_qi_mhint_apply_val(&sew_qi_hints[slot], t, floor);
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	return 0;
}

static void sew_qi_qievent_fill(struct qi_qievent_info *info,
				struct task_struct *from,
				struct task_struct *to, int lvl,
				unsigned int flags)
{
	info->from_task = from;
	info->task = to;
	info->prio = 0;
	info->qos = lvl;
	info->flags = flags;
	info->grp = 0;
}

/*
 * dada kern_qi_set_qos(task, qos): NULL task or qos > 10 -> -EINVAL,
 * qos == 0 resets.  Fires qievent 1 (set) / 2 (reset).
 */
int kern_qi_set_qos(struct task_struct *t, int qos)
{
	struct qi_qievent_info info;
	int ret;

	ret = sew_qi_api_set(t, qos);
	if (ret)
		return ret;
	sew_qi_qievent_fill(&info, NULL, t, qos, 0);
	call_qievent_notifiers(qos ? 1 : 2, &info);
	return 0;
}
EXPORT_SYMBOL_GPL(kern_qi_set_qos);
/*
 * Contract (reviewer minor): kern_qi_set_qos/do_qos_inherit/
 * undo_qos_inherit fan the qievent out through a BLOCKING notifier
 * chain, whose rwsem read-side is taken before any callback runs - a
 * preempt_count() guard inside callbacks cannot save an atomic caller.
 * Callers MUST be in process context (no rq locks, no preempt_disable).
 */

/*
 * dada do_qos_inherit(from, to, ...): propagate the source's importance
 * onto the target (6.6 walks the task vendor pad -> qi).  5.15: the
 * target takes an INHERIT floor of @lvl and qievent 4 fires; @from is
 * reported to subscribers in the event.  @flags is the dada channel
 * selector - the 5.15 port has a single channel.
 */
int do_qos_inherit(struct task_struct *from, struct task_struct *to, int lvl,
		   unsigned int flags)
{
	struct qi_qievent_info info;
	int ret;

	ret = sew_qi_api_set(to, lvl);
	if (ret)
		return ret;
	sew_qi_qievent_fill(&info, from, to, lvl, flags);
	call_qievent_notifiers(4, &info);
	return 0;
}
EXPORT_SYMBOL_GPL(do_qos_inherit);

/*
 * dada undo_qos_inherit(task, base, key, idx): removes one entry from
 * the task's eight per-chain inherit lists.  5.15 has a single
 * INHERIT slot per task, so @key/@idx have no counterpart; undo drops
 * the slot and fires qievent 3 (restore).
 */
int undo_qos_inherit(struct task_struct *task, void *key, int lvl,
		     unsigned int flags)
{
	struct qi_qievent_info info;

	if (!task)
		return -EINVAL;
	sew_qi_mhint_restore(task, SEW_QI_HINT_INHERIT);
	sew_qi_qievent_fill(&info, NULL, task, lvl, flags);
	call_qievent_notifiers(3, &info);
	return 0;
}
EXPORT_SYMBOL_GPL(undo_qos_inherit);

/*
 * dada update_static_prio(task, prio, rt_prio): stores both into
 * qi+0x98/0x9c, skipping negative inputs.  5.15 stand-in keeps them in
 * the prio table below; get_task_prio() reports the min (dada
 * get_task_prio reads qi+0x98 vs qi+0xa0, default 120 = DEFAULT_PRIO).
 */
int update_static_prio(struct task_struct *task, int prio, int rt_prio)
{
	unsigned long irqflags;
	int i, slot = -1;

	if (!task)
		return -EINVAL;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_PRIO_SLOTS; i++) {
		if (sew_qi_prio_tbl[i].task == task) {
			slot = i;
			break;
		}
		if (slot < 0 && !sew_qi_prio_tbl[i].task)
			slot = i;
	}
	if (slot < 0) {
		spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
		return -EBUSY;
	}
	sew_qi_prio_tbl[slot].task = task;
	if (prio >= 0)
		sew_qi_prio_tbl[slot].prio = prio;
	if (rt_prio >= 0)
		sew_qi_prio_tbl[slot].rt_prio = rt_prio;
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	return 0;
}
EXPORT_SYMBOL_GPL(update_static_prio);

int get_task_prio(struct task_struct *p)
{
	unsigned long irqflags;
	int lo = -1, hi = -1, i;

	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_PRIO_SLOTS; i++) {
		if (sew_qi_prio_tbl[i].task == p) {
			lo = sew_qi_prio_tbl[i].prio;
			hi = sew_qi_prio_tbl[i].rt_prio;
			break;
		}
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);

	if (lo < 0 && hi < 0)
		return DEFAULT_PRIO; /* dada default 120 */
	if (lo < 0)
		return hi;
	if (hi < 0)
		return lo;
	return min(lo, hi);
}
EXPORT_SYMBOL_GPL(get_task_prio);

/* ---- chain register switches (dada qi_vh_*_register semantics) -------- */

/*
 * dada's qi_vh_*_register/_unregister are whole-chain switches: each
 * registers (or removes) every hook callback of one lock chain and
 * unwinds on error.  Here they additionally make the module's hook
 * footprint optional per chain; xr_qi_init() enables all eight, like
 * the dada init path.  Re-registration is idempotent.
 */
static unsigned long sew_qi_chain_enabled;

#define SEW_QI_CHAIN_FUTEX	0
#define SEW_QI_CHAIN_MUTEX	1
#define SEW_QI_CHAIN_RWSEM	2
#define SEW_QI_CHAIN_PCRWSEM	3
#define SEW_QI_CHAIN_BINDER	4
#define SEW_QI_CHAIN_COMM	5
#define SEW_QI_CHAIN_FUSE	6
#define SEW_QI_CHAIN_RCU	7

int qi_vh_futex_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_FUTEX, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_do_futex(sew_qi_do_futex, NULL);
	if (!ret)
		ret = register_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	if (!ret)
		ret = register_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	if (!ret)
		ret = register_trace_android_vh_futex_wake_traverse_plist(sew_qi_futex_wake_traverse, NULL);
	if (!ret)
		ret = register_trace_android_vh_futex_wake_up_q_finish(sew_qi_futex_wake_up_q_finish, NULL);
	if (ret) {
		unregister_trace_android_vh_futex_wake_up_q_finish(sew_qi_futex_wake_up_q_finish, NULL);
		unregister_trace_android_vh_futex_wake_traverse_plist(sew_qi_futex_wake_traverse, NULL);
		unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
		unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
		unregister_trace_android_vh_do_futex(sew_qi_do_futex, NULL);
		clear_bit(SEW_QI_CHAIN_FUTEX, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_futex_register);

void qi_vh_futex_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_FUTEX, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_do_futex(sew_qi_do_futex, NULL);
	unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	unregister_trace_android_vh_futex_wake_traverse_plist(sew_qi_futex_wake_traverse, NULL);
	unregister_trace_android_vh_futex_wake_up_q_finish(sew_qi_futex_wake_up_q_finish, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_futex_unregister);

int qi_vh_mutex_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_MUTEX, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
	if (!ret)
		ret = register_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
	if (!ret)
		ret = register_trace_android_vh_alter_mutex_list_add(os_cpu_android_vh_alter_mutex_list_add, NULL);
	if (!ret)
		ret = register_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
	if (!ret)
		ret = register_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
	if (!ret)
		ret = register_trace_android_vh_mutex_can_spin_on_owner(sew_qi_mutex_can_spin, NULL);
	if (!ret)
		ret = register_trace_android_vh_mutex_opt_spin_start(sew_qi_mutex_opt_spin_start, NULL);
	if (!ret)
		ret = register_trace_android_vh_mutex_opt_spin_finish(sew_qi_mutex_opt_spin_finish, NULL);
	/*
	 * The rtmutex hooks ride the mutex-chain switch: on 6.6 the dada
	 * mutex chain covers the rt_mutex_base-backed mutex path, so
	 * 5.15 keeps them under qi_vh_mutex_register() (no extra dada
	 * symbol).
	 */
	if (!ret)
		ret = register_trace_android_vh_rtmutex_wait_start(sew_qi_rtmutex_wait_start, NULL);
	if (!ret)
		ret = register_trace_android_vh_rtmutex_wait_finish(sew_qi_rtmutex_wait_finish, NULL);
	if (!ret)
		ret = register_trace_android_vh_task_blocks_on_rtmutex(sew_qi_task_blocks_on_rtmutex, NULL);
	if (!ret)
		ret = register_trace_android_vh_rtmutex_waiter_prio(sew_qi_rtmutex_waiter_prio, NULL);
	if (!ret)
		ret = register_trace_android_vh_rt_mutex_steal(sew_qi_rt_mutex_steal, NULL);
	if (!ret)
		ret = register_trace_android_vh_record_rtmutex_lock_starttime(sew_qi_rtmutex_lock_released, NULL);
	if (ret) {
		unregister_trace_android_vh_record_rtmutex_lock_starttime(sew_qi_rtmutex_lock_released, NULL);
		unregister_trace_android_vh_rt_mutex_steal(sew_qi_rt_mutex_steal, NULL);
		unregister_trace_android_vh_rtmutex_waiter_prio(sew_qi_rtmutex_waiter_prio, NULL);
		unregister_trace_android_vh_task_blocks_on_rtmutex(sew_qi_task_blocks_on_rtmutex, NULL);
		unregister_trace_android_vh_rtmutex_wait_finish(sew_qi_rtmutex_wait_finish, NULL);
		unregister_trace_android_vh_rtmutex_wait_start(sew_qi_rtmutex_wait_start, NULL);
		unregister_trace_android_vh_mutex_opt_spin_finish(sew_qi_mutex_opt_spin_finish, NULL);
		unregister_trace_android_vh_mutex_opt_spin_start(sew_qi_mutex_opt_spin_start, NULL);
		unregister_trace_android_vh_mutex_can_spin_on_owner(sew_qi_mutex_can_spin, NULL);
		unregister_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
		unregister_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
		unregister_trace_android_vh_alter_mutex_list_add(os_cpu_android_vh_alter_mutex_list_add, NULL);
		unregister_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
		unregister_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
		clear_bit(SEW_QI_CHAIN_MUTEX, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_mutex_register);

void qi_vh_mutex_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_MUTEX, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
	unregister_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
	unregister_trace_android_vh_alter_mutex_list_add(os_cpu_android_vh_alter_mutex_list_add, NULL);
	unregister_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
	unregister_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
	unregister_trace_android_vh_mutex_can_spin_on_owner(sew_qi_mutex_can_spin, NULL);
	unregister_trace_android_vh_mutex_opt_spin_start(sew_qi_mutex_opt_spin_start, NULL);
	unregister_trace_android_vh_mutex_opt_spin_finish(sew_qi_mutex_opt_spin_finish, NULL);
	unregister_trace_android_vh_rtmutex_wait_start(sew_qi_rtmutex_wait_start, NULL);
	unregister_trace_android_vh_rtmutex_wait_finish(sew_qi_rtmutex_wait_finish, NULL);
	unregister_trace_android_vh_task_blocks_on_rtmutex(sew_qi_task_blocks_on_rtmutex, NULL);
	unregister_trace_android_vh_rtmutex_waiter_prio(sew_qi_rtmutex_waiter_prio, NULL);
	unregister_trace_android_vh_rt_mutex_steal(sew_qi_rt_mutex_steal, NULL);
	unregister_trace_android_vh_record_rtmutex_lock_starttime(sew_qi_rtmutex_lock_released, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_mutex_unregister);

int qi_vh_rwsem_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_RWSEM, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
	if (!ret)
		ret = register_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
	if (!ret)
		ret = register_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
	if (!ret)
		ret = register_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_init(sew_qi_rwsem_init, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_optimistic_rspin(sew_qi_rwsem_optimistic_rspin, NULL);
	if (!ret)
		ret = register_trace_android_vh_rwsem_read_trylock_failed(sew_qi_rwsem_read_trylock_failed, NULL);
	if (ret) {
		unregister_trace_android_vh_rwsem_read_trylock_failed(sew_qi_rwsem_read_trylock_failed, NULL);
		unregister_trace_android_vh_rwsem_optimistic_rspin(sew_qi_rwsem_optimistic_rspin, NULL);
		unregister_trace_android_vh_rwsem_init(sew_qi_rwsem_init, NULL);
		unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
		unregister_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
		unregister_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
		unregister_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
		unregister_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
		unregister_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
		unregister_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
		clear_bit(SEW_QI_CHAIN_RWSEM, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_rwsem_register);

void qi_vh_rwsem_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_RWSEM, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
	unregister_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
	unregister_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
	unregister_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
	unregister_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
	unregister_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
	unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
	unregister_trace_android_vh_rwsem_init(sew_qi_rwsem_init, NULL);
	unregister_trace_android_vh_rwsem_optimistic_rspin(sew_qi_rwsem_optimistic_rspin, NULL);
	unregister_trace_android_vh_rwsem_read_trylock_failed(sew_qi_rwsem_read_trylock_failed, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_rwsem_unregister);

int qi_vh_percpu_rwsem_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_PCRWSEM, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
	if (!ret)
		ret = register_trace_android_vh_percpu_rwsem_wq_add(sew_qi_percpu_rwsem_wq_add, NULL);
	if (ret) {
		unregister_trace_android_vh_percpu_rwsem_wq_add(sew_qi_percpu_rwsem_wq_add, NULL);
		unregister_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
		clear_bit(SEW_QI_CHAIN_PCRWSEM, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_percpu_rwsem_register);

void qi_vh_percpu_rwsem_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_PCRWSEM, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
	unregister_trace_android_vh_percpu_rwsem_wq_add(sew_qi_percpu_rwsem_wq_add, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_percpu_rwsem_unregister);

int qi_vh_binder_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_BINDER, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_binder_transaction_init(sew_qi_binder_transaction_init, NULL);
	if (!ret)
		ret = register_trace_android_vh_binder_proc_transaction(sew_qi_binder_proc_transaction, NULL);
	if (!ret)
		ret = register_trace_android_vh_binder_set_priority(sew_qi_binder_set_priority, NULL);
	if (!ret)
		ret = register_trace_android_vh_binder_restore_priority(sew_qi_binder_restore_priority, NULL);
	if (!ret)
		ret = register_trace_android_vh_binder_buffer_release(sew_qi_binder_buffer_release, NULL);
	if (!ret)
		ret = register_trace_android_vh_free_oem_binder_struct(sew_qi_free_oem_binder_struct, NULL);
	if (ret) {
		unregister_trace_android_vh_free_oem_binder_struct(sew_qi_free_oem_binder_struct, NULL);
		unregister_trace_android_vh_binder_buffer_release(sew_qi_binder_buffer_release, NULL);
		unregister_trace_android_vh_binder_restore_priority(sew_qi_binder_restore_priority, NULL);
		unregister_trace_android_vh_binder_set_priority(sew_qi_binder_set_priority, NULL);
		unregister_trace_android_vh_binder_proc_transaction(sew_qi_binder_proc_transaction, NULL);
		unregister_trace_android_vh_binder_transaction_init(sew_qi_binder_transaction_init, NULL);
		clear_bit(SEW_QI_CHAIN_BINDER, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_binder_register);

void qi_vh_binder_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_BINDER, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_binder_transaction_init(sew_qi_binder_transaction_init, NULL);
	unregister_trace_android_vh_binder_proc_transaction(sew_qi_binder_proc_transaction, NULL);
	unregister_trace_android_vh_binder_set_priority(sew_qi_binder_set_priority, NULL);
	unregister_trace_android_vh_binder_restore_priority(sew_qi_binder_restore_priority, NULL);
	unregister_trace_android_vh_binder_buffer_release(sew_qi_binder_buffer_release, NULL);
	unregister_trace_android_vh_free_oem_binder_struct(sew_qi_free_oem_binder_struct, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_binder_unregister);

/*
 * dada carries the task-lifecycle hooks under its comm chain (the
 * remaining hook classes are accounted for by the other seven
 * switches); same grouping here.
 */
int qi_vh_comm_register(void)
{
	int ret;

	if (test_and_set_bit(SEW_QI_CHAIN_COMM, &sew_qi_chain_enabled))
		return 0;
	ret = register_trace_android_vh_dup_task_struct(sew_qi_dup_task_struct, NULL);
	if (!ret)
		ret = register_trace_android_vh_exit_check(sew_qi_exit_check, NULL);
	if (!ret)
		ret = register_trace_android_vh_free_task(sew_qi_free_task, NULL);
	if (ret) {
		unregister_trace_android_vh_free_task(sew_qi_free_task, NULL);
		unregister_trace_android_vh_exit_check(sew_qi_exit_check, NULL);
		unregister_trace_android_vh_dup_task_struct(sew_qi_dup_task_struct, NULL);
		clear_bit(SEW_QI_CHAIN_COMM, &sew_qi_chain_enabled);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(qi_vh_comm_register);

void qi_vh_comm_unregister(void)
{
	if (!test_and_clear_bit(SEW_QI_CHAIN_COMM, &sew_qi_chain_enabled))
		return;
	unregister_trace_android_vh_dup_task_struct(sew_qi_dup_task_struct, NULL);
	unregister_trace_android_vh_exit_check(sew_qi_exit_check, NULL);
	unregister_trace_android_vh_free_task(sew_qi_free_task, NULL);
}
EXPORT_SYMBOL_GPL(qi_vh_comm_unregister);

/*
 * fuse/rcu chains: dada registers fuse_request_end_ext/fetch and the
 * four rcu hooks; none of those tracepoints exist on the 5.15 GKI
 * tree, so the switches are honest no-ops (PORT-DELTA).
 */
int qi_vh_fuse_register(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(qi_vh_fuse_register);

void qi_vh_fuse_unregister(void)
{
}
EXPORT_SYMBOL_GPL(qi_vh_fuse_unregister);

int qi_vh_rcu_register(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(qi_vh_rcu_register);

void qi_vh_rcu_unregister(void)
{
}
EXPORT_SYMBOL_GPL(qi_vh_rcu_unregister);

/* ---- stats / sysctl / GPU stubs (dada symbol list alignment) ---------- */

int qi_stats_register(void)
{
	/* dada attaches per-chain stat sinks; the counters are proc-facing here */
	return 0;
}
EXPORT_SYMBOL_GPL(qi_stats_register);

void qi_stats_unregister(void)
{
}
EXPORT_SYMBOL_GPL(qi_stats_unregister);

int qi_sysctl_register(void)
{
	/* dada: register_sysctl_sz(table, 2) for the opt-spin budgets - PORT-DELTA */
	return 0;
}
EXPORT_SYMBOL_GPL(qi_sysctl_register);

void qi_sysctl_unregister(void)
{
}
EXPORT_SYMBOL_GPL(qi_sysctl_unregister);

/*
 * GPU-blocked tracking: dada marks tasks from its own qi_gpu_blocked/
 * unblocked tracepoints (no in-kernel producer on 5.15), so the query
 * face reports "not blocked".
 */
bool qi_is_gpu_blocked_task(struct task_struct *p)
{
	return false;
}
EXPORT_SYMBOL_GPL(qi_is_gpu_blocked_task);

unsigned long qi_gpu_blocked_longest(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(qi_gpu_blocked_longest);

int qi_acquire_gpu_blockeds(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(qi_acquire_gpu_blockeds);

/* ---- proc control / status (unchanged knobs, extended status) --------- */

static int sew_qi_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "vip_tgid=%d\nuclamp_min=%u\nhinted_waits=%lld\nmutex_hints=%lld\nrwsem_hints=%lld\nrtmutex_hints=%lld\nbinder_hints=%lld\npassive_events=%lld\nchains=0x%lx\n",
		   sew_qi_vip_tgid, sew_qi_uclamp_min,
		   atomic64_read(&sew_qi_hinted_waits),
		   atomic64_read(&sew_qi_mutex_hints),
		   atomic64_read(&sew_qi_rwsem_hints),
		   atomic64_read(&sew_qi_rtmutex_hints),
		   atomic64_read(&sew_qi_binder_hints),
		   atomic64_read(&sew_qi_passive_events),
		   sew_qi_chain_enabled);
	return 0;
}

static int sew_qi_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_qi_proc_show, NULL);
}

static ssize_t sew_qi_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[64];
	long val;
	int field;

	if (count >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	tmp[count] = '\0';

	if (sscanf(tmp, "vip_tgid %ld", &val) == 1)
		field = 0;
	else if (sscanf(tmp, "uclamp_min %ld", &val) == 1)
		field = 1;
	else
		return -EINVAL;

	/*
	 * pid_max is not exported to modules on 5.15; pid_t is a signed
	 * int and the hook side re-checks against real tasks, so a plain
	 * non-negative bound is enough here.
	 */
	if (field == 0) {
		if (val < 0)
			return -EINVAL;
		WRITE_ONCE(sew_qi_vip_tgid, (pid_t)val);
	} else {
		if (val < 0 || val > 1024)
			return -EINVAL;
		WRITE_ONCE(sew_qi_uclamp_min, (unsigned int)val);
	}
	return count;
}

static const struct proc_ops sew_qi_proc_ops = {
	.proc_open	= sew_qi_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= sew_qi_proc_write,
};

static int __init xr_qi_init(void)
{
	int ret;

	ret = qi_vh_futex_register();
	if (ret)
		return ret;
	ret = qi_vh_mutex_register();
	if (ret)
		goto err_mutex;
	ret = qi_vh_rwsem_register();
	if (ret)
		goto err_rwsem;
	ret = qi_vh_percpu_rwsem_register();
	if (ret)
		goto err_pcrwsem;
	ret = qi_vh_binder_register();
	if (ret)
		goto err_binder;
	ret = qi_vh_comm_register();
	if (ret)
		goto err_comm;
	/* fuse/rcu chains register nothing on 5.15; enable for parity */
	qi_vh_fuse_register();
	qi_vh_rcu_register();

	if (!proc_create("xr_qi", 0600, NULL, &sew_qi_proc_ops)) {
		ret = -ENOMEM;
		goto err_proc;
	}
	return 0;

err_proc:
	qi_vh_rcu_unregister();
	qi_vh_fuse_unregister();
	qi_vh_comm_unregister();
err_comm:
	qi_vh_binder_unregister();
err_binder:
	qi_vh_percpu_rwsem_unregister();
err_pcrwsem:
	qi_vh_rwsem_unregister();
err_rwsem:
	qi_vh_mutex_unregister();
err_mutex:
	qi_vh_futex_unregister();
	return ret;
}

static void __exit xr_qi_exit(void)
{
	remove_proc_entry("xr_qi", NULL);
	qi_vh_rcu_unregister();
	qi_vh_fuse_unregister();
	qi_vh_comm_unregister();
	qi_vh_binder_unregister();
	qi_vh_percpu_rwsem_unregister();
	qi_vh_rwsem_unregister();
	qi_vh_mutex_unregister();
	qi_vh_futex_unregister();
	tracepoint_synchronize_unregister();
}

module_init(xr_qi_init);
module_exit(xr_qi_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew xr_qi QOS-inheritance port (futex/mutex/rtmutex/rwsem/binder chains, qievent + QoS API)");
