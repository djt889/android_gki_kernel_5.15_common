// SPDX-License-Identifier: GPL-2.0-only
/*
 * xr_qi: minimal QOS-inheritance on the futex and mutex wait chains,
 * reduced port of the Xiaomi OS4 xr_qi module idea ("MI QOS inherit
 * Driver": propagate importance from a lock holder to waiters).
 *
 * Scope reduction vs OS4: only the futex and mutex chains, and only a
 * uclamp_min hint. The existing android_vh_futex_wait_start / _wait_end
 * hooks are consumed (no new call sites needed). When a waiter we
 * flagged blocks on a futex, we remember its tgid; when it wakes, the
 * hint is dropped. The hint itself is applied to waiters of a single
 * configured "vip" tgid: those waiters get a small uclamp_min floor
 * while blocked, so the EAS places them on capable cores when they
 * wake.
 *
 * Mutex chain (R9 addition, mirror of the dada xr_qi.ko mutex subset):
 *  - android_vh_mutex_wait_start: a vip waiter blocking on a mutex gets
 *    the same waiter-side floor as the futex chain, AND the lock owner
 *    (lock->owner minus MUTEX_FLAGS) inherits a uclamp_min floor for as
 *    long as it holds the lock (dada: do_mutex_qos_inherit). The owner
 *    slot keeps a task_struct reference so the hint write is safe even
 *    if the owner races ahead.
 *  - android_vh_mutex_wait_finish: drop the waiter-side floor.
 *  - android_vh_mutex_unlock_slowpath and android_vh_record_mutex_lock_
 *    starttime(current, 0) (the common mutex_unlock() exit, fired with
 *    settime_jiffies == 0 on both the fast and slow path): undo the
 *    owner-side floor (dada: undo_mutex_qos_inherit). Two channels are
 *    registered because __mutex_unlock_fast() skips the slowpath hook.
 *
 * Rwsem chain (R10 addition, mirror of the dada xr_qi.ko rwsem
 * subset, same uclamp-slot pattern as the mutex chain):
 *  - android_vh_alter_rwsem_list_add: a vip waiter queued on the sem
 *    gets the waiter-side floor, and the lock owner inherits the floor
 *    until it releases (dada: do_rwsem_qos_inherit). 5.15 leaves the
 *    last owning reader in sem->owner behind RWSEM_READER_OWNED, so
 *    the masked owner covers writers and reader-owners alike. A vip
 *    WRITE waiter additionally pins RWSEM_FLAG_HANDOFF in sem->count
 *    and marks the first write waiter handoff_set (dada feat13), so
 *    later readers cannot steal the lock away from the wait chain.
 *  - android_vh_rwsem_read_wait_finish / _write_wait_finish: drop the
 *    waiter-side floor (fire on both acquired and aborted waits).
 *  - android_vh_clear_rwsem_writer_owned / _reader_owned and
 *    android_vh_record_rwsem_lock_starttime(tsk, 0) (the __up_read/
 *    __up_write exits; settime != 0 is the acquire channel, whose
 *    hold-time stats stay unported): undo the owner-side floor. Two
 *    idempotent channels per release, same shape as the mutex chain.
 *  - android_vh_rwsem_direct_rsteal: veto reader optimistic stealing
 *    while sem->wait_lock is busy, so a pending vip wait chain is not
 *    bypassed (dada reads [sem+0x10] == wait_lock).
 *  - android_vh_record_pcpu_rwsem_starttime(tsk, 0): percpu-rwsem
 *    release channel, registered for dada hook-set parity.
 *
 * NOT ported from OS4 (deliberately): android_vh_rwsem_init (dada only
 * zeroes its own per-sem vendor fields, which this port has no use
 * for), the rwsem read/write_wait_start hooks (dada does not consume
 * them - nm -u of xr_qi.ko lists only the finish hooks), the reader
 * chain hand-off in clear_rwsem_reader_owned (dada re-targets the
 * inherit to the next reader owner via its per-sem reader list; this
 * port just drops the floor when the tracked owner releases), the
 * qi feature bitmap (feat5/feat13 collapse to the single vip_tgid
 * gate), hold-time statistics, android_vh_mutex_can_spin_on_owner /
 * mutex_opt_spin_start / mutex_opt_spin_finish, the percpu-rwsem
 * wq_add/init hooks, mmap_lock/rcu/fuse hooks, RT priority migration,
 * and the full group bookkeeping.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/uaccess.h>
#include <trace/hooks/futex.h>
#include <trace/hooks/dtask.h>
#include <trace/hooks/rwsem.h>

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
 * Hint slot kinds. The futex chain predates the mutex chain; its slots
 * are keyed by tid only, so the mutex kinds must never collide with a
 * live futex slot of the same task.
 */
#define SEW_QI_HINT_FUTEX	1
#define SEW_QI_HINT_MWAITER	2
#define SEW_QI_HINT_DOWNER	3
#define SEW_QI_HINT_RWWAITER	4
#define SEW_QI_HINT_ROWNER	5

/*
 * kernel/locking/rwsem.c keeps RWSEM_READER_OWNED (bit 0) and
 * RWSEM_NONSPINNABLE (bit 1) in sem->owner and RWSEM_FLAG_HANDOFF
 * (bit 2) in sem->count (private defines there); mask/set them the
 * same way the dada module does (owner ands #~0x3, handoff ors #0x4).
 */
#define SEW_QI_RWSEM_OWNER_MASK	~0x03UL
#define SEW_QI_RWSEM_HANDOFF	(1UL << 2)

static pid_t sew_qi_vip_tgid;
static unsigned int sew_qi_uclamp_min = SEW_QI_UCLAMP_MIN_DEFAULT;
static atomic64_t sew_qi_hinted_waits;
static atomic64_t sew_qi_mutex_hints;
static atomic64_t sew_qi_rwsem_hints;

/*
 * Save/restore slots. Futex slots are keyed by tid (not tgid): if the
 * user re-points vip_tgid while a hinted task is still blocked, wait_end
 * must still restore that task (reviewer finding). Mutex slots are keyed
 * by task pointer on the owner side (which keeps a reference) and reuse
 * the tid key on the waiter side. Bounded ring of slots; a full table
 * refuses further hints rather than corrupting state.
 *
 * The uclamp_req write itself stays lock-free, mirroring the OS4
 * original: a torn bitfield read self-corrects on the next bucket
 * update, and rq aggregation catches up at the next enqueue/dequeue.
 */
#define SEW_QI_HINT_SLOTS 16
struct sew_qi_hint {
	int			tid;		/* futex/mwaiter key; -1 on owner slots */
	unsigned int		prev_value;
	struct task_struct	*owner_task;	/* DOWNER slots hold a reference */
	unsigned char		kind;
};
static struct sew_qi_hint sew_qi_hints[SEW_QI_HINT_SLOTS];
static DEFINE_SPINLOCK(sew_qi_hint_lock);
static atomic_t sew_qi_active_hints;

static void sew_qi_wait_start(void *data, u32 flags, u32 bitset)
{
	struct task_struct *t = current;
	unsigned long irqflags;
	int i, slot = -1;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * Tracepoint probes run with preemption disabled, so only
	 * non-sleeping work happens here (spinlock is fine).
	 */
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].tid == t->pid) {
			slot = i;
			break;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot >= 0) {
		sew_qi_hints[slot].tid = t->pid;
		sew_qi_hints[slot].prev_value =
			t->uclamp_req[UCLAMP_MIN].value;
		sew_qi_hints[slot].owner_task = NULL;
		sew_qi_hints[slot].kind = SEW_QI_HINT_FUTEX;
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
 * Mutex chain: raise uclamp_min for @target and remember the previous
 * value in @slot. Caller holds sew_qi_hint_lock and has already filled
 * tid/owner_task/kind.
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
		if (kind == SEW_QI_HINT_DOWNER) {
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
		h->kind = 0;
		atomic_dec(&sew_qi_active_hints);
		break;
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
}

static void sew_qi_mutex_wait_start(void *data, struct mutex *lock)
{
	struct task_struct *t = current, *owner = NULL;
	unsigned long irqflags;
	int i, slot = -1;

	if (!sew_qi_vip_tgid || task_tgid_nr(t) != sew_qi_vip_tgid)
		return;

	/*
	 * Waiter-side floor, same record/restore pattern as the futex
	 * chain (dada records the wait on the waiter's vendor data).
	 */
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == SEW_QI_HINT_MWAITER &&
		    sew_qi_hints[i].tid == t->pid) {
			slot = i;
			break;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot >= 0) {
		sew_qi_hints[slot].tid = t->pid;
		sew_qi_hints[slot].owner_task = NULL;
		sew_qi_hints[slot].kind = SEW_QI_HINT_MWAITER;
		sew_qi_mhint_apply(&sew_qi_hints[slot], t);
		atomic64_inc(&sew_qi_mutex_hints);
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);

	/*
	 * Owner-side inheritance (dada: do_mutex_qos_inherit(owner)): a
	 * vip waiter hands its floor to whoever currently holds the
	 * lock, so the holder reaches unlock faster. The reference keeps
	 * the owner task alive until the undo channel runs.
	 */
	if (!lock)
		return;
	owner = (struct task_struct *)
		(atomic_long_read(&lock->owner) & SEW_QI_MUTEX_OWNER_MASK);
	if (!owner || owner == t)
		return;
	get_task_struct(owner);

	slot = -1;
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == SEW_QI_HINT_DOWNER &&
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
	sew_qi_hints[slot].kind = SEW_QI_HINT_DOWNER;
	sew_qi_mhint_apply(&sew_qi_hints[slot], owner);
	atomic64_inc(&sew_qi_mutex_hints);
	owner = NULL;
out_owner:
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	if (owner)
		put_task_struct(owner);
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
	unsigned long irqflags;
	int i, slot = -1;

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

	/* waiter-side floor, same record pattern as the futex/mutex chains */
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == SEW_QI_HINT_RWWAITER &&
		    sew_qi_hints[i].tid == t->pid) {
			slot = i;
			break;
		}
		if (slot < 0 && sew_qi_hints[i].tid == 0)
			slot = i;
	}
	if (slot >= 0) {
		sew_qi_hints[slot].tid = t->pid;
		sew_qi_hints[slot].owner_task = NULL;
		sew_qi_hints[slot].kind = SEW_QI_HINT_RWWAITER;
		sew_qi_mhint_apply(&sew_qi_hints[slot], t);
		atomic64_inc(&sew_qi_rwsem_hints);
	}
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);

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
	if (!owner || owner == t)
		return;
	get_task_struct(owner);

	slot = -1;
	spin_lock_irqsave(&sew_qi_hint_lock, irqflags);
	for (i = 0; i < SEW_QI_HINT_SLOTS; i++) {
		if (sew_qi_hints[i].kind == SEW_QI_HINT_ROWNER &&
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
	sew_qi_hints[slot].kind = SEW_QI_HINT_ROWNER;
	sew_qi_mhint_apply(&sew_qi_hints[slot], owner);
	atomic64_inc(&sew_qi_rwsem_hints);
	owner = NULL;
out_owner:
	spin_unlock_irqrestore(&sew_qi_hint_lock, irqflags);
	if (owner)
		put_task_struct(owner);
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

/* percpu-rwsem release channel (percpu_up_write), dada hook-set parity. */
static void android_vh_record_pcpu_rwsem_starttime(void *data,
						   struct task_struct *tsk,
						   unsigned long settime_jiffies)
{
	if (settime_jiffies)
		return;
	sew_qi_mhint_restore(tsk, SEW_QI_HINT_ROWNER);
}

static int sew_qi_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "vip_tgid=%d\nuclamp_min=%u\nhinted_waits=%lld\nmutex_hints=%lld\nrwsem_hints=%lld\n",
		   sew_qi_vip_tgid, sew_qi_uclamp_min,
		   atomic64_read(&sew_qi_hinted_waits),
		   atomic64_read(&sew_qi_mutex_hints),
		   atomic64_read(&sew_qi_rwsem_hints));
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

	ret = register_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	if (ret)
		return ret;
	ret = register_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	if (ret) {
		unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
		return ret;
	}
	ret = register_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
	if (ret)
		goto err_mutex_start;
	ret = register_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
	if (ret)
		goto err_mutex_finish;
	ret = register_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
	if (ret)
		goto err_mutex_unlock;
	ret = register_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
	if (ret)
		goto err_mutex_released;
	ret = register_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
	if (ret)
		goto err_rwsem_alter;
	ret = register_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
	if (ret)
		goto err_rwsem_rfinish;
	ret = register_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
	if (ret)
		goto err_rwsem_wfinish;
	ret = register_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
	if (ret)
		goto err_rwsem_creader;
	ret = register_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
	if (ret)
		goto err_rwsem_cwriter;
	ret = register_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
	if (ret)
		goto err_rwsem_rsteal;
	ret = register_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
	if (ret)
		goto err_rwsem_record;
	ret = register_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
	if (ret)
		goto err_rwsem_pcpu;
	if (!proc_create("xr_qi", 0644, NULL, &sew_qi_proc_ops)) {
		ret = -ENOMEM;
		goto err_proc;
	}
	return 0;

err_proc:
	unregister_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
err_rwsem_pcpu:
	unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
err_rwsem_record:
	unregister_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
err_rwsem_rsteal:
	unregister_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
err_rwsem_cwriter:
	unregister_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
err_rwsem_creader:
	unregister_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
err_rwsem_wfinish:
	unregister_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
err_rwsem_rfinish:
	unregister_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
err_rwsem_alter:
	unregister_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
err_mutex_released:
	unregister_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
err_mutex_unlock:
	unregister_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
err_mutex_finish:
	unregister_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
err_mutex_start:
	unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	return ret;
}

static void __exit xr_qi_exit(void)
{
	unregister_trace_android_vh_futex_wait_start(sew_qi_wait_start, NULL);
	unregister_trace_android_vh_futex_wait_end(sew_qi_wait_end, NULL);
	unregister_trace_android_vh_mutex_wait_start(sew_qi_mutex_wait_start, NULL);
	unregister_trace_android_vh_mutex_wait_finish(sew_qi_mutex_wait_finish, NULL);
	unregister_trace_android_vh_mutex_unlock_slowpath(sew_qi_mutex_unlock, NULL);
	unregister_trace_android_vh_record_mutex_lock_starttime(sew_qi_mutex_lock_released, NULL);
	unregister_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add, NULL);
	unregister_trace_android_vh_rwsem_read_wait_finish(android_vh_rwsem_read_wait_finish, NULL);
	unregister_trace_android_vh_rwsem_write_wait_finish(android_vh_rwsem_write_wait_finish, NULL);
	unregister_trace_android_vh_clear_rwsem_reader_owned(android_vh_clear_rwsem_reader_owned, NULL);
	unregister_trace_android_vh_clear_rwsem_writer_owned(android_vh_clear_rwsem_writer_owned, NULL);
	unregister_trace_android_vh_rwsem_direct_rsteal(android_vh_rwsem_direct_rsteal, NULL);
	unregister_trace_android_vh_record_rwsem_lock_starttime(android_vh_record_rwsem_lock_starttime, NULL);
	unregister_trace_android_vh_record_pcpu_rwsem_starttime(android_vh_record_pcpu_rwsem_starttime, NULL);
	tracepoint_synchronize_unregister();
	remove_proc_entry("xr_qi", NULL);
}

module_init(xr_qi_init);
module_exit(xr_qi_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew minimal futex+mutex+rwsem QOS-inheritance (xr_qi reduced port, uclamp hint only)");
