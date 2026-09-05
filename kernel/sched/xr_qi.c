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
 * NOT ported from OS4 (deliberately): android_vh_mutex_can_spin_on_
 * owner / mutex_opt_spin_start / mutex_opt_spin_finish (optimistic
 * spin duration control via sysctls + retval override against spin
 * starvation - orthogonal to the uclamp chain and needs the dada qi
 * feature bitmap plus two sysctls), the rwsem/percpu-rwsem/mmap_lock/
 * rcu/fuse hooks, RT priority migration, and the full group
 * bookkeeping.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <trace/hooks/futex.h>
#include <trace/hooks/dtask.h>

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

static pid_t sew_qi_vip_tgid;
static unsigned int sew_qi_uclamp_min = SEW_QI_UCLAMP_MIN_DEFAULT;
static atomic64_t sew_qi_hinted_waits;
static atomic64_t sew_qi_mutex_hints;

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

static int sew_qi_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "vip_tgid=%d\nuclamp_min=%u\nhinted_waits=%lld\nmutex_hints=%lld\n",
		   sew_qi_vip_tgid, sew_qi_uclamp_min,
		   atomic64_read(&sew_qi_hinted_waits),
		   atomic64_read(&sew_qi_mutex_hints));
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
	if (!proc_create("xr_qi", 0644, NULL, &sew_qi_proc_ops)) {
		ret = -ENOMEM;
		goto err_proc;
	}
	return 0;

err_proc:
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
	tracepoint_synchronize_unregister();
	remove_proc_entry("xr_qi", NULL);
}

module_init(xr_qi_init);
module_exit(xr_qi_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew minimal futex+mutex QOS-inheritance (xr_qi reduced port, uclamp hint only)");
