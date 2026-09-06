// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/sched/rtg.c - Sew 5.15 rewrite of Xiaomi dada OS4 rtg.ko
 *                      (Related Thread Group)
 *
 * Reverse-engineered from:
 *   /root/work/os4_dada/ko/rtg.ko
 *   vermagic 6.6.57-android15-8-g32a50a34de2b-4k, license "GPL v2",
 *   name "rtg", intree, depends=plat_common,perf_actuator,
 *   19 undefined symbols, closure gap 2 (alt_cb_patch_nops,
 *   system_cpucaps), 6 GPL exports (get_related_thread_group,
 *   os_cpu_get_group_prefer_cpus, os_cpu_get_group_prefer_util,
 *   os_cpu_is_task_prefer_cpu, os_cpu_can_migrate_task,
 *   os_cpu_init_rtg_grp_prefer_cpus).
 *
 * Evidence: E:/AI/SewKernel/.omz/research/
 *   sess_d9452f03-b737-460b-bd27-aff04c01b561-os4-force-port/raw/re-rtg.txt
 *   (nm -u / nm --defined-only -g, full objdump -d, strings).  The binary
 *   contains exactly: the 5 perf_actuator_* ioctl handlers, the 5 exported
 *   helpers, an inlined _copy_from_user (6.6 arm64 uaccess glue) and
 *   init_module; every function, command and log string below is
 *   byte-identical to the binary unless marked [PORT-DELTA].
 *
 * What the module does
 * --------------------
 * Related Thread Group: related tasks (e.g. the threads of one app) are
 * grouped by id 0..19 (id 1 reserved, 0 = default group) and each group
 * carries a preferred CPU mask (rtg_prefer_cpus) plus a preferred
 * utilization cap (rtg_util, clamped to 1024).  The scheduler consults
 * the prefer mask through the os_cpu_* helpers so that tasks of the same
 * group are placed on the same cluster, avoiding cross-cluster migration
 * jitter.  Userspace sets group id / prefer cpus / util through the
 * perf_actuator QoS bridge; init_module registers five commands:
 *
 *   SET_TASK_RTG       0x40087802  {int pid; int grp_id}           8B
 *   SET_TASK_ARRAY_RTG 0x40447825  {int grp_id; int task_num;
 *                                   u32 pids[15]}                 68B
 *   SET_RTG_CPUS       0x40087803  {int grp_id; u32 cpus}           8B
 *   SET_RTG_UTIL       0x40087804  {int grp_id; u32 util}           8B
 *   CLR_RTG            0x40047807  {int grp_id}                     4B
 *
 * Port architecture (Sew 5.15 has no walt)
 * ----------------------------------------
 * On dada the group store itself (struct walt_related_thread_group,
 * 104 bytes per BTF: +4 tasks_lock, +8 tasks list, +88 rtg_prefer_cpus,
 * +96 rtg_util) lives in the builtin walt scheduler, which registers
 * plat_common hook slots 1 (FUNC_SCHED_SET_GROUP_ID), 9/10
 * (FUNC_GET_GROUP_PREFER_CPUS/UTIL) and 12
 * (FUNC_LOOKUP_RELATED_THREAD_GROUP).  rtg.ko only provides the
 * perf_actuator front end and the os_cpu_* ABI consumed by vendor
 * modules (mi_game.ko et al).  This port merges the walt backend role
 * into rtg.c (group table, task->group mapping and the four plat hooks
 * above), keeping every original rtg.ko function name.  mm/plat_common.c
 * explicitly anticipated this: "The real definitions live in the dada
 * provider modules (rtg.ko / sched-walt.ko / mi_game.ko); a future Sew
 * port of those must supply matching definitions."
 *
 * Closure gaps (2), resolved the same way as mm/plat_common.c
 * -----------------------------------------------------------
 *  1. alt_cb_patch_nops - 6.6 arm64 alternative-callback helper; on
 *     dada it is referenced only by the clang-inlined _copy_from_user
 *     glue (.text+0x750, the TTBR0-swap uaccess fast path).  5.15's
 *     native copy_from_user() already carries the PAN/SW_PAN handling,
 *     so the port uses copy_from_user() and the gap has no semantics;
 *     nothing to shim (same resolution as mm/mi_damon.c gap 1).
 *  2. system_cpucaps - 6.6 arm64 cpufeature bitmap; bit 38 of it gates
 *     the same inlined _copy_from_user fast path (tbnz x9, #38 at
 *     .text+0x848/0x858).  Absorbed by the native copy_from_user()
 *     exactly like plat_common absorbs its inlined-uaccess closure
 *     gaps: the symbol is not rebuilt, the semantics are carried by the
 *     in-tree implementation.  This port is built into the kernel image
 *     (or as a module against CONFIG_PLAT_COMMON/CONFIG_PERF_ACTUATOR,
 *     the same provider pattern plat_common established).
 *
 * Known behavioral deltas (documented, accepted for the experimental
 * branch)
 * -------------------------------------------------------------------
 * - The group table is statically allocated (20 entries) instead of
 *   walt's dynamically created group list; group existence is modelled
 *   with an "allocated" flag so the [RE] failure paths of
 *   perf_actuator_set_rtg_cpus / _set_rtg_util (-ENODEV) and
 *   os_cpu_init_rtg_grp_prefer_cpus ("grp not found") stay reachable.
 * - The task->group mapping does not take a task reference (dada's walt
 *   group list owns one - perf_actuator_clear_rtg's get/put pair guards
 *   the set_group_id call, that pairing is kept).  Nodes are removed
 *   from the android_vh_free_task vendor hook; on 5.15 free_task() runs
 *   before the task_struct slab object (SLAB_TYPESAFE_BY_RCU) can be
 *   reused, so no stale pointer is observable, and a dying task is
 *   skipped through refcount_inc_not_zero exactly like the original
 *   clear loop.
 * - plat_sched_set_group_id() is called outside the rcu_read_lock()
 *   section in perf_actuator_set_task_rtg / _set_task_array_rtg (dada
 *   calls it inside): the Sew hook must kmalloc the mapping node and
 *   must not sleep under rcu_read_lock(); a get_task_struct /
 *   put_task_struct pair preserves the same task lifetime guarantee.
 * - "rtg: task == NULL %d" exists in rtg.ko .rodata but is referenced
 *   by no code path in the binary; not reproduced.
 */

#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <trace/hooks/sched.h>

/*
 * mm/plat_common.c and mm/perf_actuator.c exports (original dada ABI,
 * no shared header in the dada tree either).
 */
extern int register_plat_func(int id, void *fn);
extern int unregister_plat_func(int id);
extern struct walt_related_thread_group *plat_lookup_related_thread_group(int group_id);
extern int plat_sched_set_group_id(struct task_struct *p, unsigned int grp_id);
extern void plat_core_ctl_update(int cpu);
extern int register_perf_actuator(int idx, int (*func)(unsigned long arg));
extern int unregister_perf_actuator(int idx);

/*
 * Hook slot ids from mm/plat_common.c (enum plat_hook_id, recovered from
 * plat_common.ko BTF); no shared header, same constants.
 */
#define FUNC_SCHED_SET_GROUP_ID			1
#define FUNC_GET_GROUP_PREFER_CPUS		9
#define FUNC_GET_GROUP_PREFER_UTIL		10
#define FUNC_LOOKUP_RELATED_THREAD_GROUP	12

/*
 * perf_actuator ioctl commands. [RE] init_module registers exactly these
 * five (register_perf_actuator keeps only the low byte as slot).
 */
#define SET_TASK_RTG				0x40087802
#define SET_TASK_ARRAY_RTG			0x40447825
#define SET_RTG_CPUS				0x40087803
#define SET_RTG_UTIL				0x40087804
#define CLR_RTG					0x40047807

/*
 * [RE] Group id space: 0..19 (cmp w0, #0x13 / b.hi in
 * get_related_thread_group, perf_actuator_set_rtg_cpus,
 * perf_actuator_set_rtg_util and perf_actuator_clear_rtg); id 1 is
 * rejected everywhere (cmp w0, #0x1 / b.eq); id 0 is the default group.
 */
#define MAX_SCHED_RTG_GRP_ID			20
#define RTG_DEFAULT_GRP_ID			0
#define RTG_RESERVED_GRP_ID			1

/* [RE] os_cpu_init_rtg_grp_prefer_cpus hardcodes group 13 (mov w0, #0xd). */
#define RTG_INIT_GRP_ID				13

/*
 * [RE] struct walt_related_thread_group (dada module BTF, 104 bytes).
 * Offsets verified against rtg.ko: +4 tasks_lock, +8 tasks,
 * +88 rtg_prefer_cpus (perf_actuator_set_rtg_cpus: str x20, [x0, #88];
 * os_cpu_get_group_prefer_cpus: ldr x8, [x8, #88]), +96 rtg_util
 * (perf_actuator_set_rtg_util: str x9, [x8, #96]).  The Sew port keeps
 * the same fields; only the type name is ABI, the layout is internal.
 */
struct walt_related_thread_group {
	int id;
	/* dada struct ABI; this port serializes on the global rtg_lock
	 * instead - tasks_lock is unused and must stay unused. */
	raw_spinlock_t tasks_lock;
	struct list_head tasks;
	bool allocated;			/* walt creates groups lazily */
	unsigned long rtg_prefer_cpus;	/* preferred cpumask word 0 */
	unsigned long rtg_util;		/* preferred utilization, <= 1024 */
};

/*
 * task->group mapping node. [PORT-DELTA] dada stores the group pointer
 * inside the walt task extension (task_struct + 3248, read by every
 * os_cpu_* helper); Sew 5.15 has no walt extension, so the mapping is an
 * external hash on the task pointer.  A node hangs off both the group's
 * tasks list (@gnode) and the hash bucket (@hnode) and owns no task
 * reference (see header comment).
 */
struct rtg_task_node {
	struct list_head gnode;
	struct hlist_node hnode;
	struct task_struct *task;
	struct walt_related_thread_group *grp;
};

#define RTG_HASH_BITS	8
#define RTG_HASH_SIZE	(1U << RTG_HASH_BITS)

/* [RE] perf_actuator_clear_rtg iterates at most 200 times (w26 counts
 * from -200 to 0) before giving up with -EAGAIN. */
#define RTG_CLEAR_MAX_ITERS	200

static struct walt_related_thread_group rtg_groups[MAX_SCHED_RTG_GRP_ID];
static struct hlist_head rtg_task_hash[RTG_HASH_SIZE];
static DEFINE_RAW_SPINLOCK(rtg_lock);

/* ---- group id validation ([RE] shared by all four entries) ------------ */

static bool rtg_grp_id_valid(int grp_id)
{
	/* [RE] grp_id == 1 (cmp #0x1 / b.eq) and grp_id > 19 (cmp #0x13 /
	 * b.hi, unsigned) are rejected. */
	if (grp_id == RTG_RESERVED_GRP_ID ||
	    (unsigned int)grp_id >= MAX_SCHED_RTG_GRP_ID)
		return false;
	return true;
}

/* ---- group store ------------------------------------------------------ */

/* Caller holds rtg_lock. */
static struct walt_related_thread_group *rtg_lookup_group_locked(int grp_id)
{
	if (grp_id < 0 || grp_id >= MAX_SCHED_RTG_GRP_ID)
		return NULL;
	if (!READ_ONCE(rtg_groups[grp_id].allocated))
		return NULL;
	return &rtg_groups[grp_id];
}

/* Caller holds rtg_lock. */
static struct rtg_task_node *rtg_find_node_locked(struct task_struct *p)
{
	struct rtg_task_node *node;

	hlist_for_each_entry(node, &rtg_task_hash[hash_ptr(p, RTG_HASH_BITS)],
			     hnode)
		if (node->task == p)
			return node;
	return NULL;
}

/* Caller holds rtg_lock. */
static void rtg_del_node_locked(struct rtg_task_node *node)
{
	list_del(&node->gnode);
	hlist_del(&node->hnode);
}

/* ---- exported helpers (original dada ABI) ----------------------------- */

/**
 * get_related_thread_group - [RE] .text+0x4. Rejects ids 1 and >19, then
 * delegates to the plat_common lookup hook (walt on dada, our group
 * table through slot 12 here); returns NULL for a group that was never
 * created.
 */
struct walt_related_thread_group *get_related_thread_group(int grp_id)
{
	if (!rtg_grp_id_valid(grp_id))
		return NULL;
	return plat_lookup_related_thread_group(grp_id);
}
EXPORT_SYMBOL_GPL(get_related_thread_group);

/**
 * os_cpu_get_group_prefer_cpus - [RE] .text+0x40. Copies the preferred
 * CPU mask word of the group owning @p into @prefer_cpus; tasks without
 * a group (or with an all-zero mask) get the full possible mask
 * (dada: (u64)-1 >> (64 - nr_cpu_ids), aarch64 register shift takes the
 * low 6 bits - same expression plat_common uses as its default).
 */
void os_cpu_get_group_prefer_cpus(struct task_struct *p,
				  struct cpumask *prefer_cpus)
{
	struct rtg_task_node *node;
	struct walt_related_thread_group *grp = NULL;
	unsigned long mask = 0;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	node = rtg_find_node_locked(p);
	if (node) {
		grp = node->grp;
		mask = grp->rtg_prefer_cpus;
	}
	raw_spin_unlock_irqrestore(&rtg_lock, flags);

	/* [RE] cbz w8 on the low word of grp->rtg_prefer_cpus; the mask is
	 * always written from a u32 ioctl, so the low word is the whole
	 * mask. */
	if (grp && mask)
		*cpumask_bits(prefer_cpus) = mask;
	else
		*cpumask_bits(prefer_cpus) =
			~0UL >> ((0u - nr_cpu_ids) & (BITS_PER_LONG - 1));
}
EXPORT_SYMBOL_GPL(os_cpu_get_group_prefer_cpus);

/**
 * os_cpu_get_group_prefer_util - [RE] .text+0x78. Returns the group's
 * rtg_util (grp+96), 0 when the task has no group.
 */
unsigned long os_cpu_get_group_prefer_util(struct task_struct *p)
{
	struct rtg_task_node *node;
	unsigned long util = 0;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	node = rtg_find_node_locked(p);
	if (node)
		util = node->grp->rtg_util;
	raw_spin_unlock_irqrestore(&rtg_lock, flags);
	return util;
}
EXPORT_SYMBOL_GPL(os_cpu_get_group_prefer_util);

/**
 * os_cpu_is_task_prefer_cpu - [RE] .text+0x94. True unless the task's
 * group has a non-empty prefer mask that does not contain @cpu.
 */
int os_cpu_is_task_prefer_cpu(struct task_struct *p, int cpu)
{
	struct rtg_task_node *node;
	unsigned long mask = 0;
	unsigned long flags;
	int ret = 1;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	node = rtg_find_node_locked(p);
	if (node)
		mask = node->grp->rtg_prefer_cpus;
	raw_spin_unlock_irqrestore(&rtg_lock, flags);

	if (mask) {
		/* [RE] lsr x8, x8, x9 / and w0, w8, #1 - the aarch64
		 * register shift wraps modulo 64; C cannot, so cap it. */
		if (cpu >= 0 && cpu < BITS_PER_LONG)
			ret = (int)(1UL & (mask >> cpu));
		else
			ret = 0;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(os_cpu_is_task_prefer_cpu);

/**
 * os_cpu_can_migrate_task - [RE] .text+0xcc. A task whose group prefers
 * CPUs may only migrate between two preferred CPUs; everything else
 * migrates freely (src outside the mask: keep, [RE] tbz w9, #0).
 */
int os_cpu_can_migrate_task(struct task_struct *p, int src_cpu, int dst_cpu)
{
	struct rtg_task_node *node;
	unsigned long mask = 0;
	unsigned long flags;
	int ret = 1;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	node = rtg_find_node_locked(p);
	if (node)
		mask = node->grp->rtg_prefer_cpus;
	raw_spin_unlock_irqrestore(&rtg_lock, flags);

	if (mask) {
		if (src_cpu >= 0 && src_cpu < BITS_PER_LONG &&
		    (1UL & (mask >> src_cpu)))
			ret = (dst_cpu >= 0 && dst_cpu < BITS_PER_LONG) ?
				(int)(1UL & (mask >> dst_cpu)) : 0;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(os_cpu_can_migrate_task);

/**
 * os_cpu_init_rtg_grp_prefer_cpus - [RE] .text+0x11c. Boot-time helper:
 * writes the low 8 bits of @prefer_cpus into group 13's prefer mask and
 * logs the result (two strings: success and "grp not found").
 */
void os_cpu_init_rtg_grp_prefer_cpus(unsigned int prefer_cpus)
{
	struct walt_related_thread_group *grp;

	grp = plat_lookup_related_thread_group(RTG_INIT_GRP_ID);
	if (grp)
		WRITE_ONCE(grp->rtg_prefer_cpus, prefer_cpus & 0xff);

	if (grp)
		pr_info("rtg: init grp %u prefer_cpus 0x%x\n",
			RTG_INIT_GRP_ID, prefer_cpus & 0xff);
	else
		pr_info("rtg: init grp %u prefer_cpus 0x%x failed: grp not found\n",
			RTG_INIT_GRP_ID, prefer_cpus & 0xff);
}
EXPORT_SYMBOL_GPL(os_cpu_init_rtg_grp_prefer_cpus);

/* ---- plat_common hooks (the walt backend role, merged in) ------------- */

/* slot 1 FUNC_SCHED_SET_GROUP_ID: create/leave groups; grp_id 0 removes
 * the task from its current group. Group creation is lazy, matching
 * walt: the first set_task_rtg materialises the group. */
static int rtg_plat_sched_set_group_id(struct task_struct *p,
				       unsigned int grp_id)
{
	struct rtg_task_node *node, *old;
	struct walt_related_thread_group *grp;
	unsigned long flags;

	if (grp_id == RTG_RESERVED_GRP_ID ||
	    grp_id >= MAX_SCHED_RTG_GRP_ID)
		return -EINVAL;

	if (grp_id != RTG_DEFAULT_GRP_ID) {
		node = kmalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		INIT_LIST_HEAD(&node->gnode);
		INIT_HLIST_NODE(&node->hnode);
		node->task = p;
		node->grp = &rtg_groups[grp_id];
	}

	raw_spin_lock_irqsave(&rtg_lock, flags);
	old = rtg_find_node_locked(p);
	if (old)
		rtg_del_node_locked(old);

	if (grp_id == RTG_DEFAULT_GRP_ID) {
		raw_spin_unlock_irqrestore(&rtg_lock, flags);
		kfree(old);
		return 0;
	}

	grp = &rtg_groups[grp_id];
	if (!grp->allocated)
		WRITE_ONCE(grp->allocated, true);

	if (old && old->grp == grp) {
		/* re-set to the same group: keep the existing node */
		list_add(&old->gnode, &grp->tasks);
		hlist_add_head(&old->hnode,
			       &rtg_task_hash[hash_ptr(p, RTG_HASH_BITS)]);
		raw_spin_unlock_irqrestore(&rtg_lock, flags);
		kfree(node);
		return 0;
	}

	list_add(&node->gnode, &grp->tasks);
	hlist_add_head(&node->hnode,
		       &rtg_task_hash[hash_ptr(p, RTG_HASH_BITS)]);
	raw_spin_unlock_irqrestore(&rtg_lock, flags);
	kfree(old);
	return 0;
}

/* slot 9 FUNC_GET_GROUP_PREFER_CPUS: forwards to the os_cpu helper, the
 * same data walt served on dada. */
static void rtg_plat_get_group_prefer_cpus(struct task_struct *p,
					   struct cpumask *prefer_cpus)
{
	os_cpu_get_group_prefer_cpus(p, prefer_cpus);
}

/* slot 10 FUNC_GET_GROUP_PREFER_UTIL */
static unsigned long rtg_plat_get_group_prefer_util(struct task_struct *p)
{
	return os_cpu_get_group_prefer_util(p);
}

/* slot 12 FUNC_LOOKUP_RELATED_THREAD_GROUP: pure table lookup, mirrors
 * walt (an uncreated group returns NULL so the [RE] -ENODEV / "grp not
 * found" paths of the ioctl handlers stay reachable). */
static struct walt_related_thread_group *
rtg_plat_lookup_related_thread_group(int group_id)
{
	struct walt_related_thread_group *grp;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	grp = rtg_lookup_group_locked(group_id);
	raw_spin_unlock_irqrestore(&rtg_lock, flags);
	return grp;
}

/* ---- task lifetime: drop mappings when the task is freed -------------- */

static void rtg_free_task_hook(void *data, struct task_struct *p)
{
	struct rtg_task_node *node;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	node = rtg_find_node_locked(p);
	if (node)
		rtg_del_node_locked(node);
	raw_spin_unlock_irqrestore(&rtg_lock, flags);
	kfree(node);
}

/* ---- perf_actuator ioctl handlers ([RE], names kept) ------------------ */

/**
 * perf_actuator_set_task_rtg - [RE] .text+0x178. Payload 8 bytes
 * {int pid; int grp_id}: put the vpid's task into group @grp_id.
 */
static int perf_actuator_set_task_rtg(unsigned long arg)
{
	struct {
		int pid;
		int grp_id;
	} data = {};
	struct task_struct *p;
	int ret;

	if (!arg)
		return -EINVAL;		/* [RE] cbz x0, -22 */
	if (copy_from_user(&data, (void __user *)(uintptr_t)arg,
			   sizeof(data)))
		return -EFAULT;		/* [RE] -14 */

	rcu_read_lock();
	p = find_task_by_vpid(data.pid);
	if (!p) {
		rcu_read_unlock();
		/* [RE] two spaces after "rtg:" in the original string. */
		pr_info("rtg:  task %d is not exist\n", data.pid);
		return -ENOENT;		/* [RE] -2 */
	}
	/* [PORT-DELTA] keep the task alive outside rcu (the hook sleeps). */
	get_task_struct(p);
	rcu_read_unlock();

	ret = plat_sched_set_group_id(p, data.grp_id);
	put_task_struct(p);

	if (ret)
		pr_info("rtg: set task %d to rtg %d failed\n",
			data.pid, data.grp_id);
	return ret;
}

/**
 * perf_actuator_set_task_array_rtg - [RE] .text+0x24c. Payload 68 bytes
 * {int grp_id; int task_num; u32 pids[15]}: put up to 15 vpids' tasks
 * into group @grp_id. Returns the last set_group_id status.
 */
static int perf_actuator_set_task_array_rtg(unsigned long arg)
{
	struct {
		int grp_id;
		int task_num;
		u32 pids[15];
	} data = {};
	struct task_struct *p;
	unsigned int i;
	int ret = 0;

	if (!arg)
		return -EINVAL;		/* [RE] cbz x0, -22 */
	if (copy_from_user(&data, (void __user *)(uintptr_t)arg,
			   sizeof(data)))
		return -EFAULT;		/* [RE] -14 */
	/* [RE] cmp w8, #0xf / b.hi: unsigned compare, task_num <= 15. */
	if ((unsigned int)data.task_num > 15)
		return -EFAULT;
	if (!data.task_num)
		return 0;		/* [RE] cbz w8 -> return 0 */

	for (i = 0; i < (unsigned int)data.task_num; i++) {
		u32 pid = data.pids[i];

		if (!pid)
			continue;	/* [RE] cbz w22, next */

		rcu_read_lock();
		p = find_task_by_vpid(pid);
		if (!p) {
			rcu_read_unlock();
			pr_info("rtg:  task %d is not exist\n", pid);
			continue;
		}
		get_task_struct(p);	/* [PORT-DELTA] see set_task_rtg */
		rcu_read_unlock();

		ret = plat_sched_set_group_id(p, data.grp_id);
		put_task_struct(p);

		if (ret)
			pr_info("rtg: set task %d to rtg %d failed\n",
				pid, data.grp_id);
	}
	return ret;
}

/**
 * perf_actuator_set_rtg_cpus - [RE] .text+0x390. Payload 8 bytes
 * {int grp_id; u32 cpus}: set the group's preferred CPU mask (32-bit,
 * zero-extended into the u64 word on dada) and nudge core control.
 * The mask write is lock-free exactly like the original (str x20).
 */
static int perf_actuator_set_rtg_cpus(unsigned long arg)
{
	struct {
		int grp_id;
		unsigned int cpus;
	} data = {};
	struct walt_related_thread_group *grp;

	if (!arg)
		return -EINVAL;		/* [RE] cbz x0, -22 */
	if (copy_from_user(&data, (void __user *)(uintptr_t)arg,
			   sizeof(data)))
		return -EFAULT;		/* [RE] -14 */

	/* [RE] id check first, then the lookup; both failures share the
	 * same log and -ENODEV (branch to .text+0x434). */
	if (!rtg_grp_id_valid(data.grp_id)) {
		pr_info("rtg: set preferred cpus for group %d fail\n",
			data.grp_id);
		return -ENODEV;
	}
	grp = plat_lookup_related_thread_group(data.grp_id);
	if (!grp) {
		pr_info("rtg: set preferred cpus for group %d fail\n",
			data.grp_id);
		return -ENODEV;		/* [RE] -19 */
	}
	WRITE_ONCE(grp->rtg_prefer_cpus, data.cpus);
	/* [RE] dada passes the group pointer (BTF-proto ambiguity, the
	 * wrapper only takes "int cpu"); pass the group id instead. */
	plat_core_ctl_update(data.grp_id);
	return 0;
}

/**
 * perf_actuator_set_rtg_util - [RE] .text+0x454. Payload 8 bytes
 * {int grp_id; u32 util}: set the group's preferred utilization,
 * clamped to 1024 ([RE] csel on cmp w20, #0x400).
 */
static int perf_actuator_set_rtg_util(unsigned long arg)
{
	struct {
		int grp_id;
		unsigned int util;
	} data = {};
	struct walt_related_thread_group *grp;

	if (!arg)
		return -EINVAL;		/* [RE] cbz x0, -22 */
	if (copy_from_user(&data, (void __user *)(uintptr_t)arg,
			   sizeof(data)))
		return -EFAULT;		/* [RE] -14 */

	/* [RE] id check first, then the lookup; both failures share the
	 * same log and -ENODEV (branch to .text+0x504). */
	if (!rtg_grp_id_valid(data.grp_id)) {
		pr_info("rtg: set prefer util for group %d fail\n",
			data.grp_id);
		return -ENODEV;
	}
	grp = plat_lookup_related_thread_group(data.grp_id);
	if (!grp) {
		pr_info("rtg: set prefer util for group %d fail\n",
			data.grp_id);
		return -ENODEV;		/* [RE] -19 */
	}
	WRITE_ONCE(grp->rtg_util, min((unsigned long)data.util, 1024UL));
	return 0;
}

/**
 * perf_actuator_clear_rtg - [RE] .text+0x524. Payload 4 bytes {int
 * grp_id}: remove every task from the group.  The original walks
 * grp->tasks taking head->next each round (nodes leave the list through
 * the set_group_id(0) call), takes a task reference outside the lock,
 * and gives up after 200 rounds with -EAGAIN if the list never drains.
 */
static int perf_actuator_clear_rtg(unsigned long arg)
{
	struct walt_related_thread_group *grp;
	struct rtg_task_node *node;
	unsigned long flags;
	bool empty;
	int grp_id = 0;
	int i;

	if (!arg)
		return -EINVAL;		/* [RE] cbz x0, -22 */
	if (copy_from_user(&grp_id, (void __user *)(uintptr_t)arg,
			   sizeof(grp_id)))
		return -EFAULT;		/* [RE] -14 */

	/* [RE] no log on these paths, plain -ENOENT. */
	if (!rtg_grp_id_valid(grp_id))
		return -ENOENT;
	grp = plat_lookup_related_thread_group(grp_id);
	if (!grp)
		return -ENOENT;

	raw_spin_lock_irqsave(&rtg_lock, flags);
	for (i = 0; i < RTG_CLEAR_MAX_ITERS; i++) {
		struct task_struct *p;

		node = list_first_entry_or_null(&grp->tasks,
						struct rtg_task_node, gnode);
		if (!node)
			break;
		p = node->task;
		/* [RE] refcount_add_not_zero(&p->usage) inline at
		 * .text+0x6a8: a dying task is skipped, the 200-round cap
		 * turns a stuck head into -EAGAIN exactly like the
		 * original overflow exit at .text+0x700. */
		if (!refcount_inc_not_zero(&p->usage))
			break;
		raw_spin_unlock_irqrestore(&rtg_lock, flags);
		plat_sched_set_group_id(p, RTG_DEFAULT_GRP_ID);
		put_task_struct(p);
		raw_spin_lock_irqsave(&rtg_lock, flags);
	}
	empty = list_empty(&grp->tasks);
	raw_spin_unlock_irqrestore(&rtg_lock, flags);

	/* [RE] w24 -> -11 (EAGAIN) when the list is still non-empty. */
	return empty ? 0 : -EAGAIN;
}

/* ---- module init/exit -------------------------------------------------- */

/*
 * [RE] init_module registers the five perf_actuator commands in this
 * order and ignores the register return values (the original performs
 * five plain bl calls and returns 0); the plat hook and vendor hook
 * registrations are the merged walt backend role and are checked.
 */
static int __init rtg_module_init(void)
{
	int ret;
	int i;

	for (i = 0; i < MAX_SCHED_RTG_GRP_ID; i++) {
		rtg_groups[i].id = i;
		raw_spin_lock_init(&rtg_groups[i].tasks_lock);
		INIT_LIST_HEAD(&rtg_groups[i].tasks);
		rtg_groups[i].allocated = (i == RTG_DEFAULT_GRP_ID);
	}

	ret = register_perf_actuator(SET_TASK_RTG, perf_actuator_set_task_rtg);
	if (ret)
		return ret;
	ret = register_perf_actuator(SET_TASK_ARRAY_RTG,
				     perf_actuator_set_task_array_rtg);
	if (ret)
		goto err_pact0;
	ret = register_perf_actuator(SET_RTG_CPUS, perf_actuator_set_rtg_cpus);
	if (ret)
		goto err_pact1;
	ret = register_perf_actuator(SET_RTG_UTIL, perf_actuator_set_rtg_util);
	if (ret)
		goto err_pact2;
	ret = register_perf_actuator(CLR_RTG, perf_actuator_clear_rtg);
	if (ret)
		goto err_pact3;

	ret = register_plat_func(FUNC_SCHED_SET_GROUP_ID,
				 rtg_plat_sched_set_group_id);
	if (ret)
		goto err_pact4;
	ret = register_plat_func(FUNC_GET_GROUP_PREFER_CPUS,
				 rtg_plat_get_group_prefer_cpus);
	if (ret)
		goto err_pf1;
	ret = register_plat_func(FUNC_GET_GROUP_PREFER_UTIL,
				 rtg_plat_get_group_prefer_util);
	if (ret)
		goto err_pf2;
	ret = register_plat_func(FUNC_LOOKUP_RELATED_THREAD_GROUP,
				 rtg_plat_lookup_related_thread_group);
	if (ret)
		goto err_pf3;

	ret = register_trace_android_vh_free_task(rtg_free_task_hook, NULL);
	if (ret)
		goto err_pf4;

	return 0;

err_pf4:
	unregister_plat_func(FUNC_LOOKUP_RELATED_THREAD_GROUP);
err_pf3:
	unregister_plat_func(FUNC_GET_GROUP_PREFER_UTIL);
err_pf2:
	unregister_plat_func(FUNC_GET_GROUP_PREFER_CPUS);
err_pf1:
	unregister_plat_func(FUNC_SCHED_SET_GROUP_ID);
err_pact4:
	unregister_perf_actuator(CLR_RTG);
err_pact3:
	unregister_perf_actuator(SET_RTG_UTIL);
err_pact2:
	unregister_perf_actuator(SET_RTG_CPUS);
err_pact1:
	unregister_perf_actuator(SET_TASK_ARRAY_RTG);
err_pact0:
	unregister_perf_actuator(SET_TASK_RTG);
	return ret;
}

/*
 * [PORT-DELTA] dada rtg.ko has no cleanup (intree, no exit section);
 * as a tristate Sew module it must at least unregister its hooks to
 * stay unload-safe. Group table state is dropped with it.
 */
static void __exit rtg_module_exit(void)
{
	struct rtg_task_node *node;
	struct hlist_node *tmp;
	unsigned long bkt;
	unsigned long flags;

	unregister_trace_android_vh_free_task(rtg_free_task_hook, NULL);
	tracepoint_synchronize_unregister();

	unregister_plat_func(FUNC_SCHED_SET_GROUP_ID);
	unregister_plat_func(FUNC_GET_GROUP_PREFER_CPUS);
	unregister_plat_func(FUNC_GET_GROUP_PREFER_UTIL);
	unregister_plat_func(FUNC_LOOKUP_RELATED_THREAD_GROUP);

	unregister_perf_actuator(SET_TASK_RTG);
	unregister_perf_actuator(SET_TASK_ARRAY_RTG);
	unregister_perf_actuator(SET_RTG_CPUS);
	unregister_perf_actuator(SET_RTG_UTIL);
	unregister_perf_actuator(CLR_RTG);

	raw_spin_lock_irqsave(&rtg_lock, flags);
	for (bkt = 0; bkt < RTG_HASH_SIZE; bkt++) {
		hlist_for_each_entry_safe(node, tmp, &rtg_task_hash[bkt],
					  hnode) {
			rtg_del_node_locked(node);
			kfree(node);
		}
	}
	raw_spin_unlock_irqrestore(&rtg_lock, flags);
}

module_init(rtg_module_init);
module_exit(rtg_module_exit);

MODULE_LICENSE("GPL v2");
