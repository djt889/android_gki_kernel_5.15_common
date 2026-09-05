// SPDX-License-Identifier: GPL-2.0
/*
 * mm/plat_common.c - Sew 5.15 port of Xiaomi dada OS4 "plat_common.ko"
 *                    (OS-CPU Platform Hook dispatch library)
 *
 * Reverse-engineered from:
 *   /root/work/os4_dada/ko/plat_common.ko
 *   vermagic 6.6.57-android15-8-g32a50a34de2b-4k, license "GPL v2",
 *   description "OS-CPU Platform Hook", zero dependencies,
 *   1 vendor hook (android_rvh_finish_prio_fork), 2 module params
 *   (critical_rt_prio:uint, sched_relaxed:uint, both 0644),
 *   39 GPL exports (__ksymtab_gpl = 39 entries, matches nm).
 *
 * Evidence: E:/AI/SewKernel/.omz/research/
 *   sess_d9452f03-b737-460b-bd27-aff04c01b561-os4-force-port/raw/re-plat-common.txt
 *   (full objdump -d of .text/.init.text/.exit.text, strings, __param,
 *    .data/.bss layout and module-BTF dump).
 *
 * Architecture recovered from disassembly + module BTF:
 *   - g_plat_hook_table: 36-entry registry (PLAT_HOOK_MAX_NR = 36), each
 *     entry (struct plat_unit) is 16 bytes: { int id; void *fn; }
 *     (register_plat_func strides entries by 16: `add x21, x8, w21, uxtw #4`,
 *     stores 32-bit id at +0 and fn pointer at +8).
 *   - register_plat_func(id, fn): rejects (id & 0xff) > 0x23 (=35) or
 *     fn == NULL with -EINVAL; takes g_table_rwsem for write; if the slot is
 *     occupied it prints a warning and *still overwrites* (branch back to the
 *     store); stores full id then fn; returns 0.
 *   - unregister_plat_func(id): rejects bad id with -EINVAL; takes the
 *     write lock; warns when slot empty or stored id mismatch, then clears
 *     id+fn anyway and returns 0 (the warn path branches back into the clear
 *     sequence).
 *   - The 35 plat_* exported wrappers each load the fn pointer at
 *     g_plat_hook_table + 16*slot + 8 (plain load, no lock - same as
 *     original) and tail-dispatch; when no hook is registered each returns
 *     its hardcoded default (see per-function comments).
 *   - Slot ids come from the module BTF enum (FUNC_SCHED_SET_GROUP_ID = 1 ..
 *     FUNC_ENABLE_GPUSYNC = 35, PLAT_HOOK_MAX_NR = 36) and match the dispatch
 *     offsets 1:1.
 *
 * Log strings are byte-identical to .rodata of the binary, including the
 * upstream copy-paste artifact "perf_actuator" inside the register/unregister
 * conflict warnings.
 *
 * [RE]     = behaviour fully determined from disassembly.
 * [RE-STUB]= parts that could not be determined from the binary (dada vendor
 *            task_struct fields / hook provider ABI); safe default used.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/cpumask.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/printk.h>
#include <trace/hooks/sched.h>

/*
 * Forward declarations of dada-internal types. plat_common only ever passes
 * these by pointer, so incomplete types suffice. The real definitions live in
 * the dada provider modules (rtg.ko / sched-walt.ko / mi_game.ko); a future
 * Sew port of those must supply matching definitions.
 */
struct walt_related_thread_group;
struct metis_choose_cpu_args;
struct sched_cluster;
struct rq;

/*
 * Hook slot ids. [RE] Module BTF enum, values verified against the dispatch
 * offsets: slot N wrapper loads g_plat_hook_table + 16*N + 8.
 */
enum plat_hook_id {
	FUNC_SCHED_SET_GROUP_ID = 1,
	FUNC_SCHED_GET_GROUP_ID = 2,
	FUNC_TASK_UTIL = 3,
	FUNC_CPU_HALTED = 4,
	FUNC_CPU_HALT_MASK = 5,
	FUNC_CAPACITY_ORIG_OF = 6,
	FUNC_IS_MAX_POSSIBLE_CLUSTER_CPU = 7,
	FUNC_FIND_IDLE_CPU_IN_FREQ_DOMAIN = 8,
	FUNC_GET_GROUP_PREFER_CPUS = 9,
	FUNC_GET_GROUP_PREFER_UTIL = 10,
	FUNC_CORE_CTL_UPDATE = 11,
	FUNC_LOOKUP_RELATED_THREAD_GROUP = 12,
	FUNC_MI_GAME_FIND_ENERGY_HOOK = 13,
	FUNC_MIGT_HOOK = 14,		/* plat_update_pkg_load */
	FUNC_MI_GAME_WALT_GET_INDICIES = 15,
	FUNC_GAME_GET_RAVG_WINDOW = 16,
	FUNC_MI_SET_NEXT_FREQ = 17,
	FUNC_MI_GAME_TASK_FORK = 18,
	FUNC_MI_GAME_SCHEDULER_TICK = 19,
	FUNC_MI_GAME_CHOOSE_CPU_FASTPATH = 20,
	FUNC_FREE_MI_TASK_STRUCT = 21,
	FUNC_MI_GAME_CHOOSE_EXCLUSIVE_CPUS = 22,
	FUNC_MI_GAME_CHOOSE_CPU = 23,
	FUNC_MI_GAME_SKIP_CPUS = 24,
	FUNC_MI_GAME_SKIP_CPUS_RT = 25,
	FUNC_MI_GAME_SHOULD_SKIP_CPU_RT = 26,
	FUNC_MI_GAME_SHOULD_SKIP_MIGRATE = 27,
	FUNC_MI_GAME_CHECK_RT = 28,
	FUNC_MI_GAME_VIP_CHECK = 29,
	FUNC_MIGT_ENABLE = 30,
	FUNC_UPDATE_FRAME_LOAD = 31,
	FUNC_FLT_ENABLE = 32,
	FUNC_GET_WAKEUP_INFO = 33,
	FUNC_MI_FORCE_UPDATE_FREQ = 34,
	FUNC_ENABLE_GPUSYNC = 35,
	PLAT_HOOK_MAX_NR = 36
};

/*
 * [RE] Registry unit, 16 bytes on aarch64: 32-bit id at +0, fn at +8.
 * (Disassembly of register/unregister; module BTF `struct plat_unit`.)
 */
struct plat_unit {
	int id;
	void *fn;
};

/* [RE] g_plat_hook_table: .bss symbol, sized by PLAT_HOOK_MAX_NR = 36. */
static struct plat_unit g_plat_hook_table[PLAT_HOOK_MAX_NR];
static DECLARE_RWSEM(g_table_rwsem);

/*
 * Module params. [RE] __param section: two entries, perm 0x01a4 = 0644,
 * parmtype uint both. Defaults from .data/.bss: critical_rt_prio = 96
 * (.data+0x50 = 0x60), sched_relaxed = 0 (.bss+0x248).
 */
static unsigned int critical_rt_prio = 96;
module_param(critical_rt_prio, uint, 0644);
MODULE_PARM_DESC(critical_rt_prio, "RT priority ceiling treated as critical by plat_is_relaxed_rt");

static unsigned int sched_relaxed;
module_param(sched_relaxed, uint, 0644);
MODULE_PARM_DESC(sched_relaxed, "Enable relaxed-RT identification (plat_is_relaxed_rt)");

/*
 * Sched cgroup ids identified by plat_init_sched_cgroup_id.
 * [RE] .data+0x40/0x44/0x48/0x4c, all initialised to 0xffffffff (-1);
 * matched against level-1 cgroup names "top-app"/"foreground"/
 * "background"/"audio" (.rodata+0xa1/0x96/0x0/0xdd).
 */
static int ta_grp_id = -1;
static int fg_grp_id = -1;
static int bg_grp_id = -1;
static int au_grp_id = -1;

/*
 * [RE] Default return value of plat_cpu_halt_mask: pointer to a zeroed
 * cpumask in .bss (+0x240, 8 bytes on the 8-CPU target).
 */
static struct cpumask g_cpu_halt_mask;

/* [RE] Dispatch reads the fn pointer with a plain load, exactly like the
 * original wrappers (ldr, no lock). Writers hold g_table_rwsem for write. */
static void *plat_hook_fn(unsigned int slot)
{
	if (slot >= PLAT_HOOK_MAX_NR)
		return NULL;
	return READ_ONCE(g_plat_hook_table[slot].fn);
}

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

/*
 * [RE] register_plat_func @ .text+0x4.
 * Returns -EINVAL when (id & 0xff) > 0x23 or fn == NULL, else 0.
 * Warns (KERN_WARNING, .rodata+0x65: "plat_hook: perf_actuator: register %u
 * conflict") on occupied slot and overwrites anyway.
 */
int register_plat_func(int id, void *fn)
{
	struct plat_unit *unit;

	if ((id & 0xff) > (PLAT_HOOK_MAX_NR - 1) || !fn)
		return -EINVAL;

	down_write(&g_table_rwsem);
	unit = &g_plat_hook_table[id & 0xff];
	if (unit->fn)
		pr_warn("plat_hook: perf_actuator: register %u conflict\n",
			id);
	unit->id = id;
	WRITE_ONCE(unit->fn, fn);
	up_write(&g_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(register_plat_func);

/*
 * [RE] unregister_plat_func @ .text+0x9c.
 * -EINVAL for bad id; warns (.rodata+0xaa: "plat_hook: perf_actuator:
 * unregister %u conflict") when slot empty or stored id != id, then clears
 * and returns 0 regardless.
 */
int unregister_plat_func(int id)
{
	struct plat_unit *unit;

	if ((id & 0xff) > (PLAT_HOOK_MAX_NR - 1))
		return -EINVAL;

	down_write(&g_table_rwsem);
	unit = &g_plat_hook_table[id & 0xff];
	if (!unit->fn || unit->id != id)
		pr_warn("plat_hook: perf_actuator: unregister %u conflict\n",
			id);
	unit->id = 0;
	WRITE_ONCE(unit->fn, NULL);
	up_write(&g_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(unregister_plat_func);

/* ------------------------------------------------------------------ */
/* Dispatch wrappers (slots 1..35)                                     */
/* ------------------------------------------------------------------ */

/* slot 1 [RE] default return 0 (mov w0, wzr). */
typedef int (*plat_sched_set_group_id_fn_t)(struct task_struct *p,
					    unsigned int grp_id);
int plat_sched_set_group_id(struct task_struct *p, unsigned int grp_id)
{
	plat_sched_set_group_id_fn_t fn = plat_hook_fn(FUNC_SCHED_SET_GROUP_ID);

	if (fn)
		return fn(p, grp_id);
	return 0;
}
EXPORT_SYMBOL_GPL(plat_sched_set_group_id);

/* slot 2 [RE] default return 0. */
typedef int (*plat_sched_get_group_id_fn_t)(struct task_struct *p);
int plat_sched_get_group_id(struct task_struct *p)
{
	plat_sched_get_group_id_fn_t fn = plat_hook_fn(FUNC_SCHED_GET_GROUP_ID);

	if (fn)
		return fn(p);
	return 0;
}
EXPORT_SYMBOL_GPL(plat_sched_get_group_id);

/* slot 3 [RE] default return 0 (mov x0, xzr), 64-bit. */
typedef unsigned long (*plat_task_util_fn_t)(struct task_struct *p);
unsigned long plat_task_util(struct task_struct *p)
{
	plat_task_util_fn_t fn = plat_hook_fn(FUNC_TASK_UTIL);

	if (fn)
		return fn(p);
	return 0;
}
EXPORT_SYMBOL_GPL(plat_task_util);

/*
 * slot 4 [RE] returns bool (hook result masked with and w0, w0, #1;
 * default 0). Param not recoverable from the binary (deduped BTF proto);
 * (int cpu) chosen by semantics - [RE-STUB] ABI.
 */
typedef bool (*plat_cpu_halted_fn_t)(int cpu);
bool plat_cpu_halted(int cpu)
{
	plat_cpu_halted_fn_t fn = plat_hook_fn(FUNC_CPU_HALTED);

	if (fn)
		return fn(cpu);
	return false;
}
EXPORT_SYMBOL_GPL(plat_cpu_halted);

/*
 * slot 5 [RE] default returns pointer to a zeroed static cpumask
 * (.bss+0x240). No args observed.
 */
typedef struct cpumask *(*plat_cpu_halt_mask_fn_t)(void);
struct cpumask *plat_cpu_halt_mask(void)
{
	plat_cpu_halt_mask_fn_t fn = plat_hook_fn(FUNC_CPU_HALT_MASK);

	if (fn)
		return fn();
	return &g_cpu_halt_mask;
}
EXPORT_SYMBOL_GPL(plat_cpu_halt_mask);

/*
 * slot 6. [RE] literal default in the binary is x0 = 0; per port spec the
 * 5.15 capacity query (arch_scale_cpu_capacity) is used as the fallback
 * instead so callers never see a bogus 0-capacity CPU.
 */
typedef unsigned long (*plat_capacity_orig_of_fn_t)(int cpu);
unsigned long plat_capacity_orig_of(int cpu)
{
	plat_capacity_orig_of_fn_t fn = plat_hook_fn(FUNC_CAPACITY_ORIG_OF);

	if (fn)
		return fn(cpu);
#ifdef CONFIG_SMP
	return arch_scale_cpu_capacity(cpu);
#else
	return SCHED_CAPACITY_SCALE;
#endif
}
EXPORT_SYMBOL_GPL(plat_capacity_orig_of);

/* slot 7 [RE] bool (and w0, w0, #1), default 0; shares the deduped BTF
 * proto with plat_cpu_halted -> same 1-arg shape. [RE-STUB] ABI. */
typedef bool (*plat_is_max_possible_cluster_cpu_fn_t)(int cpu);
bool plat_is_max_possible_cluster_cpu(int cpu)
{
	plat_is_max_possible_cluster_cpu_fn_t fn =
		plat_hook_fn(FUNC_IS_MAX_POSSIBLE_CLUSTER_CPU);

	if (fn)
		return fn(cpu);
	return false;
}
EXPORT_SYMBOL_GPL(plat_is_max_possible_cluster_cpu);

/* slot 8 [RE] default return -1 (mov w0, #0xffffffff). [RE-STUB] ABI. */
typedef int (*plat_find_idle_cpu_in_freq_domain_fn_t)(struct task_struct *p);
int plat_find_idle_cpu_in_freq_domain(struct task_struct *p)
{
	plat_find_idle_cpu_in_freq_domain_fn_t fn =
		plat_hook_fn(FUNC_FIND_IDLE_CPU_IN_FREQ_DOMAIN);

	if (fn)
		return fn(p);
	return -1;
}
EXPORT_SYMBOL_GPL(plat_find_idle_cpu_in_freq_domain);

/*
 * slot 9 [RE] default writes a single 64-bit word to the out-mask:
 *   ldr w8, nr_cpu_ids; neg w8, w8; lsr x8, x9(-1), x8; str x8, [x1]
 * i.e. *prefer_cpus = ~0UL >> ((u32)-nr_cpu_ids & 63).
 * Param names from module BTF: (task_struct *, cpumask *prefer_cpus).
 */
typedef void (*plat_get_group_prefer_cpus_fn_t)(struct task_struct *p,
						struct cpumask *prefer_cpus);
void plat_get_group_prefer_cpus(struct task_struct *p,
				struct cpumask *prefer_cpus)
{
	plat_get_group_prefer_cpus_fn_t fn =
		plat_hook_fn(FUNC_GET_GROUP_PREFER_CPUS);

	if (fn) {
		fn(p, prefer_cpus);
		return;
	}
	*cpumask_bits(prefer_cpus) =
		~0UL >> ((0u - nr_cpu_ids) & (BITS_PER_LONG - 1));
}
EXPORT_SYMBOL_GPL(plat_get_group_prefer_cpus);

/* slot 10 [RE] default return 0. */
typedef unsigned long (*plat_get_group_prefer_util_fn_t)(struct task_struct *p);
unsigned long plat_get_group_prefer_util(struct task_struct *p)
{
	plat_get_group_prefer_util_fn_t fn =
		plat_hook_fn(FUNC_GET_GROUP_PREFER_UTIL);

	if (fn)
		return fn(p);
	return 0;
}
EXPORT_SYMBOL_GPL(plat_get_group_prefer_util);

/*
 * slot 11 [RE] void (no default value is produced; both paths plain ret).
 * [RE-STUB] ABI: BTF proto was deduped against an unrelated kernel shape
 * (3 pointer args); (int cpu) chosen by semantics.
 */
typedef void (*plat_core_ctl_update_fn_t)(int cpu);
void plat_core_ctl_update(int cpu)
{
	plat_core_ctl_update_fn_t fn = plat_hook_fn(FUNC_CORE_CTL_UPDATE);

	if (fn)
		fn(cpu);
}
EXPORT_SYMBOL_GPL(plat_core_ctl_update);

/*
 * slot 12 [RE] default return NULL; return type is the module's own
 * struct walt_related_thread_group (BTF, 104 bytes) - passed by pointer.
 * BTF shows one argument (group id).
 */
typedef struct walt_related_thread_group *
(*plat_lookup_related_thread_group_fn_t)(int group_id);
struct walt_related_thread_group *plat_lookup_related_thread_group(int group_id)
{
	plat_lookup_related_thread_group_fn_t fn =
		plat_hook_fn(FUNC_LOOKUP_RELATED_THREAD_GROUP);

	if (fn)
		return fn(group_id);
	return NULL;
}
EXPORT_SYMBOL_GPL(plat_lookup_related_thread_group);

/* slot 13 [RE] void, 2 params (param name "need_idle" from module BTF). */
typedef void (*plat_mi_game_find_energy_hook_fn_t)(struct task_struct *p,
						   bool need_idle);
void plat_mi_game_find_energy_hook(struct task_struct *p, bool need_idle)
{
	plat_mi_game_find_energy_hook_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_FIND_ENERGY_HOOK);

	if (fn)
		fn(p, need_idle);
}
EXPORT_SYMBOL_GPL(plat_mi_game_find_energy_hook);

/*
 * slot 14 (BTF enum name: FUNC_MIGT_HOOK) [RE] void, 5 params; only
 * "wallclock" survived dedup readable (u64-sized). [RE-STUB] ABI for the
 * remaining params - generic widths chosen, forwarded verbatim.
 */
typedef void (*plat_update_pkg_load_fn_t)(struct task_struct *p,
					  void *arg2, void *arg3,
					  u64 wallclock, unsigned long arg5);
void plat_update_pkg_load(struct task_struct *p, void *arg2, void *arg3,
			  u64 wallclock, unsigned long arg5)
{
	plat_update_pkg_load_fn_t fn = plat_hook_fn(FUNC_MIGT_HOOK);

	if (fn)
		fn(p, arg2, arg3, wallclock, arg5);
}
EXPORT_SYMBOL_GPL(plat_update_pkg_load);

/*
 * slot 15 [RE] void, 6 params; readable names: order_index,
 * num_sched_clusters, skip_walt_indicies, energy_eval_needed.
 * [RE-STUB] ABI for exact out-param types.
 */
typedef void (*plat_mi_game_walt_get_indicies_fn_t)(struct task_struct *p,
		unsigned long *order_index, unsigned long *indicies2,
		int *num_sched_clusters, bool *skip_walt_indicies,
		bool *energy_eval_needed);
void plat_mi_game_walt_get_indicies(struct task_struct *p,
		unsigned long *order_index, unsigned long *indicies2,
		int *num_sched_clusters, bool *skip_walt_indicies,
		bool *energy_eval_needed)
{
	plat_mi_game_walt_get_indicies_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_WALT_GET_INDICIES);

	if (fn)
		fn(p, order_index, indicies2, num_sched_clusters,
		   skip_walt_indicies, energy_eval_needed);
}
EXPORT_SYMBOL_GPL(plat_mi_game_walt_get_indicies);

/* slot 16 [RE] void, 1 param (name "old_ravg_window" from module BTF). */
typedef void (*plat_game_get_ravg_window_fn_t)(u64 *old_ravg_window);
void plat_game_get_ravg_window(u64 *old_ravg_window)
{
	plat_game_get_ravg_window_fn_t fn =
		plat_hook_fn(FUNC_GAME_GET_RAVG_WINDOW);

	if (fn)
		fn(old_ravg_window);
}
EXPORT_SYMBOL_GPL(plat_game_get_ravg_window);

/*
 * slot 17 [RE] void. The wrapper rebuilds the outgoing stack frame and
 * forwards stack args 1..2 (total >= 8 params: 6 register + 2 stack);
 * module BTF says 10 but only two stack words are ever moved, so 8 is the
 * forwarded ABI. [RE-STUB] all param types unknown - forwarded verbatim.
 */
typedef void (*plat_mi_set_next_freq_fn_t)(unsigned long a1, unsigned long a2,
					   unsigned long a3, unsigned long a4,
					   unsigned long a5, unsigned long a6,
					   unsigned long a7, unsigned long a8);
void plat_mi_set_next_freq(unsigned long a1, unsigned long a2,
			   unsigned long a3, unsigned long a4,
			   unsigned long a5, unsigned long a6,
			   unsigned long a7, unsigned long a8)
{
	plat_mi_set_next_freq_fn_t fn = plat_hook_fn(FUNC_MI_SET_NEXT_FREQ);

	if (fn)
		fn(a1, a2, a3, a4, a5, a6, a7, a8);
}
EXPORT_SYMBOL_GPL(plat_mi_set_next_freq);

/* slot 18 [RE] void, 1 param (task_struct *). */
typedef void (*plat_mi_game_task_fork_fn_t)(struct task_struct *p);
void plat_mi_game_task_fork(struct task_struct *p)
{
	plat_mi_game_task_fork_fn_t fn = plat_hook_fn(FUNC_MI_GAME_TASK_FORK);

	if (fn)
		fn(p);
}
EXPORT_SYMBOL_GPL(plat_mi_game_task_fork);

/* slot 19 [RE] void, 1 param (dada rq - forward-declared). */
typedef void (*plat_mi_game_scheduler_tick_fn_t)(struct rq *rq);
void plat_mi_game_scheduler_tick(struct rq *rq)
{
	plat_mi_game_scheduler_tick_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_SCHEDULER_TICK);

	if (fn)
		fn(rq);
}
EXPORT_SYMBOL_GPL(plat_mi_game_scheduler_tick);

/*
 * slot 20 [RE] int, default 0; params (task_struct *, metis_args,
 * should_skip cb) - names from module BTF. [RE-STUB] should_skip callback
 * prototype unknown (2 args per BTF) - generic form.
 */
typedef int (*plat_game_choose_cpu_fastpath_fn_t)(struct task_struct *p,
		struct metis_choose_cpu_args *metis_args,
		bool (*should_skip)(void *a, void *b));
int plat_game_choose_cpu_fastpath(struct task_struct *p,
		struct metis_choose_cpu_args *metis_args,
		bool (*should_skip)(void *a, void *b))
{
	plat_game_choose_cpu_fastpath_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_CHOOSE_CPU_FASTPATH);

	if (fn)
		return fn(p, metis_args, should_skip);
	return 0;
}
EXPORT_SYMBOL_GPL(plat_game_choose_cpu_fastpath);

/* slot 21 [RE] void, 1 param (task_struct *). */
typedef void (*plat_free_mi_task_struct_fn_t)(struct task_struct *p);
void plat_free_mi_task_struct(struct task_struct *p)
{
	plat_free_mi_task_struct_fn_t fn =
		plat_hook_fn(FUNC_FREE_MI_TASK_STRUCT);

	if (fn)
		fn(p);
}
EXPORT_SYMBOL_GPL(plat_free_mi_task_struct);

/* slot 22 [RE] int, default -1, 1 param. */
typedef int (*plat_game_choose_exclusive_cpus_fn_t)(struct task_struct *p);
int plat_game_choose_exclusive_cpus(struct task_struct *p)
{
	plat_game_choose_exclusive_cpus_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_CHOOSE_EXCLUSIVE_CPUS);

	if (fn)
		return fn(p);
	return -1;
}
EXPORT_SYMBOL_GPL(plat_game_choose_exclusive_cpus);

/* slot 23 [RE] int, default -1, 1 param. */
typedef int (*plat_game_choose_cpu_fn_t)(struct task_struct *p);
int plat_game_choose_cpu(struct task_struct *p)
{
	plat_game_choose_cpu_fn_t fn = plat_hook_fn(FUNC_MI_GAME_CHOOSE_CPU);

	if (fn)
		return fn(p);
	return -1;
}
EXPORT_SYMBOL_GPL(plat_game_choose_cpu);

/* slot 24 [RE] bool (and w0, w0, #1), default 0; 1 param named
 * "mi_game_reserve_cpus" (cpumask-var-sized) in module BTF. */
typedef bool (*plat_game_skip_cpus_fn_t)(cpumask_var_t mi_game_reserve_cpus);
bool plat_game_skip_cpus(cpumask_var_t mi_game_reserve_cpus)
{
	plat_game_skip_cpus_fn_t fn = plat_hook_fn(FUNC_MI_GAME_SKIP_CPUS);

	if (fn)
		return fn(mi_game_reserve_cpus);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_skip_cpus);

/* slot 25 [RE] bool, default 0; 2 params (task_struct *, reserve cpumask). */
typedef bool (*plat_game_skip_cpus_rt_fn_t)(struct task_struct *p,
		cpumask_var_t mi_game_reserve_cpus);
bool plat_game_skip_cpus_rt(struct task_struct *p,
		cpumask_var_t mi_game_reserve_cpus)
{
	plat_game_skip_cpus_rt_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_SKIP_CPUS_RT);

	if (fn)
		return fn(p, mi_game_reserve_cpus);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_skip_cpus_rt);

/* slot 26 [RE] bool, default 0; 2 params, 2nd unreadable. [RE-STUB] ABI. */
typedef bool (*plat_game_should_skip_cpu_rt_fn_t)(struct task_struct *p,
						  void *grp);
bool plat_game_should_skip_cpu_rt(struct task_struct *p, void *grp)
{
	plat_game_should_skip_cpu_rt_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_SHOULD_SKIP_CPU_RT);

	if (fn)
		return fn(p, grp);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_should_skip_cpu_rt);

/* slot 27 [RE] bool, default 0; 2 params, 2nd unreadable. [RE-STUB] ABI. */
typedef bool (*plat_game_should_skip_migrate_fn_t)(struct task_struct *p,
						   void *grp);
bool plat_game_should_skip_migrate(struct task_struct *p, void *grp)
{
	plat_game_should_skip_migrate_fn_t fn =
		plat_hook_fn(FUNC_MI_GAME_SHOULD_SKIP_MIGRATE);

	if (fn)
		return fn(p, grp);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_should_skip_migrate);

/* slot 28 [RE] bool, default 0, 1 param. */
typedef bool (*plat_game_check_rt_fn_t)(struct task_struct *p);
bool plat_game_check_rt(struct task_struct *p)
{
	plat_game_check_rt_fn_t fn = plat_hook_fn(FUNC_MI_GAME_CHECK_RT);

	if (fn)
		return fn(p);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_check_rt);

/* slot 29 [RE] bool, default 0, 1 param. */
typedef bool (*plat_game_vip_check_fn_t)(struct task_struct *p);
bool plat_game_vip_check(struct task_struct *p)
{
	plat_game_vip_check_fn_t fn = plat_hook_fn(FUNC_MI_GAME_VIP_CHECK);

	if (fn)
		return fn(p);
	return false;
}
EXPORT_SYMBOL_GPL(plat_game_vip_check);

/* slot 30 [RE] int (hook result not masked), default 0, no args observed. */
typedef int (*plat_migt_enable_fn_t)(void);
int plat_migt_enable(void)
{
	plat_migt_enable_fn_t fn = plat_hook_fn(FUNC_MIGT_ENABLE);

	if (fn)
		return fn();
	return 0;
}
EXPORT_SYMBOL_GPL(plat_migt_enable);

/*
 * slot 31 [RE] void, 6 params; readable names: fstat, wallclock.
 * [RE-STUB] ABI for the rest (2nd param is dada rq, 6th dada cluster).
 */
typedef void (*plat_update_frame_load_fn_t)(struct task_struct *p, void *rq,
		unsigned long fstat, u64 wallclock, unsigned long arg5,
		void *cl);
void plat_update_frame_load(struct task_struct *p, void *rq,
			    unsigned long fstat, u64 wallclock,
			    unsigned long arg5, void *cl)
{
	plat_update_frame_load_fn_t fn = plat_hook_fn(FUNC_UPDATE_FRAME_LOAD);

	if (fn)
		fn(p, rq, fstat, wallclock, arg5, cl);
}
EXPORT_SYMBOL_GPL(plat_update_frame_load);

/* slot 32 [RE] int (hook result not masked), default 0, no args observed. */
typedef int (*plat_flt_enable_fn_t)(void);
int plat_flt_enable(void)
{
	plat_flt_enable_fn_t fn = plat_hook_fn(FUNC_FLT_ENABLE);

	if (fn)
		return fn();
	return 0;
}
EXPORT_SYMBOL_GPL(plat_flt_enable);

/* slot 33 [RE] void, 1 param (task_struct *). */
typedef void (*plat_get_wakeup_info_fn_t)(struct task_struct *p);
void plat_get_wakeup_info(struct task_struct *p)
{
	plat_get_wakeup_info_fn_t fn = plat_hook_fn(FUNC_GET_WAKEUP_INFO);

	if (fn)
		fn(p);
}
EXPORT_SYMBOL_GPL(plat_get_wakeup_info);

/*
 * slot 34 [RE] void, 1 param; no default value produced (both paths ret).
 * [RE-STUB] ABI: param assumed to be the dada cluster (same dedup string as
 * plat_update_pkg_load arg3), forwarded verbatim.
 */
typedef void (*plat_mi_force_update_freq_fn_t)(struct sched_cluster *cl);
void plat_mi_force_update_freq(struct sched_cluster *cl)
{
	plat_mi_force_update_freq_fn_t fn =
		plat_hook_fn(FUNC_MI_FORCE_UPDATE_FREQ);

	if (fn)
		fn(cl);
}
EXPORT_SYMBOL_GPL(plat_mi_force_update_freq);

/* slot 35 [RE] bool (and w0, w0, #1), default 0, no args observed. */
typedef bool (*plat_enable_gpsync_fn_t)(void);
bool plat_enable_gpsync(void)
{
	plat_enable_gpsync_fn_t fn = plat_hook_fn(FUNC_ENABLE_GPUSYNC);

	if (fn)
		return fn();
	return false;
}
EXPORT_SYMBOL_GPL(plat_enable_gpsync);

/* ------------------------------------------------------------------ */
/* Non-dispatch functions                                              */
/* ------------------------------------------------------------------ */

/*
 * [RE] plat_init_sched_cgroup_id @ .text+0xb94.
 * Given a css, when its cgroup is level 1 and the name matches one of
 * top-app / foreground / background / audio (strcmp order per .rodata),
 * record its id into ta/fg/bg/au; then pr_info
 * "plat_hook: Identified sched cgroup: level=%d, name=%s, id=%d(ta=%d fg=%d
 * bg=%d au=%d)" (.rodata+0xc, KERN_INFO).
 * The original reads the id at +80 of its first argument (6.6 css layout);
 * css->id is the 5.15 equivalent.
 */
void plat_init_sched_cgroup_id(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp;
	const char *name;
	int id;

	if (!css)
		return;

	cgrp = css->cgroup;
	if (!cgrp || cgrp->level != 1)
		return;

	rcu_read_lock();
	/* Original reads the level-1 cgroup's kernfs name directly (kn@+280,
	 * name@+16 in 6.6); this tree's cgroup_name() takes a caller buffer,
	 * so use kn->name (public in include/linux/kernfs.h). */
	name = cgrp->kn->name;
	id = css->id;
	if (!strcmp(name, "top-app")) {
		ta_grp_id = id;
	} else if (!strcmp(name, "foreground")) {
		fg_grp_id = id;
	} else if (!strcmp(name, "background")) {
		bg_grp_id = id;
	} else if (!strcmp(name, "audio")) {
		au_grp_id = id;
	}
	pr_info("plat_hook: Identified sched cgroup: level=%d, name=%s, id=%d(ta=%d fg=%d bg=%d au=%d)\n",
		cgrp->level, name, id, ta_grp_id, fg_grp_id, bg_grp_id,
		au_grp_id);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(plat_init_sched_cgroup_id);

/*
 * [RE] plat_is_relaxed_rt @ .text+0xca8.
 *   - returns 0 unless the sched_relaxed module param is set;
 *   - 0 if p->prio > 99 (cmp w8, #0x63 / b.gt) or
 *     (unsigned)p->prio > critical_rt_prio (b.hi, default 96);
 *   - then the original acquire-loads two dada task_struct vendor fields
 *     (offsets 0x578 / 0x9f8 in 6.6, presumably the related-thread-group
 *     pointer and its group) and returns true when the resolved group id is
 *     -1 or equals au_grp_id. Those fields have no 5.15 counterpart in this
 *     tree, so that part is [RE-STUB]: returns the safe default 0.
 */
int plat_is_relaxed_rt(struct task_struct *p)
{
	if (!sched_relaxed)
		return 0;
	if (!p)
		return 0;
	if (p->prio > (MAX_RT_PRIO - 1))
		return 0;
	if ((unsigned int)p->prio > critical_rt_prio)
		return 0;

	/* [RE-STUB] RTG group-id check not portable to 5.15; see above. */
	return 0;
}
EXPORT_SYMBOL_GPL(plat_is_relaxed_rt);

/*
 * [RE] plat_fix_timer_slack_fork @ .text+0xd5c (local symbol, NOT exported).
 * Registered in init on __tracepoint_android_rvh_finish_prio_fork
 * (android_rvh_probe_register, .init.text+0x4).
 * Semantics, exactly:
 *   - if p->default_timer_slack_ns == 0 -> set it to 50000 (DEFAULT_TIMER_SLACK)
 *     (6.6 field at +0xaf8; 5.15 field default_timer_slack_ns);
 *   - if p->timer_slack_ns != 0 -> done (6.6 field at +0xaf0);
 *   - else if p->policy <= 6 and BIT(policy) & 0x46 (bits 1,2,6 =
 *     SCHED_FIFO/SCHED_RR/SCHED_DEADLINE) -> leave timer_slack_ns at 0;
 *   - else p->timer_slack_ns = 50000.
 */
static void plat_fix_timer_slack_fork(void *data, struct task_struct *p)
{
	if (!p->default_timer_slack_ns) {
		p->default_timer_slack_ns = 50000;
		if (p->timer_slack_ns)
			return;
	} else if (p->timer_slack_ns) {
		return;
	}

	if (p->policy <= SCHED_DEADLINE && (BIT(p->policy) & 0x46))
		return;

	p->timer_slack_ns = 50000;
}

static int __init plat_common_init(void)
{
	int ret;

	ret = register_trace_android_rvh_finish_prio_fork(
			plat_fix_timer_slack_fork, NULL);
	if (ret)
		return ret;

	return 0;
}

/*
 * [RE] The original cleanup_module is a plain ret (no unregistration);
 * kept identical. Do not unload the module while provider hooks are
 * registered in g_plat_hook_table.
 */
static void __exit plat_common_exit(void)
{
}

module_init(plat_common_init);
module_exit(plat_common_exit);

MODULE_DESCRIPTION("OS-CPU Platform Hook");
MODULE_LICENSE("GPL v2");
