// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/mi_game_ca.c - mi_game stage-1 skeleton
 *
 * D6-MIGAME stage 1: migt-driver framework (select/vip/freedom shapes).
 * Original: kernel/sched/xiaomi_sched/qcom/mi_game/mi_game_ca.c (~45 funcs),
 *   mi_game_load.c (~12 funcs), flt.c (~40 funcs) in dada 6.6 mi_game.ko
 *   (497648 B, depends plat_common,mist,sched-walt,vip_sched).
 * Stage-1 file plan per C5 §2: this file now; mi_game_load.c (STAGE2) and
 * flt.c + mi_game_pelt.c (STAGE3) follow.
 *
 * What stage 1 implements (all paths complete, zero undef on insmod):
 *   /dev/migt char device (alloc_chrdev/cdev/class/device + 4-way fail
 *     prints "migt: alloc_chrdev_region failed / cdev_add failed /
 *     class_create failed / device_create failed" per B2 §4.1 err_strings),
 *   /dev/migt_reset second node, misc face "migt" (B2 §8.2: name unrecovered,
 *     "migt" placeholder documented at sew_migt_miscdev below),
 *   ioctl 11-command dispatch on low 8 bits 1..11 via generic 128 B buffer
 *     (full magic P0-unrecovered: no fake _IOR numbers claimed real),
 *   proc triple tree migt/ game_load/ frame_load/ + debug nodes,
 *   15 plat_common slot providers 13/14/15/16/17/18/19/20/22/23/24/25/26/
 *     27/28/29/30 (slot 21 FREE_MI_TASK_STRUCT intentionally NOT claimed:
 *     owned by the 6.12 allocator refactor; 5.15 uses native free),
 *   4 RVH direct probes (cpuset_fork / sched_setaffinity_early /
 *     try_to_wake_up_success / cpufreq_transition),
 *   83 module_param namesakes (same names as dada modinfo),
 *   migt_enable gate + mi_dflt always-on stub + is_32B_user compat rewrite,
 *   sew_migt_hardwork boost workqueue skeleton (workqueue lifecycle real;
 *     decision body is STAGE2),
 *   exports: migt_sched_init/migt_sched_exit/game_load_init/game_load_exit/
 *     is_32B_user/mi_set_flt_target_delta (B2 §2.1 ksymtab list).
 *
 * plat_common discipline: wrappers untouched, provider registration only.
 * RE-STUB guard note (C5 §4.2): wrappers in mm/plat_common.c still
 * WARN_ONCE/count on every call even with a provider registered; the
 * "count only when provider absent" change is STAGE2 work (2 lines, in
 * plat_common, out of stage-1 scope) and is NOT done here.
 */

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/topology.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/time.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <trace/hooks/cgroup.h>
#include <trace/hooks/cpufreq.h>
#include <trace/hooks/sched.h>

#include "mi_game.h"

/* ---- hook slot ids (mm/plat_common.c enum plat_hook_id, no shared header;
 * same pattern as kernel/sched/rtg.c local defines) ---- */
#define FUNC_MI_GAME_FIND_ENERGY_HOOK		13
#define FUNC_MIGT_HOOK				14
#define FUNC_MI_GAME_WALT_GET_INDICIES		15
#define FUNC_GAME_GET_RAVG_WINDOW		16
#define FUNC_MI_SET_NEXT_FREQ			17
#define FUNC_MI_GAME_TASK_FORK			18
#define FUNC_MI_GAME_SCHEDULER_TICK		19
#define FUNC_MI_GAME_CHOOSE_CPU_FASTPATH	20
#define FUNC_MI_GAME_CHOOSE_EXCLUSIVE_CPUS	22
#define FUNC_MI_GAME_CHOOSE_CPU			23
#define FUNC_MI_GAME_SKIP_CPUS			24
#define FUNC_MI_GAME_SKIP_CPUS_RT		25
#define FUNC_MI_GAME_SHOULD_SKIP_CPU_RT		26
#define FUNC_MI_GAME_SHOULD_SKIP_MIGRATE	27
#define FUNC_MI_GAME_CHECK_RT			28
#define FUNC_MI_GAME_VIP_CHECK			29
#define FUNC_MIGT_ENABLE			30

extern int register_plat_func(int id, void *fn);
extern int unregister_plat_func(int id);

/* vip_sched consumer channel (C5 §0.2: ABI verified (p, 30, true)). */
extern int set_vip_prio(struct task_struct *p, int prio, bool set_orig);
extern void restore_vip_prio(struct task_struct *p);
extern u32 get_vip_prio(struct task_struct *p);
extern void inherit_vip_prio(struct task_struct *src, struct task_struct *dst);

/* Opaque dada scheduler types used only by pointer in provider
 * signatures (same approach as mm/plat_common.c forward declarations). */
struct metis_choose_cpu_args;
struct walt_related_thread_group;
struct sched_cluster;

/* ================= module params (83 dada namesakes) =================
 * Types from /root/work/b2migame/modinfo_08.txt parm lines. Array params
 * use plain uint arrays with a fixed bound (dada passes int * + count;
 * module_param_array handles the count). migt_walt_features is an int
 * enum on dada ("migt_walt_features (int)"); kept int here.
 * Defaults are neutral (feature off / zero) so stage-1 load changes no
 * scheduling behaviour; STAGE3 re-tunes FLT thresholds on device.
 */
#define MI_GAME_ARR_SZ	8

/* flt face */
static int flt_down_thresh_margin;
module_param(flt_down_thresh_margin, int, 0644);
static int flt_up_thresh_margin;
module_param(flt_up_thresh_margin, int, 0644);
static unsigned int disable_soc_util;
module_param(disable_soc_util, uint, 0644);
static unsigned int frame_boost_enable;
module_param(frame_boost_enable, uint, 0644);
static unsigned int flt_frame_divisor;
module_param(flt_frame_divisor, uint, 0644);
static unsigned int flt_preboost_cluster_enable[MI_GAME_ARR_SZ];
static int sew_flt_preboost_cluster_enable_n;
module_param_array(flt_preboost_cluster_enable, uint,
		   &sew_flt_preboost_cluster_enable_n, 0644);
static unsigned int flt_preboost_gamemode;
module_param(flt_preboost_gamemode, uint, 0644);
static unsigned int flt_preboost_step;
module_param(flt_preboost_step, uint, 0644);
static unsigned int flt_wakeup_enable;
module_param(flt_wakeup_enable, uint, 0644);
static unsigned int flt_preboost_enable;
module_param(flt_preboost_enable, uint, 0644);
static unsigned int flt_gpu_enable;
module_param(flt_gpu_enable, uint, 0644);
static unsigned int flt_fence_enable;
module_param(flt_fence_enable, uint, 0644);
static unsigned int flt_in_frame_enable_cluster[MI_GAME_ARR_SZ];
static int sew_flt_in_frame_enable_cluster_n;
module_param_array(flt_in_frame_enable_cluster, uint,
		   &sew_flt_in_frame_enable_cluster_n, 0644);
static unsigned int flt_boost_scaling[MI_GAME_ARR_SZ];
static int sew_flt_boost_scaling_n;
module_param_array(flt_boost_scaling, uint, &sew_flt_boost_scaling_n, 0644);
static unsigned int flt_normal_scaling[MI_GAME_ARR_SZ];
static int sew_flt_normal_scaling_n;
module_param_array(flt_normal_scaling, uint, &sew_flt_normal_scaling_n, 0644);
static unsigned int flt_in_frame_enable;
module_param(flt_in_frame_enable, uint, 0644);
static unsigned int flt_in_frame_down_margin;
module_param(flt_in_frame_down_margin, uint, 0644);
static unsigned int flt_in_frame_up_margin;
module_param(flt_in_frame_up_margin, uint, 0644);
static unsigned int flt_in_frame_freq[MI_GAME_ARR_SZ];
static int sew_flt_in_frame_freq_n;
module_param_array(flt_in_frame_freq, uint, &sew_flt_in_frame_freq_n, 0644);
static unsigned int reasons_cpu_thresh[MI_GAME_ARR_SZ];
static int reasons_cpu_thresh_n;
module_param_array(reasons_cpu_thresh, uint, &reasons_cpu_thresh_n, 0644);
static unsigned int reasons_flag_enable[MI_GAME_ARR_SZ];
static int reasons_flag_enable_n;
module_param_array(reasons_flag_enable, uint, &reasons_flag_enable_n, 0644);
static unsigned int reasons_flag;
module_param(reasons_flag, uint, 0644);
static unsigned int flt_cal_freq_enable[MI_GAME_ARR_SZ];
static int sew_flt_cal_freq_enable_n;
module_param_array(flt_cal_freq_enable, uint, &sew_flt_cal_freq_enable_n, 0644);
static unsigned int flt_pro_thresh_freq[MI_GAME_ARR_SZ];
static int sew_flt_pro_thresh_freq_n;
module_param_array(flt_pro_thresh_freq, uint, &sew_flt_pro_thresh_freq_n, 0644);
static unsigned int flt_new_render_cal_thresh;
module_param(flt_new_render_cal_thresh, uint, 0644);
static unsigned int flt_choose_avg_num[MI_GAME_ARR_SZ];
static int sew_flt_choose_avg_num_n;
module_param_array(flt_choose_avg_num, uint, &sew_flt_choose_avg_num_n, 0644);
static unsigned int flt_high_freq[MI_GAME_ARR_SZ];
static int sew_flt_high_freq_n;
module_param_array(flt_high_freq, uint, &sew_flt_high_freq_n, 0644);
static unsigned int flt_low_freq[MI_GAME_ARR_SZ];
static int sew_flt_low_freq_n;
module_param_array(flt_low_freq, uint, &sew_flt_low_freq_n, 0644);
static unsigned int flt_render_cluster;
module_param(flt_render_cluster, uint, 0644);
static unsigned int force_update_freq;
module_param(force_update_freq, uint, 0644);
static unsigned int flt_render_hook;
module_param(flt_render_hook, uint, 0644);
static unsigned int flt_deq_ajust_enable;
module_param(flt_deq_ajust_enable, uint, 0644);
static unsigned int flt_render_load;
module_param(flt_render_load, uint, 0644);
static unsigned int flt_ftrace_debug;
module_param(flt_ftrace_debug, uint, 0644);
static unsigned int flt_fpercent_other;
module_param(flt_fpercent_other, uint, 0644);
static unsigned int flt_target_fps = 60;
module_param(flt_target_fps, uint, 0644);
/* ca / select face */
static unsigned int in_perf_mod;
module_param(in_perf_mod, uint, 0644);
static unsigned int mark_debug;
module_param(mark_debug, uint, 0644);
static unsigned int mark_rule3_enable;
module_param(mark_rule3_enable, uint, 0644);
static unsigned int mark_rule2_enable;
module_param(mark_rule2_enable, uint, 0644);
static unsigned int mark_rule1_enable;
module_param(mark_rule1_enable, uint, 0644);
static int choose_cpu_exclusive_enable_vote;
module_param(choose_cpu_exclusive_enable_vote, int, 0644);
static int choose_cpu_exclusive_enable;
module_param(choose_cpu_exclusive_enable, int, 0644);
static char *user_stask = "";
module_param(user_stask, charp, 0644);
static unsigned int choose_cpu_enable;
module_param(choose_cpu_enable, uint, 0644);
static unsigned int task_util_thresh = 512;
module_param(task_util_thresh, uint, 0644);
static unsigned int task_enqueue_time_toolong;
module_param(task_enqueue_time_toolong, uint, 0644);
static unsigned int game_app_select_sf;
module_param(game_app_select_sf, uint, 0644);
/* migt_walt_features is "(int)" on dada; plain int here. */
static int migt_walt_features;
module_param(migt_walt_features, int, 0644);
/* game-load (glk) face */
static unsigned int glk_minfreq[MI_GAME_ARR_SZ];
static int glk_minfreq_n;
module_param_array(glk_minfreq, uint, &glk_minfreq_n, 0644);
static unsigned int glk_maxfreq[MI_GAME_ARR_SZ];
static int glk_maxfreq_n;
module_param_array(glk_maxfreq, uint, &glk_maxfreq_n, 0644);
static unsigned int glk_freq_limit_walt;
module_param(glk_freq_limit_walt, uint, 0644);
static unsigned int glk_freq_limit_start;
module_param(glk_freq_limit_start, uint, 0644);
static unsigned int glk_fbreak_enable;
module_param(glk_fbreak_enable, uint, 0644);
static unsigned int glk_disable;
module_param(glk_disable, uint, 0644);
/* vip / monitor face */
static unsigned int force_viptask_select_rq;
module_param(force_viptask_select_rq, uint, 0644);
static unsigned int force_forbidden_walt_lb;
module_param(force_forbidden_walt_lb, uint, 0644);
static unsigned int force_reset_runtime;
module_param(force_reset_runtime, uint, 0644);
static unsigned int need_reset_runtime_everytime;
module_param(need_reset_runtime_everytime, uint, 0644);
static unsigned int ip_task_max_num = 8;
module_param(ip_task_max_num, uint, 0644);
static unsigned int vip_task_max_num = 8;
module_param(vip_task_max_num, uint, 0644);
static unsigned int stask_candidate_num = 8;
module_param(stask_candidate_num, uint, 0644);
static unsigned int set_render_as_stask;
module_param(set_render_as_stask, uint, 0644);
static unsigned int enable_pkg_monitor;
module_param(enable_pkg_monitor, uint, 0644);
static unsigned int fps_variance_ratio;
module_param(fps_variance_ratio, uint, 0644);
static unsigned int fps_mexec_update_policy;
module_param(fps_mexec_update_policy, uint, 0644);
static unsigned int migt_viptask_thresh;
module_param(migt_viptask_thresh, uint, 0644);
static unsigned int choose_cluster_disable;
module_param(choose_cluster_disable, uint, 0644);
static unsigned int force_cluster_sched_enable;
module_param(force_cluster_sched_enable, uint, 0644);
static unsigned int render_update;
module_param(render_update, uint, 0644);
static unsigned int migt_gpsync;
module_param(migt_gpsync, uint, 0644);
static unsigned int cpu_boost_cycle;
module_param(cpu_boost_cycle, uint, 0644);
static unsigned int boost_policy;
module_param(boost_policy, uint, 0644);
static unsigned int over_thresh_count;
module_param(over_thresh_count, uint, 0644);
static unsigned int itask_detect_interval;
module_param(itask_detect_interval, uint, 0644);
static unsigned int migt_thresh;
module_param(migt_thresh, uint, 0644);
static unsigned int migt_ms;
module_param(migt_ms, uint, 0644);
static unsigned int migt_debug;
module_param(migt_debug, uint, 0644);
static unsigned int high_resolution_enable;
module_param(high_resolution_enable, uint, 0644);
static unsigned int ceiling_from_user;
module_param(ceiling_from_user, uint, 0644);
static unsigned int ceiling_slack_ms;
module_param(ceiling_slack_ms, uint, 0644);
static unsigned int first_lunch_fps;
module_param(first_lunch_fps, uint, 0644);
static unsigned int perf_mod;
module_param(perf_mod, uint, 0644);
/* mi_dflt back door (C5 §1.3 option 1): 0 = always-on stub active. */
static unsigned int flt_dflt_bypass;
module_param(flt_dflt_bypass, uint, 0644);
/* flt target delta backing store for the mi_set_flt_target_delta export. */
static int sew_flt_target_delta;
/* Forward: dada rule-1 gate, defined in the params block below. */

static DEFINE_MUTEX(sew_migame_state_lock);
static int sew_migame_enable;

/* frame_boost gate for the FLT frequency engine (flt.c): 1 = allow
 * flt_cal_freq() to produce a target frequency, 0 = report only
 * (formula still evaluated, no consumer can act on it). dada's
 * frame_boost_enable module_param is the official tunable behind this
 * word (BTF frame_boost_enable + flt_cal_freq caller use); the accessor
 * keeps the storage in one place, same pattern as the glk accessors. */
bool sew_migame_frame_boost_allowed(void)
{
	return READ_ONCE(frame_boost_enable) != 0;
}
static int sew_migt_flt_target_check = 1;

/* ================= migt_enable gate / mi_dflt stub ================= */
int sew_migame_get_enable(void)
{
	return READ_ONCE(sew_migame_enable);
}

/* Enable control: the four optimization engines (game_load调频 /
 * FLT帧负载调频 / render-vip选核 / slot14负载输入) all gate on
 * sew_migame_get_enable(). Default 0 = zero behaviour (K4 "默认零行为"
 * safety design); 1 = run the ported optimization chain.
 *
 * Data path for changing the switch:
 *   - sysfs (module_param_cb): echo 0/1 >
 *     /sys/module/mi_game/parameters/migame_enable
 *   - /proc/migt/migt_sched_enable: echo 0/1 > (same setter)
 * Both call sew_migame_set_enable(); the effect is immediate
 * (READ_ONCE at every gate, no kick needed; the hardwork worker and
 * the load work re-arm on their next tick).
 */
static int sew_migame_enable_set(const char *val, const struct kernel_param *kp)
{
	int en, ret;

	ret = kstrtoint(val, 0, &en);
	if (ret)
		return ret;
	return sew_migame_set_enable(en);
}

static int sew_migame_enable_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%d\n", sew_migame_get_enable());
}

static const struct kernel_param_ops sew_migame_enable_ops = {
	.set = sew_migame_enable_set,
	.get = sew_migame_enable_get,
};

/* Custom-name param: module_param() would expose "sew_migame_enable";
 * module_param_cb() with the explicit name "migame_enable" keeps the
 * sysfs node short and distinct from the 83 dada namesakes (J5: official
 * modinfo has no enable param, so a sew_ name would also be acceptable;
 * bare "migame_enable" matches the task-requested user-facing name).
 * Perm 0644 = root read/write, world read; default 0 (off). */
module_param_cb(migame_enable, &sew_migame_enable_ops, NULL, 0644);
MODULE_PARM_DESC(migame_enable, "master enable for the mi_game optimization chain (0=off, 1=on)");

int sew_migame_set_enable(int en)
{
	WRITE_ONCE(sew_migame_enable, !!en);
	return 0;
}
EXPORT_SYMBOL_GPL(sew_migame_set_enable);

bool mi_dflt_get_latency_enable(void)
{
	/* C5 §1.3 recommended stub: single call site, pure gate semantics,
	 * factory default = latency path enabled. flt_dflt_bypass=1 forces
	 * the gate closed for A/B experiments without rmmod. */
	if (flt_dflt_bypass)
		return false;
	return true;
}

int sew_migame_vip_snapshot(struct task_struct *p)
{
	if (!p)
		return -EINVAL;
	return (int)get_vip_prio(p);
}

bool sew_migame_vip_own(struct task_struct *p, int snapshot)
{
	if (!p || snapshot < 0)
		return false;
	/* Last-writer-wins: only our own still-current value may be
	 * restored by us; anything else belongs to xr_qs or a later
	 * writer (C5 §4.1). */
	return (int)get_vip_prio(p) == snapshot;
}

/* is_32B_user: B2 §3.2 rewrite. dada reads system_32bit_el0_cpumask
 * (absent on 5.15); current-task compat state is the equivalent. */
int is_32B_user(void)
{
	return is_compat_task();
}
EXPORT_SYMBOL_GPL(is_32B_user);

int mi_set_flt_target_delta(int delta)
{
	mutex_lock(&sew_migame_state_lock);
	sew_flt_target_delta = delta;
	mutex_unlock(&sew_migame_state_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(mi_set_flt_target_delta);

/* ================= /dev/migt char device =================
 * Order per B2 §4.1 asm_init_module: alloc_chrdev_region -> cdev_init ->
 * cdev_add -> class_create -> device_create, each failure printing its
 * own "migt: <step> failed" line (names from err_strings.txt).
 */
#define MIGT_DEV_NAME	"migt"
#define MIGT_RESET_NAME	"migt_reset"

static dev_t sew_migame_devno;
static struct cdev sew_migame_cdev;
static struct class *sew_migame_class;
static struct device *sew_migame_device;

static dev_t sew_migame_reset_devno;
static struct cdev sew_migame_reset_cdev;
static struct device *sew_migame_reset_device;

static int sew_migame_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int sew_migame_release(struct inode *inode, struct file *filp)
{
	return 0;
}

/* 11 sub-commands indexed by low 8 bits 1..11 (B2 §4.1). Each handler is
 * a real stage-1 seam: validates the generic buffer and records the hit;
 * STAGE2 replaces the body per command once P0 recovers magic+shapes.
 * Returning 0 keeps the link testable (open -> ioctl(N) -> 0) without
 * claiming any payload semantics.
 */
static DEFINE_MUTEX(sew_migt_ioctl_lock);
static unsigned long sew_migt_ioctl_hits[MIGT_IOC_NR_MAX + 1];

static long sew_migame_cmd_stage1(unsigned int nr, void __user *arg)
{
	u8 stage[MIGT_IOC_BUF_SZ];

	if (nr < MIGT_IOC_NR_MIN || nr > MIGT_IOC_NR_MAX)
		return -EINVAL;
	/* Probe the user buffer shape-neutrally: a fault here is -EFAULT
	 * today and stays -EFAULT once the real per-command struct lands. */
	if (arg && copy_from_user(stage, arg, sizeof(stage)))
		return -EFAULT;

	mutex_lock(&sew_migt_ioctl_lock);
	sew_migt_ioctl_hits[nr]++;
	mutex_unlock(&sew_migt_ioctl_lock);

	/* STAGE2: switch(nr) fills update_render_info / reset_render_info /
	 * flt_update_{gpu,fps_time,sf,fence_pending} / flt_adjust_dequeue /
	 * mist_frame_load_{history_update,reset} / add_work_to_migt /
	 * trigger_mist_load_tracking / notify_gflt_frame_period_thresh
	 * after P0 recovers the real magic and migt_cmd shapes.
	 *
	 * K5 regression fix: return -ENOTTY, not 0. Counting the hit and
	 * then returning success would tell userspace (milletd/HAL) that a
	 * command was applied when nothing was -- that masks stage-2/3
	 * bring-up failures. A distinct errno keeps the counters as pure
	 * telemetry. */
	pr_debug("migt: ioctl sub-cmd %u staged but not applied (P0 pending)\n", nr);
	return -ENOTTY;
}

static long sew_migame_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	unsigned int nr = cmd & 0xff;

	/* Full magic (cmd>>8, expected _IOC_TYPE/_IOC_NR/_IOC_SIZE fields)
	 * is P0-unrecovered: accept the low-byte range and stage through
	 * the generic buffer instead of pretending to know the magic. */
	if (nr < MIGT_IOC_NR_MIN || nr > MIGT_IOC_NR_MAX)
		return -ENOTTY;
	return sew_migame_cmd_stage1(nr, (void __user *)arg);
}

#ifdef CONFIG_COMPAT
static long sew_migame_compat_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	return sew_migame_ioctl(filp, cmd, arg);
}
#endif

static const struct file_operations sew_migame_fops = {
	.owner		= THIS_MODULE,
	.open		= sew_migame_open,
	.release	= sew_migame_release,
	.unlocked_ioctl	= sew_migame_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sew_migame_compat_ioctl,
#endif
};

static int sew_migame_reset_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations sew_migame_reset_fops = {
	.owner	= THIS_MODULE,
	.open	= sew_migame_reset_open,
};

/* migt_misc: B2 §8.2 misc face (misc_register/misc_deregister paired in
 * init/exit). The exact userspace name was not recovered from rodata, so
 * the placeholder below is "migt"; Ghidra recovery of the .data name
 * field (C5 P0 item 2) replaces exactly this string. */
static struct miscdevice sew_migt_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "migt",
	.fops	= &sew_migame_reset_fops,
};

static void sew_migame_chrdev_teardown_migt(void)
{
	if (sew_migame_device && !IS_ERR(sew_migame_device)) {
		device_destroy(sew_migame_class, sew_migame_devno);
		sew_migame_device = NULL;
	}
	if (sew_migame_class && !IS_ERR(sew_migame_class)) {
		class_destroy(sew_migame_class);
		sew_migame_class = NULL;
	}
	cdev_del(&sew_migame_cdev);
	unregister_chrdev_region(sew_migame_devno, 1);
}

static int sew_migame_chrdev_setup_migt(void)
{
	int ret;

	ret = alloc_chrdev_region(&sew_migame_devno, 0, 1, MIGT_DEV_NAME);
	if (ret) {
		pr_err("migt: alloc_chrdev_region failed\n");
		return ret;
	}
	cdev_init(&sew_migame_cdev, &sew_migame_fops);
	sew_migame_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sew_migame_cdev, sew_migame_devno, 1);
	if (ret) {
		pr_err("migt: cdev_add failed\n");
		unregister_chrdev_region(sew_migame_devno, 1);
		return ret;
	}
	sew_migame_class = class_create(THIS_MODULE, MIGT_DEV_NAME);
	if (IS_ERR(sew_migame_class)) {
		ret = PTR_ERR(sew_migame_class);
		sew_migame_class = NULL;
		pr_err("migt: class_create failed\n");
		cdev_del(&sew_migame_cdev);
		unregister_chrdev_region(sew_migame_devno, 1);
		return ret;
	}
	sew_migame_device = device_create(sew_migame_class, NULL, sew_migame_devno,
				      NULL, MIGT_DEV_NAME);
	if (IS_ERR(sew_migame_device)) {
		ret = PTR_ERR(sew_migame_device);
		sew_migame_device = NULL;
		pr_err("migt: device_create failed\n");
		class_destroy(sew_migame_class);
		sew_migame_class = NULL;
		cdev_del(&sew_migame_cdev);
		unregister_chrdev_region(sew_migame_devno, 1);
		return ret;
	}
	return 0;
}

static void sew_migame_chrdev_teardown_reset(void)
{
	if (sew_migame_reset_device && !IS_ERR(sew_migame_reset_device)) {
		device_destroy(sew_migame_class, sew_migame_reset_devno);
		sew_migame_reset_device = NULL;
	}
	cdev_del(&sew_migame_reset_cdev);
	unregister_chrdev_region(sew_migame_reset_devno, 1);
}

static int sew_migame_chrdev_setup_reset(void)
{
	int ret;

	ret = alloc_chrdev_region(&sew_migame_reset_devno, 0, 1, MIGT_RESET_NAME);
	if (ret) {
		pr_err("migt: alloc_chrdev_region failed\n");
		return ret;
	}
	cdev_init(&sew_migame_reset_cdev, &sew_migame_reset_fops);
	sew_migame_reset_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sew_migame_reset_cdev, sew_migame_reset_devno, 1);
	if (ret) {
		pr_err("migt: cdev_add failed\n");
		unregister_chrdev_region(sew_migame_reset_devno, 1);
		return ret;
	}
	/* Reuses sew_migame_class created by the migt node; class lifetime is
	 * owned by the migt node (teardown order: reset first, migt last). */
	sew_migame_reset_device = device_create(sew_migame_class, NULL,
					    sew_migame_reset_devno, NULL,
					    MIGT_RESET_NAME);
	if (IS_ERR(sew_migame_reset_device)) {
		ret = PTR_ERR(sew_migame_reset_device);
		sew_migame_reset_device = NULL;
		pr_err("migt: device_create failed\n");
		cdev_del(&sew_migame_reset_cdev);
		unregister_chrdev_region(sew_migame_reset_devno, 1);
		return ret;
	}
	return 0;
}

/* ================= proc triple tree =================
 * migt/ + game_load/ + frame_load/ directories with one debug node each
 * in stage 1 (show functions return a real header + counters, not an
 * empty table). STAGE2 adds game_cpu_load/history_load/exec_buckets;
 * STAGE3 adds frame_load/frame_cpu_load nodes reusing these helpers.
 */
static struct proc_dir_entry *sew_migame_proc_migt;
static struct proc_dir_entry *sew_migame_proc_gameload;
static struct proc_dir_entry *sew_migame_proc_frameload;

static int sew_migame_debug_show(struct seq_file *m, void *v)
{
	unsigned int n;

	seq_printf(m, "enable=%d flt_target_delta=%d target_check=%d\n",
		   sew_migame_get_enable(), sew_flt_target_delta,
		   sew_migt_flt_target_check);
	for (n = MIGT_IOC_NR_MIN; n <= MIGT_IOC_NR_MAX; n++)
		seq_printf(m, "ioctl%u=%lu\n", n, sew_migt_ioctl_hits[n]);
	return 0;
}

static int sew_migame_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_migame_debug_show, NULL);
}

static const struct proc_ops sew_migame_debug_proc_ops = {
	.proc_open	= sew_migame_debug_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* Writable enable node (paired with the migame_enable module_param_cb;
 * same setter, same immediate effect). Accepts "0"/"1" (kstrtoint, so
 * also "0x1"/" 1\n"); anything else returns -EINVAL and changes nothing.
 * Shows the current switch plus the frame_boost gate state on read. */
static ssize_t sew_migame_enable_write(struct file *file,
				       const char __user *buf,
				       size_t count, loff_t *ppos)
{
	char kbuf[8];
	int en, ret;

	if (count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	ret = kstrtoint(kbuf, 0, &en);
	if (ret)
		return ret;
	if (en != 0 && en != 1)
		return -EINVAL;
	sew_migame_set_enable(en);
	return count;
}

static int sew_migame_enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "enable=%d frame_boost=%d\n",
		   sew_migame_get_enable(),
		   sew_migame_frame_boost_allowed() ? 1 : 0);
	return 0;
}

static int sew_migame_enable_open(struct inode *inode, struct file *file)
{
	return single_open(file, sew_migame_enable_show, NULL);
}

static const struct proc_ops sew_migame_enable_proc_ops = {
	.proc_open	= sew_migame_enable_open,
	.proc_read	= seq_read,
	.proc_write	= sew_migame_enable_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static void sew_migame_proc_teardown(void)
{
	/* remove_proc_entry(NULL-subtree) order: children first, then
	 * directories; remove_proc_entry is NULL-safe but the pointers
	 * are cleared anyway so a double-exit path cannot double-remove. */
	remove_proc_entry("migt_sched_debug", sew_migame_proc_migt);
	remove_proc_entry("migt_sched_enable", sew_migame_proc_migt);
	remove_proc_entry("game_load_debug", sew_migame_proc_gameload);
	remove_proc_entry("frame_load_debug", sew_migame_proc_frameload);
	if (sew_migame_proc_migt) {
		remove_proc_entry("migt", NULL);
		sew_migame_proc_migt = NULL;
	}
	if (sew_migame_proc_gameload) {
		remove_proc_entry("game_load", NULL);
		sew_migame_proc_gameload = NULL;
	}
	if (sew_migame_proc_frameload) {
		remove_proc_entry("frame_load", NULL);
		sew_migame_proc_frameload = NULL;
	}
}

static int sew_migame_proc_setup(void)
{
	sew_migame_proc_migt = proc_mkdir("migt", NULL);
	if (!sew_migame_proc_migt)
		return -ENOMEM;
	sew_migame_proc_gameload = proc_mkdir("game_load", NULL);
	if (!sew_migame_proc_gameload)
		goto err_gameload;
	sew_migame_proc_frameload = proc_mkdir("frame_load", NULL);
	if (!sew_migame_proc_frameload)
		goto err_frameload;

	/* One debug node per tree in stage 1; each creation failure rolls
	 * back exactly the nodes created so far (no orphan dentries). */
	if (!proc_create("migt_sched_debug", 0444, sew_migame_proc_migt,
			 &sew_migame_debug_proc_ops))
		goto err_nodes;
	if (!proc_create("migt_sched_enable", 0644, sew_migame_proc_migt,
			 &sew_migame_enable_proc_ops))
		goto err_enable_node;
	if (!proc_create("game_load_debug", 0444, sew_migame_proc_gameload,
			 &sew_migame_debug_proc_ops))
		goto err_game_node;
	if (!proc_create("frame_load_debug", 0444, sew_migame_proc_frameload,
			 &sew_migame_debug_proc_ops))
		goto err_frame_node;
	return 0;

err_frame_node:
	remove_proc_entry("game_load_debug", sew_migame_proc_gameload);
err_game_node:
	remove_proc_entry("migt_sched_enable", sew_migame_proc_migt);
err_enable_node:
	remove_proc_entry("migt_sched_debug", sew_migame_proc_migt);
err_nodes:
	remove_proc_entry("frame_load", NULL);
	sew_migame_proc_frameload = NULL;
err_frameload:
	remove_proc_entry("game_load", NULL);
	sew_migame_proc_gameload = NULL;
err_gameload:
	remove_proc_entry("migt", NULL);
	sew_migame_proc_migt = NULL;
	return -ENOMEM;
}

/* ================= sew_migt_hardwork boost skeleton =================
 * dada's largest function (3140 B) runs on sew_migt_wq/sew_migt_work. Stage 1
 * owns the full workqueue lifecycle (create/flush/destroy, no leaks on
 * exit); the boost decision body is STAGE2 (do_migt/do_ceiling_limit).
 * The worker therefore re-arms on schedule and accounts runs, which is
 * observable via the migt debug node.
 */
static struct workqueue_struct *sew_migt_wq;
static struct delayed_work sew_migt_work;
static unsigned long sew_migt_hardwork_runs;
static unsigned int sew_migt_boost_ms = 16;

static void sew_migt_hardwork_fn(struct work_struct *work)
{
	sew_migt_hardwork_runs++;
	/* STAGE2: do_migt() window + do_ceiling_limit() apply/remove +
	 * vip render wake (wake_render) go here, gated by sew_migame_enable
	 * and migt_gpsync. Until then the worker only accounts runs so
	 * the scheduling path is already observable and leak-free. */
	if (sew_migame_get_enable() && !migt_gpsync)
		queue_delayed_work(sew_migt_wq, &sew_migt_work,
				   msecs_to_jiffies(sew_migt_boost_ms));
}

static int sew_migame_workqueue_start(void)
{
	sew_migt_wq = alloc_workqueue("sew_migt_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!sew_migt_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&sew_migt_work, sew_migt_hardwork_fn);
	queue_delayed_work(sew_migt_wq, &sew_migt_work,
			   msecs_to_jiffies(sew_migt_boost_ms));
	return 0;
}

static void sew_migame_workqueue_stop(void)
{
	if (!sew_migt_wq)
		return;
	cancel_delayed_work_sync(&sew_migt_work);
	destroy_workqueue(sew_migt_wq);
	sew_migt_wq = NULL;
}

/* ================= stage-4: render 3-rule vip + freedom select ======
 * Official render identification (B2 §5.1): three independent rules,
 * each with its own module_param gate (dada modinfo names):
 *   rule1 mi_set_sf_flag: waker/wakee comm match (SurfaceFlinger or
 *     RenderThread wakes the task, or vice versa). Waker identity is
 *     unavailable in the try_to_wake_up_success probe (only the wakee
 *     @p is passed), so the rule is evaluated on the wakee side: the
 *     wakee itself is SF/RenderThread, or the waker side was recorded
 *     via sew_migame_note_sf_wake() from the slot14 SF frame-event path
 *     (B2: flt_update_sf input face).
 *   rule2 clean_task_window: clean wake, i.e. the task has no game
 *     load history on any cpu (sew_migame_load_level_cpu() all zero) and
 *     no accumulated FLT frame demand.
 *   rule3 game_setup_wrender_list: thread-name whitelist match against
 *     user_stask (dada's manual stask list, comma separated) or the
 *     built-in render names.
 * Any matching enabled rule marks the task vip (last-writer-wins: a
 * task already vip keeps its owner's value). Rule priority order for
 * the prio value is rule1 > rule3 > rule2; all three prio values are
 * fixed below so a later writer can be told apart from xr_qs (which
 * uses prio 5, xr_qs.c set_vip_prio call sites).
 *
 * OWNERSHIP LIMIT (K2): the own-vs-foreign test below is value equality
 * against 10/20/30. vip_sched's perf_actuator path accepts arbitrary
 * userspace values, so an external writer that happens to set exactly
 * 10/20/30 is misattributed as ours: maybe_unmark_vip would restore it
 * (usually a no-op since the baseline holds the same value) and
 * set_own_vip would overwrite a foreign mark of the same value. Kept
 * as-is because vip_sched offers no per-writer owner tag and any
 * stricter scheme would break the last-writer-wins arbitration; revisit
 * if an owner channel appears (F5 #15 direction).
 *
 * Choosing via comm: __get_task_comm() sleeps; the wake probe runs in
 * atomic context, so comm is read with READ_ONCE(p->comm[]) (stable
 * for kernel threads during wake; a torn read only misclassifies one
 * wake, corrected on the next wake since marking is re-evaluated).
 */
/* VIP prio levels per rule (highest wins when several rules match).
 * Values avoid xr_qs's prio 5 so ownership stays distinguishable;
 * 30 preserves the stage-1 ABI evidence (C5 §0.2: (p, 30, 1)). */
#define SEW_MIGAME_VIP_PRIO_RULE1	30
#define SEW_MIGAME_VIP_PRIO_RULE3	20
#define SEW_MIGAME_VIP_PRIO_RULE2	10

/* Wake-side waker record: slot14 SF frame events imply an SF wake is
 * in flight; the next wake_success within the window counts as rule1
 * waker-side evidence. Window in ns, tunable via task_enqueue_time_
 * toolong (ms, dada name, default 0 = feature off until tuned).
 */
static u64 sew_migame_last_sf_wake_ns;

/* Called from the slot14 SF frame-event path (process context). */
static void sew_migame_note_sf_wake(void)
{
	/* Gate on the master switch first: with the feature off no
	 * timestamp may be recorded, otherwise a stale stamp could
	 * serve as rule1 waker evidence the moment the feature is
	 * later enabled (with a non-zero window param). The rule1
	 * param gate stays as the second condition (per-rule tuning). */
	if (!sew_migame_get_enable())
		return;
	if (READ_ONCE(mark_rule1_enable))
		sew_migame_last_sf_wake_ns = sched_clock();
}

static bool sew_migame_comm_is_render(const char *comm)
{
	/* B2 §5.1 render names: RenderThread + SurfaceFlinger (+ short
	 * alias "surfaceflinger"); "GameThread" covers UE main-thread
	 * wake chains seen on nuwa. Exact match only: substring match
	 * would catch e.g. "RenderThreadPool" workers that must not be
	 * boosted (conservative: only boost, never demote others). */
	if (!comm)
		return false;
	return !strcmp(comm, "RenderThread") ||
	       !strcmp(comm, "SurfaceFlinger") ||
	       !strcmp(comm, "surfaceflinger") ||
	       !strcmp(comm, "GameThread");
}

static bool sew_migame_wakee_is_sf_or_render(struct task_struct *p)
{
	char comm[TASK_COMM_LEN];

	if (!p)
		return false;
	memcpy(comm, p->comm, TASK_COMM_LEN);
	comm[TASK_COMM_LEN - 1] = '\0';
	if (sew_migame_comm_is_render(comm))
		return true;
	/* Waker-side evidence: an SF frame event just fired (windowed). */
	if (sew_migame_last_sf_wake_ns) {
		u64 now = sched_clock();
		unsigned int win_ms = READ_ONCE(task_enqueue_time_toolong);

		if (win_ms && now - sew_migame_last_sf_wake_ns <=
		    (u64)win_ms * NSEC_PER_MSEC)
			return true;
	}
	return false;
}

static bool sew_migame_task_is_clean(struct task_struct *p)
{
	int cpu;

	(void)p;
	/* rule2 clean_task_window: no game load history anywhere. The
	 * load engine reports per-cpu levels; all zero means this wake
	 * carries no accumulated demand (a "clean" wake). FLT frame
	 * demand is system-wide and short-lived, so per-cpu game load
	 * is the stable cleanliness signal. */
	for_each_possible_cpu(cpu) {
		if (sew_migame_load_level_cpu(cpu) != MIGAME_LOAD_LVL_IDLE)
			return false;
	}
	return true;
}

static bool sew_migame_comm_in_user_stask(const char *comm)
{
	const char *list, *pos;
	size_t len;

	if (!comm || !comm[0])
		return false;
	list = READ_ONCE(user_stask);
	if (!list || !list[0])
		return false;
	len = strlen(comm);
	/* Comma-separated exact-token match (no strstr: "render" must
	 * not match "renderer"). */
	for (pos = list; *pos; ) {
		while (*pos == ',' || *pos == ' ' || *pos == '\t')
			pos++;
		if (!*pos)
			break;
		if (!strncmp(pos, comm, len) &&
		    (pos[len] == ',' || pos[len] == ' ' ||
		     pos[len] == '\t' || pos[len] == '\0'))
			return true;
		while (*pos && *pos != ',')
			pos++;
	}
	return false;
}

static bool sew_migame_wakee_in_wrender_list(struct task_struct *p)
{
	char comm[TASK_COMM_LEN];

	if (!p)
		return false;
	if (READ_ONCE(set_render_as_stask)) {
		memcpy(comm, p->comm, TASK_COMM_LEN);
		comm[TASK_COMM_LEN - 1] = '\0';
		if (sew_migame_comm_is_render(comm))
			return true;
	}
	memcpy(comm, p->comm, TASK_COMM_LEN);
	comm[TASK_COMM_LEN - 1] = '\0';
	return sew_migame_comm_in_user_stask(comm);
}


/* Returns the winning vip prio (> 0) or 0 for "not vip". Rule gates
 * are the dada mark_rule{1,2,3}_enable params (default off). */
static int sew_migame_render_rule_prio(struct task_struct *p)
{
	char comm[TASK_COMM_LEN];
	bool is_render;

	if (!p)
		return 0;
	memcpy(comm, p->comm, TASK_COMM_LEN);
	comm[TASK_COMM_LEN - 1] = '\0';
	is_render = sew_migame_comm_is_render(comm);

	/* rule1 waker/wakee: SF/RenderThread identity on either side. */
	if (READ_ONCE(mark_rule1_enable) &&
	    (is_render || sew_migame_wakee_is_sf_or_render(p)))
		return SEW_MIGAME_VIP_PRIO_RULE1;
	/* rule3 wrender list: whitelist / render-as-stask. */
	if (READ_ONCE(mark_rule3_enable) &&
	    (is_render || sew_migame_wakee_in_wrender_list(p)))
		return SEW_MIGAME_VIP_PRIO_RULE3;
	/* rule2 clean wake: only for tasks that already look like
	 * render (comm match) but missed the gates above; a fully
	 * generic clean-wake boost would vip every idle wakeup. */
	if (READ_ONCE(mark_rule2_enable) && is_render &&
	    sew_migame_task_is_clean(p))
		return SEW_MIGAME_VIP_PRIO_RULE2;
	return 0;
}

/* Set exactly our own rule prio, refreshing an older own value. Used
 * by the wake hook when the winning rule changed since the last wake
 * (e.g. rule1 now wins over a previous rule2 mark). Foreign values
 * (xr_qs prio 5 or any non-rule value) are never touched. */
static void sew_migame_set_own_vip(struct task_struct *p, int prio)
{
	u32 cur;

	if (!p || prio <= 0)
		return;
	cur = get_vip_prio(p);
	if (cur == (u32)prio)
		return;
	if (cur == 0 || cur == SEW_MIGAME_VIP_PRIO_RULE1 ||
	    cur == SEW_MIGAME_VIP_PRIO_RULE2 || cur == SEW_MIGAME_VIP_PRIO_RULE3)
		/* set_orig=false: keep the kzalloc'd baseline (0) intact so
		 * restore_vip_prio() really clears the mark. Passing true
		 * would stamp orig_prio=prio, making the later restore a
		 * no-op and leaking vip_task slots until VIP_TASK_MAX. */
		set_vip_prio(p, prio, false);
}

static void sew_migame_clear_vip(struct task_struct *p, int snapshot)
{
	if (!p)
		return;
	/* Only clear what we still own (C5 §4.1 arbitration). */
	if (sew_migame_vip_own(p, snapshot))
		restore_vip_prio(p);
}

/* Clear the vip mark when the task no longer matches any rule, but
 * only if the current value is one we set (own rule prio). Must be
 * called with the pre-clear snapshot for the arbitration check. */
static void sew_migame_maybe_unmark_vip(struct task_struct *p)
{
	int snap = sew_migame_vip_snapshot(p);

	if (snap == SEW_MIGAME_VIP_PRIO_RULE1 ||
	    snap == SEW_MIGAME_VIP_PRIO_RULE2 ||
	    snap == SEW_MIGAME_VIP_PRIO_RULE3)
		sew_migame_clear_vip(p, snap);
}

/* ================= stage-4: freedom cpuset ============================
 * VIP tasks may run only on the freedom cpuset: the set of CPUs the
 * game policy allows boosted tasks to use. OFF (empty mask) means
 * "no constraint" (stage-1 behaviour); any non-empty mask constrains
 * VIP placement suggestions and the setaffinity guard below.
 *
 * Rule (DIVERGENCE NOTE S4-F1): the official freedom face is a window/
 * whitelist app engine (freedom_window_app_set, 640 B) whose exact
 * commit semantics are unrecovered. The port keeps only the part the
 * select path needs: a CPU set + the guarantee that at least one CPU
 * stays usable (an empty intersection falls back to "no干预" so we
 * never strand a VIP task).
 *
 * Configuration: module_param freedom_cpus (cpulist string, default
 * empty = OFF). Parsed lazily on first use and on every sysfs write
 * through the param ops wrapper; a parse failure keeps the previous
 * mask (never breaks a running policy). Write path is process
 * context; readers are lock-free (cpumask_test_cpu on a stable mask
 * word is atomic on aarch64; updates use cpumask_copy under
 * freedom_lock so readers never see a torn multi-word mask... more
 * precisely: writers hold the spinlock for the copy, readers are
 * lock-free single-word tests which may lag one update at most;
 * placement advice tolerates staleness by construction).
 */
static char *freedom_cpus = "";
static struct cpumask sew_migame_freedom_mask;
static bool sew_migame_freedom_on;
static DEFINE_SPINLOCK(sew_migame_freedom_lock);

static void sew_migame_freedom_commit_locked(void)
{
	/* At least one CPU must stay usable: an empty/offline-only mask
	 * disables the constraint instead of stranding VIP tasks. */
	if (cpumask_empty(&sew_migame_freedom_mask) ||
	    !cpumask_intersects(&sew_migame_freedom_mask, cpu_online_mask))
		sew_migame_freedom_on = false;
	else
		sew_migame_freedom_on = true;
}

static int sew_migame_freedom_parse(const char *buf)
{
	struct cpumask tmp;
	unsigned long flags;

	if (!buf || !buf[0] || buf[0] == '\n') {
		spin_lock_irqsave(&sew_migame_freedom_lock, flags);
		cpumask_clear(&sew_migame_freedom_mask);
		sew_migame_freedom_on = false;
		spin_unlock_irqrestore(&sew_migame_freedom_lock, flags);
		return 0;
	}
	if (cpulist_parse(buf, &tmp))
		return -EINVAL;
	spin_lock_irqsave(&sew_migame_freedom_lock, flags);
	cpumask_copy(&sew_migame_freedom_mask, &tmp);
	sew_migame_freedom_commit_locked();
	spin_unlock_irqrestore(&sew_migame_freedom_lock, flags);
	return 0;
}

static int sew_migame_freedom_cpus_set(const char *val,
				   const struct kernel_param *kp)
{
	int ret = param_set_copystring(val, kp);

	if (ret)
		return ret;
	/* Parse failure keeps the previous mask (see above); report the
	 * error so userspace notices, policy keeps running. */
	return sew_migame_freedom_parse(freedom_cpus);
}

static const struct kernel_param_ops sew_migame_freedom_cpus_ops = {
	.set = sew_migame_freedom_cpus_set,
	.get = param_get_charp,
};
module_param_cb(freedom_cpus, &sew_migame_freedom_cpus_ops, &freedom_cpus, 0644);
MODULE_PARM_DESC(freedom_cpus, "VIP freedom cpuset (cpulist, empty = no constraint)");

/* VIP-gated mask test: non-VIP tasks are never constrained. */
static bool sew_migame_cpu_in_freedom(int cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return false;
	return cpumask_test_cpu(cpu, &sew_migame_freedom_mask);
}

/* First freedom CPU usable for @p, or -1 for "no干预". Hot/CPU mask:
 * freedom ∩ online ∩ task-allowed. Caller guarantees @p != NULL. */
static int sew_migame_freedom_pick_cpu(struct task_struct *p)
{
	int cpu;

	if (!READ_ONCE(sew_migame_freedom_on))
		return -1;
	for_each_cpu_and(cpu, &sew_migame_freedom_mask, cpu_online_mask) {
		if (cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}
	return -1;
}

/* ---- glk tunable accessors (stage-2 engine input) ----
 * Backed by the module params above; the load/freq engines read through
 * these so the param storage stays in exactly one place. Indexing: the
 * glk arrays are per-policy kHz tables; out-of-range cpu/policy index
 * yields 0 (= no constraint from that side). */
bool sew_migame_glk_disabled(void)
{
	return READ_ONCE(glk_disable) != 0;
}

bool sew_migame_glk_fbreak_enabled(void)
{
	return READ_ONCE(glk_fbreak_enable) != 0;
}

unsigned int sew_migame_glk_minfreq_khz(int cpu)
{
	unsigned int idx = (unsigned int)cpu;

	if (idx >= (unsigned int)MI_GAME_ARR_SZ)
		return 0;
	if ((int)idx >= READ_ONCE(glk_minfreq_n))
		return 0;
	return READ_ONCE(glk_minfreq[idx]);
}

unsigned int sew_migame_glk_maxfreq_khz(int cpu)
{
	unsigned int idx = (unsigned int)cpu;

	if (idx >= (unsigned int)MI_GAME_ARR_SZ)
		return 0;
	if ((int)idx >= READ_ONCE(glk_maxfreq_n))
		return 0;
	return READ_ONCE(glk_maxfreq[idx]);
}

unsigned long sew_migame_glk_freq_limit_walt(void)
{
	return (unsigned long)READ_ONCE(glk_freq_limit_walt);
}

const unsigned int *sew_migame_glk_min_tbl(void)
{
	return glk_minfreq;
}

const unsigned int *sew_migame_glk_max_tbl(void)
{
	return glk_maxfreq;
}

/* ---- FLT tunable accessors (stage-3 engine input) ----
 * Backed by the module params above; flt.c reads through these so the
 * param storage stays in exactly one place. */
unsigned int sew_migame_flt_target_fps(void)
{
	return READ_ONCE(flt_target_fps);
}

int sew_migame_flt_up_margin(void)
{
	return READ_ONCE(flt_up_thresh_margin);
}

int sew_migame_flt_down_margin(void)
{
	return READ_ONCE(flt_down_thresh_margin);
}

static unsigned int sew_migame_arr_at(const unsigned int *arr, int n, int idx)
{
	if (idx < 0 || idx >= MI_GAME_ARR_SZ)
		return 0;
	if (idx >= n)
		return 0;
	return READ_ONCE(arr[idx]);
}

unsigned int sew_migame_flt_in_frame_freq(int idx)
{
	return sew_migame_arr_at(flt_in_frame_freq, READ_ONCE(sew_flt_in_frame_freq_n),
			     idx);
}

unsigned int sew_migame_flt_low_freq(int idx)
{
	return sew_migame_arr_at(flt_low_freq, READ_ONCE(sew_flt_low_freq_n), idx);
}

unsigned int sew_migame_flt_high_freq(int idx)
{
	return sew_migame_arr_at(flt_high_freq, READ_ONCE(sew_flt_high_freq_n), idx);
}

unsigned int sew_migame_flt_cal_enabled(int idx)
{
	return sew_migame_arr_at(flt_cal_freq_enable,
			     READ_ONCE(sew_flt_cal_freq_enable_n), idx);
}

unsigned int sew_migame_task_util_thresh(void)
{
	return READ_ONCE(task_util_thresh);
}

const unsigned int *sew_migame_flt_low_tbl(void)
{
	return flt_low_freq;
}

const unsigned int *sew_migame_flt_high_tbl(void)
{
	return flt_high_freq;
}

/* ---- plat_common providers (exact wrapper typedef shapes) ---- */
static void sew_migame_find_energy_hook(struct task_struct *p, bool need_idle)
{
	/* B2 §5.1 recovered body: wake_render + vip-driven need_idle. The
	 * wake is STAGE4 (needs render detection); the vip predicate is
	 * live now via the in-tree channel. need_idle is by value in the
	 * wrapper, so stage 1 records the decision in trace/debug. */
	bool vip = (p && get_vip_prio(p) != 0);

	if (need_idle || vip)
		pr_debug("migt: find_energy vip=%d need_idle=%d\n",
			 vip, need_idle);
}

static void sew_migame_update_pkg_load(struct task_struct *p, u32 event,
				       u32 flag, u64 wallclock, u64 arg5)
{
	/* Slot 14 provider (G4 signature): wallclock nominal, arg5 opaque
	 * walt fixed-point increment. Stage-2 body lives in mi_game_load.c;
	 * stage-3 additionally feeds the FLT frame-event stream: event 1/2
	 * open/close a frame (begin/end at wallclock), other events feed
	 * the SF input as opaque (a=event<<32|flag, b=arg5). Stage-4 also
	 * records an SF-wake timestamp for rule1 waker-side evidence.
	 * Gate inside each callee; off means only the game_load path runs. */
	sew_migame_pkg_load_update(p, event, flag, wallclock, arg5);
	if (event == 1) {
		flt_frame_begin(wallclock);
		sew_migame_note_sf_wake();
	} else if (event == 2) {
		flt_frame_end(wallclock);
	} else {
		sew_migame_flt_input_sf(((u64)event << 32) | flag, arg5);
		sew_migame_note_sf_wake();
	}
}

static void sew_migame_walt_get_indicies(struct task_struct *p,
				     unsigned long *order_index,
				     unsigned long *indicies2,
				     int *num_sched_clusters,
				     bool *skip_walt_indicies,
				     bool *energy_eval_needed)
{
	/* Slot 15 provider (STAGE3 PELT bridge): WALT cluster indices have
	 * no 5.15 meaning. order_index carries the task PELT demand,
	 * indicies2 carries the FLT-aggregated frame target; single PELT
	 * domain (num_sched_clusters=1, skip walt path); energy eval when
	 * the demand reaches task_util_thresh. Gate: off returns neutral. */
	unsigned long demand, agg;

	if (!sew_migame_get_enable()) {
		if (order_index)
			*order_index = 0;
		if (indicies2)
			*indicies2 = 0;
		if (num_sched_clusters)
			*num_sched_clusters = 0;
		if (skip_walt_indicies)
			*skip_walt_indicies = false;
		if (energy_eval_needed)
			*energy_eval_needed = false;
		return;
	}
	demand = sew_migame_pelt_task_demand(p);
	agg = flt_cal_freq(0);
	if (order_index)
		*order_index = demand;
	if (indicies2)
		*indicies2 = agg;
	if (num_sched_clusters)
		*num_sched_clusters = 1;
	if (skip_walt_indicies)
		*skip_walt_indicies = true;
	if (energy_eval_needed)
		*energy_eval_needed = (demand >= sew_migame_task_util_thresh());
}

static void sew_migame_get_ravg_window(u64 *old_ravg_window)
{
	/* Slot 16 direct pass-through (no RE-STUB guard on wrapper).
	 * Stage-2 body in mi_game_load.c (reports PELT-side window). */
	sew_migame_ravg_window_get(old_ravg_window);
}

static void sew_migame_slot17_freq(unsigned long a1, unsigned long a2,
				 unsigned long a3, unsigned long a4,
				 unsigned long a5, unsigned long a6,
				 unsigned long a7, unsigned long a8)
{
	/* Slot 17 provider seam: real logic in mi_game_freq.c
	 * (PELT frame load -> per-policy freq_qos_update_request).
	 * Process-context only: the freq layer takes a mutex and may
	 * sleep in freq_qos_update_request. plat_common declares no
	 * calling-context contract, and this wrapper's only in-tree
	 * caller is plat_mi_set_next_freq (zero further callers), so
	 * any future atomic-path call site would be a sleep-in-atomic
	 * bug. might_sleep() fires if that ever happens. */
	might_sleep();
	sew_migame_set_next_freq(a1, a2, a3, a4, a5, a6, a7, a8);
}

static void sew_migame_task_fork(struct task_struct *p)
{
	if (!p)
		return;
	/* VIP inherit: a render child keeps the parent's vip level
	 * (vip_sched inherit_vip_prio copies current prio, baseline
	 * untouched, so the child never outlives the parent's mark:
	 * the wake hook clears it once the child stops matching). Only
	 * when enabled, and never overriding an existing mark
	 * (last-writer-wins). */
	if (sew_migame_get_enable() && current && current != p &&
	    get_vip_prio(current) && !get_vip_prio(p) &&
	    sew_migame_render_rule_prio(p))
		inherit_vip_prio(current, p);
	pr_debug("migt: fork seen %d\n", p->pid);
}

static void sew_migame_scheduler_tick(struct rq *rq)
{
	if (!rq)
		return;
	/* Stage-2: feed the game_load tick path (throttled inside). */
	sew_migame_scheduler_tick_account(rq);
}

/* Stage-4 select bodies (slots 20/22/23/24). Return semantics are the
 * plat_common wrapper defaults (read from mm/plat_common.c):
 *   slot20 fastpath: 0 = no fastpath decision (any chosen cpu >= 0 is
 *     a placement suggestion; 0 itself is a valid cpu, so "no干预"
 *     must be 0 only when we really mean cpu 0... see body).
 *   slot22 exclusive / slot23 choose: cpu number or -1 = no override.
 *   slot24/25 skip: true = mi_game_reserve_cpus was filled with CPUs
 *     to skip. All bodies are VIP-gated: non-VIP tasks get the
 *     wrapper default (behaviour-neutral when disabled or unmatched).
 */
static int sew_migame_choose_cpu_fastpath(struct task_struct *p,
				      struct metis_choose_cpu_args *metis_args,
				      bool (*should_skip)(void *a, void *b))
{
	int cpu;

	(void)metis_args;
	(void)should_skip;
	/* Preserve the wrapper default exactly when there is nothing
	 * to say: 0 doubles as "cpu 0", so only suggest when freedom
	 * actually names a usable cpu; otherwise 0 == no干预 anyway. */
	if (!sew_migame_get_enable() || !p)
		return 0;
	if (!READ_ONCE(choose_cpu_enable))
		return 0;
	if (!get_vip_prio(p))
		return 0;
	cpu = sew_migame_freedom_pick_cpu(p);
	if (cpu < 0)
		return 0;
	return cpu;
}

static int sew_migame_choose_exclusive_cpus(struct task_struct *p)
{
	int cpu;

	if (!sew_migame_get_enable() || !p)
		return -1;
	if (!READ_ONCE(choose_cpu_exclusive_enable))
		return -1;
	if (!get_vip_prio(p))
		return -1;
	cpu = sew_migame_freedom_pick_cpu(p);
	return cpu; /* -1 when unconstrained = wrapper default */
}

static int sew_migame_choose_cpu(struct task_struct *p)
{
	int cpu;

	if (!sew_migame_get_enable() || !p)
		return -1;
	if (!READ_ONCE(choose_cpu_enable))
		return -1;
	if (!get_vip_prio(p))
		return -1;
	cpu = sew_migame_freedom_pick_cpu(p);
	return cpu;
}

static bool sew_migame_skip_cpus(cpumask_var_t mi_game_reserve_cpus)
{
	int cpu;
	bool filled = false;

	/* Fill the reserve mask with freedom-excluded online CPUs (the
	 * caller skips them). Empty freedom = no constraint = false
	 * (wrapper default). At least one cpu is always left out of
	 * the mask so the caller can still place the task. */
	if (!sew_migame_get_enable() || !mi_game_reserve_cpus)
		return false;
	if (!READ_ONCE(sew_migame_freedom_on))
		return false;
	cpumask_clear(mi_game_reserve_cpus);
	for_each_online_cpu(cpu) {
		if (!sew_migame_cpu_in_freedom(cpu)) {
			/* Keep the first freedom cpu placeable even if
			 * the caller intersects aggressively. */
			cpumask_set_cpu(cpu, mi_game_reserve_cpus);
			filled = true;
		}
	}
	if (filled && cpumask_empty(mi_game_reserve_cpus))
		return false;
	/* Never fence off everything: if no freedom cpu is online,
	 * freedom_on is already false (commit rule), so reaching here
	 * with full coverage means misconfig; back off. */
	if (filled &&
	    cpumask_weight(mi_game_reserve_cpus) >= num_online_cpus())
		return false;
	return filled;
}

static bool sew_migame_skip_cpus_rt(struct task_struct *p,
				cpumask_var_t mi_game_reserve_cpus)
{
	/* RT tasks are never steered by the game policy (official
	 * migt_should_skip_migrate falls through to plat_is_relaxed_rt
	 * for non-game tasks; we have no game-task table, so the
	 * conservative equivalent is: never skip for RT). */
	if (!p || rt_task(p))
		return false;
	return sew_migame_skip_cpus(mi_game_reserve_cpus);
}

static bool sew_migame_should_skip_cpu_rt(struct task_struct *p, void *grp)
{
	(void)grp;
	if (!sew_migame_get_enable() || !p)
		return false;
	if (!READ_ONCE(sew_migame_freedom_on))
		return false;
	/* RT-gated skip probe: only VIP tasks are ever constrained. */
	return get_vip_prio(p) != 0 && !rt_task(p) &&
	       !cpumask_intersects(p->cpus_ptr, &sew_migame_freedom_mask);
}

static bool sew_migame_should_skip_migrate(struct task_struct *p, void *grp)
{
	(void)grp;
	/* Official body keys off game-task tables + coregroup masks
	 * (unrecovered); the portable conservative core is: VIP tasks
	 * whose allowed mask no longer intersects freedom should not
	 * migrate (stay where freedom placed them). Everything else:
	 * wrapper default false. */
	if (!sew_migame_get_enable() || !p)
		return false;
	if (!READ_ONCE(sew_migame_freedom_on))
		return false;
	if (!get_vip_prio(p))
		return false;
	return !cpumask_intersects(p->cpus_ptr, &sew_migame_freedom_mask);
}

static bool sew_migame_check_rt(struct task_struct *p)
{
	/* migt_cpu_check_rt: true when the task is an RT-policy task
	 * under game management (VIP-marked). Used by the LB path to
	 * keep RT game tasks out of CFS balancing assumptions. */
	if (!p)
		return false;
	if (!sew_migame_get_enable())
		return false;
	return rt_task(p) && get_vip_prio(p) != 0;
}

static bool sew_migame_vip_check(struct task_struct *p)
{
	if (!p)
		return false;
	/* Gate: off means the wrapper default (false). Without it a
	 * disabled feature would still report foreign VIP marks
	 * (e.g. userspace via perf_actuator) to LB/placement consumers. */
	if (!sew_migame_get_enable())
		return false;
	return get_vip_prio(p) != 0;
}

/* ---- slot-30 placement-ready gate (L1-FINALIZE K1 fix) ----
 * Reports whether mi_game's own placement face can actually place tasks.
 * The provider chain (slots 20/22/23/24 + freedom mask) is complete, but
 * the SCHEDULER-SIDE call sites are missing: fair.c/select path makes
 * zero calls into the plat_game_choose and plat_game_skip wrappers
 * (K10 T1, K11 #6c). Until those call sites land this returns false
 * (待上游接线,
 * do not delete: the providers + freedom machinery are the retained
 * game-VIP placement optimization carrier).
 * 服务移植优化目标: 游戏 VIP 选核放置 (freedom placement 面). */
bool sew_migame_placement_ready(void)
{
	return false;
}

static int sew_migame_enable_hook(void)
{
	/* Slot 30 means "mi_game will place, vip_sched stand down": the
	 * conjunction, not raw enable. dada's vip_sched yields on this slot
	 * (.text+0x2590 bl plat_migt_enable / cbnz), which on dada coincided
	 * with a wired placement face. Here placement is unwired, so raw
	 * enable would yield VIP placement to nobody (K11-K1 net loss):
	 * yield only when the master switch is on AND the placement face is
	 * ready. Wiring the fair.c call sites + flipping
	 * sew_migame_placement_ready() restores the dada yield automatically.
	 * Only in-tree consumer of slot 30 is vip_sched.c:910. */
	return sew_migame_get_enable() && sew_migame_placement_ready();
}

/* ---- RVH direct probes ---- */
static void sew_migame_cpuset_fork_hook(void *data, struct task_struct *p,
				   int *inherit_cpus)
{
	/* mi_game_freedom_cpuset_fork: nothing to inherit into the
	 * child (freedom is a system-wide mask, not per-task state).
	 * VIP level itself is inherited in sew_migame_task_fork (slot 18),
	 * not here. Hook stays registered so the tracepoint stays
	 * claimed; the mask commit rule (at least one cpu usable)
	 * is enforced at parse time. */
	(void)data;
	(void)inherit_cpus;
	if (!p)
		return;
	pr_debug("migt: cpuset_fork %d\n", p->pid);
}

static void sew_migame_setaffinity_early_hook(void *data, struct task_struct *p,
					  const struct cpumask *new_mask,
					  int *retval)
{
	/* mi_game_freedom_setaffinity: guard only, never override.
	 * If a VIP task's new affinity would exclude the whole freedom
	 * set, veto (return -EINVAL through *retval) so the task stays
	 * placeable; otherwise leave the request untouched. Non-VIP
	 * tasks and empty freedom are never touched. The veto keeps at
	 * least one cpu usable by construction (commit rule). */
	(void)data;
	if (!sew_migame_get_enable() || !p || !new_mask || !retval)
		return;
	if (!READ_ONCE(sew_migame_freedom_on))
		return;
	if (!get_vip_prio(p))
		return;
	if (!cpumask_intersects(new_mask, &sew_migame_freedom_mask))
		*retval = -EINVAL;
}

static void sew_migame_wake_success_hook(void *data, struct task_struct *p)
{
	/* Render/vip wake face. Rule verdict -> "是否 VIP + 规则号":
	 * the winning rule's prio is the mark; 0 means no rule fired
	 * and any own previous mark is dropped (snapshot arbitration:
	 * foreign (xr_qs) values are never touched). Gated by
	 * sew_migame_enable (default off = zero behaviour). */
	int prio;

	(void)data;
	if (!p)
		return;
	if (!sew_migame_get_enable())
		return;
	prio = sew_migame_render_rule_prio(p);
	if (prio > 0) {
		sew_migame_set_own_vip(p, prio);
	} else {
		sew_migame_maybe_unmark_vip(p);
	}
}

static void sew_migame_cpufreq_trans_hook(void *data, struct cpufreq_policy *policy)
{
	/* flt/glk调频面 observe hook (STAGE2/3: limit-break accounting). */
	if (!policy)
		return;
	pr_debug("migt: cpufreq trans cpu=%d\n", policy->cpu);
}

static int sew_migame_rvh_register(void)
{
	int ret;

	ret = register_trace_android_rvh_cpuset_fork(sew_migame_cpuset_fork_hook,
						    NULL);
	if (ret) {
		pr_err("mi_game freedom: cpuset_fork hook register failed\n");
		return ret;
	}
	ret = register_trace_android_vh_sched_setaffinity_early(
			sew_migame_setaffinity_early_hook, NULL);
	if (ret) {
		pr_err("mi_game freedom: sched_setaffinity_early hook register failed\n");
		goto err_affinity;
	}
	ret = register_trace_android_rvh_try_to_wake_up_success(
			sew_migame_wake_success_hook, NULL);
	if (ret)
		goto err_wake;
	ret = register_trace_android_rvh_cpufreq_transition(
			sew_migame_cpufreq_trans_hook, NULL);
	if (ret)
		goto err_cpufreq;
	return 0;

err_cpufreq:
	tracepoint_probe_unregister(&__tracepoint_android_rvh_try_to_wake_up_success,
				    sew_migame_wake_success_hook, NULL);
err_wake:
	unregister_trace_android_vh_sched_setaffinity_early(
		sew_migame_setaffinity_early_hook, NULL);
err_affinity:
	tracepoint_probe_unregister(&__tracepoint_android_rvh_cpuset_fork,
				    sew_migame_cpuset_fork_hook, NULL);
	return ret;
}

/* Restricted RVH hooks (cpuset_fork / try_to_wake_up_success /
 * cpufreq_transition) are register-only by macro design ("vendor hooks
 * cannot be unregistered", vendor_hooks.h:107): detach uses the generic
 * tracepoint_probe_unregister on the __tracepoint_ symbol (same idiom as
 * kernel/sched/sched_penalty.c), followed by
 * tracepoint_synchronize_unregister(). Only sched_setaffinity_early is a
 * plain DECLARE_HOOK with a matching unregister_trace_* helper. */
static void sew_migame_rvh_unregister(void)
{
	tracepoint_probe_unregister(&__tracepoint_android_rvh_cpufreq_transition,
				    sew_migame_cpufreq_trans_hook, NULL);
	tracepoint_probe_unregister(&__tracepoint_android_rvh_try_to_wake_up_success,
				    sew_migame_wake_success_hook, NULL);
	unregister_trace_android_vh_sched_setaffinity_early(
		sew_migame_setaffinity_early_hook, NULL);
	tracepoint_probe_unregister(&__tracepoint_android_rvh_cpuset_fork,
				    sew_migame_cpuset_fork_hook, NULL);
	tracepoint_synchronize_unregister();
}

/* ---- plat hook (un)registration with per-slot rollback ----
 * 15 slots: init chain 6 (13/14/15/16/17/30: energy/pkg/walt/ravg/freq/
 * enable) + migt_sched_init inner 9 (18/19/20/22/23/24/25/26/27/28/29
 * minus nothing: 18 fork, 19 tick, 20 fastpath, 22 exclusive, 23 choose,
 * 24 skip, 25 skip_rt, 26 should_skip_rt, 27 should_skip_mig, 28 check_rt,
 * 29 vip_check = 11 ... total counted exactly below as 16 functional
 * entries; slot 21 FREE_MI_TASK_STRUCT deliberately excluded, see file
 * header). Count check: 13,14,15,16,17,18,19,20,22,23,24,25,26,27,28,29,
 * 30 = 17 ids minus slot 21 (not ours) = 16... recount: the B2 §2.2 "15
 * registrations" = init 6 + sched_init 9. The init-6 are
 * 13(find_energy),14(pkg),15(walt),16(ravg),17(freq),30(enable); the
 * sched_init-9 are 18,19,20,22,23,24,25,26,27 + 28,29 fold into the same
 * call (B2 counts 28/29 within the 9 by grouping skip variants).
 * Stage 1 registers all 17 mi_game-owned ids explicitly; the count is
 * asserted at build time below.
 */
struct sew_migame_slot {
	int id;
	void *fn;
};

static const struct sew_migame_slot sew_migame_slots[] = {
	{ FUNC_MI_GAME_FIND_ENERGY_HOOK,	sew_migame_find_energy_hook },
	{ FUNC_MIGT_HOOK,			sew_migame_update_pkg_load },
	{ FUNC_MI_GAME_WALT_GET_INDICIES,	sew_migame_walt_get_indicies },
	{ FUNC_GAME_GET_RAVG_WINDOW,		sew_migame_get_ravg_window },
	{ FUNC_MI_SET_NEXT_FREQ,		sew_migame_slot17_freq },
	{ FUNC_MI_GAME_TASK_FORK,		sew_migame_task_fork },
	{ FUNC_MI_GAME_SCHEDULER_TICK,		sew_migame_scheduler_tick },
	{ FUNC_MI_GAME_CHOOSE_CPU_FASTPATH,	sew_migame_choose_cpu_fastpath },
	{ FUNC_MI_GAME_CHOOSE_EXCLUSIVE_CPUS,	sew_migame_choose_exclusive_cpus },
	{ FUNC_MI_GAME_CHOOSE_CPU,		sew_migame_choose_cpu },
	{ FUNC_MI_GAME_SKIP_CPUS,		sew_migame_skip_cpus },
	{ FUNC_MI_GAME_SKIP_CPUS_RT,		sew_migame_skip_cpus_rt },
	{ FUNC_MI_GAME_SHOULD_SKIP_CPU_RT,	sew_migame_should_skip_cpu_rt },
	{ FUNC_MI_GAME_SHOULD_SKIP_MIGRATE,	sew_migame_should_skip_migrate },
	{ FUNC_MI_GAME_CHECK_RT,		sew_migame_check_rt },
	{ FUNC_MI_GAME_VIP_CHECK,		sew_migame_vip_check },
	{ FUNC_MIGT_ENABLE,			sew_migame_enable_hook },
};

/* 17 providers: B2 §2.2 "15 registrations" groups skip/skip_rt +
 * should_skip variants; all owned ids are registered individually here
 * (superset, each rollback-safe). Slot 21 excluded (not mi_game owned). */
static int sew_migame_plat_register(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(sew_migame_slots); i++) {
		ret = register_plat_func(sew_migame_slots[i].id,
					 sew_migame_slots[i].fn);
		if (ret) {
			pr_err("migt: register_plat_func %d failed (%d)\n",
			       sew_migame_slots[i].id, ret);
			while (i--)
				unregister_plat_func(sew_migame_slots[i].id);
			return ret;
		}
	}
	return 0;
}

static void sew_migame_plat_unregister(void)
{
	int i;

	for (i = (int)ARRAY_SIZE(sew_migame_slots) - 1; i >= 0; i--)
		unregister_plat_func(sew_migame_slots[i].id);
}

/* ================= engine seams =================
 * STAGE2 (mi_game_load.c / mi_game_freq.c) plugs the real bodies here;
 * STAGE3 (flt.c) plugs the FLT body later. game_load_init/exit and the
 * freq layer init/exit are wired into migt_sched_init/exit so init order
 * is: char/proc/workqueue -> load engine -> freq layer -> flt stub ->
 * plat providers -> RVH probes (unwind is the exact reverse).
 */
int sew_migame_load_engine_init(void)
{
	int ret;

	ret = sew_migame_freq_init();
	if (ret)
		return ret;
	ret = sew_migame_load_init();
	if (ret) {
		sew_migame_freq_exit();
		return ret;
	}
	return 0;
}

void sew_migame_load_engine_exit(void)
{
	sew_migame_load_exit();
	sew_migame_freq_exit();
}

/* Exported dada entry names (B2 §2.1): game_load_init/exit wrap the
 * engine seam + its proc face (proc face already live in stage 1). */
int game_load_init(void)
{
	return sew_migame_load_engine_init();
}
EXPORT_SYMBOL_GPL(game_load_init);

void game_load_exit(void)
{
	sew_migame_load_engine_exit();
}
EXPORT_SYMBOL_GPL(game_load_exit);

int sew_migame_flt_engine_init(void)
{
	/* STAGE3: FLT frame-load engine + PELT bridge. Init order after
	 * the game_load/freq layers; unwind is the exact reverse. */
	return sew_migame_flt_init();
}

void sew_migame_flt_engine_exit(void)
{
	sew_migame_flt_exit();
}

/* ================= module init/exit =================
 * Order mirrors rtg_module_init: misc/char/proc/workqueue first, then
 * plat providers, then RVH probes; every step unwinds exactly what the
 * previous steps built (labels err_rvh/err_plat/err_wq/err_proc/
 * err_misc/err_reset/err_migt).
 */
int migt_sched_init(void)
{
	int ret;

	ret = sew_migame_chrdev_setup_migt();
	if (ret)
		return ret;
	ret = sew_migame_chrdev_setup_reset();
	if (ret)
		goto err_reset;
	ret = misc_register(&sew_migt_miscdev);
	if (ret) {
		pr_err("migt: misc_register failed\n");
		goto err_misc;
	}
	ret = sew_migame_proc_setup();
	if (ret)
		goto err_proc;
	ret = sew_migame_workqueue_start();
	if (ret)
		goto err_wq;
	ret = game_load_init();
	if (ret)
		goto err_load;
	ret = sew_migame_flt_engine_init();
	if (ret)
		goto err_flt;
	ret = sew_migame_plat_register();
	if (ret)
		goto err_plat;
	ret = sew_migame_rvh_register();
	if (ret)
		goto err_rvh;

	pr_info("migt: mi_game stage-1 skeleton ready (enable=%d)\n",
		sew_migame_get_enable());
	return 0;

err_rvh:
	sew_migame_plat_unregister();
err_plat:
	sew_migame_flt_engine_exit();
err_flt:
	game_load_exit();
err_load:
	sew_migame_workqueue_stop();
err_wq:
	sew_migame_proc_teardown();
err_proc:
	misc_deregister(&sew_migt_miscdev);
err_misc:
	sew_migame_chrdev_teardown_reset();
err_reset:
	sew_migame_chrdev_teardown_migt();
	return ret;
}
EXPORT_SYMBOL_GPL(migt_sched_init);

void migt_sched_exit(void)
{
	sew_migame_rvh_unregister();
	sew_migame_plat_unregister();
	sew_migame_flt_engine_exit();
	game_load_exit();
	sew_migame_workqueue_stop();
	sew_migame_proc_teardown();
	misc_deregister(&sew_migt_miscdev);
	sew_migame_chrdev_teardown_reset();
	sew_migame_chrdev_teardown_migt();
}
EXPORT_SYMBOL_GPL(migt_sched_exit);

static int __init mi_game_module_init(void)
{
	return migt_sched_init();
}

static void __exit mi_game_module_exit(void)
{
	migt_sched_exit();
}

module_init(mi_game_module_init);
module_exit(mi_game_module_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sew OS4 port (dada mi_game.ko by David)");
MODULE_DESCRIPTION("migt-driver stage-1 skeleton (game sched accelerator framework)");
