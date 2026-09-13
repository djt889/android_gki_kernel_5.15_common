// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/xiaomi_sched/qcom/mi_game/mi_game.h - mi_game stage-1 public header
 *
 * D6-MIGAME stage 1 skeleton (5.15 GKI port of Xiaomi dada OS4 mi_game.ko).
 * See E:/AI/ClaudeCode/outputs/os4-3rom-analysis/C5-migame-plan.md and
 * B2-mi-game-feasibility.md for the reverse-engineering evidence.
 *
 * Stage-1 scope contract:
 *   - IN SCOPE: /dev/migt char device + /dev/migt_reset node + misc face,
 *     ioctl 11-command dispatch skeleton (generic buffer, no fake magic),
 *     proc triple-tree (migt/ game_load/ frame_load/) create/remove,
 *     15 plat_common hook providers, 4 RVH direct probes,
 *     migt_enable gate, mi_dflt always-on stub, is_32B_user compat rewrite,
 *     83 module_param namesakes, exported init/exit entry names.
 *   - STAGE 2 FILLS: game_load engine (game_load_update/history/reset,
 *     glk irq_work, freq_qos击穿 via xr_set_next_freq PELT rewrite).
 *     mi_game_load.c does not exist yet; the stage-1 stubs
 *     sew_migame_load_engine_init/exit are the seam.
 *   - STAGE 3 FILLS: FLT frame-load engine (flt_cal_freq etc. + PELT
 *     bridge mi_game_pelt.c). Stubs sew_migame_flt_engine_init/exit are seam.
 *   - STAGE 4 FILLS: vip wiring internals (render 3-rule detection bodies,
 *     freedom cpuset whitelist bodies, game_lb_control policy body) and
 *     the xr_qs/vip_sched arbitration (last-writer-wins + snapshot rule).
 *     The function shapes exist; only policy bodies are deferred.
 *
 * No unfinished work inside stage-1 scope: every stage-1 path is fully
 * implemented with error rollback. "STAGE2/3/4" markers below denote the legal phasing,
 * not unfinished stage-1 work.
 */

#ifndef __MI_GAME_H__
#define __MI_GAME_H__

#include <linux/types.h>

/* Stage-1 ioctl dispatch: low 8 bits 1..11 are real (B2 asm evidence:
 * "and w8,w21,#0xff; sub w8,#0x1; cmp w8,#0xa"). Full magic (cmd>>8) and
 * per-command payload shapes are P0-unrecovered: recovered via Ghidra on
 * migt_ioctl (2292 B) or from the milletd/MiGame HAL header. Stage 1
 * therefore dispatches on the low byte and stages through a generic
 * fixed-size buffer; per-command copy_from_user shapes are STAGE2 work
 * once P0 lands. The _IOR/_IOW numbers below are placeholders that MUST
 * be replaced with the recovered values (see MIGT_IOC_MAGIC note).
 */
#define MIGT_IOC_NR_MIN		1
#define MIGT_IOC_NR_MAX		11
/* Placeholder magic 'g' (0x67): replaced by the Ghidra-recovered magic in
 * stage 2 (P0-1). Kept as a single macro so the swap is one line. */
#define MIGT_IOC_MAGIC		'g'
/* Generic staging buffer: largest plausible ioctl payload (covers the
 * 68 B rtg SET_TASK_ARRAY precedent with margin). NOT a claim about the
 * real migt_cmd size; replaced per-command once P0 recovers the shapes. */
#define MIGT_IOC_BUF_SZ		128

struct task_struct;
struct rq;
struct cpumask;

/* ---- stage-1 public entry points (also the .ko exported symbols) ---- */
int migt_sched_init(void);
void migt_sched_exit(void);
int game_load_init(void);
void game_load_exit(void);
/* is_32B_user: exported compat helper (B2 §3.2: rewritten via
 * is_compat_task(), native copy_from_user replaces the 6.6 fast path). */
int is_32B_user(void);
/* mi_set_flt_target_delta: exported FLT knob; stage-1 stores it,
 * stage-3 consumes it in flt_cal_freq. */
int mi_set_flt_target_delta(int delta);

/* ---- engine seams (STAGE3 fills flt.c) ---- */
int sew_migame_load_engine_init(void);
void sew_migame_load_engine_exit(void);
int sew_migame_flt_engine_init(void);
void sew_migame_flt_engine_exit(void);

/* ---- stage-2 game_load engine (mi_game_load.c) ----
 * sew_migame_load_init/exit own the irq_work + policy notifier + per-CPU
 * state; wrapped by sew_migame_load_engine_init/exit together with the
 * freq layer (see mi_game_ca.c init order comment). */
int sew_migame_load_init(void);
void sew_migame_load_exit(void);

/* ---- stage-2 game_load engine (mi_game_load.c) ---- */
void sew_migame_load_reset_cpu(int cpu);
void sew_migame_load_reset_all(void);
void sew_migame_load_history_update(int cpu, u64 delta);
u32 sew_migame_load_level_cpu(int cpu);
/* Slot14 provider, G4 signature: wallclock nominal, arg5 opaque. */
void sew_migame_pkg_load_update(struct task_struct *p, u32 event, u32 flag,
			    u64 wallclock, u64 arg5);
/* ravg window (slot16): reports the PELT-side window, 0 = PELT path. */
void sew_migame_ravg_window_get(u64 *old_ravg_window);
/* scheduler_tick accounting hook (stage-2: game_load tick input). */
void sew_migame_scheduler_tick_account(struct rq *rq);

/* ---- stage-2 freq_qos layer (mi_game_freq.c) ---- */
int sew_migame_freq_init(void);
void sew_migame_freq_exit(void);
void sew_migame_freq_kick(u32 level, u32 seq);
void sew_migame_freq_clear(void);
/* Slot17 provider (8-word official payload; a1=level hint, a2=on/off). */
void sew_migame_set_next_freq(unsigned long a1, unsigned long a2,
			  unsigned long a3, unsigned long a4,
			  unsigned long a5, unsigned long a6,
			  unsigned long a7, unsigned long a8);

/* Load-level constants shared by load + freq layers. */
#define MIGAME_LOAD_LVL_IDLE	0x08
#define MIGAME_LOAD_LVL_LOW	0x10
#define MIGAME_LOAD_LVL_MID	0x19
#define MIGAME_LOAD_LVL_HIGH	0x20
#define MIGAME_LOAD_LVL_BOOST	0x21

/* ---- glk tunable accessors (backed by mi_game_ca.c module params) ---- */
bool sew_migame_glk_disabled(void);
bool sew_migame_glk_fbreak_enabled(void);
unsigned int sew_migame_glk_minfreq_khz(int cpu);
unsigned int sew_migame_glk_maxfreq_khz(int cpu);
unsigned long sew_migame_glk_freq_limit_walt(void);
/* Raw kHz tables for FLT floor computation (policy-indexed, 8-wide). */
const unsigned int *sew_migame_glk_min_tbl(void);
const unsigned int *sew_migame_glk_max_tbl(void);

/* ---- FLT tunable accessors (backed by mi_game_ca.c module params) ---- */
unsigned int sew_migame_flt_target_fps(void);
int sew_migame_flt_up_margin(void);
int sew_migame_flt_down_margin(void);
unsigned int sew_migame_flt_in_frame_freq(int idx);
unsigned int sew_migame_flt_low_freq(int idx);
unsigned int sew_migame_flt_high_freq(int idx);
unsigned int sew_migame_flt_cal_enabled(int idx);
unsigned int sew_migame_task_util_thresh(void);
/* Raw low/high kHz tables for FLT floor computation (8-wide). */
const unsigned int *sew_migame_flt_low_tbl(void);
const unsigned int *sew_migame_flt_high_tbl(void);

/* ---- migt_enable gate (slot 30 provider reads this) ----
 * Writers: migame_enable module_param_cb + /proc/migt/migt_sched_enable
 * (both in mi_game_ca.c, both call sew_migame_set_enable). Exported so
 * milletd-adjacent drivers can toggle without sysfs/proc. Default 0. */
int sew_migame_get_enable(void);
int sew_migame_set_enable(int en);
/* Slot-30 placement-ready predicate (L1-FINALIZE K1 fix): false until the
 * scheduler-side wrapper call sites for the placement face land (fair.c
 * surgery, K10 T1 / K11 #6c). Declared here so the slot-30 provider use
 * stays single-source; remote consumers must go through plat_migt_enable()
 * (plat_common slot 30), never this symbol directly. */
bool sew_migame_placement_ready(void);

/* ---- frame_boost gate (backed by the official frame_boost_enable
 * module_param in mi_game_ca.c; consumed by flt_cal_freq in flt.c) ----
 * True when userspace has armed frame-boost. Both switches (master
 * enable + frame_boost) must be on for the FLT frequency engine to
 * emit a target; this keeps enable=1 alone from pinning frequencies
 * on untuned threshold tables. */
bool sew_migame_frame_boost_allowed(void);

/* ---- mi_dflt latency-enable stub (C5 §1.3: recommended always-on stub,
 * single call site, pure gate semantics; module_param flt_dflt_bypass
 * leaves the back door). STAGE4 may rewire to sched_uclamp_used if real
 * device behaviour disagrees. */
bool mi_dflt_get_latency_enable(void);

/* ---- vip arbitration snapshot helpers (STAGE4 policy, stage-1 shape) ----
 * Rule (C5 §4.1): snapshot get_vip_prio() before set_vip_flag(); only
 * restore when the current value still equals ours (last-writer-wins,
 * never clears a value owned by xr_qs or a later writer). */
struct task_struct;
int sew_migame_vip_snapshot(struct task_struct *p);
bool sew_migame_vip_own(struct task_struct *p, int snapshot);

/* ---- stage-3 PELT bridge (mi_game_pelt.c) ----
 * WALT->PELT mapping; DIVERGENCE D1/D2 documented at the file top. */
unsigned long sew_migame_pelt_task_demand(struct task_struct *p);
unsigned long sew_migame_pelt_cpu_util(int cpu);
unsigned int sew_migame_pelt_window_ms(void);
u64 sew_migame_pelt_now(void);
unsigned long sew_migame_cpu_capacity(unsigned int cpu);

/* ---- stage-3 FLT engine (flt.c) ---- */
int sew_migame_flt_init(void);
void sew_migame_flt_exit(void);
/* Frame boundaries: ring buffer of 8 {start,end,duration} entries. */
void flt_frame_begin(u64 ts);
void flt_frame_end(u64 ts);
/* Core computation (DIVERGENCE D3): frame-average scaling. */
unsigned long flt_cal_freq(unsigned int base_khz_hint);
/* uclamp apply + restore (D6 snapshot discipline, DIVERGENCE D4). */
int sew_flt_uclamp_apply(struct task_struct *p, unsigned int min,
		     unsigned int max);
void sew_flt_uclamp_restore(struct task_struct *p);
/* SF/GPU/fence inputs: registerable callbacks + feed entry points. */
typedef void (*sew_flt_sf_cb_t)(u64 a, u64 b);
typedef void (*sew_flt_gpu_cb_t)(unsigned long load);
typedef void (*sew_flt_fence_cb_t)(void);
int sew_flt_register_sf_cb(sew_flt_sf_cb_t cb);
int sew_flt_register_gpu_cb(sew_flt_gpu_cb_t cb);
int sew_flt_register_fence_cb(sew_flt_fence_cb_t cb);
void sew_migame_flt_input_sf(u64 a, u64 b);
void sew_migame_flt_input_gpu(unsigned long load);
void sew_migame_flt_input_fence(void);

#endif /* __MI_GAME_H__ */
