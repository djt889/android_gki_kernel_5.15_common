// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_sig: signal-sniffer sensor (type=1) for the millet frozen
 * control subsystem, ported from millet_sig.ko (dada OS4).
 *
 * Binary behavior (disasm .text):
 * - millet_sig(sig, killer, dst) [tracepoint probe]: if sig > 15
 *   reject; else if ((1 << sig) & 0x8248) build a 176-byte report and
 *   call millet_sendmsg(1, ...). Probe signature matches
 *   DECLARE_HOOK(android_vh_do_send_sig_info,
 *   TP_PROTO(int sig, struct task_struct *killer, struct task_struct
 *   *dst)) in-tree (signal.h:12, fired signal.c:1301).
 * - signals_sendmsg(data, len-value, slot_base): drops NULL
 *   data/base ("input invalid"); parses the uplink report (sig at
 *   word[0], killer/dst task pointers embedded by the probe); reads dst
 *   uid via task_uid(); passes the freezing_slow_path gate, a
 *   system-freeze-counter gate (freezer_active on 6.6 ->
 *   millet_freeze_active() on 5.15), and a per-task "already handled
 *   uid" filter; then calls millet_sendto_user(1, 2, ...).
 *   (F1: the old port misread the args as (dst, frame, killer) which
 *   faulted; the binary passes (report, len-value, slot_base).)
 * - signas_init_millet: fills slot words (type 1, stride 120).
 * - init_module: printk "enter sig_mod_init func!",
 *   register_millet_hook(1, recv=NULL, send=signals_sendmsg),
 *   init_millet_subsystem(1, "SIG"),
 *   tracepoint_probe_register(__tracepoint_android_vh_do_send_sig_info,
 *   millet_sig, NULL).
 * - Exports millet_sig (ksymtab_gpl, matching official UND surface).
 *
 * 5.15 closures: freezer_active does not exist -> millet_freeze_active()
 * (atomic_read(&system_freezing_cnt)); tracepoint_probe_register is
 * EXPORT_SYMBOL_GPL (tracepoint.c:535).
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <trace/hooks/signal.h>

extern int register_millet_hook(unsigned int type, void *recv, void *send);
extern int unregister_millet_hook(unsigned int type);
extern void init_millet_subsystem(unsigned int tier, const char *name);
extern int millet_sendmsg(unsigned int tier, const void *data, unsigned int len);
extern int millet_sendto_user(unsigned int tier, unsigned int cmd,
			      const void *data, unsigned int len);
extern bool millet_freeze_active(void);
extern unsigned int millet_debug;

/* Crash/kill-class signal mask from the binary: bits 3/6/11/15. */
#define SEW_MILLET_SIG_MASK	0x8248U

/*
 * Per-task "already handled" record: the binary keeps a last_report
 * pointer + uid word (BSS) and suppresses a repeat report for the same
 * task/uid pair. A tiny exact-match cache (no eviction subtleties:
 * slots are overwritten round-robin) preserves the dedup behavior
 * without unbounded growth.
 *
 * F1 minor fix: store pid (pid_nr), NOT the bare task_struct pointer.
 * The old code kept tsk without a reference: after the task exits and
 * its struct is freed, the slot holds a dangling pointer (a later
 * reuse of the same address with the same uid would false-hit the
 * dedup; worse, any future deref would be UAF). pids are stable
 * values, safe to compare without lifetime. task_pid_nr() is called
 * on the live task at report time, so no rcu pinning is needed for
 * the stored value.
 */
#define SEW_MILLET_SIG_CACHE_NR	8

struct sew_millet_sig_seen {
	pid_t			pid;
	u32			uid;
};

static struct sew_millet_sig_seen sew_millet_sig_cache[SEW_MILLET_SIG_CACHE_NR];
static unsigned int sew_millet_sig_cache_pos;
static DEFINE_SPINLOCK(sew_millet_sig_cache_lock);

static bool sew_millet_sig_already_handled(struct task_struct *tsk, u32 uid)
{
	pid_t pid = task_pid_nr(tsk);
	int i;
	bool hit = false;
	unsigned long flags;

	spin_lock_irqsave(&sew_millet_sig_cache_lock, flags);
	for (i = 0; i < SEW_MILLET_SIG_CACHE_NR; i++) {
		if (sew_millet_sig_cache[i].pid == pid &&
		    sew_millet_sig_cache[i].uid == uid) {
			hit = true;
			break;
		}
	}
	if (!hit) {
		sew_millet_sig_cache[sew_millet_sig_cache_pos].pid = pid;
		sew_millet_sig_cache[sew_millet_sig_cache_pos].uid = uid;
		sew_millet_sig_cache_pos =
			(sew_millet_sig_cache_pos + 1) % SEW_MILLET_SIG_CACHE_NR;
	}
	spin_unlock_irqrestore(&sew_millet_sig_cache_lock, flags);
	return hit;
}

/* Report layout delivered via millet_sendto_user(1, 2, ...). */
struct sew_millet_sig_report {
	u32	sig;
	u32	killer_pid;
	u32	dst_pid;
	u32	dst_uid;
};

/*
 * Uplink payload built by millet_sig() and consumed by
 * sew_millet_sig_sendmsg() via arg1. Offsets are part of the INTERNAL
 * (core<->sensor) ABI: sig at word[0], killer/dst task pointers where
 * the binary's probe stores them. offsetof() guards in the send half
 * pin the layout; reorder only with the send half updated in lockstep.
 */
struct sew_millet_sig_uplink {
	u32			sig;
	u32			pad;
	u64			active;
	u32			killer_uid;
	u32			_pad1;
	struct task_struct	*killer;
	struct task_struct	*dst;
	u8			tail[128];
};

/*
 * signals_sendmsg(data, len, slot_base): send half of the type-1 slot.
 * Port-internal convention (see core; F1 corrected the pre-F1 misread
 * of (dst-task, writable-frame, killer-task), which faulted by
 * deref'ing the report as a task via __task_cred and running
 * freezing_slow_path(tsk=(void *)len)):
 *	arg1 = uplink payload: the signal report built by millet_sig()
 *	       (u32 sig at word[0]; killer task pointer + dst task pointer
 *	       embedded by the probe),
 *	arg2 = payload length VALUE cast through void *,
 *	arg3 = slot-array base (unused here, NULL-checked for parity).
 * Returns 0 on delivered, -1 on invalid input (matches the binary's
 * "signals_sendmsg: %s input invalid" path and its -1 returns).
 * Callable from probe context: GFP_ATOMIC, no sleeping locks (uses the
 * cache spinlock only).
 */
static int sew_millet_sig_sendmsg(void *arg1, void *arg2, void *arg3)
{
	const u32 *rep = arg1;
	unsigned long len = (unsigned long)arg2;
	struct task_struct *dst;
	struct task_struct *tsk;
	struct sew_millet_sig_report local;
	u32 uid;
	u32 sig;

	if (!arg1 || !arg3) {
		pr_info("millet-sig: signals_sendmsg: %s input invalid\n",
			__func__);
		return -1;
	}
	/* F1-D1R5: the probe always passes the full 176B report; refuse
	 * anything that cannot hold sig + both task pointers. */
	if (len < offsetof(struct sew_millet_sig_uplink, dst) + sizeof(void *)) {
		pr_info("millet-sig: signals_sendmsg: %s short payload %lu\n",
			__func__, len);
		return -1;
	}

	sig = rep[0];
	dst = ((struct sew_millet_sig_uplink *)rep)->dst;
	tsk = ((struct sew_millet_sig_uplink *)rep)->killer;
	if (!dst || !tsk) {
		pr_info("millet-sig: signals_sendmsg: %s input invalid\n",
			__func__);
		return -1;
	}

	/* dst uid via task_uid() (RCU-safe accessor; no reference is taken
	 * and none is needed: the pointer is used only inside this call,
	 * issued synchronously by the probe while both tasks are alive.
	 * F1-D1R6: the old comment claimed an "rcu-guarded" __task_cred
	 * deref with lifetime protection, but no get_task_struct was ever
	 * taken; task_uid() states the true guarantee honestly.) */
	uid = from_kuid_munged(&init_user_ns, task_uid(dst));

	/*
	 * Gate order mirrors the binary: freezing_slow_path on the
	 * *killer* task first, then the system-freeze counter, then the
	 * already-handled filter.
	 */
	if (!freezing_slow_path(tsk))
		return -1;
	if (!millet_freeze_active())
		return -1;
	if (sew_millet_sig_already_handled(dst, uid))
		return 0;

	local.sig = sig;
	local.killer_pid = task_pid_nr(tsk);
	local.dst_pid = task_pid_nr(dst);
	local.dst_uid = uid;

	return millet_sendto_user(1, 2, &local, sizeof(local));
}

/*
 * Tracepoint probe for android_vh_do_send_sig_info. Fires in sender
 * context (do_send_sig_info, sighand lock held by the caller after
 * the trace): only issue the non-sleeping millet_sendmsg report path
 * (GFP_ATOMIC + spinlocks). Matches the binary's filter
 * ((1U << sig) & 0x8248) and its millet_sendmsg(1, ...) call.
 */
void millet_sig(int sig, struct task_struct *killer, struct task_struct *dst)
{
	struct sew_millet_sig_uplink report;

	BUILD_BUG_ON(offsetof(struct sew_millet_sig_uplink, sig) != 0);
	BUILD_BUG_ON(offsetof(struct sew_millet_sig_uplink, killer) != 24);
	BUILD_BUG_ON(offsetof(struct sew_millet_sig_uplink, dst) != 32);
	BUILD_BUG_ON(sizeof(report) != 168);

	if (!killer || !dst || sig < 0 || sig > 15)
		return;
	if (!((1U << sig) & SEW_MILLET_SIG_MASK))
		return;

	memset(&report, 0, sizeof(report));
	report.sig = (u32)sig;
	report.active = millet_freeze_active() ? 1ULL : 0ULL;
	report.killer_uid = from_kuid_munged(&init_user_ns,
					     task_uid(killer));
	report.killer = killer;
	report.dst = dst;

	millet_sendmsg(1, &report, sizeof(report));
}
EXPORT_SYMBOL_GPL(millet_sig);

int __init sew_millet_sig_init(void)
{
	int ret;

	pr_info("millet-sig: enter sig_mod_init func!\n");

	ret = register_millet_hook(1, NULL, sew_millet_sig_sendmsg);
	if (ret) {
		pr_info("millet-sig: register hook failed\n");
		return ret;
	}
	init_millet_subsystem(1, "SIG");

	ret = tracepoint_probe_register(
		&__tracepoint_android_vh_do_send_sig_info,
		millet_sig, NULL);
	if (ret) {
		pr_info("millet-sig: probe register failed %d\n", ret);
		unregister_millet_hook(1);
		return ret;
	}
	return 0;
}

void __exit sew_millet_sig_exit(void)
{
	tracepoint_probe_unregister(
		&__tracepoint_android_vh_do_send_sig_info,
		millet_sig, NULL);
	tracepoint_synchronize_unregister();
	unregister_millet_hook(1);
}

