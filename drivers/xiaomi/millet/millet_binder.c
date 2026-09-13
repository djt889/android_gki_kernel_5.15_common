// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_binder: binder observation sensor (types 2/3) for the millet
 * frozen control subsystem, ported from millet_binder.ko (dada OS4).
 *
 * The OS4 module consumes three binder_gki private exports --
 * oem_register_binder_hook (in-flight trans/wait4/overflow/reply/
 * query_stat hooks), query_binder_app_stat (per-app busy/idle/txn
 * counters) and reset_isfrozen (third-party unfreeze poke) -- plus
 * the 6.6 freezer_active static key and millet_pkg's
 * find_and_clear_piduid gate. None of the three binder_gki exports
 * exists in 5.15 GKI's built-in binder; reset_isfrozen has no
 * third-party-callable counterpart either (BINDER_FREEZE is a
 * self-directed ioctl), and this port performs no freezing, so no
 * substitute is attempted (see the DIVERGENCE NOTE block below).
 * What IS portable -- and what this file implements -- is the
 * observation surface on the public android_vh_binder_* hooks:
 *
 * - entry side (type 3, "binder send"): android_vh_binder_trans
 *   fires in binder_transaction() after the target node/proc has
 *   been resolved (target_proc valid, or NULL for malformed
 *   handles) and outside the inner proc spinlock. The callback
 *   reads the caller identity (proc->pid), the destination
 *   (target_proc->pid), and the oneway flag / code out of the
 *   user-supplied struct binder_transaction_data. This mirrors the
 *   OS4 module's "send" half (type 3).
 * - finish side (type 2, "binder receive"): the existing
 *   sew_millet_binder_txn_finish hook in millet_core.c, driven by
 *   android_vh_binder_proc_transaction_finish, counts completed
 *   transactions whose servicing thread is frozen. That hook is
 *   NOT duplicated here; this file owns only the entry side. See
 *   the de-dup note at the bottom of this header.
 * - is_frozen direct read: both sides consult state read straight
 *   off the target binder_proc / task_struct (is_frozen bit and the
 *   in-tree frozen() predicate). No reset_isfrozen poke, no state
 *   mutation: this observer only counts (never sets/clears), so the
 *   MIUI freeze service driving the same binder_proc.is_frozen bit
 *   cannot ping-pong with this path (C2 X2 already closed).
 * - simplified STAT: query_binder_app_stat has no public
 *   counterpart (per-app busy/idle/txn accounting lives inside the
 *   closed binder_gki). The port reports its own counters
 *   (total/frozen_hits per side) via /proc/millet/stat instead of a
 *   netlink BINDER_STAT dump. No netlink downlink is emitted by
 *   this file: the observation surface comes first, daemon-driven
 *   actions stay in the P3 userspace daemon.
 *
 * DIVERGENCE NOTE (private-dependency gap, P4 70% scope):
 * - oem_register_binder_hook: the private hook table gave the OS4
 *   module per-transaction wait4/overflow/reply/query_stat
 *   visibility mid-flight. No public vendor hook exposes the same
 *   points, so wait-queue depth, overflow events and reply-path
 *   latency are NOT observed here. Entry+finish counting covers
 *   the send/receive volume and frozen-target hits, which is the
 *   ~70% the feasibility study (B4) deemed portable.
 * - query_binder_app_stat: replaced by the four local counters
 *   (entry_total/entry_frozen here + the core finish counters);
 *   per-app busy/idle breakdown is unavailable.
 * - reset_isfrozen: not ported and not stubbed. Unfreeze is a
 *   daemon action (BINDER_FREEZE ioctl / cgroup.freeze write from
 *   userspace); a kernel observer must not clear another
 *   subsystem's freeze bit behind its back.
 * - find_and_clear_piduid gate: the OS4 send path consulted the
 *   pkg freeze table before tagging a transaction. The 5.15 pkg
 *   port exports that symbol, but this observer deliberately does
 *   not call it: the table is advisory allowlist state and the
 *   entry hook must stay lock-free (no hash spinlock may be taken
 *   on this path). Frozen targeting is decided purely from
 *   is_frozen reads.
 * - freezer_active (6.6 static key): does not exist on 5.15; no
 *   freeze-cycle gate is applied here (the core observer does not
 *   use one either -- both sides count whenever the two switches
 *   below allow it).
 *
 * Locking / context discipline:
 * - The entry callback runs inside binder_transaction(), i.e. in
 *   the ioctl syscall path of the SENDING thread (process context,
 *   no spinlock held -- the target outer lock is taken and released
 *   around ref resolution before the hook fires). It may still race
 *   with target teardown, so only plain-word fields of target_proc
 *   are read (pid, is_frozen) and NO reference is taken, NO task is
 *   dereferenced, NO netlink skb is allocated. All accounting is
 *   atomic64_inc (lock-free).
 * - millet_binder_switch is shared with millet_core.c (single bool,
 *   module param owned by core). The effective gate is
 *   millet_binder_switch && judge_millet_freeze_switch(): with the
 *   freeze master switch defaulting to 0 (off), the observer is
 *   silent until the daemon arms it, matching the freeze-switch
 *   discipline of the rest of the subsystem. millet_binder_switch
 *   itself keeps the OS4 default (true) so that flipping only the
 *   master switch enables the full observation surface at once.
 * - Hook register/unregister pairing: sew_millet_binder_init attaches
 *   exactly one tracepoint (android_vh_binder_trans);
 *   sew_millet_binder_exit detaches the same callback and issues
 *   tracepoint_synchronize_unregister() before returning, so no
 *   in-flight probe can touch this file's counters after exit.
 *   Registration failure in init propagates the error so core
 *   skips the SEW_MILLET_SUB_BINDER bit and exit does not detach what
 *   was never attached.
 *
 * De-dup note (vs core sew_millet_binder_txn_finish):
 * - Core owns the FINISH side (type 2 "binder receive"): counts a
 *   transaction once, when the target thread has been selected and
 *   the work is queued, keyed on frozen(target thread).
 * - This file owns the ENTRY side (type 3 "binder send"): counts a
 *   transaction once, at issue time, keyed on target_proc->is_frozen.
 * - A single transaction therefore increments at most one counter
 *   per side, and the two sides never share a counter. The stat
 *   lines keep the names apart (binder_total/binder_frozen for the
 *   finish side, binder_tx_total/binder_tx_frozen for the entry
 *   side) so a reader cannot mistake one side's volume for the
 *   other's.
 */

#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <trace/hooks/binder.h>
#include <uapi/linux/android/binder.h>
/* struct binder_proc / struct binder_thread / is_frozen */
#include "../../android/binder_internal.h"

extern bool millet_binder_switch;
extern bool judge_millet_freeze_switch(void);
extern unsigned int millet_debug;

/*
 * Entry-side (type 3) counters. The finish-side (type 2) counters
 * live in millet_core.c next to sew_millet_binder_txn_finish and are
 * printed by the same stat block (binder_total/binder_frozen); the
 * entry counters here extend that block with binder_tx_* lines.
 */
static atomic64_t sew_millet_binder_entry_total;
static atomic64_t sew_millet_binder_entry_frozen;

/*
 * Entry callback for android_vh_binder_trans. Prototype mirrors
 * TP_PROTO(struct binder_proc *target_proc, struct binder_proc *proc,
 * struct binder_thread *thread, struct binder_transaction_data *tr).
 * target_proc may be NULL (malformed handle path resolves no target);
 * tr is the ioctl-supplied descriptor (code/flags readable). Only
 * counting + is_frozen sampling: never sleeps, never allocates,
 * never takes a lock.
 */
static void sew_millet_binder_entry_cb(void *data,
				   struct binder_proc *target_proc,
				   struct binder_proc *proc,
				   struct binder_thread *thread,
				   struct binder_transaction_data *tr)
{
	bool oneway;
	u32 code;

	(void)data;
	(void)thread;
	if (!millet_binder_switch || !judge_millet_freeze_switch())
		return;
	if (!proc || !tr)
		return;

	atomic64_inc(&sew_millet_binder_entry_total);

	/*
	 * Sample frozen targeting straight off the resolved proc. A
	 * torn bool read here only misattributes one transaction; the
	 * field is written under the target inner lock and single-byte
	 * loads/stores are single-copy atomic on arm64.
	 */
	if (target_proc && target_proc->is_frozen)
		atomic64_inc(&sew_millet_binder_entry_frozen);

	if (!millet_debug)
		return;

	oneway = !!(tr->flags & TF_ONE_WAY);
	code = tr->code;
	pr_info("millet-binder: tx entry src=%d dst=%d code=%u %s\n",
		proc->pid, target_proc ? target_proc->pid : -1, code,
		oneway ? "oneway" : "sync");
}

/*
 * Stat helper called from millet_core.c's sew_millet_stat_show to append
 * the entry-side lines. Runs in procfs (process) context; plain
 * atomic64 reads, no locking.
 */
void sew_millet_binder_stat_show(struct seq_file *m)
{
	seq_printf(m, "binder_tx_total: %lld\nbinder_tx_frozen: %lld\n",
		   atomic64_read(&sew_millet_binder_entry_total),
		   atomic64_read(&sew_millet_binder_entry_frozen));
}

int __init sew_millet_binder_init(void)
{
	int ret;

	ret = register_trace_android_vh_binder_trans(sew_millet_binder_entry_cb,
						     NULL);
	if (ret) {
		pr_info("millet-binder: entry hook register failed %d\n",
			ret);
		return ret;
	}
	pr_info("millet-binder: entry observer attached (type 3)\n");
	return 0;
}

void __exit sew_millet_binder_exit(void)
{
	unregister_trace_android_vh_binder_trans(sew_millet_binder_entry_cb,
						 NULL);
	tracepoint_synchronize_unregister();
	pr_info("millet-binder: entry observer detached\n");
}
