// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_core: "Millet smart frozen control subsystem" port from Xiaomi
 * dada OS4 (millet_core.ko 123KB, intree, depends empty).
 *
 * RE evidence: /root/work/os4_dada/ko/millet_core.ko (vermagic
 * 6.6.57-android15). Raw: .omz/research/.../raw/re-millet.txt (4522
 * lines of modinfo/nm/strings/objdump evidence + the follow-up netlink
 * protocol breakthrough: unit=31, recv_handler message layout).
 *
 * What the OS4 module does
 * ------------------------
 * Six tier slots (args 1..6, 120 bytes each + 32B name, init_millet_
 * subsystem zeroes [x9,#0x10/0x14/0x30] and copies the tier name ≤31B).
 * Two uid hash tables (core_uid_* 7 ops, uid_rec_* 7 ops, blacklist via
 * core_black_uid_rec). Netlink kernel server unit=31 (NETLINK private
 * range; init_module: net=x0(init_net), unit w1=0x1f, cfg=w2/w3 48B
 * rodata template = struct netlink_kernel_cfg, input=recv_handler).
 * recv_handler message format (disasm-proven): nlmsg payload [0x18]=u64
 * 0xabcd_dcba magic, [0x20]=u64 0x1234_1234 magic, [0x10]=tier 1..6,
 * [0x14]=cmd 1/3. /proc/millet/{stat(rw),sock(ro),version(ro)} via
 * millet_proc_fops + millet_stat_write/open + millet_version_show.
 * Five module params: millet_binder_switch(bool),
 * millet_freeze_switch(int), binder_warn_ahead_space(ulong),
 * frozen_uid_min(uint), millet_debug(uint).
 * judge_millet_freeze_switch: returns (switch==1).
 *
 * 5.15 closures (all verified in-tree)
 * ------------------------------------
 * - system_cpucaps (6.6 cpuset-era symbol): no 5.15 equivalent in the
 *   paths core touches -> not referenced (rtg.c precedent).
 * - alt_cb_patch_nops: 6.6 arm64 alternative glue, absorbed by the
 *   native copy primitives (rtg.c precedent).
 * - freezer_active (6.6 kernel/freezer.c static key): does not exist on
 *   5.15. Replaced by an internal atomic gating variable
 *   (sew_millet_active) driven by millet_freeze_switch != 0 - the
 *   observable behavior (freeze subsystem on/off) is preserved.
 *
 * PORT-DELTA list
 * ---------------
 * - Netlink unit kept at 31 (same number dada uses) so a vendor
 *   userspace daemon speaking the OS4 protocol keeps working.  If the
 *   vendor daemon is dead (GKI vermagic mismatch may block vendor ko
 *   loading), the addon-side daemon (see outputs/) is the peer.
 * - judge_millet_freeze_switch semantics kept: 1 => freeze path on.
 * - The six sibling modules (binder/hs/oem_cgroup/pkg/sig) are NOT
 *   ported here: millet_binder hard-depends on binder_gki exports
 *   (oem_register_binder_hook, query_binder_app_stat) that do not
 *   exist in 5.15 GKI's built-in binder.  Its binder_freeze logic is
 *   instead re-implemented inside this file on the public
 *   android_vh_binder_preset/transaction hooks with the in-tree
 *   frozen() predicate (see sew_millet_binder_* below).
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/freezer.h>
#include <net/sock.h>
#include <trace/hooks/binder.h>
/* full binder_transaction / binder_proc for the txn observer */
#include "../../android/binder_internal.h"

/* ---- module params (dada names kept) --------------------------------- */
static bool millet_binder_switch = true;
module_param(millet_binder_switch, bool, 0644);
MODULE_PARM_DESC(millet_binder_switch, "enable binder freeze preemption path");

static int millet_freeze_switch;
module_param(millet_freeze_switch, int, 0644);
MODULE_PARM_DESC(millet_freeze_switch, "freeze subsystem on (1) / off");

static unsigned long binder_warn_ahead_space = 4096;
module_param(binder_warn_ahead_space, ulong, 0644);
MODULE_PARM_DESC(binder_warn_ahead_space, "binder warn-ahead space (KB)");

static unsigned int frozen_uid_min = 10000;
module_param(frozen_uid_min, uint, 0644);
MODULE_PARM_DESC(frozen_uid_min, "uids below this are never frozen");

static unsigned int millet_debug;
module_param(millet_debug, uint, 0644);
MODULE_PARM_DESC(millet_debug, "debug verbosity");

/* ---- netlink protocol (dada numbers kept) ----------------------------- */
#define MILLET_NETLINK_UNIT	31
#define MILLET_MSG_MAGIC0	0xabcddcbaULL
#define MILLET_MSG_MAGIC1	0x12341234ULL
#define MILLET_TIER_MIN		1
#define MILLET_TIER_MAX		6
#define MILLET_TIER_SIZE	120
#define MILLET_TIER_NAME_LEN	32

static struct sock *millet_nl_sk;
/* last userspace peer seen by recv_handler (milletd).  The original
 * binary hard-codes a unicast target; record the real sender instead
 * so replies reach the daemon that registered (audit P1). */
static u32 millet_peer_portid;
static DEFINE_SPINLOCK(millet_peer_lock);
static kuid_t millet_peer_uid;
static unsigned int millet_peer_changes;
static atomic64_t millet_drop_spoof;
static atomic64_t millet_drop_noreg;
static atomic64_t millet_send_err;

/* ---- tier slots (args 1..6, 120B + 32B name) --------------------------- */
struct millet_tier {
	u8	data[MILLET_TIER_SIZE];
	char	name[MILLET_TIER_NAME_LEN];
};

static struct millet_tier millet_tiers[MILLET_TIER_MAX];
static DEFINE_MUTEX(millet_tier_lock);

/* ---- uid hash tables (core_uid_* + uid_rec_*, dada op surface) --------- */
#define MILLET_UID_BUCKETS	64

struct millet_uid_rec {
	struct hlist_node	node;
	kuid_t			uid;
	unsigned long		flags;
};

static struct hlist_head millet_core_uid_hash[MILLET_UID_BUCKETS];
static struct hlist_head millet_uid_rec_hash[MILLET_UID_BUCKETS];
static DEFINE_SPINLOCK(millet_uid_lock);

static unsigned int millet_uid_bucket(kuid_t uid)
{
	return from_kuid_munged(&init_user_ns, uid) % MILLET_UID_BUCKETS;
}

int core_uid_hash_add(kuid_t uid, unsigned long flags)
{
	struct millet_uid_rec *rec;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry(rec, &millet_core_uid_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			rec->flags = flags;
			spin_unlock_irqrestore(&millet_uid_lock, irqflags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (!rec)
		return -ENOMEM;
	rec->uid = uid;
	rec->flags = flags;
	spin_lock_irqsave(&millet_uid_lock, irqflags);
	{
		struct millet_uid_rec *e;

		/* re-check: a concurrent writer may have inserted first. */
		hlist_for_each_entry(e, &millet_core_uid_hash[bkt], node) {
			if (uid_eq(e->uid, uid)) {
				e->flags = flags;
				spin_unlock_irqrestore(&millet_uid_lock, irqflags);
				kfree(rec);
				return 0;
			}
		}
		hlist_add_head(&rec->node, &millet_core_uid_hash[bkt]);
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return 0;
}
EXPORT_SYMBOL_GPL(core_uid_hash_add);

int core_uid_hash_del(kuid_t uid)
{
	struct millet_uid_rec *rec;
	struct hlist_node *tmp;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;
	int ret = -ENOENT;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry_safe(rec, tmp, &millet_core_uid_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			hlist_del(&rec->node);
			kfree(rec);
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return ret;
}
EXPORT_SYMBOL_GPL(core_uid_hash_del);

bool core_uid_hash_find(kuid_t uid)
{
	struct millet_uid_rec *rec;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;
	bool found = false;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry(rec, &millet_core_uid_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return found;
}
EXPORT_SYMBOL_GPL(core_uid_hash_find);

int core_uid_hash_show(struct seq_file *m, void *v)
{
	/* seq_printf may sleep (seq buffer grow): snapshot under the
	 * lock, print after unlock (audit P1). */
#define MILLET_SHOW_MAX 128
	struct { u32 uid; unsigned long flags; } snap[MILLET_SHOW_MAX];
	struct millet_uid_rec *rec;
	unsigned long irqflags;
	int i, n = 0;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	for (i = 0; i < MILLET_UID_BUCKETS && n < MILLET_SHOW_MAX; i++) {
		hlist_for_each_entry(rec, &millet_core_uid_hash[i], node) {
			if (n >= MILLET_SHOW_MAX)
				break;
			snap[n].uid = from_kuid_munged(&init_user_ns, rec->uid);
			snap[n].flags = rec->flags;
			n++;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	for (i = 0; i < n; i++)
		seq_printf(m, "uid: %u flags: %lu\n", snap[i].uid, snap[i].flags);
	return 0;
#undef MILLET_SHOW_MAX
}
EXPORT_SYMBOL_GPL(core_uid_hash_show);

static void core_uid_hash_clear(void)
{
	struct millet_uid_rec *rec;
	struct hlist_node *tmp;
	unsigned long irqflags;
	int i;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	for (i = 0; i < MILLET_UID_BUCKETS; i++) {
		hlist_for_each_entry_safe(rec, tmp,
					  &millet_core_uid_hash[i], node) {
			hlist_del(&rec->node);
			kfree(rec);
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
}

int uid_rec_hash_add(kuid_t uid, unsigned long flags)
{
	struct millet_uid_rec *rec;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry(rec, &millet_uid_rec_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			rec->flags = flags;
			spin_unlock_irqrestore(&millet_uid_lock, irqflags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (!rec)
		return -ENOMEM;
	rec->uid = uid;
	rec->flags = flags;
	spin_lock_irqsave(&millet_uid_lock, irqflags);
	{
		struct millet_uid_rec *e;

		hlist_for_each_entry(e, &millet_uid_rec_hash[bkt], node) {
			if (uid_eq(e->uid, uid)) {
				e->flags = flags;
				spin_unlock_irqrestore(&millet_uid_lock, irqflags);
				kfree(rec);
				return 0;
			}
		}
		hlist_add_head(&rec->node, &millet_uid_rec_hash[bkt]);
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return 0;
}
EXPORT_SYMBOL_GPL(uid_rec_hash_add);

int uid_rec_hash_del(kuid_t uid)
{
	struct millet_uid_rec *rec;
	struct hlist_node *tmp;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;
	int ret = -ENOENT;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry_safe(rec, tmp, &millet_uid_rec_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			hlist_del(&rec->node);
			kfree(rec);
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return ret;
}
EXPORT_SYMBOL_GPL(uid_rec_hash_del);

bool uid_rec_hash_find(kuid_t uid)
{
	struct millet_uid_rec *rec;
	unsigned int bkt = millet_uid_bucket(uid);
	unsigned long irqflags;
	bool found = false;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	hlist_for_each_entry(rec, &millet_uid_rec_hash[bkt], node) {
		if (uid_eq(rec->uid, uid)) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	return found;
}
EXPORT_SYMBOL_GPL(uid_rec_hash_find);

int uid_rec_hash_show(struct seq_file *m, void *v)
{
	/* same snapshot discipline as core_uid_hash_show (audit P1). */
#define MILLET_SHOW_MAX 128
	struct { u32 uid; unsigned long flags; } snap[MILLET_SHOW_MAX];
	struct millet_uid_rec *rec;
	unsigned long irqflags;
	int i, n = 0;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	for (i = 0; i < MILLET_UID_BUCKETS && n < MILLET_SHOW_MAX; i++) {
		hlist_for_each_entry(rec, &millet_uid_rec_hash[i], node) {
			if (n >= MILLET_SHOW_MAX)
				break;
			snap[n].uid = from_kuid_munged(&init_user_ns, rec->uid);
			snap[n].flags = rec->flags;
			n++;
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
	for (i = 0; i < n; i++)
		seq_printf(m, "uid: %u flags: %lu\n", snap[i].uid, snap[i].flags);
	return 0;
#undef MILLET_SHOW_MAX
}
EXPORT_SYMBOL_GPL(uid_rec_hash_show);

static void uid_rec_hash_clear(void)
{
	struct millet_uid_rec *rec;
	struct hlist_node *tmp;
	unsigned long irqflags;
	int i;

	spin_lock_irqsave(&millet_uid_lock, irqflags);
	for (i = 0; i < MILLET_UID_BUCKETS; i++) {
		hlist_for_each_entry_safe(rec, tmp,
					  &millet_uid_rec_hash[i], node) {
			hlist_del(&rec->node);
			kfree(rec);
		}
	}
	spin_unlock_irqrestore(&millet_uid_lock, irqflags);
}

/* ---- freeze decision --------------------------------------------------- */
bool judge_millet_freeze_switch(void)
{
	return millet_freeze_switch == 1;
}
EXPORT_SYMBOL_GPL(judge_millet_freeze_switch);

static bool __maybe_unused sew_millet_uid_frozen_ok(kuid_t uid)
{
	if (from_kuid_munged(&init_user_ns, uid) < frozen_uid_min)
		return false;
	return !core_uid_hash_find(uid);
}

/* ---- netlink server (unit 31, recv_handler message layout) ------------- */
struct millet_nl_msg {
	__u64	magic0;
	__u64	magic1;
	__u32	tier;
	__u32	cmd;
	__u8	data[0];
};

static void millet_recv_handler(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct millet_nl_msg *msg;
	unsigned int tier;

	if (!skb)
		return;
	/* netlink cb delivers a full datagram, but a truncated/foreign
	 * sender must not drive nlmsg_data past the skb (audit P1). */
	nlh = nlmsg_hdr(skb);
	if (!nlmsg_ok(nlh, skb->len) || nlmsg_len(nlh) < sizeof(*msg))
		return;
	msg = nlmsg_data(nlh);
	if (msg->magic0 != MILLET_MSG_MAGIC0 ||
	    msg->magic1 != MILLET_MSG_MAGIC1)
		return;
	if (msg->tier < MILLET_TIER_MIN || msg->tier > MILLET_TIER_MAX)
		return;
	tier = msg->tier;
	/* Only root or system may register as the reply peer; other
	 * senders are dropped and counted. */
	{
		kuid_t uid = NETLINK_CREDS(skb)->uid;
		unsigned long irqflags;
		u32 portid = NETLINK_CB(skb).portid;

		if (!uid_eq(uid, GLOBAL_ROOT_UID) &&
		    from_kuid_munged(&init_user_ns, uid) != 1000) {
			atomic64_inc(&millet_drop_spoof);
			return;
		}
		spin_lock_irqsave(&millet_peer_lock, irqflags);
		if (millet_peer_portid != portid) {
			millet_peer_portid = portid;
			millet_peer_uid = uid;
			millet_peer_changes++;
			if (millet_debug)
				pr_info("millet-core: peer %u changes %u\n",
					millet_peer_portid,
					millet_peer_changes);
		}
		spin_unlock_irqrestore(&millet_peer_lock, irqflags);
	}

	mutex_lock(&millet_tier_lock);
	if (tier <= MILLET_TIER_MAX) {
		/* RE only confirms the tier/cmd field values; the
		 * histogram bump is a porting inference. */
		if (msg->cmd < MILLET_TIER_SIZE)
			millet_tiers[tier - 1].data[msg->cmd]++;
	}
	if (millet_debug)
		pr_info("millet-core: tier %u cmd %u\n", tier, msg->cmd);
	mutex_unlock(&millet_tier_lock);
}

int millet_sendmsg(unsigned int tier, const void *data, unsigned int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct millet_nl_msg *msg;
	unsigned int size = NLMSG_SPACE(sizeof(*msg) + len);
	unsigned long irqflags;
	u32 peer;
	int ret;

	if (tier < MILLET_TIER_MIN || tier > MILLET_TIER_MAX)
		return -EINVAL;
	if (!millet_nl_sk)
		return -ENODEV;

	spin_lock_irqsave(&millet_peer_lock, irqflags);
	peer = millet_peer_portid;
	spin_unlock_irqrestore(&millet_peer_lock, irqflags);
	if (!peer) {
		atomic64_inc(&millet_drop_noreg);
		return -ENOTCONN;
	}

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	nlh = nlmsg_put(skb, 0, 0, 0, sizeof(*msg) + len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	msg = nlmsg_data(nlh);
	msg->magic0 = MILLET_MSG_MAGIC0;
	msg->magic1 = MILLET_MSG_MAGIC1;
	msg->tier = tier;
	msg->cmd = 0;
	if (data && len)
		memcpy(msg->data, data, len);
	ret = netlink_unicast(millet_nl_sk, skb, peer, MSG_DONTWAIT);
	if (ret < 0) {
		atomic64_inc(&millet_send_err);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(millet_sendmsg);

int millet_sendto_user(unsigned int tier, unsigned int cmd,
		       const void *data, unsigned int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct millet_nl_msg *msg;
	unsigned int size = NLMSG_SPACE(sizeof(*msg) + len);
	unsigned long irqflags;
	u32 peer;
	int ret;

	if (tier < MILLET_TIER_MIN || tier > MILLET_TIER_MAX)
		return -EINVAL;
	if (!millet_nl_sk)
		return -ENODEV;

	spin_lock_irqsave(&millet_peer_lock, irqflags);
	peer = millet_peer_portid;
	spin_unlock_irqrestore(&millet_peer_lock, irqflags);
	if (!peer) {
		atomic64_inc(&millet_drop_noreg);
		return -ENOTCONN;
	}

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	nlh = nlmsg_put(skb, 0, 0, 0, sizeof(*msg) + len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	msg = nlmsg_data(nlh);
	msg->magic0 = MILLET_MSG_MAGIC0;
	msg->magic1 = MILLET_MSG_MAGIC1;
	msg->tier = tier;
	msg->cmd = cmd;
	if (data && len)
		memcpy(msg->data, data, len);
	ret = netlink_unicast(millet_nl_sk, skb, peer, MSG_DONTWAIT);
	if (ret < 0) {
		atomic64_inc(&millet_send_err);
		return ret;
	}
	return 0;
}

/* ---- binder freeze preemption (millet_binder logic, public hooks) ------ */
/*
 * millet_binder.ko cannot be ported as-is: it consumes binder_gki
 * exports (oem_register_binder_hook, query_binder_app_stat) that do not
 * exist in 5.15 GKI's built-in binder, and 5.15 has no freezer_active
 * static key.  Its observable behavior - transactions aimed at frozen
 * targets are detected and warned - is re-implemented here on the
 * public android_vh_binder_preset hook with the in-tree frozen()
 * predicate.  Warn-ahead accounting uses binder_warn_ahead_space.
 */
static atomic64_t sew_millet_binder_frozen_hits;
static atomic64_t sew_millet_binder_total;

/*
 * Re-implementation target: the binary logs "binder_trans_hook dst=%d
 * srcpid=%d" and warns on "no is_frozen" - transactions aimed at frozen
 * targets.  android_vh_binder_proc_transaction_finish fires after the
 * inner proc lock is dropped (binder.c:3050 unlock, 3055 trace) with
 * the resolved binder thread, so frozen() + printk are safe here.
 */
static void sew_millet_binder_txn_finish(void *data,
					 struct binder_proc *proc,
					 struct binder_transaction *t,
					 struct task_struct *binder_th_task,
					 bool pending_async, bool sync)
{
	struct task_struct *target;

	if (!millet_binder_switch || !judge_millet_freeze_switch())
		return;
	if (!t || !t->to_proc)
		return;
	target = binder_th_task ? binder_th_task : current;
	atomic64_inc(&sew_millet_binder_total);
	if (frozen(target)) {
		atomic64_inc(&sew_millet_binder_frozen_hits);
		if (millet_debug)
			pr_info("millet-binder: binder_trans_hook to frozen pid=%d\n",
				task_pid_nr(target));
	}
}

/* ---- /proc/millet ------------------------------------------------------ */
static int millet_stat_show(struct seq_file *m, void *v)
{
	seq_printf(m, "freeze_switch: %d\nbinder_switch: %d\n",
		   millet_freeze_switch, millet_binder_switch);
	seq_printf(m, "frozen_uid_min: %u\nwarn_ahead_space: %lu\n",
		   frozen_uid_min, binder_warn_ahead_space);
	seq_printf(m, "binder_total: %lld\nbinder_frozen: %lld\n",
		   atomic64_read(&sew_millet_binder_total),
		   atomic64_read(&sew_millet_binder_frozen_hits));
	return core_uid_hash_show(m, v);
}

static int millet_stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, millet_stat_show, NULL);
}

static const struct proc_ops millet_stat_fops = {
	.proc_open	= millet_stat_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int millet_sock_show(struct seq_file *m, void *v)
{
	unsigned long irqflags;
	u32 peer;
	unsigned int changes;

	spin_lock_irqsave(&millet_peer_lock, irqflags);
	peer = millet_peer_portid;
	changes = millet_peer_changes;
	spin_unlock_irqrestore(&millet_peer_lock, irqflags);

	seq_printf(m, "netlink_unit: %d\nbound: %d\n",
		   MILLET_NETLINK_UNIT, millet_nl_sk ? 1 : 0);
	seq_printf(m, "peer_portid: %u\npeer_changes: %u\n",
		   peer, changes);
	seq_printf(m, "drop_noreg: %lld\nsend_err: %lld\ndrop_spoof: %lld\n",
		   atomic64_read(&millet_drop_noreg),
		   atomic64_read(&millet_send_err),
		   atomic64_read(&millet_drop_spoof));
	return 0;
}

static int millet_sock_open(struct inode *inode, struct file *file)
{
	return single_open(file, millet_sock_show, NULL);
}

static const struct proc_ops millet_sock_fops = {
	.proc_open	= millet_sock_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int millet_version_show(struct seq_file *m, void *v)
{
	seq_puts(m, "millet-core sew-5.15 port (OS4 tier protocol)\n");
	return 0;
}

static int millet_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, millet_version_show, NULL);
}

static const struct proc_ops millet_version_fops = {
	.proc_open	= millet_version_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *millet_proc_dir;

/* ---- hook registration surface (sibling-module shape) ------------------ */
int register_millet_hook(void)
{
	return register_trace_android_vh_binder_proc_transaction_finish(
		sew_millet_binder_txn_finish, NULL);
}
EXPORT_SYMBOL_GPL(register_millet_hook);

int unregister_millet_hook(void)
{
	unregister_trace_android_vh_binder_proc_transaction_finish(
		sew_millet_binder_txn_finish, NULL);
	return 0;
}
EXPORT_SYMBOL_GPL(unregister_millet_hook);

/* ---- init / exit -------------------------------------------------------- */
static struct netlink_kernel_cfg millet_nl_cfg = {
	.input	= millet_recv_handler,
};

static void init_millet_subsystem(unsigned int tier, const char *name)
{
	if (tier < MILLET_TIER_MIN || tier > MILLET_TIER_MAX)
		return;

	mutex_lock(&millet_tier_lock);
	memset(&millet_tiers[tier - 1], 0, sizeof(millet_tiers[0]));
	if (name)
		strscpy(millet_tiers[tier - 1].name, name,
			MILLET_TIER_NAME_LEN);
	mutex_unlock(&millet_tier_lock);
}

static int __init millet_core_init(void)
{
	int i, ret = 0;

	for (i = 0; i < MILLET_UID_BUCKETS; i++) {
		INIT_HLIST_HEAD(&millet_core_uid_hash[i]);
		INIT_HLIST_HEAD(&millet_uid_rec_hash[i]);
	}
	for (i = MILLET_TIER_MIN; i <= MILLET_TIER_MAX; i++)
		init_millet_subsystem(i, NULL);

	millet_nl_sk = netlink_kernel_create(&init_net, MILLET_NETLINK_UNIT,
					     &millet_nl_cfg);
	if (!millet_nl_sk) {
		pr_err("millet-core: netlink unit %d create failed\n",
		       MILLET_NETLINK_UNIT);
		return -ENODEV;
	}

	millet_proc_dir = proc_mkdir("millet", NULL);
	if (!millet_proc_dir) {
		pr_err("millet-core: create /proc/millet failed\n");
		netlink_kernel_release(millet_nl_sk);
		millet_nl_sk = NULL;
		return -ENOMEM;
	}
	if (!proc_create("stat", 0644, millet_proc_dir, &millet_stat_fops) ||
	    !proc_create("sock", 0444, millet_proc_dir, &millet_sock_fops) ||
	    !proc_create("version", 0444, millet_proc_dir,
			 &millet_version_fops)) {
		pr_err("millet-core: proc nodes failed\n");
		remove_proc_entry("millet", NULL);
		millet_proc_dir = NULL;
		netlink_kernel_release(millet_nl_sk);
		millet_nl_sk = NULL;
		return -ENOMEM;
	}

	ret = register_millet_hook();
	if (ret)
		pr_info("millet-core: binder hook delayed (switch off? no)\n");

	pr_info("millet-core: enter millet_init func!\n");
	return 0;
}

static void __exit millet_core_exit(void)
{
	unregister_millet_hook();
	tracepoint_synchronize_unregister();
	remove_proc_entry("stat", millet_proc_dir);
	remove_proc_entry("sock", millet_proc_dir);
	remove_proc_entry("version", millet_proc_dir);
	remove_proc_entry("millet", NULL);
	millet_proc_dir = NULL;
	if (millet_nl_sk) {
		netlink_kernel_release(millet_nl_sk);
		millet_nl_sk = NULL;
	}
	core_uid_hash_clear();
	uid_rec_hash_clear();
}

module_init(millet_core_init);
module_exit(millet_core_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew port of the Xiaomi OS4 millet_core (smart frozen control subsystem)");
