// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_pkg: netfilter packet-sniffer sensor (type=5) for the millet
 * frozen control subsystem, ported from millet_pkg.ko (dada OS4).
 *
 * Binary behavior (disasm .text + .data + relocs):
 * - Four nf hooks (pkg_nf_ops, nf_register_net_hooks(init_net, ops, 4)):
 *   IPv4 LOCAL_IN (pf=2, hooknum=1) -> pkg_ip4_in; IPv6 LOCAL_IN
 *   (pf=10, hooknum=1) -> pkg_ip6_in; IPv4 LOCAL_OUT (pf=2,
 *   hooknum=3) -> pkg_ip4_out (accept stub); IPv6 LOCAL_OUT (pf=10,
 *   hooknum=3) -> pkg_ip6_out (accept stub).
 * - pkg_ip4_in: IPv4 protocol byte (skb->data[nh_off+9]) must be TCP(6);
 *   sock lookup -> sk_uid (sk+0x290 path) -> uid>>4 must exceed 0x271
 *   (i.e. app uids, skipping system); uid_rec_hash_find_and_clear(uid)
 *   must hit; then millet_sendmsg(5, uid-payload). Errors print
 *   "pkg_ip4_in"/"up report failed!".
 * - pkg_ip6_in: ipv6_find_hdr(skb, &off, -1, &fragoff, &fragflg) must
 *   return IPPROTO_TCP(6); the rest is identical to ip4_in.
 * - pkg_recv_hook(msg, len): downlink command table on msg words:
 *   0x64+0..5: uid add/del/blacklist management via core_uid_hash_*,
 *   pkg_add_uid, uid_rec_hash_*; cmd 0x6f toggles freezebinder_enable
 *   (1: arm + millet_sendmsg(5,...), else disarm); cmd 1/2/3 map to
 *   uid_rec_hash_add/del/clear. Mirrors the binary's jump-table
 *   ranges (0x64..0x69 extended table, 1/2/3 short table).
 * - pkg_sendmsg(data, len-value, slot_base): parses the uplink
 *   payload (uid at word[8], needs >= 27 words per the binary's
 *   ldr w10,[x1,#104]), builds its own 128B report (tier=5, cmd=2,
 *   uid preserved at w[8]), then millet_sendto_user. (F1: the old port
 *   stored through the len value as if it were a frame -> oops.)
 * - pkg_add_uid(uid, table10): 10-slot exact dedup insert; -1 when full
 *   ("%s : add uid:%d failed (full)!").
 * - find_and_clear_piduid(pid, tsk, uid): binder gate primitive
 *   (exported): freezebinder_enable must be armed; core_uid_hash_find
 *   hit -> debug print, return 1; else pid-blacklist veto (10 ldar
 *   slots) -> 0; else uid black/allow derivation from pid; uid <
 *   frozen_uid_min (6000 in 6.6 binary; here the live frozen_uid_min)
 *   -> core_uid_hash_find; uid blacklist veto -> 0; else debug print,
 *   return 1. Returns 1 "clear to freeze-path" / 0 "veto".
 * - init_module: freezebinder_enable=0 ("freezebinder_enable=%d :
 *   set!"), nf_register_net_hooks(..., 4), register_millet_hook(5,
 *   pkg_recv_hook, pkg_sendmsg), init_millet_subsystem(5, "PKG").
 * - cleanup_module: unregister_millet_hook(5),
 *   nf_unregister_net_hooks.
 * - pkg_stat_show: uid_rec_hash_show + seq_printf (proc hook kept for
 *   core's stat readout reuse).
 *
 * 5.15 notes: nf_hookfn signature (priv, skb, state) unchanged;
 * ipv6_find_hdr present (ipv6.h:1076, EXPORT_SYMBOL); nf_register_net_
 * hooks present (netfilter.h:188, EXPORT_SYMBOL). sk_uid retrieval uses
 * the public sk_uid() helper (sock.h) instead of the binary's raw
 * sk+0x290 offset.
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/sock.h>

extern int core_uid_hash_add(kuid_t uid, unsigned long flags);
extern int core_uid_hash_del(kuid_t uid);
extern bool core_uid_hash_find(kuid_t uid);
extern int uid_rec_hash_add(kuid_t uid, unsigned long flags);
extern int uid_rec_hash_del(kuid_t uid);
extern int uid_rec_hash_show(struct seq_file *m, void *v);
extern void uid_rec_hash_clear(void);
extern bool uid_rec_hash_find_and_clear(kuid_t uid);
extern int register_millet_hook(unsigned int type, void *recv, void *send);
extern int unregister_millet_hook(unsigned int type);
extern void init_millet_subsystem(unsigned int tier, const char *name);
extern int millet_sendmsg(unsigned int tier, const void *data, unsigned int len);
extern int millet_sendto_user(unsigned int tier, unsigned int cmd,
			      const void *data, unsigned int len);
extern int freezebinder_enable;
extern unsigned int frozen_uid_min;
extern unsigned int millet_debug;
extern u32 core_black_pid_rec[10];
extern u32 core_black_uid_rec[10];

/*
 * F1 block layout note: core's struct sew_millet_report_frame is the shared
 * 128B uplink frame, but THIS sensor's payload words are positional:
 * - pkg keeps the uid at uplink word[26] (binary pkg_sendmsg:
 *   ldr w10,[x1,#104]; the uplinker stores it at buffer+104, see
 *   pkg_ip4_in stp w19,[sp,#112] with the buffer at sp+8). The send
 *   half preserves it into the report's w[8] (str w10,[x1,#32]).
 * - hs stamps w[0]=tier/w[2]=cmd only.
 * - sig reads dst/killer tasks from arg1/arg3 (see millet_sig.c).
 * SEW_MILLET_PKG_UID_WORD=8 is therefore part of the daemon-visible ABI;
 * SEW_MILLET_PKG_UP_UID_WORD=26 is the kernel-internal uplink ABI.
 */
#define SEW_MILLET_PKG_UID_WORD	8
#define SEW_MILLET_PKG_UP_UID_WORD	26
#define SEW_MILLET_PKG_FRAME_WORDS	32

/* Compile-time guard: both uid words must be inside the 128B frame. */
static inline void __sew_millet_pkg_layout_check(void)
{
	BUILD_BUG_ON(SEW_MILLET_PKG_UID_WORD >= SEW_MILLET_PKG_FRAME_WORDS);
	BUILD_BUG_ON(SEW_MILLET_PKG_UP_UID_WORD >= SEW_MILLET_PKG_FRAME_WORDS);
	BUILD_BUG_ON(SEW_MILLET_PKG_FRAME_WORDS * 4 != 128);
}

/* App-uid floor from the binary: uid>>4 must exceed 0x271. */
#define SEW_MILLET_PKG_UID_SHIFT	4
#define SEW_MILLET_PKG_UID_MIN	0x271

/* Downlink command ids (binary jump-table derived). */
#define SEW_MILLET_PKG_CMD_UID_BASE	0x64
#define SEW_MILLET_PKG_CMD_ARM	0x6f

struct sew_millet_pkg_report {
	u32	pad[SEW_MILLET_PKG_UP_UID_WORD];	/* words 0..25: zeroed */
	u32	uid;				/* word 26: uplink uid slot */
	u32	ext[5];				/* words 27..31: pad to 128B */
};

static inline void __sew_millet_pkg_size_check(void)
{
	BUILD_BUG_ON(sizeof(struct sew_millet_pkg_report) != 128);
}

/* 10-slot exact-dedup insert; 0 ok, -1 full/duplicate.
 * Runs in netlink-recv process context (writer). The reader
 * (find_and_clear_piduid in softirq) uses READ_ONCE per slot; see the
 * locking note on core_black_*_rec below. */
static int sew_millet_pkg_add_uid(u32 uid, u32 *table)
{
	int i, free = -1;

	for (i = 0; i < 10; i++) {
		u32 cur = READ_ONCE(table[i]);

		if (cur == uid)
			return 0;
		if (!cur && free < 0)
			free = i;
	}
	if (free < 0) {
		pr_info("millet-millet_pkg: %s : add uid:%d failed (full)!\n",
			__func__, uid);
		return -1;
	}
	/* Publish with a single ordered store; concurrent softirq readers
	 * either see 0 (slot still empty) or uid, never a torn word. */
	WRITE_ONCE(table[free], uid);
	return 0;
}

static bool sew_millet_pkg_blacklisted(u32 id, u32 *table)
{
	int i;

	for (i = 0; i < 10; i++) {
		/* F1-D1R4: lock-free softirq reader. The writer
		 * (sew_millet_pkg_add_uid, netlink process context) publishes
		 * each slot with a single WRITE_ONCE; a concurrent reader
		 * sees either empty or the new id. arm64 word loads are
		 * single-copy atomic; READ_ONCE keeps the compiler from
		 * fusing/reloading the slot across the loop. No sleeping
		 * lock may be taken here (nf hook runs in softirq), and a
		 * spinlock shared with the process-context writer would
		 * need irqsave discipline on both sides for zero gain:
		 * exact "find-empty-then-fill" atomicity is NOT required
		 * (a duplicate insert on full-table race only wastes one
		 * slot; the table is advisory, hash tables are
		 * authoritative). */
		if (READ_ONCE(table[i]) == id)
			return true;
	}
	return false;
}

/*
 * Binder-gate primitive (exported, matches official __ksymtab_gpl):
 * 1 = freeze-path clear, 0 = veto. pid==0 or a disarmed
 * freezebinder_enable vetoes immediately. A core-table hit clears
 * immediately (with debug trace); otherwise the pid/uid blacklists and
 * the frozen_uid_min floor decide. All blacklist slots are plain u32
 * words updated by the downlink path; single-word loads/stores are
 * atomic on arm64 so no lock is taken here (softirq-safe by design).
 */
bool find_and_clear_piduid(unsigned int pid, void *tsk, unsigned int uid)
{
	u32 duid = uid;

	(void)tsk;
	if (!pid)
		return false;
	if (!freezebinder_enable)
		return false;

	if (core_uid_hash_find(KUIDT_INIT(duid))) {
		if (millet_debug)
			pr_info("millet-millet_pkg: find_and_clear_piduid dstuid srcuid=%d srcpid=%d, dstuid=%d\n",
				duid, pid, duid);
		return true;
	}

	/* pid blacklist veto (10 ldar slots in the binary). */
	if (sew_millet_pkg_blacklisted(pid, core_black_pid_rec))
		return false;

	if (duid < frozen_uid_min) {
		if (core_uid_hash_find(KUIDT_INIT(duid))) {
			if (millet_debug)
				pr_info("millet-millet_pkg: find_and_clear_piduid realuid srcuid=%d srcpid=%d, dstuid=%d\n",
					duid, pid, duid);
			return true;
		}
		return false;
	}

	/* uid blacklist veto (10 ldar slots in the binary). */
	if (sew_millet_pkg_blacklisted(duid, core_black_uid_rec))
		return false;

	if (millet_debug)
		pr_info("millet-millet_pkg: find_and_clear_piduid srcuid srcuid=%d srcpid=%d, dstuid=%d\n",
			duid, pid, duid);
	return true;
}
EXPORT_SYMBOL_GPL(find_and_clear_piduid);

/* Extract the socket uid of an IPv4/TCP skb; 0 when not determinable.
 * Uses the plain sk_uid field under sk_callback_lock discipline would
 * sleep; the field word itself is read lock-free like the binary's
 * ldar, and a torn read only misattributes one packet to uid 0 (which
 * is filtered as non-app below). The nf hook runs in softirq, so no
 * sleeping lock may be taken here. */
static u32 sew_millet_pkg_skb_uid(struct sk_buff *skb)
{
	struct sock *sk;

	sk = skb_to_full_sk(skb);
	if (!sk)
		return 0;
	return from_kuid_munged(&init_user_ns, READ_ONCE(sk->sk_uid));
}

/* Shared tail of ip4_in/ip6_in after the uid is known.
 * Layout matches the binary: the uplinker stores the uid at uplink
 * word[SEW_MILLET_PKG_UP_UID_WORD] (buffer+104, mirroring the binary's
 * stp w19,[sp,#112] with the 0xB0 buffer sitting at sp+8).
 * sizeof(rep) is the full 128B frame, so the word is always in-bounds. */
static unsigned int sew_millet_pkg_report_uid(u32 uid)
{
	struct sew_millet_pkg_report rep;

	if ((uid >> SEW_MILLET_PKG_UID_SHIFT) < SEW_MILLET_PKG_UID_MIN)
		return NF_ACCEPT;
	if (!uid_rec_hash_find_and_clear(KUIDT_INIT(uid)))
		return NF_ACCEPT;

	memset(&rep, 0, sizeof(rep));
	((u32 *)&rep)[SEW_MILLET_PKG_UP_UID_WORD] = uid;
	if (millet_sendmsg(5, &rep, sizeof(rep)))
		pr_info("millet-millet_pkg: %s : up report failed!\n",
			"pkg_ip4_in");
	return NF_ACCEPT;
}

static unsigned int sew_millet_pkg_ip4_in(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct iphdr *iph;
	u32 uid;

	(void)priv;
	(void)state;
	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	uid = sew_millet_pkg_skb_uid(skb);
	if (!uid)
		return NF_ACCEPT;
	return sew_millet_pkg_report_uid(uid);
}

static unsigned int sew_millet_pkg_ip6_in(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	unsigned int off = 0;
	unsigned short fragoff = 0;
	int fragflg = 0, nexthdr;
	u32 uid;

	(void)priv;
	(void)state;
	if (!skb)
		return NF_ACCEPT;
	nexthdr = ipv6_find_hdr(skb, &off, -1, &fragoff, &fragflg);
	if (nexthdr != IPPROTO_TCP)
		return NF_ACCEPT;

	uid = sew_millet_pkg_skb_uid(skb);
	if (!uid)
		return NF_ACCEPT;
	return sew_millet_pkg_report_uid(uid);
}

/* OUT hooks are accept stubs in the binary (return 1 == NF_ACCEPT). */
static unsigned int sew_millet_pkg_ip_out(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	(void)priv;
	(void)skb;
	(void)state;
	return NF_ACCEPT;
}

static struct nf_hook_ops sew_millet_pkg_nf_ops[] = {
	{
		.hook		= sew_millet_pkg_ip4_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		.hook		= sew_millet_pkg_ip6_in,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		.hook		= sew_millet_pkg_ip_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		.hook		= sew_millet_pkg_ip_out,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FIRST,
	},
};

/*
 * Send half of the type-5 slot. F1 calling convention:
 *	arg1 = uplink payload (u32 words; uid at word[SEW_MILLET_PKG_UP_UID_WORD]),
 *	arg2 = payload length VALUE cast through void *,
 *	arg3 = slot-array base (per-task seq lookup; NULL-checked).
 * Builds its OWN 128B report frame on the stack (never stores through
 * arg2: the old code did w=arg2 which faulted when arg2 was the len
 * value 8) and delivers via millet_sendto_user(5, 2, ...).
 * Binary cross-check: pkg_sendmsg ldr w10,[x1,#104] reads word[26] of
 * the INCOMING payload (large daemon-built frame), then
 * str w10,[x1,#32] preserves the uid into the OUTGOING report at w[8].
 * So arg1 must carry >= 27 words; shorter payloads are rejected.
 */
static int sew_millet_pkg_sendmsg(void *arg1, void *arg2, void *arg3)
{
	const u32 *in = arg1;
	unsigned long len = (unsigned long)arg2;
	u32 frame[SEW_MILLET_PKG_FRAME_WORDS];
	u32 uid;

	__sew_millet_pkg_layout_check();
	__sew_millet_pkg_size_check();
	if (!arg1 || !arg3) {
		pr_info("millet-millet_pkg: %s input invalid\n", __func__);
		return -1;
	}
	/* F1-D1R5: length check before touching in[26]. The uplinker
	 * (sew_millet_pkg_report_uid) always passes the full 128B frame; the
	 * daemon downlink path passes the full 128B frame too. Accept both,
	 * reject anything that cannot hold the uid word. */
	if (len < (SEW_MILLET_PKG_UP_UID_WORD + 1) * sizeof(u32)) {
		pr_info("millet-millet_pkg: %s short payload %lu\n",
			__func__, len);
		return -1;
	}
	uid = in[SEW_MILLET_PKG_UP_UID_WORD];
	memset(frame, 0, sizeof(frame));
	frame[0] = 5;
	frame[2] = 2;
	frame[SEW_MILLET_PKG_UID_WORD] = uid;
	return millet_sendto_user(5, 2, frame, sizeof(frame));
}

/*
 * Downlink command table (runs in netlink recv process context):
 * msg words: [18]=cmd class, [19]=uid operand. Classes 0x64..0x69
 * manage the core/blacklist tables; 0x6f arms/disarms
 * freezebinder_enable; 1/2/3 manage the uid_rec table. Unknown
 * classes are ignored (binary falls through to the epilogue).
 */
static void sew_millet_pkg_recv_hook(void *msg, unsigned int len)
{
	u32 *w = msg;
	u32 cmd, uid;

	if (!msg || len < 80 * sizeof(u32))
		return;
	cmd = w[72 / sizeof(u32)];
	uid = w[76 / sizeof(u32)];

	if (cmd >= SEW_MILLET_PKG_CMD_UID_BASE &&
	    cmd <= SEW_MILLET_PKG_CMD_UID_BASE + 5) {
		switch (cmd - SEW_MILLET_PKG_CMD_UID_BASE) {
		case 0:
			if (uid != SEW_MILLET_PKG_CMD_ARM)
				core_uid_hash_add(KUIDT_INIT(uid), 0);
			break;
		case 1:
			core_uid_hash_del(KUIDT_INIT(uid));
			break;
		case 2:
			sew_millet_pkg_add_uid(uid, core_black_pid_rec);
			break;
		case 3:
			sew_millet_pkg_add_uid(uid, core_black_uid_rec);
			break;
		case 4:
			sew_millet_pkg_add_uid(uid, core_black_pid_rec);
			break;
		case 5:
			sew_millet_pkg_add_uid(uid, core_black_uid_rec);
			break;
		}
		return;
	}

	if (cmd == SEW_MILLET_PKG_CMD_ARM) {
		if (uid == SEW_MILLET_PKG_CMD_ARM) {
			struct sew_millet_pkg_report rep;

			freezebinder_enable = 1;
			memset(&rep, 0, sizeof(rep));
			((u32 *)&rep)[SEW_MILLET_PKG_UP_UID_WORD] =
				SEW_MILLET_PKG_CMD_ARM;
			if (millet_sendmsg(5, &rep, sizeof(rep)))
				pr_info("millet-millet_pkg: %s : up report failed!\n",
					__func__);
			pr_info("millet-millet_pkg: freezebinder_enable=%d : set!\n",
				freezebinder_enable);
		} else {
			freezebinder_enable = 0;
			pr_info("millet-millet_pkg: freezebinder_enable=%d : set!\n",
				freezebinder_enable);
		}
		return;
	}

	switch (cmd) {
	case 1:
		uid_rec_hash_add(KUIDT_INIT(uid), 0);
		break;
	case 2:
		uid_rec_hash_del(KUIDT_INIT(uid));
		break;
	case 3:
		uid_rec_hash_clear();
		break;
	default:
		break;
	}
}

int millet_pkg_stat_show(struct seq_file *m, void *v)
{
	int ret;

	ret = uid_rec_hash_show(m, v);
	seq_printf(m, "freezebinder_enable: %d\n", freezebinder_enable);
	return ret;
}
EXPORT_SYMBOL_GPL(millet_pkg_stat_show);

int __init sew_millet_pkg_init(void)
{
	int ret;

	pr_info("millet-millet_pkg: enter millet_pkg_init func!\n");

	freezebinder_enable = 0;
	pr_info("millet-millet_pkg: freezebinder_enable=%d : set!\n",
		freezebinder_enable);

	ret = nf_register_net_hooks(&init_net, sew_millet_pkg_nf_ops,
				    ARRAY_SIZE(sew_millet_pkg_nf_ops));
	if (ret) {
		pr_info("millet-millet_pkg: nf_register_hooks(millet hooks) error\n");
		return ret;
	}
	pr_info("millet-millet_pkg: nf_register_hooks(millet hooks) success\n");

	ret = register_millet_hook(5, sew_millet_pkg_recv_hook,
				   sew_millet_pkg_sendmsg);
	if (ret) {
		nf_unregister_net_hooks(&init_net, sew_millet_pkg_nf_ops,
					ARRAY_SIZE(sew_millet_pkg_nf_ops));
		return ret;
	}
	init_millet_subsystem(5, "PKG");
	return 0;
}

void __exit sew_millet_pkg_exit(void)
{
	unregister_millet_hook(5);
	nf_unregister_net_hooks(&init_net, sew_millet_pkg_nf_ops,
				ARRAY_SIZE(sew_millet_pkg_nf_ops));
}

