// SPDX-License-Identifier: GPL-2.0-only
/*
 * millet_hs: handshake/heartbeat plugin (type=6) for the millet frozen
 * control subsystem, ported from millet_hs.ko (dada OS4).
 *
 * Binary behavior (disasm .text + relocs):
 * - hs_recv_hook(msg, len): builds a zeroed 176-byte frame and calls
 *   millet_sendmsg(6, frame, len). Fixed tier 6, always returns 0.
 * - hs_sendmsg(data, len-value, slot_base): NULL-checks len+base
 *   ("millet_hs: %s input invalid"); builds its OWN 128B report with
 *   tier=6, cmd=2 and calls millet_sendto_user(6, 2, ...). (F1: the
 *   binary's [x1]=6/[x1,#8]=2 stores target the outgoing report, not
 *   the incoming len value.)
 * - hs_init_millet(slot): slot[732]=1, slot[840]=1 (type-6 slot words
 *   at 6*120+12 / 6*120+120).
 * - init_module: printk "enter millet_hs_init func!",
 *   register_millet_hook(6, hs_recv_hook, hs_sendmsg),
 *   init_millet_subsystem(6, "HANDSHK").
 * - cleanup_module: unregister_millet_hook(6).
 *
 * No kernel-private dependencies: pure core API. No dynamic state, so
 * no locking is needed beyond what core provides.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

extern int register_millet_hook(unsigned int type, void *recv, void *send);
extern int unregister_millet_hook(unsigned int type);
extern void init_millet_subsystem(unsigned int tier, const char *name);
extern int millet_sendmsg(unsigned int tier, const void *data, unsigned int len);
extern int millet_sendto_user(unsigned int tier, unsigned int cmd,
			      const void *data, unsigned int len);

/*
 * Downlink callback for type 6 (cmd==3 path in core's recv_handler).
 * Forwards the daemon frame to the send half as a heartbeat report.
 * Runs in netlink recv (process) context.
 */
static void sew_millet_hs_recv_hook(void *msg, unsigned int len)
{
	u8 frame[176];

	/* Cap to the frame: the wire message may be longer. */
	if (len > sizeof(frame))
		len = sizeof(frame);
	memset(frame, 0, sizeof(frame));
	if (msg && len)
		memcpy(frame, msg, len);
	millet_sendmsg(6, frame, sizeof(frame));
}

/*
 * Send half of the type-6 slot. Port-internal convention (see core):
 *	arg1 = uplink payload (opaque here; the binary ignores it),
 *	arg2 = payload length VALUE cast through void *,
 *	arg3 = slot-array base (unused here, NULL-checked for parity).
 * Builds its OWN 128B report frame on the stack with tier=6/cmd=2
 * (matching the binary's [x1]=6 / [x1,#8]=2 stores, which target the
 * uplink payload frame in the binary; the port uses a private frame so
 * the (possibly short) uplink buffer is never written). Delivers via
 * millet_sendto_user(6, 2, ...). The old pre-F1 code stored through
 * arg2, which is the len VALUE (176) -> write to address 0xb0 -> oops.
 */
static int sew_millet_hs_sendmsg(void *arg1, void *arg2, void *arg3)
{
	u32 frame[32];

	(void)arg1;
	(void)arg2;
	if (!arg3) {
		pr_info("millet-millet_hs: %s input invalid\n", __func__);
		return -1;
	}
	BUILD_BUG_ON(sizeof(frame) != 128);
	memset(frame, 0, sizeof(frame));
	frame[0] = 6;
	frame[2] = 2;
	return millet_sendto_user(6, 2, frame, sizeof(frame));
}

int __init sew_millet_hs_init(void)
{
	int ret;

	pr_info("millet-millet_hs: enter millet_hs_init func!\n");

	ret = register_millet_hook(6, sew_millet_hs_recv_hook,
				   sew_millet_hs_sendmsg);
	if (ret) {
		pr_info("millet-millet_hs: register hook failed\n");
		return ret;
	}
	init_millet_subsystem(6, "HANDSHK");
	return 0;
}

void __exit sew_millet_hs_exit(void)
{
	unregister_millet_hook(6);
}

