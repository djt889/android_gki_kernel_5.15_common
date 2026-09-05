// SPDX-License-Identifier: GPL-2.0
/*
 * mm/perf_actuator.c
 *
 * Sew 5.15 rewrite of Xiaomi dada OS4 perf_actuator.ko
 * (vermagic 6.6.57-android15-8-g32a50a34de2b-4k, intree, GPL v2,
 * zero dependencies). Function, variable and device names are kept
 * identical to the shipped binary so the userspace contract and the
 * register_*() ABI stay source-compatible with the dada modules.
 *
 * The module is a pure userland-to-kernel QoS dispatch bridge built
 * around two misc devices and two callback tables:
 *
 *   /dev/xr_perf_actuator  (perf_actuator_device, 42 slots,
 *                           guarded by g_table_rwsem)
 *   /dev/xr_fbt            (xr_fbt_device,      12 slots,
 *                           guarded by g_fbt_table_rwsem)
 *
 * Vendor modules (mi_game, perf_helper, ...) register a callback for
 * a 32-bit ioctl command through register_perf_actuator() /
 * register_xr_fbt(); userspace then issues that ioctl with a payload
 * pointer as @arg and the module dispatches to the registered
 * callback under a read lock.
 *
 * Layout was reconstructed from the binary; full evidence (nm,
 * objdump -d/-r/-s, strings) is archived at
 * .omz/research/sess_d9452f03-b737-460b-bd27-aff04c01b561-os4-force-port/raw/re-perf-actuator.txt
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/rwsem.h>

/* Slot counts enforced by the binary: bss tables are 42*16B and 12*16B. */
#define PERF_ACTUATOR_NR_ENTRIES	42	/* idx mask check: cmp #0x29 */
#define XR_FBT_NR_ENTRIES		12	/* idx mask check: cmp #0xb */

/*
 * Both ioctls only accept the "x" (0x78) type byte; the low byte of the
 * command is the table slot index.
 */
#define PERF_ACTUATOR_IOCTL_MAGIC	0x78

/*
 * One callback slot. The full 32-bit ioctl command is stored in @cmd,
 * the slot index is cmd & 0xff. Matches the 16-byte bss layout
 * {u32 cmd; u32 pad; void *func} of the original module.
 */
struct perf_actuator_entry {
	unsigned int cmd;
	int (*func)(unsigned long arg);
};

static struct perf_actuator_entry g_perf_actuator_table[PERF_ACTUATOR_NR_ENTRIES];
static struct perf_actuator_entry g_xr_fbt_table[XR_FBT_NR_ENTRIES];

static DECLARE_RWSEM(g_table_rwsem);	/* guards g_perf_actuator_table */
static DECLARE_RWSEM(g_fbt_table_rwsem);	/* guards g_xr_fbt_table */

/*
 * Register @func for the ioctl command @idx. Slot = idx & 0xff. Like
 * the original, an occupied slot is not an error: the old callback is
 * overwritten after a "register %u conflict" warning. Also like the
 * original, out-of-range idx / NULL func print
 * "invalid cmd:%d or func:%p" and fail with -EINVAL.
 */
int register_perf_actuator(int idx, int (*func)(unsigned long arg))
{
	struct perf_actuator_entry *entry;
	int slot = idx & 0xff;

	if (slot >= PERF_ACTUATOR_NR_ENTRIES || !func) {
		pr_err("perf_actuator: invalid cmd:%d or func:%p\n", idx, func);
		return -EINVAL;
	}

	down_write(&g_table_rwsem);
	entry = &g_perf_actuator_table[slot];
	if (entry->func)
		pr_err("perf_actuator: perf_actuator: register %u conflict\n",
		       (unsigned int)idx);
	entry->cmd = (unsigned int)idx;
	entry->func = func;
	up_write(&g_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(register_perf_actuator);

/*
 * Clear the slot for @idx. The original never fails on an unregistered
 * slot: it warns "unregister %u conflict" and clears it anyway,
 * returning 0. Only an out-of-range idx returns -EINVAL (silently).
 */
int unregister_perf_actuator(int idx)
{
	struct perf_actuator_entry *entry;
	int slot = idx & 0xff;

	if (slot >= PERF_ACTUATOR_NR_ENTRIES)
		return -EINVAL;

	down_write(&g_table_rwsem);
	entry = &g_perf_actuator_table[slot];
	if (!entry->func || entry->cmd != (unsigned int)idx)
		pr_err("perf_actuator: perf_actuator: unregister %u conflict\n",
		       (unsigned int)idx);
	entry->cmd = 0;
	entry->func = NULL;
	up_write(&g_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(unregister_perf_actuator);

/* xr_fbt flavor of the register API; out-of-range/NULL is silent here. */
int register_xr_fbt(int idx, int (*func)(unsigned long arg))
{
	struct perf_actuator_entry *entry;
	int slot = idx & 0xff;

	if (slot >= XR_FBT_NR_ENTRIES || !func)
		return -EINVAL;

	down_write(&g_fbt_table_rwsem);
	entry = &g_xr_fbt_table[slot];
	if (entry->func)
		pr_err("xr_fbt: xr_fbt: register %u conflict\n",
		       (unsigned int)idx);
	entry->cmd = (unsigned int)idx;
	entry->func = func;
	up_write(&g_fbt_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(register_xr_fbt);

int unregister_xr_fbt(int idx)
{
	struct perf_actuator_entry *entry;
	int slot = idx & 0xff;

	if (slot >= XR_FBT_NR_ENTRIES)
		return -EINVAL;

	down_write(&g_fbt_table_rwsem);
	entry = &g_xr_fbt_table[slot];
	if (!entry->func || entry->cmd != (unsigned int)idx)
		pr_err("xr_fbt: xr_fbt: unregister %u conflict\n",
		       (unsigned int)idx);
	entry->cmd = 0;
	entry->func = NULL;
	up_write(&g_fbt_table_rwsem);

	return 0;
}
EXPORT_SYMBOL_GPL(unregister_xr_fbt);

static int perf_actuator_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int perf_actuator_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 * perf_actuator device dispatch. Command layout checked by the binary:
 *   [15:8] == 0x78 magic, [7:0] == table slot. A NULL @arg, bad magic
 * or out-of-range slot fail before the table is consulted; a missing
 * or mismatched registration returns -ENOENT.
 */
static long perf_actuator_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct perf_actuator_entry *entry;
	int slot = cmd & 0xff;
	long ret;

	pr_info("perf_actuator: perf_actuator: perf_actuator_ioctl idx %d\n",
		slot);

	if (!arg) {
		pr_err("perf_actuator: perf_actuator: invalid user uarg\n");
		return -EINVAL;
	}

	if (((cmd >> 8) & 0xff) != PERF_ACTUATOR_IOCTL_MAGIC) {
		pr_err("perf_actuator: perf_actuator: invalid magic %u\n",
		       (unsigned int)((cmd >> 8) & 0xff));
		return -EINVAL;
	}

	if (slot >= PERF_ACTUATOR_NR_ENTRIES) {
		pr_err("perf_actuator: perf_actuator: invalid cmd, %u > %d\n",
		       (unsigned int)slot, PERF_ACTUATOR_NR_ENTRIES);
		return -ERANGE;
	}

	down_read(&g_table_rwsem);
	entry = &g_perf_actuator_table[slot];
	if (!entry->func || entry->cmd != cmd) {
		pr_err("perf_actuator: perf_actuator: idx %d, cmd %d not match or not registered!\n",
		       slot, (int)cmd);
		up_read(&g_table_rwsem);
		return -ENOENT;
	}

	ret = entry->func(arg);
	up_read(&g_table_rwsem);

	return ret;
}

static int xr_fbt_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int xr_fbt_release(struct inode *inode, struct file *file)
{
	return 0;
}

/* xr_fbt device dispatch: same checks, no entry trace log, 12 slots. */
static long xr_fbt_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	struct perf_actuator_entry *entry;
	int slot = cmd & 0xff;
	long ret;

	if (!arg) {
		pr_err("xr_fbt: xr_fbt: invalid user uarg\n");
		return -EINVAL;
	}

	if (((cmd >> 8) & 0xff) != PERF_ACTUATOR_IOCTL_MAGIC) {
		pr_err("xr_fbt: xr_fbt: invalid magic %u\n",
		       (unsigned int)((cmd >> 8) & 0xff));
		return -EINVAL;
	}

	if (slot >= XR_FBT_NR_ENTRIES) {
		pr_err("xr_fbt: xr_fbt: invalid cmd, %u > %d\n",
		       (unsigned int)slot, XR_FBT_NR_ENTRIES);
		return -ERANGE;
	}

	down_read(&g_fbt_table_rwsem);
	entry = &g_xr_fbt_table[slot];
	if (!entry->func || entry->cmd != cmd) {
		pr_err("xr_fbt: xr_fbt: cmd not match or not registered!\n");
		up_read(&g_fbt_table_rwsem);
		return -ENOENT;
	}

	ret = entry->func(arg);
	up_read(&g_fbt_table_rwsem);

	return ret;
}

static const struct file_operations perf_actuator_fops = {
	.owner = THIS_MODULE,
	.open = perf_actuator_open,
	.release = perf_actuator_release,
	.unlocked_ioctl = perf_actuator_ioctl,
};

static const struct file_operations xr_fbt_fops = {
	.owner = THIS_MODULE,
	.open = xr_fbt_open,
	.release = xr_fbt_release,
	.unlocked_ioctl = xr_fbt_ioctl,
};

/*
 * Device names as shipped: the perf_actuator_device node is
 * "xr_perf_actuator", the xr_fbt_device node is "xr_fbt"; both use a
 * dynamic minor (0xff in the binary = MISC_DYNAMIC_MINOR).
 */
static struct miscdevice perf_actuator_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "xr_perf_actuator",
	.fops = &perf_actuator_fops,
};

static struct miscdevice xr_fbt_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "xr_fbt",
	.fops = &xr_fbt_fops,
};

int xr_fbt_dev_init(void)
{
	return misc_register(&xr_fbt_device);
}

void xr_fbt_dev_exit(void)
{
	misc_deregister(&xr_fbt_device);
}

static int __init perf_actuator_init(void)
{
	int ret;

	ret = misc_register(&perf_actuator_device);
	if (ret) {
		pr_err("perf_actuator: perf_actuator: init failed!\n");
		return ret;
	}

	pr_info("perf_actuator: perf_actuator: init success!\n");

	/* As in the original: xr_fbt failure does not unwind the first device. */
	return xr_fbt_dev_init();
}

static void __exit perf_actuator_exit(void)
{
	misc_deregister(&perf_actuator_device);
	xr_fbt_dev_exit();
}

module_init(perf_actuator_init);
module_exit(perf_actuator_exit);
MODULE_LICENSE("GPL v2");
