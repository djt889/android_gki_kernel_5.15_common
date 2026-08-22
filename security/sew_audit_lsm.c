// SPDX-License-Identifier: GPL-2.0
/*
 * sew_audit: block loading of kernel modules that duplicate functionality
 * already built into the Sew kernel.
 *
 * Several vendor/ROM kernels ship .ko modules (binder priority tuning,
 * kshrink async reclaim, etc.) that would conflict with the same features
 * built in here. Blocking them at module load avoids duplicate vendor-hook
 * registration and double-reclaim/double-protect behavior.
 *
 * Matching is by module file name prefix, restricted to system partitions
 * so recovery/ramdisk module loads are never affected.
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include <linux/lsm_hooks.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/string.h>

/*
 * Module file name prefixes to block. A load from a system partition whose
 * file name starts with one of these is rejected with -EPERM.
 */
static const char * const sew_audit_block_prefixes[] = {
	"binder_prio",
	"moon_",
	"kshrink_",
};

/*
 * Paths whose duplicate-module loads are blocked: system partitions, plus
 *  - /system_dlkm/: GKI vendor module partition (Android 13+)
 *  - /data/adb/modules/: Magisk/KernelSU module storage; a binder_prio ko
 *    loaded from here would double-register the same vendor hooks as the
 *    built-in binder_sched_opt (observed LSPosed safe-mode trigger).
 * Recovery/ramdisk paths (first-stage /lib/modules) stay allowed by design
 * so recovery boot is never broken.
 */
static bool sew_audit_block_path(const char *path)
{
	return !strncmp(path, "/vendor_dlkm/", 13) ||
	       !strncmp(path, "/vendor/", 8) ||
	       !strncmp(path, "/system/", 8) ||
	       !strncmp(path, "/odm/", 5) ||
	       !strncmp(path, "/product/", 9) ||
	       !strncmp(path, "/system_ext/", 12) ||
	       !strncmp(path, "/system_dlkm/", 13) ||
	       !strncmp(path, "/data/adb/modules/", 18);
}

static bool sew_audit_name_blocked(const char *name, unsigned int len)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sew_audit_block_prefixes); i++) {
		const char *prefix = sew_audit_block_prefixes[i];
		unsigned int plen = strlen(prefix);

		if (len >= plen && !strncmp(name, prefix, plen))
			return true;
	}

	return false;
}

static int sew_audit_kernel_read_file(struct file *file,
				      enum kernel_read_file_id id, bool unused)
{
	const struct dentry *dentry;

	if (id != READING_MODULE)
		return 0;

	if (!file) {
		pr_info_ratelimited("sew_audit: module read path-unavailable\n");
		return 0;
	}

	dentry = file->f_path.dentry;
	if (dentry && dentry->d_name.name &&
	    sew_audit_name_blocked(dentry->d_name.name, dentry->d_name.len)) {
		char *buf = __getname();
		char *path;

		if (!buf)
			return 0;

		path = d_path(&file->f_path, buf, PATH_MAX);
		if (!IS_ERR(path) && sew_audit_block_path(path)) {
			__putname(buf);
			pr_info_ratelimited("sew_audit: BLOCKED module %s (protected path)\n",
					    dentry->d_name.name);
			return -EPERM;
		}
		__putname(buf);
	}

	return 0;
}

static struct security_hook_list sew_audit_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(kernel_read_file, sew_audit_kernel_read_file),
};

static int __init sew_audit_lsm_init(void)
{
	security_add_hooks(sew_audit_hooks, ARRAY_SIZE(sew_audit_hooks),
			   "sew_audit");
	return 0;
}

DEFINE_EARLY_LSM(sew_audit) = {
	.name = "sew_audit",
	.init = sew_audit_lsm_init,
};
