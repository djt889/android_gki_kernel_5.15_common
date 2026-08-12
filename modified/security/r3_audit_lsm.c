// SPDX-License-Identifier: GPL-2.0
/*
 * R3: Record module file reads for diagnostics.
 * R4: Additionally block binder_prio module loading (by exact file name).
 * R5 fix: Only block binder_prio.ko when loaded from a system partition
 *         path. Recovery/ramdisk module loads (which may also reference
 *         binder_prio.ko) are allowed so recovery boot is not broken.
 *
 * Policy: finit_module() loads modules from files, so Android init's
 * modules.load mechanism goes through kernel_read_file(READING_MODULE),
 * where the originating struct file and its name are available. Blocking
 * here covers the standard Android init module-load path. The older
 * init_module() API (memory blob, no file) cannot be name-matched at the
 * kernel_load_data() hook, so it is left unblocked.
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include <linux/lsm_hooks.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/string.h>

#define R3_BLOCK_FILENAME "binder_prio.ko"
#define R3_BLOCK_FILENAME_LEN (sizeof(R3_BLOCK_FILENAME) - 1)

/*
 * System partition mount points. binder_prio.ko loaded from one of these is
 * the R4 target. Loads from any other path (e.g. recovery ramdisk) pass.
 */
static bool r3_audit_system_path(const char *path)
{
	return !strncmp(path, "/vendor_dlkm/", 13) ||
	       !strncmp(path, "/vendor/", 8) ||
	       !strncmp(path, "/system/", 8) ||
	       !strncmp(path, "/odm/", 5) ||
	       !strncmp(path, "/product/", 9) ||
	       !strncmp(path, "/system_ext/", 12);
}

static int r3_audit_kernel_read_file(struct file *file,
				    enum kernel_read_file_id id, bool unused)
{
	const struct dentry *dentry;

	if (id != READING_MODULE)
		return 0;

	if (file) {
		pr_info_ratelimited("r3_audit: module read %pD\n", file);

		dentry = file->f_path.dentry;

		if (dentry && dentry->d_name.name &&
		    dentry->d_name.len == R3_BLOCK_FILENAME_LEN &&
		    !memcmp(dentry->d_name.name, R3_BLOCK_FILENAME,
			    R3_BLOCK_FILENAME_LEN)) {
			char *buf = __getname();
			char *path;

			if (!buf)
				return 0;

			path = d_path(&file->f_path, buf, PATH_MAX);
			if (!IS_ERR(path) && r3_audit_system_path(path)) {
				__putname(buf);
				pr_info_ratelimited("r3_audit: BLOCKED binder_prio module load (system path)\n");
				return -EPERM;
			}
			__putname(buf);
			pr_info_ratelimited("r3_audit: binder_prio load from non-system path, allow\n");
		}
	} else {
		pr_info_ratelimited("r3_audit: module read path-unavailable\n");
	}

	return 0;
}

static struct security_hook_list r3_audit_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(kernel_read_file, r3_audit_kernel_read_file),
};

static int __init r3_audit_lsm_init(void)
{
	security_add_hooks(r3_audit_hooks, ARRAY_SIZE(r3_audit_hooks),
			   "r3_audit");
	return 0;
}

DEFINE_EARLY_LSM(r3_audit) = {
	.name = "r3_audit",
	.init = r3_audit_lsm_init,
};
