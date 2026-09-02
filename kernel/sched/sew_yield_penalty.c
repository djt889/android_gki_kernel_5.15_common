// SPDX-License-Identifier: GPL-2.0-only
/*
 * sew_yield_penalty: penalize sched_yield() from a designated task so an
 * untimely yield cannot push a frame-critical thread to the back of the
 * run queue. The penalty replaces the yield with a bounded sleep up to
 * the next frame boundary (target_fps derived frame_time scaled by
 * penalty_headroom).
 *
 * Hook: android_rvh_before_do_sched_yield (restricted). The hook fires at
 * the very top of do_sched_yield(); writing a non-zero value to @unused
 * makes the syscall return without yielding, and this module sleeps the
 * caller here instead. Sleeping inside the hook is safe: at this point
 * do_sched_yield() holds no rq lock and no pi locks (this_rq_lock_irq has
 * not run yet), so a plain usleep is not nested under any scheduler lock.
 *
 * Port of the Xiaomi OS4 sched-penalty module idea (kernel/sched/
 * sched-penalty.c, "QTI WALT optimization"), rewritten for PELT 5.15 with
 * one deliberate fix: the original had no guard against penalizing
 * system threads, so a wrong target_pid could stall system_server. The
 * uid gate below rejects everything outside the Android app range.
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/delay.h>
#include <linux/cred.h>
#include <linux/tracepoint.h>
#include <trace/hooks/sched.h>

static int sew_penalty_target_pid;
static unsigned int sew_penalty_target_fps = 60;
/* 0..100 percent added on top of one frame period. */
static unsigned int sew_penalty_headroom_pct = 10;

static u64 sew_yield_count;
static u64 sew_yield_sleep_ns;

/*
 * Android app uids: 10000..19999 (PER_USER_RANGE shifted by AID_APP_START).
 * The gate is deliberately dumb: anything outside is refused, including
 * system (1000) and root (0). Writing a pid from those ranges returns
 * -EPERM from the sysfs store below, and even a forged target cannot
 * pass here at hook time.
 */
static bool sew_penalty_uid_allowed(struct task_struct *t)
{
	kuid_t uid;
	unsigned int val;

	uid = task_uid(t);
	val = from_kuid_munged(current_user_ns(), uid);
	return val >= 10000 && val < 20000;
}

static void sew_penalty_before_yield(void *data, long *unused)
{
	struct task_struct *t = current;
	u64 frame_ns, lo, hi;

	if (!sew_penalty_target_pid || !sew_penalty_target_fps)
		return;
	if (task_tgid_nr(t) != sew_penalty_target_pid)
		return;
	if (!sew_penalty_uid_allowed(t))
		return;

	frame_ns = div64_u64(NSEC_PER_SEC, sew_penalty_target_fps);
	lo = div64_u64(frame_ns, 2);
	hi = frame_ns + div64_u64(frame_ns * sew_penalty_headroom_pct, 100);
	if (hi <= lo)
		hi = lo + 1;

	sew_yield_count++;
	sew_yield_sleep_ns += hi - lo;

	/* Skip the yield; sleep half a frame up to one frame + headroom. */
	*unused = 1;
	usleep_range(lo, hi);
}

static ssize_t target_pid_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret, val;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;
	/*
	 * Refuse to accept pids owned by non-app uids by checking the
	 * target's credentials now, not just at hook time.
	 */
	if (val > 0) {
		struct task_struct *t;
		bool allowed = false;

		rcu_read_lock();
		t = find_task_by_vpid(val);
		if (t)
			allowed = sew_penalty_uid_allowed(t);
		rcu_read_unlock();
		if (!allowed)
			return -EPERM;
	}
	sew_penalty_target_pid = val;
	return count;
}

static ssize_t target_pid_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", sew_penalty_target_pid);
}

static ssize_t target_fps_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret;
	unsigned int val;

	ret = kstrtouint(buf, 10, &val);
	if (ret)
		return ret;
	if (val < 10 || val > 240)
		return -EINVAL;
	sew_penalty_target_fps = val;
	return count;
}

static ssize_t target_fps_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", sew_penalty_target_fps);
}

static ssize_t headroom_store(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	int ret;
	unsigned int val;

	ret = kstrtouint(buf, 10, &val);
	if (ret)
		return ret;
	if (val > 100)
		return -EINVAL;
	sew_penalty_headroom_pct = val;
	return count;
}

static ssize_t headroom_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", sew_penalty_headroom_pct);
}

static ssize_t stats_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE,
			 "penalized_yields=%llu\nsleep_ns_total=%llu\n",
			 sew_yield_count, sew_yield_sleep_ns);
}

static struct kobj_attribute target_pid_attr =
	__ATTR(target_pid, 0644, target_pid_show, target_pid_store);
static struct kobj_attribute target_fps_attr =
	__ATTR(target_fps, 0644, target_fps_show, target_fps_store);
static struct kobj_attribute headroom_attr =
	__ATTR(penalty_headroom, 0644, headroom_show, headroom_store);
static struct kobj_attribute stats_attr =
	__ATTR(stats, 0444, stats_show, NULL);

static struct attribute *sew_penalty_attrs[] = {
	&target_pid_attr.attr,
	&target_fps_attr.attr,
	&headroom_attr.attr,
	&stats_attr.attr,
	NULL
};
ATTRIBUTE_GROUPS(sew_penalty);

static struct kobject *sew_penalty_kobj;

static int __init sew_yield_penalty_init(void)
{
	int ret;

	sew_penalty_kobj = kobject_create_and_add("sched_penalty", kernel_kobj);
	if (!sew_penalty_kobj)
		return -ENOMEM;

	ret = sysfs_create_groups(sew_penalty_kobj, sew_penalty_groups);
	if (ret) {
		kobject_put(sew_penalty_kobj);
		sew_penalty_kobj = NULL;
		return ret;
	}

	ret = tracepoint_probe_register(
		&__tracepoint_android_rvh_before_do_sched_yield,
		sew_penalty_before_yield, NULL);
	if (ret) {
		sysfs_remove_groups(sew_penalty_kobj, sew_penalty_groups);
		kobject_put(sew_penalty_kobj);
		sew_penalty_kobj = NULL;
		return ret;
	}

	return 0;
}

static void __exit sew_yield_penalty_exit(void)
{
	tracepoint_probe_unregister(
		&__tracepoint_android_rvh_before_do_sched_yield,
		sew_penalty_before_yield, NULL);
	tracepoint_synchronize_unregister();
	if (sew_penalty_kobj) {
		sysfs_remove_groups(sew_penalty_kobj, sew_penalty_groups);
		kobject_put(sew_penalty_kobj);
	}
}

module_init(sew_yield_penalty_init);
module_exit(sew_yield_penalty_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sew yield penalty: bounded-sleep replacement for sched_yield of a target task");
