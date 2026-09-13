// SPDX-License-Identifier: GPL-2.0-only
/*
 * thermal_pause - Qualcomm thermal CPU pause cooling device (port)
 *
 * Reference binary:
 *   /root/work/os4ref/dada/vb_work/ramdisk/lib/modules/thermal_pause.ko
 *   (6.6.57, depends: sched-walt, GLOBAL: thermal_pause_notifier_register,
 *   thermal_pause_notifier_unregister, thermal_paused_cpumask)
 *
 * Port to 5.15 GKI (scheme A): the reference pauses CPUs through the
 * proprietary WALT scheduler calls walt_pause_cpus()/walt_resume_cpus()
 * (modinfo depends=sched-walt, R_AARCH64_CALL26 @update_work+0xf4/+0x194),
 * which do not exist on 5.15. This port replaces the pause/resume action
 * with the exported hotplug helpers remove_cpu()/add_cpu()
 * (kernel/cpu.c, EXPORT_SYMBOL_GPL) taken under lock_device_hotplug() /
 * unlock_device_hotplug() (include/linux/device.h). remove_cpu() serializes
 * with suspend through the hotplug locks and returns -EBUSY on contention;
 * the update work retries bounded times and keeps the desired state pending.
 *
 * DT binding kept compatible with the reference (.rodata: "qcom,thermal-pause",
 * child "qcom,cpus" phandle list resolved against the cpu device's
 * device_node, child "qcom,cdev-alias" string used as cdev name
 * "thermal-pause-<alias>"):probe returns -ENODEV cleanly when no DT node is
 * present. Cooling device states mirror the reference: max_state=1,
 * 0 = resume, 1 = pause.
 *
 * Pause ordering vs LMH/cpufreq thermal: thermal_pause is the heaviest tier
 * (real offline). Its trip point must be configured ABOVE the LMH limit
 * trip in the cooling-maps, otherwise both mitigations fight and oscillate.
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/thermal.h>
#include <linux/workqueue.h>

#define SEW_TP_DRV_NAME			"thermal_pause"
#define SEW_TP_CDEV_NAME_FMT		"thermal-pause-%u"
#define SEW_TP_CDEV_NAME_LEN		32
#define SEW_TP_MAX_RETRY			8
#define SEW_TP_RETRY_DELAY_MS		100

/* Matches the reference: blocking notifier, event 1 = pause, 0 = resume. */
#define SEW_TP_EVENT_RESUME			0UL
#define SEW_TP_EVENT_PAUSE			1UL

struct sew_tp_cdev {
	struct list_head node;
	struct thermal_cooling_device *cdev;
	struct work_struct pause_work;
	struct work_struct resume_work;
	struct kref ref;
	/* set under sew_tp_lock by teardown; work/hp paths must bail out */
	bool dead;
	char name[SEW_TP_CDEV_NAME_LEN];
	/* cpumask snapshot parsed from the child qcom,cpus list */
	cpumask_var_t cpus;
	/* last requested state (0/1); protected by sew_tp_lock */
	unsigned long requested_state;
};

static LIST_HEAD(sew_tp_cdev_list);
static DEFINE_MUTEX(sew_tp_lock);
static BLOCKING_NOTIFIER_HEAD(thermal_pause_notifier);

/* Public paused mask, same name/signature as the reference (cpumask_t *). */
cpumask_t thermal_paused_cpumask;
EXPORT_SYMBOL_GPL(thermal_paused_cpumask);

/**
 * thermal_pause_notifier_register - register a pause/resume listener
 * @nb: notifier block; called with event SEW_TP_EVENT_PAUSE (1) / SEW_TP_EVENT_RESUME (0),
 *      data = (void *)(uintptr_t)cpu
 */
int thermal_pause_notifier_register(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&thermal_pause_notifier, nb);
}
EXPORT_SYMBOL_GPL(thermal_pause_notifier_register);

int thermal_pause_notifier_unregister(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&thermal_pause_notifier, nb);
}
EXPORT_SYMBOL_GPL(thermal_pause_notifier_unregister);

/*
 * Offline one CPU via the exported hotplug path.
 *
 * Guards (all re-checked by the caller under sew_tp_lock before commit):
 *  - cpu 0 and the last online CPU are never offlined;
 *  - cpus not in thermal_paused_cpumask are skipped by the caller.
 * Returns 0 on success (or already offline), -EBUSY on hotplug contention
 * (caller retries), other < 0 on hard failure.
 */
static int sew_tp_offline_cpu(unsigned int cpu)
{
	int ret;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -ENODEV;

	if (!cpu_online(cpu))
		return 0;

	if (num_online_cpus() <= 1)
		return -EBUSY;

	ret = remove_cpu(cpu);
	if (ret == 1)
		return 0;
	return ret;
}

/*
 * Online one CPU via the exported hotplug path.
 * Returns 0 on success (or already online), -EBUSY on contention.
 */
static int sew_tp_online_cpu(unsigned int cpu)
{
	int ret;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -ENODEV;

	if (cpu_online(cpu))
		return 0;

	ret = add_cpu(cpu);
	if (ret == 1)
		return 0;
	return ret;
}

/*
 * Apply one pause pass over @mask. CPUs that fail with -EBUSY are left
 * out of thermal_paused_cpumask so the retry pass picks them up later.
 * Hard-failed CPUs are skipped (left online) so one bad CPU can never
 * wedge the whole level. Returns the number of CPUs still pending.
 *
 * Locking: the blocking notifier runs OUTSIDE sew_tp_lock — a listener that
 * takes sew_tp_lock must never deadlock against us. Newly paused CPUs are
 * staged in the local @done mask and notified after unlock.
 */
static unsigned int sew_tp_pause_pass(const struct cpumask *mask)
{
	unsigned int cpu, pending = 0;
	cpumask_var_t done;

	if (!alloc_cpumask_var(&done, GFP_KERNEL))
		return cpumask_weight(mask);

	cpumask_clear(done);

	for_each_cpu(cpu, mask) {
		int ret;

		if (cpu == 0 || cpumask_test_cpu(cpu, &thermal_paused_cpumask))
			continue;

		/* Protect CPU0 + last-online-CPU under lock. */
		mutex_lock(&sew_tp_lock);
		if (num_online_cpus() <= 1) {
			mutex_unlock(&sew_tp_lock);
			pending++;
			continue;
		}
		mutex_unlock(&sew_tp_lock);

		ret = sew_tp_offline_cpu(cpu);
		if (!ret) {
			mutex_lock(&sew_tp_lock);
			/*
			 * Re-check under lock: an -EBUSY retry race or an
			 * external online event must not resurrect a CPU
			 * whose level already moved on.
			 */
			cpumask_set_cpu(cpu, &thermal_paused_cpumask);
			cpumask_set_cpu(cpu, done);
			mutex_unlock(&sew_tp_lock);
		} else if (ret == -EBUSY) {
			pending++;
		} else {
			pr_err("%s:%s Error pausing CPU:%*pbl. err:%d\n",
			       SEW_TP_DRV_NAME, __func__, nr_cpu_ids, mask, ret);
		}
	}

	/* Notify outside sew_tp_lock (blocking chain may sleep / re-take sew_tp_lock). */
	for_each_cpu(cpu, done)
		blocking_notifier_call_chain(&thermal_pause_notifier,
					     SEW_TP_EVENT_PAUSE,
					     (void *)(uintptr_t)cpu);

	free_cpumask_var(done);
	return pending;
}

/*
 * Apply one resume pass over currently paused CPUs intersected with @mask.
 * Mirrors sew_tp_pause_pass: -EBUSY stays pending, hard errors are logged.
 * Notifier runs outside sew_tp_lock for the same reason.
 */
static unsigned int sew_tp_resume_pass(const struct cpumask *mask)
{
	unsigned int cpu, pending = 0;
	cpumask_var_t target, done;

	if (!alloc_cpumask_var(&target, GFP_KERNEL))
		return cpumask_weight(mask);
	if (!alloc_cpumask_var(&done, GFP_KERNEL)) {
		free_cpumask_var(target);
		return cpumask_weight(mask);
	}

	mutex_lock(&sew_tp_lock);
	cpumask_and(target, &thermal_paused_cpumask, mask);
	mutex_unlock(&sew_tp_lock);
	cpumask_clear(done);

	for_each_cpu(cpu, target) {
		int ret = sew_tp_online_cpu(cpu);

		if (!ret) {
			mutex_lock(&sew_tp_lock);
			cpumask_clear_cpu(cpu, &thermal_paused_cpumask);
			cpumask_set_cpu(cpu, done);
			mutex_unlock(&sew_tp_lock);
		} else if (ret == -EBUSY) {
			pending++;
		} else {
			pr_err("%s:%s Error resuming CPU:%*pbl. err:%d\n",
			       SEW_TP_DRV_NAME, __func__, nr_cpu_ids, mask, ret);
		}
	}

	for_each_cpu(cpu, done)
		blocking_notifier_call_chain(&thermal_pause_notifier,
					     SEW_TP_EVENT_RESUME,
					     (void *)(uintptr_t)cpu);

	free_cpumask_var(done);
	free_cpumask_var(target);
	return pending;
}

static void sew_tp_pause_workfn(struct work_struct *work)
{
	struct sew_tp_cdev *tp = container_of(work, struct sew_tp_cdev, pause_work);
	unsigned int tries = SEW_TP_MAX_RETRY;

	/* set_cur_state(1) while a resume is in flight: resume wins. */
	mutex_lock(&sew_tp_lock);
	if (tp->dead || tp->requested_state != 1) {
		mutex_unlock(&sew_tp_lock);
		return;
	}
	mutex_unlock(&sew_tp_lock);

	while (sew_tp_pause_pass(tp->cpus)) {
		mutex_lock(&sew_tp_lock);
		if (tp->dead || tp->requested_state != 1) {
			mutex_unlock(&sew_tp_lock);
			break;
		}
		mutex_unlock(&sew_tp_lock);

		if (!tries--) {
			pr_warn_ratelimited("%s:%s %s: CPUs still pending after %u retries\n",
					    SEW_TP_DRV_NAME, __func__, tp->name,
					    SEW_TP_MAX_RETRY);
			break;
		}
		msleep(SEW_TP_RETRY_DELAY_MS);
	}
}

static void sew_tp_resume_workfn(struct work_struct *work)
{
	struct sew_tp_cdev *tp = container_of(work, struct sew_tp_cdev, resume_work);
	unsigned int tries = SEW_TP_MAX_RETRY;

	/* set_cur_state(0) while a pause is in flight: pause wins. */
	mutex_lock(&sew_tp_lock);
	if (tp->dead || tp->requested_state != 0) {
		mutex_unlock(&sew_tp_lock);
		return;
	}
	mutex_unlock(&sew_tp_lock);

	while (sew_tp_resume_pass(tp->cpus)) {
		mutex_lock(&sew_tp_lock);
		if (tp->dead || tp->requested_state != 0) {
			mutex_unlock(&sew_tp_lock);
			break;
		}
		mutex_unlock(&sew_tp_lock);

		if (!tries--) {
			pr_warn_ratelimited("%s:%s %s: CPUs still pending after %u retries\n",
					    SEW_TP_DRV_NAME, __func__, tp->name,
					    SEW_TP_MAX_RETRY);
			break;
		}
		msleep(SEW_TP_RETRY_DELAY_MS);
	}
}

static int sew_tp_get_max_state(struct thermal_cooling_device *cdev,
			    unsigned long *state)
{
	*state = 1;
	return 0;
}

static int sew_tp_get_cur_state(struct thermal_cooling_device *cdev,
			    unsigned long *state)
{
	struct sew_tp_cdev *tp = cdev->devdata;

	mutex_lock(&sew_tp_lock);
	*state = tp->requested_state;
	mutex_unlock(&sew_tp_lock);
	return 0;
}

static int sew_tp_set_cur_state(struct thermal_cooling_device *cdev,
			    unsigned long state)
{
	struct sew_tp_cdev *tp = cdev->devdata;

	if (state > 1)
		return -EINVAL;

	mutex_lock(&sew_tp_lock);
	if (tp->requested_state == state) {
		mutex_unlock(&sew_tp_lock);
		return 0;
	}
	tp->requested_state = state;
	mutex_unlock(&sew_tp_lock);

	if (state)
		queue_work(system_unbound_wq, &tp->pause_work);
	else
		queue_work(system_unbound_wq, &tp->resume_work);

	return 0;
}

static const struct thermal_cooling_device_ops sew_tp_cdev_ops = {
	.get_max_state = sew_tp_get_max_state,
	.get_cur_state = sew_tp_get_cur_state,
	.set_cur_state = sew_tp_set_cur_state,
};

static unsigned int sew_tp_next_id(void)
{
	struct sew_tp_cdev *tp;
	unsigned int cand;
	bool clash;

	lockdep_assert_held(&sew_tp_lock);
	/*
	 * Allocate the lowest index whose "thermal-pause-%u" name is not
	 * already taken, so a DT numeric alias can never collide with an
	 * auto-assigned id on probe retry or mixed alias/plain DTs.
	 */
	for (cand = 0; cand < 1024; cand++) {
		char name[SEW_TP_CDEV_NAME_LEN];

		snprintf(name, sizeof(name), SEW_TP_CDEV_NAME_FMT, cand);
		clash = false;
		list_for_each_entry(tp, &sew_tp_cdev_list, node) {
			if (!strcmp(tp->name, name)) {
				clash = true;
				break;
			}
		}
		if (!clash)
			break;
	}
	return cand;
}

static int sew_tp_parse_cpus(struct sew_tp_cdev *tp, struct device_node *child)
{
	struct of_phandle_iterator it;
	unsigned int cpu;
	int ret;

	cpumask_clear(tp->cpus);

	ret = of_phandle_iterator_init(&it, child, "qcom,cpus", NULL, 0);
	if (ret)
		return ret;

	while (!(ret = of_phandle_iterator_next(&it))) {
		struct device_node *cpu_np = it.node;

		for_each_possible_cpu(cpu) {
			struct device_node *cn = of_cpu_device_node_get(cpu);

			if (cn == cpu_np)
				cpumask_set_cpu(cpu, tp->cpus);
			of_node_put(cn);
		}
		of_node_put(cpu_np);
	}

	/* of_phandle_iterator_next() ends the list with -ENOENT. */
	if (ret != -ENOENT)
		return ret < 0 ? ret : -EINVAL;

	if (cpumask_empty(tp->cpus))
		return -ENODEV;

	/* Never allow pausing CPU0 through DT either. */
	cpumask_clear_cpu(0, tp->cpus);

	return 0;
}

static bool sew_tp_name_in_use(const char *name)
{
	struct sew_tp_cdev *tp;

	lockdep_assert_held(&sew_tp_lock);
	list_for_each_entry(tp, &sew_tp_cdev_list, node)
		if (!strcmp(tp->name, name))
			return true;
	return false;
}

/* Unregister + free one cdev entry. sew_tp_lock must NOT be held. */
static void sew_tp_release(struct kref *ref)
{
	struct sew_tp_cdev *tp = container_of(ref, struct sew_tp_cdev, ref);

	free_cpumask_var(tp->cpus);
}

static void sew_tp_destroy_cdev(struct sew_tp_cdev *tp)
{
	bool on_list;

	/* Disconnect from thermal core first so no new work can arrive. */
	if (tp->cdev)
		thermal_cooling_device_unregister(tp->cdev);
	tp->cdev = NULL;

	cancel_work_sync(&tp->pause_work);
	cancel_work_sync(&tp->resume_work);
	/* Best effort: bring back every CPU we offlined. */
	sew_tp_resume_pass(tp->cpus);

	mutex_lock(&sew_tp_lock);
	on_list = !list_empty(&tp->node);
	if (on_list)
		list_del_init(&tp->node);
	mutex_unlock(&sew_tp_lock);

	if (on_list)
		kref_put(&tp->ref, sew_tp_release);
}

/*
 * Register one cooling device for child node @child. The child carries
 * "qcom,cdev-alias" (name suffix) and "qcom,cpus" (phandle list pointing
 * at cpu nodes; resolved by matching device_nodes against cpu_possible()
 * exactly like the reference probe loop).
 */
static int sew_tp_register_cdev(struct platform_device *pdev,
			    struct device_node *child)
{
	struct sew_tp_cdev *tp;
	struct thermal_cooling_device *cdev;
	const char *alias = NULL;
	unsigned int alias_id;
	bool have_alias = false;
	int ret;

	tp = devm_kzalloc(&pdev->dev, sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return -ENOMEM;

	if (!alloc_cpumask_var(&tp->cpus, GFP_KERNEL)) {
		devm_kfree(&pdev->dev, tp);
		return -ENOMEM;
	}

	ret = sew_tp_parse_cpus(tp, child);
	if (ret)
		goto free_mask;

	if (!of_property_read_string(child, "qcom,cdev-alias", &alias) &&
	    alias && alias[0]) {
		unsigned long v;

		if (kstrtoul(alias, 0, &v) || v > UINT_MAX) {
			ret = -EINVAL;
			goto free_mask;
		}
		alias_id = (unsigned int)v;
		have_alias = true;
	}

	mutex_lock(&sew_tp_lock);
	if (have_alias) {
		/* Numeric alias requested: reject duplicates explicitly. */
		snprintf(tp->name, sizeof(tp->name), SEW_TP_CDEV_NAME_FMT,
			 alias_id);
		if (sew_tp_name_in_use(tp->name)) {
			mutex_unlock(&sew_tp_lock);
			ret = -EEXIST;
			goto free_mask;
		}
	} else {
		alias_id = sew_tp_next_id();
		snprintf(tp->name, sizeof(tp->name), SEW_TP_CDEV_NAME_FMT,
			 alias_id);
	}
	mutex_unlock(&sew_tp_lock);

	INIT_WORK(&tp->pause_work, sew_tp_pause_workfn);
	INIT_WORK(&tp->resume_work, sew_tp_resume_workfn);
	tp->requested_state = 0;
	kref_init(&tp->ref);
	INIT_LIST_HEAD(&tp->node);

	cdev = thermal_of_cooling_device_register(child, tp->name, tp,
						  &sew_tp_cdev_ops);
	if (IS_ERR(cdev)) {
		ret = PTR_ERR(cdev);
		pr_err("%s:%s Cooling register failed for %s, ret:%d\n",
		       SEW_TP_DRV_NAME, __func__, tp->name, ret);
		goto free_mask;
	}

	tp->cdev = cdev;
	mutex_lock(&sew_tp_lock);
	/* cdev name is unique under sew_tp_lock (checked above); re-check under
	 * the same critical section that publishes the entry. */
	if (sew_tp_name_in_use(tp->name)) {
		mutex_unlock(&sew_tp_lock);
		thermal_cooling_device_unregister(cdev);
		tp->cdev = NULL;
		ret = -EEXIST;
		goto free_mask;
	}
	list_add_tail(&tp->node, &sew_tp_cdev_list);
	mutex_unlock(&sew_tp_lock);

	return 0;

free_mask:
	free_cpumask_var(tp->cpus);
	devm_kfree(&pdev->dev, tp);
	return ret;
}

/*
 * cpuhp online callback: if a paused CPU comes back online from outside
 * (e.g. userspace echo 1 > .../online), re-queue the pause work so the
 * thermal level is not silently lost. Matches thermal_pause_hp_online().
 */
static int sew_tp_hp_online(unsigned int cpu)
{
	struct sew_tp_cdev *tp = NULL, *it;

	mutex_lock(&sew_tp_lock);
	list_for_each_entry(it, &sew_tp_cdev_list, node) {
		if (it->dead)
			continue;
		if (!cpumask_test_cpu(cpu, it->cpus))
			continue;
		if (!cpumask_test_cpu(cpu, &thermal_paused_cpumask))
			continue;
		if (it->requested_state != 1)
			continue;
		kref_get(&it->ref);
		tp = it;
		break;
	}
	mutex_unlock(&sew_tp_lock);

	if (!tp)
		return 0;

	/* Outside sew_tp_lock; drop our ref after queueing. */
	if (!tp->dead)
		queue_work(system_unbound_wq, &tp->pause_work);
	kref_put(&tp->ref, sew_tp_release);

	return 0;
}

static int sew_tp_hp_offline(unsigned int cpu)
{
	/* No action: offline (ours or external) needs no repair. */
	return 0;
}

static enum cpuhp_state sew_tp_hp_state;

static int thermal_pause_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct device_node *child;
	int ret;

	if (!np)
		return -ENODEV;

	child = of_get_next_available_child(np, NULL);
	if (!child)
		return -ENODEV;

	while (child) {
		struct device_node *next =
			of_get_next_available_child(np, child);

		ret = sew_tp_register_cdev(pdev, child);
		if (ret)
			dev_warn(&pdev->dev,
				 "skip child %pOF (ret=%d)\n", child, ret);
		of_node_put(child);
		child = next;
	}

	mutex_lock(&sew_tp_lock);
	ret = list_empty(&sew_tp_cdev_list) ? -ENODEV : 0;
	mutex_unlock(&sew_tp_lock);
	if (ret)
		goto err_no_cdev;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, SEW_TP_DRV_NAME ":online",
				sew_tp_hp_online, sew_tp_hp_offline);
	if (ret < 0)
		goto err_no_cdev;
	sew_tp_hp_state = ret;

	return 0;

err_no_cdev:
	/* Unwind everything this probe registered so retry is clean. */
	mutex_lock(&sew_tp_lock);
	while (!list_empty(&sew_tp_cdev_list)) {
		struct sew_tp_cdev *tp =
			list_first_entry(&sew_tp_cdev_list, struct sew_tp_cdev, node);

		mutex_unlock(&sew_tp_lock);
		sew_tp_destroy_cdev(tp);
		mutex_lock(&sew_tp_lock);
	}
	mutex_unlock(&sew_tp_lock);
	return ret;
}

static int thermal_pause_remove(struct platform_device *pdev)
{
	struct sew_tp_cdev *tp, *tmp;
	LIST_HEAD(gone);

	/*
	 * Disconnect the cpuhp source first, then mark entries dead under
	 * lock so in-flight work/hp callbacks bail out instead of touching
	 * a cdev that is being torn down.
	 */
	if (sew_tp_hp_state) {
		__cpuhp_remove_state(sew_tp_hp_state, false);
		sew_tp_hp_state = 0;
	}

	mutex_lock(&sew_tp_lock);
	list_for_each_entry(tp, &sew_tp_cdev_list, node)
		tp->dead = true;
	list_splice_init(&sew_tp_cdev_list, &gone);
	mutex_unlock(&sew_tp_lock);

	/*
	 * With the entries off the global list (and dead-flagged), no new
	 * thermal-core or hp callback can find them. Unregister first to cut
	 * the work source, then cancel work, then resume CPUs.
	 */
	list_for_each_entry_safe(tp, tmp, &gone, node)
		sew_tp_destroy_cdev(tp);

	return 0;
}

static const struct of_device_id thermal_pause_match[] = {
	{ .compatible = "qcom,thermal-pause" },
	{ }
};
MODULE_DEVICE_TABLE(of, thermal_pause_match);

static struct platform_driver thermal_pause_driver = {
	.probe = thermal_pause_probe,
	.remove = thermal_pause_remove,
	.driver = {
		.name = SEW_TP_DRV_NAME,
		.of_match_table = thermal_pause_match,
	},
};

module_platform_driver(thermal_pause_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Qualcomm thermal CPU pause cooling device (5.15 port, hotplug-based)");
MODULE_AUTHOR("OS4 port");
