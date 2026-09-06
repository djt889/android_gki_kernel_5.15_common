/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xr_qs tracepoints - 5.15 port of the Xiaomi OS4 xr_qs.ko ("OS-CPU QOS
 * sched Driver", Shaohua Fan <fanshaohua@xiaomi.com>) private trace
 * events. Names and field sets preserved from the 6.6.57 binary.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xr_qs

#if !defined(_TRACE_XR_QS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XR_QS_H

#include <linux/tracepoint.h>

/* rtg group changes: task=%d grp[%d]->grp[%d] ret=%d */
DECLARE_EVENT_CLASS(qs_rtg_grp_tpl,
	TP_PROTO(int pid, int orig_grp, int new_grp, int ret),
	TP_ARGS(pid, orig_grp, new_grp, ret),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, orig_grp)
		__field(int, new_grp)
		__field(int, ret)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->orig_grp = orig_grp;
		__entry->new_grp = new_grp;
		__entry->ret = ret;
	),
	TP_printk("task=%d grp[%d]->grp[%d] ret=%d",
		  __entry->pid, __entry->orig_grp,
		  __entry->new_grp, __entry->ret)
);
DEFINE_EVENT(qs_rtg_grp_tpl, qs_set_rtg_grp,
	TP_PROTO(int pid, int orig_grp, int new_grp, int ret),
	TP_ARGS(pid, orig_grp, new_grp, ret));
DEFINE_EVENT(qs_rtg_grp_tpl, qs_exchange_rtg_grp,
	TP_PROTO(int pid, int orig_grp, int new_grp, int ret),
	TP_ARGS(pid, orig_grp, new_grp, ret));
DEFINE_EVENT(qs_rtg_grp_tpl, qs_move_rtg_grp,
	TP_PROTO(int pid, int orig_grp, int new_grp, int ret),
	TP_ARGS(pid, orig_grp, new_grp, ret));

/* qos skip rtg grp: task=%d grp[%d]->grp[%d] */
TRACE_EVENT(qs_skip_rtg_grp,
	TP_PROTO(int pid, int orig_grp, int new_grp),
	TP_ARGS(pid, orig_grp, new_grp),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, orig_grp)
		__field(int, new_grp)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->orig_grp = orig_grp;
		__entry->new_grp = new_grp;
	),
	TP_printk("task=%d grp[%d]->grp[%d]",
		  __entry->pid, __entry->orig_grp, __entry->new_grp)
);

/* qos restore rtg grp: pid=%d */
TRACE_EVENT(qs_restore_rtg_grp,
	TP_PROTO(int pid),
	TP_ARGS(pid),
	TP_STRUCT__entry(
		__field(int, pid)
	),
	TP_fast_assign(
		__entry->pid = pid;
	),
	TP_printk("pid=%d", __entry->pid)
);

/* qos set rt sched: pid=%d policy=%u prio=%d */
DECLARE_EVENT_CLASS(qs_rt_sched_tpl,
	TP_PROTO(int pid, unsigned int policy, int prio),
	TP_ARGS(pid, policy, prio),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned int, policy)
		__field(int, prio)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->policy = policy;
		__entry->prio = prio;
	),
	TP_printk("pid=%d policy=%u prio=%d",
		  __entry->pid, __entry->policy, __entry->prio)
);
DEFINE_EVENT(qs_rt_sched_tpl, qs_set_rt_sched,
	TP_PROTO(int pid, unsigned int policy, int prio),
	TP_ARGS(pid, policy, prio));
DEFINE_EVENT(qs_rt_sched_tpl, qs_restore_rt_sched,
	TP_PROTO(int pid, unsigned int policy, int prio),
	TP_ARGS(pid, policy, prio));

/* qos skip rt sched: pid=%d policy=%u old_prio=%d new_prio=%d */
TRACE_EVENT(qs_skip_rt_sched,
	TP_PROTO(int pid, unsigned int policy, int old_prio, int new_prio),
	TP_ARGS(pid, policy, old_prio, new_prio),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned int, policy)
		__field(int, old_prio)
		__field(int, new_prio)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->policy = policy;
		__entry->old_prio = old_prio;
		__entry->new_prio = new_prio;
	),
	TP_printk("pid=%d policy=%u old_prio=%d new_prio=%d",
		  __entry->pid, __entry->policy,
		  __entry->old_prio, __entry->new_prio)
);

/* qos update rt sched: pid=%d policy=%u qos=%u prio=%d */
TRACE_EVENT(qs_update_rt_sched,
	TP_PROTO(int pid, unsigned int policy, unsigned int qos, int prio),
	TP_ARGS(pid, policy, qos, prio),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned int, policy)
		__field(unsigned int, qos)
		__field(int, prio)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->policy = policy;
		__entry->qos = qos;
		__entry->prio = prio;
	),
	TP_printk("pid=%d policy=%u qos=%u prio=%d",
		  __entry->pid, __entry->policy, __entry->qos, __entry->prio)
);

/* qos correct rt sched: pid=%d prio=%d */
TRACE_EVENT(qs_correct_rt_sched,
	TP_PROTO(int pid, int prio),
	TP_ARGS(pid, prio),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, prio)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->prio = prio;
	),
	TP_printk("pid=%d prio=%d", __entry->pid, __entry->prio)
);

/* qos set vip sched: from=%d to=%d */
TRACE_EVENT(qs_set_vip_sched,
	TP_PROTO(int from, int to),
	TP_ARGS(from, to),
	TP_STRUCT__entry(
		__field(int, from)
		__field(int, to)
	),
	TP_fast_assign(
		__entry->from = from;
		__entry->to = to;
	),
	TP_printk("from=%d to=%d", __entry->from, __entry->to)
);

/* qos reset vip sched: pid=%d */
TRACE_EVENT(qs_reset_vip_sched,
	TP_PROTO(int pid),
	TP_ARGS(pid),
	TP_STRUCT__entry(
		__field(int, pid)
	),
	TP_fast_assign(
		__entry->pid = pid;
	),
	TP_printk("pid=%d", __entry->pid)
);

/* qos sched binder preset: pid=%d */
TRACE_EVENT(qs_binder_preset,
	TP_PROTO(int pid),
	TP_ARGS(pid),
	TP_STRUCT__entry(
		__field(int, pid)
	),
	TP_fast_assign(
		__entry->pid = pid;
	),
	TP_printk("pid=%d", __entry->pid)
);

/* speedlock set: pid=%d, vip_prio=%d, sem=%lu */
TRACE_EVENT(sl_set,
	TP_PROTO(int pid, int prio, unsigned long sem),
	TP_ARGS(pid, prio, sem),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, prio)
		__field(unsigned long, sem)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->prio = prio;
		__entry->sem = sem;
	),
	TP_printk("pid=%d, vip_prio=%d, sem=%lu",
		  __entry->pid, __entry->prio, __entry->sem)
);

/* speedlock reset: pid=%d, sem=%lu */
TRACE_EVENT(sl_reset,
	TP_PROTO(int pid, unsigned long sem),
	TP_ARGS(pid, sem),
	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned long, sem)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__entry->sem = sem;
	),
	TP_printk("pid=%d, sem=%lu", __entry->pid, __entry->sem)
);

/* speedlock timeout: pid=%d */
TRACE_EVENT(sl_timeout,
	TP_PROTO(int pid),
	TP_ARGS(pid),
	TP_STRUCT__entry(
		__field(int, pid)
	),
	TP_fast_assign(
		__entry->pid = pid;
	),
	TP_printk("pid=%d", __entry->pid)
);

#endif /* _TRACE_XR_QS_H */

/* GKI's define_trace.h defaults to trace/hooks; keep the events location */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/events

/* This part must be outside protection */
#include <trace/define_trace.h>
