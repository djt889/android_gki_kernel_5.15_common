/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/trace/events/vip_sched.h - trace events for kernel/sched/vip_sched.c
 *
 * 1:1 port of the ten TRACE_EVENTs defined by the Xiaomi dada OS4
 * vip_sched.ko (vermagic 6.6.57-android15-8, source path recorded in the
 * module string table as
 * kernel/sched/xiaomi_sched/common/vip_sched/vip_sched.c).
 *
 * Field names, ordering and print_fmt strings are byte-identical to the
 * .rodata/.BTF of the original module (evidence:
 * .omz/research/sess_d9452f03-.../raw/re-vip-sched.txt, strings section:
 * print_fmt_<name> / trace_event_fields_<name> entries).  TP_PROTO
 * signatures were recovered from the __traceiter_<name> disassembly and
 * the bpf_trace_runN arity (run1..run7) called by each perf_trace_<name>.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM vip_sched

#if !defined(_TRACE_VIP_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VIP_SCHED_H

#include <linux/tracepoint.h>

struct task_struct;
struct vip_rq;

/*
 * dada: emitted by vip_balance_commit's source-cpu scan (find_emerg_cpu)
 * for the chosen congested vip rq: cpu, its level state (0/1/2) and the
 * number of vip tasks queued on it.
 */
TRACE_EVENT(find_emerg_cpu,

	TP_PROTO(int cpu, int vip_preempt, int nr_running),

	TP_ARGS(cpu, vip_preempt, nr_running),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, vip_preempt)
		__field(int, nr_running)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->vip_preempt = vip_preempt;
		__entry->nr_running = nr_running;
	),

	TP_printk("emerg=%d preempt=%d nr=%d",
		  __entry->cpu, __entry->vip_preempt,
		  __entry->nr_running)
);

/*
 * dada: emitted once at the end of find_vip_cpu(), both on success and
 * on the -1 exits.  mask is the candidate mask actually scanned (the
 * congestion candidate set when no idle cpu was found), target is the
 * returned cpu (-1 on failure), repick is 1 when the prefer-mask pass
 * failed and the full allowed mask was retried.
 */
TRACE_EVENT(find_vip_cpu,

	TP_PROTO(pid_t pid, unsigned long mask, int cpu, bool repick,
		 unsigned long allowed_mask, unsigned long halt_mask,
		 unsigned long rtg_mask),

	TP_ARGS(pid, mask, cpu, repick, allowed_mask, halt_mask, rtg_mask),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(unsigned long, mask)
		__field(int, cpu)
		__field(bool, repick)
		__field(unsigned long, allowed_mask)
		__field(unsigned long, halt_mask)
		__field(unsigned long, rtg_mask)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->mask = mask;
		__entry->cpu = cpu;
		__entry->repick = repick;
		__entry->allowed_mask = allowed_mask;
		__entry->halt_mask = halt_mask;
		__entry->rtg_mask = rtg_mask;
	),

	TP_printk("pid=%d mask=0x%lx target=%d repick=%d allowed_mask=0x%lx halt_mask=0x%lx rtg_mask=0x%lx",
		  __entry->pid, __entry->mask, __entry->cpu,
		  __entry->repick, __entry->allowed_mask,
		  __entry->halt_mask, __entry->rtg_mask)
);

/* dada: kick_vip_balance() fired an IPI at dst_cpu for a vip task. */
TRACE_EVENT(kick_vip_balance,

	TP_PROTO(int src_cpu, int dst_cpu, pid_t pid, bool kick_idle),

	TP_ARGS(src_cpu, dst_cpu, pid, kick_idle),

	TP_STRUCT__entry(
		__field(int, src_cpu)
		__field(int, dst_cpu)
		__field(pid_t, pid)
		__field(bool, kick_idle)
	),

	TP_fast_assign(
		__entry->src_cpu = src_cpu;
		__entry->dst_cpu = dst_cpu;
		__entry->pid = pid;
		__entry->kick_idle = kick_idle;
	),

	TP_printk("src_cpu=%d dst_cpu=%d task=%d%s",
		  __entry->src_cpu, __entry->dst_cpu, __entry->pid,
		  __entry->kick_idle ? " idle" : "")
);

/* dada: vip_balance_commit() migrated a vip task src_cpu -> dst_cpu. */
TRACE_EVENT(vip_balance,

	TP_PROTO(int src_cpu, int dst_cpu, pid_t pid),

	TP_ARGS(src_cpu, dst_cpu, pid),

	TP_STRUCT__entry(
		__field(int, src_cpu)
		__field(int, dst_cpu)
		__field(pid_t, pid)
	),

	TP_fast_assign(
		__entry->src_cpu = src_cpu;
		__entry->dst_cpu = dst_cpu;
		__entry->pid = pid;
	),

	TP_printk("src_cpu=%d dst_cpu=%d task=%d",
		  __entry->src_cpu, __entry->dst_cpu, __entry->pid)
);

/*
 * dada: enqueue_vip_task()/dequeue_vip_task() moved a task on/off a
 * per-cpu vip queue.  dada passes the target vip_rq and lets the trace
 * class read cpu/nr_running from it; we do the same through TP_fast_assign
 * so the print_fmt stays identical ("%s: cpu=%d h_prio=%d nr_runing=%d
 * pid=%d", note dada's original "nr_runing" typo is preserved).
 */
TRACE_EVENT(queue_vip_task,

	TP_PROTO(bool enqueue, struct vip_rq *vrq, int h_prio, pid_t pid),

	TP_ARGS(enqueue, vrq, h_prio, pid),

	TP_STRUCT__entry(
		__field(bool, enqueue)
		__field(int, cpu)
		__field(int, h_prio)
		__field(int, nr_running)
		__field(pid_t, pid)
	),

	TP_fast_assign(
		__entry->enqueue = enqueue;
		__entry->cpu = vrq->cpu;
		__entry->h_prio = h_prio;
		__entry->nr_running = vrq->nr_queued;
		__entry->pid = pid;
	),

	TP_printk("%s: cpu=%d h_prio=%d nr_runing=%d pid=%d",
		  __entry->enqueue ? "enq" : "deq",
		  __entry->cpu, __entry->h_prio,
		  __entry->nr_running, __entry->pid)
);

/* dada: set_vip_prio_locked() wrote a new vip priority. */
TRACE_EVENT(set_vip_prio,

	TP_PROTO(pid_t pid, int prio, int orig_prio),

	TP_ARGS(pid, prio, orig_prio),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(int, prio)
		__field(int, orig_prio)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->prio = prio;
		__entry->orig_prio = orig_prio;
	),

	TP_printk("pid=%d prio=%d orig_prio=%d",
		  __entry->pid, __entry->prio, __entry->orig_prio)
);

/* dada: vip_sched_check_preempt_wakeup() forces wakeup preemption. */
TRACE_EVENT(vip_preempt_curr,

	TP_PROTO(pid_t curr_pid, pid_t pid, int vip_prio),

	TP_ARGS(curr_pid, pid, vip_prio),

	TP_STRUCT__entry(
		__field(pid_t, curr_pid)
		__field(pid_t, pid)
		__field(int, vip_prio)
	),

	TP_fast_assign(
		__entry->curr_pid = curr_pid;
		__entry->pid = pid;
		__entry->vip_prio = vip_prio;
	),

	TP_printk("curr=%d vip=%d prio=%d",
		  __entry->curr_pid, __entry->pid, __entry->vip_prio)
);

/*
 * dada: vip_sched_replace_next_task_fair() attempted/completed the CFS
 * pick replacement.  wait_time is the staleness (ns) of the candidate
 * computed from its runnable stamps; p carries the pid.  See the
 * [RE-AMBIG] note in vip_sched.c on the mask argument.
 */
TRACE_EVENT(vip_replace_next_task,

	TP_PROTO(struct task_struct *p, int vip_prio, unsigned long mask,
		 int orig_pid, unsigned long long wait_time),

	TP_ARGS(p, vip_prio, mask, orig_pid, wait_time),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(int, vip_prio)
		__field(unsigned long, mask)
		__field(int, orig_pid)
		__field(unsigned long long, wait_time)
	),

	TP_fast_assign(
		__entry->pid = p ? p->pid : -1;
		__entry->vip_prio = vip_prio;
		__entry->mask = mask;
		__entry->orig_pid = orig_pid;
		__entry->wait_time = wait_time;
	),

	TP_printk("pid=%d vip_prio=%d mask=0x%lx orig_pid=%d wait_time=%llu",
		  __entry->pid, __entry->vip_prio, __entry->mask,
		  __entry->orig_pid, __entry->wait_time)
);

/*
 * dada: vip_sched_schedule() context-switch bookkeeping - the level
 * state machine result (0/1/2) plus the utilization of the incoming
 * task (plat_task_util).
 */
TRACE_EVENT(vip_schedule,

	TP_PROTO(int p_pid, int p_prio, int n_pid, int n_prio,
		 int vip_preempt, unsigned long n_util),

	TP_ARGS(p_pid, p_prio, n_pid, n_prio, vip_preempt, n_util),

	TP_STRUCT__entry(
		__field(int, p_pid)
		__field(int, p_prio)
		__field(int, n_pid)
		__field(int, n_prio)
		__field(int, vip_preempt)
		__field(unsigned long, n_util)
	),

	TP_fast_assign(
		__entry->p_pid = p_pid;
		__entry->p_prio = p_prio;
		__entry->n_pid = n_pid;
		__entry->n_prio = n_prio;
		__entry->vip_preempt = vip_preempt;
		__entry->n_util = n_util;
	),

	TP_printk("prev=%d p_prio=%d next=%d n_prio=%d preempt=%d n_util=%lu",
		  __entry->p_pid, __entry->p_prio, __entry->n_pid,
		  __entry->n_prio, __entry->vip_preempt, __entry->n_util)
);

/* dada: __can_migrate_vip() verdict for a vip migration candidate. */
TRACE_EVENT(can_migrate_vip,

	TP_PROTO(int cpu, pid_t pid, int prio, bool migrate, int reason),

	TP_ARGS(cpu, pid, prio, migrate, reason),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(pid_t, pid)
		__field(int, prio)
		__field(bool, migrate)
		__field(int, reason)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->pid = pid;
		__entry->prio = prio;
		__entry->migrate = migrate;
		__entry->reason = reason;
	),

	TP_printk("cpu=%d pid=%d prio=%d migrate=%d reason=%d",
		  __entry->cpu, __entry->pid, __entry->prio,
		  __entry->migrate, __entry->reason)
);

#endif /* _TRACE_VIP_SCHED_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
