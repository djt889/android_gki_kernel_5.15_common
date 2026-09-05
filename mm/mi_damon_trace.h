/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mi_damon_trace.h - tracepoint for the mi_damon cold-page reclaim port.
 *
 * Mirrors the trace event embedded in dada OS4 mi_damon.ko (6.6.57,
 * scmversion g32a50a34de2b): system name "mi_damon", event
 * "damon_aggregated", print format
 *   "target_id=%lu nr_regions=%u %lu-%lu: %u %u"
 * Field nr_accesses is reported in permil of the max access rate
 * (1000 * last_nr_accesses / (aggr_interval / sample_interval)), matching
 * the permil-based access_pattern units of the original module.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM mi_damon

#if !defined(_MI_DAMON_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MI_DAMON_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(damon_aggregated,

	TP_PROTO(unsigned long target_id, unsigned int nr_regions,
		 unsigned long start, unsigned long end,
		 unsigned int nr_accesses_permil, unsigned int age),

	TP_ARGS(target_id, nr_regions, start, end, nr_accesses_permil, age),

	TP_STRUCT__entry(
		__field(unsigned long, target_id)
		__field(unsigned int, nr_regions)
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned int, nr_accesses_permil)
		__field(unsigned int, age)
	),

	TP_fast_assign(
		__entry->target_id = target_id;
		__entry->nr_regions = nr_regions;
		__entry->start = start;
		__entry->end = end;
		__entry->nr_accesses_permil = nr_accesses_permil;
		__entry->age = age;
	),

	TP_printk("target_id=%lu nr_regions=%u %lu-%lu: %u %u",
		__entry->target_id, __entry->nr_regions,
		__entry->start, __entry->end,
		__entry->nr_accesses_permil, __entry->age)
);

#endif /* _MI_DAMON_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mi_damon_trace
#include <trace/define_trace.h>
