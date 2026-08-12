/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_SLABD_H
#define _MM_SLABD_H

#include <linux/gfp.h>

struct mem_cgroup;

bool kshrink_slabd_queue(gfp_t gfp_mask, int nid,
			      struct mem_cgroup *memcg, int priority);

#endif /* _MM_SLABD_H */
