/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

/* This file provides custom allocation primitives
 */

#define ZSTDH_DEPS_NEED_MALLOC
#include "zstd_deps.h"   /* ZSTDH_malloc, ZSTDH_calloc, ZSTDH_free, ZSTDH_memset */

#include "compiler.h" /* MEM_STATIC */
#define ZSTDH_STATIC_LINKING_ONLY
#include <linux/zstdh.h> /* ZSTDH_customMem */

#ifndef ZSTDH_ALLOCATIONS_H
#define ZSTDH_ALLOCATIONS_H

/* custom memory allocation functions */

MEM_STATIC void* ZSTDH_customMalloc(size_t size, ZSTDH_customMem customMem)
{
    if (customMem.customAlloc)
        return customMem.customAlloc(customMem.opaque, size);
    return ZSTDH_malloc(size);
}

MEM_STATIC void* ZSTDH_customCalloc(size_t size, ZSTDH_customMem customMem)
{
    if (customMem.customAlloc) {
        /* calloc implemented as malloc+memset;
         * not as efficient as calloc, but next best guess for custom malloc */
        void* const ptr = customMem.customAlloc(customMem.opaque, size);
        ZSTDH_memset(ptr, 0, size);
        return ptr;
    }
    return ZSTDH_calloc(1, size);
}

MEM_STATIC void ZSTDH_customFree(void* ptr, ZSTDH_customMem customMem)
{
    if (ptr!=NULL) {
        if (customMem.customFree)
            customMem.customFree(customMem.opaque, ptr);
        else
            ZSTDH_free(ptr);
    }
}

#endif /* ZSTDH_ALLOCATIONS_H */
