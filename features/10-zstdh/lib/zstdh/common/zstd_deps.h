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

/*
 * This file provides common libc dependencies that zstd requires.
 * The purpose is to allow replacing this file with a custom implementation
 * to compile zstd without libc support.
 */

/* Need:
 * NULL
 * INT_MAX
 * UINT_MAX
 * ZSTDH_memcpy()
 * ZSTDH_memset()
 * ZSTDH_memmove()
 */
#ifndef ZSTDH_DEPS_COMMON
#define ZSTDH_DEPS_COMMON

#include <linux/limits.h>
#include <linux/stddef.h>

#define ZSTDH_memcpy(d,s,n) __builtin_memcpy((d),(s),(n))
#define ZSTDH_memmove(d,s,n) __builtin_memmove((d),(s),(n))
#define ZSTDH_memset(d,s,n) __builtin_memset((d),(s),(n))

#endif /* ZSTDH_DEPS_COMMON */

/*
 * Define malloc as always failing. That means the user must
 * either use ZSTDH_customMem or statically allocate memory.
 * Need:
 * ZSTDH_malloc()
 * ZSTDH_free()
 * ZSTDH_calloc()
 */
#ifdef ZSTDH_DEPS_NEED_MALLOC
#ifndef ZSTDH_DEPS_MALLOC
#define ZSTDH_DEPS_MALLOC

#define ZSTDH_malloc(s) ({ (void)(s); NULL; })
#define ZSTDH_free(p) ((void)(p))
#define ZSTDH_calloc(n,s) ({ (void)(n); (void)(s); NULL; })

#endif /* ZSTDH_DEPS_MALLOC */
#endif /* ZSTDH_DEPS_NEED_MALLOC */

/*
 * Provides 64-bit math support.
 * Need:
 * U64 ZSTDH_div64(U64 dividend, U32 divisor)
 */
#ifdef ZSTDH_DEPS_NEED_MATH64
#ifndef ZSTDH_DEPS_MATH64
#define ZSTDH_DEPS_MATH64

#include <linux/math64.h>

static uint64_t ZSTDH_div64(uint64_t dividend, uint32_t divisor) {
  return div_u64(dividend, divisor);
}

#endif /* ZSTDH_DEPS_MATH64 */
#endif /* ZSTDH_DEPS_NEED_MATH64 */

/*
 * This is only requested when DEBUGLEVEL >= 1, meaning
 * it is disabled in production.
 * Need:
 * assert()
 */
#ifdef ZSTDH_DEPS_NEED_ASSERT
#ifndef ZSTDH_DEPS_ASSERT
#define ZSTDH_DEPS_ASSERT

#include <linux/kernel.h>

#define assert(x) WARN_ON(!(x))

#endif /* ZSTDH_DEPS_ASSERT */
#endif /* ZSTDH_DEPS_NEED_ASSERT */

/*
 * This is only requested when DEBUGLEVEL >= 2, meaning
 * it is disabled in production.
 * Need:
 * ZSTDH_DEBUG_PRINT()
 */
#ifdef ZSTDH_DEPS_NEED_IO
#ifndef ZSTDH_DEPS_IO
#define ZSTDH_DEPS_IO

#include <linux/printk.h>

#define ZSTDH_DEBUG_PRINT(...) pr_debug(__VA_ARGS__)

#endif /* ZSTDH_DEPS_IO */
#endif /* ZSTDH_DEPS_NEED_IO */

/*
 * Only requested when MSAN is enabled.
 * Need:
 * intptr_t
 */
#ifdef ZSTDH_DEPS_NEED_STDINT
#ifndef ZSTDH_DEPS_STDINT
#define ZSTDH_DEPS_STDINT

/* intptr_t already provided by ZSTDH_DEPS_COMMON */

#endif /* ZSTDH_DEPS_STDINT */
#endif /* ZSTDH_DEPS_NEED_STDINT */
