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

#ifndef ZSTDH_DOUBLE_FAST_H
#define ZSTDH_DOUBLE_FAST_H

#include "../common/mem.h"      /* U32 */
#include "zstd_compress_internal.h"     /* ZSTDH_CCtx, size_t */

#ifndef ZSTDH_EXCLUDE_DFAST_BLOCK_COMPRESSOR

void ZSTDH_fillDoubleHashTable(ZSTDH_MatchState_t* ms,
                              void const* end, ZSTDH_dictTableLoadMethod_e dtlm,
                              ZSTDH_tableFillPurpose_e tfp);

size_t ZSTDH_compressBlock_doubleFast(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_doubleFast_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_doubleFast_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST ZSTDH_compressBlock_doubleFast
#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST_DICTMATCHSTATE ZSTDH_compressBlock_doubleFast_dictMatchState
#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST_EXTDICT ZSTDH_compressBlock_doubleFast_extDict
#else
#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST NULL
#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_DOUBLEFAST_EXTDICT NULL
#endif /* ZSTDH_EXCLUDE_DFAST_BLOCK_COMPRESSOR */

#endif /* ZSTDH_DOUBLE_FAST_H */
