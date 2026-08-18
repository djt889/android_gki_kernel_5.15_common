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

#ifndef ZSTDH_FAST_H
#define ZSTDH_FAST_H

#include "../common/mem.h"      /* U32 */
#include "zstd_compress_internal.h"

void ZSTDH_fillHashTable(ZSTDH_MatchState_t* ms,
                        void const* end, ZSTDH_dictTableLoadMethod_e dtlm,
                        ZSTDH_tableFillPurpose_e tfp);
size_t ZSTDH_compressBlock_fast(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_fast_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_fast_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#endif /* ZSTDH_FAST_H */
