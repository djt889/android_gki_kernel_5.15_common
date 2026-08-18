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

#ifndef ZSTDH_OPT_H
#define ZSTDH_OPT_H

#include "zstd_compress_internal.h"

#if !defined(ZSTDH_EXCLUDE_BTLAZY2_BLOCK_COMPRESSOR) \
 || !defined(ZSTDH_EXCLUDE_BTOPT_BLOCK_COMPRESSOR) \
 || !defined(ZSTDH_EXCLUDE_BTULTRA_BLOCK_COMPRESSOR)
/* used in ZSTDH_loadDictionaryContent() */
void ZSTDH_updateTree(ZSTDH_MatchState_t* ms, const BYTE* ip, const BYTE* iend);
#endif

#ifndef ZSTDH_EXCLUDE_BTOPT_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_btopt(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btopt_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btopt_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_BTOPT ZSTDH_compressBlock_btopt
#define ZSTDH_COMPRESSBLOCK_BTOPT_DICTMATCHSTATE ZSTDH_compressBlock_btopt_dictMatchState
#define ZSTDH_COMPRESSBLOCK_BTOPT_EXTDICT ZSTDH_compressBlock_btopt_extDict
#else
#define ZSTDH_COMPRESSBLOCK_BTOPT NULL
#define ZSTDH_COMPRESSBLOCK_BTOPT_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_BTOPT_EXTDICT NULL
#endif

#ifndef ZSTDH_EXCLUDE_BTULTRA_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_btultra(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btultra_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btultra_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

        /* note : no btultra2 variant for extDict nor dictMatchState,
         * because btultra2 is not meant to work with dictionaries
         * and is only specific for the first block (no prefix) */
size_t ZSTDH_compressBlock_btultra2(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_BTULTRA ZSTDH_compressBlock_btultra
#define ZSTDH_COMPRESSBLOCK_BTULTRA_DICTMATCHSTATE ZSTDH_compressBlock_btultra_dictMatchState
#define ZSTDH_COMPRESSBLOCK_BTULTRA_EXTDICT ZSTDH_compressBlock_btultra_extDict
#define ZSTDH_COMPRESSBLOCK_BTULTRA2 ZSTDH_compressBlock_btultra2
#else
#define ZSTDH_COMPRESSBLOCK_BTULTRA NULL
#define ZSTDH_COMPRESSBLOCK_BTULTRA_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_BTULTRA_EXTDICT NULL
#define ZSTDH_COMPRESSBLOCK_BTULTRA2 NULL
#endif

#endif /* ZSTDH_OPT_H */
