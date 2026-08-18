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

#ifndef ZSTDH_LAZY_H
#define ZSTDH_LAZY_H

#include "zstd_compress_internal.h"

/*
 * Dedicated Dictionary Search Structure bucket log. In the
 * ZSTDH_dedicatedDictSearch mode, the hashTable has
 * 2 ** ZSTDH_LAZY_DDSS_BUCKET_LOG entries in each bucket, rather than just
 * one.
 */
#define ZSTDH_LAZY_DDSS_BUCKET_LOG 2

#define ZSTDH_ROW_HASH_TAG_BITS 8        /* nb bits to use for the tag */

#if !defined(ZSTDH_EXCLUDE_GREEDY_BLOCK_COMPRESSOR) \
 || !defined(ZSTDH_EXCLUDE_LAZY_BLOCK_COMPRESSOR) \
 || !defined(ZSTDH_EXCLUDE_LAZY2_BLOCK_COMPRESSOR) \
 || !defined(ZSTDH_EXCLUDE_BTLAZY2_BLOCK_COMPRESSOR)
U32 ZSTDH_insertAndFindFirstIndex(ZSTDH_MatchState_t* ms, const BYTE* ip);
void ZSTDH_row_update(ZSTDH_MatchState_t* const ms, const BYTE* ip);

void ZSTDH_dedicatedDictSearch_lazy_loadDictionary(ZSTDH_MatchState_t* ms, const BYTE* const ip);

void ZSTDH_preserveUnsortedMark (U32* const table, U32 const size, U32 const reducerValue);  /*! used in ZSTDH_reduceIndex(). preemptively increase value of ZSTDH_DUBT_UNSORTED_MARK */
#endif

#ifndef ZSTDH_EXCLUDE_GREEDY_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_greedy(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_dictMatchState_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_dedicatedDictSearch(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_dedicatedDictSearch_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_greedy_extDict_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_GREEDY ZSTDH_compressBlock_greedy
#define ZSTDH_COMPRESSBLOCK_GREEDY_ROW ZSTDH_compressBlock_greedy_row
#define ZSTDH_COMPRESSBLOCK_GREEDY_DICTMATCHSTATE ZSTDH_compressBlock_greedy_dictMatchState
#define ZSTDH_COMPRESSBLOCK_GREEDY_DICTMATCHSTATE_ROW ZSTDH_compressBlock_greedy_dictMatchState_row
#define ZSTDH_COMPRESSBLOCK_GREEDY_DEDICATEDDICTSEARCH ZSTDH_compressBlock_greedy_dedicatedDictSearch
#define ZSTDH_COMPRESSBLOCK_GREEDY_DEDICATEDDICTSEARCH_ROW ZSTDH_compressBlock_greedy_dedicatedDictSearch_row
#define ZSTDH_COMPRESSBLOCK_GREEDY_EXTDICT ZSTDH_compressBlock_greedy_extDict
#define ZSTDH_COMPRESSBLOCK_GREEDY_EXTDICT_ROW ZSTDH_compressBlock_greedy_extDict_row
#else
#define ZSTDH_COMPRESSBLOCK_GREEDY NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_ROW NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_DICTMATCHSTATE_ROW NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_DEDICATEDDICTSEARCH NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_DEDICATEDDICTSEARCH_ROW NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_EXTDICT NULL
#define ZSTDH_COMPRESSBLOCK_GREEDY_EXTDICT_ROW NULL
#endif

#ifndef ZSTDH_EXCLUDE_LAZY_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_lazy(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_dictMatchState_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_dedicatedDictSearch(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_dedicatedDictSearch_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy_extDict_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_LAZY ZSTDH_compressBlock_lazy
#define ZSTDH_COMPRESSBLOCK_LAZY_ROW ZSTDH_compressBlock_lazy_row
#define ZSTDH_COMPRESSBLOCK_LAZY_DICTMATCHSTATE ZSTDH_compressBlock_lazy_dictMatchState
#define ZSTDH_COMPRESSBLOCK_LAZY_DICTMATCHSTATE_ROW ZSTDH_compressBlock_lazy_dictMatchState_row
#define ZSTDH_COMPRESSBLOCK_LAZY_DEDICATEDDICTSEARCH ZSTDH_compressBlock_lazy_dedicatedDictSearch
#define ZSTDH_COMPRESSBLOCK_LAZY_DEDICATEDDICTSEARCH_ROW ZSTDH_compressBlock_lazy_dedicatedDictSearch_row
#define ZSTDH_COMPRESSBLOCK_LAZY_EXTDICT ZSTDH_compressBlock_lazy_extDict
#define ZSTDH_COMPRESSBLOCK_LAZY_EXTDICT_ROW ZSTDH_compressBlock_lazy_extDict_row
#else
#define ZSTDH_COMPRESSBLOCK_LAZY NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_DICTMATCHSTATE_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_DEDICATEDDICTSEARCH NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_DEDICATEDDICTSEARCH_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_EXTDICT NULL
#define ZSTDH_COMPRESSBLOCK_LAZY_EXTDICT_ROW NULL
#endif

#ifndef ZSTDH_EXCLUDE_LAZY2_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_lazy2(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_dictMatchState_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_dedicatedDictSearch(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_dedicatedDictSearch_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_lazy2_extDict_row(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_LAZY2 ZSTDH_compressBlock_lazy2
#define ZSTDH_COMPRESSBLOCK_LAZY2_ROW ZSTDH_compressBlock_lazy2_row
#define ZSTDH_COMPRESSBLOCK_LAZY2_DICTMATCHSTATE ZSTDH_compressBlock_lazy2_dictMatchState
#define ZSTDH_COMPRESSBLOCK_LAZY2_DICTMATCHSTATE_ROW ZSTDH_compressBlock_lazy2_dictMatchState_row
#define ZSTDH_COMPRESSBLOCK_LAZY2_DEDICATEDDICTSEARCH ZSTDH_compressBlock_lazy2_dedicatedDictSearch
#define ZSTDH_COMPRESSBLOCK_LAZY2_DEDICATEDDICTSEARCH_ROW ZSTDH_compressBlock_lazy2_dedicatedDictSearch_row
#define ZSTDH_COMPRESSBLOCK_LAZY2_EXTDICT ZSTDH_compressBlock_lazy2_extDict
#define ZSTDH_COMPRESSBLOCK_LAZY2_EXTDICT_ROW ZSTDH_compressBlock_lazy2_extDict_row
#else
#define ZSTDH_COMPRESSBLOCK_LAZY2 NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_DICTMATCHSTATE_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_DEDICATEDDICTSEARCH NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_DEDICATEDDICTSEARCH_ROW NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_EXTDICT NULL
#define ZSTDH_COMPRESSBLOCK_LAZY2_EXTDICT_ROW NULL
#endif

#ifndef ZSTDH_EXCLUDE_BTLAZY2_BLOCK_COMPRESSOR
size_t ZSTDH_compressBlock_btlazy2(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btlazy2_dictMatchState(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);
size_t ZSTDH_compressBlock_btlazy2_extDict(
        ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
        void const* src, size_t srcSize);

#define ZSTDH_COMPRESSBLOCK_BTLAZY2 ZSTDH_compressBlock_btlazy2
#define ZSTDH_COMPRESSBLOCK_BTLAZY2_DICTMATCHSTATE ZSTDH_compressBlock_btlazy2_dictMatchState
#define ZSTDH_COMPRESSBLOCK_BTLAZY2_EXTDICT ZSTDH_compressBlock_btlazy2_extDict
#else
#define ZSTDH_COMPRESSBLOCK_BTLAZY2 NULL
#define ZSTDH_COMPRESSBLOCK_BTLAZY2_DICTMATCHSTATE NULL
#define ZSTDH_COMPRESSBLOCK_BTLAZY2_EXTDICT NULL
#endif

#endif /* ZSTDH_LAZY_H */
