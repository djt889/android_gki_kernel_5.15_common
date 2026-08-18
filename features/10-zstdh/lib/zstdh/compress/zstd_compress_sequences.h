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

#ifndef ZSTDH_COMPRESS_SEQUENCES_H
#define ZSTDH_COMPRESS_SEQUENCES_H

#include "zstd_compress_internal.h" /* SeqDef */
#include "../common/fse.h" /* FSEH_repeat, FSEH_CTable */
#include "../common/zstd_internal.h" /* SymbolEncodingType_e, ZSTDH_strategy */

typedef enum {
    ZSTDH_defaultDisallowed = 0,
    ZSTDH_defaultAllowed = 1
} ZSTDH_DefaultPolicy_e;

SymbolEncodingType_e
ZSTDH_selectEncodingType(
        FSEH_repeat* repeatMode, unsigned const* count, unsigned const max,
        size_t const mostFrequent, size_t nbSeq, unsigned const FSELog,
        FSEH_CTable const* prevCTable,
        short const* defaultNorm, U32 defaultNormLog,
        ZSTDH_DefaultPolicy_e const isDefaultAllowed,
        ZSTDH_strategy const strategy);

size_t
ZSTDH_buildCTable(void* dst, size_t dstCapacity,
                FSEH_CTable* nextCTable, U32 FSELog, SymbolEncodingType_e type,
                unsigned* count, U32 max,
                const BYTE* codeTable, size_t nbSeq,
                const S16* defaultNorm, U32 defaultNormLog, U32 defaultMax,
                const FSEH_CTable* prevCTable, size_t prevCTableSize,
                void* entropyWorkspace, size_t entropyWorkspaceSize);

size_t ZSTDH_encodeSequences(
            void* dst, size_t dstCapacity,
            FSEH_CTable const* CTable_MatchLength, BYTE const* mlCodeTable,
            FSEH_CTable const* CTable_OffsetBits, BYTE const* ofCodeTable,
            FSEH_CTable const* CTable_LitLength, BYTE const* llCodeTable,
            SeqDef const* sequences, size_t nbSeq, int longOffsets, int bmi2);

size_t ZSTDH_fseBitCost(
    FSEH_CTable const* ctable,
    unsigned const* count,
    unsigned const max);

size_t ZSTDH_crossEntropyCost(short const* norm, unsigned accuracyLog,
                             unsigned const* count, unsigned const max);
#endif /* ZSTDH_COMPRESS_SEQUENCES_H */
