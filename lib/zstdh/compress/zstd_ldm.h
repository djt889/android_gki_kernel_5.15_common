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

#ifndef ZSTDH_LDM_H
#define ZSTDH_LDM_H

#include "zstd_compress_internal.h"   /* ldmParams_t, U32 */
#include <linux/zstdh.h>   /* ZSTDH_CCtx, size_t */

/*-*************************************
*  Long distance matching
***************************************/

#define ZSTDH_LDM_DEFAULT_WINDOW_LOG ZSTDH_WINDOWLOG_LIMIT_DEFAULT

void ZSTDH_ldm_fillHashTable(
            ldmState_t* state, const BYTE* ip,
            const BYTE* iend, ldmParams_t const* params);

/*
 * ZSTDH_ldm_generateSequences():
 *
 * Generates the sequences using the long distance match finder.
 * Generates long range matching sequences in `sequences`, which parse a prefix
 * of the source. `sequences` must be large enough to store every sequence,
 * which can be checked with `ZSTDH_ldm_getMaxNbSeq()`.
 * @returns 0 or an error code.
 *
 * NOTE: The user must have called ZSTDH_window_update() for all of the input
 * they have, even if they pass it to ZSTDH_ldm_generateSequences() in chunks.
 * NOTE: This function returns an error if it runs out of space to store
 *       sequences.
 */
size_t ZSTDH_ldm_generateSequences(
            ldmState_t* ldms, RawSeqStore_t* sequences,
            ldmParams_t const* params, void const* src, size_t srcSize);

/*
 * ZSTDH_ldm_blockCompress():
 *
 * Compresses a block using the predefined sequences, along with a secondary
 * block compressor. The literals section of every sequence is passed to the
 * secondary block compressor, and those sequences are interspersed with the
 * predefined sequences. Returns the length of the last literals.
 * Updates `rawSeqStore.pos` to indicate how many sequences have been consumed.
 * `rawSeqStore.seq` may also be updated to split the last sequence between two
 * blocks.
 * @return The length of the last literals.
 *
 * NOTE: The source must be at most the maximum block size, but the predefined
 * sequences can be any size, and may be longer than the block. In the case that
 * they are longer than the block, the last sequences may need to be split into
 * two. We handle that case correctly, and update `rawSeqStore` appropriately.
 * NOTE: This function does not return any errors.
 */
size_t ZSTDH_ldm_blockCompress(RawSeqStore_t* rawSeqStore,
            ZSTDH_MatchState_t* ms, SeqStore_t* seqStore, U32 rep[ZSTDH_REP_NUM],
            ZSTDH_ParamSwitch_e useRowMatchFinder,
            void const* src, size_t srcSize);

/*
 * ZSTDH_ldm_skipSequences():
 *
 * Skip past `srcSize` bytes worth of sequences in `rawSeqStore`.
 * Avoids emitting matches less than `minMatch` bytes.
 * Must be called for data that is not passed to ZSTDH_ldm_blockCompress().
 */
void ZSTDH_ldm_skipSequences(RawSeqStore_t* rawSeqStore, size_t srcSize,
    U32 const minMatch);

/* ZSTDH_ldm_skipRawSeqStoreBytes():
 * Moves forward in rawSeqStore by nbBytes, updating fields 'pos' and 'posInSequence'.
 * Not to be used in conjunction with ZSTDH_ldm_skipSequences().
 * Must be called for data with is not passed to ZSTDH_ldm_blockCompress().
 */
void ZSTDH_ldm_skipRawSeqStoreBytes(RawSeqStore_t* rawSeqStore, size_t nbBytes);

/* ZSTDH_ldm_getTableSize() :
 *  Estimate the space needed for long distance matching tables or 0 if LDM is
 *  disabled.
 */
size_t ZSTDH_ldm_getTableSize(ldmParams_t params);

/* ZSTDH_ldm_getSeqSpace() :
 *  Return an upper bound on the number of sequences that can be produced by
 *  the long distance matcher, or 0 if LDM is disabled.
 */
size_t ZSTDH_ldm_getMaxNbSeq(ldmParams_t params, size_t maxChunkSize);

/* ZSTDH_ldm_adjustParameters() :
 *  If the params->hashRateLog is not set, set it to its default value based on
 *  windowLog and params->hashLog.
 *
 *  Ensures that params->bucketSizeLog is <= params->hashLog (setting it to
 *  params->hashLog if it is not).
 *
 *  Ensures that the minMatchLength >= targetLength during optimal parsing.
 */
void ZSTDH_ldm_adjustParameters(ldmParams_t* params,
                               ZSTDH_compressionParameters const* cParams);

#endif /* ZSTDH_FAST_H */
