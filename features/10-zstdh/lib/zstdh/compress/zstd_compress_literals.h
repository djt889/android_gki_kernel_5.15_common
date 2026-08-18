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

#ifndef ZSTDH_COMPRESS_LITERALS_H
#define ZSTDH_COMPRESS_LITERALS_H

#include "zstd_compress_internal.h" /* ZSTDH_hufCTables_t, ZSTDH_minGain() */


size_t ZSTDH_noCompressLiterals (void* dst, size_t dstCapacity, const void* src, size_t srcSize);

/* ZSTDH_compressRleLiteralsBlock() :
 * Conditions :
 * - All bytes in @src are identical
 * - dstCapacity >= 4 */
size_t ZSTDH_compressRleLiteralsBlock (void* dst, size_t dstCapacity, const void* src, size_t srcSize);

/* ZSTDH_compressLiterals():
 * @entropyWorkspace: must be aligned on 4-bytes boundaries
 * @entropyWorkspaceSize : must be >= HUFH_WORKSPACE_SIZE
 * @suspectUncompressible: sampling checks, to potentially skip huffman coding
 */
size_t ZSTDH_compressLiterals (void* dst, size_t dstCapacity,
                        const void* src, size_t srcSize,
                              void* entropyWorkspace, size_t entropyWorkspaceSize,
                        const ZSTDH_hufCTables_t* prevHuf,
                              ZSTDH_hufCTables_t* nextHuf,
                              ZSTDH_strategy strategy, int disableLiteralCompression,
                              int suspectUncompressible,
                              int bmi2);

#endif /* ZSTDH_COMPRESS_LITERALS_H */
