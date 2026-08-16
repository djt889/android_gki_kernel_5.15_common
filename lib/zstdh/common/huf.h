/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
/* ******************************************************************
 * huff0 huffman codec,
 * part of Finite State Entropy library
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * You can contact the author at :
 * - Source repository : https://github.com/Cyan4973/FiniteStateEntropy
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
****************************************************************** */

#ifndef HUFH_H_298734234
#define HUFH_H_298734234

/* *** Dependencies *** */
#include "zstd_deps.h"    /* size_t */
#include "mem.h"          /* U32 */
#define FSEH_STATIC_LINKING_ONLY
#include "fse.h"

/* ***   Tool functions *** */
#define HUFH_BLOCKSIZE_MAX (128 * 1024)   /*< maximum input size for a single block compressed with HUFH_compress */
size_t HUFH_compressBound(size_t size);   /*< maximum compressed size (worst case) */

/* Error Management */
unsigned    HUFH_isError(size_t code);       /*< tells if a return value is an error code */
const char* HUFH_getErrorName(size_t code);  /*< provides error code string (useful for debugging) */


#define HUFH_WORKSPACE_SIZE ((8 << 10) + 512 /* sorting scratch space */)
#define HUFH_WORKSPACE_SIZE_U64 (HUFH_WORKSPACE_SIZE / sizeof(U64))

/* *** Constants *** */
#define HUFH_TABLELOG_MAX      12      /* max runtime value of tableLog (due to static allocation); can be modified up to HUFH_TABLELOG_ABSOLUTEMAX */
#define HUFH_TABLELOG_DEFAULT  11      /* default tableLog value when none specified */
#define HUFH_SYMBOLVALUE_MAX  255

#define HUFH_TABLELOG_ABSOLUTEMAX  12  /* absolute limit of HUFH_MAX_TABLELOG. Beyond that value, code does not work */
#if (HUFH_TABLELOG_MAX > HUFH_TABLELOG_ABSOLUTEMAX)
#  error "HUFH_TABLELOG_MAX is too large !"
#endif


/* ****************************************
*  Static allocation
******************************************/
/* HUF buffer bounds */
#define HUFH_CTABLEBOUND 129
#define HUFH_BLOCKBOUND(size) (size + (size>>8) + 8)   /* only true when incompressible is pre-filtered with fast heuristic */
#define HUFH_COMPRESSBOUND(size) (HUFH_CTABLEBOUND + HUFH_BLOCKBOUND(size))   /* Macro version, useful for static allocation */

/* static allocation of HUF's Compression Table */
/* this is a private definition, just exposed for allocation and strict aliasing purpose. never EVER access its members directly */
typedef size_t HUFH_CElt;   /* consider it an incomplete type */
#define HUFH_CTABLE_SIZE_ST(maxSymbolValue)   ((maxSymbolValue)+2)   /* Use tables of size_t, for proper alignment */
#define HUFH_CTABLE_SIZE(maxSymbolValue)       (HUFH_CTABLE_SIZE_ST(maxSymbolValue) * sizeof(size_t))
#define HUFH_CREATE_STATIC_CTABLE(name, maxSymbolValue) \
    HUFH_CElt name[HUFH_CTABLE_SIZE_ST(maxSymbolValue)] /* no final ; */

/* static allocation of HUF's DTable */
typedef U32 HUFH_DTable;
#define HUFH_DTABLE_SIZE(maxTableLog)   (1 + (1<<(maxTableLog)))
#define HUFH_CREATE_STATIC_DTABLEX1(DTable, maxTableLog) \
        HUFH_DTable DTable[HUFH_DTABLE_SIZE((maxTableLog)-1)] = { ((U32)((maxTableLog)-1) * 0x01000001) }
#define HUFH_CREATE_STATIC_DTABLEX2(DTable, maxTableLog) \
        HUFH_DTable DTable[HUFH_DTABLE_SIZE(maxTableLog)] = { ((U32)(maxTableLog) * 0x01000001) }


/* ****************************************
*  Advanced decompression functions
******************************************/

/*
 * Huffman flags bitset.
 * For all flags, 0 is the default value.
 */
typedef enum {
    /*
     * If compiled with DYNAMIC_BMI2: Set flag only if the CPU supports BMI2 at runtime.
     * Otherwise: Ignored.
     */
    HUFH_flags_bmi2 = (1 << 0),
    /*
     * If set: Test possible table depths to find the one that produces the smallest header + encoded size.
     * If unset: Use heuristic to find the table depth.
     */
    HUFH_flags_optimalDepth = (1 << 1),
    /*
     * If set: If the previous table can encode the input, always reuse the previous table.
     * If unset: If the previous table can encode the input, reuse the previous table if it results in a smaller output.
     */
    HUFH_flags_preferRepeat = (1 << 2),
    /*
     * If set: Sample the input and check if the sample is uncompressible, if it is then don't attempt to compress.
     * If unset: Always histogram the entire input.
     */
    HUFH_flags_suspectUncompressible = (1 << 3),
    /*
     * If set: Don't use assembly implementations
     * If unset: Allow using assembly implementations
     */
    HUFH_flags_disableAsm = (1 << 4),
    /*
     * If set: Don't use the fast decoding loop, always use the fallback decoding loop.
     * If unset: Use the fast decoding loop when possible.
     */
    HUFH_flags_disableFast = (1 << 5)
} HUFH_flags_e;


/* ****************************************
 *  HUF detailed API
 * ****************************************/
#define HUFH_OPTIMAL_DEPTH_THRESHOLD ZSTDH_btultra

/*! HUFH_compress() does the following:
 *  1. count symbol occurrence from source[] into table count[] using FSEH_count() (exposed within "fse.h")
 *  2. (optional) refine tableLog using HUFH_optimalTableLog()
 *  3. build Huffman table from count using HUFH_buildCTable()
 *  4. save Huffman table to memory buffer using HUFH_writeCTable()
 *  5. encode the data stream using HUFH_compress4X_usingCTable()
 *
 *  The following API allows targeting specific sub-functions for advanced tasks.
 *  For example, it's possible to compress several blocks using the same 'CTable',
 *  or to save and regenerate 'CTable' using external methods.
 */
unsigned HUFH_minTableLog(unsigned symbolCardinality);
unsigned HUFH_cardinality(const unsigned* count, unsigned maxSymbolValue);
unsigned HUFH_optimalTableLog(unsigned maxTableLog, size_t srcSize, unsigned maxSymbolValue, void* workSpace,
 size_t wkspSize, HUFH_CElt* table, const unsigned* count, int flags); /* table is used as scratch space for building and testing tables, not a return value */
size_t HUFH_writeCTable_wksp(void* dst, size_t maxDstSize, const HUFH_CElt* CTable, unsigned maxSymbolValue, unsigned huffLog, void* workspace, size_t workspaceSize);
size_t HUFH_compress4X_usingCTable(void* dst, size_t dstSize, const void* src, size_t srcSize, const HUFH_CElt* CTable, int flags);
size_t HUFH_estimateCompressedSize(const HUFH_CElt* CTable, const unsigned* count, unsigned maxSymbolValue);
int HUFH_validateCTable(const HUFH_CElt* CTable, const unsigned* count, unsigned maxSymbolValue);

typedef enum {
   HUFH_repeat_none,  /*< Cannot use the previous table */
   HUFH_repeat_check, /*< Can use the previous table but it must be checked. Note : The previous table must have been constructed by HUFH_compress{1, 4}X_repeat */
   HUFH_repeat_valid  /*< Can use the previous table and it is assumed to be valid */
 } HUFH_repeat;

/* HUFH_compress4X_repeat() :
 *  Same as HUFH_compress4X_wksp(), but considers using hufTable if *repeat != HUFH_repeat_none.
 *  If it uses hufTable it does not modify hufTable or repeat.
 *  If it doesn't, it sets *repeat = HUFH_repeat_none, and it sets hufTable to the table used.
 *  If preferRepeat then the old table will always be used if valid.
 *  If suspectUncompressible then some sampling checks will be run to potentially skip huffman coding */
size_t HUFH_compress4X_repeat(void* dst, size_t dstSize,
                       const void* src, size_t srcSize,
                       unsigned maxSymbolValue, unsigned tableLog,
                       void* workSpace, size_t wkspSize,    /*< `workSpace` must be aligned on 4-bytes boundaries, `wkspSize` must be >= HUFH_WORKSPACE_SIZE */
                       HUFH_CElt* hufTable, HUFH_repeat* repeat, int flags);

/* HUFH_buildCTable_wksp() :
 *  Same as HUFH_buildCTable(), but using externally allocated scratch buffer.
 * `workSpace` must be aligned on 4-bytes boundaries, and its size must be >= HUFH_CTABLE_WORKSPACE_SIZE.
 */
#define HUFH_CTABLE_WORKSPACE_SIZE_U32 ((4 * (HUFH_SYMBOLVALUE_MAX + 1)) + 192)
#define HUFH_CTABLE_WORKSPACE_SIZE (HUFH_CTABLE_WORKSPACE_SIZE_U32 * sizeof(unsigned))
size_t HUFH_buildCTable_wksp (HUFH_CElt* tree,
                       const unsigned* count, U32 maxSymbolValue, U32 maxNbBits,
                             void* workSpace, size_t wkspSize);

/*! HUFH_readStats() :
 *  Read compact Huffman tree, saved by HUFH_writeCTable().
 * `huffWeight` is destination buffer.
 * @return : size read from `src` , or an error Code .
 *  Note : Needed by HUFH_readCTable() and HUFH_readDTableXn() . */
size_t HUFH_readStats(BYTE* huffWeight, size_t hwSize,
                     U32* rankStats, U32* nbSymbolsPtr, U32* tableLogPtr,
                     const void* src, size_t srcSize);

/*! HUFH_readStats_wksp() :
 * Same as HUFH_readStats() but takes an external workspace which must be
 * 4-byte aligned and its size must be >= HUFH_READ_STATS_WORKSPACE_SIZE.
 * If the CPU has BMI2 support, pass bmi2=1, otherwise pass bmi2=0.
 */
#define HUFH_READ_STATS_WORKSPACE_SIZE_U32 FSEH_DECOMPRESS_WKSP_SIZE_U32(6, HUFH_TABLELOG_MAX-1)
#define HUFH_READ_STATS_WORKSPACE_SIZE (HUFH_READ_STATS_WORKSPACE_SIZE_U32 * sizeof(unsigned))
size_t HUFH_readStats_wksp(BYTE* huffWeight, size_t hwSize,
                          U32* rankStats, U32* nbSymbolsPtr, U32* tableLogPtr,
                          const void* src, size_t srcSize,
                          void* workspace, size_t wkspSize,
                          int flags);

/* HUFH_readCTable() :
 *  Loading a CTable saved with HUFH_writeCTable() */
size_t HUFH_readCTable (HUFH_CElt* CTable, unsigned* maxSymbolValuePtr, const void* src, size_t srcSize, unsigned *hasZeroWeights);

/* HUFH_getNbBitsFromCTable() :
 *  Read nbBits from CTable symbolTable, for symbol `symbolValue` presumed <= HUFH_SYMBOLVALUE_MAX
 *  Note 1 : If symbolValue > HUFH_readCTableHeader(symbolTable).maxSymbolValue, returns 0
 *  Note 2 : is not inlined, as HUFH_CElt definition is private
 */
U32 HUFH_getNbBitsFromCTable(const HUFH_CElt* symbolTable, U32 symbolValue);

typedef struct {
    BYTE tableLog;
    BYTE maxSymbolValue;
    BYTE unused[sizeof(size_t) - 2];
} HUFH_CTableHeader;

/* HUFH_readCTableHeader() :
 *  @returns The header from the CTable specifying the tableLog and the maxSymbolValue.
 */
HUFH_CTableHeader HUFH_readCTableHeader(HUFH_CElt const* ctable);

/*
 * HUFH_decompress() does the following:
 * 1. select the decompression algorithm (X1, X2) based on pre-computed heuristics
 * 2. build Huffman table from save, using HUFH_readDTableX?()
 * 3. decode 1 or 4 segments in parallel using HUFH_decompress?X?_usingDTable()
 */

/* HUFH_selectDecoder() :
 *  Tells which decoder is likely to decode faster,
 *  based on a set of pre-computed metrics.
 * @return : 0==HUFH_decompress4X1, 1==HUFH_decompress4X2 .
 *  Assumption : 0 < dstSize <= 128 KB */
U32 HUFH_selectDecoder (size_t dstSize, size_t cSrcSize);

/*
 *  The minimum workspace size for the `workSpace` used in
 *  HUFH_readDTableX1_wksp() and HUFH_readDTableX2_wksp().
 *
 *  The space used depends on HUFH_TABLELOG_MAX, ranging from ~1500 bytes when
 *  HUFH_TABLE_LOG_MAX=12 to ~1850 bytes when HUFH_TABLE_LOG_MAX=15.
 *  Buffer overflow errors may potentially occur if code modifications result in
 *  a required workspace size greater than that specified in the following
 *  macro.
 */
#define HUFH_DECOMPRESS_WORKSPACE_SIZE ((2 << 10) + (1 << 9))
#define HUFH_DECOMPRESS_WORKSPACE_SIZE_U32 (HUFH_DECOMPRESS_WORKSPACE_SIZE / sizeof(U32))


/* ====================== */
/* single stream variants */
/* ====================== */

size_t HUFH_compress1X_usingCTable(void* dst, size_t dstSize, const void* src, size_t srcSize, const HUFH_CElt* CTable, int flags);
/* HUFH_compress1X_repeat() :
 *  Same as HUFH_compress1X_wksp(), but considers using hufTable if *repeat != HUFH_repeat_none.
 *  If it uses hufTable it does not modify hufTable or repeat.
 *  If it doesn't, it sets *repeat = HUFH_repeat_none, and it sets hufTable to the table used.
 *  If preferRepeat then the old table will always be used if valid.
 *  If suspectUncompressible then some sampling checks will be run to potentially skip huffman coding */
size_t HUFH_compress1X_repeat(void* dst, size_t dstSize,
                       const void* src, size_t srcSize,
                       unsigned maxSymbolValue, unsigned tableLog,
                       void* workSpace, size_t wkspSize,   /*< `workSpace` must be aligned on 4-bytes boundaries, `wkspSize` must be >= HUFH_WORKSPACE_SIZE */
                       HUFH_CElt* hufTable, HUFH_repeat* repeat, int flags);

size_t HUFH_decompress1X_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags);
#ifndef HUFH_FORCE_DECOMPRESS_X1
size_t HUFH_decompress1X2_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags);   /*< double-symbols decoder */
#endif

/* BMI2 variants.
 * If the CPU has BMI2 support, pass bmi2=1, otherwise pass bmi2=0.
 */
size_t HUFH_decompress1X_usingDTable(void* dst, size_t maxDstSize, const void* cSrc, size_t cSrcSize, const HUFH_DTable* DTable, int flags);
#ifndef HUFH_FORCE_DECOMPRESS_X2
size_t HUFH_decompress1X1_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags);
#endif
size_t HUFH_decompress4X_usingDTable(void* dst, size_t maxDstSize, const void* cSrc, size_t cSrcSize, const HUFH_DTable* DTable, int flags);
size_t HUFH_decompress4X_hufOnly_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags);
#ifndef HUFH_FORCE_DECOMPRESS_X2
size_t HUFH_readDTableX1_wksp(HUFH_DTable* DTable, const void* src, size_t srcSize, void* workSpace, size_t wkspSize, int flags);
#endif
#ifndef HUFH_FORCE_DECOMPRESS_X1
size_t HUFH_readDTableX2_wksp(HUFH_DTable* DTable, const void* src, size_t srcSize, void* workSpace, size_t wkspSize, int flags);
#endif

#endif   /* HUFH_H_298734234 */
