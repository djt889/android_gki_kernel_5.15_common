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


/* zstdh_decompress_internal:
 * objects and definitions shared within lib/decompress modules */

 #ifndef ZSTDH_DECOMPRESS_INTERNAL_H
 #define ZSTDH_DECOMPRESS_INTERNAL_H


/*-*******************************************************
 *  Dependencies
 *********************************************************/
#include "../common/mem.h"             /* BYTE, U16, U32 */
#include "../common/zstd_internal.h"   /* constants : MaxLL, MaxML, MaxOff, LLFSELog, etc. */



/*-*******************************************************
 *  Constants
 *********************************************************/
static UNUSED_ATTR const U32 LL_base[MaxLL+1] = {
                 0,    1,    2,     3,     4,     5,     6,      7,
                 8,    9,   10,    11,    12,    13,    14,     15,
                16,   18,   20,    22,    24,    28,    32,     40,
                48,   64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
                0x2000, 0x4000, 0x8000, 0x10000 };

static UNUSED_ATTR const U32 OF_base[MaxOff+1] = {
                 0,        1,       1,       5,     0xD,     0x1D,     0x3D,     0x7D,
                 0xFD,   0x1FD,   0x3FD,   0x7FD,   0xFFD,   0x1FFD,   0x3FFD,   0x7FFD,
                 0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD,
                 0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD };

static UNUSED_ATTR const U8 OF_bits[MaxOff+1] = {
                     0,  1,  2,  3,  4,  5,  6,  7,
                     8,  9, 10, 11, 12, 13, 14, 15,
                    16, 17, 18, 19, 20, 21, 22, 23,
                    24, 25, 26, 27, 28, 29, 30, 31 };

static UNUSED_ATTR const U32 ML_base[MaxML+1] = {
                     3,  4,  5,    6,     7,     8,     9,    10,
                    11, 12, 13,   14,    15,    16,    17,    18,
                    19, 20, 21,   22,    23,    24,    25,    26,
                    27, 28, 29,   30,    31,    32,    33,    34,
                    35, 37, 39,   41,    43,    47,    51,    59,
                    67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803,
                    0x1003, 0x2003, 0x4003, 0x8003, 0x10003 };


/*-*******************************************************
 *  Decompression types
 *********************************************************/
 typedef struct {
     U32 fastMode;
     U32 tableLog;
 } ZSTDH_seqSymbol_header;

 typedef struct {
     U16  nextState;
     BYTE nbAdditionalBits;
     BYTE nbBits;
     U32  baseValue;
 } ZSTDH_seqSymbol;

 #define SEQSYMBOL_TABLE_SIZE(log)   (1 + (1 << (log)))

#define ZSTDH_BUILD_FSEH_TABLE_WKSP_SIZE (sizeof(S16) * (MaxSeq + 1) + (1u << MaxFSELog) + sizeof(U64))
#define ZSTDH_BUILD_FSEH_TABLE_WKSP_SIZE_U32 ((ZSTDH_BUILD_FSEH_TABLE_WKSP_SIZE + sizeof(U32) - 1) / sizeof(U32))
#define ZSTDH_HUFFDTABLE_CAPACITY_LOG 12

typedef struct {
    ZSTDH_seqSymbol LLTable[SEQSYMBOL_TABLE_SIZE(LLFSELog)];    /* Note : Space reserved for FSE Tables */
    ZSTDH_seqSymbol OFTable[SEQSYMBOL_TABLE_SIZE(OffFSELog)];   /* is also used as temporary workspace while building hufTable during DDict creation */
    ZSTDH_seqSymbol MLTable[SEQSYMBOL_TABLE_SIZE(MLFSELog)];    /* and therefore must be at least HUFH_DECOMPRESS_WORKSPACE_SIZE large */
    HUFH_DTable hufTable[HUFH_DTABLE_SIZE(ZSTDH_HUFFDTABLE_CAPACITY_LOG)];  /* can accommodate HUFH_decompress4X */
    U32 rep[ZSTDH_REP_NUM];
    U32 workspace[ZSTDH_BUILD_FSEH_TABLE_WKSP_SIZE_U32];
} ZSTDH_entropyDTables_t;

typedef enum { ZSTDds_getFrameHeaderSize, ZSTDds_decodeFrameHeader,
               ZSTDds_decodeBlockHeader, ZSTDds_decompressBlock,
               ZSTDds_decompressLastBlock, ZSTDds_checkChecksum,
               ZSTDds_decodeSkippableHeader, ZSTDds_skipFrame } ZSTDH_dStage;

typedef enum { zdss_init=0, zdss_loadHeader,
               zdss_read, zdss_load, zdss_flush } ZSTDH_dStreamStage;

typedef enum {
    ZSTDH_use_indefinitely = -1,  /* Use the dictionary indefinitely */
    ZSTDH_dont_use = 0,           /* Do not use the dictionary (if one exists free it) */
    ZSTDH_use_once = 1            /* Use the dictionary once and set to ZSTDH_dont_use */
} ZSTDH_dictUses_e;

/* Hashset for storing references to multiple ZSTDH_DDict within ZSTDH_DCtx */
typedef struct {
    const ZSTDH_DDict** ddictPtrTable;
    size_t ddictPtrTableSize;
    size_t ddictPtrCount;
} ZSTDH_DDictHashSet;

#ifndef ZSTDH_DECODER_INTERNAL_BUFFER
#  define ZSTDH_DECODER_INTERNAL_BUFFER  (1 << 16)
#endif

#define ZSTDH_LBMIN 64
#define ZSTDH_LBMAX (128 << 10)

/* extra buffer, compensates when dst is not large enough to store litBuffer */
#define ZSTDH_LITBUFFEREXTRASIZE  BOUNDED(ZSTDH_LBMIN, ZSTDH_DECODER_INTERNAL_BUFFER, ZSTDH_LBMAX)

typedef enum {
    ZSTDH_not_in_dst = 0,  /* Stored entirely within litExtraBuffer */
    ZSTDH_in_dst = 1,           /* Stored entirely within dst (in memory after current output write) */
    ZSTDH_split = 2            /* Split between litExtraBuffer and dst */
} ZSTDH_litLocation_e;

struct ZSTDH_DCtx_s
{
    const ZSTDH_seqSymbol* LLTptr;
    const ZSTDH_seqSymbol* MLTptr;
    const ZSTDH_seqSymbol* OFTptr;
    const HUFH_DTable* HUFptr;
    ZSTDH_entropyDTables_t entropy;
    U32 workspace[HUFH_DECOMPRESS_WORKSPACE_SIZE_U32];   /* space needed when building huffman tables */
    const void* previousDstEnd;   /* detect continuity */
    const void* prefixStart;      /* start of current segment */
    const void* virtualStart;     /* virtual start of previous segment if it was just before current one */
    const void* dictEnd;          /* end of previous segment */
    size_t expected;
    ZSTDH_FrameHeader fParams;
    U64 processedCSize;
    U64 decodedSize;
    blockType_e bType;            /* used in ZSTDH_decompressContinue(), store blockType between block header decoding and block decompression stages */
    ZSTDH_dStage stage;
    U32 litEntropy;
    U32 fseEntropy;
    struct xxh64_state xxhState;
    size_t headerSize;
    ZSTDH_format_e format;
    ZSTDH_forceIgnoreChecksum_e forceIgnoreChecksum;   /* User specified: if == 1, will ignore checksums in compressed frame. Default == 0 */
    U32 validateChecksum;         /* if == 1, will validate checksum. Is == 1 if (fParams.checksumFlag == 1) and (forceIgnoreChecksum == 0). */
    const BYTE* litPtr;
    ZSTDH_customMem customMem;
    size_t litSize;
    size_t rleSize;
    size_t staticSize;
    int isFrameDecompression;
#if DYNAMIC_BMI2
    int bmi2;                     /* == 1 if the CPU supports BMI2 and 0 otherwise. CPU support is determined dynamically once per context lifetime. */
#endif

    /* dictionary */
    ZSTDH_DDict* ddictLocal;
    const ZSTDH_DDict* ddict;     /* set by ZSTDH_initDStream_usingDDict(), or ZSTDH_DCtx_refDDict() */
    U32 dictID;
    int ddictIsCold;             /* if == 1 : dictionary is "new" for working context, and presumed "cold" (not in cpu cache) */
    ZSTDH_dictUses_e dictUses;
    ZSTDH_DDictHashSet* ddictSet;                    /* Hash set for multiple ddicts */
    ZSTDH_refMultipleDDicts_e refMultipleDDicts;     /* User specified: if == 1, will allow references to multiple DDicts. Default == 0 (disabled) */
    int disableHufAsm;
    int maxBlockSizeParam;

    /* streaming */
    ZSTDH_dStreamStage streamStage;
    char*  inBuff;
    size_t inBuffSize;
    size_t inPos;
    size_t maxWindowSize;
    char*  outBuff;
    size_t outBuffSize;
    size_t outStart;
    size_t outEnd;
    size_t lhSize;
    U32 hostageByte;
    int noForwardProgress;
    ZSTDH_bufferMode_e outBufferMode;
    ZSTDH_outBuffer expectedOutBuffer;

    /* workspace */
    BYTE* litBuffer;
    const BYTE* litBufferEnd;
    ZSTDH_litLocation_e litBufferLocation;
    BYTE litExtraBuffer[ZSTDH_LITBUFFEREXTRASIZE + WILDCOPY_OVERLENGTH]; /* literal buffer can be split between storage within dst and within this scratch buffer */
    BYTE headerBuffer[ZSTDH_FRAMEHEADERSIZE_MAX];

    size_t oversizedDuration;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    void const* dictContentBeginForFuzzing;
    void const* dictContentEndForFuzzing;
#endif

    /* Tracing */
};  /* typedef'd to ZSTDH_DCtx within "zstd.h" */

MEM_STATIC int ZSTDH_DCtx_get_bmi2(const struct ZSTDH_DCtx_s *dctx) {
#if DYNAMIC_BMI2
    return dctx->bmi2;
#else
    (void)dctx;
    return 0;
#endif
}

/*-*******************************************************
 *  Shared internal functions
 *********************************************************/

/*! ZSTDH_loadDEntropy() :
 *  dict : must point at beginning of a valid zstd dictionary.
 * @return : size of dictionary header (size of magic number + dict ID + entropy tables) */
size_t ZSTDH_loadDEntropy(ZSTDH_entropyDTables_t* entropy,
                   const void* const dict, size_t const dictSize);

/*! ZSTDH_checkContinuity() :
 *  check if next `dst` follows previous position, where decompression ended.
 *  If yes, do nothing (continue on current segment).
 *  If not, classify previous segment as "external dictionary", and start a new segment.
 *  This function cannot fail. */
void ZSTDH_checkContinuity(ZSTDH_DCtx* dctx, const void* dst, size_t dstSize);


#endif /* ZSTDH_DECOMPRESS_INTERNAL_H */
