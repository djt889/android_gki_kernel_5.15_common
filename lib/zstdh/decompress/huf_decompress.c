// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/* ******************************************************************
 * huff0 huffman decoder,
 * part of Finite State Entropy library
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 *  You can contact the author at :
 *  - FSE+HUF source repository : https://github.com/Cyan4973/FiniteStateEntropy
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
****************************************************************** */

/* **************************************************************
*  Dependencies
****************************************************************/
#include "../common/zstd_deps.h"  /* ZSTDH_memcpy, ZSTDH_memset */
#include "../common/compiler.h"
#include "../common/bitstream.h"  /* BIT_* */
#include "../common/fse.h"        /* to compress headers */
#include "../common/huf.h"
#include "../common/error_private.h"
#include "../common/zstd_internal.h"
#include "../common/bits.h"       /* ZSTDH_highbit32, ZSTDH_countTrailingZeros64 */

/* **************************************************************
*  Constants
****************************************************************/

#define HUFH_DECODER_FAST_TABLELOG 11

/* **************************************************************
*  Macros
****************************************************************/

#ifdef HUFH_DISABLE_FAST_DECODE
# define HUFH_ENABLE_FAST_DECODE 0
#else
# define HUFH_ENABLE_FAST_DECODE 1
#endif

/* These two optional macros force the use one way or another of the two
 * Huffman decompression implementations. You can't force in both directions
 * at the same time.
 */
#if defined(HUFH_FORCE_DECOMPRESS_X1) && \
    defined(HUFH_FORCE_DECOMPRESS_X2)
#error "Cannot force the use of the X1 and X2 decoders at the same time!"
#endif

/* When DYNAMIC_BMI2 is enabled, fast decoders are only called when bmi2 is
 * supported at runtime, so we can add the BMI2 target attribute.
 * When it is disabled, we will still get BMI2 if it is enabled statically.
 */
#if DYNAMIC_BMI2
# define HUFH_FAST_BMI2_ATTRS BMI2_TARGET_ATTRIBUTE
#else
# define HUFH_FAST_BMI2_ATTRS
#endif

#define HUFH_EXTERN_C
#define HUFH_ASM_DECL HUFH_EXTERN_C

#if DYNAMIC_BMI2
# define HUFH_NEED_BMI2_FUNCTION 1
#else
# define HUFH_NEED_BMI2_FUNCTION 0
#endif

/* **************************************************************
*  Error Management
****************************************************************/
#define HUFH_isError ERR_isError


/* **************************************************************
*  Byte alignment for workSpace management
****************************************************************/
#define HUFH_ALIGN(x, a)         HUFH_ALIGN_MASK((x), (a) - 1)
#define HUFH_ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))


/* **************************************************************
*  BMI2 Variant Wrappers
****************************************************************/
typedef size_t (*HUFH_DecompressUsingDTableFn)(void *dst, size_t dstSize,
                                              const void *cSrc,
                                              size_t cSrcSize,
                                              const HUFH_DTable *DTable);

#if DYNAMIC_BMI2

#define HUFH_DGEN(fn)                                                        \
                                                                            \
    static size_t fn##_default(                                             \
                  void* dst,  size_t dstSize,                               \
            const void* cSrc, size_t cSrcSize,                              \
            const HUFH_DTable* DTable)                                       \
    {                                                                       \
        return fn##_body(dst, dstSize, cSrc, cSrcSize, DTable);             \
    }                                                                       \
                                                                            \
    static BMI2_TARGET_ATTRIBUTE size_t fn##_bmi2(                          \
                  void* dst,  size_t dstSize,                               \
            const void* cSrc, size_t cSrcSize,                              \
            const HUFH_DTable* DTable)                                       \
    {                                                                       \
        return fn##_body(dst, dstSize, cSrc, cSrcSize, DTable);             \
    }                                                                       \
                                                                            \
    static size_t fn(void* dst, size_t dstSize, void const* cSrc,           \
                     size_t cSrcSize, HUFH_DTable const* DTable, int flags)  \
    {                                                                       \
        if (flags & HUFH_flags_bmi2) {                                       \
            return fn##_bmi2(dst, dstSize, cSrc, cSrcSize, DTable);         \
        }                                                                   \
        return fn##_default(dst, dstSize, cSrc, cSrcSize, DTable);          \
    }

#else

#define HUFH_DGEN(fn)                                                        \
    static size_t fn(void* dst, size_t dstSize, void const* cSrc,           \
                     size_t cSrcSize, HUFH_DTable const* DTable, int flags)  \
    {                                                                       \
        (void)flags;                                                        \
        return fn##_body(dst, dstSize, cSrc, cSrcSize, DTable);             \
    }

#endif


/*-***************************/
/*  generic DTableDesc       */
/*-***************************/
typedef struct { BYTE maxTableLog; BYTE tableType; BYTE tableLog; BYTE reserved; } DTableDesc;

static DTableDesc HUFH_getDTableDesc(const HUFH_DTable* table)
{
    DTableDesc dtd;
    ZSTDH_memcpy(&dtd, table, sizeof(dtd));
    return dtd;
}

static size_t HUFH_initFastDStream(BYTE const* ip) {
    BYTE const lastByte = ip[7];
    size_t const bitsConsumed = lastByte ? 8 - ZSTDH_highbit32(lastByte) : 0;
    size_t const value = MEM_readLEST(ip) | 1;
    assert(bitsConsumed <= 8);
    assert(sizeof(size_t) == 8);
    return value << bitsConsumed;
}


/*
 * The input/output arguments to the Huffman fast decoding loop:
 *
 * ip [in/out] - The input pointers, must be updated to reflect what is consumed.
 * op [in/out] - The output pointers, must be updated to reflect what is written.
 * bits [in/out] - The bitstream containers, must be updated to reflect the current state.
 * dt [in] - The decoding table.
 * ilowest [in] - The beginning of the valid range of the input. Decoders may read
 *                down to this pointer. It may be below iend[0].
 * oend [in] - The end of the output stream. op[3] must not cross oend.
 * iend [in] - The end of each input stream. ip[i] may cross iend[i],
 *             as long as it is above ilowest, but that indicates corruption.
 */
typedef struct {
    BYTE const* ip[4];
    BYTE* op[4];
    U64 bits[4];
    void const* dt;
    BYTE const* ilowest;
    BYTE* oend;
    BYTE const* iend[4];
} HUFH_DecompressFastArgs;

typedef void (*HUFH_DecompressFastLoopFn)(HUFH_DecompressFastArgs*);

/*
 * Initializes args for the fast decoding loop.
 * @returns 1 on success
 *          0 if the fallback implementation should be used.
 *          Or an error code on failure.
 */
static size_t HUFH_DecompressFastArgs_init(HUFH_DecompressFastArgs* args, void* dst, size_t dstSize, void const* src, size_t srcSize, const HUFH_DTable* DTable)
{
    void const* dt = DTable + 1;
    U32 const dtLog = HUFH_getDTableDesc(DTable).tableLog;

    const BYTE* const istart = (const BYTE*)src;

    BYTE* const oend = ZSTDH_maybeNullPtrAdd((BYTE*)dst, dstSize);

    /* The fast decoding loop assumes 64-bit little-endian.
     * This condition is false on x32.
     */
    if (!MEM_isLittleEndian() || MEM_32bits())
        return 0;

    /* Avoid nullptr addition */
    if (dstSize == 0)
        return 0;
    assert(dst != NULL);

    /* strict minimum : jump table + 1 byte per stream */
    if (srcSize < 10)
        return ERROR(corruption_detected);

    /* Must have at least 8 bytes per stream because we don't handle initializing smaller bit containers.
     * If table log is not correct at this point, fallback to the old decoder.
     * On small inputs we don't have enough data to trigger the fast loop, so use the old decoder.
     */
    if (dtLog != HUFH_DECODER_FAST_TABLELOG)
        return 0;

    /* Read the jump table. */
    {
        size_t const length1 = MEM_readLE16(istart);
        size_t const length2 = MEM_readLE16(istart+2);
        size_t const length3 = MEM_readLE16(istart+4);
        size_t const length4 = srcSize - (length1 + length2 + length3 + 6);
        args->iend[0] = istart + 6;  /* jumpTable */
        args->iend[1] = args->iend[0] + length1;
        args->iend[2] = args->iend[1] + length2;
        args->iend[3] = args->iend[2] + length3;

        /* HUFH_initFastDStream() requires this, and this small of an input
         * won't benefit from the ASM loop anyways.
         */
        if (length1 < 8 || length2 < 8 || length3 < 8 || length4 < 8)
            return 0;
        if (length4 > srcSize) return ERROR(corruption_detected);   /* overflow */
    }
    /* ip[] contains the position that is currently loaded into bits[]. */
    args->ip[0] = args->iend[1] - sizeof(U64);
    args->ip[1] = args->iend[2] - sizeof(U64);
    args->ip[2] = args->iend[3] - sizeof(U64);
    args->ip[3] = (BYTE const*)src + srcSize - sizeof(U64);

    /* op[] contains the output pointers. */
    args->op[0] = (BYTE*)dst;
    args->op[1] = args->op[0] + (dstSize+3)/4;
    args->op[2] = args->op[1] + (dstSize+3)/4;
    args->op[3] = args->op[2] + (dstSize+3)/4;

    /* No point to call the ASM loop for tiny outputs. */
    if (args->op[3] >= oend)
        return 0;

    /* bits[] is the bit container.
        * It is read from the MSB down to the LSB.
        * It is shifted left as it is read, and zeros are
        * shifted in. After the lowest valid bit a 1 is
        * set, so that CountTrailingZeros(bits[]) can be used
        * to count how many bits we've consumed.
        */
    args->bits[0] = HUFH_initFastDStream(args->ip[0]);
    args->bits[1] = HUFH_initFastDStream(args->ip[1]);
    args->bits[2] = HUFH_initFastDStream(args->ip[2]);
    args->bits[3] = HUFH_initFastDStream(args->ip[3]);

    /* The decoders must be sure to never read beyond ilowest.
     * This is lower than iend[0], but allowing decoders to read
     * down to ilowest can allow an extra iteration or two in the
     * fast loop.
     */
    args->ilowest = istart;

    args->oend = oend;
    args->dt = dt;

    return 1;
}

static size_t HUFH_initRemainingDStream(BIT_DStream_t* bit, HUFH_DecompressFastArgs const* args, int stream, BYTE* segmentEnd)
{
    /* Validate that we haven't overwritten. */
    if (args->op[stream] > segmentEnd)
        return ERROR(corruption_detected);
    /* Validate that we haven't read beyond iend[].
        * Note that ip[] may be < iend[] because the MSB is
        * the next bit to read, and we may have consumed 100%
        * of the stream, so down to iend[i] - 8 is valid.
        */
    if (args->ip[stream] < args->iend[stream] - 8)
        return ERROR(corruption_detected);

    /* Construct the BIT_DStream_t. */
    assert(sizeof(size_t) == 8);
    bit->bitContainer = MEM_readLEST(args->ip[stream]);
    bit->bitsConsumed = ZSTDH_countTrailingZeros64(args->bits[stream]);
    bit->start = (const char*)args->ilowest;
    bit->limitPtr = bit->start + sizeof(size_t);
    bit->ptr = (const char*)args->ip[stream];

    return 0;
}

/* Calls X(N) for each stream 0, 1, 2, 3. */
#define HUFH_4X_FOR_EACH_STREAM(X) \
    do {                          \
        X(0);                     \
        X(1);                     \
        X(2);                     \
        X(3);                     \
    } while (0)

/* Calls X(N, var) for each stream 0, 1, 2, 3. */
#define HUFH_4X_FOR_EACH_STREAM_WITH_VAR(X, var) \
    do {                                        \
        X(0, (var));                            \
        X(1, (var));                            \
        X(2, (var));                            \
        X(3, (var));                            \
    } while (0)


#ifndef HUFH_FORCE_DECOMPRESS_X2

/*-***************************/
/*  single-symbol decoding   */
/*-***************************/
typedef struct { BYTE nbBits; BYTE byte; } HUFH_DEltX1;   /* single-symbol decoding */

/*
 * Packs 4 HUFH_DEltX1 structs into a U64. This is used to lay down 4 entries at
 * a time.
 */
static U64 HUFH_DEltX1_set4(BYTE symbol, BYTE nbBits) {
    U64 D4;
    if (MEM_isLittleEndian()) {
        D4 = (U64)((symbol << 8) + nbBits);
    } else {
        D4 = (U64)(symbol + (nbBits << 8));
    }
    assert(D4 < (1U << 16));
    D4 *= 0x0001000100010001ULL;
    return D4;
}

/*
 * Increase the tableLog to targetTableLog and rescales the stats.
 * If tableLog > targetTableLog this is a no-op.
 * @returns New tableLog
 */
static U32 HUFH_rescaleStats(BYTE* huffWeight, U32* rankVal, U32 nbSymbols, U32 tableLog, U32 targetTableLog)
{
    if (tableLog > targetTableLog)
        return tableLog;
    if (tableLog < targetTableLog) {
        U32 const scale = targetTableLog - tableLog;
        U32 s;
        /* Increase the weight for all non-zero probability symbols by scale. */
        for (s = 0; s < nbSymbols; ++s) {
            huffWeight[s] += (BYTE)((huffWeight[s] == 0) ? 0 : scale);
        }
        /* Update rankVal to reflect the new weights.
         * All weights except 0 get moved to weight + scale.
         * Weights [1, scale] are empty.
         */
        for (s = targetTableLog; s > scale; --s) {
            rankVal[s] = rankVal[s - scale];
        }
        for (s = scale; s > 0; --s) {
            rankVal[s] = 0;
        }
    }
    return targetTableLog;
}

typedef struct {
        U32 rankVal[HUFH_TABLELOG_ABSOLUTEMAX + 1];
        U32 rankStart[HUFH_TABLELOG_ABSOLUTEMAX + 1];
        U32 statsWksp[HUFH_READ_STATS_WORKSPACE_SIZE_U32];
        BYTE symbols[HUFH_SYMBOLVALUE_MAX + 1];
        BYTE huffWeight[HUFH_SYMBOLVALUE_MAX + 1];
} HUFH_ReadDTableX1_Workspace;

size_t HUFH_readDTableX1_wksp(HUFH_DTable* DTable, const void* src, size_t srcSize, void* workSpace, size_t wkspSize, int flags)
{
    U32 tableLog = 0;
    U32 nbSymbols = 0;
    size_t iSize;
    void* const dtPtr = DTable + 1;
    HUFH_DEltX1* const dt = (HUFH_DEltX1*)dtPtr;
    HUFH_ReadDTableX1_Workspace* wksp = (HUFH_ReadDTableX1_Workspace*)workSpace;

    DEBUG_STATIC_ASSERT(HUFH_DECOMPRESS_WORKSPACE_SIZE >= sizeof(*wksp));
    if (sizeof(*wksp) > wkspSize) return ERROR(tableLog_tooLarge);

    DEBUG_STATIC_ASSERT(sizeof(DTableDesc) == sizeof(HUFH_DTable));
    /* ZSTDH_memset(huffWeight, 0, sizeof(huffWeight)); */   /* is not necessary, even though some analyzer complain ... */

    iSize = HUFH_readStats_wksp(wksp->huffWeight, HUFH_SYMBOLVALUE_MAX + 1, wksp->rankVal, &nbSymbols, &tableLog, src, srcSize, wksp->statsWksp, sizeof(wksp->statsWksp), flags);
    if (HUFH_isError(iSize)) return iSize;


    /* Table header */
    {   DTableDesc dtd = HUFH_getDTableDesc(DTable);
        U32 const maxTableLog = dtd.maxTableLog + 1;
        U32 const targetTableLog = MIN(maxTableLog, HUFH_DECODER_FAST_TABLELOG);
        tableLog = HUFH_rescaleStats(wksp->huffWeight, wksp->rankVal, nbSymbols, tableLog, targetTableLog);
        if (tableLog > (U32)(dtd.maxTableLog+1)) return ERROR(tableLog_tooLarge);   /* DTable too small, Huffman tree cannot fit in */
        dtd.tableType = 0;
        dtd.tableLog = (BYTE)tableLog;
        ZSTDH_memcpy(DTable, &dtd, sizeof(dtd));
    }

    /* Compute symbols and rankStart given rankVal:
     *
     * rankVal already contains the number of values of each weight.
     *
     * symbols contains the symbols ordered by weight. First are the rankVal[0]
     * weight 0 symbols, followed by the rankVal[1] weight 1 symbols, and so on.
     * symbols[0] is filled (but unused) to avoid a branch.
     *
     * rankStart contains the offset where each rank belongs in the DTable.
     * rankStart[0] is not filled because there are no entries in the table for
     * weight 0.
     */
    {   int n;
        U32 nextRankStart = 0;
        int const unroll = 4;
        int const nLimit = (int)nbSymbols - unroll + 1;
        for (n=0; n<(int)tableLog+1; n++) {
            U32 const curr = nextRankStart;
            nextRankStart += wksp->rankVal[n];
            wksp->rankStart[n] = curr;
        }
        for (n=0; n < nLimit; n += unroll) {
            int u;
            for (u=0; u < unroll; ++u) {
                size_t const w = wksp->huffWeight[n+u];
                wksp->symbols[wksp->rankStart[w]++] = (BYTE)(n+u);
            }
        }
        for (; n < (int)nbSymbols; ++n) {
            size_t const w = wksp->huffWeight[n];
            wksp->symbols[wksp->rankStart[w]++] = (BYTE)n;
        }
    }

    /* fill DTable
     * We fill all entries of each weight in order.
     * That way length is a constant for each iteration of the outer loop.
     * We can switch based on the length to a different inner loop which is
     * optimized for that particular case.
     */
    {   U32 w;
        int symbol = wksp->rankVal[0];
        int rankStart = 0;
        for (w=1; w<tableLog+1; ++w) {
            int const symbolCount = wksp->rankVal[w];
            int const length = (1 << w) >> 1;
            int uStart = rankStart;
            BYTE const nbBits = (BYTE)(tableLog + 1 - w);
            int s;
            int u;
            switch (length) {
            case 1:
                for (s=0; s<symbolCount; ++s) {
                    HUFH_DEltX1 D;
                    D.byte = wksp->symbols[symbol + s];
                    D.nbBits = nbBits;
                    dt[uStart] = D;
                    uStart += 1;
                }
                break;
            case 2:
                for (s=0; s<symbolCount; ++s) {
                    HUFH_DEltX1 D;
                    D.byte = wksp->symbols[symbol + s];
                    D.nbBits = nbBits;
                    dt[uStart+0] = D;
                    dt[uStart+1] = D;
                    uStart += 2;
                }
                break;
            case 4:
                for (s=0; s<symbolCount; ++s) {
                    U64 const D4 = HUFH_DEltX1_set4(wksp->symbols[symbol + s], nbBits);
                    MEM_write64(dt + uStart, D4);
                    uStart += 4;
                }
                break;
            case 8:
                for (s=0; s<symbolCount; ++s) {
                    U64 const D4 = HUFH_DEltX1_set4(wksp->symbols[symbol + s], nbBits);
                    MEM_write64(dt + uStart, D4);
                    MEM_write64(dt + uStart + 4, D4);
                    uStart += 8;
                }
                break;
            default:
                for (s=0; s<symbolCount; ++s) {
                    U64 const D4 = HUFH_DEltX1_set4(wksp->symbols[symbol + s], nbBits);
                    for (u=0; u < length; u += 16) {
                        MEM_write64(dt + uStart + u + 0, D4);
                        MEM_write64(dt + uStart + u + 4, D4);
                        MEM_write64(dt + uStart + u + 8, D4);
                        MEM_write64(dt + uStart + u + 12, D4);
                    }
                    assert(u == length);
                    uStart += length;
                }
                break;
            }
            symbol += symbolCount;
            rankStart += symbolCount * length;
        }
    }
    return iSize;
}

FORCE_INLINE_TEMPLATE BYTE
HUFH_decodeSymbolX1(BIT_DStream_t* Dstream, const HUFH_DEltX1* dt, const U32 dtLog)
{
    size_t const val = BIT_lookBitsFast(Dstream, dtLog); /* note : dtLog >= 1 */
    BYTE const c = dt[val].byte;
    BIT_skipBits(Dstream, dt[val].nbBits);
    return c;
}

#define HUFH_DECODE_SYMBOLX1_0(ptr, DStreamPtr) \
    do { *ptr++ = HUFH_decodeSymbolX1(DStreamPtr, dt, dtLog); } while (0)

#define HUFH_DECODE_SYMBOLX1_1(ptr, DStreamPtr)      \
    do {                                            \
        if (MEM_64bits() || (HUFH_TABLELOG_MAX<=12)) \
            HUFH_DECODE_SYMBOLX1_0(ptr, DStreamPtr); \
    } while (0)

#define HUFH_DECODE_SYMBOLX1_2(ptr, DStreamPtr)      \
    do {                                            \
        if (MEM_64bits())                           \
            HUFH_DECODE_SYMBOLX1_0(ptr, DStreamPtr); \
    } while (0)

HINT_INLINE size_t
HUFH_decodeStreamX1(BYTE* p, BIT_DStream_t* const bitDPtr, BYTE* const pEnd, const HUFH_DEltX1* const dt, const U32 dtLog)
{
    BYTE* const pStart = p;

    /* up to 4 symbols at a time */
    if ((pEnd - p) > 3) {
        while ((BIT_reloadDStream(bitDPtr) == BIT_DStream_unfinished) & (p < pEnd-3)) {
            HUFH_DECODE_SYMBOLX1_2(p, bitDPtr);
            HUFH_DECODE_SYMBOLX1_1(p, bitDPtr);
            HUFH_DECODE_SYMBOLX1_2(p, bitDPtr);
            HUFH_DECODE_SYMBOLX1_0(p, bitDPtr);
        }
    } else {
        BIT_reloadDStream(bitDPtr);
    }

    /* [0-3] symbols remaining */
    if (MEM_32bits())
        while ((BIT_reloadDStream(bitDPtr) == BIT_DStream_unfinished) & (p < pEnd))
            HUFH_DECODE_SYMBOLX1_0(p, bitDPtr);

    /* no more data to retrieve from bitstream, no need to reload */
    while (p < pEnd)
        HUFH_DECODE_SYMBOLX1_0(p, bitDPtr);

    return (size_t)(pEnd-pStart);
}

FORCE_INLINE_TEMPLATE size_t
HUFH_decompress1X1_usingDTable_internal_body(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable)
{
    BYTE* op = (BYTE*)dst;
    BYTE* const oend = ZSTDH_maybeNullPtrAdd(op, dstSize);
    const void* dtPtr = DTable + 1;
    const HUFH_DEltX1* const dt = (const HUFH_DEltX1*)dtPtr;
    BIT_DStream_t bitD;
    DTableDesc const dtd = HUFH_getDTableDesc(DTable);
    U32 const dtLog = dtd.tableLog;

    CHECK_F( BIT_initDStream(&bitD, cSrc, cSrcSize) );

    HUFH_decodeStreamX1(op, &bitD, oend, dt, dtLog);

    if (!BIT_endOfDStream(&bitD)) return ERROR(corruption_detected);

    return dstSize;
}

/* HUFH_decompress4X1_usingDTable_internal_body():
 * Conditions :
 * @dstSize >= 6
 */
FORCE_INLINE_TEMPLATE size_t
HUFH_decompress4X1_usingDTable_internal_body(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable)
{
    /* Check */
    if (cSrcSize < 10) return ERROR(corruption_detected);  /* strict minimum : jump table + 1 byte per stream */
    if (dstSize < 6) return ERROR(corruption_detected);         /* stream 4-split doesn't work */

    {   const BYTE* const istart = (const BYTE*) cSrc;
        BYTE* const ostart = (BYTE*) dst;
        BYTE* const oend = ostart + dstSize;
        BYTE* const olimit = oend - 3;
        const void* const dtPtr = DTable + 1;
        const HUFH_DEltX1* const dt = (const HUFH_DEltX1*)dtPtr;

        /* Init */
        BIT_DStream_t bitD1;
        BIT_DStream_t bitD2;
        BIT_DStream_t bitD3;
        BIT_DStream_t bitD4;
        size_t const length1 = MEM_readLE16(istart);
        size_t const length2 = MEM_readLE16(istart+2);
        size_t const length3 = MEM_readLE16(istart+4);
        size_t const length4 = cSrcSize - (length1 + length2 + length3 + 6);
        const BYTE* const istart1 = istart + 6;  /* jumpTable */
        const BYTE* const istart2 = istart1 + length1;
        const BYTE* const istart3 = istart2 + length2;
        const BYTE* const istart4 = istart3 + length3;
        const size_t segmentSize = (dstSize+3) / 4;
        BYTE* const opStart2 = ostart + segmentSize;
        BYTE* const opStart3 = opStart2 + segmentSize;
        BYTE* const opStart4 = opStart3 + segmentSize;
        BYTE* op1 = ostart;
        BYTE* op2 = opStart2;
        BYTE* op3 = opStart3;
        BYTE* op4 = opStart4;
        DTableDesc const dtd = HUFH_getDTableDesc(DTable);
        U32 const dtLog = dtd.tableLog;
        U32 endSignal = 1;

        if (length4 > cSrcSize) return ERROR(corruption_detected);   /* overflow */
        if (opStart4 > oend) return ERROR(corruption_detected);      /* overflow */
        assert(dstSize >= 6); /* validated above */
        CHECK_F( BIT_initDStream(&bitD1, istart1, length1) );
        CHECK_F( BIT_initDStream(&bitD2, istart2, length2) );
        CHECK_F( BIT_initDStream(&bitD3, istart3, length3) );
        CHECK_F( BIT_initDStream(&bitD4, istart4, length4) );

        /* up to 16 symbols per loop (4 symbols per stream) in 64-bit mode */
        if ((size_t)(oend - op4) >= sizeof(size_t)) {
            for ( ; (endSignal) & (op4 < olimit) ; ) {
                HUFH_DECODE_SYMBOLX1_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX1_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX1_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX1_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX1_1(op1, &bitD1);
                HUFH_DECODE_SYMBOLX1_1(op2, &bitD2);
                HUFH_DECODE_SYMBOLX1_1(op3, &bitD3);
                HUFH_DECODE_SYMBOLX1_1(op4, &bitD4);
                HUFH_DECODE_SYMBOLX1_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX1_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX1_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX1_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX1_0(op1, &bitD1);
                HUFH_DECODE_SYMBOLX1_0(op2, &bitD2);
                HUFH_DECODE_SYMBOLX1_0(op3, &bitD3);
                HUFH_DECODE_SYMBOLX1_0(op4, &bitD4);
                endSignal &= BIT_reloadDStreamFast(&bitD1) == BIT_DStream_unfinished;
                endSignal &= BIT_reloadDStreamFast(&bitD2) == BIT_DStream_unfinished;
                endSignal &= BIT_reloadDStreamFast(&bitD3) == BIT_DStream_unfinished;
                endSignal &= BIT_reloadDStreamFast(&bitD4) == BIT_DStream_unfinished;
            }
        }

        /* check corruption */
        /* note : should not be necessary : op# advance in lock step, and we control op4.
         *        but curiously, binary generated by gcc 7.2 & 7.3 with -mbmi2 runs faster when >=1 test is present */
        if (op1 > opStart2) return ERROR(corruption_detected);
        if (op2 > opStart3) return ERROR(corruption_detected);
        if (op3 > opStart4) return ERROR(corruption_detected);
        /* note : op4 supposed already verified within main loop */

        /* finish bitStreams one by one */
        HUFH_decodeStreamX1(op1, &bitD1, opStart2, dt, dtLog);
        HUFH_decodeStreamX1(op2, &bitD2, opStart3, dt, dtLog);
        HUFH_decodeStreamX1(op3, &bitD3, opStart4, dt, dtLog);
        HUFH_decodeStreamX1(op4, &bitD4, oend,     dt, dtLog);

        /* check */
        { U32 const endCheck = BIT_endOfDStream(&bitD1) & BIT_endOfDStream(&bitD2) & BIT_endOfDStream(&bitD3) & BIT_endOfDStream(&bitD4);
          if (!endCheck) return ERROR(corruption_detected); }

        /* decoded size */
        return dstSize;
    }
}

#if HUFH_NEED_BMI2_FUNCTION
static BMI2_TARGET_ATTRIBUTE
size_t HUFH_decompress4X1_usingDTable_internal_bmi2(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable) {
    return HUFH_decompress4X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable);
}
#endif

static
size_t HUFH_decompress4X1_usingDTable_internal_default(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable) {
    return HUFH_decompress4X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable);
}

#if ZSTDH_ENABLE_ASM_X86_64_BMI2

HUFH_ASM_DECL void HUFH_decompress4X1_usingDTable_internal_fast_asm_loop(HUFH_DecompressFastArgs* args) ZSTDLIB_HIDDEN;

#endif

static HUFH_FAST_BMI2_ATTRS
void HUFH_decompress4X1_usingDTable_internal_fast_c_loop(HUFH_DecompressFastArgs* args)
{
    U64 bits[4];
    BYTE const* ip[4];
    BYTE* op[4];
    U16 const* const dtable = (U16 const*)args->dt;
    BYTE* const oend = args->oend;
    BYTE const* const ilowest = args->ilowest;

    /* Copy the arguments to local variables */
    ZSTDH_memcpy(&bits, &args->bits, sizeof(bits));
    ZSTDH_memcpy((void*)(&ip), &args->ip, sizeof(ip));
    ZSTDH_memcpy(&op, &args->op, sizeof(op));

    assert(MEM_isLittleEndian());
    assert(!MEM_32bits());

    for (;;) {
        BYTE* olimit;
        int stream;

        /* Assert loop preconditions */
#ifndef NDEBUG
        for (stream = 0; stream < 4; ++stream) {
            assert(op[stream] <= (stream == 3 ? oend : op[stream + 1]));
            assert(ip[stream] >= ilowest);
        }
#endif
        /* Compute olimit */
        {
            /* Each iteration produces 5 output symbols per stream */
            size_t const oiters = (size_t)(oend - op[3]) / 5;
            /* Each iteration consumes up to 11 bits * 5 = 55 bits < 7 bytes
             * per stream.
             */
            size_t const iiters = (size_t)(ip[0] - ilowest) / 7;
            /* We can safely run iters iterations before running bounds checks */
            size_t const iters = MIN(oiters, iiters);
            size_t const symbols = iters * 5;

            /* We can simply check that op[3] < olimit, instead of checking all
             * of our bounds, since we can't hit the other bounds until we've run
             * iters iterations, which only happens when op[3] == olimit.
             */
            olimit = op[3] + symbols;

            /* Exit fast decoding loop once we reach the end. */
            if (op[3] == olimit)
                break;

            /* Exit the decoding loop if any input pointer has crossed the
             * previous one. This indicates corruption, and a precondition
             * to our loop is that ip[i] >= ip[0].
             */
            for (stream = 1; stream < 4; ++stream) {
                if (ip[stream] < ip[stream - 1])
                    goto _out;
            }
        }

#ifndef NDEBUG
        for (stream = 1; stream < 4; ++stream) {
            assert(ip[stream] >= ip[stream - 1]);
        }
#endif

#define HUFH_4X1_DECODE_SYMBOL(_stream, _symbol)        \
    do {                                               \
        U64 const index = bits[(_stream)] >> 53;       \
        U16 const entry = dtable[index];               \
        bits[(_stream)] <<= entry & 0x3F;              \
        op[(_stream)][(_symbol)] = (BYTE)(entry >> 8); \
    } while (0)

#define HUFH_5X1_RELOAD_STREAM(_stream)                              \
    do {                                                            \
        U64 const ctz = ZSTDH_countTrailingZeros64(bits[(_stream)]); \
        U64 const nbBits = ctz & 7;                                 \
        U64 const nbBytes = ctz >> 3;                               \
        op[(_stream)] += 5;                                         \
        ip[(_stream)] -= nbBytes;                                   \
        bits[(_stream)] = MEM_read64(ip[(_stream)]) | 1;            \
        bits[(_stream)] <<= nbBits;                                 \
    } while (0)

        /* Manually unroll the loop because compilers don't consistently
         * unroll the inner loops, which destroys performance.
         */
        do {
            /* Decode 5 symbols in each of the 4 streams */
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X1_DECODE_SYMBOL, 0);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X1_DECODE_SYMBOL, 1);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X1_DECODE_SYMBOL, 2);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X1_DECODE_SYMBOL, 3);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X1_DECODE_SYMBOL, 4);

            /* Reload each of the 4 the bitstreams */
            HUFH_4X_FOR_EACH_STREAM(HUFH_5X1_RELOAD_STREAM);
        } while (op[3] < olimit);

#undef HUFH_4X1_DECODE_SYMBOL
#undef HUFH_5X1_RELOAD_STREAM
    }

_out:

    /* Save the final values of each of the state variables back to args. */
    ZSTDH_memcpy(&args->bits, &bits, sizeof(bits));
    ZSTDH_memcpy((void*)(&args->ip), &ip, sizeof(ip));
    ZSTDH_memcpy(&args->op, &op, sizeof(op));
}

/*
 * @returns @p dstSize on success (>= 6)
 *          0 if the fallback implementation should be used
 *          An error if an error occurred
 */
static HUFH_FAST_BMI2_ATTRS
size_t
HUFH_decompress4X1_usingDTable_internal_fast(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable,
    HUFH_DecompressFastLoopFn loopFn)
{
    void const* dt = DTable + 1;
    BYTE const* const ilowest = (BYTE const*)cSrc;
    BYTE* const oend = ZSTDH_maybeNullPtrAdd((BYTE*)dst, dstSize);
    HUFH_DecompressFastArgs args;
    {   size_t const ret = HUFH_DecompressFastArgs_init(&args, dst, dstSize, cSrc, cSrcSize, DTable);
        FORWARD_IF_ERROR(ret, "Failed to init fast loop args");
        if (ret == 0)
            return 0;
    }

    assert(args.ip[0] >= args.ilowest);
    loopFn(&args);

    /* Our loop guarantees that ip[] >= ilowest and that we haven't
    * overwritten any op[].
    */
    assert(args.ip[0] >= ilowest);
    assert(args.ip[0] >= ilowest);
    assert(args.ip[1] >= ilowest);
    assert(args.ip[2] >= ilowest);
    assert(args.ip[3] >= ilowest);
    assert(args.op[3] <= oend);

    assert(ilowest == args.ilowest);
    assert(ilowest + 6 == args.iend[0]);
    (void)ilowest;

    /* finish bit streams one by one. */
    {   size_t const segmentSize = (dstSize+3) / 4;
        BYTE* segmentEnd = (BYTE*)dst;
        int i;
        for (i = 0; i < 4; ++i) {
            BIT_DStream_t bit;
            if (segmentSize <= (size_t)(oend - segmentEnd))
                segmentEnd += segmentSize;
            else
                segmentEnd = oend;
            FORWARD_IF_ERROR(HUFH_initRemainingDStream(&bit, &args, i, segmentEnd), "corruption");
            /* Decompress and validate that we've produced exactly the expected length. */
            args.op[i] += HUFH_decodeStreamX1(args.op[i], &bit, segmentEnd, (HUFH_DEltX1 const*)dt, HUFH_DECODER_FAST_TABLELOG);
            if (args.op[i] != segmentEnd) return ERROR(corruption_detected);
        }
    }

    /* decoded size */
    assert(dstSize != 0);
    return dstSize;
}

HUFH_DGEN(HUFH_decompress1X1_usingDTable_internal)

static size_t HUFH_decompress4X1_usingDTable_internal(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable, int flags)
{
    HUFH_DecompressUsingDTableFn fallbackFn = HUFH_decompress4X1_usingDTable_internal_default;
    HUFH_DecompressFastLoopFn loopFn = HUFH_decompress4X1_usingDTable_internal_fast_c_loop;

#if DYNAMIC_BMI2
    if (flags & HUFH_flags_bmi2) {
        fallbackFn = HUFH_decompress4X1_usingDTable_internal_bmi2;
# if ZSTDH_ENABLE_ASM_X86_64_BMI2
        if (!(flags & HUFH_flags_disableAsm)) {
            loopFn = HUFH_decompress4X1_usingDTable_internal_fast_asm_loop;
        }
# endif
    } else {
        return fallbackFn(dst, dstSize, cSrc, cSrcSize, DTable);
    }
#endif

#if ZSTDH_ENABLE_ASM_X86_64_BMI2 && defined(__BMI2__)
    if (!(flags & HUFH_flags_disableAsm)) {
        loopFn = HUFH_decompress4X1_usingDTable_internal_fast_asm_loop;
    }
#endif

    if (HUFH_ENABLE_FAST_DECODE && !(flags & HUFH_flags_disableFast)) {
        size_t const ret = HUFH_decompress4X1_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable, loopFn);
        if (ret != 0)
            return ret;
    }
    return fallbackFn(dst, dstSize, cSrc, cSrcSize, DTable);
}

static size_t HUFH_decompress4X1_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize,
                                   const void* cSrc, size_t cSrcSize,
                                   void* workSpace, size_t wkspSize, int flags)
{
    const BYTE* ip = (const BYTE*) cSrc;

    size_t const hSize = HUFH_readDTableX1_wksp(dctx, cSrc, cSrcSize, workSpace, wkspSize, flags);
    if (HUFH_isError(hSize)) return hSize;
    if (hSize >= cSrcSize) return ERROR(srcSize_wrong);
    ip += hSize; cSrcSize -= hSize;

    return HUFH_decompress4X1_usingDTable_internal(dst, dstSize, ip, cSrcSize, dctx, flags);
}

#endif /* HUFH_FORCE_DECOMPRESS_X2 */


#ifndef HUFH_FORCE_DECOMPRESS_X1

/* *************************/
/* double-symbols decoding */
/* *************************/

typedef struct { U16 sequence; BYTE nbBits; BYTE length; } HUFH_DEltX2;  /* double-symbols decoding */
typedef struct { BYTE symbol; } sortedSymbol_t;
typedef U32 rankValCol_t[HUFH_TABLELOG_MAX + 1];
typedef rankValCol_t rankVal_t[HUFH_TABLELOG_MAX];

/*
 * Constructs a HUFH_DEltX2 in a U32.
 */
static U32 HUFH_buildDEltX2U32(U32 symbol, U32 nbBits, U32 baseSeq, int level)
{
    U32 seq;
    DEBUG_STATIC_ASSERT(offsetof(HUFH_DEltX2, sequence) == 0);
    DEBUG_STATIC_ASSERT(offsetof(HUFH_DEltX2, nbBits) == 2);
    DEBUG_STATIC_ASSERT(offsetof(HUFH_DEltX2, length) == 3);
    DEBUG_STATIC_ASSERT(sizeof(HUFH_DEltX2) == sizeof(U32));
    if (MEM_isLittleEndian()) {
        seq = level == 1 ? symbol : (baseSeq + (symbol << 8));
        return seq + (nbBits << 16) + ((U32)level << 24);
    } else {
        seq = level == 1 ? (symbol << 8) : ((baseSeq << 8) + symbol);
        return (seq << 16) + (nbBits << 8) + (U32)level;
    }
}

/*
 * Constructs a HUFH_DEltX2.
 */
static HUFH_DEltX2 HUFH_buildDEltX2(U32 symbol, U32 nbBits, U32 baseSeq, int level)
{
    HUFH_DEltX2 DElt;
    U32 const val = HUFH_buildDEltX2U32(symbol, nbBits, baseSeq, level);
    DEBUG_STATIC_ASSERT(sizeof(DElt) == sizeof(val));
    ZSTDH_memcpy(&DElt, &val, sizeof(val));
    return DElt;
}

/*
 * Constructs 2 HUFH_DEltX2s and packs them into a U64.
 */
static U64 HUFH_buildDEltX2U64(U32 symbol, U32 nbBits, U16 baseSeq, int level)
{
    U32 DElt = HUFH_buildDEltX2U32(symbol, nbBits, baseSeq, level);
    return (U64)DElt + ((U64)DElt << 32);
}

/*
 * Fills the DTable rank with all the symbols from [begin, end) that are each
 * nbBits long.
 *
 * @param DTableRank The start of the rank in the DTable.
 * @param begin The first symbol to fill (inclusive).
 * @param end The last symbol to fill (exclusive).
 * @param nbBits Each symbol is nbBits long.
 * @param tableLog The table log.
 * @param baseSeq If level == 1 { 0 } else { the first level symbol }
 * @param level The level in the table. Must be 1 or 2.
 */
static void HUFH_fillDTableX2ForWeight(
    HUFH_DEltX2* DTableRank,
    sortedSymbol_t const* begin, sortedSymbol_t const* end,
    U32 nbBits, U32 tableLog,
    U16 baseSeq, int const level)
{
    U32 const length = 1U << ((tableLog - nbBits) & 0x1F /* quiet static-analyzer */);
    const sortedSymbol_t* ptr;
    assert(level >= 1 && level <= 2);
    switch (length) {
    case 1:
        for (ptr = begin; ptr != end; ++ptr) {
            HUFH_DEltX2 const DElt = HUFH_buildDEltX2(ptr->symbol, nbBits, baseSeq, level);
            *DTableRank++ = DElt;
        }
        break;
    case 2:
        for (ptr = begin; ptr != end; ++ptr) {
            HUFH_DEltX2 const DElt = HUFH_buildDEltX2(ptr->symbol, nbBits, baseSeq, level);
            DTableRank[0] = DElt;
            DTableRank[1] = DElt;
            DTableRank += 2;
        }
        break;
    case 4:
        for (ptr = begin; ptr != end; ++ptr) {
            U64 const DEltX2 = HUFH_buildDEltX2U64(ptr->symbol, nbBits, baseSeq, level);
            ZSTDH_memcpy(DTableRank + 0, &DEltX2, sizeof(DEltX2));
            ZSTDH_memcpy(DTableRank + 2, &DEltX2, sizeof(DEltX2));
            DTableRank += 4;
        }
        break;
    case 8:
        for (ptr = begin; ptr != end; ++ptr) {
            U64 const DEltX2 = HUFH_buildDEltX2U64(ptr->symbol, nbBits, baseSeq, level);
            ZSTDH_memcpy(DTableRank + 0, &DEltX2, sizeof(DEltX2));
            ZSTDH_memcpy(DTableRank + 2, &DEltX2, sizeof(DEltX2));
            ZSTDH_memcpy(DTableRank + 4, &DEltX2, sizeof(DEltX2));
            ZSTDH_memcpy(DTableRank + 6, &DEltX2, sizeof(DEltX2));
            DTableRank += 8;
        }
        break;
    default:
        for (ptr = begin; ptr != end; ++ptr) {
            U64 const DEltX2 = HUFH_buildDEltX2U64(ptr->symbol, nbBits, baseSeq, level);
            HUFH_DEltX2* const DTableRankEnd = DTableRank + length;
            for (; DTableRank != DTableRankEnd; DTableRank += 8) {
                ZSTDH_memcpy(DTableRank + 0, &DEltX2, sizeof(DEltX2));
                ZSTDH_memcpy(DTableRank + 2, &DEltX2, sizeof(DEltX2));
                ZSTDH_memcpy(DTableRank + 4, &DEltX2, sizeof(DEltX2));
                ZSTDH_memcpy(DTableRank + 6, &DEltX2, sizeof(DEltX2));
            }
        }
        break;
    }
}

/* HUFH_fillDTableX2Level2() :
 * `rankValOrigin` must be a table of at least (HUFH_TABLELOG_MAX + 1) U32 */
static void HUFH_fillDTableX2Level2(HUFH_DEltX2* DTable, U32 targetLog, const U32 consumedBits,
                           const U32* rankVal, const int minWeight, const int maxWeight1,
                           const sortedSymbol_t* sortedSymbols, U32 const* rankStart,
                           U32 nbBitsBaseline, U16 baseSeq)
{
    /* Fill skipped values (all positions up to rankVal[minWeight]).
     * These are positions only get a single symbol because the combined weight
     * is too large.
     */
    if (minWeight>1) {
        U32 const length = 1U << ((targetLog - consumedBits) & 0x1F /* quiet static-analyzer */);
        U64 const DEltX2 = HUFH_buildDEltX2U64(baseSeq, consumedBits, /* baseSeq */ 0, /* level */ 1);
        int const skipSize = rankVal[minWeight];
        assert(length > 1);
        assert((U32)skipSize < length);
        switch (length) {
        case 2:
            assert(skipSize == 1);
            ZSTDH_memcpy(DTable, &DEltX2, sizeof(DEltX2));
            break;
        case 4:
            assert(skipSize <= 4);
            ZSTDH_memcpy(DTable + 0, &DEltX2, sizeof(DEltX2));
            ZSTDH_memcpy(DTable + 2, &DEltX2, sizeof(DEltX2));
            break;
        default:
            {
                int i;
                for (i = 0; i < skipSize; i += 8) {
                    ZSTDH_memcpy(DTable + i + 0, &DEltX2, sizeof(DEltX2));
                    ZSTDH_memcpy(DTable + i + 2, &DEltX2, sizeof(DEltX2));
                    ZSTDH_memcpy(DTable + i + 4, &DEltX2, sizeof(DEltX2));
                    ZSTDH_memcpy(DTable + i + 6, &DEltX2, sizeof(DEltX2));
                }
            }
        }
    }

    /* Fill each of the second level symbols by weight. */
    {
        int w;
        for (w = minWeight; w < maxWeight1; ++w) {
            int const begin = rankStart[w];
            int const end = rankStart[w+1];
            U32 const nbBits = nbBitsBaseline - w;
            U32 const totalBits = nbBits + consumedBits;
            HUFH_fillDTableX2ForWeight(
                DTable + rankVal[w],
                sortedSymbols + begin, sortedSymbols + end,
                totalBits, targetLog,
                baseSeq, /* level */ 2);
        }
    }
}

static void HUFH_fillDTableX2(HUFH_DEltX2* DTable, const U32 targetLog,
                           const sortedSymbol_t* sortedList,
                           const U32* rankStart, rankValCol_t* rankValOrigin, const U32 maxWeight,
                           const U32 nbBitsBaseline)
{
    U32* const rankVal = rankValOrigin[0];
    const int scaleLog = nbBitsBaseline - targetLog;   /* note : targetLog >= srcLog, hence scaleLog <= 1 */
    const U32 minBits  = nbBitsBaseline - maxWeight;
    int w;
    int const wEnd = (int)maxWeight + 1;

    /* Fill DTable in order of weight. */
    for (w = 1; w < wEnd; ++w) {
        int const begin = (int)rankStart[w];
        int const end = (int)rankStart[w+1];
        U32 const nbBits = nbBitsBaseline - w;

        if (targetLog-nbBits >= minBits) {
            /* Enough room for a second symbol. */
            int start = rankVal[w];
            U32 const length = 1U << ((targetLog - nbBits) & 0x1F /* quiet static-analyzer */);
            int minWeight = nbBits + scaleLog;
            int s;
            if (minWeight < 1) minWeight = 1;
            /* Fill the DTable for every symbol of weight w.
             * These symbols get at least 1 second symbol.
             */
            for (s = begin; s != end; ++s) {
                HUFH_fillDTableX2Level2(
                    DTable + start, targetLog, nbBits,
                    rankValOrigin[nbBits], minWeight, wEnd,
                    sortedList, rankStart,
                    nbBitsBaseline, sortedList[s].symbol);
                start += length;
            }
        } else {
            /* Only a single symbol. */
            HUFH_fillDTableX2ForWeight(
                DTable + rankVal[w],
                sortedList + begin, sortedList + end,
                nbBits, targetLog,
                /* baseSeq */ 0, /* level */ 1);
        }
    }
}

typedef struct {
    rankValCol_t rankVal[HUFH_TABLELOG_MAX];
    U32 rankStats[HUFH_TABLELOG_MAX + 1];
    U32 rankStart0[HUFH_TABLELOG_MAX + 3];
    sortedSymbol_t sortedSymbol[HUFH_SYMBOLVALUE_MAX + 1];
    BYTE weightList[HUFH_SYMBOLVALUE_MAX + 1];
    U32 calleeWksp[HUFH_READ_STATS_WORKSPACE_SIZE_U32];
} HUFH_ReadDTableX2_Workspace;

size_t HUFH_readDTableX2_wksp(HUFH_DTable* DTable,
                       const void* src, size_t srcSize,
                             void* workSpace, size_t wkspSize, int flags)
{
    U32 tableLog, maxW, nbSymbols;
    DTableDesc dtd = HUFH_getDTableDesc(DTable);
    U32 maxTableLog = dtd.maxTableLog;
    size_t iSize;
    void* dtPtr = DTable+1;   /* force compiler to avoid strict-aliasing */
    HUFH_DEltX2* const dt = (HUFH_DEltX2*)dtPtr;
    U32 *rankStart;

    HUFH_ReadDTableX2_Workspace* const wksp = (HUFH_ReadDTableX2_Workspace*)workSpace;

    if (sizeof(*wksp) > wkspSize) return ERROR(GENERIC);

    rankStart = wksp->rankStart0 + 1;
    ZSTDH_memset(wksp->rankStats, 0, sizeof(wksp->rankStats));
    ZSTDH_memset(wksp->rankStart0, 0, sizeof(wksp->rankStart0));

    DEBUG_STATIC_ASSERT(sizeof(HUFH_DEltX2) == sizeof(HUFH_DTable));   /* if compiler fails here, assertion is wrong */
    if (maxTableLog > HUFH_TABLELOG_MAX) return ERROR(tableLog_tooLarge);
    /* ZSTDH_memset(weightList, 0, sizeof(weightList)); */  /* is not necessary, even though some analyzer complain ... */

    iSize = HUFH_readStats_wksp(wksp->weightList, HUFH_SYMBOLVALUE_MAX + 1, wksp->rankStats, &nbSymbols, &tableLog, src, srcSize, wksp->calleeWksp, sizeof(wksp->calleeWksp), flags);
    if (HUFH_isError(iSize)) return iSize;

    /* check result */
    if (tableLog > maxTableLog) return ERROR(tableLog_tooLarge);   /* DTable can't fit code depth */
    if (tableLog <= HUFH_DECODER_FAST_TABLELOG && maxTableLog > HUFH_DECODER_FAST_TABLELOG) maxTableLog = HUFH_DECODER_FAST_TABLELOG;

    /* find maxWeight */
    for (maxW = tableLog; wksp->rankStats[maxW]==0; maxW--) {}  /* necessarily finds a solution before 0 */

    /* Get start index of each weight */
    {   U32 w, nextRankStart = 0;
        for (w=1; w<maxW+1; w++) {
            U32 curr = nextRankStart;
            nextRankStart += wksp->rankStats[w];
            rankStart[w] = curr;
        }
        rankStart[0] = nextRankStart;   /* put all 0w symbols at the end of sorted list*/
        rankStart[maxW+1] = nextRankStart;
    }

    /* sort symbols by weight */
    {   U32 s;
        for (s=0; s<nbSymbols; s++) {
            U32 const w = wksp->weightList[s];
            U32 const r = rankStart[w]++;
            wksp->sortedSymbol[r].symbol = (BYTE)s;
        }
        rankStart[0] = 0;   /* forget 0w symbols; this is beginning of weight(1) */
    }

    /* Build rankVal */
    {   U32* const rankVal0 = wksp->rankVal[0];
        {   int const rescale = (maxTableLog-tableLog) - 1;   /* tableLog <= maxTableLog */
            U32 nextRankVal = 0;
            U32 w;
            for (w=1; w<maxW+1; w++) {
                U32 curr = nextRankVal;
                nextRankVal += wksp->rankStats[w] << (w+rescale);
                rankVal0[w] = curr;
        }   }
        {   U32 const minBits = tableLog+1 - maxW;
            U32 consumed;
            for (consumed = minBits; consumed < maxTableLog - minBits + 1; consumed++) {
                U32* const rankValPtr = wksp->rankVal[consumed];
                U32 w;
                for (w = 1; w < maxW+1; w++) {
                    rankValPtr[w] = rankVal0[w] >> consumed;
    }   }   }   }

    HUFH_fillDTableX2(dt, maxTableLog,
                   wksp->sortedSymbol,
                   wksp->rankStart0, wksp->rankVal, maxW,
                   tableLog+1);

    dtd.tableLog = (BYTE)maxTableLog;
    dtd.tableType = 1;
    ZSTDH_memcpy(DTable, &dtd, sizeof(dtd));
    return iSize;
}


FORCE_INLINE_TEMPLATE U32
HUFH_decodeSymbolX2(void* op, BIT_DStream_t* DStream, const HUFH_DEltX2* dt, const U32 dtLog)
{
    size_t const val = BIT_lookBitsFast(DStream, dtLog);   /* note : dtLog >= 1 */
    ZSTDH_memcpy(op, &dt[val].sequence, 2);
    BIT_skipBits(DStream, dt[val].nbBits);
    return dt[val].length;
}

FORCE_INLINE_TEMPLATE U32
HUFH_decodeLastSymbolX2(void* op, BIT_DStream_t* DStream, const HUFH_DEltX2* dt, const U32 dtLog)
{
    size_t const val = BIT_lookBitsFast(DStream, dtLog);   /* note : dtLog >= 1 */
    ZSTDH_memcpy(op, &dt[val].sequence, 1);
    if (dt[val].length==1) {
        BIT_skipBits(DStream, dt[val].nbBits);
    } else {
        if (DStream->bitsConsumed < (sizeof(DStream->bitContainer)*8)) {
            BIT_skipBits(DStream, dt[val].nbBits);
            if (DStream->bitsConsumed > (sizeof(DStream->bitContainer)*8))
                /* ugly hack; works only because it's the last symbol. Note : can't easily extract nbBits from just this symbol */
                DStream->bitsConsumed = (sizeof(DStream->bitContainer)*8);
        }
    }
    return 1;
}

#define HUFH_DECODE_SYMBOLX2_0(ptr, DStreamPtr) \
    do { ptr += HUFH_decodeSymbolX2(ptr, DStreamPtr, dt, dtLog); } while (0)

#define HUFH_DECODE_SYMBOLX2_1(ptr, DStreamPtr)                     \
    do {                                                           \
        if (MEM_64bits() || (HUFH_TABLELOG_MAX<=12))                \
            ptr += HUFH_decodeSymbolX2(ptr, DStreamPtr, dt, dtLog); \
    } while (0)

#define HUFH_DECODE_SYMBOLX2_2(ptr, DStreamPtr)                     \
    do {                                                           \
        if (MEM_64bits())                                          \
            ptr += HUFH_decodeSymbolX2(ptr, DStreamPtr, dt, dtLog); \
    } while (0)

HINT_INLINE size_t
HUFH_decodeStreamX2(BYTE* p, BIT_DStream_t* bitDPtr, BYTE* const pEnd,
                const HUFH_DEltX2* const dt, const U32 dtLog)
{
    BYTE* const pStart = p;

    /* up to 8 symbols at a time */
    if ((size_t)(pEnd - p) >= sizeof(bitDPtr->bitContainer)) {
        if (dtLog <= 11 && MEM_64bits()) {
            /* up to 10 symbols at a time */
            while ((BIT_reloadDStream(bitDPtr) == BIT_DStream_unfinished) & (p < pEnd-9)) {
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
            }
        } else {
            /* up to 8 symbols at a time */
            while ((BIT_reloadDStream(bitDPtr) == BIT_DStream_unfinished) & (p < pEnd-(sizeof(bitDPtr->bitContainer)-1))) {
                HUFH_DECODE_SYMBOLX2_2(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_1(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_2(p, bitDPtr);
                HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);
            }
        }
    } else {
        BIT_reloadDStream(bitDPtr);
    }

    /* closer to end : up to 2 symbols at a time */
    if ((size_t)(pEnd - p) >= 2) {
        while ((BIT_reloadDStream(bitDPtr) == BIT_DStream_unfinished) & (p <= pEnd-2))
            HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);

        while (p <= pEnd-2)
            HUFH_DECODE_SYMBOLX2_0(p, bitDPtr);   /* no need to reload : reached the end of DStream */
    }

    if (p < pEnd)
        p += HUFH_decodeLastSymbolX2(p, bitDPtr, dt, dtLog);

    return p-pStart;
}

FORCE_INLINE_TEMPLATE size_t
HUFH_decompress1X2_usingDTable_internal_body(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable)
{
    BIT_DStream_t bitD;

    /* Init */
    CHECK_F( BIT_initDStream(&bitD, cSrc, cSrcSize) );

    /* decode */
    {   BYTE* const ostart = (BYTE*) dst;
        BYTE* const oend = ZSTDH_maybeNullPtrAdd(ostart, dstSize);
        const void* const dtPtr = DTable+1;   /* force compiler to not use strict-aliasing */
        const HUFH_DEltX2* const dt = (const HUFH_DEltX2*)dtPtr;
        DTableDesc const dtd = HUFH_getDTableDesc(DTable);
        HUFH_decodeStreamX2(ostart, &bitD, oend, dt, dtd.tableLog);
    }

    /* check */
    if (!BIT_endOfDStream(&bitD)) return ERROR(corruption_detected);

    /* decoded size */
    return dstSize;
}

/* HUFH_decompress4X2_usingDTable_internal_body():
 * Conditions:
 * @dstSize >= 6
 */
FORCE_INLINE_TEMPLATE size_t
HUFH_decompress4X2_usingDTable_internal_body(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable)
{
    if (cSrcSize < 10) return ERROR(corruption_detected);   /* strict minimum : jump table + 1 byte per stream */
    if (dstSize < 6) return ERROR(corruption_detected);         /* stream 4-split doesn't work */

    {   const BYTE* const istart = (const BYTE*) cSrc;
        BYTE* const ostart = (BYTE*) dst;
        BYTE* const oend = ostart + dstSize;
        BYTE* const olimit = oend - (sizeof(size_t)-1);
        const void* const dtPtr = DTable+1;
        const HUFH_DEltX2* const dt = (const HUFH_DEltX2*)dtPtr;

        /* Init */
        BIT_DStream_t bitD1;
        BIT_DStream_t bitD2;
        BIT_DStream_t bitD3;
        BIT_DStream_t bitD4;
        size_t const length1 = MEM_readLE16(istart);
        size_t const length2 = MEM_readLE16(istart+2);
        size_t const length3 = MEM_readLE16(istart+4);
        size_t const length4 = cSrcSize - (length1 + length2 + length3 + 6);
        const BYTE* const istart1 = istart + 6;  /* jumpTable */
        const BYTE* const istart2 = istart1 + length1;
        const BYTE* const istart3 = istart2 + length2;
        const BYTE* const istart4 = istart3 + length3;
        size_t const segmentSize = (dstSize+3) / 4;
        BYTE* const opStart2 = ostart + segmentSize;
        BYTE* const opStart3 = opStart2 + segmentSize;
        BYTE* const opStart4 = opStart3 + segmentSize;
        BYTE* op1 = ostart;
        BYTE* op2 = opStart2;
        BYTE* op3 = opStart3;
        BYTE* op4 = opStart4;
        U32 endSignal = 1;
        DTableDesc const dtd = HUFH_getDTableDesc(DTable);
        U32 const dtLog = dtd.tableLog;

        if (length4 > cSrcSize) return ERROR(corruption_detected);  /* overflow */
        if (opStart4 > oend) return ERROR(corruption_detected);     /* overflow */
        assert(dstSize >= 6 /* validated above */);
        CHECK_F( BIT_initDStream(&bitD1, istart1, length1) );
        CHECK_F( BIT_initDStream(&bitD2, istart2, length2) );
        CHECK_F( BIT_initDStream(&bitD3, istart3, length3) );
        CHECK_F( BIT_initDStream(&bitD4, istart4, length4) );

        /* 16-32 symbols per loop (4-8 symbols per stream) */
        if ((size_t)(oend - op4) >= sizeof(size_t)) {
            for ( ; (endSignal) & (op4 < olimit); ) {
#if defined(__clang__) && (defined(__x86_64__) || defined(__i386__))
                HUFH_DECODE_SYMBOLX2_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_1(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_0(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_1(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_0(op2, &bitD2);
                endSignal &= BIT_reloadDStreamFast(&bitD1) == BIT_DStream_unfinished;
                endSignal &= BIT_reloadDStreamFast(&bitD2) == BIT_DStream_unfinished;
                HUFH_DECODE_SYMBOLX2_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_1(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_0(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_1(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_0(op4, &bitD4);
                endSignal &= BIT_reloadDStreamFast(&bitD3) == BIT_DStream_unfinished;
                endSignal &= BIT_reloadDStreamFast(&bitD4) == BIT_DStream_unfinished;
#else
                HUFH_DECODE_SYMBOLX2_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_1(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_1(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_1(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_1(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_2(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_2(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_2(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_2(op4, &bitD4);
                HUFH_DECODE_SYMBOLX2_0(op1, &bitD1);
                HUFH_DECODE_SYMBOLX2_0(op2, &bitD2);
                HUFH_DECODE_SYMBOLX2_0(op3, &bitD3);
                HUFH_DECODE_SYMBOLX2_0(op4, &bitD4);
                endSignal = (U32)LIKELY((U32)
                            (BIT_reloadDStreamFast(&bitD1) == BIT_DStream_unfinished)
                        & (BIT_reloadDStreamFast(&bitD2) == BIT_DStream_unfinished)
                        & (BIT_reloadDStreamFast(&bitD3) == BIT_DStream_unfinished)
                        & (BIT_reloadDStreamFast(&bitD4) == BIT_DStream_unfinished));
#endif
            }
        }

        /* check corruption */
        if (op1 > opStart2) return ERROR(corruption_detected);
        if (op2 > opStart3) return ERROR(corruption_detected);
        if (op3 > opStart4) return ERROR(corruption_detected);
        /* note : op4 already verified within main loop */

        /* finish bitStreams one by one */
        HUFH_decodeStreamX2(op1, &bitD1, opStart2, dt, dtLog);
        HUFH_decodeStreamX2(op2, &bitD2, opStart3, dt, dtLog);
        HUFH_decodeStreamX2(op3, &bitD3, opStart4, dt, dtLog);
        HUFH_decodeStreamX2(op4, &bitD4, oend,     dt, dtLog);

        /* check */
        { U32 const endCheck = BIT_endOfDStream(&bitD1) & BIT_endOfDStream(&bitD2) & BIT_endOfDStream(&bitD3) & BIT_endOfDStream(&bitD4);
          if (!endCheck) return ERROR(corruption_detected); }

        /* decoded size */
        return dstSize;
    }
}

#if HUFH_NEED_BMI2_FUNCTION
static BMI2_TARGET_ATTRIBUTE
size_t HUFH_decompress4X2_usingDTable_internal_bmi2(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable) {
    return HUFH_decompress4X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable);
}
#endif

static
size_t HUFH_decompress4X2_usingDTable_internal_default(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable) {
    return HUFH_decompress4X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable);
}

#if ZSTDH_ENABLE_ASM_X86_64_BMI2

HUFH_ASM_DECL void HUFH_decompress4X2_usingDTable_internal_fast_asm_loop(HUFH_DecompressFastArgs* args) ZSTDLIB_HIDDEN;

#endif

static HUFH_FAST_BMI2_ATTRS
void HUFH_decompress4X2_usingDTable_internal_fast_c_loop(HUFH_DecompressFastArgs* args)
{
    U64 bits[4];
    BYTE const* ip[4];
    BYTE* op[4];
    BYTE* oend[4];
    HUFH_DEltX2 const* const dtable = (HUFH_DEltX2 const*)args->dt;
    BYTE const* const ilowest = args->ilowest;

    /* Copy the arguments to local registers. */
    ZSTDH_memcpy(&bits, &args->bits, sizeof(bits));
    ZSTDH_memcpy((void*)(&ip), &args->ip, sizeof(ip));
    ZSTDH_memcpy(&op, &args->op, sizeof(op));

    oend[0] = op[1];
    oend[1] = op[2];
    oend[2] = op[3];
    oend[3] = args->oend;

    assert(MEM_isLittleEndian());
    assert(!MEM_32bits());

    for (;;) {
        BYTE* olimit;
        int stream;

        /* Assert loop preconditions */
#ifndef NDEBUG
        for (stream = 0; stream < 4; ++stream) {
            assert(op[stream] <= oend[stream]);
            assert(ip[stream] >= ilowest);
        }
#endif
        /* Compute olimit */
        {
            /* Each loop does 5 table lookups for each of the 4 streams.
             * Each table lookup consumes up to 11 bits of input, and produces
             * up to 2 bytes of output.
             */
            /* We can consume up to 7 bytes of input per iteration per stream.
             * We also know that each input pointer is >= ip[0]. So we can run
             * iters loops before running out of input.
             */
            size_t iters = (size_t)(ip[0] - ilowest) / 7;
            /* Each iteration can produce up to 10 bytes of output per stream.
             * Each output stream my advance at different rates. So take the
             * minimum number of safe iterations among all the output streams.
             */
            for (stream = 0; stream < 4; ++stream) {
                size_t const oiters = (size_t)(oend[stream] - op[stream]) / 10;
                iters = MIN(iters, oiters);
            }

            /* Each iteration produces at least 5 output symbols. So until
             * op[3] crosses olimit, we know we haven't executed iters
             * iterations yet. This saves us maintaining an iters counter,
             * at the expense of computing the remaining # of iterations
             * more frequently.
             */
            olimit = op[3] + (iters * 5);

            /* Exit the fast decoding loop once we reach the end. */
            if (op[3] == olimit)
                break;

            /* Exit the decoding loop if any input pointer has crossed the
             * previous one. This indicates corruption, and a precondition
             * to our loop is that ip[i] >= ip[0].
             */
            for (stream = 1; stream < 4; ++stream) {
                if (ip[stream] < ip[stream - 1])
                    goto _out;
            }
        }

#ifndef NDEBUG
        for (stream = 1; stream < 4; ++stream) {
            assert(ip[stream] >= ip[stream - 1]);
        }
#endif

#define HUFH_4X2_DECODE_SYMBOL(_stream, _decode3)               \
    do {                                                       \
        if ((_decode3) || (_stream) != 3) {                    \
            U64 const index = bits[(_stream)] >> 53;           \
            size_t const entry = MEM_readLE32(&dtable[index]); \
            MEM_write16(op[(_stream)], (U16)entry);            \
            bits[(_stream)] <<= (entry >> 16) & 0x3F;          \
            op[(_stream)] += entry >> 24;                      \
        }                                                      \
    } while (0)

#define HUFH_5X2_RELOAD_STREAM(_stream, _decode3)                        \
    do {                                                                \
        if (_decode3) HUFH_4X2_DECODE_SYMBOL(3, 1);                      \
        {                                                               \
            U64 const ctz = ZSTDH_countTrailingZeros64(bits[(_stream)]); \
            U64 const nbBits = ctz & 7;                                 \
            U64 const nbBytes = ctz >> 3;                               \
            ip[(_stream)] -= nbBytes;                                   \
            bits[(_stream)] = MEM_read64(ip[(_stream)]) | 1;            \
            bits[(_stream)] <<= nbBits;                                 \
        }                                                               \
    } while (0)

#if defined(__aarch64__)
#  define HUFH_4X2_4WAY 1
#else
#  define HUFH_4X2_4WAY 0
#endif
#define HUFH_4X2_3WAY !HUFH_4X2_4WAY

        /* Manually unroll the loop because compilers don't consistently
         * unroll the inner loops, which destroys performance.
         */
        do {
            /* Decode 5 symbols from each of the first 3 or 4 streams.
             * In the 3-way case the final stream will be decoded during
             * the reload phase to reduce register pressure.
             */
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X2_DECODE_SYMBOL, HUFH_4X2_4WAY);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X2_DECODE_SYMBOL, HUFH_4X2_4WAY);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X2_DECODE_SYMBOL, HUFH_4X2_4WAY);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X2_DECODE_SYMBOL, HUFH_4X2_4WAY);
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_4X2_DECODE_SYMBOL, HUFH_4X2_4WAY);

            /* In the 3-way case decode one symbol from the final stream. */
            HUFH_4X2_DECODE_SYMBOL(3, HUFH_4X2_3WAY);

            /* In the 3-way case decode 4 symbols from the final stream &
             * reload bitstreams. The final stream is reloaded last, meaning
             * that all 5 symbols are decoded from the final stream before
             * it is reloaded.
             */
            HUFH_4X_FOR_EACH_STREAM_WITH_VAR(HUFH_5X2_RELOAD_STREAM, HUFH_4X2_3WAY);
        } while (op[3] < olimit);
    }

#undef HUFH_4X2_DECODE_SYMBOL
#undef HUFH_5X2_RELOAD_STREAM

_out:

    /* Save the final values of each of the state variables back to args. */
    ZSTDH_memcpy(&args->bits, &bits, sizeof(bits));
    ZSTDH_memcpy((void*)(&args->ip), &ip, sizeof(ip));
    ZSTDH_memcpy(&args->op, &op, sizeof(op));
}


static HUFH_FAST_BMI2_ATTRS size_t
HUFH_decompress4X2_usingDTable_internal_fast(
          void* dst,  size_t dstSize,
    const void* cSrc, size_t cSrcSize,
    const HUFH_DTable* DTable,
    HUFH_DecompressFastLoopFn loopFn) {
    void const* dt = DTable + 1;
    const BYTE* const ilowest = (const BYTE*)cSrc;
    BYTE* const oend = ZSTDH_maybeNullPtrAdd((BYTE*)dst, dstSize);
    HUFH_DecompressFastArgs args;
    {
        size_t const ret = HUFH_DecompressFastArgs_init(&args, dst, dstSize, cSrc, cSrcSize, DTable);
        FORWARD_IF_ERROR(ret, "Failed to init asm args");
        if (ret == 0)
            return 0;
    }

    assert(args.ip[0] >= args.ilowest);
    loopFn(&args);

    /* note : op4 already verified within main loop */
    assert(args.ip[0] >= ilowest);
    assert(args.ip[1] >= ilowest);
    assert(args.ip[2] >= ilowest);
    assert(args.ip[3] >= ilowest);
    assert(args.op[3] <= oend);

    assert(ilowest == args.ilowest);
    assert(ilowest + 6 == args.iend[0]);
    (void)ilowest;

    /* finish bitStreams one by one */
    {
        size_t const segmentSize = (dstSize+3) / 4;
        BYTE* segmentEnd = (BYTE*)dst;
        int i;
        for (i = 0; i < 4; ++i) {
            BIT_DStream_t bit;
            if (segmentSize <= (size_t)(oend - segmentEnd))
                segmentEnd += segmentSize;
            else
                segmentEnd = oend;
            FORWARD_IF_ERROR(HUFH_initRemainingDStream(&bit, &args, i, segmentEnd), "corruption");
            args.op[i] += HUFH_decodeStreamX2(args.op[i], &bit, segmentEnd, (HUFH_DEltX2 const*)dt, HUFH_DECODER_FAST_TABLELOG);
            if (args.op[i] != segmentEnd)
                return ERROR(corruption_detected);
        }
    }

    /* decoded size */
    return dstSize;
}

static size_t HUFH_decompress4X2_usingDTable_internal(void* dst, size_t dstSize, void const* cSrc,
                    size_t cSrcSize, HUFH_DTable const* DTable, int flags)
{
    HUFH_DecompressUsingDTableFn fallbackFn = HUFH_decompress4X2_usingDTable_internal_default;
    HUFH_DecompressFastLoopFn loopFn = HUFH_decompress4X2_usingDTable_internal_fast_c_loop;

#if DYNAMIC_BMI2
    if (flags & HUFH_flags_bmi2) {
        fallbackFn = HUFH_decompress4X2_usingDTable_internal_bmi2;
# if ZSTDH_ENABLE_ASM_X86_64_BMI2
        if (!(flags & HUFH_flags_disableAsm)) {
            loopFn = HUFH_decompress4X2_usingDTable_internal_fast_asm_loop;
        }
# endif
    } else {
        return fallbackFn(dst, dstSize, cSrc, cSrcSize, DTable);
    }
#endif

#if ZSTDH_ENABLE_ASM_X86_64_BMI2 && defined(__BMI2__)
    if (!(flags & HUFH_flags_disableAsm)) {
        loopFn = HUFH_decompress4X2_usingDTable_internal_fast_asm_loop;
    }
#endif

    if (HUFH_ENABLE_FAST_DECODE && !(flags & HUFH_flags_disableFast)) {
        size_t const ret = HUFH_decompress4X2_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable, loopFn);
        if (ret != 0)
            return ret;
    }
    return fallbackFn(dst, dstSize, cSrc, cSrcSize, DTable);
}

HUFH_DGEN(HUFH_decompress1X2_usingDTable_internal)

size_t HUFH_decompress1X2_DCtx_wksp(HUFH_DTable* DCtx, void* dst, size_t dstSize,
                                   const void* cSrc, size_t cSrcSize,
                                   void* workSpace, size_t wkspSize, int flags)
{
    const BYTE* ip = (const BYTE*) cSrc;

    size_t const hSize = HUFH_readDTableX2_wksp(DCtx, cSrc, cSrcSize,
                                               workSpace, wkspSize, flags);
    if (HUFH_isError(hSize)) return hSize;
    if (hSize >= cSrcSize) return ERROR(srcSize_wrong);
    ip += hSize; cSrcSize -= hSize;

    return HUFH_decompress1X2_usingDTable_internal(dst, dstSize, ip, cSrcSize, DCtx, flags);
}

static size_t HUFH_decompress4X2_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize,
                                   const void* cSrc, size_t cSrcSize,
                                   void* workSpace, size_t wkspSize, int flags)
{
    const BYTE* ip = (const BYTE*) cSrc;

    size_t hSize = HUFH_readDTableX2_wksp(dctx, cSrc, cSrcSize,
                                         workSpace, wkspSize, flags);
    if (HUFH_isError(hSize)) return hSize;
    if (hSize >= cSrcSize) return ERROR(srcSize_wrong);
    ip += hSize; cSrcSize -= hSize;

    return HUFH_decompress4X2_usingDTable_internal(dst, dstSize, ip, cSrcSize, dctx, flags);
}

#endif /* HUFH_FORCE_DECOMPRESS_X1 */


/* ***********************************/
/* Universal decompression selectors */
/* ***********************************/


#if !defined(HUFH_FORCE_DECOMPRESS_X1) && !defined(HUFH_FORCE_DECOMPRESS_X2)
typedef struct { U32 tableTime; U32 decode256Time; } algo_time_t;
static const algo_time_t algoTime[16 /* Quantization */][2 /* single, double */] =
{
    /* single, double, quad */
    {{0,0}, {1,1}},  /* Q==0 : impossible */
    {{0,0}, {1,1}},  /* Q==1 : impossible */
    {{ 150,216}, { 381,119}},   /* Q == 2 : 12-18% */
    {{ 170,205}, { 514,112}},   /* Q == 3 : 18-25% */
    {{ 177,199}, { 539,110}},   /* Q == 4 : 25-32% */
    {{ 197,194}, { 644,107}},   /* Q == 5 : 32-38% */
    {{ 221,192}, { 735,107}},   /* Q == 6 : 38-44% */
    {{ 256,189}, { 881,106}},   /* Q == 7 : 44-50% */
    {{ 359,188}, {1167,109}},   /* Q == 8 : 50-56% */
    {{ 582,187}, {1570,114}},   /* Q == 9 : 56-62% */
    {{ 688,187}, {1712,122}},   /* Q ==10 : 62-69% */
    {{ 825,186}, {1965,136}},   /* Q ==11 : 69-75% */
    {{ 976,185}, {2131,150}},   /* Q ==12 : 75-81% */
    {{1180,186}, {2070,175}},   /* Q ==13 : 81-87% */
    {{1377,185}, {1731,202}},   /* Q ==14 : 87-93% */
    {{1412,185}, {1695,202}},   /* Q ==15 : 93-99% */
};
#endif

/* HUFH_selectDecoder() :
 *  Tells which decoder is likely to decode faster,
 *  based on a set of pre-computed metrics.
 * @return : 0==HUFH_decompress4X1, 1==HUFH_decompress4X2 .
 *  Assumption : 0 < dstSize <= 128 KB */
U32 HUFH_selectDecoder (size_t dstSize, size_t cSrcSize)
{
    assert(dstSize > 0);
    assert(dstSize <= 128*1024);
#if defined(HUFH_FORCE_DECOMPRESS_X1)
    (void)dstSize;
    (void)cSrcSize;
    return 0;
#elif defined(HUFH_FORCE_DECOMPRESS_X2)
    (void)dstSize;
    (void)cSrcSize;
    return 1;
#else
    /* decoder timing evaluation */
    {   U32 const Q = (cSrcSize >= dstSize) ? 15 : (U32)(cSrcSize * 16 / dstSize);   /* Q < 16 */
        U32 const D256 = (U32)(dstSize >> 8);
        U32 const DTime0 = algoTime[Q][0].tableTime + (algoTime[Q][0].decode256Time * D256);
        U32 DTime1 = algoTime[Q][1].tableTime + (algoTime[Q][1].decode256Time * D256);
        DTime1 += DTime1 >> 5;  /* small advantage to algorithm using less memory, to reduce cache eviction */
        return DTime1 < DTime0;
    }
#endif
}

size_t HUFH_decompress1X_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize,
                                  const void* cSrc, size_t cSrcSize,
                                  void* workSpace, size_t wkspSize, int flags)
{
    /* validation checks */
    if (dstSize == 0) return ERROR(dstSize_tooSmall);
    if (cSrcSize > dstSize) return ERROR(corruption_detected);   /* invalid */
    if (cSrcSize == dstSize) { ZSTDH_memcpy(dst, cSrc, dstSize); return dstSize; }   /* not compressed */
    if (cSrcSize == 1) { ZSTDH_memset(dst, *(const BYTE*)cSrc, dstSize); return dstSize; }   /* RLE */

    {   U32 const algoNb = HUFH_selectDecoder(dstSize, cSrcSize);
#if defined(HUFH_FORCE_DECOMPRESS_X1)
        (void)algoNb;
        assert(algoNb == 0);
        return HUFH_decompress1X1_DCtx_wksp(dctx, dst, dstSize, cSrc,
                                cSrcSize, workSpace, wkspSize, flags);
#elif defined(HUFH_FORCE_DECOMPRESS_X2)
        (void)algoNb;
        assert(algoNb == 1);
        return HUFH_decompress1X2_DCtx_wksp(dctx, dst, dstSize, cSrc,
                                cSrcSize, workSpace, wkspSize, flags);
#else
        return algoNb ? HUFH_decompress1X2_DCtx_wksp(dctx, dst, dstSize, cSrc,
                                cSrcSize, workSpace, wkspSize, flags):
                        HUFH_decompress1X1_DCtx_wksp(dctx, dst, dstSize, cSrc,
                                cSrcSize, workSpace, wkspSize, flags);
#endif
    }
}


size_t HUFH_decompress1X_usingDTable(void* dst, size_t maxDstSize, const void* cSrc, size_t cSrcSize, const HUFH_DTable* DTable, int flags)
{
    DTableDesc const dtd = HUFH_getDTableDesc(DTable);
#if defined(HUFH_FORCE_DECOMPRESS_X1)
    (void)dtd;
    assert(dtd.tableType == 0);
    return HUFH_decompress1X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#elif defined(HUFH_FORCE_DECOMPRESS_X2)
    (void)dtd;
    assert(dtd.tableType == 1);
    return HUFH_decompress1X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#else
    return dtd.tableType ? HUFH_decompress1X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags) :
                           HUFH_decompress1X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#endif
}

#ifndef HUFH_FORCE_DECOMPRESS_X2
size_t HUFH_decompress1X1_DCtx_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags)
{
    const BYTE* ip = (const BYTE*) cSrc;

    size_t const hSize = HUFH_readDTableX1_wksp(dctx, cSrc, cSrcSize, workSpace, wkspSize, flags);
    if (HUFH_isError(hSize)) return hSize;
    if (hSize >= cSrcSize) return ERROR(srcSize_wrong);
    ip += hSize; cSrcSize -= hSize;

    return HUFH_decompress1X1_usingDTable_internal(dst, dstSize, ip, cSrcSize, dctx, flags);
}
#endif

size_t HUFH_decompress4X_usingDTable(void* dst, size_t maxDstSize, const void* cSrc, size_t cSrcSize, const HUFH_DTable* DTable, int flags)
{
    DTableDesc const dtd = HUFH_getDTableDesc(DTable);
#if defined(HUFH_FORCE_DECOMPRESS_X1)
    (void)dtd;
    assert(dtd.tableType == 0);
    return HUFH_decompress4X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#elif defined(HUFH_FORCE_DECOMPRESS_X2)
    (void)dtd;
    assert(dtd.tableType == 1);
    return HUFH_decompress4X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#else
    return dtd.tableType ? HUFH_decompress4X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags) :
                           HUFH_decompress4X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags);
#endif
}

size_t HUFH_decompress4X_hufOnly_wksp(HUFH_DTable* dctx, void* dst, size_t dstSize, const void* cSrc, size_t cSrcSize, void* workSpace, size_t wkspSize, int flags)
{
    /* validation checks */
    if (dstSize == 0) return ERROR(dstSize_tooSmall);
    if (cSrcSize == 0) return ERROR(corruption_detected);

    {   U32 const algoNb = HUFH_selectDecoder(dstSize, cSrcSize);
#if defined(HUFH_FORCE_DECOMPRESS_X1)
        (void)algoNb;
        assert(algoNb == 0);
        return HUFH_decompress4X1_DCtx_wksp(dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags);
#elif defined(HUFH_FORCE_DECOMPRESS_X2)
        (void)algoNb;
        assert(algoNb == 1);
        return HUFH_decompress4X2_DCtx_wksp(dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags);
#else
        return algoNb ? HUFH_decompress4X2_DCtx_wksp(dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags) :
                        HUFH_decompress4X1_DCtx_wksp(dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags);
#endif
    }
}
