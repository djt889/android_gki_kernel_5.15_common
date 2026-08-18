// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/* ******************************************************************
 * Huffman encoder, part of New Generation Entropy library
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 *  You can contact the author at :
 *  - FSE+HUF source repository : https://github.com/Cyan4973/FiniteStateEntropy
 *  - Public forum : https://groups.google.com/forum/#!forum/lz4c
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
****************************************************************** */

/* **************************************************************
*  Compiler specifics
****************************************************************/


/* **************************************************************
*  Includes
****************************************************************/
#include "../common/zstd_deps.h"     /* ZSTDH_memcpy, ZSTDH_memset */
#include "../common/compiler.h"
#include "../common/bitstream.h"
#include "hist.h"
#define FSEH_STATIC_LINKING_ONLY   /* FSEH_optimalTableLog_internal */
#include "../common/fse.h"        /* header compression */
#include "../common/huf.h"
#include "../common/error_private.h"
#include "../common/bits.h"       /* ZSTDH_highbit32 */


/* **************************************************************
*  Error Management
****************************************************************/
#define HUFH_isError ERR_isError
#define HUFH_STATIC_ASSERT(c) DEBUG_STATIC_ASSERT(c)   /* use only *after* variable declarations */


/* **************************************************************
*  Required declarations
****************************************************************/
typedef struct nodeElt_s {
    U32 count;
    U16 parent;
    BYTE byte;
    BYTE nbBits;
} nodeElt;


/* **************************************************************
*  Debug Traces
****************************************************************/

#if DEBUGLEVEL >= 2

static size_t showU32(const U32* arr, size_t size)
{
    size_t u;
    for (u=0; u<size; u++) {
        RAWLOG(6, " %u", arr[u]); (void)arr;
    }
    RAWLOG(6, " \n");
    return size;
}

static size_t HUFH_getNbBits(HUFH_CElt elt);

static size_t showCTableBits(const HUFH_CElt* ctable, size_t size)
{
    size_t u;
    for (u=0; u<size; u++) {
        RAWLOG(6, " %zu", HUFH_getNbBits(ctable[u])); (void)ctable;
    }
    RAWLOG(6, " \n");
    return size;

}

static size_t showHNodeSymbols(const nodeElt* hnode, size_t size)
{
    size_t u;
    for (u=0; u<size; u++) {
        RAWLOG(6, " %u", hnode[u].byte); (void)hnode;
    }
    RAWLOG(6, " \n");
    return size;
}

static size_t showHNodeBits(const nodeElt* hnode, size_t size)
{
    size_t u;
    for (u=0; u<size; u++) {
        RAWLOG(6, " %u", hnode[u].nbBits); (void)hnode;
    }
    RAWLOG(6, " \n");
    return size;
}

#endif


/* *******************************************************
*  HUF : Huffman block compression
*********************************************************/
#define HUFH_WORKSPACE_MAX_ALIGNMENT 8

static void* HUFH_alignUpWorkspace(void* workspace, size_t* workspaceSizePtr, size_t align)
{
    size_t const mask = align - 1;
    size_t const rem = (size_t)workspace & mask;
    size_t const add = (align - rem) & mask;
    BYTE* const aligned = (BYTE*)workspace + add;
    assert((align & (align - 1)) == 0); /* pow 2 */
    assert(align <= HUFH_WORKSPACE_MAX_ALIGNMENT);
    if (*workspaceSizePtr >= add) {
        assert(add < align);
        assert(((size_t)aligned & mask) == 0);
        *workspaceSizePtr -= add;
        return aligned;
    } else {
        *workspaceSizePtr = 0;
        return NULL;
    }
}


/* HUFH_compressWeights() :
 * Same as FSEH_compress(), but dedicated to huff0's weights compression.
 * The use case needs much less stack memory.
 * Note : all elements within weightTable are supposed to be <= HUFH_TABLELOG_MAX.
 */
#define MAX_FSEH_TABLELOG_FOR_HUFF_HEADER 6

typedef struct {
    FSEH_CTable CTable[FSEH_CTABLE_SIZE_U32(MAX_FSEH_TABLELOG_FOR_HUFF_HEADER, HUFH_TABLELOG_MAX)];
    U32 scratchBuffer[FSEH_BUILD_CTABLE_WORKSPACE_SIZE_U32(HUFH_TABLELOG_MAX, MAX_FSEH_TABLELOG_FOR_HUFF_HEADER)];
    unsigned count[HUFH_TABLELOG_MAX+1];
    S16 norm[HUFH_TABLELOG_MAX+1];
} HUFH_CompressWeightsWksp;

static size_t
HUFH_compressWeights(void* dst, size_t dstSize,
              const void* weightTable, size_t wtSize,
                    void* workspace, size_t workspaceSize)
{
    BYTE* const ostart = (BYTE*) dst;
    BYTE* op = ostart;
    BYTE* const oend = ostart + dstSize;

    unsigned maxSymbolValue = HUFH_TABLELOG_MAX;
    U32 tableLog = MAX_FSEH_TABLELOG_FOR_HUFF_HEADER;
    HUFH_CompressWeightsWksp* wksp = (HUFH_CompressWeightsWksp*)HUFH_alignUpWorkspace(workspace, &workspaceSize, ZSTDH_ALIGNOF(U32));

    if (workspaceSize < sizeof(HUFH_CompressWeightsWksp)) return ERROR(GENERIC);

    /* init conditions */
    if (wtSize <= 1) return 0;  /* Not compressible */

    /* Scan input and build symbol stats */
    {   unsigned const maxCount = HISTH_count_simple(wksp->count, &maxSymbolValue, weightTable, wtSize);   /* never fails */
        if (maxCount == wtSize) return 1;   /* only a single symbol in src : rle */
        if (maxCount == 1) return 0;        /* each symbol present maximum once => not compressible */
    }

    tableLog = FSEH_optimalTableLog(tableLog, wtSize, maxSymbolValue);
    CHECK_F( FSEH_normalizeCount(wksp->norm, tableLog, wksp->count, wtSize, maxSymbolValue, /* useLowProbCount */ 0) );

    /* Write table description header */
    {   CHECK_V_F(hSize, FSEH_writeNCount(op, (size_t)(oend-op), wksp->norm, maxSymbolValue, tableLog) );
        op += hSize;
    }

    /* Compress */
    CHECK_F( FSEH_buildCTable_wksp(wksp->CTable, wksp->norm, maxSymbolValue, tableLog, wksp->scratchBuffer, sizeof(wksp->scratchBuffer)) );
    {   CHECK_V_F(cSize, FSEH_compress_usingCTable(op, (size_t)(oend - op), weightTable, wtSize, wksp->CTable) );
        if (cSize == 0) return 0;   /* not enough space for compressed data */
        op += cSize;
    }

    return (size_t)(op-ostart);
}

static size_t HUFH_getNbBits(HUFH_CElt elt)
{
    return elt & 0xFF;
}

static size_t HUFH_getNbBitsFast(HUFH_CElt elt)
{
    return elt;
}

static size_t HUFH_getValue(HUFH_CElt elt)
{
    return elt & ~(size_t)0xFF;
}

static size_t HUFH_getValueFast(HUFH_CElt elt)
{
    return elt;
}

static void HUFH_setNbBits(HUFH_CElt* elt, size_t nbBits)
{
    assert(nbBits <= HUFH_TABLELOG_ABSOLUTEMAX);
    *elt = nbBits;
}

static void HUFH_setValue(HUFH_CElt* elt, size_t value)
{
    size_t const nbBits = HUFH_getNbBits(*elt);
    if (nbBits > 0) {
        assert((value >> nbBits) == 0);
        *elt |= value << (sizeof(HUFH_CElt) * 8 - nbBits);
    }
}

HUFH_CTableHeader HUFH_readCTableHeader(HUFH_CElt const* ctable)
{
    HUFH_CTableHeader header;
    ZSTDH_memcpy(&header, ctable, sizeof(header));
    return header;
}

static void HUFH_writeCTableHeader(HUFH_CElt* ctable, U32 tableLog, U32 maxSymbolValue)
{
    HUFH_CTableHeader header;
    HUFH_STATIC_ASSERT(sizeof(ctable[0]) == sizeof(header));
    ZSTDH_memset(&header, 0, sizeof(header));
    assert(tableLog < 256);
    header.tableLog = (BYTE)tableLog;
    assert(maxSymbolValue < 256);
    header.maxSymbolValue = (BYTE)maxSymbolValue;
    ZSTDH_memcpy(ctable, &header, sizeof(header));
}

typedef struct {
    HUFH_CompressWeightsWksp wksp;
    BYTE bitsToWeight[HUFH_TABLELOG_MAX + 1];   /* precomputed conversion table */
    BYTE huffWeight[HUFH_SYMBOLVALUE_MAX];
} HUFH_WriteCTableWksp;

size_t HUFH_writeCTable_wksp(void* dst, size_t maxDstSize,
                            const HUFH_CElt* CTable, unsigned maxSymbolValue, unsigned huffLog,
                            void* workspace, size_t workspaceSize)
{
    HUFH_CElt const* const ct = CTable + 1;
    BYTE* op = (BYTE*)dst;
    U32 n;
    HUFH_WriteCTableWksp* wksp = (HUFH_WriteCTableWksp*)HUFH_alignUpWorkspace(workspace, &workspaceSize, ZSTDH_ALIGNOF(U32));

    HUFH_STATIC_ASSERT(HUFH_CTABLE_WORKSPACE_SIZE >= sizeof(HUFH_WriteCTableWksp));

    assert(HUFH_readCTableHeader(CTable).maxSymbolValue == maxSymbolValue);
    assert(HUFH_readCTableHeader(CTable).tableLog == huffLog);

    /* check conditions */
    if (workspaceSize < sizeof(HUFH_WriteCTableWksp)) return ERROR(GENERIC);
    if (maxSymbolValue > HUFH_SYMBOLVALUE_MAX) return ERROR(maxSymbolValue_tooLarge);

    /* convert to weight */
    wksp->bitsToWeight[0] = 0;
    for (n=1; n<huffLog+1; n++)
        wksp->bitsToWeight[n] = (BYTE)(huffLog + 1 - n);
    for (n=0; n<maxSymbolValue; n++)
        wksp->huffWeight[n] = wksp->bitsToWeight[HUFH_getNbBits(ct[n])];

    /* attempt weights compression by FSE */
    if (maxDstSize < 1) return ERROR(dstSize_tooSmall);
    {   CHECK_V_F(hSize, HUFH_compressWeights(op+1, maxDstSize-1, wksp->huffWeight, maxSymbolValue, &wksp->wksp, sizeof(wksp->wksp)) );
        if ((hSize>1) & (hSize < maxSymbolValue/2)) {   /* FSE compressed */
            op[0] = (BYTE)hSize;
            return hSize+1;
    }   }

    /* write raw values as 4-bits (max : 15) */
    if (maxSymbolValue > (256-128)) return ERROR(GENERIC);   /* should not happen : likely means source cannot be compressed */
    if (((maxSymbolValue+1)/2) + 1 > maxDstSize) return ERROR(dstSize_tooSmall);   /* not enough space within dst buffer */
    op[0] = (BYTE)(128 /*special case*/ + (maxSymbolValue-1));
    wksp->huffWeight[maxSymbolValue] = 0;   /* to be sure it doesn't cause msan issue in final combination */
    for (n=0; n<maxSymbolValue; n+=2)
        op[(n/2)+1] = (BYTE)((wksp->huffWeight[n] << 4) + wksp->huffWeight[n+1]);
    return ((maxSymbolValue+1)/2) + 1;
}


size_t HUFH_readCTable (HUFH_CElt* CTable, unsigned* maxSymbolValuePtr, const void* src, size_t srcSize, unsigned* hasZeroWeights)
{
    BYTE huffWeight[HUFH_SYMBOLVALUE_MAX + 1];   /* init not required, even though some static analyzer may complain */
    U32 rankVal[HUFH_TABLELOG_ABSOLUTEMAX + 1];   /* large enough for values from 0 to 16 */
    U32 tableLog = 0;
    U32 nbSymbols = 0;
    HUFH_CElt* const ct = CTable + 1;

    /* get symbol weights */
    CHECK_V_F(readSize, HUFH_readStats(huffWeight, HUFH_SYMBOLVALUE_MAX+1, rankVal, &nbSymbols, &tableLog, src, srcSize));
    *hasZeroWeights = (rankVal[0] > 0);

    /* check result */
    if (tableLog > HUFH_TABLELOG_MAX) return ERROR(tableLog_tooLarge);
    if (nbSymbols > *maxSymbolValuePtr+1) return ERROR(maxSymbolValue_tooSmall);

    *maxSymbolValuePtr = nbSymbols - 1;

    HUFH_writeCTableHeader(CTable, tableLog, *maxSymbolValuePtr);

    /* Prepare base value per rank */
    {   U32 n, nextRankStart = 0;
        for (n=1; n<=tableLog; n++) {
            U32 curr = nextRankStart;
            nextRankStart += (rankVal[n] << (n-1));
            rankVal[n] = curr;
    }   }

    /* fill nbBits */
    {   U32 n; for (n=0; n<nbSymbols; n++) {
            const U32 w = huffWeight[n];
            HUFH_setNbBits(ct + n, (BYTE)(tableLog + 1 - w) & -(w != 0));
    }   }

    /* fill val */
    {   U16 nbPerRank[HUFH_TABLELOG_MAX+2]  = {0};  /* support w=0=>n=tableLog+1 */
        U16 valPerRank[HUFH_TABLELOG_MAX+2] = {0};
        { U32 n; for (n=0; n<nbSymbols; n++) nbPerRank[HUFH_getNbBits(ct[n])]++; }
        /* determine stating value per rank */
        valPerRank[tableLog+1] = 0;   /* for w==0 */
        {   U16 min = 0;
            U32 n; for (n=tableLog; n>0; n--) {  /* start at n=tablelog <-> w=1 */
                valPerRank[n] = min;     /* get starting value within each rank */
                min += nbPerRank[n];
                min >>= 1;
        }   }
        /* assign value within rank, symbol order */
        { U32 n; for (n=0; n<nbSymbols; n++) HUFH_setValue(ct + n, valPerRank[HUFH_getNbBits(ct[n])]++); }
    }

    return readSize;
}

U32 HUFH_getNbBitsFromCTable(HUFH_CElt const* CTable, U32 symbolValue)
{
    const HUFH_CElt* const ct = CTable + 1;
    assert(symbolValue <= HUFH_SYMBOLVALUE_MAX);
    if (symbolValue > HUFH_readCTableHeader(CTable).maxSymbolValue)
        return 0;
    return (U32)HUFH_getNbBits(ct[symbolValue]);
}


/*
 * HUFH_setMaxHeight():
 * Try to enforce @targetNbBits on the Huffman tree described in @huffNode.
 *
 * It attempts to convert all nodes with nbBits > @targetNbBits
 * to employ @targetNbBits instead. Then it adjusts the tree
 * so that it remains a valid canonical Huffman tree.
 *
 * @pre               The sum of the ranks of each symbol == 2^largestBits,
 *                    where largestBits == huffNode[lastNonNull].nbBits.
 * @post              The sum of the ranks of each symbol == 2^largestBits,
 *                    where largestBits is the return value (expected <= targetNbBits).
 *
 * @param huffNode    The Huffman tree modified in place to enforce targetNbBits.
 *                    It's presumed sorted, from most frequent to rarest symbol.
 * @param lastNonNull The symbol with the lowest count in the Huffman tree.
 * @param targetNbBits  The allowed number of bits, which the Huffman tree
 *                    may not respect. After this function the Huffman tree will
 *                    respect targetNbBits.
 * @return            The maximum number of bits of the Huffman tree after adjustment.
 */
static U32 HUFH_setMaxHeight(nodeElt* huffNode, U32 lastNonNull, U32 targetNbBits)
{
    const U32 largestBits = huffNode[lastNonNull].nbBits;
    /* early exit : no elt > targetNbBits, so the tree is already valid. */
    if (largestBits <= targetNbBits) return largestBits;

    DEBUGLOG(5, "HUFH_setMaxHeight (targetNbBits = %u)", targetNbBits);

    /* there are several too large elements (at least >= 2) */
    {   int totalCost = 0;
        const U32 baseCost = 1 << (largestBits - targetNbBits);
        int n = (int)lastNonNull;

        /* Adjust any ranks > targetNbBits to targetNbBits.
         * Compute totalCost, which is how far the sum of the ranks is
         * we are over 2^largestBits after adjust the offending ranks.
         */
        while (huffNode[n].nbBits > targetNbBits) {
            totalCost += baseCost - (1 << (largestBits - huffNode[n].nbBits));
            huffNode[n].nbBits = (BYTE)targetNbBits;
            n--;
        }
        /* n stops at huffNode[n].nbBits <= targetNbBits */
        assert(huffNode[n].nbBits <= targetNbBits);
        /* n end at index of smallest symbol using < targetNbBits */
        while (huffNode[n].nbBits == targetNbBits) --n;

        /* renorm totalCost from 2^largestBits to 2^targetNbBits
         * note : totalCost is necessarily a multiple of baseCost */
        assert(((U32)totalCost & (baseCost - 1)) == 0);
        totalCost >>= (largestBits - targetNbBits);
        assert(totalCost > 0);

        /* repay normalized cost */
        {   U32 const noSymbol = 0xF0F0F0F0;
            U32 rankLast[HUFH_TABLELOG_MAX+2];

            /* Get pos of last (smallest = lowest cum. count) symbol per rank */
            ZSTDH_memset(rankLast, 0xF0, sizeof(rankLast));
            {   U32 currentNbBits = targetNbBits;
                int pos;
                for (pos=n ; pos >= 0; pos--) {
                    if (huffNode[pos].nbBits >= currentNbBits) continue;
                    currentNbBits = huffNode[pos].nbBits;   /* < targetNbBits */
                    rankLast[targetNbBits-currentNbBits] = (U32)pos;
            }   }

            while (totalCost > 0) {
                /* Try to reduce the next power of 2 above totalCost because we
                 * gain back half the rank.
                 */
                U32 nBitsToDecrease = ZSTDH_highbit32((U32)totalCost) + 1;
                for ( ; nBitsToDecrease > 1; nBitsToDecrease--) {
                    U32 const highPos = rankLast[nBitsToDecrease];
                    U32 const lowPos = rankLast[nBitsToDecrease-1];
                    if (highPos == noSymbol) continue;
                    /* Decrease highPos if no symbols of lowPos or if it is
                     * not cheaper to remove 2 lowPos than highPos.
                     */
                    if (lowPos == noSymbol) break;
                    {   U32 const highTotal = huffNode[highPos].count;
                        U32 const lowTotal = 2 * huffNode[lowPos].count;
                        if (highTotal <= lowTotal) break;
                }   }
                /* only triggered when no more rank 1 symbol left => find closest one (note : there is necessarily at least one !) */
                assert(rankLast[nBitsToDecrease] != noSymbol || nBitsToDecrease == 1);
                /* HUFH_MAX_TABLELOG test just to please gcc 5+; but it should not be necessary */
                while ((nBitsToDecrease<=HUFH_TABLELOG_MAX) && (rankLast[nBitsToDecrease] == noSymbol))
                    nBitsToDecrease++;
                assert(rankLast[nBitsToDecrease] != noSymbol);
                /* Increase the number of bits to gain back half the rank cost. */
                totalCost -= 1 << (nBitsToDecrease-1);
                huffNode[rankLast[nBitsToDecrease]].nbBits++;

                /* Fix up the new rank.
                 * If the new rank was empty, this symbol is now its smallest.
                 * Otherwise, this symbol will be the largest in the new rank so no adjustment.
                 */
                if (rankLast[nBitsToDecrease-1] == noSymbol)
                    rankLast[nBitsToDecrease-1] = rankLast[nBitsToDecrease];
                /* Fix up the old rank.
                 * If the symbol was at position 0, meaning it was the highest weight symbol in the tree,
                 * it must be the only symbol in its rank, so the old rank now has no symbols.
                 * Otherwise, since the Huffman nodes are sorted by count, the previous position is now
                 * the smallest node in the rank. If the previous position belongs to a different rank,
                 * then the rank is now empty.
                 */
                if (rankLast[nBitsToDecrease] == 0)    /* special case, reached largest symbol */
                    rankLast[nBitsToDecrease] = noSymbol;
                else {
                    rankLast[nBitsToDecrease]--;
                    if (huffNode[rankLast[nBitsToDecrease]].nbBits != targetNbBits-nBitsToDecrease)
                        rankLast[nBitsToDecrease] = noSymbol;   /* this rank is now empty */
                }
            }   /* while (totalCost > 0) */

            /* If we've removed too much weight, then we have to add it back.
             * To avoid overshooting again, we only adjust the smallest rank.
             * We take the largest nodes from the lowest rank 0 and move them
             * to rank 1. There's guaranteed to be enough rank 0 symbols because
             * TODO.
             */
            while (totalCost < 0) {  /* Sometimes, cost correction overshoot */
                /* special case : no rank 1 symbol (using targetNbBits-1);
                 * let's create one from largest rank 0 (using targetNbBits).
                 */
                if (rankLast[1] == noSymbol) {
                    while (huffNode[n].nbBits == targetNbBits) n--;
                    huffNode[n+1].nbBits--;
                    assert(n >= 0);
                    rankLast[1] = (U32)(n+1);
                    totalCost++;
                    continue;
                }
                huffNode[ rankLast[1] + 1 ].nbBits--;
                rankLast[1]++;
                totalCost ++;
            }
        }   /* repay normalized cost */
    }   /* there are several too large elements (at least >= 2) */

    return targetNbBits;
}

typedef struct {
    U16 base;
    U16 curr;
} rankPos;

typedef nodeElt huffNodeTable[2 * (HUFH_SYMBOLVALUE_MAX + 1)];

/* Number of buckets available for HUFH_sort() */
#define RANK_POSITION_TABLE_SIZE 192

typedef struct {
  huffNodeTable huffNodeTbl;
  rankPos rankPosition[RANK_POSITION_TABLE_SIZE];
} HUFH_buildCTable_wksp_tables;

/* RANK_POSITION_DISTINCT_COUNT_CUTOFF == Cutoff point in HUFH_sort() buckets for which we use log2 bucketing.
 * Strategy is to use as many buckets as possible for representing distinct
 * counts while using the remainder to represent all "large" counts.
 *
 * To satisfy this requirement for 192 buckets, we can do the following:
 * Let buckets 0-166 represent distinct counts of [0, 166]
 * Let buckets 166 to 192 represent all remaining counts up to RANK_POSITION_MAX_COUNT_LOG using log2 bucketing.
 */
#define RANK_POSITION_MAX_COUNT_LOG 32
#define RANK_POSITION_LOG_BUCKETS_BEGIN ((RANK_POSITION_TABLE_SIZE - 1) - RANK_POSITION_MAX_COUNT_LOG - 1 /* == 158 */)
#define RANK_POSITION_DISTINCT_COUNT_CUTOFF (RANK_POSITION_LOG_BUCKETS_BEGIN + ZSTDH_highbit32(RANK_POSITION_LOG_BUCKETS_BEGIN) /* == 166 */)

/* Return the appropriate bucket index for a given count. See definition of
 * RANK_POSITION_DISTINCT_COUNT_CUTOFF for explanation of bucketing strategy.
 */
static U32 HUFH_getIndex(U32 const count) {
    return (count < RANK_POSITION_DISTINCT_COUNT_CUTOFF)
        ? count
        : ZSTDH_highbit32(count) + RANK_POSITION_LOG_BUCKETS_BEGIN;
}

/* Helper swap function for HUFH_quickSortPartition() */
static void HUFH_swapNodes(nodeElt* a, nodeElt* b) {
	nodeElt tmp = *a;
	*a = *b;
	*b = tmp;
}

/* Returns 0 if the huffNode array is not sorted by descending count */
MEM_STATIC int HUFH_isSorted(nodeElt huffNode[], U32 const maxSymbolValue1) {
    U32 i;
    for (i = 1; i < maxSymbolValue1; ++i) {
        if (huffNode[i].count > huffNode[i-1].count) {
            return 0;
        }
    }
    return 1;
}

/* Insertion sort by descending order */
HINT_INLINE void HUFH_insertionSort(nodeElt huffNode[], int const low, int const high) {
    int i;
    int const size = high-low+1;
    huffNode += low;
    for (i = 1; i < size; ++i) {
        nodeElt const key = huffNode[i];
        int j = i - 1;
        while (j >= 0 && huffNode[j].count < key.count) {
            huffNode[j + 1] = huffNode[j];
            j--;
        }
        huffNode[j + 1] = key;
    }
}

/* Pivot helper function for quicksort. */
static int HUFH_quickSortPartition(nodeElt arr[], int const low, int const high) {
    /* Simply select rightmost element as pivot. "Better" selectors like
     * median-of-three don't experimentally appear to have any benefit.
     */
    U32 const pivot = arr[high].count;
    int i = low - 1;
    int j = low;
    for ( ; j < high; j++) {
        if (arr[j].count > pivot) {
            i++;
            HUFH_swapNodes(&arr[i], &arr[j]);
        }
    }
    HUFH_swapNodes(&arr[i + 1], &arr[high]);
    return i + 1;
}

/* Classic quicksort by descending with partially iterative calls
 * to reduce worst case callstack size.
 */
static void HUFH_simpleQuickSort(nodeElt arr[], int low, int high) {
    int const kInsertionSortThreshold = 8;
    if (high - low < kInsertionSortThreshold) {
        HUFH_insertionSort(arr, low, high);
        return;
    }
    while (low < high) {
        int const idx = HUFH_quickSortPartition(arr, low, high);
        if (idx - low < high - idx) {
            HUFH_simpleQuickSort(arr, low, idx - 1);
            low = idx + 1;
        } else {
            HUFH_simpleQuickSort(arr, idx + 1, high);
            high = idx - 1;
        }
    }
}

/*
 * HUFH_sort():
 * Sorts the symbols [0, maxSymbolValue] by count[symbol] in decreasing order.
 * This is a typical bucket sorting strategy that uses either quicksort or insertion sort to sort each bucket.
 *
 * @param[out] huffNode       Sorted symbols by decreasing count. Only members `.count` and `.byte` are filled.
 *                            Must have (maxSymbolValue + 1) entries.
 * @param[in]  count          Histogram of the symbols.
 * @param[in]  maxSymbolValue Maximum symbol value.
 * @param      rankPosition   This is a scratch workspace. Must have RANK_POSITION_TABLE_SIZE entries.
 */
static void HUFH_sort(nodeElt huffNode[], const unsigned count[], U32 const maxSymbolValue, rankPos rankPosition[]) {
    U32 n;
    U32 const maxSymbolValue1 = maxSymbolValue+1;

    /* Compute base and set curr to base.
     * For symbol s let lowerRank = HUFH_getIndex(count[n]) and rank = lowerRank + 1.
     * See HUFH_getIndex to see bucketing strategy.
     * We attribute each symbol to lowerRank's base value, because we want to know where
     * each rank begins in the output, so for rank R we want to count ranks R+1 and above.
     */
    ZSTDH_memset(rankPosition, 0, sizeof(*rankPosition) * RANK_POSITION_TABLE_SIZE);
    for (n = 0; n < maxSymbolValue1; ++n) {
        U32 lowerRank = HUFH_getIndex(count[n]);
        assert(lowerRank < RANK_POSITION_TABLE_SIZE - 1);
        rankPosition[lowerRank].base++;
    }

    assert(rankPosition[RANK_POSITION_TABLE_SIZE - 1].base == 0);
    /* Set up the rankPosition table */
    for (n = RANK_POSITION_TABLE_SIZE - 1; n > 0; --n) {
        rankPosition[n-1].base += rankPosition[n].base;
        rankPosition[n-1].curr = rankPosition[n-1].base;
    }

    /* Insert each symbol into their appropriate bucket, setting up rankPosition table. */
    for (n = 0; n < maxSymbolValue1; ++n) {
        U32 const c = count[n];
        U32 const r = HUFH_getIndex(c) + 1;
        U32 const pos = rankPosition[r].curr++;
        assert(pos < maxSymbolValue1);
        huffNode[pos].count = c;
        huffNode[pos].byte  = (BYTE)n;
    }

    /* Sort each bucket. */
    for (n = RANK_POSITION_DISTINCT_COUNT_CUTOFF; n < RANK_POSITION_TABLE_SIZE - 1; ++n) {
        int const bucketSize = rankPosition[n].curr - rankPosition[n].base;
        U32 const bucketStartIdx = rankPosition[n].base;
        if (bucketSize > 1) {
            assert(bucketStartIdx < maxSymbolValue1);
            HUFH_simpleQuickSort(huffNode + bucketStartIdx, 0, bucketSize-1);
        }
    }

    assert(HUFH_isSorted(huffNode, maxSymbolValue1));
}


/* HUFH_buildCTable_wksp() :
 *  Same as HUFH_buildCTable(), but using externally allocated scratch buffer.
 *  `workSpace` must be aligned on 4-bytes boundaries, and be at least as large as sizeof(HUFH_buildCTable_wksp_tables).
 */
#define STARTNODE (HUFH_SYMBOLVALUE_MAX+1)

/* HUFH_buildTree():
 * Takes the huffNode array sorted by HUFH_sort() and builds an unlimited-depth Huffman tree.
 *
 * @param huffNode        The array sorted by HUFH_sort(). Builds the Huffman tree in this array.
 * @param maxSymbolValue  The maximum symbol value.
 * @return                The smallest node in the Huffman tree (by count).
 */
static int HUFH_buildTree(nodeElt* huffNode, U32 maxSymbolValue)
{
    nodeElt* const huffNode0 = huffNode - 1;
    int nonNullRank;
    int lowS, lowN;
    int nodeNb = STARTNODE;
    int n, nodeRoot;
    DEBUGLOG(5, "HUFH_buildTree (alphabet size = %u)", maxSymbolValue + 1);
    /* init for parents */
    nonNullRank = (int)maxSymbolValue;
    while(huffNode[nonNullRank].count == 0) nonNullRank--;
    lowS = nonNullRank; nodeRoot = nodeNb + lowS - 1; lowN = nodeNb;
    huffNode[nodeNb].count = huffNode[lowS].count + huffNode[lowS-1].count;
    huffNode[lowS].parent = huffNode[lowS-1].parent = (U16)nodeNb;
    nodeNb++; lowS-=2;
    for (n=nodeNb; n<=nodeRoot; n++) huffNode[n].count = (U32)(1U<<30);
    huffNode0[0].count = (U32)(1U<<31);  /* fake entry, strong barrier */

    /* create parents */
    while (nodeNb <= nodeRoot) {
        int const n1 = (huffNode[lowS].count < huffNode[lowN].count) ? lowS-- : lowN++;
        int const n2 = (huffNode[lowS].count < huffNode[lowN].count) ? lowS-- : lowN++;
        huffNode[nodeNb].count = huffNode[n1].count + huffNode[n2].count;
        huffNode[n1].parent = huffNode[n2].parent = (U16)nodeNb;
        nodeNb++;
    }

    /* distribute weights (unlimited tree height) */
    huffNode[nodeRoot].nbBits = 0;
    for (n=nodeRoot-1; n>=STARTNODE; n--)
        huffNode[n].nbBits = huffNode[ huffNode[n].parent ].nbBits + 1;
    for (n=0; n<=nonNullRank; n++)
        huffNode[n].nbBits = huffNode[ huffNode[n].parent ].nbBits + 1;

    DEBUGLOG(6, "Initial distribution of bits completed (%zu sorted symbols)", showHNodeBits(huffNode, maxSymbolValue+1));

    return nonNullRank;
}

/*
 * HUFH_buildCTableFromTree():
 * Build the CTable given the Huffman tree in huffNode.
 *
 * @param[out] CTable         The output Huffman CTable.
 * @param      huffNode       The Huffman tree.
 * @param      nonNullRank    The last and smallest node in the Huffman tree.
 * @param      maxSymbolValue The maximum symbol value.
 * @param      maxNbBits      The exact maximum number of bits used in the Huffman tree.
 */
static void HUFH_buildCTableFromTree(HUFH_CElt* CTable, nodeElt const* huffNode, int nonNullRank, U32 maxSymbolValue, U32 maxNbBits)
{
    HUFH_CElt* const ct = CTable + 1;
    /* fill result into ctable (val, nbBits) */
    int n;
    U16 nbPerRank[HUFH_TABLELOG_MAX+1] = {0};
    U16 valPerRank[HUFH_TABLELOG_MAX+1] = {0};
    int const alphabetSize = (int)(maxSymbolValue + 1);
    for (n=0; n<=nonNullRank; n++)
        nbPerRank[huffNode[n].nbBits]++;
    /* determine starting value per rank */
    {   U16 min = 0;
        for (n=(int)maxNbBits; n>0; n--) {
            valPerRank[n] = min;      /* get starting value within each rank */
            min += nbPerRank[n];
            min >>= 1;
    }   }
    for (n=0; n<alphabetSize; n++)
        HUFH_setNbBits(ct + huffNode[n].byte, huffNode[n].nbBits);   /* push nbBits per symbol, symbol order */
    for (n=0; n<alphabetSize; n++)
        HUFH_setValue(ct + n, valPerRank[HUFH_getNbBits(ct[n])]++);   /* assign value within rank, symbol order */

    HUFH_writeCTableHeader(CTable, maxNbBits, maxSymbolValue);
}

size_t
HUFH_buildCTable_wksp(HUFH_CElt* CTable, const unsigned* count, U32 maxSymbolValue, U32 maxNbBits,
                     void* workSpace, size_t wkspSize)
{
    HUFH_buildCTable_wksp_tables* const wksp_tables =
        (HUFH_buildCTable_wksp_tables*)HUFH_alignUpWorkspace(workSpace, &wkspSize, ZSTDH_ALIGNOF(U32));
    nodeElt* const huffNode0 = wksp_tables->huffNodeTbl;
    nodeElt* const huffNode = huffNode0+1;
    int nonNullRank;

    HUFH_STATIC_ASSERT(HUFH_CTABLE_WORKSPACE_SIZE == sizeof(HUFH_buildCTable_wksp_tables));

    DEBUGLOG(5, "HUFH_buildCTable_wksp (alphabet size = %u)", maxSymbolValue+1);

    /* safety checks */
    if (wkspSize < sizeof(HUFH_buildCTable_wksp_tables))
        return ERROR(workSpace_tooSmall);
    if (maxNbBits == 0) maxNbBits = HUFH_TABLELOG_DEFAULT;
    if (maxSymbolValue > HUFH_SYMBOLVALUE_MAX)
        return ERROR(maxSymbolValue_tooLarge);
    ZSTDH_memset(huffNode0, 0, sizeof(huffNodeTable));

    /* sort, decreasing order */
    HUFH_sort(huffNode, count, maxSymbolValue, wksp_tables->rankPosition);
    DEBUGLOG(6, "sorted symbols completed (%zu symbols)", showHNodeSymbols(huffNode, maxSymbolValue+1));

    /* build tree */
    nonNullRank = HUFH_buildTree(huffNode, maxSymbolValue);

    /* determine and enforce maxTableLog */
    maxNbBits = HUFH_setMaxHeight(huffNode, (U32)nonNullRank, maxNbBits);
    if (maxNbBits > HUFH_TABLELOG_MAX) return ERROR(GENERIC);   /* check fit into table */

    HUFH_buildCTableFromTree(CTable, huffNode, nonNullRank, maxSymbolValue, maxNbBits);

    return maxNbBits;
}

size_t HUFH_estimateCompressedSize(const HUFH_CElt* CTable, const unsigned* count, unsigned maxSymbolValue)
{
    HUFH_CElt const* ct = CTable + 1;
    size_t nbBits = 0;
    int s;
    for (s = 0; s <= (int)maxSymbolValue; ++s) {
        nbBits += HUFH_getNbBits(ct[s]) * count[s];
    }
    return nbBits >> 3;
}

int HUFH_validateCTable(const HUFH_CElt* CTable, const unsigned* count, unsigned maxSymbolValue) {
    HUFH_CTableHeader header = HUFH_readCTableHeader(CTable);
    HUFH_CElt const* ct = CTable + 1;
    int bad = 0;
    int s;

    assert(header.tableLog <= HUFH_TABLELOG_ABSOLUTEMAX);

    if (header.maxSymbolValue < maxSymbolValue)
        return 0;

    for (s = 0; s <= (int)maxSymbolValue; ++s) {
        bad |= (count[s] != 0) & (HUFH_getNbBits(ct[s]) == 0);
    }
    return !bad;
}

size_t HUFH_compressBound(size_t size) { return HUFH_COMPRESSBOUND(size); }

/* HUFH_CStream_t:
 * Huffman uses its own BIT_CStream_t implementation.
 * There are three major differences from BIT_CStream_t:
 *   1. HUFH_addBits() takes a HUFH_CElt (size_t) which is
 *      the pair (nbBits, value) in the format:
 *      format:
 *        - Bits [0, 4)            = nbBits
 *        - Bits [4, 64 - nbBits)  = 0
 *        - Bits [64 - nbBits, 64) = value
 *   2. The bitContainer is built from the upper bits and
 *      right shifted. E.g. to add a new value of N bits
 *      you right shift the bitContainer by N, then or in
 *      the new value into the N upper bits.
 *   3. The bitstream has two bit containers. You can add
 *      bits to the second container and merge them into
 *      the first container.
 */

#define HUFH_BITS_IN_CONTAINER (sizeof(size_t) * 8)

typedef struct {
    size_t bitContainer[2];
    size_t bitPos[2];

    BYTE* startPtr;
    BYTE* ptr;
    BYTE* endPtr;
} HUFH_CStream_t;

/*! HUFH_initCStream():
 * Initializes the bitstream.
 * @returns 0 or an error code.
 */
static size_t HUFH_initCStream(HUFH_CStream_t* bitC,
                                  void* startPtr, size_t dstCapacity)
{
    ZSTDH_memset(bitC, 0, sizeof(*bitC));
    bitC->startPtr = (BYTE*)startPtr;
    bitC->ptr = bitC->startPtr;
    bitC->endPtr = bitC->startPtr + dstCapacity - sizeof(bitC->bitContainer[0]);
    if (dstCapacity <= sizeof(bitC->bitContainer[0])) return ERROR(dstSize_tooSmall);
    return 0;
}

/*! HUFH_addBits():
 * Adds the symbol stored in HUFH_CElt elt to the bitstream.
 *
 * @param elt   The element we're adding. This is a (nbBits, value) pair.
 *              See the HUFH_CStream_t docs for the format.
 * @param idx   Insert into the bitstream at this idx.
 * @param kFast This is a template parameter. If the bitstream is guaranteed
 *              to have at least 4 unused bits after this call it may be 1,
 *              otherwise it must be 0. HUFH_addBits() is faster when fast is set.
 */
FORCE_INLINE_TEMPLATE void HUFH_addBits(HUFH_CStream_t* bitC, HUFH_CElt elt, int idx, int kFast)
{
    assert(idx <= 1);
    assert(HUFH_getNbBits(elt) <= HUFH_TABLELOG_ABSOLUTEMAX);
    /* This is efficient on x86-64 with BMI2 because shrx
     * only reads the low 6 bits of the register. The compiler
     * knows this and elides the mask. When fast is set,
     * every operation can use the same value loaded from elt.
     */
    bitC->bitContainer[idx] >>= HUFH_getNbBits(elt);
    bitC->bitContainer[idx] |= kFast ? HUFH_getValueFast(elt) : HUFH_getValue(elt);
    /* We only read the low 8 bits of bitC->bitPos[idx] so it
     * doesn't matter that the high bits have noise from the value.
     */
    bitC->bitPos[idx] += HUFH_getNbBitsFast(elt);
    assert((bitC->bitPos[idx] & 0xFF) <= HUFH_BITS_IN_CONTAINER);
    /* The last 4-bits of elt are dirty if fast is set,
     * so we must not be overwriting bits that have already been
     * inserted into the bit container.
     */
#if DEBUGLEVEL >= 1
    {
        size_t const nbBits = HUFH_getNbBits(elt);
        size_t const dirtyBits = nbBits == 0 ? 0 : ZSTDH_highbit32((U32)nbBits) + 1;
        (void)dirtyBits;
        /* Middle bits are 0. */
        assert(((elt >> dirtyBits) << (dirtyBits + nbBits)) == 0);
        /* We didn't overwrite any bits in the bit container. */
        assert(!kFast || (bitC->bitPos[idx] & 0xFF) <= HUFH_BITS_IN_CONTAINER);
        (void)dirtyBits;
    }
#endif
}

FORCE_INLINE_TEMPLATE void HUFH_zeroIndex1(HUFH_CStream_t* bitC)
{
    bitC->bitContainer[1] = 0;
    bitC->bitPos[1] = 0;
}

/*! HUFH_mergeIndex1() :
 * Merges the bit container @ index 1 into the bit container @ index 0
 * and zeros the bit container @ index 1.
 */
FORCE_INLINE_TEMPLATE void HUFH_mergeIndex1(HUFH_CStream_t* bitC)
{
    assert((bitC->bitPos[1] & 0xFF) < HUFH_BITS_IN_CONTAINER);
    bitC->bitContainer[0] >>= (bitC->bitPos[1] & 0xFF);
    bitC->bitContainer[0] |= bitC->bitContainer[1];
    bitC->bitPos[0] += bitC->bitPos[1];
    assert((bitC->bitPos[0] & 0xFF) <= HUFH_BITS_IN_CONTAINER);
}

/*! HUFH_flushBits() :
* Flushes the bits in the bit container @ index 0.
*
* @post bitPos will be < 8.
* @param kFast If kFast is set then we must know a-priori that
*              the bit container will not overflow.
*/
FORCE_INLINE_TEMPLATE void HUFH_flushBits(HUFH_CStream_t* bitC, int kFast)
{
    /* The upper bits of bitPos are noisy, so we must mask by 0xFF. */
    size_t const nbBits = bitC->bitPos[0] & 0xFF;
    size_t const nbBytes = nbBits >> 3;
    /* The top nbBits bits of bitContainer are the ones we need. */
    size_t const bitContainer = bitC->bitContainer[0] >> (HUFH_BITS_IN_CONTAINER - nbBits);
    /* Mask bitPos to account for the bytes we consumed. */
    bitC->bitPos[0] &= 7;
    assert(nbBits > 0);
    assert(nbBits <= sizeof(bitC->bitContainer[0]) * 8);
    assert(bitC->ptr <= bitC->endPtr);
    MEM_writeLEST(bitC->ptr, bitContainer);
    bitC->ptr += nbBytes;
    assert(!kFast || bitC->ptr <= bitC->endPtr);
    if (!kFast && bitC->ptr > bitC->endPtr) bitC->ptr = bitC->endPtr;
    /* bitContainer doesn't need to be modified because the leftover
     * bits are already the top bitPos bits. And we don't care about
     * noise in the lower values.
     */
}

/*! HUFH_endMark()
 * @returns The Huffman stream end mark: A 1-bit value = 1.
 */
static HUFH_CElt HUFH_endMark(void)
{
    HUFH_CElt endMark;
    HUFH_setNbBits(&endMark, 1);
    HUFH_setValue(&endMark, 1);
    return endMark;
}

/*! HUFH_closeCStream() :
 *  @return Size of CStream, in bytes,
 *          or 0 if it could not fit into dstBuffer */
static size_t HUFH_closeCStream(HUFH_CStream_t* bitC)
{
    HUFH_addBits(bitC, HUFH_endMark(), /* idx */ 0, /* kFast */ 0);
    HUFH_flushBits(bitC, /* kFast */ 0);
    {
        size_t const nbBits = bitC->bitPos[0] & 0xFF;
        if (bitC->ptr >= bitC->endPtr) return 0; /* overflow detected */
        return (size_t)(bitC->ptr - bitC->startPtr) + (nbBits > 0);
    }
}

FORCE_INLINE_TEMPLATE void
HUFH_encodeSymbol(HUFH_CStream_t* bitCPtr, U32 symbol, const HUFH_CElt* CTable, int idx, int fast)
{
    HUFH_addBits(bitCPtr, CTable[symbol], idx, fast);
}

FORCE_INLINE_TEMPLATE void
HUFH_compress1X_usingCTable_internal_body_loop(HUFH_CStream_t* bitC,
                                   const BYTE* ip, size_t srcSize,
                                   const HUFH_CElt* ct,
                                   int kUnroll, int kFastFlush, int kLastFast)
{
    /* Join to kUnroll */
    int n = (int)srcSize;
    int rem = n % kUnroll;
    if (rem > 0) {
        for (; rem > 0; --rem) {
            HUFH_encodeSymbol(bitC, ip[--n], ct, 0, /* fast */ 0);
        }
        HUFH_flushBits(bitC, kFastFlush);
    }
    assert(n % kUnroll == 0);

    /* Join to 2 * kUnroll */
    if (n % (2 * kUnroll)) {
        int u;
        for (u = 1; u < kUnroll; ++u) {
            HUFH_encodeSymbol(bitC, ip[n - u], ct, 0, 1);
        }
        HUFH_encodeSymbol(bitC, ip[n - kUnroll], ct, 0, kLastFast);
        HUFH_flushBits(bitC, kFastFlush);
        n -= kUnroll;
    }
    assert(n % (2 * kUnroll) == 0);

    for (; n>0; n-= 2 * kUnroll) {
        /* Encode kUnroll symbols into the bitstream @ index 0. */
        int u;
        for (u = 1; u < kUnroll; ++u) {
            HUFH_encodeSymbol(bitC, ip[n - u], ct, /* idx */ 0, /* fast */ 1);
        }
        HUFH_encodeSymbol(bitC, ip[n - kUnroll], ct, /* idx */ 0, /* fast */ kLastFast);
        HUFH_flushBits(bitC, kFastFlush);
        /* Encode kUnroll symbols into the bitstream @ index 1.
         * This allows us to start filling the bit container
         * without any data dependencies.
         */
        HUFH_zeroIndex1(bitC);
        for (u = 1; u < kUnroll; ++u) {
            HUFH_encodeSymbol(bitC, ip[n - kUnroll - u], ct, /* idx */ 1, /* fast */ 1);
        }
        HUFH_encodeSymbol(bitC, ip[n - kUnroll - kUnroll], ct, /* idx */ 1, /* fast */ kLastFast);
        /* Merge bitstream @ index 1 into the bitstream @ index 0 */
        HUFH_mergeIndex1(bitC);
        HUFH_flushBits(bitC, kFastFlush);
    }
    assert(n == 0);

}

/*
 * Returns a tight upper bound on the output space needed by Huffman
 * with 8 bytes buffer to handle over-writes. If the output is at least
 * this large we don't need to do bounds checks during Huffman encoding.
 */
static size_t HUFH_tightCompressBound(size_t srcSize, size_t tableLog)
{
    return ((srcSize * tableLog) >> 3) + 8;
}


FORCE_INLINE_TEMPLATE size_t
HUFH_compress1X_usingCTable_internal_body(void* dst, size_t dstSize,
                                   const void* src, size_t srcSize,
                                   const HUFH_CElt* CTable)
{
    U32 const tableLog = HUFH_readCTableHeader(CTable).tableLog;
    HUFH_CElt const* ct = CTable + 1;
    const BYTE* ip = (const BYTE*) src;
    BYTE* const ostart = (BYTE*)dst;
    BYTE* const oend = ostart + dstSize;
    HUFH_CStream_t bitC;

    /* init */
    if (dstSize < 8) return 0;   /* not enough space to compress */
    { BYTE* op = ostart;
      size_t const initErr = HUFH_initCStream(&bitC, op, (size_t)(oend-op));
      if (HUFH_isError(initErr)) return 0; }

    if (dstSize < HUFH_tightCompressBound(srcSize, (size_t)tableLog) || tableLog > 11)
        HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ MEM_32bits() ? 2 : 4, /* kFast */ 0, /* kLastFast */ 0);
    else {
        if (MEM_32bits()) {
            switch (tableLog) {
            case 11:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 2, /* kFastFlush */ 1, /* kLastFast */ 0);
                break;
            case 10: ZSTDH_FALLTHROUGH;
            case 9: ZSTDH_FALLTHROUGH;
            case 8:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 2, /* kFastFlush */ 1, /* kLastFast */ 1);
                break;
            case 7: ZSTDH_FALLTHROUGH;
            default:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 3, /* kFastFlush */ 1, /* kLastFast */ 1);
                break;
            }
        } else {
            switch (tableLog) {
            case 11:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 5, /* kFastFlush */ 1, /* kLastFast */ 0);
                break;
            case 10:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 5, /* kFastFlush */ 1, /* kLastFast */ 1);
                break;
            case 9:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 6, /* kFastFlush */ 1, /* kLastFast */ 0);
                break;
            case 8:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 7, /* kFastFlush */ 1, /* kLastFast */ 0);
                break;
            case 7:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 8, /* kFastFlush */ 1, /* kLastFast */ 0);
                break;
            case 6: ZSTDH_FALLTHROUGH;
            default:
                HUFH_compress1X_usingCTable_internal_body_loop(&bitC, ip, srcSize, ct, /* kUnroll */ 9, /* kFastFlush */ 1, /* kLastFast */ 1);
                break;
            }
        }
    }
    assert(bitC.ptr <= bitC.endPtr);

    return HUFH_closeCStream(&bitC);
}

#if DYNAMIC_BMI2

static BMI2_TARGET_ATTRIBUTE size_t
HUFH_compress1X_usingCTable_internal_bmi2(void* dst, size_t dstSize,
                                   const void* src, size_t srcSize,
                                   const HUFH_CElt* CTable)
{
    return HUFH_compress1X_usingCTable_internal_body(dst, dstSize, src, srcSize, CTable);
}

static size_t
HUFH_compress1X_usingCTable_internal_default(void* dst, size_t dstSize,
                                      const void* src, size_t srcSize,
                                      const HUFH_CElt* CTable)
{
    return HUFH_compress1X_usingCTable_internal_body(dst, dstSize, src, srcSize, CTable);
}

static size_t
HUFH_compress1X_usingCTable_internal(void* dst, size_t dstSize,
                              const void* src, size_t srcSize,
                              const HUFH_CElt* CTable, const int flags)
{
    if (flags & HUFH_flags_bmi2) {
        return HUFH_compress1X_usingCTable_internal_bmi2(dst, dstSize, src, srcSize, CTable);
    }
    return HUFH_compress1X_usingCTable_internal_default(dst, dstSize, src, srcSize, CTable);
}

#else

static size_t
HUFH_compress1X_usingCTable_internal(void* dst, size_t dstSize,
                              const void* src, size_t srcSize,
                              const HUFH_CElt* CTable, const int flags)
{
    (void)flags;
    return HUFH_compress1X_usingCTable_internal_body(dst, dstSize, src, srcSize, CTable);
}

#endif

size_t HUFH_compress1X_usingCTable(void* dst, size_t dstSize, const void* src, size_t srcSize, const HUFH_CElt* CTable, int flags)
{
    return HUFH_compress1X_usingCTable_internal(dst, dstSize, src, srcSize, CTable, flags);
}

static size_t
HUFH_compress4X_usingCTable_internal(void* dst, size_t dstSize,
                              const void* src, size_t srcSize,
                              const HUFH_CElt* CTable, int flags)
{
    size_t const segmentSize = (srcSize+3)/4;   /* first 3 segments */
    const BYTE* ip = (const BYTE*) src;
    const BYTE* const iend = ip + srcSize;
    BYTE* const ostart = (BYTE*) dst;
    BYTE* const oend = ostart + dstSize;
    BYTE* op = ostart;

    if (dstSize < 6 + 1 + 1 + 1 + 8) return 0;   /* minimum space to compress successfully */
    if (srcSize < 12) return 0;   /* no saving possible : too small input */
    op += 6;   /* jumpTable */

    assert(op <= oend);
    {   CHECK_V_F(cSize, HUFH_compress1X_usingCTable_internal(op, (size_t)(oend-op), ip, segmentSize, CTable, flags) );
        if (cSize == 0 || cSize > 65535) return 0;
        MEM_writeLE16(ostart, (U16)cSize);
        op += cSize;
    }

    ip += segmentSize;
    assert(op <= oend);
    {   CHECK_V_F(cSize, HUFH_compress1X_usingCTable_internal(op, (size_t)(oend-op), ip, segmentSize, CTable, flags) );
        if (cSize == 0 || cSize > 65535) return 0;
        MEM_writeLE16(ostart+2, (U16)cSize);
        op += cSize;
    }

    ip += segmentSize;
    assert(op <= oend);
    {   CHECK_V_F(cSize, HUFH_compress1X_usingCTable_internal(op, (size_t)(oend-op), ip, segmentSize, CTable, flags) );
        if (cSize == 0 || cSize > 65535) return 0;
        MEM_writeLE16(ostart+4, (U16)cSize);
        op += cSize;
    }

    ip += segmentSize;
    assert(op <= oend);
    assert(ip <= iend);
    {   CHECK_V_F(cSize, HUFH_compress1X_usingCTable_internal(op, (size_t)(oend-op), ip, (size_t)(iend-ip), CTable, flags) );
        if (cSize == 0 || cSize > 65535) return 0;
        op += cSize;
    }

    return (size_t)(op-ostart);
}

size_t HUFH_compress4X_usingCTable(void* dst, size_t dstSize, const void* src, size_t srcSize, const HUFH_CElt* CTable, int flags)
{
    return HUFH_compress4X_usingCTable_internal(dst, dstSize, src, srcSize, CTable, flags);
}

typedef enum { HUFH_singleStream, HUFH_fourStreams } HUFH_nbStreams_e;

static size_t HUFH_compressCTable_internal(
                BYTE* const ostart, BYTE* op, BYTE* const oend,
                const void* src, size_t srcSize,
                HUFH_nbStreams_e nbStreams, const HUFH_CElt* CTable, const int flags)
{
    size_t const cSize = (nbStreams==HUFH_singleStream) ?
                         HUFH_compress1X_usingCTable_internal(op, (size_t)(oend - op), src, srcSize, CTable, flags) :
                         HUFH_compress4X_usingCTable_internal(op, (size_t)(oend - op), src, srcSize, CTable, flags);
    if (HUFH_isError(cSize)) { return cSize; }
    if (cSize==0) { return 0; }   /* uncompressible */
    op += cSize;
    /* check compressibility */
    assert(op >= ostart);
    if ((size_t)(op-ostart) >= srcSize-1) { return 0; }
    return (size_t)(op-ostart);
}

typedef struct {
    unsigned count[HUFH_SYMBOLVALUE_MAX + 1];
    HUFH_CElt CTable[HUFH_CTABLE_SIZE_ST(HUFH_SYMBOLVALUE_MAX)];
    union {
        HUFH_buildCTable_wksp_tables buildCTable_wksp;
        HUFH_WriteCTableWksp writeCTable_wksp;
        U32 hist_wksp[HISTH_WKSP_SIZE_U32];
    } wksps;
} HUFH_compress_tables_t;

#define SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE 4096
#define SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO 10  /* Must be >= 2 */

unsigned HUFH_cardinality(const unsigned* count, unsigned maxSymbolValue)
{
    unsigned cardinality = 0;
    unsigned i;

    for (i = 0; i < maxSymbolValue + 1; i++) {
        if (count[i] != 0) cardinality += 1;
    }

    return cardinality;
}

unsigned HUFH_minTableLog(unsigned symbolCardinality)
{
    U32 minBitsSymbols = ZSTDH_highbit32(symbolCardinality) + 1;
    return minBitsSymbols;
}

unsigned HUFH_optimalTableLog(
            unsigned maxTableLog,
            size_t srcSize,
            unsigned maxSymbolValue,
            void* workSpace, size_t wkspSize,
            HUFH_CElt* table,
      const unsigned* count,
            int flags)
{
    assert(srcSize > 1); /* Not supported, RLE should be used instead */
    assert(wkspSize >= sizeof(HUFH_buildCTable_wksp_tables));

    if (!(flags & HUFH_flags_optimalDepth)) {
        /* cheap evaluation, based on FSE */
        return FSEH_optimalTableLog_internal(maxTableLog, srcSize, maxSymbolValue, 1);
    }

    {   BYTE* dst = (BYTE*)workSpace + sizeof(HUFH_WriteCTableWksp);
        size_t dstSize = wkspSize - sizeof(HUFH_WriteCTableWksp);
        size_t hSize, newSize;
        const unsigned symbolCardinality = HUFH_cardinality(count, maxSymbolValue);
        const unsigned minTableLog = HUFH_minTableLog(symbolCardinality);
        size_t optSize = ((size_t) ~0) - 1;
        unsigned optLog = maxTableLog, optLogGuess;

        DEBUGLOG(6, "HUFH_optimalTableLog: probing huf depth (srcSize=%zu)", srcSize);

        /* Search until size increases */
        for (optLogGuess = minTableLog; optLogGuess <= maxTableLog; optLogGuess++) {
            DEBUGLOG(7, "checking for huffLog=%u", optLogGuess);

            {   size_t maxBits = HUFH_buildCTable_wksp(table, count, maxSymbolValue, optLogGuess, workSpace, wkspSize);
                if (ERR_isError(maxBits)) continue;

                if (maxBits < optLogGuess && optLogGuess > minTableLog) break;

                hSize = HUFH_writeCTable_wksp(dst, dstSize, table, maxSymbolValue, (U32)maxBits, workSpace, wkspSize);
            }

            if (ERR_isError(hSize)) continue;

            newSize = HUFH_estimateCompressedSize(table, count, maxSymbolValue) + hSize;

            if (newSize > optSize + 1) {
                break;
            }

            if (newSize < optSize) {
                optSize = newSize;
                optLog = optLogGuess;
            }
        }
        assert(optLog <= HUFH_TABLELOG_MAX);
        return optLog;
    }
}

/* HUFH_compress_internal() :
 * `workSpace_align4` must be aligned on 4-bytes boundaries,
 * and occupies the same space as a table of HUFH_WORKSPACE_SIZE_U64 unsigned */
static size_t
HUFH_compress_internal (void* dst, size_t dstSize,
                 const void* src, size_t srcSize,
                       unsigned maxSymbolValue, unsigned huffLog,
                       HUFH_nbStreams_e nbStreams,
                       void* workSpace, size_t wkspSize,
                       HUFH_CElt* oldHufTable, HUFH_repeat* repeat, int flags)
{
    HUFH_compress_tables_t* const table = (HUFH_compress_tables_t*)HUFH_alignUpWorkspace(workSpace, &wkspSize, ZSTDH_ALIGNOF(size_t));
    BYTE* const ostart = (BYTE*)dst;
    BYTE* const oend = ostart + dstSize;
    BYTE* op = ostart;

    DEBUGLOG(5, "HUFH_compress_internal (srcSize=%zu)", srcSize);
    HUFH_STATIC_ASSERT(sizeof(*table) + HUFH_WORKSPACE_MAX_ALIGNMENT <= HUFH_WORKSPACE_SIZE);

    /* checks & inits */
    if (wkspSize < sizeof(*table)) return ERROR(workSpace_tooSmall);
    if (!srcSize) return 0;  /* Uncompressed */
    if (!dstSize) return 0;  /* cannot fit anything within dst budget */
    if (srcSize > HUFH_BLOCKSIZE_MAX) return ERROR(srcSize_wrong);   /* current block size limit */
    if (huffLog > HUFH_TABLELOG_MAX) return ERROR(tableLog_tooLarge);
    if (maxSymbolValue > HUFH_SYMBOLVALUE_MAX) return ERROR(maxSymbolValue_tooLarge);
    if (!maxSymbolValue) maxSymbolValue = HUFH_SYMBOLVALUE_MAX;
    if (!huffLog) huffLog = HUFH_TABLELOG_DEFAULT;

    /* Heuristic : If old table is valid, use it for small inputs */
    if ((flags & HUFH_flags_preferRepeat) && repeat && *repeat == HUFH_repeat_valid) {
        return HUFH_compressCTable_internal(ostart, op, oend,
                                           src, srcSize,
                                           nbStreams, oldHufTable, flags);
    }

    /* If uncompressible data is suspected, do a smaller sampling first */
    DEBUG_STATIC_ASSERT(SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO >= 2);
    if ((flags & HUFH_flags_suspectUncompressible) && srcSize >= (SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE * SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO)) {
        size_t largestTotal = 0;
        DEBUGLOG(5, "input suspected incompressible : sampling to check");
        {   unsigned maxSymbolValueBegin = maxSymbolValue;
            CHECK_V_F(largestBegin, HISTH_count_simple (table->count, &maxSymbolValueBegin, (const BYTE*)src, SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE) );
            largestTotal += largestBegin;
        }
        {   unsigned maxSymbolValueEnd = maxSymbolValue;
            CHECK_V_F(largestEnd, HISTH_count_simple (table->count, &maxSymbolValueEnd, (const BYTE*)src + srcSize - SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE, SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE) );
            largestTotal += largestEnd;
        }
        if (largestTotal <= ((2 * SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE) >> 7)+4) return 0;   /* heuristic : probably not compressible enough */
    }

    /* Scan input and build symbol stats */
    {   CHECK_V_F(largest, HISTH_count_wksp (table->count, &maxSymbolValue, (const BYTE*)src, srcSize, table->wksps.hist_wksp, sizeof(table->wksps.hist_wksp)) );
        if (largest == srcSize) { *ostart = ((const BYTE*)src)[0]; return 1; }   /* single symbol, rle */
        if (largest <= (srcSize >> 7)+4) return 0;   /* heuristic : probably not compressible enough */
    }
    DEBUGLOG(6, "histogram detail completed (%zu symbols)", showU32(table->count, maxSymbolValue+1));

    /* Check validity of previous table */
    if ( repeat
      && *repeat == HUFH_repeat_check
      && !HUFH_validateCTable(oldHufTable, table->count, maxSymbolValue)) {
        *repeat = HUFH_repeat_none;
    }
    /* Heuristic : use existing table for small inputs */
    if ((flags & HUFH_flags_preferRepeat) && repeat && *repeat != HUFH_repeat_none) {
        return HUFH_compressCTable_internal(ostart, op, oend,
                                           src, srcSize,
                                           nbStreams, oldHufTable, flags);
    }

    /* Build Huffman Tree */
    huffLog = HUFH_optimalTableLog(huffLog, srcSize, maxSymbolValue, &table->wksps, sizeof(table->wksps), table->CTable, table->count, flags);
    {   size_t const maxBits = HUFH_buildCTable_wksp(table->CTable, table->count,
                                            maxSymbolValue, huffLog,
                                            &table->wksps.buildCTable_wksp, sizeof(table->wksps.buildCTable_wksp));
        CHECK_F(maxBits);
        huffLog = (U32)maxBits;
        DEBUGLOG(6, "bit distribution completed (%zu symbols)", showCTableBits(table->CTable + 1, maxSymbolValue+1));
    }

    /* Write table description header */
    {   CHECK_V_F(hSize, HUFH_writeCTable_wksp(op, dstSize, table->CTable, maxSymbolValue, huffLog,
                                              &table->wksps.writeCTable_wksp, sizeof(table->wksps.writeCTable_wksp)) );
        /* Check if using previous huffman table is beneficial */
        if (repeat && *repeat != HUFH_repeat_none) {
            size_t const oldSize = HUFH_estimateCompressedSize(oldHufTable, table->count, maxSymbolValue);
            size_t const newSize = HUFH_estimateCompressedSize(table->CTable, table->count, maxSymbolValue);
            if (oldSize <= hSize + newSize || hSize + 12 >= srcSize) {
                return HUFH_compressCTable_internal(ostart, op, oend,
                                                   src, srcSize,
                                                   nbStreams, oldHufTable, flags);
        }   }

        /* Use the new huffman table */
        if (hSize + 12ul >= srcSize) { return 0; }
        op += hSize;
        if (repeat) { *repeat = HUFH_repeat_none; }
        if (oldHufTable)
            ZSTDH_memcpy(oldHufTable, table->CTable, sizeof(table->CTable));  /* Save new table */
    }
    return HUFH_compressCTable_internal(ostart, op, oend,
                                       src, srcSize,
                                       nbStreams, table->CTable, flags);
}

size_t HUFH_compress1X_repeat (void* dst, size_t dstSize,
                      const void* src, size_t srcSize,
                      unsigned maxSymbolValue, unsigned huffLog,
                      void* workSpace, size_t wkspSize,
                      HUFH_CElt* hufTable, HUFH_repeat* repeat, int flags)
{
    DEBUGLOG(5, "HUFH_compress1X_repeat (srcSize = %zu)", srcSize);
    return HUFH_compress_internal(dst, dstSize, src, srcSize,
                                 maxSymbolValue, huffLog, HUFH_singleStream,
                                 workSpace, wkspSize, hufTable,
                                 repeat, flags);
}

/* HUFH_compress4X_repeat():
 * compress input using 4 streams.
 * consider skipping quickly
 * reuse an existing huffman compression table */
size_t HUFH_compress4X_repeat (void* dst, size_t dstSize,
                      const void* src, size_t srcSize,
                      unsigned maxSymbolValue, unsigned huffLog,
                      void* workSpace, size_t wkspSize,
                      HUFH_CElt* hufTable, HUFH_repeat* repeat, int flags)
{
    DEBUGLOG(5, "HUFH_compress4X_repeat (srcSize = %zu)", srcSize);
    return HUFH_compress_internal(dst, dstSize, src, srcSize,
                                 maxSymbolValue, huffLog, HUFH_fourStreams,
                                 workSpace, wkspSize,
                                 hufTable, repeat, flags);
}
