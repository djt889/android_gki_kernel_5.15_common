// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */


/* ***************************************************************
*  Tuning parameters
*****************************************************************/
/*!
 * HEAPMODE :
 * Select how default decompression function ZSTDH_decompress() allocates its context,
 * on stack (0), or into heap (1, default; requires malloc()).
 * Note that functions with explicit context such as ZSTDH_decompressDCtx() are unaffected.
 */
#ifndef ZSTDH_HEAPMODE
#  define ZSTDH_HEAPMODE 1
#endif

/*!
*  LEGACY_SUPPORT :
*  if set to 1+, ZSTDH_decompress() can decode older formats (v0.1+)
*/

/*!
 *  MAXWINDOWSIZE_DEFAULT :
 *  maximum window size accepted by DStream __by default__.
 *  Frames requiring more memory will be rejected.
 *  It's possible to set a different limit using ZSTDH_DCtx_setMaxWindowSize().
 */
#ifndef ZSTDH_MAXWINDOWSIZE_DEFAULT
#  define ZSTDH_MAXWINDOWSIZE_DEFAULT (((U32)1 << ZSTDH_WINDOWLOG_LIMIT_DEFAULT) + 1)
#endif

/*!
 *  NO_FORWARD_PROGRESS_MAX :
 *  maximum allowed nb of calls to ZSTDH_decompressStream()
 *  without any forward progress
 *  (defined as: no byte read from input, and no byte flushed to output)
 *  before triggering an error.
 */
#ifndef ZSTDH_NO_FORWARD_PROGRESS_MAX
#  define ZSTDH_NO_FORWARD_PROGRESS_MAX 16
#endif


/*-*******************************************************
*  Dependencies
*********************************************************/
#include "../common/zstd_deps.h"   /* ZSTDH_memcpy, ZSTDH_memmove, ZSTDH_memset */
#include "../common/allocations.h"  /* ZSTDH_customMalloc, ZSTDH_customCalloc, ZSTDH_customFree */
#include "../common/error_private.h"
#include "../common/zstd_internal.h"  /* blockProperties_t */
#include "../common/mem.h"         /* low level memory routines */
#include "../common/bits.h"  /* ZSTDH_highbit32 */
#define FSEH_STATIC_LINKING_ONLY
#include "../common/fse.h"
#include "../common/huf.h"
#include <linux/xxhash.h> /* xxh64_reset, xxh64_update, xxh64_digest, XXH64 */
#include "zstd_decompress_internal.h"   /* ZSTDH_DCtx */
#include "zstd_ddict.h"  /* ZSTDH_DDictDictContent */
#include "zstd_decompress_block.h"   /* ZSTDH_decompressBlock_internal */




/* ***********************************
 * Multiple DDicts Hashset internals *
 *************************************/

#define DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT 4
#define DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT 3  /* These two constants represent SIZE_MULT/COUNT_MULT load factor without using a float.
                                                    * Currently, that means a 0.75 load factor.
                                                    * So, if count * COUNT_MULT / size * SIZE_MULT != 0, then we've exceeded
                                                    * the load factor of the ddict hash set.
                                                    */

#define DDICT_HASHSET_TABLE_BASE_SIZE 64
#define DDICT_HASHSET_RESIZE_FACTOR 2

/* Hash function to determine starting position of dict insertion within the table
 * Returns an index between [0, hashSet->ddictPtrTableSize]
 */
static size_t ZSTDH_DDictHashSet_getIndex(const ZSTDH_DDictHashSet* hashSet, U32 dictID) {
    const U64 hash = xxh64(&dictID, sizeof(U32), 0);
    /* DDict ptr table size is a multiple of 2, use size - 1 as mask to get index within [0, hashSet->ddictPtrTableSize) */
    return hash & (hashSet->ddictPtrTableSize - 1);
}

/* Adds DDict to a hashset without resizing it.
 * If inserting a DDict with a dictID that already exists in the set, replaces the one in the set.
 * Returns 0 if successful, or a zstd error code if something went wrong.
 */
static size_t ZSTDH_DDictHashSet_emplaceDDict(ZSTDH_DDictHashSet* hashSet, const ZSTDH_DDict* ddict) {
    const U32 dictID = ZSTDH_getDictID_fromDDict(ddict);
    size_t idx = ZSTDH_DDictHashSet_getIndex(hashSet, dictID);
    const size_t idxRangeMask = hashSet->ddictPtrTableSize - 1;
    RETURN_ERROR_IF(hashSet->ddictPtrCount == hashSet->ddictPtrTableSize, GENERIC, "Hash set is full!");
    DEBUGLOG(4, "Hashed index: for dictID: %u is %zu", dictID, idx);
    while (hashSet->ddictPtrTable[idx] != NULL) {
        /* Replace existing ddict if inserting ddict with same dictID */
        if (ZSTDH_getDictID_fromDDict(hashSet->ddictPtrTable[idx]) == dictID) {
            DEBUGLOG(4, "DictID already exists, replacing rather than adding");
            hashSet->ddictPtrTable[idx] = ddict;
            return 0;
        }
        idx &= idxRangeMask;
        idx++;
    }
    DEBUGLOG(4, "Final idx after probing for dictID %u is: %zu", dictID, idx);
    hashSet->ddictPtrTable[idx] = ddict;
    hashSet->ddictPtrCount++;
    return 0;
}

/* Expands hash table by factor of DDICT_HASHSET_RESIZE_FACTOR and
 * rehashes all values, allocates new table, frees old table.
 * Returns 0 on success, otherwise a zstd error code.
 */
static size_t ZSTDH_DDictHashSet_expand(ZSTDH_DDictHashSet* hashSet, ZSTDH_customMem customMem) {
    size_t newTableSize = hashSet->ddictPtrTableSize * DDICT_HASHSET_RESIZE_FACTOR;
    const ZSTDH_DDict** newTable = (const ZSTDH_DDict**)ZSTDH_customCalloc(sizeof(ZSTDH_DDict*) * newTableSize, customMem);
    const ZSTDH_DDict** oldTable = hashSet->ddictPtrTable;
    size_t oldTableSize = hashSet->ddictPtrTableSize;
    size_t i;

    DEBUGLOG(4, "Expanding DDict hash table! Old size: %zu new size: %zu", oldTableSize, newTableSize);
    RETURN_ERROR_IF(!newTable, memory_allocation, "Expanded hashset allocation failed!");
    hashSet->ddictPtrTable = newTable;
    hashSet->ddictPtrTableSize = newTableSize;
    hashSet->ddictPtrCount = 0;
    for (i = 0; i < oldTableSize; ++i) {
        if (oldTable[i] != NULL) {
            FORWARD_IF_ERROR(ZSTDH_DDictHashSet_emplaceDDict(hashSet, oldTable[i]), "");
        }
    }
    ZSTDH_customFree((void*)oldTable, customMem);
    DEBUGLOG(4, "Finished re-hash");
    return 0;
}

/* Fetches a DDict with the given dictID
 * Returns the ZSTDH_DDict* with the requested dictID. If it doesn't exist, then returns NULL.
 */
static const ZSTDH_DDict* ZSTDH_DDictHashSet_getDDict(ZSTDH_DDictHashSet* hashSet, U32 dictID) {
    size_t idx = ZSTDH_DDictHashSet_getIndex(hashSet, dictID);
    const size_t idxRangeMask = hashSet->ddictPtrTableSize - 1;
    DEBUGLOG(4, "Hashed index: for dictID: %u is %zu", dictID, idx);
    for (;;) {
        size_t currDictID = ZSTDH_getDictID_fromDDict(hashSet->ddictPtrTable[idx]);
        if (currDictID == dictID || currDictID == 0) {
            /* currDictID == 0 implies a NULL ddict entry */
            break;
        } else {
            idx &= idxRangeMask;    /* Goes to start of table when we reach the end */
            idx++;
        }
    }
    DEBUGLOG(4, "Final idx after probing for dictID %u is: %zu", dictID, idx);
    return hashSet->ddictPtrTable[idx];
}

/* Allocates space for and returns a ddict hash set
 * The hash set's ZSTDH_DDict* table has all values automatically set to NULL to begin with.
 * Returns NULL if allocation failed.
 */
static ZSTDH_DDictHashSet* ZSTDH_createDDictHashSet(ZSTDH_customMem customMem) {
    ZSTDH_DDictHashSet* ret = (ZSTDH_DDictHashSet*)ZSTDH_customMalloc(sizeof(ZSTDH_DDictHashSet), customMem);
    DEBUGLOG(4, "Allocating new hash set");
    if (!ret)
        return NULL;
    ret->ddictPtrTable = (const ZSTDH_DDict**)ZSTDH_customCalloc(DDICT_HASHSET_TABLE_BASE_SIZE * sizeof(ZSTDH_DDict*), customMem);
    if (!ret->ddictPtrTable) {
        ZSTDH_customFree(ret, customMem);
        return NULL;
    }
    ret->ddictPtrTableSize = DDICT_HASHSET_TABLE_BASE_SIZE;
    ret->ddictPtrCount = 0;
    return ret;
}

/* Frees the table of ZSTDH_DDict* within a hashset, then frees the hashset itself.
 * Note: The ZSTDH_DDict* within the table are NOT freed.
 */
static void ZSTDH_freeDDictHashSet(ZSTDH_DDictHashSet* hashSet, ZSTDH_customMem customMem) {
    DEBUGLOG(4, "Freeing ddict hash set");
    if (hashSet && hashSet->ddictPtrTable) {
        ZSTDH_customFree((void*)hashSet->ddictPtrTable, customMem);
    }
    if (hashSet) {
        ZSTDH_customFree(hashSet, customMem);
    }
}

/* Public function: Adds a DDict into the ZSTDH_DDictHashSet, possibly triggering a resize of the hash set.
 * Returns 0 on success, or a ZSTD error.
 */
static size_t ZSTDH_DDictHashSet_addDDict(ZSTDH_DDictHashSet* hashSet, const ZSTDH_DDict* ddict, ZSTDH_customMem customMem) {
    DEBUGLOG(4, "Adding dict ID: %u to hashset with - Count: %zu Tablesize: %zu", ZSTDH_getDictID_fromDDict(ddict), hashSet->ddictPtrCount, hashSet->ddictPtrTableSize);
    if (hashSet->ddictPtrCount * DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT / hashSet->ddictPtrTableSize * DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT != 0) {
        FORWARD_IF_ERROR(ZSTDH_DDictHashSet_expand(hashSet, customMem), "");
    }
    FORWARD_IF_ERROR(ZSTDH_DDictHashSet_emplaceDDict(hashSet, ddict), "");
    return 0;
}

/*-*************************************************************
*   Context management
***************************************************************/
size_t ZSTDH_sizeof_DCtx (const ZSTDH_DCtx* dctx)
{
    if (dctx==NULL) return 0;   /* support sizeof NULL */
    return sizeof(*dctx)
           + ZSTDH_sizeof_DDict(dctx->ddictLocal)
           + dctx->inBuffSize + dctx->outBuffSize;
}

size_t ZSTDH_estimateDCtxSize(void) { return sizeof(ZSTDH_DCtx); }


static size_t ZSTDH_startingInputLength(ZSTDH_format_e format)
{
    size_t const startingInputLength = ZSTDH_FRAMEHEADERSIZE_PREFIX(format);
    /* only supports formats ZSTDH_f_zstd1 and ZSTDH_f_zstd1_magicless */
    assert( (format == ZSTDH_f_zstd1) || (format == ZSTDH_f_zstd1_magicless) );
    return startingInputLength;
}

static void ZSTDH_DCtx_resetParameters(ZSTDH_DCtx* dctx)
{
    assert(dctx->streamStage == zdss_init);
    dctx->format = ZSTDH_f_zstd1;
    dctx->maxWindowSize = ZSTDH_MAXWINDOWSIZE_DEFAULT;
    dctx->outBufferMode = ZSTDH_bm_buffered;
    dctx->forceIgnoreChecksum = ZSTDH_d_validateChecksum;
    dctx->refMultipleDDicts = ZSTDH_rmd_refSingleDDict;
    dctx->disableHufAsm = 0;
    dctx->maxBlockSizeParam = 0;
}

static void ZSTDH_initDCtx_internal(ZSTDH_DCtx* dctx)
{
    dctx->staticSize  = 0;
    dctx->ddict       = NULL;
    dctx->ddictLocal  = NULL;
    dctx->dictEnd     = NULL;
    dctx->ddictIsCold = 0;
    dctx->dictUses = ZSTDH_dont_use;
    dctx->inBuff      = NULL;
    dctx->inBuffSize  = 0;
    dctx->outBuffSize = 0;
    dctx->streamStage = zdss_init;
    dctx->noForwardProgress = 0;
    dctx->oversizedDuration = 0;
    dctx->isFrameDecompression = 1;
#if DYNAMIC_BMI2
    dctx->bmi2 = ZSTDH_cpuSupportsBmi2();
#endif
    dctx->ddictSet = NULL;
    ZSTDH_DCtx_resetParameters(dctx);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    dctx->dictContentEndForFuzzing = NULL;
#endif
}

ZSTDH_DCtx* ZSTDH_initStaticDCtx(void *workspace, size_t workspaceSize)
{
    ZSTDH_DCtx* const dctx = (ZSTDH_DCtx*) workspace;

    if ((size_t)workspace & 7) return NULL;  /* 8-aligned */
    if (workspaceSize < sizeof(ZSTDH_DCtx)) return NULL;  /* minimum size */

    ZSTDH_initDCtx_internal(dctx);
    dctx->staticSize = workspaceSize;
    dctx->inBuff = (char*)(dctx+1);
    return dctx;
}

static ZSTDH_DCtx* ZSTDH_createDCtx_internal(ZSTDH_customMem customMem) {
    if ((!customMem.customAlloc) ^ (!customMem.customFree)) return NULL;

    {   ZSTDH_DCtx* const dctx = (ZSTDH_DCtx*)ZSTDH_customMalloc(sizeof(*dctx), customMem);
        if (!dctx) return NULL;
        dctx->customMem = customMem;
        ZSTDH_initDCtx_internal(dctx);
        return dctx;
    }
}

ZSTDH_DCtx* ZSTDH_createDCtx_advanced(ZSTDH_customMem customMem)
{
    return ZSTDH_createDCtx_internal(customMem);
}

ZSTDH_DCtx* ZSTDH_createDCtx(void)
{
    DEBUGLOG(3, "ZSTDH_createDCtx");
    return ZSTDH_createDCtx_internal(ZSTDH_defaultCMem);
}

static void ZSTDH_clearDict(ZSTDH_DCtx* dctx)
{
    ZSTDH_freeDDict(dctx->ddictLocal);
    dctx->ddictLocal = NULL;
    dctx->ddict = NULL;
    dctx->dictUses = ZSTDH_dont_use;
}

size_t ZSTDH_freeDCtx(ZSTDH_DCtx* dctx)
{
    if (dctx==NULL) return 0;   /* support free on NULL */
    RETURN_ERROR_IF(dctx->staticSize, memory_allocation, "not compatible with static DCtx");
    {   ZSTDH_customMem const cMem = dctx->customMem;
        ZSTDH_clearDict(dctx);
        ZSTDH_customFree(dctx->inBuff, cMem);
        dctx->inBuff = NULL;
        if (dctx->ddictSet) {
            ZSTDH_freeDDictHashSet(dctx->ddictSet, cMem);
            dctx->ddictSet = NULL;
        }
        ZSTDH_customFree(dctx, cMem);
        return 0;
    }
}

/* no longer useful */
void ZSTDH_copyDCtx(ZSTDH_DCtx* dstDCtx, const ZSTDH_DCtx* srcDCtx)
{
    size_t const toCopy = (size_t)((char*)(&dstDCtx->inBuff) - (char*)dstDCtx);
    ZSTDH_memcpy(dstDCtx, srcDCtx, toCopy);  /* no need to copy workspace */
}

/* Given a dctx with a digested frame params, re-selects the correct ZSTDH_DDict based on
 * the requested dict ID from the frame. If there exists a reference to the correct ZSTDH_DDict, then
 * accordingly sets the ddict to be used to decompress the frame.
 *
 * If no DDict is found, then no action is taken, and the ZSTDH_DCtx::ddict remains as-is.
 *
 * ZSTDH_d_refMultipleDDicts must be enabled for this function to be called.
 */
static void ZSTDH_DCtx_selectFrameDDict(ZSTDH_DCtx* dctx) {
    assert(dctx->refMultipleDDicts && dctx->ddictSet);
    DEBUGLOG(4, "Adjusting DDict based on requested dict ID from frame");
    if (dctx->ddict) {
        const ZSTDH_DDict* frameDDict = ZSTDH_DDictHashSet_getDDict(dctx->ddictSet, dctx->fParams.dictID);
        if (frameDDict) {
            DEBUGLOG(4, "DDict found!");
            ZSTDH_clearDict(dctx);
            dctx->dictID = dctx->fParams.dictID;
            dctx->ddict = frameDDict;
            dctx->dictUses = ZSTDH_use_indefinitely;
        }
    }
}


/*-*************************************************************
 *   Frame header decoding
 ***************************************************************/

/*! ZSTDH_isFrame() :
 *  Tells if the content of `buffer` starts with a valid Frame Identifier.
 *  Note : Frame Identifier is 4 bytes. If `size < 4`, @return will always be 0.
 *  Note 2 : Legacy Frame Identifiers are considered valid only if Legacy Support is enabled.
 *  Note 3 : Skippable Frame Identifiers are considered valid. */
unsigned ZSTDH_isFrame(const void* buffer, size_t size)
{
    if (size < ZSTDH_FRAMEIDSIZE) return 0;
    {   U32 const magic = MEM_readLE32(buffer);
        if (magic == ZSTDH_MAGICNUMBER) return 1;
        if ((magic & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) return 1;
    }
    return 0;
}

/*! ZSTDH_isSkippableFrame() :
 *  Tells if the content of `buffer` starts with a valid Frame Identifier for a skippable frame.
 *  Note : Frame Identifier is 4 bytes. If `size < 4`, @return will always be 0.
 */
unsigned ZSTDH_isSkippableFrame(const void* buffer, size_t size)
{
    if (size < ZSTDH_FRAMEIDSIZE) return 0;
    {   U32 const magic = MEM_readLE32(buffer);
        if ((magic & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) return 1;
    }
    return 0;
}

/* ZSTDH_frameHeaderSize_internal() :
 *  srcSize must be large enough to reach header size fields.
 *  note : only works for formats ZSTDH_f_zstd1 and ZSTDH_f_zstd1_magicless.
 * @return : size of the Frame Header
 *           or an error code, which can be tested with ZSTDH_isError() */
static size_t ZSTDH_frameHeaderSize_internal(const void* src, size_t srcSize, ZSTDH_format_e format)
{
    size_t const minInputSize = ZSTDH_startingInputLength(format);
    RETURN_ERROR_IF(srcSize < minInputSize, srcSize_wrong, "");

    {   BYTE const fhd = ((const BYTE*)src)[minInputSize-1];
        U32 const dictID= fhd & 3;
        U32 const singleSegment = (fhd >> 5) & 1;
        U32 const fcsId = fhd >> 6;
        return minInputSize + !singleSegment
             + ZSTDH_did_fieldSize[dictID] + ZSTDH_fcs_fieldSize[fcsId]
             + (singleSegment && !fcsId);
    }
}

/* ZSTDH_frameHeaderSize() :
 *  srcSize must be >= ZSTDH_frameHeaderSize_prefix.
 * @return : size of the Frame Header,
 *           or an error code (if srcSize is too small) */
size_t ZSTDH_frameHeaderSize(const void* src, size_t srcSize)
{
    return ZSTDH_frameHeaderSize_internal(src, srcSize, ZSTDH_f_zstd1);
}


/* ZSTDH_getFrameHeader_advanced() :
 *  decode Frame Header, or require larger `srcSize`.
 *  note : only works for formats ZSTDH_f_zstd1 and ZSTDH_f_zstd1_magicless
 * @return : 0, `zfhPtr` is correctly filled,
 *          >0, `srcSize` is too small, value is wanted `srcSize` amount,
**           or an error code, which can be tested using ZSTDH_isError() */
size_t ZSTDH_getFrameHeader_advanced(ZSTDH_FrameHeader* zfhPtr, const void* src, size_t srcSize, ZSTDH_format_e format)
{
    const BYTE* ip = (const BYTE*)src;
    size_t const minInputSize = ZSTDH_startingInputLength(format);

    DEBUGLOG(5, "ZSTDH_getFrameHeader_advanced: minInputSize = %zu, srcSize = %zu", minInputSize, srcSize);

    if (srcSize > 0) {
        /* note : technically could be considered an assert(), since it's an invalid entry */
        RETURN_ERROR_IF(src==NULL, GENERIC, "invalid parameter : src==NULL, but srcSize>0");
    }
    if (srcSize < minInputSize) {
        if (srcSize > 0 && format != ZSTDH_f_zstd1_magicless) {
            /* when receiving less than @minInputSize bytes,
             * control these bytes at least correspond to a supported magic number
             * in order to error out early if they don't.
            **/
            size_t const toCopy = MIN(4, srcSize);
            unsigned char hbuf[4]; MEM_writeLE32(hbuf, ZSTDH_MAGICNUMBER);
            assert(src != NULL);
            ZSTDH_memcpy(hbuf, src, toCopy);
            if ( MEM_readLE32(hbuf) != ZSTDH_MAGICNUMBER ) {
                /* not a zstd frame : let's check if it's a skippable frame */
                MEM_writeLE32(hbuf, ZSTDH_MAGIC_SKIPPABLE_START);
                ZSTDH_memcpy(hbuf, src, toCopy);
                if ((MEM_readLE32(hbuf) & ZSTDH_MAGIC_SKIPPABLE_MASK) != ZSTDH_MAGIC_SKIPPABLE_START) {
                    RETURN_ERROR(prefix_unknown,
                                "first bytes don't correspond to any supported magic number");
        }   }   }
        return minInputSize;
    }

    ZSTDH_memset(zfhPtr, 0, sizeof(*zfhPtr));   /* not strictly necessary, but static analyzers may not understand that zfhPtr will be read only if return value is zero, since they are 2 different signals */
    if ( (format != ZSTDH_f_zstd1_magicless)
      && (MEM_readLE32(src) != ZSTDH_MAGICNUMBER) ) {
        if ((MEM_readLE32(src) & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {
            /* skippable frame */
            if (srcSize < ZSTDH_SKIPPABLEHEADERSIZE)
                return ZSTDH_SKIPPABLEHEADERSIZE; /* magic number + frame length */
            ZSTDH_memset(zfhPtr, 0, sizeof(*zfhPtr));
            zfhPtr->frameType = ZSTDH_skippableFrame;
            zfhPtr->dictID = MEM_readLE32(src) - ZSTDH_MAGIC_SKIPPABLE_START;
            zfhPtr->headerSize = ZSTDH_SKIPPABLEHEADERSIZE;
            zfhPtr->frameContentSize = MEM_readLE32((const char *)src + ZSTDH_FRAMEIDSIZE);
            return 0;
        }
        RETURN_ERROR(prefix_unknown, "");
    }

    /* ensure there is enough `srcSize` to fully read/decode frame header */
    {   size_t const fhsize = ZSTDH_frameHeaderSize_internal(src, srcSize, format);
        if (srcSize < fhsize) return fhsize;
        zfhPtr->headerSize = (U32)fhsize;
    }

    {   BYTE const fhdByte = ip[minInputSize-1];
        size_t pos = minInputSize;
        U32 const dictIDSizeCode = fhdByte&3;
        U32 const checksumFlag = (fhdByte>>2)&1;
        U32 const singleSegment = (fhdByte>>5)&1;
        U32 const fcsID = fhdByte>>6;
        U64 windowSize = 0;
        U32 dictID = 0;
        U64 frameContentSize = ZSTDH_CONTENTSIZE_UNKNOWN;
        RETURN_ERROR_IF((fhdByte & 0x08) != 0, frameParameter_unsupported,
                        "reserved bits, must be zero");

        if (!singleSegment) {
            BYTE const wlByte = ip[pos++];
            U32 const windowLog = (wlByte >> 3) + ZSTDH_WINDOWLOG_ABSOLUTEMIN;
            RETURN_ERROR_IF(windowLog > ZSTDH_WINDOWLOG_MAX, frameParameter_windowTooLarge, "");
            windowSize = (1ULL << windowLog);
            windowSize += (windowSize >> 3) * (wlByte&7);
        }
        switch(dictIDSizeCode)
        {
            default:
                assert(0);  /* impossible */
                ZSTDH_FALLTHROUGH;
            case 0 : break;
            case 1 : dictID = ip[pos]; pos++; break;
            case 2 : dictID = MEM_readLE16(ip+pos); pos+=2; break;
            case 3 : dictID = MEM_readLE32(ip+pos); pos+=4; break;
        }
        switch(fcsID)
        {
            default:
                assert(0);  /* impossible */
                ZSTDH_FALLTHROUGH;
            case 0 : if (singleSegment) frameContentSize = ip[pos]; break;
            case 1 : frameContentSize = MEM_readLE16(ip+pos)+256; break;
            case 2 : frameContentSize = MEM_readLE32(ip+pos); break;
            case 3 : frameContentSize = MEM_readLE64(ip+pos); break;
        }
        if (singleSegment) windowSize = frameContentSize;

        zfhPtr->frameType = ZSTDH_frame;
        zfhPtr->frameContentSize = frameContentSize;
        zfhPtr->windowSize = windowSize;
        zfhPtr->blockSizeMax = (unsigned) MIN(windowSize, ZSTDH_BLOCKSIZE_MAX);
        zfhPtr->dictID = dictID;
        zfhPtr->checksumFlag = checksumFlag;
    }
    return 0;
}

/* ZSTDH_getFrameHeader() :
 *  decode Frame Header, or require larger `srcSize`.
 *  note : this function does not consume input, it only reads it.
 * @return : 0, `zfhPtr` is correctly filled,
 *          >0, `srcSize` is too small, value is wanted `srcSize` amount,
 *           or an error code, which can be tested using ZSTDH_isError() */
size_t ZSTDH_getFrameHeader(ZSTDH_FrameHeader* zfhPtr, const void* src, size_t srcSize)
{
    return ZSTDH_getFrameHeader_advanced(zfhPtr, src, srcSize, ZSTDH_f_zstd1);
}

/* ZSTDH_getFrameContentSize() :
 *  compatible with legacy mode
 * @return : decompressed size of the single frame pointed to be `src` if known, otherwise
 *         - ZSTDH_CONTENTSIZE_UNKNOWN if the size cannot be determined
 *         - ZSTDH_CONTENTSIZE_ERROR if an error occurred (e.g. invalid magic number, srcSize too small) */
unsigned long long ZSTDH_getFrameContentSize(const void *src, size_t srcSize)
{
    {   ZSTDH_FrameHeader zfh;
        if (ZSTDH_getFrameHeader(&zfh, src, srcSize) != 0)
            return ZSTDH_CONTENTSIZE_ERROR;
        if (zfh.frameType == ZSTDH_skippableFrame) {
            return 0;
        } else {
            return zfh.frameContentSize;
    }   }
}

static size_t readSkippableFrameSize(void const* src, size_t srcSize)
{
    size_t const skippableHeaderSize = ZSTDH_SKIPPABLEHEADERSIZE;
    U32 sizeU32;

    RETURN_ERROR_IF(srcSize < ZSTDH_SKIPPABLEHEADERSIZE, srcSize_wrong, "");

    sizeU32 = MEM_readLE32((BYTE const*)src + ZSTDH_FRAMEIDSIZE);
    RETURN_ERROR_IF((U32)(sizeU32 + ZSTDH_SKIPPABLEHEADERSIZE) < sizeU32,
                    frameParameter_unsupported, "");
    {   size_t const skippableSize = skippableHeaderSize + sizeU32;
        RETURN_ERROR_IF(skippableSize > srcSize, srcSize_wrong, "");
        return skippableSize;
    }
}

/*! ZSTDH_readSkippableFrame() :
 * Retrieves content of a skippable frame, and writes it to dst buffer.
 *
 * The parameter magicVariant will receive the magicVariant that was supplied when the frame was written,
 * i.e. magicNumber - ZSTDH_MAGIC_SKIPPABLE_START.  This can be NULL if the caller is not interested
 * in the magicVariant.
 *
 * Returns an error if destination buffer is not large enough, or if this is not a valid skippable frame.
 *
 * @return : number of bytes written or a ZSTD error.
 */
size_t ZSTDH_readSkippableFrame(void* dst, size_t dstCapacity,
                               unsigned* magicVariant,  /* optional, can be NULL */
                         const void* src, size_t srcSize)
{
    RETURN_ERROR_IF(srcSize < ZSTDH_SKIPPABLEHEADERSIZE, srcSize_wrong, "");

    {   U32 const magicNumber = MEM_readLE32(src);
        size_t skippableFrameSize = readSkippableFrameSize(src, srcSize);
        size_t skippableContentSize = skippableFrameSize - ZSTDH_SKIPPABLEHEADERSIZE;

        /* check input validity */
        RETURN_ERROR_IF(!ZSTDH_isSkippableFrame(src, srcSize), frameParameter_unsupported, "");
        RETURN_ERROR_IF(skippableFrameSize < ZSTDH_SKIPPABLEHEADERSIZE || skippableFrameSize > srcSize, srcSize_wrong, "");
        RETURN_ERROR_IF(skippableContentSize > dstCapacity, dstSize_tooSmall, "");

        /* deliver payload */
        if (skippableContentSize > 0  && dst != NULL)
            ZSTDH_memcpy(dst, (const BYTE *)src + ZSTDH_SKIPPABLEHEADERSIZE, skippableContentSize);
        if (magicVariant != NULL)
            *magicVariant = magicNumber - ZSTDH_MAGIC_SKIPPABLE_START;
        return skippableContentSize;
    }
}

/* ZSTDH_findDecompressedSize() :
 *  `srcSize` must be the exact length of some number of ZSTD compressed and/or
 *      skippable frames
 *  note: compatible with legacy mode
 * @return : decompressed size of the frames contained */
unsigned long long ZSTDH_findDecompressedSize(const void* src, size_t srcSize)
{
    unsigned long long totalDstSize = 0;

    while (srcSize >= ZSTDH_startingInputLength(ZSTDH_f_zstd1)) {
        U32 const magicNumber = MEM_readLE32(src);

        if ((magicNumber & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {
            size_t const skippableSize = readSkippableFrameSize(src, srcSize);
            if (ZSTDH_isError(skippableSize)) return ZSTDH_CONTENTSIZE_ERROR;
            assert(skippableSize <= srcSize);

            src = (const BYTE *)src + skippableSize;
            srcSize -= skippableSize;
            continue;
        }

        {   unsigned long long const fcs = ZSTDH_getFrameContentSize(src, srcSize);
            if (fcs >= ZSTDH_CONTENTSIZE_ERROR) return fcs;

            if (totalDstSize + fcs < totalDstSize)
                return ZSTDH_CONTENTSIZE_ERROR; /* check for overflow */
            totalDstSize += fcs;
        }
        /* skip to next frame */
        {   size_t const frameSrcSize = ZSTDH_findFrameCompressedSize(src, srcSize);
            if (ZSTDH_isError(frameSrcSize)) return ZSTDH_CONTENTSIZE_ERROR;
            assert(frameSrcSize <= srcSize);

            src = (const BYTE *)src + frameSrcSize;
            srcSize -= frameSrcSize;
        }
    }  /* while (srcSize >= ZSTDH_frameHeaderSize_prefix) */

    if (srcSize) return ZSTDH_CONTENTSIZE_ERROR;

    return totalDstSize;
}

/* ZSTDH_getDecompressedSize() :
 *  compatible with legacy mode
 * @return : decompressed size if known, 0 otherwise
             note : 0 can mean any of the following :
                   - frame content is empty
                   - decompressed size field is not present in frame header
                   - frame header unknown / not supported
                   - frame header not complete (`srcSize` too small) */
unsigned long long ZSTDH_getDecompressedSize(const void* src, size_t srcSize)
{
    unsigned long long const ret = ZSTDH_getFrameContentSize(src, srcSize);
    ZSTDH_STATIC_ASSERT(ZSTDH_CONTENTSIZE_ERROR < ZSTDH_CONTENTSIZE_UNKNOWN);
    return (ret >= ZSTDH_CONTENTSIZE_ERROR) ? 0 : ret;
}


/* ZSTDH_decodeFrameHeader() :
 * `headerSize` must be the size provided by ZSTDH_frameHeaderSize().
 * If multiple DDict references are enabled, also will choose the correct DDict to use.
 * @return : 0 if success, or an error code, which can be tested using ZSTDH_isError() */
static size_t ZSTDH_decodeFrameHeader(ZSTDH_DCtx* dctx, const void* src, size_t headerSize)
{
    size_t const result = ZSTDH_getFrameHeader_advanced(&(dctx->fParams), src, headerSize, dctx->format);
    if (ZSTDH_isError(result)) return result;    /* invalid header */
    RETURN_ERROR_IF(result>0, srcSize_wrong, "headerSize too small");

    /* Reference DDict requested by frame if dctx references multiple ddicts */
    if (dctx->refMultipleDDicts == ZSTDH_rmd_refMultipleDDicts && dctx->ddictSet) {
        ZSTDH_DCtx_selectFrameDDict(dctx);
    }

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    /* Skip the dictID check in fuzzing mode, because it makes the search
     * harder.
     */
    RETURN_ERROR_IF(dctx->fParams.dictID && (dctx->dictID != dctx->fParams.dictID),
                    dictionary_wrong, "");
#endif
    dctx->validateChecksum = (dctx->fParams.checksumFlag && !dctx->forceIgnoreChecksum) ? 1 : 0;
    if (dctx->validateChecksum) xxh64_reset(&dctx->xxhState, 0);
    dctx->processedCSize += headerSize;
    return 0;
}

static ZSTDH_frameSizeInfo ZSTDH_errorFrameSizeInfo(size_t ret)
{
    ZSTDH_frameSizeInfo frameSizeInfo;
    frameSizeInfo.compressedSize = ret;
    frameSizeInfo.decompressedBound = ZSTDH_CONTENTSIZE_ERROR;
    return frameSizeInfo;
}

static ZSTDH_frameSizeInfo ZSTDH_findFrameSizeInfo(const void* src, size_t srcSize, ZSTDH_format_e format)
{
    ZSTDH_frameSizeInfo frameSizeInfo;
    ZSTDH_memset(&frameSizeInfo, 0, sizeof(ZSTDH_frameSizeInfo));


    if (format == ZSTDH_f_zstd1 && (srcSize >= ZSTDH_SKIPPABLEHEADERSIZE)
        && (MEM_readLE32(src) & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {
        frameSizeInfo.compressedSize = readSkippableFrameSize(src, srcSize);
        assert(ZSTDH_isError(frameSizeInfo.compressedSize) ||
               frameSizeInfo.compressedSize <= srcSize);
        return frameSizeInfo;
    } else {
        const BYTE* ip = (const BYTE*)src;
        const BYTE* const ipstart = ip;
        size_t remainingSize = srcSize;
        size_t nbBlocks = 0;
        ZSTDH_FrameHeader zfh;

        /* Extract Frame Header */
        {   size_t const ret = ZSTDH_getFrameHeader_advanced(&zfh, src, srcSize, format);
            if (ZSTDH_isError(ret))
                return ZSTDH_errorFrameSizeInfo(ret);
            if (ret > 0)
                return ZSTDH_errorFrameSizeInfo(ERROR(srcSize_wrong));
        }

        ip += zfh.headerSize;
        remainingSize -= zfh.headerSize;

        /* Iterate over each block */
        while (1) {
            blockProperties_t blockProperties;
            size_t const cBlockSize = ZSTDH_getcBlockSize(ip, remainingSize, &blockProperties);
            if (ZSTDH_isError(cBlockSize))
                return ZSTDH_errorFrameSizeInfo(cBlockSize);

            if (ZSTDH_blockHeaderSize + cBlockSize > remainingSize)
                return ZSTDH_errorFrameSizeInfo(ERROR(srcSize_wrong));

            ip += ZSTDH_blockHeaderSize + cBlockSize;
            remainingSize -= ZSTDH_blockHeaderSize + cBlockSize;
            nbBlocks++;

            if (blockProperties.lastBlock) break;
        }

        /* Final frame content checksum */
        if (zfh.checksumFlag) {
            if (remainingSize < 4)
                return ZSTDH_errorFrameSizeInfo(ERROR(srcSize_wrong));
            ip += 4;
        }

        frameSizeInfo.nbBlocks = nbBlocks;
        frameSizeInfo.compressedSize = (size_t)(ip - ipstart);
        frameSizeInfo.decompressedBound = (zfh.frameContentSize != ZSTDH_CONTENTSIZE_UNKNOWN)
                                        ? zfh.frameContentSize
                                        : (unsigned long long)nbBlocks * zfh.blockSizeMax;
        return frameSizeInfo;
    }
}

static size_t ZSTDH_findFrameCompressedSize_advanced(const void *src, size_t srcSize, ZSTDH_format_e format) {
    ZSTDH_frameSizeInfo const frameSizeInfo = ZSTDH_findFrameSizeInfo(src, srcSize, format);
    return frameSizeInfo.compressedSize;
}

/* ZSTDH_findFrameCompressedSize() :
 * See docs in zstd.h
 * Note: compatible with legacy mode */
size_t ZSTDH_findFrameCompressedSize(const void *src, size_t srcSize)
{
    return ZSTDH_findFrameCompressedSize_advanced(src, srcSize, ZSTDH_f_zstd1);
}

/* ZSTDH_decompressBound() :
 *  compatible with legacy mode
 *  `src` must point to the start of a ZSTD frame or a skippable frame
 *  `srcSize` must be at least as large as the frame contained
 *  @return : the maximum decompressed size of the compressed source
 */
unsigned long long ZSTDH_decompressBound(const void* src, size_t srcSize)
{
    unsigned long long bound = 0;
    /* Iterate over each frame */
    while (srcSize > 0) {
        ZSTDH_frameSizeInfo const frameSizeInfo = ZSTDH_findFrameSizeInfo(src, srcSize, ZSTDH_f_zstd1);
        size_t const compressedSize = frameSizeInfo.compressedSize;
        unsigned long long const decompressedBound = frameSizeInfo.decompressedBound;
        if (ZSTDH_isError(compressedSize) || decompressedBound == ZSTDH_CONTENTSIZE_ERROR)
            return ZSTDH_CONTENTSIZE_ERROR;
        assert(srcSize >= compressedSize);
        src = (const BYTE*)src + compressedSize;
        srcSize -= compressedSize;
        bound += decompressedBound;
    }
    return bound;
}

size_t ZSTDH_decompressionMargin(void const* src, size_t srcSize)
{
    size_t margin = 0;
    unsigned maxBlockSize = 0;

    /* Iterate over each frame */
    while (srcSize > 0) {
        ZSTDH_frameSizeInfo const frameSizeInfo = ZSTDH_findFrameSizeInfo(src, srcSize, ZSTDH_f_zstd1);
        size_t const compressedSize = frameSizeInfo.compressedSize;
        unsigned long long const decompressedBound = frameSizeInfo.decompressedBound;
        ZSTDH_FrameHeader zfh;

        FORWARD_IF_ERROR(ZSTDH_getFrameHeader(&zfh, src, srcSize), "");
        if (ZSTDH_isError(compressedSize) || decompressedBound == ZSTDH_CONTENTSIZE_ERROR)
            return ERROR(corruption_detected);

        if (zfh.frameType == ZSTDH_frame) {
            /* Add the frame header to our margin */
            margin += zfh.headerSize;
            /* Add the checksum to our margin */
            margin += zfh.checksumFlag ? 4 : 0;
            /* Add 3 bytes per block */
            margin += 3 * frameSizeInfo.nbBlocks;

            /* Compute the max block size */
            maxBlockSize = MAX(maxBlockSize, zfh.blockSizeMax);
        } else {
            assert(zfh.frameType == ZSTDH_skippableFrame);
            /* Add the entire skippable frame size to our margin. */
            margin += compressedSize;
        }

        assert(srcSize >= compressedSize);
        src = (const BYTE*)src + compressedSize;
        srcSize -= compressedSize;
    }

    /* Add the max block size back to the margin. */
    margin += maxBlockSize;

    return margin;
}

/*-*************************************************************
 *   Frame decoding
 ***************************************************************/

/* ZSTDH_insertBlock() :
 *  insert `src` block into `dctx` history. Useful to track uncompressed blocks. */
size_t ZSTDH_insertBlock(ZSTDH_DCtx* dctx, const void* blockStart, size_t blockSize)
{
    DEBUGLOG(5, "ZSTDH_insertBlock: %u bytes", (unsigned)blockSize);
    ZSTDH_checkContinuity(dctx, blockStart, blockSize);
    dctx->previousDstEnd = (const char*)blockStart + blockSize;
    return blockSize;
}


static size_t ZSTDH_copyRawBlock(void* dst, size_t dstCapacity,
                          const void* src, size_t srcSize)
{
    DEBUGLOG(5, "ZSTDH_copyRawBlock");
    RETURN_ERROR_IF(srcSize > dstCapacity, dstSize_tooSmall, "");
    if (dst == NULL) {
        if (srcSize == 0) return 0;
        RETURN_ERROR(dstBuffer_null, "");
    }
    ZSTDH_memmove(dst, src, srcSize);
    return srcSize;
}

static size_t ZSTDH_setRleBlock(void* dst, size_t dstCapacity,
                               BYTE b,
                               size_t regenSize)
{
    RETURN_ERROR_IF(regenSize > dstCapacity, dstSize_tooSmall, "");
    if (dst == NULL) {
        if (regenSize == 0) return 0;
        RETURN_ERROR(dstBuffer_null, "");
    }
    ZSTDH_memset(dst, b, regenSize);
    return regenSize;
}

static void ZSTDH_DCtx_trace_end(ZSTDH_DCtx const* dctx, U64 uncompressedSize, U64 compressedSize, int streaming)
{
    (void)dctx;
    (void)uncompressedSize;
    (void)compressedSize;
    (void)streaming;
}


/*! ZSTDH_decompressFrame() :
 * @dctx must be properly initialized
 *  will update *srcPtr and *srcSizePtr,
 *  to make *srcPtr progress by one frame. */
static size_t ZSTDH_decompressFrame(ZSTDH_DCtx* dctx,
                                   void* dst, size_t dstCapacity,
                             const void** srcPtr, size_t *srcSizePtr)
{
    const BYTE* const istart = (const BYTE*)(*srcPtr);
    const BYTE* ip = istart;
    BYTE* const ostart = (BYTE*)dst;
    BYTE* const oend = dstCapacity != 0 ? ostart + dstCapacity : ostart;
    BYTE* op = ostart;
    size_t remainingSrcSize = *srcSizePtr;

    DEBUGLOG(4, "ZSTDH_decompressFrame (srcSize:%i)", (int)*srcSizePtr);

    /* check */
    RETURN_ERROR_IF(
        remainingSrcSize < ZSTDH_FRAMEHEADERSIZE_MIN(dctx->format)+ZSTDH_blockHeaderSize,
        srcSize_wrong, "");

    /* Frame Header */
    {   size_t const frameHeaderSize = ZSTDH_frameHeaderSize_internal(
                ip, ZSTDH_FRAMEHEADERSIZE_PREFIX(dctx->format), dctx->format);
        if (ZSTDH_isError(frameHeaderSize)) return frameHeaderSize;
        RETURN_ERROR_IF(remainingSrcSize < frameHeaderSize+ZSTDH_blockHeaderSize,
                        srcSize_wrong, "");
        FORWARD_IF_ERROR( ZSTDH_decodeFrameHeader(dctx, ip, frameHeaderSize) , "");
        ip += frameHeaderSize; remainingSrcSize -= frameHeaderSize;
    }

    /* Shrink the blockSizeMax if enabled */
    if (dctx->maxBlockSizeParam != 0)
        dctx->fParams.blockSizeMax = MIN(dctx->fParams.blockSizeMax, (unsigned)dctx->maxBlockSizeParam);

    /* Loop on each block */
    while (1) {
        BYTE* oBlockEnd = oend;
        size_t decodedSize;
        blockProperties_t blockProperties;
        size_t const cBlockSize = ZSTDH_getcBlockSize(ip, remainingSrcSize, &blockProperties);
        if (ZSTDH_isError(cBlockSize)) return cBlockSize;

        ip += ZSTDH_blockHeaderSize;
        remainingSrcSize -= ZSTDH_blockHeaderSize;
        RETURN_ERROR_IF(cBlockSize > remainingSrcSize, srcSize_wrong, "");

        if (ip >= op && ip < oBlockEnd) {
            /* We are decompressing in-place. Limit the output pointer so that we
             * don't overwrite the block that we are currently reading. This will
             * fail decompression if the input & output pointers aren't spaced
             * far enough apart.
             *
             * This is important to set, even when the pointers are far enough
             * apart, because ZSTDH_decompressBlock_internal() can decide to store
             * literals in the output buffer, after the block it is decompressing.
             * Since we don't want anything to overwrite our input, we have to tell
             * ZSTDH_decompressBlock_internal to never write past ip.
             *
             * See ZSTDH_allocateLiteralsBuffer() for reference.
             */
            oBlockEnd = op + (ip - op);
        }

        switch(blockProperties.blockType)
        {
        case bt_compressed:
            assert(dctx->isFrameDecompression == 1);
            decodedSize = ZSTDH_decompressBlock_internal(dctx, op, (size_t)(oBlockEnd-op), ip, cBlockSize, not_streaming);
            break;
        case bt_raw :
            /* Use oend instead of oBlockEnd because this function is safe to overlap. It uses memmove. */
            decodedSize = ZSTDH_copyRawBlock(op, (size_t)(oend-op), ip, cBlockSize);
            break;
        case bt_rle :
            decodedSize = ZSTDH_setRleBlock(op, (size_t)(oBlockEnd-op), *ip, blockProperties.origSize);
            break;
        case bt_reserved :
        default:
            RETURN_ERROR(corruption_detected, "invalid block type");
        }
        FORWARD_IF_ERROR(decodedSize, "Block decompression failure");
        DEBUGLOG(5, "Decompressed block of dSize = %u", (unsigned)decodedSize);
        if (dctx->validateChecksum) {
            xxh64_update(&dctx->xxhState, op, decodedSize);
        }
        if (decodedSize) /* support dst = NULL,0 */ {
            op += decodedSize;
        }
        assert(ip != NULL);
        ip += cBlockSize;
        remainingSrcSize -= cBlockSize;
        if (blockProperties.lastBlock) break;
    }

    if (dctx->fParams.frameContentSize != ZSTDH_CONTENTSIZE_UNKNOWN) {
        RETURN_ERROR_IF((U64)(op-ostart) != dctx->fParams.frameContentSize,
                        corruption_detected, "");
    }
    if (dctx->fParams.checksumFlag) { /* Frame content checksum verification */
        RETURN_ERROR_IF(remainingSrcSize<4, checksum_wrong, "");
        if (!dctx->forceIgnoreChecksum) {
            U32 const checkCalc = (U32)xxh64_digest(&dctx->xxhState);
            U32 checkRead;
            checkRead = MEM_readLE32(ip);
            RETURN_ERROR_IF(checkRead != checkCalc, checksum_wrong, "");
        }
        ip += 4;
        remainingSrcSize -= 4;
    }
    ZSTDH_DCtx_trace_end(dctx, (U64)(op-ostart), (U64)(ip-istart), /* streaming */ 0);
    /* Allow caller to get size read */
    DEBUGLOG(4, "ZSTDH_decompressFrame: decompressed frame of size %i, consuming %i bytes of input", (int)(op-ostart), (int)(ip - (const BYTE*)*srcPtr));
    *srcPtr = ip;
    *srcSizePtr = remainingSrcSize;
    return (size_t)(op-ostart);
}

static
ZSTDH_ALLOW_POINTER_OVERFLOW_ATTR
size_t ZSTDH_decompressMultiFrame(ZSTDH_DCtx* dctx,
                                        void* dst, size_t dstCapacity,
                                  const void* src, size_t srcSize,
                                  const void* dict, size_t dictSize,
                                  const ZSTDH_DDict* ddict)
{
    void* const dststart = dst;
    int moreThan1Frame = 0;

    DEBUGLOG(5, "ZSTDH_decompressMultiFrame");
    assert(dict==NULL || ddict==NULL);  /* either dict or ddict set, not both */

    if (ddict) {
        dict = ZSTDH_DDict_dictContent(ddict);
        dictSize = ZSTDH_DDict_dictSize(ddict);
    }

    while (srcSize >= ZSTDH_startingInputLength(dctx->format)) {


        if (dctx->format == ZSTDH_f_zstd1 && srcSize >= 4) {
            U32 const magicNumber = MEM_readLE32(src);
            DEBUGLOG(5, "reading magic number %08X", (unsigned)magicNumber);
            if ((magicNumber & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {
                /* skippable frame detected : skip it */
                size_t const skippableSize = readSkippableFrameSize(src, srcSize);
                FORWARD_IF_ERROR(skippableSize, "invalid skippable frame");
                assert(skippableSize <= srcSize);

                src = (const BYTE *)src + skippableSize;
                srcSize -= skippableSize;
                continue; /* check next frame */
        }   }

        if (ddict) {
            /* we were called from ZSTDH_decompress_usingDDict */
            FORWARD_IF_ERROR(ZSTDH_decompressBegin_usingDDict(dctx, ddict), "");
        } else {
            /* this will initialize correctly with no dict if dict == NULL, so
             * use this in all cases but ddict */
            FORWARD_IF_ERROR(ZSTDH_decompressBegin_usingDict(dctx, dict, dictSize), "");
        }
        ZSTDH_checkContinuity(dctx, dst, dstCapacity);

        {   const size_t res = ZSTDH_decompressFrame(dctx, dst, dstCapacity,
                                                    &src, &srcSize);
            RETURN_ERROR_IF(
                (ZSTDH_getErrorCode(res) == ZSTDH_error_prefix_unknown)
             && (moreThan1Frame==1),
                srcSize_wrong,
                "At least one frame successfully completed, "
                "but following bytes are garbage: "
                "it's more likely to be a srcSize error, "
                "specifying more input bytes than size of frame(s). "
                "Note: one could be unlucky, it might be a corruption error instead, "
                "happening right at the place where we expect zstd magic bytes. "
                "But this is _much_ less likely than a srcSize field error.");
            if (ZSTDH_isError(res)) return res;
            assert(res <= dstCapacity);
            if (res != 0)
                dst = (BYTE*)dst + res;
            dstCapacity -= res;
        }
        moreThan1Frame = 1;
    }  /* while (srcSize >= ZSTDH_frameHeaderSize_prefix) */

    RETURN_ERROR_IF(srcSize, srcSize_wrong, "input not entirely consumed");

    return (size_t)((BYTE*)dst - (BYTE*)dststart);
}

size_t ZSTDH_decompress_usingDict(ZSTDH_DCtx* dctx,
                                 void* dst, size_t dstCapacity,
                           const void* src, size_t srcSize,
                           const void* dict, size_t dictSize)
{
    return ZSTDH_decompressMultiFrame(dctx, dst, dstCapacity, src, srcSize, dict, dictSize, NULL);
}


static ZSTDH_DDict const* ZSTDH_getDDict(ZSTDH_DCtx* dctx)
{
    switch (dctx->dictUses) {
    default:
        assert(0 /* Impossible */);
        ZSTDH_FALLTHROUGH;
    case ZSTDH_dont_use:
        ZSTDH_clearDict(dctx);
        return NULL;
    case ZSTDH_use_indefinitely:
        return dctx->ddict;
    case ZSTDH_use_once:
        dctx->dictUses = ZSTDH_dont_use;
        return dctx->ddict;
    }
}

size_t ZSTDH_decompressDCtx(ZSTDH_DCtx* dctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize)
{
    return ZSTDH_decompress_usingDDict(dctx, dst, dstCapacity, src, srcSize, ZSTDH_getDDict(dctx));
}


size_t ZSTDH_decompress(void* dst, size_t dstCapacity, const void* src, size_t srcSize)
{
#if defined(ZSTDH_HEAPMODE) && (ZSTDH_HEAPMODE>=1)
    size_t regenSize;
    ZSTDH_DCtx* const dctx =  ZSTDH_createDCtx_internal(ZSTDH_defaultCMem);
    RETURN_ERROR_IF(dctx==NULL, memory_allocation, "NULL pointer!");
    regenSize = ZSTDH_decompressDCtx(dctx, dst, dstCapacity, src, srcSize);
    ZSTDH_freeDCtx(dctx);
    return regenSize;
#else   /* stack mode */
    ZSTDH_DCtx dctx;
    ZSTDH_initDCtx_internal(&dctx);
    return ZSTDH_decompressDCtx(&dctx, dst, dstCapacity, src, srcSize);
#endif
}


/*-**************************************
*   Advanced Streaming Decompression API
*   Bufferless and synchronous
****************************************/
size_t ZSTDH_nextSrcSizeToDecompress(ZSTDH_DCtx* dctx) { return dctx->expected; }

/*
 * Similar to ZSTDH_nextSrcSizeToDecompress(), but when a block input can be streamed, we
 * allow taking a partial block as the input. Currently only raw uncompressed blocks can
 * be streamed.
 *
 * For blocks that can be streamed, this allows us to reduce the latency until we produce
 * output, and avoid copying the input.
 *
 * @param inputSize - The total amount of input that the caller currently has.
 */
static size_t ZSTDH_nextSrcSizeToDecompressWithInputSize(ZSTDH_DCtx* dctx, size_t inputSize) {
    if (!(dctx->stage == ZSTDds_decompressBlock || dctx->stage == ZSTDds_decompressLastBlock))
        return dctx->expected;
    if (dctx->bType != bt_raw)
        return dctx->expected;
    return BOUNDED(1, inputSize, dctx->expected);
}

ZSTDH_nextInputType_e ZSTDH_nextInputType(ZSTDH_DCtx* dctx) {
    switch(dctx->stage)
    {
    default:   /* should not happen */
        assert(0);
        ZSTDH_FALLTHROUGH;
    case ZSTDds_getFrameHeaderSize:
        ZSTDH_FALLTHROUGH;
    case ZSTDds_decodeFrameHeader:
        return ZSTDnit_frameHeader;
    case ZSTDds_decodeBlockHeader:
        return ZSTDnit_blockHeader;
    case ZSTDds_decompressBlock:
        return ZSTDnit_block;
    case ZSTDds_decompressLastBlock:
        return ZSTDnit_lastBlock;
    case ZSTDds_checkChecksum:
        return ZSTDnit_checksum;
    case ZSTDds_decodeSkippableHeader:
        ZSTDH_FALLTHROUGH;
    case ZSTDds_skipFrame:
        return ZSTDnit_skippableFrame;
    }
}

static int ZSTDH_isSkipFrame(ZSTDH_DCtx* dctx) { return dctx->stage == ZSTDds_skipFrame; }

/* ZSTDH_decompressContinue() :
 *  srcSize : must be the exact nb of bytes expected (see ZSTDH_nextSrcSizeToDecompress())
 *  @return : nb of bytes generated into `dst` (necessarily <= `dstCapacity)
 *            or an error code, which can be tested using ZSTDH_isError() */
size_t ZSTDH_decompressContinue(ZSTDH_DCtx* dctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize)
{
    DEBUGLOG(5, "ZSTDH_decompressContinue (srcSize:%u)", (unsigned)srcSize);
    /* Sanity check */
    RETURN_ERROR_IF(srcSize != ZSTDH_nextSrcSizeToDecompressWithInputSize(dctx, srcSize), srcSize_wrong, "not allowed");
    ZSTDH_checkContinuity(dctx, dst, dstCapacity);

    dctx->processedCSize += srcSize;

    switch (dctx->stage)
    {
    case ZSTDds_getFrameHeaderSize :
        assert(src != NULL);
        if (dctx->format == ZSTDH_f_zstd1) {  /* allows header */
            assert(srcSize >= ZSTDH_FRAMEIDSIZE);  /* to read skippable magic number */
            if ((MEM_readLE32(src) & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {        /* skippable frame */
                ZSTDH_memcpy(dctx->headerBuffer, src, srcSize);
                dctx->expected = ZSTDH_SKIPPABLEHEADERSIZE - srcSize;  /* remaining to load to get full skippable frame header */
                dctx->stage = ZSTDds_decodeSkippableHeader;
                return 0;
        }   }
        dctx->headerSize = ZSTDH_frameHeaderSize_internal(src, srcSize, dctx->format);
        if (ZSTDH_isError(dctx->headerSize)) return dctx->headerSize;
        ZSTDH_memcpy(dctx->headerBuffer, src, srcSize);
        dctx->expected = dctx->headerSize - srcSize;
        dctx->stage = ZSTDds_decodeFrameHeader;
        return 0;

    case ZSTDds_decodeFrameHeader:
        assert(src != NULL);
        ZSTDH_memcpy(dctx->headerBuffer + (dctx->headerSize - srcSize), src, srcSize);
        FORWARD_IF_ERROR(ZSTDH_decodeFrameHeader(dctx, dctx->headerBuffer, dctx->headerSize), "");
        dctx->expected = ZSTDH_blockHeaderSize;
        dctx->stage = ZSTDds_decodeBlockHeader;
        return 0;

    case ZSTDds_decodeBlockHeader:
        {   blockProperties_t bp;
            size_t const cBlockSize = ZSTDH_getcBlockSize(src, ZSTDH_blockHeaderSize, &bp);
            if (ZSTDH_isError(cBlockSize)) return cBlockSize;
            RETURN_ERROR_IF(cBlockSize > dctx->fParams.blockSizeMax, corruption_detected, "Block Size Exceeds Maximum");
            dctx->expected = cBlockSize;
            dctx->bType = bp.blockType;
            dctx->rleSize = bp.origSize;
            if (cBlockSize) {
                dctx->stage = bp.lastBlock ? ZSTDds_decompressLastBlock : ZSTDds_decompressBlock;
                return 0;
            }
            /* empty block */
            if (bp.lastBlock) {
                if (dctx->fParams.checksumFlag) {
                    dctx->expected = 4;
                    dctx->stage = ZSTDds_checkChecksum;
                } else {
                    dctx->expected = 0; /* end of frame */
                    dctx->stage = ZSTDds_getFrameHeaderSize;
                }
            } else {
                dctx->expected = ZSTDH_blockHeaderSize;  /* jump to next header */
                dctx->stage = ZSTDds_decodeBlockHeader;
            }
            return 0;
        }

    case ZSTDds_decompressLastBlock:
    case ZSTDds_decompressBlock:
        DEBUGLOG(5, "ZSTDH_decompressContinue: case ZSTDds_decompressBlock");
        {   size_t rSize;
            switch(dctx->bType)
            {
            case bt_compressed:
                DEBUGLOG(5, "ZSTDH_decompressContinue: case bt_compressed");
                assert(dctx->isFrameDecompression == 1);
                rSize = ZSTDH_decompressBlock_internal(dctx, dst, dstCapacity, src, srcSize, is_streaming);
                dctx->expected = 0;  /* Streaming not supported */
                break;
            case bt_raw :
                assert(srcSize <= dctx->expected);
                rSize = ZSTDH_copyRawBlock(dst, dstCapacity, src, srcSize);
                FORWARD_IF_ERROR(rSize, "ZSTDH_copyRawBlock failed");
                assert(rSize == srcSize);
                dctx->expected -= rSize;
                break;
            case bt_rle :
                rSize = ZSTDH_setRleBlock(dst, dstCapacity, *(const BYTE*)src, dctx->rleSize);
                dctx->expected = 0;  /* Streaming not supported */
                break;
            case bt_reserved :   /* should never happen */
            default:
                RETURN_ERROR(corruption_detected, "invalid block type");
            }
            FORWARD_IF_ERROR(rSize, "");
            RETURN_ERROR_IF(rSize > dctx->fParams.blockSizeMax, corruption_detected, "Decompressed Block Size Exceeds Maximum");
            DEBUGLOG(5, "ZSTDH_decompressContinue: decoded size from block : %u", (unsigned)rSize);
            dctx->decodedSize += rSize;
            if (dctx->validateChecksum) xxh64_update(&dctx->xxhState, dst, rSize);
            dctx->previousDstEnd = (char*)dst + rSize;

            /* Stay on the same stage until we are finished streaming the block. */
            if (dctx->expected > 0) {
                return rSize;
            }

            if (dctx->stage == ZSTDds_decompressLastBlock) {   /* end of frame */
                DEBUGLOG(4, "ZSTDH_decompressContinue: decoded size from frame : %u", (unsigned)dctx->decodedSize);
                RETURN_ERROR_IF(
                    dctx->fParams.frameContentSize != ZSTDH_CONTENTSIZE_UNKNOWN
                 && dctx->decodedSize != dctx->fParams.frameContentSize,
                    corruption_detected, "");
                if (dctx->fParams.checksumFlag) {  /* another round for frame checksum */
                    dctx->expected = 4;
                    dctx->stage = ZSTDds_checkChecksum;
                } else {
                    ZSTDH_DCtx_trace_end(dctx, dctx->decodedSize, dctx->processedCSize, /* streaming */ 1);
                    dctx->expected = 0;   /* ends here */
                    dctx->stage = ZSTDds_getFrameHeaderSize;
                }
            } else {
                dctx->stage = ZSTDds_decodeBlockHeader;
                dctx->expected = ZSTDH_blockHeaderSize;
            }
            return rSize;
        }

    case ZSTDds_checkChecksum:
        assert(srcSize == 4);  /* guaranteed by dctx->expected */
        {
            if (dctx->validateChecksum) {
                U32 const h32 = (U32)xxh64_digest(&dctx->xxhState);
                U32 const check32 = MEM_readLE32(src);
                DEBUGLOG(4, "ZSTDH_decompressContinue: checksum : calculated %08X :: %08X read", (unsigned)h32, (unsigned)check32);
                RETURN_ERROR_IF(check32 != h32, checksum_wrong, "");
            }
            ZSTDH_DCtx_trace_end(dctx, dctx->decodedSize, dctx->processedCSize, /* streaming */ 1);
            dctx->expected = 0;
            dctx->stage = ZSTDds_getFrameHeaderSize;
            return 0;
        }

    case ZSTDds_decodeSkippableHeader:
        assert(src != NULL);
        assert(srcSize <= ZSTDH_SKIPPABLEHEADERSIZE);
        assert(dctx->format != ZSTDH_f_zstd1_magicless);
        ZSTDH_memcpy(dctx->headerBuffer + (ZSTDH_SKIPPABLEHEADERSIZE - srcSize), src, srcSize);   /* complete skippable header */
        dctx->expected = MEM_readLE32(dctx->headerBuffer + ZSTDH_FRAMEIDSIZE);   /* note : dctx->expected can grow seriously large, beyond local buffer size */
        dctx->stage = ZSTDds_skipFrame;
        return 0;

    case ZSTDds_skipFrame:
        dctx->expected = 0;
        dctx->stage = ZSTDds_getFrameHeaderSize;
        return 0;

    default:
        assert(0);   /* impossible */
        RETURN_ERROR(GENERIC, "impossible to reach");   /* some compilers require default to do something */
    }
}


static size_t ZSTDH_refDictContent(ZSTDH_DCtx* dctx, const void* dict, size_t dictSize)
{
    dctx->dictEnd = dctx->previousDstEnd;
    dctx->virtualStart = (const char*)dict - ((const char*)(dctx->previousDstEnd) - (const char*)(dctx->prefixStart));
    dctx->prefixStart = dict;
    dctx->previousDstEnd = (const char*)dict + dictSize;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    dctx->dictContentBeginForFuzzing = dctx->prefixStart;
    dctx->dictContentEndForFuzzing = dctx->previousDstEnd;
#endif
    return 0;
}

/*! ZSTDH_loadDEntropy() :
 *  dict : must point at beginning of a valid zstd dictionary.
 * @return : size of entropy tables read */
size_t
ZSTDH_loadDEntropy(ZSTDH_entropyDTables_t* entropy,
                  const void* const dict, size_t const dictSize)
{
    const BYTE* dictPtr = (const BYTE*)dict;
    const BYTE* const dictEnd = dictPtr + dictSize;

    RETURN_ERROR_IF(dictSize <= 8, dictionary_corrupted, "dict is too small");
    assert(MEM_readLE32(dict) == ZSTDH_MAGIC_DICTIONARY);   /* dict must be valid */
    dictPtr += 8;   /* skip header = magic + dictID */

    ZSTDH_STATIC_ASSERT(offsetof(ZSTDH_entropyDTables_t, OFTable) == offsetof(ZSTDH_entropyDTables_t, LLTable) + sizeof(entropy->LLTable));
    ZSTDH_STATIC_ASSERT(offsetof(ZSTDH_entropyDTables_t, MLTable) == offsetof(ZSTDH_entropyDTables_t, OFTable) + sizeof(entropy->OFTable));
    ZSTDH_STATIC_ASSERT(sizeof(entropy->LLTable) + sizeof(entropy->OFTable) + sizeof(entropy->MLTable) >= HUFH_DECOMPRESS_WORKSPACE_SIZE);
    {   void* const workspace = &entropy->LLTable;   /* use fse tables as temporary workspace; implies fse tables are grouped together */
        size_t const workspaceSize = sizeof(entropy->LLTable) + sizeof(entropy->OFTable) + sizeof(entropy->MLTable);
#ifdef HUFH_FORCE_DECOMPRESS_X1
        /* in minimal huffman, we always use X1 variants */
        size_t const hSize = HUFH_readDTableX1_wksp(entropy->hufTable,
                                                dictPtr, dictEnd - dictPtr,
                                                workspace, workspaceSize, /* flags */ 0);
#else
        size_t const hSize = HUFH_readDTableX2_wksp(entropy->hufTable,
                                                dictPtr, (size_t)(dictEnd - dictPtr),
                                                workspace, workspaceSize, /* flags */ 0);
#endif
        RETURN_ERROR_IF(HUFH_isError(hSize), dictionary_corrupted, "");
        dictPtr += hSize;
    }

    {   short offcodeNCount[MaxOff+1];
        unsigned offcodeMaxValue = MaxOff, offcodeLog;
        size_t const offcodeHeaderSize = FSEH_readNCount(offcodeNCount, &offcodeMaxValue, &offcodeLog, dictPtr, (size_t)(dictEnd-dictPtr));
        RETURN_ERROR_IF(FSEH_isError(offcodeHeaderSize), dictionary_corrupted, "");
        RETURN_ERROR_IF(offcodeMaxValue > MaxOff, dictionary_corrupted, "");
        RETURN_ERROR_IF(offcodeLog > OffFSELog, dictionary_corrupted, "");
        ZSTDH_buildFSETable( entropy->OFTable,
                            offcodeNCount, offcodeMaxValue,
                            OF_base, OF_bits,
                            offcodeLog,
                            entropy->workspace, sizeof(entropy->workspace),
                            /* bmi2 */0);
        dictPtr += offcodeHeaderSize;
    }

    {   short matchlengthNCount[MaxML+1];
        unsigned matchlengthMaxValue = MaxML, matchlengthLog;
        size_t const matchlengthHeaderSize = FSEH_readNCount(matchlengthNCount, &matchlengthMaxValue, &matchlengthLog, dictPtr, (size_t)(dictEnd-dictPtr));
        RETURN_ERROR_IF(FSEH_isError(matchlengthHeaderSize), dictionary_corrupted, "");
        RETURN_ERROR_IF(matchlengthMaxValue > MaxML, dictionary_corrupted, "");
        RETURN_ERROR_IF(matchlengthLog > MLFSELog, dictionary_corrupted, "");
        ZSTDH_buildFSETable( entropy->MLTable,
                            matchlengthNCount, matchlengthMaxValue,
                            ML_base, ML_bits,
                            matchlengthLog,
                            entropy->workspace, sizeof(entropy->workspace),
                            /* bmi2 */ 0);
        dictPtr += matchlengthHeaderSize;
    }

    {   short litlengthNCount[MaxLL+1];
        unsigned litlengthMaxValue = MaxLL, litlengthLog;
        size_t const litlengthHeaderSize = FSEH_readNCount(litlengthNCount, &litlengthMaxValue, &litlengthLog, dictPtr, (size_t)(dictEnd-dictPtr));
        RETURN_ERROR_IF(FSEH_isError(litlengthHeaderSize), dictionary_corrupted, "");
        RETURN_ERROR_IF(litlengthMaxValue > MaxLL, dictionary_corrupted, "");
        RETURN_ERROR_IF(litlengthLog > LLFSELog, dictionary_corrupted, "");
        ZSTDH_buildFSETable( entropy->LLTable,
                            litlengthNCount, litlengthMaxValue,
                            LL_base, LL_bits,
                            litlengthLog,
                            entropy->workspace, sizeof(entropy->workspace),
                            /* bmi2 */ 0);
        dictPtr += litlengthHeaderSize;
    }

    RETURN_ERROR_IF(dictPtr+12 > dictEnd, dictionary_corrupted, "");
    {   int i;
        size_t const dictContentSize = (size_t)(dictEnd - (dictPtr+12));
        for (i=0; i<3; i++) {
            U32 const rep = MEM_readLE32(dictPtr); dictPtr += 4;
            RETURN_ERROR_IF(rep==0 || rep > dictContentSize,
                            dictionary_corrupted, "");
            entropy->rep[i] = rep;
    }   }

    return (size_t)(dictPtr - (const BYTE*)dict);
}

static size_t ZSTDH_decompress_insertDictionary(ZSTDH_DCtx* dctx, const void* dict, size_t dictSize)
{
    if (dictSize < 8) return ZSTDH_refDictContent(dctx, dict, dictSize);
    {   U32 const magic = MEM_readLE32(dict);
        if (magic != ZSTDH_MAGIC_DICTIONARY) {
            return ZSTDH_refDictContent(dctx, dict, dictSize);   /* pure content mode */
    }   }
    dctx->dictID = MEM_readLE32((const char*)dict + ZSTDH_FRAMEIDSIZE);

    /* load entropy tables */
    {   size_t const eSize = ZSTDH_loadDEntropy(&dctx->entropy, dict, dictSize);
        RETURN_ERROR_IF(ZSTDH_isError(eSize), dictionary_corrupted, "");
        dict = (const char*)dict + eSize;
        dictSize -= eSize;
    }
    dctx->litEntropy = dctx->fseEntropy = 1;

    /* reference dictionary content */
    return ZSTDH_refDictContent(dctx, dict, dictSize);
}

size_t ZSTDH_decompressBegin(ZSTDH_DCtx* dctx)
{
    assert(dctx != NULL);
    dctx->expected = ZSTDH_startingInputLength(dctx->format);  /* dctx->format must be properly set */
    dctx->stage = ZSTDds_getFrameHeaderSize;
    dctx->processedCSize = 0;
    dctx->decodedSize = 0;
    dctx->previousDstEnd = NULL;
    dctx->prefixStart = NULL;
    dctx->virtualStart = NULL;
    dctx->dictEnd = NULL;
    dctx->entropy.hufTable[0] = (HUFH_DTable)((ZSTDH_HUFFDTABLE_CAPACITY_LOG)*0x1000001);  /* cover both little and big endian */
    dctx->litEntropy = dctx->fseEntropy = 0;
    dctx->dictID = 0;
    dctx->bType = bt_reserved;
    dctx->isFrameDecompression = 1;
    ZSTDH_STATIC_ASSERT(sizeof(dctx->entropy.rep) == sizeof(repStartValue));
    ZSTDH_memcpy(dctx->entropy.rep, repStartValue, sizeof(repStartValue));  /* initial repcodes */
    dctx->LLTptr = dctx->entropy.LLTable;
    dctx->MLTptr = dctx->entropy.MLTable;
    dctx->OFTptr = dctx->entropy.OFTable;
    dctx->HUFptr = dctx->entropy.hufTable;
    return 0;
}

size_t ZSTDH_decompressBegin_usingDict(ZSTDH_DCtx* dctx, const void* dict, size_t dictSize)
{
    FORWARD_IF_ERROR( ZSTDH_decompressBegin(dctx) , "");
    if (dict && dictSize)
        RETURN_ERROR_IF(
            ZSTDH_isError(ZSTDH_decompress_insertDictionary(dctx, dict, dictSize)),
            dictionary_corrupted, "");
    return 0;
}


/* ======   ZSTDH_DDict   ====== */

size_t ZSTDH_decompressBegin_usingDDict(ZSTDH_DCtx* dctx, const ZSTDH_DDict* ddict)
{
    DEBUGLOG(4, "ZSTDH_decompressBegin_usingDDict");
    assert(dctx != NULL);
    if (ddict) {
        const char* const dictStart = (const char*)ZSTDH_DDict_dictContent(ddict);
        size_t const dictSize = ZSTDH_DDict_dictSize(ddict);
        const void* const dictEnd = dictStart + dictSize;
        dctx->ddictIsCold = (dctx->dictEnd != dictEnd);
        DEBUGLOG(4, "DDict is %s",
                    dctx->ddictIsCold ? "~cold~" : "hot!");
    }
    FORWARD_IF_ERROR( ZSTDH_decompressBegin(dctx) , "");
    if (ddict) {   /* NULL ddict is equivalent to no dictionary */
        ZSTDH_copyDDictParameters(dctx, ddict);
    }
    return 0;
}

/*! ZSTDH_getDictID_fromDict() :
 *  Provides the dictID stored within dictionary.
 *  if @return == 0, the dictionary is not conformant with Zstandard specification.
 *  It can still be loaded, but as a content-only dictionary. */
unsigned ZSTDH_getDictID_fromDict(const void* dict, size_t dictSize)
{
    if (dictSize < 8) return 0;
    if (MEM_readLE32(dict) != ZSTDH_MAGIC_DICTIONARY) return 0;
    return MEM_readLE32((const char*)dict + ZSTDH_FRAMEIDSIZE);
}

/*! ZSTDH_getDictID_fromFrame() :
 *  Provides the dictID required to decompress frame stored within `src`.
 *  If @return == 0, the dictID could not be decoded.
 *  This could for one of the following reasons :
 *  - The frame does not require a dictionary (most common case).
 *  - The frame was built with dictID intentionally removed.
 *    Needed dictionary is a hidden piece of information.
 *    Note : this use case also happens when using a non-conformant dictionary.
 *  - `srcSize` is too small, and as a result, frame header could not be decoded.
 *    Note : possible if `srcSize < ZSTDH_FRAMEHEADERSIZE_MAX`.
 *  - This is not a Zstandard frame.
 *  When identifying the exact failure cause, it's possible to use
 *  ZSTDH_getFrameHeader(), which will provide a more precise error code. */
unsigned ZSTDH_getDictID_fromFrame(const void* src, size_t srcSize)
{
    ZSTDH_FrameHeader zfp = { 0, 0, 0, ZSTDH_frame, 0, 0, 0, 0, 0 };
    size_t const hError = ZSTDH_getFrameHeader(&zfp, src, srcSize);
    if (ZSTDH_isError(hError)) return 0;
    return zfp.dictID;
}


/*! ZSTDH_decompress_usingDDict() :
*   Decompression using a pre-digested Dictionary
*   Use dictionary without significant overhead. */
size_t ZSTDH_decompress_usingDDict(ZSTDH_DCtx* dctx,
                                  void* dst, size_t dstCapacity,
                            const void* src, size_t srcSize,
                            const ZSTDH_DDict* ddict)
{
    /* pass content and size in case legacy frames are encountered */
    return ZSTDH_decompressMultiFrame(dctx, dst, dstCapacity, src, srcSize,
                                     NULL, 0,
                                     ddict);
}


/*=====================================
*   Streaming decompression
*====================================*/

ZSTDH_DStream* ZSTDH_createDStream(void)
{
    DEBUGLOG(3, "ZSTDH_createDStream");
    return ZSTDH_createDCtx_internal(ZSTDH_defaultCMem);
}

ZSTDH_DStream* ZSTDH_initStaticDStream(void *workspace, size_t workspaceSize)
{
    return ZSTDH_initStaticDCtx(workspace, workspaceSize);
}

ZSTDH_DStream* ZSTDH_createDStream_advanced(ZSTDH_customMem customMem)
{
    return ZSTDH_createDCtx_internal(customMem);
}

size_t ZSTDH_freeDStream(ZSTDH_DStream* zds)
{
    return ZSTDH_freeDCtx(zds);
}


/* ***  Initialization  *** */

size_t ZSTDH_DStreamInSize(void)  { return ZSTDH_BLOCKSIZE_MAX + ZSTDH_blockHeaderSize; }
size_t ZSTDH_DStreamOutSize(void) { return ZSTDH_BLOCKSIZE_MAX; }

size_t ZSTDH_DCtx_loadDictionary_advanced(ZSTDH_DCtx* dctx,
                                   const void* dict, size_t dictSize,
                                         ZSTDH_dictLoadMethod_e dictLoadMethod,
                                         ZSTDH_dictContentType_e dictContentType)
{
    RETURN_ERROR_IF(dctx->streamStage != zdss_init, stage_wrong, "");
    ZSTDH_clearDict(dctx);
    if (dict && dictSize != 0) {
        dctx->ddictLocal = ZSTDH_createDDict_advanced(dict, dictSize, dictLoadMethod, dictContentType, dctx->customMem);
        RETURN_ERROR_IF(dctx->ddictLocal == NULL, memory_allocation, "NULL pointer!");
        dctx->ddict = dctx->ddictLocal;
        dctx->dictUses = ZSTDH_use_indefinitely;
    }
    return 0;
}

size_t ZSTDH_DCtx_loadDictionary_byReference(ZSTDH_DCtx* dctx, const void* dict, size_t dictSize)
{
    return ZSTDH_DCtx_loadDictionary_advanced(dctx, dict, dictSize, ZSTDH_dlm_byRef, ZSTDH_dct_auto);
}

size_t ZSTDH_DCtx_loadDictionary(ZSTDH_DCtx* dctx, const void* dict, size_t dictSize)
{
    return ZSTDH_DCtx_loadDictionary_advanced(dctx, dict, dictSize, ZSTDH_dlm_byCopy, ZSTDH_dct_auto);
}

size_t ZSTDH_DCtx_refPrefix_advanced(ZSTDH_DCtx* dctx, const void* prefix, size_t prefixSize, ZSTDH_dictContentType_e dictContentType)
{
    FORWARD_IF_ERROR(ZSTDH_DCtx_loadDictionary_advanced(dctx, prefix, prefixSize, ZSTDH_dlm_byRef, dictContentType), "");
    dctx->dictUses = ZSTDH_use_once;
    return 0;
}

size_t ZSTDH_DCtx_refPrefix(ZSTDH_DCtx* dctx, const void* prefix, size_t prefixSize)
{
    return ZSTDH_DCtx_refPrefix_advanced(dctx, prefix, prefixSize, ZSTDH_dct_rawContent);
}


/* ZSTDH_initDStream_usingDict() :
 * return : expected size, aka ZSTDH_startingInputLength().
 * this function cannot fail */
size_t ZSTDH_initDStream_usingDict(ZSTDH_DStream* zds, const void* dict, size_t dictSize)
{
    DEBUGLOG(4, "ZSTDH_initDStream_usingDict");
    FORWARD_IF_ERROR( ZSTDH_DCtx_reset(zds, ZSTDH_reset_session_only) , "");
    FORWARD_IF_ERROR( ZSTDH_DCtx_loadDictionary(zds, dict, dictSize) , "");
    return ZSTDH_startingInputLength(zds->format);
}

/* note : this variant can't fail */
size_t ZSTDH_initDStream(ZSTDH_DStream* zds)
{
    DEBUGLOG(4, "ZSTDH_initDStream");
    FORWARD_IF_ERROR(ZSTDH_DCtx_reset(zds, ZSTDH_reset_session_only), "");
    FORWARD_IF_ERROR(ZSTDH_DCtx_refDDict(zds, NULL), "");
    return ZSTDH_startingInputLength(zds->format);
}
EXPORT_SYMBOL(ZSTDH_initDStream);

/* ZSTDH_initDStream_usingDDict() :
 * ddict will just be referenced, and must outlive decompression session
 * this function cannot fail */
size_t ZSTDH_initDStream_usingDDict(ZSTDH_DStream* dctx, const ZSTDH_DDict* ddict)
{
    DEBUGLOG(4, "ZSTDH_initDStream_usingDDict");
    FORWARD_IF_ERROR( ZSTDH_DCtx_reset(dctx, ZSTDH_reset_session_only) , "");
    FORWARD_IF_ERROR( ZSTDH_DCtx_refDDict(dctx, ddict) , "");
    return ZSTDH_startingInputLength(dctx->format);
}

/* ZSTDH_resetDStream() :
 * return : expected size, aka ZSTDH_startingInputLength().
 * this function cannot fail */
size_t ZSTDH_resetDStream(ZSTDH_DStream* dctx)
{
    DEBUGLOG(4, "ZSTDH_resetDStream");
    FORWARD_IF_ERROR(ZSTDH_DCtx_reset(dctx, ZSTDH_reset_session_only), "");
    return ZSTDH_startingInputLength(dctx->format);
}


size_t ZSTDH_DCtx_refDDict(ZSTDH_DCtx* dctx, const ZSTDH_DDict* ddict)
{
    RETURN_ERROR_IF(dctx->streamStage != zdss_init, stage_wrong, "");
    ZSTDH_clearDict(dctx);
    if (ddict) {
        dctx->ddict = ddict;
        dctx->dictUses = ZSTDH_use_indefinitely;
        if (dctx->refMultipleDDicts == ZSTDH_rmd_refMultipleDDicts) {
            if (dctx->ddictSet == NULL) {
                dctx->ddictSet = ZSTDH_createDDictHashSet(dctx->customMem);
                if (!dctx->ddictSet) {
                    RETURN_ERROR(memory_allocation, "Failed to allocate memory for hash set!");
                }
            }
            assert(!dctx->staticSize);  /* Impossible: ddictSet cannot have been allocated if static dctx */
            FORWARD_IF_ERROR(ZSTDH_DDictHashSet_addDDict(dctx->ddictSet, ddict, dctx->customMem), "");
        }
    }
    return 0;
}

/* ZSTDH_DCtx_setMaxWindowSize() :
 * note : no direct equivalence in ZSTDH_DCtx_setParameter,
 * since this version sets windowSize, and the other sets windowLog */
size_t ZSTDH_DCtx_setMaxWindowSize(ZSTDH_DCtx* dctx, size_t maxWindowSize)
{
    ZSTDH_bounds const bounds = ZSTDH_dParam_getBounds(ZSTDH_d_windowLogMax);
    size_t const min = (size_t)1 << bounds.lowerBound;
    size_t const max = (size_t)1 << bounds.upperBound;
    RETURN_ERROR_IF(dctx->streamStage != zdss_init, stage_wrong, "");
    RETURN_ERROR_IF(maxWindowSize < min, parameter_outOfBound, "");
    RETURN_ERROR_IF(maxWindowSize > max, parameter_outOfBound, "");
    dctx->maxWindowSize = maxWindowSize;
    return 0;
}

size_t ZSTDH_DCtx_setFormat(ZSTDH_DCtx* dctx, ZSTDH_format_e format)
{
    return ZSTDH_DCtx_setParameter(dctx, ZSTDH_d_format, (int)format);
}

ZSTDH_bounds ZSTDH_dParam_getBounds(ZSTDH_dParameter dParam)
{
    ZSTDH_bounds bounds = { 0, 0, 0 };
    switch(dParam) {
        case ZSTDH_d_windowLogMax:
            bounds.lowerBound = ZSTDH_WINDOWLOG_ABSOLUTEMIN;
            bounds.upperBound = ZSTDH_WINDOWLOG_MAX;
            return bounds;
        case ZSTDH_d_format:
            bounds.lowerBound = (int)ZSTDH_f_zstd1;
            bounds.upperBound = (int)ZSTDH_f_zstd1_magicless;
            ZSTDH_STATIC_ASSERT(ZSTDH_f_zstd1 < ZSTDH_f_zstd1_magicless);
            return bounds;
        case ZSTDH_d_stableOutBuffer:
            bounds.lowerBound = (int)ZSTDH_bm_buffered;
            bounds.upperBound = (int)ZSTDH_bm_stable;
            return bounds;
        case ZSTDH_d_forceIgnoreChecksum:
            bounds.lowerBound = (int)ZSTDH_d_validateChecksum;
            bounds.upperBound = (int)ZSTDH_d_ignoreChecksum;
            return bounds;
        case ZSTDH_d_refMultipleDDicts:
            bounds.lowerBound = (int)ZSTDH_rmd_refSingleDDict;
            bounds.upperBound = (int)ZSTDH_rmd_refMultipleDDicts;
            return bounds;
        case ZSTDH_d_disableHuffmanAssembly:
            bounds.lowerBound = 0;
            bounds.upperBound = 1;
            return bounds;
        case ZSTDH_d_maxBlockSize:
            bounds.lowerBound = ZSTDH_BLOCKSIZE_MAX_MIN;
            bounds.upperBound = ZSTDH_BLOCKSIZE_MAX;
            return bounds;

        default:;
    }
    bounds.error = ERROR(parameter_unsupported);
    return bounds;
}

/* ZSTDH_dParam_withinBounds:
 * @return 1 if value is within dParam bounds,
 * 0 otherwise */
static int ZSTDH_dParam_withinBounds(ZSTDH_dParameter dParam, int value)
{
    ZSTDH_bounds const bounds = ZSTDH_dParam_getBounds(dParam);
    if (ZSTDH_isError(bounds.error)) return 0;
    if (value < bounds.lowerBound) return 0;
    if (value > bounds.upperBound) return 0;
    return 1;
}

#define CHECK_DBOUNDS(p,v) {                \
    RETURN_ERROR_IF(!ZSTDH_dParam_withinBounds(p, v), parameter_outOfBound, ""); \
}

size_t ZSTDH_DCtx_getParameter(ZSTDH_DCtx* dctx, ZSTDH_dParameter param, int* value)
{
    switch (param) {
        case ZSTDH_d_windowLogMax:
            *value = (int)ZSTDH_highbit32((U32)dctx->maxWindowSize);
            return 0;
        case ZSTDH_d_format:
            *value = (int)dctx->format;
            return 0;
        case ZSTDH_d_stableOutBuffer:
            *value = (int)dctx->outBufferMode;
            return 0;
        case ZSTDH_d_forceIgnoreChecksum:
            *value = (int)dctx->forceIgnoreChecksum;
            return 0;
        case ZSTDH_d_refMultipleDDicts:
            *value = (int)dctx->refMultipleDDicts;
            return 0;
        case ZSTDH_d_disableHuffmanAssembly:
            *value = (int)dctx->disableHufAsm;
            return 0;
        case ZSTDH_d_maxBlockSize:
            *value = dctx->maxBlockSizeParam;
            return 0;
        default:;
    }
    RETURN_ERROR(parameter_unsupported, "");
}

size_t ZSTDH_DCtx_setParameter(ZSTDH_DCtx* dctx, ZSTDH_dParameter dParam, int value)
{
    RETURN_ERROR_IF(dctx->streamStage != zdss_init, stage_wrong, "");
    switch(dParam) {
        case ZSTDH_d_windowLogMax:
            if (value == 0) value = ZSTDH_WINDOWLOG_LIMIT_DEFAULT;
            CHECK_DBOUNDS(ZSTDH_d_windowLogMax, value);
            dctx->maxWindowSize = ((size_t)1) << value;
            return 0;
        case ZSTDH_d_format:
            CHECK_DBOUNDS(ZSTDH_d_format, value);
            dctx->format = (ZSTDH_format_e)value;
            return 0;
        case ZSTDH_d_stableOutBuffer:
            CHECK_DBOUNDS(ZSTDH_d_stableOutBuffer, value);
            dctx->outBufferMode = (ZSTDH_bufferMode_e)value;
            return 0;
        case ZSTDH_d_forceIgnoreChecksum:
            CHECK_DBOUNDS(ZSTDH_d_forceIgnoreChecksum, value);
            dctx->forceIgnoreChecksum = (ZSTDH_forceIgnoreChecksum_e)value;
            return 0;
        case ZSTDH_d_refMultipleDDicts:
            CHECK_DBOUNDS(ZSTDH_d_refMultipleDDicts, value);
            if (dctx->staticSize != 0) {
                RETURN_ERROR(parameter_unsupported, "Static dctx does not support multiple DDicts!");
            }
            dctx->refMultipleDDicts = (ZSTDH_refMultipleDDicts_e)value;
            return 0;
        case ZSTDH_d_disableHuffmanAssembly:
            CHECK_DBOUNDS(ZSTDH_d_disableHuffmanAssembly, value);
            dctx->disableHufAsm = value != 0;
            return 0;
        case ZSTDH_d_maxBlockSize:
            if (value != 0) CHECK_DBOUNDS(ZSTDH_d_maxBlockSize, value);
            dctx->maxBlockSizeParam = value;
            return 0;
        default:;
    }
    RETURN_ERROR(parameter_unsupported, "");
}

size_t ZSTDH_DCtx_reset(ZSTDH_DCtx* dctx, ZSTDH_ResetDirective reset)
{
    if ( (reset == ZSTDH_reset_session_only)
      || (reset == ZSTDH_reset_session_and_parameters) ) {
        dctx->streamStage = zdss_init;
        dctx->noForwardProgress = 0;
        dctx->isFrameDecompression = 1;
    }
    if ( (reset == ZSTDH_reset_parameters)
      || (reset == ZSTDH_reset_session_and_parameters) ) {
        RETURN_ERROR_IF(dctx->streamStage != zdss_init, stage_wrong, "");
        ZSTDH_clearDict(dctx);
        ZSTDH_DCtx_resetParameters(dctx);
    }
    return 0;
}


size_t ZSTDH_sizeof_DStream(const ZSTDH_DStream* dctx)
{
    return ZSTDH_sizeof_DCtx(dctx);
}

static size_t ZSTDH_decodingBufferSize_internal(unsigned long long windowSize, unsigned long long frameContentSize, size_t blockSizeMax)
{
    size_t const blockSize = MIN((size_t)MIN(windowSize, ZSTDH_BLOCKSIZE_MAX), blockSizeMax);
    /* We need blockSize + WILDCOPY_OVERLENGTH worth of buffer so that if a block
     * ends at windowSize + WILDCOPY_OVERLENGTH + 1 bytes, we can start writing
     * the block at the beginning of the output buffer, and maintain a full window.
     *
     * We need another blockSize worth of buffer so that we can store split
     * literals at the end of the block without overwriting the extDict window.
     */
    unsigned long long const neededRBSize = windowSize + (blockSize * 2) + (WILDCOPY_OVERLENGTH * 2);
    unsigned long long const neededSize = MIN(frameContentSize, neededRBSize);
    size_t const minRBSize = (size_t) neededSize;
    RETURN_ERROR_IF((unsigned long long)minRBSize != neededSize,
                    frameParameter_windowTooLarge, "");
    return minRBSize;
}

size_t ZSTDH_decodingBufferSize_min(unsigned long long windowSize, unsigned long long frameContentSize)
{
    return ZSTDH_decodingBufferSize_internal(windowSize, frameContentSize, ZSTDH_BLOCKSIZE_MAX);
}

size_t ZSTDH_estimateDStreamSize(size_t windowSize)
{
    size_t const blockSize = MIN(windowSize, ZSTDH_BLOCKSIZE_MAX);
    size_t const inBuffSize = blockSize;  /* no block can be larger */
    size_t const outBuffSize = ZSTDH_decodingBufferSize_min(windowSize, ZSTDH_CONTENTSIZE_UNKNOWN);
    return ZSTDH_estimateDCtxSize() + inBuffSize + outBuffSize;
}

size_t ZSTDH_estimateDStreamSize_fromFrame(const void* src, size_t srcSize)
{
    U32 const windowSizeMax = 1U << ZSTDH_WINDOWLOG_MAX;   /* note : should be user-selectable, but requires an additional parameter (or a dctx) */
    ZSTDH_FrameHeader zfh;
    size_t const err = ZSTDH_getFrameHeader(&zfh, src, srcSize);
    if (ZSTDH_isError(err)) return err;
    RETURN_ERROR_IF(err>0, srcSize_wrong, "");
    RETURN_ERROR_IF(zfh.windowSize > windowSizeMax,
                    frameParameter_windowTooLarge, "");
    return ZSTDH_estimateDStreamSize((size_t)zfh.windowSize);
}


/* *****   Decompression   ***** */

static int ZSTDH_DCtx_isOverflow(ZSTDH_DStream* zds, size_t const neededInBuffSize, size_t const neededOutBuffSize)
{
    return (zds->inBuffSize + zds->outBuffSize) >= (neededInBuffSize + neededOutBuffSize) * ZSTDH_WORKSPACETOOLARGE_FACTOR;
}

static void ZSTDH_DCtx_updateOversizedDuration(ZSTDH_DStream* zds, size_t const neededInBuffSize, size_t const neededOutBuffSize)
{
    if (ZSTDH_DCtx_isOverflow(zds, neededInBuffSize, neededOutBuffSize))
        zds->oversizedDuration++;
    else
        zds->oversizedDuration = 0;
}

static int ZSTDH_DCtx_isOversizedTooLong(ZSTDH_DStream* zds)
{
    return zds->oversizedDuration >= ZSTDH_WORKSPACETOOLARGE_MAXDURATION;
}

/* Checks that the output buffer hasn't changed if ZSTDH_obm_stable is used. */
static size_t ZSTDH_checkOutBuffer(ZSTDH_DStream const* zds, ZSTDH_outBuffer const* output)
{
    ZSTDH_outBuffer const expect = zds->expectedOutBuffer;
    /* No requirement when ZSTDH_obm_stable is not enabled. */
    if (zds->outBufferMode != ZSTDH_bm_stable)
        return 0;
    /* Any buffer is allowed in zdss_init, this must be the same for every other call until
     * the context is reset.
     */
    if (zds->streamStage == zdss_init)
        return 0;
    /* The buffer must match our expectation exactly. */
    if (expect.dst == output->dst && expect.pos == output->pos && expect.size == output->size)
        return 0;
    RETURN_ERROR(dstBuffer_wrong, "ZSTDH_d_stableOutBuffer enabled but output differs!");
}

/* Calls ZSTDH_decompressContinue() with the right parameters for ZSTDH_decompressStream()
 * and updates the stage and the output buffer state. This call is extracted so it can be
 * used both when reading directly from the ZSTDH_inBuffer, and in buffered input mode.
 * NOTE: You must break after calling this function since the streamStage is modified.
 */
static size_t ZSTDH_decompressContinueStream(
            ZSTDH_DStream* zds, char** op, char* oend,
            void const* src, size_t srcSize) {
    int const isSkipFrame = ZSTDH_isSkipFrame(zds);
    if (zds->outBufferMode == ZSTDH_bm_buffered) {
        size_t const dstSize = isSkipFrame ? 0 : zds->outBuffSize - zds->outStart;
        size_t const decodedSize = ZSTDH_decompressContinue(zds,
                zds->outBuff + zds->outStart, dstSize, src, srcSize);
        FORWARD_IF_ERROR(decodedSize, "");
        if (!decodedSize && !isSkipFrame) {
            zds->streamStage = zdss_read;
        } else {
            zds->outEnd = zds->outStart + decodedSize;
            zds->streamStage = zdss_flush;
        }
    } else {
        /* Write directly into the output buffer */
        size_t const dstSize = isSkipFrame ? 0 : (size_t)(oend - *op);
        size_t const decodedSize = ZSTDH_decompressContinue(zds, *op, dstSize, src, srcSize);
        FORWARD_IF_ERROR(decodedSize, "");
        *op += decodedSize;
        /* Flushing is not needed. */
        zds->streamStage = zdss_read;
        assert(*op <= oend);
        assert(zds->outBufferMode == ZSTDH_bm_stable);
    }
    return 0;
}

size_t ZSTDH_decompressStream(ZSTDH_DStream* zds, ZSTDH_outBuffer* output, ZSTDH_inBuffer* input)
{
    const char* const src = (const char*)input->src;
    const char* const istart = input->pos != 0 ? src + input->pos : src;
    const char* const iend = input->size != 0 ? src + input->size : src;
    const char* ip = istart;
    char* const dst = (char*)output->dst;
    char* const ostart = output->pos != 0 ? dst + output->pos : dst;
    char* const oend = output->size != 0 ? dst + output->size : dst;
    char* op = ostart;
    U32 someMoreWork = 1;

    DEBUGLOG(5, "ZSTDH_decompressStream");
    assert(zds != NULL);
    RETURN_ERROR_IF(
        input->pos > input->size,
        srcSize_wrong,
        "forbidden. in: pos: %u   vs size: %u",
        (U32)input->pos, (U32)input->size);
    RETURN_ERROR_IF(
        output->pos > output->size,
        dstSize_tooSmall,
        "forbidden. out: pos: %u   vs size: %u",
        (U32)output->pos, (U32)output->size);
    DEBUGLOG(5, "input size : %u", (U32)(input->size - input->pos));
    FORWARD_IF_ERROR(ZSTDH_checkOutBuffer(zds, output), "");

    while (someMoreWork) {
        switch(zds->streamStage)
        {
        case zdss_init :
            DEBUGLOG(5, "stage zdss_init => transparent reset ");
            zds->streamStage = zdss_loadHeader;
            zds->lhSize = zds->inPos = zds->outStart = zds->outEnd = 0;
            zds->hostageByte = 0;
            zds->expectedOutBuffer = *output;
            ZSTDH_FALLTHROUGH;

        case zdss_loadHeader :
            DEBUGLOG(5, "stage zdss_loadHeader (srcSize : %u)", (U32)(iend - ip));
            {   size_t const hSize = ZSTDH_getFrameHeader_advanced(&zds->fParams, zds->headerBuffer, zds->lhSize, zds->format);
                if (zds->refMultipleDDicts && zds->ddictSet) {
                    ZSTDH_DCtx_selectFrameDDict(zds);
                }
                if (ZSTDH_isError(hSize)) {
                    return hSize;   /* error */
                }
                if (hSize != 0) {   /* need more input */
                    size_t const toLoad = hSize - zds->lhSize;   /* if hSize!=0, hSize > zds->lhSize */
                    size_t const remainingInput = (size_t)(iend-ip);
                    assert(iend >= ip);
                    if (toLoad > remainingInput) {   /* not enough input to load full header */
                        if (remainingInput > 0) {
                            ZSTDH_memcpy(zds->headerBuffer + zds->lhSize, ip, remainingInput);
                            zds->lhSize += remainingInput;
                        }
                        input->pos = input->size;
                        /* check first few bytes */
                        FORWARD_IF_ERROR(
                            ZSTDH_getFrameHeader_advanced(&zds->fParams, zds->headerBuffer, zds->lhSize, zds->format),
                            "First few bytes detected incorrect" );
                        /* return hint input size */
                        return (MAX((size_t)ZSTDH_FRAMEHEADERSIZE_MIN(zds->format), hSize) - zds->lhSize) + ZSTDH_blockHeaderSize;   /* remaining header bytes + next block header */
                    }
                    assert(ip != NULL);
                    ZSTDH_memcpy(zds->headerBuffer + zds->lhSize, ip, toLoad); zds->lhSize = hSize; ip += toLoad;
                    break;
            }   }

            /* check for single-pass mode opportunity */
            if (zds->fParams.frameContentSize != ZSTDH_CONTENTSIZE_UNKNOWN
                && zds->fParams.frameType != ZSTDH_skippableFrame
                && (U64)(size_t)(oend-op) >= zds->fParams.frameContentSize) {
                size_t const cSize = ZSTDH_findFrameCompressedSize_advanced(istart, (size_t)(iend-istart), zds->format);
                if (cSize <= (size_t)(iend-istart)) {
                    /* shortcut : using single-pass mode */
                    size_t const decompressedSize = ZSTDH_decompress_usingDDict(zds, op, (size_t)(oend-op), istart, cSize, ZSTDH_getDDict(zds));
                    if (ZSTDH_isError(decompressedSize)) return decompressedSize;
                    DEBUGLOG(4, "shortcut to single-pass ZSTDH_decompress_usingDDict()");
                    assert(istart != NULL);
                    ip = istart + cSize;
                    op = op ? op + decompressedSize : op; /* can occur if frameContentSize = 0 (empty frame) */
                    zds->expected = 0;
                    zds->streamStage = zdss_init;
                    someMoreWork = 0;
                    break;
            }   }

            /* Check output buffer is large enough for ZSTDH_odm_stable. */
            if (zds->outBufferMode == ZSTDH_bm_stable
                && zds->fParams.frameType != ZSTDH_skippableFrame
                && zds->fParams.frameContentSize != ZSTDH_CONTENTSIZE_UNKNOWN
                && (U64)(size_t)(oend-op) < zds->fParams.frameContentSize) {
                RETURN_ERROR(dstSize_tooSmall, "ZSTDH_obm_stable passed but ZSTDH_outBuffer is too small");
            }

            /* Consume header (see ZSTDds_decodeFrameHeader) */
            DEBUGLOG(4, "Consume header");
            FORWARD_IF_ERROR(ZSTDH_decompressBegin_usingDDict(zds, ZSTDH_getDDict(zds)), "");

            if (zds->format == ZSTDH_f_zstd1
                && (MEM_readLE32(zds->headerBuffer) & ZSTDH_MAGIC_SKIPPABLE_MASK) == ZSTDH_MAGIC_SKIPPABLE_START) {  /* skippable frame */
                zds->expected = MEM_readLE32(zds->headerBuffer + ZSTDH_FRAMEIDSIZE);
                zds->stage = ZSTDds_skipFrame;
            } else {
                FORWARD_IF_ERROR(ZSTDH_decodeFrameHeader(zds, zds->headerBuffer, zds->lhSize), "");
                zds->expected = ZSTDH_blockHeaderSize;
                zds->stage = ZSTDds_decodeBlockHeader;
            }

            /* control buffer memory usage */
            DEBUGLOG(4, "Control max memory usage (%u KB <= max %u KB)",
                        (U32)(zds->fParams.windowSize >>10),
                        (U32)(zds->maxWindowSize >> 10) );
            zds->fParams.windowSize = MAX(zds->fParams.windowSize, 1U << ZSTDH_WINDOWLOG_ABSOLUTEMIN);
            RETURN_ERROR_IF(zds->fParams.windowSize > zds->maxWindowSize,
                            frameParameter_windowTooLarge, "");
            if (zds->maxBlockSizeParam != 0)
                zds->fParams.blockSizeMax = MIN(zds->fParams.blockSizeMax, (unsigned)zds->maxBlockSizeParam);

            /* Adapt buffer sizes to frame header instructions */
            {   size_t const neededInBuffSize = MAX(zds->fParams.blockSizeMax, 4 /* frame checksum */);
                size_t const neededOutBuffSize = zds->outBufferMode == ZSTDH_bm_buffered
                        ? ZSTDH_decodingBufferSize_internal(zds->fParams.windowSize, zds->fParams.frameContentSize, zds->fParams.blockSizeMax)
                        : 0;

                ZSTDH_DCtx_updateOversizedDuration(zds, neededInBuffSize, neededOutBuffSize);

                {   int const tooSmall = (zds->inBuffSize < neededInBuffSize) || (zds->outBuffSize < neededOutBuffSize);
                    int const tooLarge = ZSTDH_DCtx_isOversizedTooLong(zds);

                    if (tooSmall || tooLarge) {
                        size_t const bufferSize = neededInBuffSize + neededOutBuffSize;
                        DEBUGLOG(4, "inBuff  : from %u to %u",
                                    (U32)zds->inBuffSize, (U32)neededInBuffSize);
                        DEBUGLOG(4, "outBuff : from %u to %u",
                                    (U32)zds->outBuffSize, (U32)neededOutBuffSize);
                        if (zds->staticSize) {  /* static DCtx */
                            DEBUGLOG(4, "staticSize : %u", (U32)zds->staticSize);
                            assert(zds->staticSize >= sizeof(ZSTDH_DCtx));  /* controlled at init */
                            RETURN_ERROR_IF(
                                bufferSize > zds->staticSize - sizeof(ZSTDH_DCtx),
                                memory_allocation, "");
                        } else {
                            ZSTDH_customFree(zds->inBuff, zds->customMem);
                            zds->inBuffSize = 0;
                            zds->outBuffSize = 0;
                            zds->inBuff = (char*)ZSTDH_customMalloc(bufferSize, zds->customMem);
                            RETURN_ERROR_IF(zds->inBuff == NULL, memory_allocation, "");
                        }
                        zds->inBuffSize = neededInBuffSize;
                        zds->outBuff = zds->inBuff + zds->inBuffSize;
                        zds->outBuffSize = neededOutBuffSize;
            }   }   }
            zds->streamStage = zdss_read;
            ZSTDH_FALLTHROUGH;

        case zdss_read:
            DEBUGLOG(5, "stage zdss_read");
            {   size_t const neededInSize = ZSTDH_nextSrcSizeToDecompressWithInputSize(zds, (size_t)(iend - ip));
                DEBUGLOG(5, "neededInSize = %u", (U32)neededInSize);
                if (neededInSize==0) {  /* end of frame */
                    zds->streamStage = zdss_init;
                    someMoreWork = 0;
                    break;
                }
                if ((size_t)(iend-ip) >= neededInSize) {  /* decode directly from src */
                    FORWARD_IF_ERROR(ZSTDH_decompressContinueStream(zds, &op, oend, ip, neededInSize), "");
                    assert(ip != NULL);
                    ip += neededInSize;
                    /* Function modifies the stage so we must break */
                    break;
            }   }
            if (ip==iend) { someMoreWork = 0; break; }   /* no more input */
            zds->streamStage = zdss_load;
            ZSTDH_FALLTHROUGH;

        case zdss_load:
            {   size_t const neededInSize = ZSTDH_nextSrcSizeToDecompress(zds);
                size_t const toLoad = neededInSize - zds->inPos;
                int const isSkipFrame = ZSTDH_isSkipFrame(zds);
                size_t loadedSize;
                /* At this point we shouldn't be decompressing a block that we can stream. */
                assert(neededInSize == ZSTDH_nextSrcSizeToDecompressWithInputSize(zds, (size_t)(iend - ip)));
                if (isSkipFrame) {
                    loadedSize = MIN(toLoad, (size_t)(iend-ip));
                } else {
                    RETURN_ERROR_IF(toLoad > zds->inBuffSize - zds->inPos,
                                    corruption_detected,
                                    "should never happen");
                    loadedSize = ZSTDH_limitCopy(zds->inBuff + zds->inPos, toLoad, ip, (size_t)(iend-ip));
                }
                if (loadedSize != 0) {
                    /* ip may be NULL */
                    ip += loadedSize;
                    zds->inPos += loadedSize;
                }
                if (loadedSize < toLoad) { someMoreWork = 0; break; }   /* not enough input, wait for more */

                /* decode loaded input */
                zds->inPos = 0;   /* input is consumed */
                FORWARD_IF_ERROR(ZSTDH_decompressContinueStream(zds, &op, oend, zds->inBuff, neededInSize), "");
                /* Function modifies the stage so we must break */
                break;
            }
        case zdss_flush:
            {
                size_t const toFlushSize = zds->outEnd - zds->outStart;
                size_t const flushedSize = ZSTDH_limitCopy(op, (size_t)(oend-op), zds->outBuff + zds->outStart, toFlushSize);

                op = op ? op + flushedSize : op;

                zds->outStart += flushedSize;
                if (flushedSize == toFlushSize) {  /* flush completed */
                    zds->streamStage = zdss_read;
                    if ( (zds->outBuffSize < zds->fParams.frameContentSize)
                        && (zds->outStart + zds->fParams.blockSizeMax > zds->outBuffSize) ) {
                        DEBUGLOG(5, "restart filling outBuff from beginning (left:%i, needed:%u)",
                                (int)(zds->outBuffSize - zds->outStart),
                                (U32)zds->fParams.blockSizeMax);
                        zds->outStart = zds->outEnd = 0;
                    }
                    break;
            }   }
            /* cannot complete flush */
            someMoreWork = 0;
            break;

        default:
            assert(0);    /* impossible */
            RETURN_ERROR(GENERIC, "impossible to reach");   /* some compilers require default to do something */
    }   }

    /* result */
    input->pos = (size_t)(ip - (const char*)(input->src));
    output->pos = (size_t)(op - (char*)(output->dst));

    /* Update the expected output buffer for ZSTDH_obm_stable. */
    zds->expectedOutBuffer = *output;

    if ((ip==istart) && (op==ostart)) {  /* no forward progress */
        zds->noForwardProgress ++;
        if (zds->noForwardProgress >= ZSTDH_NO_FORWARD_PROGRESS_MAX) {
            RETURN_ERROR_IF(op==oend, noForwardProgress_destFull, "");
            RETURN_ERROR_IF(ip==iend, noForwardProgress_inputEmpty, "");
            assert(0);
        }
    } else {
        zds->noForwardProgress = 0;
    }
    {   size_t nextSrcSizeHint = ZSTDH_nextSrcSizeToDecompress(zds);
        if (!nextSrcSizeHint) {   /* frame fully decoded */
            if (zds->outEnd == zds->outStart) {  /* output fully flushed */
                if (zds->hostageByte) {
                    if (input->pos >= input->size) {
                        /* can't release hostage (not present) */
                        zds->streamStage = zdss_read;
                        return 1;
                    }
                    input->pos++;  /* release hostage */
                }   /* zds->hostageByte */
                return 0;
            }  /* zds->outEnd == zds->outStart */
            if (!zds->hostageByte) { /* output not fully flushed; keep last byte as hostage; will be released when all output is flushed */
                input->pos--;   /* note : pos > 0, otherwise, impossible to finish reading last block */
                zds->hostageByte=1;
            }
            return 1;
        }  /* nextSrcSizeHint==0 */
        nextSrcSizeHint += ZSTDH_blockHeaderSize * (ZSTDH_nextInputType(zds) == ZSTDnit_block);   /* preload header of next block */
        assert(zds->inPos <= nextSrcSizeHint);
        nextSrcSizeHint -= zds->inPos;   /* part already loaded*/
        return nextSrcSizeHint;
    }
}
EXPORT_SYMBOL(ZSTDH_decompressStream);

size_t ZSTDH_decompressStream_simpleArgs (
                            ZSTDH_DCtx* dctx,
                            void* dst, size_t dstCapacity, size_t* dstPos,
                      const void* src, size_t srcSize, size_t* srcPos)
{
    ZSTDH_outBuffer output;
    ZSTDH_inBuffer  input;
    output.dst = dst;
    output.size = dstCapacity;
    output.pos = *dstPos;
    input.src = src;
    input.size = srcSize;
    input.pos = *srcPos;
    {   size_t const cErr = ZSTDH_decompressStream(dctx, &output, &input);
        *dstPos = output.pos;
        *srcPos = input.pos;
        return cErr;
    }
}
