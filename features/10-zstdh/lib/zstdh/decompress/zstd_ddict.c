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

/* zstdh_ddict.c :
 * concentrates all logic that needs to know the internals of ZSTDH_DDict object */

/*-*******************************************************
*  Dependencies
*********************************************************/
#include "../common/allocations.h"  /* ZSTDH_customMalloc, ZSTDH_customFree */
#include "../common/zstd_deps.h"   /* ZSTDH_memcpy, ZSTDH_memmove, ZSTDH_memset */
#include "../common/cpu.h"         /* bmi2 */
#include "../common/mem.h"         /* low level memory routines */
#define FSEH_STATIC_LINKING_ONLY
#include "../common/fse.h"
#include "../common/huf.h"
#include "zstd_decompress_internal.h"
#include "zstd_ddict.h"




/*-*******************************************************
*  Types
*********************************************************/
struct ZSTDH_DDict_s {
    void* dictBuffer;
    const void* dictContent;
    size_t dictSize;
    ZSTDH_entropyDTables_t entropy;
    U32 dictID;
    U32 entropyPresent;
    ZSTDH_customMem cMem;
};  /* typedef'd to ZSTDH_DDict within "zstd.h" */

const void* ZSTDH_DDict_dictContent(const ZSTDH_DDict* ddict)
{
    assert(ddict != NULL);
    return ddict->dictContent;
}

size_t ZSTDH_DDict_dictSize(const ZSTDH_DDict* ddict)
{
    assert(ddict != NULL);
    return ddict->dictSize;
}

void ZSTDH_copyDDictParameters(ZSTDH_DCtx* dctx, const ZSTDH_DDict* ddict)
{
    DEBUGLOG(4, "ZSTDH_copyDDictParameters");
    assert(dctx != NULL);
    assert(ddict != NULL);
    dctx->dictID = ddict->dictID;
    dctx->prefixStart = ddict->dictContent;
    dctx->virtualStart = ddict->dictContent;
    dctx->dictEnd = (const BYTE*)ddict->dictContent + ddict->dictSize;
    dctx->previousDstEnd = dctx->dictEnd;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    dctx->dictContentBeginForFuzzing = dctx->prefixStart;
    dctx->dictContentEndForFuzzing = dctx->previousDstEnd;
#endif
    if (ddict->entropyPresent) {
        dctx->litEntropy = 1;
        dctx->fseEntropy = 1;
        dctx->LLTptr = ddict->entropy.LLTable;
        dctx->MLTptr = ddict->entropy.MLTable;
        dctx->OFTptr = ddict->entropy.OFTable;
        dctx->HUFptr = ddict->entropy.hufTable;
        dctx->entropy.rep[0] = ddict->entropy.rep[0];
        dctx->entropy.rep[1] = ddict->entropy.rep[1];
        dctx->entropy.rep[2] = ddict->entropy.rep[2];
    } else {
        dctx->litEntropy = 0;
        dctx->fseEntropy = 0;
    }
}


static size_t
ZSTDH_loadEntropy_intoDDict(ZSTDH_DDict* ddict,
                           ZSTDH_dictContentType_e dictContentType)
{
    ddict->dictID = 0;
    ddict->entropyPresent = 0;
    if (dictContentType == ZSTDH_dct_rawContent) return 0;

    if (ddict->dictSize < 8) {
        if (dictContentType == ZSTDH_dct_fullDict)
            return ERROR(dictionary_corrupted);   /* only accept specified dictionaries */
        return 0;   /* pure content mode */
    }
    {   U32 const magic = MEM_readLE32(ddict->dictContent);
        if (magic != ZSTDH_MAGIC_DICTIONARY) {
            if (dictContentType == ZSTDH_dct_fullDict)
                return ERROR(dictionary_corrupted);   /* only accept specified dictionaries */
            return 0;   /* pure content mode */
        }
    }
    ddict->dictID = MEM_readLE32((const char*)ddict->dictContent + ZSTDH_FRAMEIDSIZE);

    /* load entropy tables */
    RETURN_ERROR_IF(ZSTDH_isError(ZSTDH_loadDEntropy(
            &ddict->entropy, ddict->dictContent, ddict->dictSize)),
        dictionary_corrupted, "");
    ddict->entropyPresent = 1;
    return 0;
}


static size_t ZSTDH_initDDict_internal(ZSTDH_DDict* ddict,
                                      const void* dict, size_t dictSize,
                                      ZSTDH_dictLoadMethod_e dictLoadMethod,
                                      ZSTDH_dictContentType_e dictContentType)
{
    if ((dictLoadMethod == ZSTDH_dlm_byRef) || (!dict) || (!dictSize)) {
        ddict->dictBuffer = NULL;
        ddict->dictContent = dict;
        if (!dict) dictSize = 0;
    } else {
        void* const internalBuffer = ZSTDH_customMalloc(dictSize, ddict->cMem);
        ddict->dictBuffer = internalBuffer;
        ddict->dictContent = internalBuffer;
        if (!internalBuffer) return ERROR(memory_allocation);
        ZSTDH_memcpy(internalBuffer, dict, dictSize);
    }
    ddict->dictSize = dictSize;
    ddict->entropy.hufTable[0] = (HUFH_DTable)((ZSTDH_HUFFDTABLE_CAPACITY_LOG)*0x1000001);  /* cover both little and big endian */

    /* parse dictionary content */
    FORWARD_IF_ERROR( ZSTDH_loadEntropy_intoDDict(ddict, dictContentType) , "");

    return 0;
}

ZSTDH_DDict* ZSTDH_createDDict_advanced(const void* dict, size_t dictSize,
                                      ZSTDH_dictLoadMethod_e dictLoadMethod,
                                      ZSTDH_dictContentType_e dictContentType,
                                      ZSTDH_customMem customMem)
{
    if ((!customMem.customAlloc) ^ (!customMem.customFree)) return NULL;

    {   ZSTDH_DDict* const ddict = (ZSTDH_DDict*) ZSTDH_customMalloc(sizeof(ZSTDH_DDict), customMem);
        if (ddict == NULL) return NULL;
        ddict->cMem = customMem;
        {   size_t const initResult = ZSTDH_initDDict_internal(ddict,
                                            dict, dictSize,
                                            dictLoadMethod, dictContentType);
            if (ZSTDH_isError(initResult)) {
                ZSTDH_freeDDict(ddict);
                return NULL;
        }   }
        return ddict;
    }
}

/*! ZSTDH_createDDict() :
*   Create a digested dictionary, to start decompression without startup delay.
*   `dict` content is copied inside DDict.
*   Consequently, `dict` can be released after `ZSTDH_DDict` creation */
ZSTDH_DDict* ZSTDH_createDDict(const void* dict, size_t dictSize)
{
    ZSTDH_customMem const allocator = { NULL, NULL, NULL };
    return ZSTDH_createDDict_advanced(dict, dictSize, ZSTDH_dlm_byCopy, ZSTDH_dct_auto, allocator);
}

/*! ZSTDH_createDDict_byReference() :
 *  Create a digested dictionary, to start decompression without startup delay.
 *  Dictionary content is simply referenced, it will be accessed during decompression.
 *  Warning : dictBuffer must outlive DDict (DDict must be freed before dictBuffer) */
ZSTDH_DDict* ZSTDH_createDDict_byReference(const void* dictBuffer, size_t dictSize)
{
    ZSTDH_customMem const allocator = { NULL, NULL, NULL };
    return ZSTDH_createDDict_advanced(dictBuffer, dictSize, ZSTDH_dlm_byRef, ZSTDH_dct_auto, allocator);
}


const ZSTDH_DDict* ZSTDH_initStaticDDict(
                                void* sBuffer, size_t sBufferSize,
                                const void* dict, size_t dictSize,
                                ZSTDH_dictLoadMethod_e dictLoadMethod,
                                ZSTDH_dictContentType_e dictContentType)
{
    size_t const neededSpace = sizeof(ZSTDH_DDict)
                             + (dictLoadMethod == ZSTDH_dlm_byRef ? 0 : dictSize);
    ZSTDH_DDict* const ddict = (ZSTDH_DDict*)sBuffer;
    assert(sBuffer != NULL);
    assert(dict != NULL);
    if ((size_t)sBuffer & 7) return NULL;   /* 8-aligned */
    if (sBufferSize < neededSpace) return NULL;
    if (dictLoadMethod == ZSTDH_dlm_byCopy) {
        ZSTDH_memcpy(ddict+1, dict, dictSize);  /* local copy */
        dict = ddict+1;
    }
    if (ZSTDH_isError( ZSTDH_initDDict_internal(ddict,
                                              dict, dictSize,
                                              ZSTDH_dlm_byRef, dictContentType) ))
        return NULL;
    return ddict;
}


size_t ZSTDH_freeDDict(ZSTDH_DDict* ddict)
{
    if (ddict==NULL) return 0;   /* support free on NULL */
    {   ZSTDH_customMem const cMem = ddict->cMem;
        ZSTDH_customFree(ddict->dictBuffer, cMem);
        ZSTDH_customFree(ddict, cMem);
        return 0;
    }
}

/*! ZSTDH_estimateDDictSize() :
 *  Estimate amount of memory that will be needed to create a dictionary for decompression.
 *  Note : dictionary created by reference using ZSTDH_dlm_byRef are smaller */
size_t ZSTDH_estimateDDictSize(size_t dictSize, ZSTDH_dictLoadMethod_e dictLoadMethod)
{
    return sizeof(ZSTDH_DDict) + (dictLoadMethod == ZSTDH_dlm_byRef ? 0 : dictSize);
}

size_t ZSTDH_sizeof_DDict(const ZSTDH_DDict* ddict)
{
    if (ddict==NULL) return 0;   /* support sizeof on NULL */
    return sizeof(*ddict) + (ddict->dictBuffer ? ddict->dictSize : 0) ;
}

/*! ZSTDH_getDictID_fromDDict() :
 *  Provides the dictID of the dictionary loaded into `ddict`.
 *  If @return == 0, the dictionary is not conformant to Zstandard specification, or empty.
 *  Non-conformant dictionaries can still be loaded, but as content-only dictionaries. */
unsigned ZSTDH_getDictID_fromDDict(const ZSTDH_DDict* ddict)
{
    if (ddict==NULL) return 0;
    return ddict->dictID;
}
