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

#ifndef ZSTDH_CWKSP_H
#define ZSTDH_CWKSP_H

/*-*************************************
*  Dependencies
***************************************/
#include "../common/allocations.h"  /* ZSTDH_customMalloc, ZSTDH_customFree */
#include "../common/zstd_internal.h"
#include "../common/portability_macros.h"
#include "../common/compiler.h" /* ZS2_isPower2 */

/*-*************************************
*  Constants
***************************************/

/* Since the workspace is effectively its own little malloc implementation /
 * arena, when we run under ASAN, we should similarly insert redzones between
 * each internal element of the workspace, so ASAN will catch overruns that
 * reach outside an object but that stay inside the workspace.
 *
 * This defines the size of that redzone.
 */
#ifndef ZSTDH_CWKSP_ASAN_REDZONE_SIZE
#define ZSTDH_CWKSP_ASAN_REDZONE_SIZE 128
#endif


/* Set our tables and aligneds to align by 64 bytes */
#define ZSTDH_CWKSP_ALIGNMENT_BYTES 64

/*-*************************************
*  Structures
***************************************/
typedef enum {
    ZSTDH_cwksp_alloc_objects,
    ZSTDH_cwksp_alloc_aligned_init_once,
    ZSTDH_cwksp_alloc_aligned,
    ZSTDH_cwksp_alloc_buffers
} ZSTDH_cwksp_alloc_phase_e;

/*
 * Used to describe whether the workspace is statically allocated (and will not
 * necessarily ever be freed), or if it's dynamically allocated and we can
 * expect a well-formed caller to free this.
 */
typedef enum {
    ZSTDH_cwksp_dynamic_alloc,
    ZSTDH_cwksp_static_alloc
} ZSTDH_cwksp_static_alloc_e;

/*
 * Zstd fits all its internal datastructures into a single continuous buffer,
 * so that it only needs to perform a single OS allocation (or so that a buffer
 * can be provided to it and it can perform no allocations at all). This buffer
 * is called the workspace.
 *
 * Several optimizations complicate that process of allocating memory ranges
 * from this workspace for each internal datastructure:
 *
 * - These different internal datastructures have different setup requirements:
 *
 *   - The static objects need to be cleared once and can then be trivially
 *     reused for each compression.
 *
 *   - Various buffers don't need to be initialized at all--they are always
 *     written into before they're read.
 *
 *   - The matchstate tables have a unique requirement that they don't need
 *     their memory to be totally cleared, but they do need the memory to have
 *     some bound, i.e., a guarantee that all values in the memory they've been
 *     allocated is less than some maximum value (which is the starting value
 *     for the indices that they will then use for compression). When this
 *     guarantee is provided to them, they can use the memory without any setup
 *     work. When it can't, they have to clear the area.
 *
 * - These buffers also have different alignment requirements.
 *
 * - We would like to reuse the objects in the workspace for multiple
 *   compressions without having to perform any expensive reallocation or
 *   reinitialization work.
 *
 * - We would like to be able to efficiently reuse the workspace across
 *   multiple compressions **even when the compression parameters change** and
 *   we need to resize some of the objects (where possible).
 *
 * To attempt to manage this buffer, given these constraints, the ZSTDH_cwksp
 * abstraction was created. It works as follows:
 *
 * Workspace Layout:
 *
 * [                        ... workspace ...                           ]
 * [objects][tables ->] free space [<- buffers][<- aligned][<- init once]
 *
 * The various objects that live in the workspace are divided into the
 * following categories, and are allocated separately:
 *
 * - Static objects: this is optionally the enclosing ZSTDH_CCtx or ZSTDH_CDict,
 *   so that literally everything fits in a single buffer. Note: if present,
 *   this must be the first object in the workspace, since ZSTDH_customFree{CCtx,
 *   CDict}() rely on a pointer comparison to see whether one or two frees are
 *   required.
 *
 * - Fixed size objects: these are fixed-size, fixed-count objects that are
 *   nonetheless "dynamically" allocated in the workspace so that we can
 *   control how they're initialized separately from the broader ZSTDH_CCtx.
 *   Examples:
 *   - Entropy Workspace
 *   - 2 x ZSTDH_compressedBlockState_t
 *   - CDict dictionary contents
 *
 * - Tables: these are any of several different datastructures (hash tables,
 *   chain tables, binary trees) that all respect a common format: they are
 *   uint32_t arrays, all of whose values are between 0 and (nextSrc - base).
 *   Their sizes depend on the cparams. These tables are 64-byte aligned.
 *
 * - Init once: these buffers require to be initialized at least once before
 *   use. They should be used when we want to skip memory initialization
 *   while not triggering memory checkers (like Valgrind) when reading from
 *   from this memory without writing to it first.
 *   These buffers should be used carefully as they might contain data
 *   from previous compressions.
 *   Buffers are aligned to 64 bytes.
 *
 * - Aligned: these buffers don't require any initialization before they're
 *   used. The user of the buffer should make sure they write into a buffer
 *   location before reading from it.
 *   Buffers are aligned to 64 bytes.
 *
 * - Buffers: these buffers are used for various purposes that don't require
 *   any alignment or initialization before they're used. This means they can
 *   be moved around at no cost for a new compression.
 *
 * Allocating Memory:
 *
 * The various types of objects must be allocated in order, so they can be
 * correctly packed into the workspace buffer. That order is:
 *
 * 1. Objects
 * 2. Init once / Tables
 * 3. Aligned / Tables
 * 4. Buffers / Tables
 *
 * Attempts to reserve objects of different types out of order will fail.
 */
typedef struct {
    void* workspace;
    void* workspaceEnd;

    void* objectEnd;
    void* tableEnd;
    void* tableValidEnd;
    void* allocStart;
    void* initOnceStart;

    BYTE allocFailed;
    int workspaceOversizedDuration;
    ZSTDH_cwksp_alloc_phase_e phase;
    ZSTDH_cwksp_static_alloc_e isStatic;
} ZSTDH_cwksp;

/*-*************************************
*  Functions
***************************************/

MEM_STATIC size_t ZSTDH_cwksp_available_space(ZSTDH_cwksp* ws);
MEM_STATIC void*  ZSTDH_cwksp_initialAllocStart(ZSTDH_cwksp* ws);

MEM_STATIC void ZSTDH_cwksp_assert_internal_consistency(ZSTDH_cwksp* ws) {
    (void)ws;
    assert(ws->workspace <= ws->objectEnd);
    assert(ws->objectEnd <= ws->tableEnd);
    assert(ws->objectEnd <= ws->tableValidEnd);
    assert(ws->tableEnd <= ws->allocStart);
    assert(ws->tableValidEnd <= ws->allocStart);
    assert(ws->allocStart <= ws->workspaceEnd);
    assert(ws->initOnceStart <= ZSTDH_cwksp_initialAllocStart(ws));
    assert(ws->workspace <= ws->initOnceStart);
}

/*
 * Align must be a power of 2.
 */
MEM_STATIC size_t ZSTDH_cwksp_align(size_t size, size_t align) {
    size_t const mask = align - 1;
    assert(ZSTDH_isPower2(align));
    return (size + mask) & ~mask;
}

/*
 * Use this to determine how much space in the workspace we will consume to
 * allocate this object. (Normally it should be exactly the size of the object,
 * but under special conditions, like ASAN, where we pad each object, it might
 * be larger.)
 *
 * Since tables aren't currently redzoned, you don't need to call through this
 * to figure out how much space you need for the matchState tables. Everything
 * else is though.
 *
 * Do not use for sizing aligned buffers. Instead, use ZSTDH_cwksp_aligned64_alloc_size().
 */
MEM_STATIC size_t ZSTDH_cwksp_alloc_size(size_t size) {
    if (size == 0)
        return 0;
    return size;
}

MEM_STATIC size_t ZSTDH_cwksp_aligned_alloc_size(size_t size, size_t alignment) {
    return ZSTDH_cwksp_alloc_size(ZSTDH_cwksp_align(size, alignment));
}

/*
 * Returns an adjusted alloc size that is the nearest larger multiple of 64 bytes.
 * Used to determine the number of bytes required for a given "aligned".
 */
MEM_STATIC size_t ZSTDH_cwksp_aligned64_alloc_size(size_t size) {
    return ZSTDH_cwksp_aligned_alloc_size(size, ZSTDH_CWKSP_ALIGNMENT_BYTES);
}

/*
 * Returns the amount of additional space the cwksp must allocate
 * for internal purposes (currently only alignment).
 */
MEM_STATIC size_t ZSTDH_cwksp_slack_space_required(void) {
    /* For alignment, the wksp will always allocate an additional 2*ZSTDH_CWKSP_ALIGNMENT_BYTES
     * bytes to align the beginning of tables section and end of buffers;
     */
    size_t const slackSpace = ZSTDH_CWKSP_ALIGNMENT_BYTES * 2;
    return slackSpace;
}


/*
 * Return the number of additional bytes required to align a pointer to the given number of bytes.
 * alignBytes must be a power of two.
 */
MEM_STATIC size_t ZSTDH_cwksp_bytes_to_align_ptr(void* ptr, const size_t alignBytes) {
    size_t const alignBytesMask = alignBytes - 1;
    size_t const bytes = (alignBytes - ((size_t)ptr & (alignBytesMask))) & alignBytesMask;
    assert(ZSTDH_isPower2(alignBytes));
    assert(bytes < alignBytes);
    return bytes;
}

/*
 * Returns the initial value for allocStart which is used to determine the position from
 * which we can allocate from the end of the workspace.
 */
MEM_STATIC void*  ZSTDH_cwksp_initialAllocStart(ZSTDH_cwksp* ws)
{
    char* endPtr = (char*)ws->workspaceEnd;
    assert(ZSTDH_isPower2(ZSTDH_CWKSP_ALIGNMENT_BYTES));
    endPtr = endPtr - ((size_t)endPtr % ZSTDH_CWKSP_ALIGNMENT_BYTES);
    return (void*)endPtr;
}

/*
 * Internal function. Do not use directly.
 * Reserves the given number of bytes within the aligned/buffer segment of the wksp,
 * which counts from the end of the wksp (as opposed to the object/table segment).
 *
 * Returns a pointer to the beginning of that space.
 */
MEM_STATIC void*
ZSTDH_cwksp_reserve_internal_buffer_space(ZSTDH_cwksp* ws, size_t const bytes)
{
    void* const alloc = (BYTE*)ws->allocStart - bytes;
    void* const bottom = ws->tableEnd;
    DEBUGLOG(5, "cwksp: reserving [0x%p]:%zd bytes; %zd bytes remaining",
        alloc, bytes, ZSTDH_cwksp_available_space(ws) - bytes);
    ZSTDH_cwksp_assert_internal_consistency(ws);
    assert(alloc >= bottom);
    if (alloc < bottom) {
        DEBUGLOG(4, "cwksp: alloc failed!");
        ws->allocFailed = 1;
        return NULL;
    }
    /* the area is reserved from the end of wksp.
     * If it overlaps with tableValidEnd, it voids guarantees on values' range */
    if (alloc < ws->tableValidEnd) {
        ws->tableValidEnd = alloc;
    }
    ws->allocStart = alloc;
    return alloc;
}

/*
 * Moves the cwksp to the next phase, and does any necessary allocations.
 * cwksp initialization must necessarily go through each phase in order.
 * Returns a 0 on success, or zstd error
 */
MEM_STATIC size_t
ZSTDH_cwksp_internal_advance_phase(ZSTDH_cwksp* ws, ZSTDH_cwksp_alloc_phase_e phase)
{
    assert(phase >= ws->phase);
    if (phase > ws->phase) {
        /* Going from allocating objects to allocating initOnce / tables */
        if (ws->phase < ZSTDH_cwksp_alloc_aligned_init_once &&
            phase >= ZSTDH_cwksp_alloc_aligned_init_once) {
            ws->tableValidEnd = ws->objectEnd;
            ws->initOnceStart = ZSTDH_cwksp_initialAllocStart(ws);

            {   /* Align the start of the tables to 64 bytes. Use [0, 63] bytes */
                void *const alloc = ws->objectEnd;
                size_t const bytesToAlign = ZSTDH_cwksp_bytes_to_align_ptr(alloc, ZSTDH_CWKSP_ALIGNMENT_BYTES);
                void *const objectEnd = (BYTE *) alloc + bytesToAlign;
                DEBUGLOG(5, "reserving table alignment addtl space: %zu", bytesToAlign);
                RETURN_ERROR_IF(objectEnd > ws->workspaceEnd, memory_allocation,
                                "table phase - alignment initial allocation failed!");
                ws->objectEnd = objectEnd;
                ws->tableEnd = objectEnd;  /* table area starts being empty */
                if (ws->tableValidEnd < ws->tableEnd) {
                    ws->tableValidEnd = ws->tableEnd;
                }
            }
        }
        ws->phase = phase;
        ZSTDH_cwksp_assert_internal_consistency(ws);
    }
    return 0;
}

/*
 * Returns whether this object/buffer/etc was allocated in this workspace.
 */
MEM_STATIC int ZSTDH_cwksp_owns_buffer(const ZSTDH_cwksp* ws, const void* ptr)
{
    return (ptr != NULL) && (ws->workspace <= ptr) && (ptr < ws->workspaceEnd);
}

/*
 * Internal function. Do not use directly.
 */
MEM_STATIC void*
ZSTDH_cwksp_reserve_internal(ZSTDH_cwksp* ws, size_t bytes, ZSTDH_cwksp_alloc_phase_e phase)
{
    void* alloc;
    if (ZSTDH_isError(ZSTDH_cwksp_internal_advance_phase(ws, phase)) || bytes == 0) {
        return NULL;
    }


    alloc = ZSTDH_cwksp_reserve_internal_buffer_space(ws, bytes);


    return alloc;
}

/*
 * Reserves and returns unaligned memory.
 */
MEM_STATIC BYTE* ZSTDH_cwksp_reserve_buffer(ZSTDH_cwksp* ws, size_t bytes)
{
    return (BYTE*)ZSTDH_cwksp_reserve_internal(ws, bytes, ZSTDH_cwksp_alloc_buffers);
}

/*
 * Reserves and returns memory sized on and aligned on ZSTDH_CWKSP_ALIGNMENT_BYTES (64 bytes).
 * This memory has been initialized at least once in the past.
 * This doesn't mean it has been initialized this time, and it might contain data from previous
 * operations.
 * The main usage is for algorithms that might need read access into uninitialized memory.
 * The algorithm must maintain safety under these conditions and must make sure it doesn't
 * leak any of the past data (directly or in side channels).
 */
MEM_STATIC void* ZSTDH_cwksp_reserve_aligned_init_once(ZSTDH_cwksp* ws, size_t bytes)
{
    size_t const alignedBytes = ZSTDH_cwksp_align(bytes, ZSTDH_CWKSP_ALIGNMENT_BYTES);
    void* ptr = ZSTDH_cwksp_reserve_internal(ws, alignedBytes, ZSTDH_cwksp_alloc_aligned_init_once);
    assert(((size_t)ptr & (ZSTDH_CWKSP_ALIGNMENT_BYTES-1)) == 0);
    if(ptr && ptr < ws->initOnceStart) {
        /* We assume the memory following the current allocation is either:
         * 1. Not usable as initOnce memory (end of workspace)
         * 2. Another initOnce buffer that has been allocated before (and so was previously memset)
         * 3. An ASAN redzone, in which case we don't want to write on it
         * For these reasons it should be fine to not explicitly zero every byte up to ws->initOnceStart.
         * Note that we assume here that MSAN and ASAN cannot run in the same time. */
        ZSTDH_memset(ptr, 0, MIN((size_t)((U8*)ws->initOnceStart - (U8*)ptr), alignedBytes));
        ws->initOnceStart = ptr;
    }
    return ptr;
}

/*
 * Reserves and returns memory sized on and aligned on ZSTDH_CWKSP_ALIGNMENT_BYTES (64 bytes).
 */
MEM_STATIC void* ZSTDH_cwksp_reserve_aligned64(ZSTDH_cwksp* ws, size_t bytes)
{
    void* const ptr = ZSTDH_cwksp_reserve_internal(ws,
                        ZSTDH_cwksp_align(bytes, ZSTDH_CWKSP_ALIGNMENT_BYTES),
                        ZSTDH_cwksp_alloc_aligned);
    assert(((size_t)ptr & (ZSTDH_CWKSP_ALIGNMENT_BYTES-1)) == 0);
    return ptr;
}

/*
 * Aligned on 64 bytes. These buffers have the special property that
 * their values remain constrained, allowing us to reuse them without
 * memset()-ing them.
 */
MEM_STATIC void* ZSTDH_cwksp_reserve_table(ZSTDH_cwksp* ws, size_t bytes)
{
    const ZSTDH_cwksp_alloc_phase_e phase = ZSTDH_cwksp_alloc_aligned_init_once;
    void* alloc;
    void* end;
    void* top;

    /* We can only start allocating tables after we are done reserving space for objects at the
     * start of the workspace */
    if(ws->phase < phase) {
        if (ZSTDH_isError(ZSTDH_cwksp_internal_advance_phase(ws, phase))) {
            return NULL;
        }
    }
    alloc = ws->tableEnd;
    end = (BYTE *)alloc + bytes;
    top = ws->allocStart;

    DEBUGLOG(5, "cwksp: reserving %p table %zd bytes, %zd bytes remaining",
        alloc, bytes, ZSTDH_cwksp_available_space(ws) - bytes);
    assert((bytes & (sizeof(U32)-1)) == 0);
    ZSTDH_cwksp_assert_internal_consistency(ws);
    assert(end <= top);
    if (end > top) {
        DEBUGLOG(4, "cwksp: table alloc failed!");
        ws->allocFailed = 1;
        return NULL;
    }
    ws->tableEnd = end;


    assert((bytes & (ZSTDH_CWKSP_ALIGNMENT_BYTES-1)) == 0);
    assert(((size_t)alloc & (ZSTDH_CWKSP_ALIGNMENT_BYTES-1)) == 0);
    return alloc;
}

/*
 * Aligned on sizeof(void*).
 * Note : should happen only once, at workspace first initialization
 */
MEM_STATIC void* ZSTDH_cwksp_reserve_object(ZSTDH_cwksp* ws, size_t bytes)
{
    size_t const roundedBytes = ZSTDH_cwksp_align(bytes, sizeof(void*));
    void* alloc = ws->objectEnd;
    void* end = (BYTE*)alloc + roundedBytes;


    DEBUGLOG(4,
        "cwksp: reserving %p object %zd bytes (rounded to %zd), %zd bytes remaining",
        alloc, bytes, roundedBytes, ZSTDH_cwksp_available_space(ws) - roundedBytes);
    assert((size_t)alloc % ZSTDH_ALIGNOF(void*) == 0);
    assert(bytes % ZSTDH_ALIGNOF(void*) == 0);
    ZSTDH_cwksp_assert_internal_consistency(ws);
    /* we must be in the first phase, no advance is possible */
    if (ws->phase != ZSTDH_cwksp_alloc_objects || end > ws->workspaceEnd) {
        DEBUGLOG(3, "cwksp: object alloc failed!");
        ws->allocFailed = 1;
        return NULL;
    }
    ws->objectEnd = end;
    ws->tableEnd = end;
    ws->tableValidEnd = end;


    return alloc;
}
/*
 * with alignment control
 * Note : should happen only once, at workspace first initialization
 */
MEM_STATIC void* ZSTDH_cwksp_reserve_object_aligned(ZSTDH_cwksp* ws, size_t byteSize, size_t alignment)
{
    size_t const mask = alignment - 1;
    size_t const surplus = (alignment > sizeof(void*)) ? alignment - sizeof(void*) : 0;
    void* const start = ZSTDH_cwksp_reserve_object(ws, byteSize + surplus);
    if (start == NULL) return NULL;
    if (surplus == 0) return start;
    assert(ZSTDH_isPower2(alignment));
    return (void*)(((size_t)start + surplus) & ~mask);
}

MEM_STATIC void ZSTDH_cwksp_mark_tables_dirty(ZSTDH_cwksp* ws)
{
    DEBUGLOG(4, "cwksp: ZSTDH_cwksp_mark_tables_dirty");


    assert(ws->tableValidEnd >= ws->objectEnd);
    assert(ws->tableValidEnd <= ws->allocStart);
    ws->tableValidEnd = ws->objectEnd;
    ZSTDH_cwksp_assert_internal_consistency(ws);
}

MEM_STATIC void ZSTDH_cwksp_mark_tables_clean(ZSTDH_cwksp* ws) {
    DEBUGLOG(4, "cwksp: ZSTDH_cwksp_mark_tables_clean");
    assert(ws->tableValidEnd >= ws->objectEnd);
    assert(ws->tableValidEnd <= ws->allocStart);
    if (ws->tableValidEnd < ws->tableEnd) {
        ws->tableValidEnd = ws->tableEnd;
    }
    ZSTDH_cwksp_assert_internal_consistency(ws);
}

/*
 * Zero the part of the allocated tables not already marked clean.
 */
MEM_STATIC void ZSTDH_cwksp_clean_tables(ZSTDH_cwksp* ws) {
    DEBUGLOG(4, "cwksp: ZSTDH_cwksp_clean_tables");
    assert(ws->tableValidEnd >= ws->objectEnd);
    assert(ws->tableValidEnd <= ws->allocStart);
    if (ws->tableValidEnd < ws->tableEnd) {
        ZSTDH_memset(ws->tableValidEnd, 0, (size_t)((BYTE*)ws->tableEnd - (BYTE*)ws->tableValidEnd));
    }
    ZSTDH_cwksp_mark_tables_clean(ws);
}

/*
 * Invalidates table allocations.
 * All other allocations remain valid.
 */
MEM_STATIC void ZSTDH_cwksp_clear_tables(ZSTDH_cwksp* ws)
{
    DEBUGLOG(4, "cwksp: clearing tables!");


    ws->tableEnd = ws->objectEnd;
    ZSTDH_cwksp_assert_internal_consistency(ws);
}

/*
 * Invalidates all buffer, aligned, and table allocations.
 * Object allocations remain valid.
 */
MEM_STATIC void ZSTDH_cwksp_clear(ZSTDH_cwksp* ws) {
    DEBUGLOG(4, "cwksp: clearing!");



    ws->tableEnd = ws->objectEnd;
    ws->allocStart = ZSTDH_cwksp_initialAllocStart(ws);
    ws->allocFailed = 0;
    if (ws->phase > ZSTDH_cwksp_alloc_aligned_init_once) {
        ws->phase = ZSTDH_cwksp_alloc_aligned_init_once;
    }
    ZSTDH_cwksp_assert_internal_consistency(ws);
}

MEM_STATIC size_t ZSTDH_cwksp_sizeof(const ZSTDH_cwksp* ws) {
    return (size_t)((BYTE*)ws->workspaceEnd - (BYTE*)ws->workspace);
}

MEM_STATIC size_t ZSTDH_cwksp_used(const ZSTDH_cwksp* ws) {
    return (size_t)((BYTE*)ws->tableEnd - (BYTE*)ws->workspace)
         + (size_t)((BYTE*)ws->workspaceEnd - (BYTE*)ws->allocStart);
}

/*
 * The provided workspace takes ownership of the buffer [start, start+size).
 * Any existing values in the workspace are ignored (the previously managed
 * buffer, if present, must be separately freed).
 */
MEM_STATIC void ZSTDH_cwksp_init(ZSTDH_cwksp* ws, void* start, size_t size, ZSTDH_cwksp_static_alloc_e isStatic) {
    DEBUGLOG(4, "cwksp: init'ing workspace with %zd bytes", size);
    assert(((size_t)start & (sizeof(void*)-1)) == 0); /* ensure correct alignment */
    ws->workspace = start;
    ws->workspaceEnd = (BYTE*)start + size;
    ws->objectEnd = ws->workspace;
    ws->tableValidEnd = ws->objectEnd;
    ws->initOnceStart = ZSTDH_cwksp_initialAllocStart(ws);
    ws->phase = ZSTDH_cwksp_alloc_objects;
    ws->isStatic = isStatic;
    ZSTDH_cwksp_clear(ws);
    ws->workspaceOversizedDuration = 0;
    ZSTDH_cwksp_assert_internal_consistency(ws);
}

MEM_STATIC size_t ZSTDH_cwksp_create(ZSTDH_cwksp* ws, size_t size, ZSTDH_customMem customMem) {
    void* workspace = ZSTDH_customMalloc(size, customMem);
    DEBUGLOG(4, "cwksp: creating new workspace with %zd bytes", size);
    RETURN_ERROR_IF(workspace == NULL, memory_allocation, "NULL pointer!");
    ZSTDH_cwksp_init(ws, workspace, size, ZSTDH_cwksp_dynamic_alloc);
    return 0;
}

MEM_STATIC void ZSTDH_cwksp_free(ZSTDH_cwksp* ws, ZSTDH_customMem customMem) {
    void *ptr = ws->workspace;
    DEBUGLOG(4, "cwksp: freeing workspace");
    ZSTDH_memset(ws, 0, sizeof(ZSTDH_cwksp));
    ZSTDH_customFree(ptr, customMem);
}

/*
 * Moves the management of a workspace from one cwksp to another. The src cwksp
 * is left in an invalid state (src must be re-init()'ed before it's used again).
 */
MEM_STATIC void ZSTDH_cwksp_move(ZSTDH_cwksp* dst, ZSTDH_cwksp* src) {
    *dst = *src;
    ZSTDH_memset(src, 0, sizeof(ZSTDH_cwksp));
}

MEM_STATIC int ZSTDH_cwksp_reserve_failed(const ZSTDH_cwksp* ws) {
    return ws->allocFailed;
}

/*-*************************************
*  Functions Checking Free Space
***************************************/

/* ZSTDH_alignmentSpaceWithinBounds() :
 * Returns if the estimated space needed for a wksp is within an acceptable limit of the
 * actual amount of space used.
 */
MEM_STATIC int ZSTDH_cwksp_estimated_space_within_bounds(const ZSTDH_cwksp *const ws, size_t const estimatedSpace) {
    /* We have an alignment space between objects and tables between tables and buffers, so we can have up to twice
     * the alignment bytes difference between estimation and actual usage */
    return (estimatedSpace - ZSTDH_cwksp_slack_space_required()) <= ZSTDH_cwksp_used(ws) &&
           ZSTDH_cwksp_used(ws) <= estimatedSpace;
}


MEM_STATIC size_t ZSTDH_cwksp_available_space(ZSTDH_cwksp* ws) {
    return (size_t)((BYTE*)ws->allocStart - (BYTE*)ws->tableEnd);
}

MEM_STATIC int ZSTDH_cwksp_check_available(ZSTDH_cwksp* ws, size_t additionalNeededSpace) {
    return ZSTDH_cwksp_available_space(ws) >= additionalNeededSpace;
}

MEM_STATIC int ZSTDH_cwksp_check_too_large(ZSTDH_cwksp* ws, size_t additionalNeededSpace) {
    return ZSTDH_cwksp_check_available(
        ws, additionalNeededSpace * ZSTDH_WORKSPACETOOLARGE_FACTOR);
}

MEM_STATIC int ZSTDH_cwksp_check_wasteful(ZSTDH_cwksp* ws, size_t additionalNeededSpace) {
    return ZSTDH_cwksp_check_too_large(ws, additionalNeededSpace)
        && ws->workspaceOversizedDuration > ZSTDH_WORKSPACETOOLARGE_MAXDURATION;
}

MEM_STATIC void ZSTDH_cwksp_bump_oversized_duration(
        ZSTDH_cwksp* ws, size_t additionalNeededSpace) {
    if (ZSTDH_cwksp_check_too_large(ws, additionalNeededSpace)) {
        ws->workspaceOversizedDuration++;
    } else {
        ws->workspaceOversizedDuration = 0;
    }
}

#endif /* ZSTDH_CWKSP_H */
