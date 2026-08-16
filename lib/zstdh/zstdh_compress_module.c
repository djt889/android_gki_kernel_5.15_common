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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/zstdh.h>

#include "common/zstd_deps.h"
#include "common/zstd_internal.h"
#include "compress/zstd_compress_internal.h"

#define ZSTDH_FORWARD_IF_ERR(ret)            \
	do {                                \
		size_t const __ret = (ret); \
		if (ZSTDH_isError(__ret))    \
			return __ret;       \
	} while (0)

static size_t zstdh_cctx_init(zstdh_cctx *cctx, const zstdh_parameters *parameters,
	unsigned long long pledged_src_size)
{
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_reset(
		cctx, ZSTDH_reset_session_and_parameters));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setPledgedSrcSize(
		cctx, pledged_src_size));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_windowLog, parameters->cParams.windowLog));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_hashLog, parameters->cParams.hashLog));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_chainLog, parameters->cParams.chainLog));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_searchLog, parameters->cParams.searchLog));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_minMatch, parameters->cParams.minMatch));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_targetLength, parameters->cParams.targetLength));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_strategy, parameters->cParams.strategy));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_contentSizeFlag, parameters->fParams.contentSizeFlag));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_checksumFlag, parameters->fParams.checksumFlag));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_dictIDFlag, !parameters->fParams.noDictIDFlag));
	return 0;
}

int zstdh_min_clevel(void)
{
	return ZSTDH_minCLevel();
}
EXPORT_SYMBOL(zstdh_min_clevel);

int zstdh_max_clevel(void)
{
	return ZSTDH_maxCLevel();
}
EXPORT_SYMBOL(zstdh_max_clevel);

size_t zstdh_compress_bound(size_t src_size)
{
	return ZSTDH_compressBound(src_size);
}
EXPORT_SYMBOL(zstdh_compress_bound);

zstdh_parameters zstdh_get_params(int level,
	unsigned long long estimated_src_size)
{
	return ZSTDH_getParams(level, estimated_src_size, 0);
}
EXPORT_SYMBOL(zstdh_get_params);

size_t zstdh_cctx_set_param(zstdh_cctx *cctx, ZSTDH_cParameter param, int value)
{
	return ZSTDH_CCtx_setParameter(cctx, param, value);
}
EXPORT_SYMBOL(zstdh_cctx_set_param);

size_t zstdh_cctx_workspace_bound(const zstdh_compression_parameters *cparams)
{
	return ZSTDH_estimateCCtxSize_usingCParams(*cparams);
}
EXPORT_SYMBOL(zstdh_cctx_workspace_bound);

// Used by zstdh_cctx_workspace_bound_with_ext_seq_prod()
static size_t dummy_external_sequence_producer(
	void *sequenceProducerState,
	ZSTDH_Sequence *outSeqs, size_t outSeqsCapacity,
	const void *src, size_t srcSize,
	const void *dict, size_t dictSize,
	int compressionLevel,
	size_t windowSize)
{
	(void)sequenceProducerState;
	(void)outSeqs; (void)outSeqsCapacity;
	(void)src; (void)srcSize;
	(void)dict; (void)dictSize;
	(void)compressionLevel;
	(void)windowSize;
	return ZSTDH_SEQUENCE_PRODUCER_ERROR;
}

static void init_cctx_params_from_compress_params(
	ZSTDH_CCtx_params *cctx_params,
	const zstdh_compression_parameters *compress_params)
{
	ZSTDH_parameters zstdh_params;
	memset(&zstdh_params, 0, sizeof(zstdh_params));
	zstdh_params.cParams = *compress_params;
	ZSTDH_CCtxParams_init_advanced(cctx_params, zstdh_params);
}

size_t zstdh_cctx_workspace_bound_with_ext_seq_prod(const zstdh_compression_parameters *compress_params)
{
	ZSTDH_CCtx_params cctx_params;
	init_cctx_params_from_compress_params(&cctx_params, compress_params);
	ZSTDH_CCtxParams_registerSequenceProducer(&cctx_params, NULL, dummy_external_sequence_producer);
	return ZSTDH_estimateCCtxSize_usingCCtxParams(&cctx_params);
}
EXPORT_SYMBOL(zstdh_cctx_workspace_bound_with_ext_seq_prod);

size_t zstdh_cstream_workspace_bound_with_ext_seq_prod(const zstdh_compression_parameters *compress_params)
{
	ZSTDH_CCtx_params cctx_params;
	init_cctx_params_from_compress_params(&cctx_params, compress_params);
	ZSTDH_CCtxParams_registerSequenceProducer(&cctx_params, NULL, dummy_external_sequence_producer);
	return ZSTDH_estimateCStreamSize_usingCCtxParams(&cctx_params);
}
EXPORT_SYMBOL(zstdh_cstream_workspace_bound_with_ext_seq_prod);

zstdh_cctx *zstdh_init_cctx(void *workspace, size_t workspace_size)
{
	if (workspace == NULL)
		return NULL;
	return ZSTDH_initStaticCCtx(workspace, workspace_size);
}
EXPORT_SYMBOL(zstdh_init_cctx);

size_t zstdh_compress_cctx(zstdh_cctx *cctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size, const zstdh_parameters *parameters)
{
	ZSTDH_FORWARD_IF_ERR(zstdh_cctx_init(cctx, parameters, src_size));
	return ZSTDH_compress2(cctx, dst, dst_capacity, src, src_size);
}
EXPORT_SYMBOL(zstdh_compress_cctx);

/*
 * zstdh: like zstdh_compress_cctx() but keeps the hash table warm across
 * calls (no session reset). The caller must guarantee the cctx is used by
 * a single CPU (zram does this via per-CPU streams). Parameters must be
 * identical on every call, which the caller ensures.
 */
size_t zstdh_compress_cctx_reuse(zstdh_cctx *cctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size, const zstdh_parameters *parameters)
{
	size_t dstPos = 0, srcPos = 0;
	size_t ret;

	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setPledgedSrcSize(cctx, src_size));
	ZSTDH_FORWARD_IF_ERR(ZSTDH_CCtx_setParameter(
		cctx, ZSTDH_c_contentSizeFlag, parameters->fParams.contentSizeFlag));
	ret = ZSTDH_compressStream2_simpleArgs(cctx,
		dst, dst_capacity, &dstPos,
		src, src_size, &srcPos, ZSTDH_e_end);
	if (ZSTDH_isError(ret))
		return ret;
	return dstPos;
}
EXPORT_SYMBOL(zstdh_compress_cctx_reuse);

size_t zstdh_cstream_workspace_bound(const zstdh_compression_parameters *cparams)
{
	return ZSTDH_estimateCStreamSize_usingCParams(*cparams);
}
EXPORT_SYMBOL(zstdh_cstream_workspace_bound);

size_t ZSTDH_CStreamWorkspaceBound(ZSTDH_compressionParameters *cparams)
{
	return zstdh_cstream_workspace_bound(cparams);
}
EXPORT_SYMBOL(ZSTDH_CStreamWorkspaceBound);

zstdh_cstream *zstdh_init_cstream(const zstdh_parameters *parameters,
	unsigned long long pledged_src_size, void *workspace, size_t workspace_size)
{
	zstdh_cstream *cstream;

	if (workspace == NULL)
		return NULL;

	cstream = ZSTDH_initStaticCStream(workspace, workspace_size);
	if (cstream == NULL)
		return NULL;

	/* 0 means unknown in linux zstd API but means 0 in new zstd API */
	if (pledged_src_size == 0)
		pledged_src_size = ZSTDH_CONTENTSIZE_UNKNOWN;

	if (ZSTDH_isError(zstdh_cctx_init(cstream, parameters, pledged_src_size)))
		return NULL;

	return cstream;
}
EXPORT_SYMBOL(zstdh_init_cstream);

size_t zstdh_reset_cstream(zstdh_cstream *cstream,
	unsigned long long pledged_src_size)
{
	if (pledged_src_size == 0)
		pledged_src_size = ZSTDH_CONTENTSIZE_UNKNOWN;
	ZSTDH_FORWARD_IF_ERR( ZSTDH_CCtx_reset(cstream, ZSTDH_reset_session_only) );
	ZSTDH_FORWARD_IF_ERR( ZSTDH_CCtx_setPledgedSrcSize(cstream, pledged_src_size) );
	return 0;
}
EXPORT_SYMBOL(zstdh_reset_cstream);

size_t zstdh_compress_stream(zstdh_cstream *cstream, zstdh_out_buffer *output,
	zstdh_in_buffer *input)
{
	return ZSTDH_compressStream(cstream, output, input);
}
EXPORT_SYMBOL(zstdh_compress_stream);

size_t zstdh_flush_stream(zstdh_cstream *cstream, zstdh_out_buffer *output)
{
	return ZSTDH_flushStream(cstream, output);
}
EXPORT_SYMBOL(zstdh_flush_stream);

size_t zstdh_end_stream(zstdh_cstream *cstream, zstdh_out_buffer *output)
{
	return ZSTDH_endStream(cstream, output);
}
EXPORT_SYMBOL(zstdh_end_stream);

void zstdh_register_sequence_producer(
  zstdh_cctx *cctx,
  void* sequence_producer_state,
  zstdh_sequence_producer_f sequence_producer
) {
	ZSTDH_registerSequenceProducer(cctx, sequence_producer_state, sequence_producer);
}
EXPORT_SYMBOL(zstdh_register_sequence_producer);

size_t zstdh_compress_sequences_and_literals(zstdh_cctx *cctx, void* dst, size_t dst_capacity,
					    const zstdh_sequence *in_seqs, size_t in_seqs_size,
					    const void* literals, size_t lit_size, size_t lit_capacity,
					    size_t decompressed_size)
{
	return ZSTDH_compressSequencesAndLiterals(cctx, dst, dst_capacity, in_seqs,
						 in_seqs_size, literals, lit_size,
						 lit_capacity, decompressed_size);
}
EXPORT_SYMBOL(zstdh_compress_sequences_and_literals);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Zstd Compressor");
