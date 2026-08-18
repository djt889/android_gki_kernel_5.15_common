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

/* Common symbols. zstdh_compress must depend on zstdh_decompress. */

unsigned int zstdh_is_error(size_t code)
{
	return ZSTDH_isError(code);
}
EXPORT_SYMBOL(zstdh_is_error);

zstdh_error_code zstdh_get_error_code(size_t code)
{
	return ZSTDH_getErrorCode(code);
}
EXPORT_SYMBOL(zstdh_get_error_code);

const char *zstdh_get_error_name(size_t code)
{
	return ZSTDH_getErrorName(code);
}
EXPORT_SYMBOL(zstdh_get_error_name);

/* Decompression symbols. */

size_t zstdh_dctx_workspace_bound(void)
{
	return ZSTDH_estimateDCtxSize();
}
EXPORT_SYMBOL(zstdh_dctx_workspace_bound);

zstdh_dctx *zstdh_init_dctx(void *workspace, size_t workspace_size)
{
	if (workspace == NULL)
		return NULL;
	return ZSTDH_initStaticDCtx(workspace, workspace_size);
}
EXPORT_SYMBOL(zstdh_init_dctx);

size_t zstdh_decompress_dctx(zstdh_dctx *dctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size)
{
	return ZSTDH_decompressDCtx(dctx, dst, dst_capacity, src, src_size);
}
EXPORT_SYMBOL(zstdh_decompress_dctx);

size_t zstdh_dstream_workspace_bound(size_t max_window_size)
{
	return ZSTDH_estimateDStreamSize(max_window_size);
}
EXPORT_SYMBOL(zstdh_dstream_workspace_bound);

size_t ZSTDH_DStreamWorkspaceBound(size_t max_window_size)
{
	return zstdh_dstream_workspace_bound(max_window_size);
}
EXPORT_SYMBOL(ZSTDH_DStreamWorkspaceBound);

zstdh_dstream *zstdh_init_dstream(size_t max_window_size, void *workspace,
	size_t workspace_size)
{
	if (workspace == NULL)
		return NULL;
	(void)max_window_size;
	return ZSTDH_initStaticDStream(workspace, workspace_size);
}
EXPORT_SYMBOL(zstdh_init_dstream);

size_t zstdh_reset_dstream(zstdh_dstream *dstream)
{
	return ZSTDH_DCtx_reset(dstream, ZSTDH_reset_session_only);
}
EXPORT_SYMBOL(zstdh_reset_dstream);

size_t zstdh_decompress_stream(zstdh_dstream *dstream, zstdh_out_buffer *output,
	zstdh_in_buffer *input)
{
	return ZSTDH_decompressStream(dstream, output, input);
}
EXPORT_SYMBOL(zstdh_decompress_stream);

size_t zstdh_find_frame_compressed_size(const void *src, size_t src_size)
{
	return ZSTDH_findFrameCompressedSize(src, src_size);
}
EXPORT_SYMBOL(zstdh_find_frame_compressed_size);

size_t zstdh_get_frame_header(zstdh_frame_header *header, const void *src,
	size_t src_size)
{
	return ZSTDH_getFrameHeader(header, src, src_size);
}
EXPORT_SYMBOL(zstdh_get_frame_header);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Zstd Decompressor");
