/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of https://github.com/facebook/zstd) and
 * the GPLv2 (found in the COPYING file in the root directory of
 * https://github.com/facebook/zstd). You may select, at your option, one of the
 * above-listed licenses.
 */

#ifndef LINUX_ZSTDH_H
#define LINUX_ZSTDH_H

/**
 * This is a kernel-style API that wraps the upstream zstd API, which cannot be
 * used directly because the symbols aren't exported. It exposes the minimal
 * functionality which is currently required by users of zstd in the kernel.
 * Expose extra functions from lib/zstd/zstd.h as needed.
 */

/* ======   Dependency   ====== */
#include <linux/types.h>
#include <linux/zstdh_errors.h>
#include <linux/zstdh_lib.h>

/* ======   Helper Functions   ====== */
/**
 * zstdh_compress_bound() - maximum compressed size in worst case scenario
 * @src_size: The size of the data to compress.
 *
 * Return:    The maximum compressed size in the worst case scenario.
 */
size_t zstdh_compress_bound(size_t src_size);

/**
 * zstdh_is_error() - tells if a size_t function result is an error code
 * @code:  The function result to check for error.
 *
 * Return: Non-zero iff the code is an error.
 */
unsigned int zstdh_is_error(size_t code);

/**
 * enum zstdh_error_code - zstd error codes
 */
typedef ZSTDH_ErrorCode zstdh_error_code;

/**
 * zstdh_get_error_code() - translates an error function result to an error code
 * @code:  The function result for which zstdh_is_error(code) is true.
 *
 * Return: A unique error code for this error.
 */
zstdh_error_code zstdh_get_error_code(size_t code);

/**
 * zstdh_get_error_name() - translates an error function result to a string
 * @code:  The function result for which zstdh_is_error(code) is true.
 *
 * Return: An error string corresponding to the error code.
 */
const char *zstdh_get_error_name(size_t code);

/**
 * zstdh_min_clevel() - minimum allowed compression level
 *
 * Return: The minimum allowed compression level.
 */
int zstdh_min_clevel(void);

/**
 * zstdh_max_clevel() - maximum allowed compression level
 *
 * Return: The maximum allowed compression level.
 */
int zstdh_max_clevel(void);

/* ======   Parameter Selection   ====== */

/**
 * enum zstdh_strategy - zstd compression search strategy
 *
 * From faster to stronger. See zstdh_lib.h.
 */
typedef ZSTDH_strategy zstdh_strategy;

/**
 * struct zstdh_compression_parameters - zstd compression parameters
 * @windowLog:    Log of the largest match distance. Larger means more
 *                compression, and more memory needed during decompression.
 * @chainLog:     Fully searched segment. Larger means more compression,
 *                slower, and more memory (useless for fast).
 * @hashLog:      Dispatch table. Larger means more compression,
 *                slower, and more memory.
 * @searchLog:    Number of searches. Larger means more compression and slower.
 * @searchLength: Match length searched. Larger means faster decompression,
 *                sometimes less compression.
 * @targetLength: Acceptable match size for optimal parser (only). Larger means
 *                more compression, and slower.
 * @strategy:     The zstd compression strategy.
 *
 * See zstdh_lib.h.
 */
typedef ZSTDH_compressionParameters zstdh_compression_parameters;

/**
 * struct zstdh_frame_parameters - zstd frame parameters
 * @contentSizeFlag: Controls whether content size will be present in the
 *                   frame header (when known).
 * @checksumFlag:    Controls whether a 32-bit checksum is generated at the
 *                   end of the frame for error detection.
 * @noDictIDFlag:    Controls whether dictID will be saved into the frame
 *                   header when using dictionary compression.
 *
 * The default value is all fields set to 0. See zstdh_lib.h.
 */
typedef ZSTDH_frameParameters zstdh_frame_parameters;

/**
 * struct zstdh_parameters - zstd parameters
 * @cParams: The compression parameters.
 * @fParams: The frame parameters.
 */
typedef ZSTDH_parameters zstdh_parameters;

/**
 * zstdh_get_params() - returns zstdh_parameters for selected level
 * @level:              The compression level
 * @estimated_src_size: The estimated source size to compress or 0
 *                      if unknown.
 *
 * Return:              The selected zstdh_parameters.
 */
zstdh_parameters zstdh_get_params(int level,
	unsigned long long estimated_src_size);

typedef ZSTDH_CCtx zstdh_cctx;
typedef ZSTDH_cParameter zstdh_cparameter;

/**
 * zstdh_cctx_set_param() - sets a compression parameter
 * @cctx:         The context. Must have been initialized with zstdh_init_cctx().
 * @param:        The parameter to set.
 * @value:        The value to set the parameter to.
 *
 * Return:        Zero or an error, which can be checked using zstdh_is_error().
 */
size_t zstdh_cctx_set_param(zstdh_cctx *cctx, zstdh_cparameter param, int value);

/* ======   Single-pass Compression   ====== */

/**
 * zstdh_cctx_workspace_bound() - max memory needed to initialize a zstdh_cctx
 * @parameters: The compression parameters to be used.
 *
 * If multiple compression parameters might be used, the caller must call
 * zstdh_cctx_workspace_bound() for each set of parameters and use the maximum
 * size.
 *
 * Return:      A lower bound on the size of the workspace that is passed to
 *              zstdh_init_cctx().
 */
size_t zstdh_cctx_workspace_bound(const zstdh_compression_parameters *parameters);

/**
 * zstdh_cctx_workspace_bound_with_ext_seq_prod() - max memory needed to
 * initialize a zstdh_cctx when using the block-level external sequence
 * producer API.
 * @parameters: The compression parameters to be used.
 *
 * If multiple compression parameters might be used, the caller must call
 * this function for each set of parameters and use the maximum size.
 *
 * Return:      A lower bound on the size of the workspace that is passed to
 *              zstdh_init_cctx().
 */
size_t zstdh_cctx_workspace_bound_with_ext_seq_prod(const zstdh_compression_parameters *parameters);

/**
 * zstdh_init_cctx() - initialize a zstd compression context
 * @workspace:      The workspace to emplace the context into. It must outlive
 *                  the returned context.
 * @workspace_size: The size of workspace. Use zstdh_cctx_workspace_bound() to
 *                  determine how large the workspace must be.
 *
 * Return:          A zstd compression context or NULL on error.
 */
zstdh_cctx *zstdh_init_cctx(void *workspace, size_t workspace_size);

/**
 * zstdh_compress_cctx() - compress src into dst with the initialized parameters
 * @cctx:         The context. Must have been initialized with zstdh_init_cctx().
 * @dst:          The buffer to compress src into.
 * @dst_capacity: The size of the destination buffer. May be any size, but
 *                ZSTDH_compressBound(srcSize) is guaranteed to be large enough.
 * @src:          The data to compress.
 * @src_size:     The size of the data to compress.
 * @parameters:   The compression parameters to be used.
 *
 * Return:        The compressed size or an error, which can be checked using
 *                zstdh_is_error().
 */
size_t zstdh_compress_cctx(zstdh_cctx *cctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size, const zstdh_parameters *parameters);

/*
 * zstdh_compress_cctx_reuse() - like zstdh_compress_cctx() but keeps the
 * hash table warm across calls (no session reset). The caller must ensure
 * the cctx is used by a single CPU (zram does this per-CPU). Parameters
 * must be identical on every call.
 */
size_t zstdh_compress_cctx_reuse(zstdh_cctx *cctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size, const zstdh_parameters *parameters);

/* ======   Single-pass Decompression   ====== */

typedef ZSTDH_DCtx zstdh_dctx;

/**
 * zstdh_dctx_workspace_bound() - max memory needed to initialize a zstdh_dctx
 *
 * Return: A lower bound on the size of the workspace that is passed to
 *         zstdh_init_dctx().
 */
size_t zstdh_dctx_workspace_bound(void);

/**
 * zstdh_init_dctx() - initialize a zstd decompression context
 * @workspace:      The workspace to emplace the context into. It must outlive
 *                  the returned context.
 * @workspace_size: The size of workspace. Use zstdh_dctx_workspace_bound() to
 *                  determine how large the workspace must be.
 *
 * Return:          A zstd decompression context or NULL on error.
 */
zstdh_dctx *zstdh_init_dctx(void *workspace, size_t workspace_size);

/**
 * zstdh_decompress_dctx() - decompress zstd compressed src into dst
 * @dctx:         The decompression context.
 * @dst:          The buffer to decompress src into.
 * @dst_capacity: The size of the destination buffer. Must be at least as large
 *                as the decompressed size. If the caller cannot upper bound the
 *                decompressed size, then it's better to use the streaming API.
 * @src:          The zstd compressed data to decompress. Multiple concatenated
 *                frames and skippable frames are allowed.
 * @src_size:     The exact size of the data to decompress.
 *
 * Return:        The decompressed size or an error, which can be checked using
 *                zstdh_is_error().
 */
size_t zstdh_decompress_dctx(zstdh_dctx *dctx, void *dst, size_t dst_capacity,
	const void *src, size_t src_size);

/* ======   Streaming Buffers   ====== */

/**
 * struct zstdh_in_buffer - input buffer for streaming
 * @src:  Start of the input buffer.
 * @size: Size of the input buffer.
 * @pos:  Position where reading stopped. Will be updated.
 *        Necessarily 0 <= pos <= size.
 *
 * See zstdh_lib.h.
 */
typedef ZSTDH_inBuffer zstdh_in_buffer;

/**
 * struct zstdh_out_buffer - output buffer for streaming
 * @dst:  Start of the output buffer.
 * @size: Size of the output buffer.
 * @pos:  Position where writing stopped. Will be updated.
 *        Necessarily 0 <= pos <= size.
 *
 * See zstdh_lib.h.
 */
typedef ZSTDH_outBuffer zstdh_out_buffer;

/* ======   Streaming Compression   ====== */

typedef ZSTDH_CStream zstdh_cstream;

/**
 * zstdh_cstream_workspace_bound() - memory needed to initialize a zstdh_cstream
 * @cparams: The compression parameters to be used for compression.
 *
 * Return:   A lower bound on the size of the workspace that is passed to
 *           zstdh_init_cstream().
 */
size_t zstdh_cstream_workspace_bound(const zstdh_compression_parameters *cparams);

/**
 * zstdh_cstream_workspace_bound_with_ext_seq_prod() - memory needed to initialize
 * a zstdh_cstream when using the block-level external sequence producer API.
 * @cparams: The compression parameters to be used for compression.
 *
 * Return:   A lower bound on the size of the workspace that is passed to
 *           zstdh_init_cstream().
 */
size_t zstdh_cstream_workspace_bound_with_ext_seq_prod(const zstdh_compression_parameters *cparams);

/**
 * zstdh_init_cstream() - initialize a zstd streaming compression context
 * @parameters        The zstd parameters to use for compression.
 * @pledged_src_size: If params.fParams.contentSizeFlag == 1 then the caller
 *                    must pass the source size (zero means empty source).
 *                    Otherwise, the caller may optionally pass the source
 *                    size, or zero if unknown.
 * @workspace:        The workspace to emplace the context into. It must outlive
 *                    the returned context.
 * @workspace_size:   The size of workspace.
 *                    Use zstdh_cstream_workspace_bound(params->cparams) to
 *                    determine how large the workspace must be.
 *
 * Return:            The zstd streaming compression context or NULL on error.
 */
zstdh_cstream *zstdh_init_cstream(const zstdh_parameters *parameters,
	unsigned long long pledged_src_size, void *workspace, size_t workspace_size);

/**
 * zstdh_reset_cstream() - reset the context using parameters from creation
 * @cstream:          The zstd streaming compression context to reset.
 * @pledged_src_size: Optionally the source size, or zero if unknown.
 *
 * Resets the context using the parameters from creation. Skips dictionary
 * loading, since it can be reused. If `pledged_src_size` is non-zero the frame
 * content size is always written into the frame header.
 *
 * Return:            Zero or an error, which can be checked using
 *                    zstdh_is_error().
 */
size_t zstdh_reset_cstream(zstdh_cstream *cstream,
	unsigned long long pledged_src_size);

/**
 * zstdh_compress_stream() - streaming compress some of input into output
 * @cstream: The zstd streaming compression context.
 * @output:  Destination buffer. `output->pos` is updated to indicate how much
 *           compressed data was written.
 * @input:   Source buffer. `input->pos` is updated to indicate how much data
 *           was read. Note that it may not consume the entire input, in which
 *           case `input->pos < input->size`, and it's up to the caller to
 *           present remaining data again.
 *
 * The `input` and `output` buffers may be any size. Guaranteed to make some
 * forward progress if `input` and `output` are not empty.
 *
 * Return:   A hint for the number of bytes to use as the input for the next
 *           function call or an error, which can be checked using
 *           zstdh_is_error().
 */
size_t zstdh_compress_stream(zstdh_cstream *cstream, zstdh_out_buffer *output,
	zstdh_in_buffer *input);

/**
 * zstdh_flush_stream() - flush internal buffers into output
 * @cstream: The zstd streaming compression context.
 * @output:  Destination buffer. `output->pos` is updated to indicate how much
 *           compressed data was written.
 *
 * zstdh_flush_stream() must be called until it returns 0, meaning all the data
 * has been flushed. Since zstdh_flush_stream() causes a block to be ended,
 * calling it too often will degrade the compression ratio.
 *
 * Return:   The number of bytes still present within internal buffers or an
 *           error, which can be checked using zstdh_is_error().
 */
size_t zstdh_flush_stream(zstdh_cstream *cstream, zstdh_out_buffer *output);

/**
 * zstdh_end_stream() - flush internal buffers into output and end the frame
 * @cstream: The zstd streaming compression context.
 * @output:  Destination buffer. `output->pos` is updated to indicate how much
 *           compressed data was written.
 *
 * zstdh_end_stream() must be called until it returns 0, meaning all the data has
 * been flushed and the frame epilogue has been written.
 *
 * Return:   The number of bytes still present within internal buffers or an
 *           error, which can be checked using zstdh_is_error().
 */
size_t zstdh_end_stream(zstdh_cstream *cstream, zstdh_out_buffer *output);

/* ======   Streaming Decompression   ====== */

typedef ZSTDH_DStream zstdh_dstream;

/**
 * zstdh_dstream_workspace_bound() - memory needed to initialize a zstdh_dstream
 * @max_window_size: The maximum window size allowed for compressed frames.
 *
 * Return:           A lower bound on the size of the workspace that is passed
 *                   to zstdh_init_dstream().
 */
size_t zstdh_dstream_workspace_bound(size_t max_window_size);

/**
 * zstdh_init_dstream() - initialize a zstd streaming decompression context
 * @max_window_size: The maximum window size allowed for compressed frames.
 * @workspace:       The workspace to emplace the context into. It must outlive
 *                   the returned context.
 * @workspaceSize:   The size of workspace.
 *                   Use zstdh_dstream_workspace_bound(max_window_size) to
 *                   determine how large the workspace must be.
 *
 * Return:           The zstd streaming decompression context.
 */
zstdh_dstream *zstdh_init_dstream(size_t max_window_size, void *workspace,
	size_t workspace_size);

/**
 * zstdh_reset_dstream() - reset the context using parameters from creation
 * @dstream: The zstd streaming decompression context to reset.
 *
 * Resets the context using the parameters from creation. Skips dictionary
 * loading, since it can be reused.
 *
 * Return:   Zero or an error, which can be checked using zstdh_is_error().
 */
size_t zstdh_reset_dstream(zstdh_dstream *dstream);

/**
 * zstdh_decompress_stream() - streaming decompress some of input into output
 * @dstream: The zstd streaming decompression context.
 * @output:  Destination buffer. `output.pos` is updated to indicate how much
 *           decompressed data was written.
 * @input:   Source buffer. `input.pos` is updated to indicate how much data was
 *           read. Note that it may not consume the entire input, in which case
 *           `input.pos < input.size`, and it's up to the caller to present
 *           remaining data again.
 *
 * The `input` and `output` buffers may be any size. Guaranteed to make some
 * forward progress if `input` and `output` are not empty.
 * zstdh_decompress_stream() will not consume the last byte of the frame until
 * the entire frame is flushed.
 *
 * Return:   Returns 0 iff a frame is completely decoded and fully flushed.
 *           Otherwise returns a hint for the number of bytes to use as the
 *           input for the next function call or an error, which can be checked
 *           using zstdh_is_error(). The size hint will never load more than the
 *           frame.
 */
size_t zstdh_decompress_stream(zstdh_dstream *dstream, zstdh_out_buffer *output,
	zstdh_in_buffer *input);

/* ======   Frame Inspection Functions ====== */

/**
 * zstdh_find_frame_compressed_size() - returns the size of a compressed frame
 * @src:      Source buffer. It should point to the start of a zstd encoded
 *            frame or a skippable frame.
 * @src_size: The size of the source buffer. It must be at least as large as the
 *            size of the frame.
 *
 * Return:    The compressed size of the frame pointed to by `src` or an error,
 *            which can be check with zstdh_is_error().
 *            Suitable to pass to ZSTDH_decompress() or similar functions.
 */
size_t zstdh_find_frame_compressed_size(const void *src, size_t src_size);

/**
 * zstdh_register_sequence_producer() - exposes the zstd library function
 * ZSTDH_registerSequenceProducer(). This is used for the block-level external
 * sequence producer API. See upstream zstd.h for detailed documentation.
 */
typedef ZSTDH_sequenceProducer_F zstdh_sequence_producer_f;
void zstdh_register_sequence_producer(
  zstdh_cctx *cctx,
  void* sequence_producer_state,
  zstdh_sequence_producer_f sequence_producer
);

/**
 * struct zstdh_frame_params - zstd frame parameters stored in the frame header
 * @frameContentSize: The frame content size, or ZSTDH_CONTENTSIZE_UNKNOWN if not
 *                    present.
 * @windowSize:       The window size, or 0 if the frame is a skippable frame.
 * @blockSizeMax:     The maximum block size.
 * @frameType:        The frame type (zstd or skippable)
 * @headerSize:       The size of the frame header.
 * @dictID:           The dictionary id, or 0 if not present.
 * @checksumFlag:     Whether a checksum was used.
 *
 * See zstdh_lib.h.
 */
typedef ZSTDH_FrameHeader zstdh_frame_header;

/**
 * zstdh_get_frame_header() - extracts parameters from a zstd or skippable frame
 * @params:   On success the frame parameters are written here.
 * @src:      The source buffer. It must point to a zstd or skippable frame.
 * @src_size: The size of the source buffer.
 *
 * Return:    0 on success. If more data is required it returns how many bytes
 *            must be provided to make forward progress. Otherwise it returns
 *            an error, which can be checked using zstdh_is_error().
 */
size_t zstdh_get_frame_header(zstdh_frame_header *params, const void *src,
	size_t src_size);

/**
 * struct zstdh_sequence - a sequence of literals or a match
 *
 * @offset: The offset of the match
 * @litLength: The literal length of the sequence
 * @matchLength: The match length of the sequence
 * @rep: Represents which repeat offset is used
 */
typedef ZSTDH_Sequence zstdh_sequence;

/**
 * zstdh_compress_sequences_and_literals() - compress an array of zstdh_sequence and literals
 *
 * @cctx: The zstd compression context.
 * @dst: The buffer to compress the data into.
 * @dst_capacity: The size of the destination buffer.
 * @in_seqs: The array of zstdh_sequence to compress.
 * @in_seqs_size: The number of sequences in in_seqs.
 * @literals: The literals associated to the sequences to be compressed.
 * @lit_size: The size of the literals in the literals buffer.
 * @lit_capacity: The size of the literals buffer.
 * @decompressed_size: The size of the input data
 *
 * Return: The compressed size or an error, which can be checked using
 * 	   zstdh_is_error().
 */
size_t zstdh_compress_sequences_and_literals(zstdh_cctx *cctx, void* dst, size_t dst_capacity,
					    const zstdh_sequence *in_seqs, size_t in_seqs_size,
					    const void* literals, size_t lit_size, size_t lit_capacity,
					    size_t decompressed_size);

#endif  /* LINUX_ZSTDH_H */
