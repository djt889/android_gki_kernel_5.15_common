# SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
# ################################################################
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.
# ################################################################
obj-$(CONFIG_ZSTDH_COMPRESS) += zstdh_compress.o
obj-$(CONFIG_ZSTDH_DECOMPRESS) += zstdh_decompress.o
obj-$(CONFIG_ZSTDH_COMMON) += zstdh_common.o

zstdh_compress-y := \
		zstdh_compress_module.o \
		compress/fse_compress.o \
		compress/hist.o \
		compress/huf_compress.o \
		compress/zstdh_compress.o \
		compress/zstd_compress_literals.o \
		compress/zstd_compress_sequences.o \
		compress/zstd_compress_superblock.o \
		compress/zstd_double_fast.o \
		compress/zstd_fast.o \
		compress/zstd_lazy.o \
		compress/zstd_ldm.o \
		compress/zstd_opt.o \
		compress/zstd_preSplit.o \

zstdh_decompress-y := \
		zstdh_decompress_module.o \
		decompress/huf_decompress.o \
		decompress/zstd_ddict.o \
		decompress/zstdh_decompress.o \
		decompress/zstd_decompress_block.o \

zstdh_common-y := \
		zstdh_common_module.o \
		common/debug.o \
		common/entropy_common.o \
		common/error_private.o \
		common/fse_decompress.o \
		common/zstdh_common.o \
