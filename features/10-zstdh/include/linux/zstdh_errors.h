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

#ifndef ZSTDH_ERRORS_H_398273423
#define ZSTDH_ERRORS_H_398273423


/* =====   ZSTDHERRORLIB_API : control library symbols visibility   ===== */
#define ZSTDHERRORLIB_VISIBLE 

#ifndef ZSTDHERRORLIB_HIDDEN
#  if (__GNUC__ >= 4) && !defined(__MINGW32__)
#    define ZSTDHERRORLIB_HIDDEN __attribute__ ((visibility ("hidden")))
#  else
#    define ZSTDHERRORLIB_HIDDEN
#  endif
#endif

#define ZSTDHERRORLIB_API ZSTDHERRORLIB_VISIBLE

/*-*********************************************
 *  Error codes list
 *-*********************************************
 *  Error codes _values_ are pinned down since v1.3.1 only.
 *  Therefore, don't rely on values if you may link to any version < v1.3.1.
 *
 *  Only values < 100 are considered stable.
 *
 *  note 1 : this API shall be used with static linking only.
 *           dynamic linking is not yet officially supported.
 *  note 2 : Prefer relying on the enum than on its value whenever possible
 *           This is the only supported way to use the error list < v1.3.1
 *  note 3 : ZSTDH_isError() is always correct, whatever the library version.
 **********************************************/
typedef enum {
  ZSTDH_error_no_error = 0,
  ZSTDH_error_GENERIC  = 1,
  ZSTDH_error_prefix_unknown                = 10,
  ZSTDH_error_version_unsupported           = 12,
  ZSTDH_error_frameParameter_unsupported    = 14,
  ZSTDH_error_frameParameter_windowTooLarge = 16,
  ZSTDH_error_corruption_detected = 20,
  ZSTDH_error_checksum_wrong      = 22,
  ZSTDH_error_literals_headerWrong = 24,
  ZSTDH_error_dictionary_corrupted      = 30,
  ZSTDH_error_dictionary_wrong          = 32,
  ZSTDH_error_dictionaryCreation_failed = 34,
  ZSTDH_error_parameter_unsupported   = 40,
  ZSTDH_error_parameter_combination_unsupported = 41,
  ZSTDH_error_parameter_outOfBound    = 42,
  ZSTDH_error_tableLog_tooLarge       = 44,
  ZSTDH_error_maxSymbolValue_tooLarge = 46,
  ZSTDH_error_maxSymbolValue_tooSmall = 48,
  ZSTDH_error_cannotProduce_uncompressedBlock = 49,
  ZSTDH_error_stabilityCondition_notRespected = 50,
  ZSTDH_error_stage_wrong       = 60,
  ZSTDH_error_init_missing      = 62,
  ZSTDH_error_memory_allocation = 64,
  ZSTDH_error_workSpace_tooSmall= 66,
  ZSTDH_error_dstSize_tooSmall = 70,
  ZSTDH_error_srcSize_wrong    = 72,
  ZSTDH_error_dstBuffer_null   = 74,
  ZSTDH_error_noForwardProgress_destFull = 80,
  ZSTDH_error_noForwardProgress_inputEmpty = 82,
  /* following error codes are __NOT STABLE__, they can be removed or changed in future versions */
  ZSTDH_error_frameIndex_tooLarge = 100,
  ZSTDH_error_seekableIO          = 102,
  ZSTDH_error_dstBuffer_wrong     = 104,
  ZSTDH_error_srcBuffer_wrong     = 105,
  ZSTDH_error_sequenceProducer_failed = 106,
  ZSTDH_error_externalSequences_invalid = 107,
  ZSTDH_error_maxCode = 120  /* never EVER use this value directly, it can change in future versions! Use ZSTDH_isError() instead */
} ZSTDH_ErrorCode;

ZSTDHERRORLIB_API const char* ZSTDH_getErrorString(ZSTDH_ErrorCode code);   /*< Same as ZSTDH_getErrorName, but using a `ZSTDH_ErrorCode` enum argument */



#endif /* ZSTDH_ERRORS_H_398273423 */
