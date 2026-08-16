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



/*-*************************************
*  Dependencies
***************************************/
#define ZSTDH_DEPS_NEED_MALLOC
#include "error_private.h"
#include "zstd_internal.h"


/*-****************************************
*  Version
******************************************/
unsigned ZSTDH_versionNumber(void) { return ZSTDH_VERSION_NUMBER; }

const char* ZSTDH_versionString(void) { return ZSTDH_VERSION_STRING; }


/*-****************************************
*  ZSTD Error Management
******************************************/
#undef ZSTDH_isError   /* defined within zstdh_internal.h */
/*! ZSTDH_isError() :
 *  tells if a return value is an error code
 *  symbol is required for external callers */
unsigned ZSTDH_isError(size_t code) { return ERR_isError(code); }

/*! ZSTDH_getErrorName() :
 *  provides error code string from function result (useful for debugging) */
const char* ZSTDH_getErrorName(size_t code) { return ERRH_getErrorName(code); }

/*! ZSTDH_getError() :
 *  convert a `size_t` function result into a proper ZSTDH_errorCode enum */
ZSTDH_ErrorCode ZSTDH_getErrorCode(size_t code) { return ERRH_getErrorCode(code); }

/*! ZSTDH_getErrorString() :
 *  provides error code string from enum */
const char* ZSTDH_getErrorString(ZSTDH_ErrorCode code) { return ERRH_getErrorString(code); }
