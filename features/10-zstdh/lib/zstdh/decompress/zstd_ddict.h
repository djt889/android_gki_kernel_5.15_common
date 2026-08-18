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


#ifndef ZSTDH_DDICT_H
#define ZSTDH_DDICT_H

/*-*******************************************************
 *  Dependencies
 *********************************************************/
#include "../common/zstd_deps.h"   /* size_t */
#include <linux/zstdh.h>     /* ZSTDH_DDict, and several public functions */


/*-*******************************************************
 *  Interface
 *********************************************************/

/* note: several prototypes are already published in `zstd.h` :
 * ZSTDH_createDDict()
 * ZSTDH_createDDict_byReference()
 * ZSTDH_createDDict_advanced()
 * ZSTDH_freeDDict()
 * ZSTDH_initStaticDDict()
 * ZSTDH_sizeof_DDict()
 * ZSTDH_estimateDDictSize()
 * ZSTDH_getDictID_fromDict()
 */

const void* ZSTDH_DDict_dictContent(const ZSTDH_DDict* ddict);
size_t ZSTDH_DDict_dictSize(const ZSTDH_DDict* ddict);

void ZSTDH_copyDDictParameters(ZSTDH_DCtx* dctx, const ZSTDH_DDict* ddict);



#endif /* ZSTDH_DDICT_H */
