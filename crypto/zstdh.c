// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cryptographic API.
 *
 * Copyright (c) 2017-present, Facebook, Inc.
 */
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/vmalloc.h>
#include <linux/zstdh.h>
#include <crypto/internal/scompress.h>


static int __read_mostly compression_level = 1;

int set_compression_level_zstdh(const char *val, const struct kernel_param *kp)
{
	int temp, ret;

	ret = sscanf(val, "%i", &temp);
	if (ret == -EINVAL) {
		return -EINVAL;
	}

	if (temp == 0) {
		temp = 1;
	} else if (temp > zstdh_max_clevel()) {
		temp = zstdh_max_clevel();
	} else if (temp < zstdh_min_clevel()) {
		temp = zstdh_min_clevel();
	}

	*((int *)kp->arg) = temp;

	return 0;
}

module_param_call(compression_level, set_compression_level_zstdh, param_get_int, &compression_level, 0644);

struct zstdh_ctx {
	zstdh_cctx *cctx;
	zstdh_dctx *dctx;
	void *cwksp;
	void *dwksp;
	/*
	 * zstdh: reuse hash table across pages. zram uses per-CPU streams,
	 * so each CPU has its own tfm/cctx - safe to keep the hash warm.
	 */
	bool first_compress;
};

static zstdh_parameters zstdh_params(void)
{
	return zstdh_get_params(compression_level, PAGE_SIZE);
}

static int zstdh_comp_init(struct zstdh_ctx *ctx)
{
	int ret = 0;
	const zstdh_parameters params = zstdh_params();
	const size_t wksp_size = zstdh_cctx_workspace_bound(&params.cParams);

	ctx->cwksp = vzalloc(wksp_size);
	if (!ctx->cwksp) {
		ret = -ENOMEM;
		goto out;
	}

	ctx->cctx = zstdh_init_cctx(ctx->cwksp, wksp_size);
	if (!ctx->cctx) {
		ret = -EINVAL;
		goto out_free;
	}
	ctx->first_compress = true;
out:
	return ret;
out_free:
	vfree(ctx->cwksp);
	goto out;
}

static int zstdh_decomp_init(struct zstdh_ctx *ctx)
{
	int ret = 0;
	const size_t wksp_size = zstdh_dctx_workspace_bound();

	ctx->dwksp = vzalloc(wksp_size);
	if (!ctx->dwksp) {
		ret = -ENOMEM;
		goto out;
	}

	ctx->dctx = zstdh_init_dctx(ctx->dwksp, wksp_size);
	if (!ctx->dctx) {
		ret = -EINVAL;
		goto out_free;
	}
out:
	return ret;
out_free:
	vfree(ctx->dwksp);
	goto out;
}

static void zstdh_comp_exit(struct zstdh_ctx *ctx)
{
	vfree(ctx->cwksp);
	ctx->cwksp = NULL;
	ctx->cctx = NULL;
}

static void zstdh_decomp_exit(struct zstdh_ctx *ctx)
{
	vfree(ctx->dwksp);
	ctx->dwksp = NULL;
	ctx->dctx = NULL;
}

static int __zstd_init(void *ctx)
{
	int ret;

	ret = zstdh_comp_init(ctx);
	if (ret)
		return ret;
	ret = zstdh_decomp_init(ctx);
	if (ret)
		zstdh_comp_exit(ctx);
	return ret;
}

static void *zstdh_alloc_ctx(struct crypto_scomp *tfm)
{
	int ret;
	struct zstdh_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ret = __zstd_init(ctx);
	if (ret) {
		kfree(ctx);
		return ERR_PTR(ret);
	}

	return ctx;
}

static int zstdh_init(struct crypto_tfm *tfm)
{
	struct zstdh_ctx *ctx = crypto_tfm_ctx(tfm);

	return __zstd_init(ctx);
}

static void __zstd_exit(void *ctx)
{
	zstdh_comp_exit(ctx);
	zstdh_decomp_exit(ctx);
}

static void zstdh_free_ctx(struct crypto_scomp *tfm, void *ctx)
{
	__zstd_exit(ctx);
	kfree_sensitive(ctx);
}

static void zstdh_exit(struct crypto_tfm *tfm)
{
	struct zstdh_ctx *ctx = crypto_tfm_ctx(tfm);

	__zstd_exit(ctx);
}

static int __zstd_compress(const u8 *src, unsigned int slen,
			   u8 *dst, unsigned int *dlen, void *ctx, bool reuse)
{
	size_t out_len;
	struct zstdh_ctx *zctx = ctx;
	const zstdh_parameters params = zstdh_params();

	/*
	 * zstdh: reuse the hash table across pages for the comp interface
	 * (used by zram's per-CPU streams, each CPU has its own tfm/cctx).
	 * The first call does a full init (zstdh_compress_cctx sets all params
	 * and the hash table); subsequent calls go through
	 * zstdh_compress_cctx_reuse(), which now maps to ZSTDH_compress2()
	 * (reset_session_only + stable buffers + dstSizeTooSmall check), keeping
	 * the hash warm while fixing the broken output of the old reuse path.
	 * The scomp interface keeps a full reset because its ctx may be shared
	 * between callers, so reusing the hash would race.
	 */
	if (reuse && !zctx->first_compress) {
		out_len = zstdh_compress_cctx_reuse(zctx->cctx, dst, *dlen,
						     src, slen, &params);
	} else {
		out_len = zstdh_compress_cctx(zctx->cctx, dst, *dlen,
					       src, slen, &params);
		if (reuse)
			zctx->first_compress = false;
	}
	if (zstdh_is_error(out_len))
		return -EINVAL;
	*dlen = out_len;
	return 0;
}

static int zstdh_compress(struct crypto_tfm *tfm, const u8 *src,
			 unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct zstdh_ctx *ctx = crypto_tfm_ctx(tfm);

	return __zstd_compress(src, slen, dst, dlen, ctx, true);
}

static int zstdh_scompress(struct crypto_scomp *tfm, const u8 *src,
			  unsigned int slen, u8 *dst, unsigned int *dlen,
			  void *ctx)
{
	return __zstd_compress(src, slen, dst, dlen, ctx, false);
}

static int __zstd_decompress(const u8 *src, unsigned int slen,
				 u8 *dst, unsigned int *dlen, void *ctx)
{
	size_t out_len;
	struct zstdh_ctx *zctx = ctx;

	out_len = zstdh_decompress_dctx(zctx->dctx, dst, *dlen, src, slen);
	if (zstdh_is_error(out_len))
		return -EINVAL;
	*dlen = out_len;
	return 0;
}

static int zstdh_decompress(struct crypto_tfm *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct zstdh_ctx *ctx = crypto_tfm_ctx(tfm);

	return __zstd_decompress(src, slen, dst, dlen, ctx);
}

static int zstdh_sdecompress(struct crypto_scomp *tfm, const u8 *src,
				unsigned int slen, u8 *dst, unsigned int *dlen,
				void *ctx)
{
	return __zstd_decompress(src, slen, dst, dlen, ctx);
}

static struct crypto_alg alg = {
	.cra_name		= "zstdh",
	.cra_driver_name	= "zstdh-generic",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct zstdh_ctx),
	.cra_module		= THIS_MODULE,
	.cra_init		= zstdh_init,
	.cra_exit		= zstdh_exit,
	.cra_u			= { .compress = {
	.coa_compress		= zstdh_compress,
	.coa_decompress		= zstdh_decompress } }
};

static struct scomp_alg scomp = {
	.alloc_ctx		= zstdh_alloc_ctx,
	.free_ctx		= zstdh_free_ctx,
	.compress		= zstdh_scompress,
	.decompress		= zstdh_sdecompress,
	.base			= {
		.cra_name	= "zstdh",
		.cra_driver_name = "zstdh-scomp",
		.cra_module	 = THIS_MODULE,
	}
};

static int __init zstdh_mod_init(void)
{
	int ret;

	ret = crypto_register_alg(&alg);
	if (ret)
		return ret;

	ret = crypto_register_scomp(&scomp);
	if (ret)
		crypto_unregister_alg(&alg);

	return ret;
}

static void __exit zstdh_mod_fini(void)
{
	crypto_unregister_alg(&alg);
	crypto_unregister_scomp(&scomp);
}

subsys_initcall(zstdh_mod_init);
module_exit(zstdh_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Zstdh Compression Algorithm");
MODULE_ALIAS_CRYPTO("zstdh");
