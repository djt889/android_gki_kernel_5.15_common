// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cryptographic API: LZ4JO (JiuXia optimized LZ4)
 *
 * Based on crypto/lz4.c, using the LZ4JO library (lib/lz4/lz4jo.c) which is
 * a symbol-renamed, AArch64-tuned copy of LZ4 1.10.0 sharing the same NEON
 * decompression accelerator (lib/lz4/lz4armv8).
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/lz4jo.h>
#include <crypto/internal/scompress.h>

struct lz4jo_ctx {
	void *lz4jo_comp_mem;
};

static void *lz4jo_alloc_ctx(struct crypto_scomp *tfm)
{
	void *ctx;

	ctx = vmalloc(LZ4JO_MEM_COMPRESS);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	return ctx;
}

static int lz4jo_init(struct crypto_tfm *tfm)
{
	struct lz4jo_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->lz4jo_comp_mem = lz4jo_alloc_ctx(NULL);
	if (IS_ERR(ctx->lz4jo_comp_mem))
		return -ENOMEM;

	return 0;
}

static void lz4jo_free_ctx(struct crypto_scomp *tfm, void *ctx)
{
	vfree(ctx);
}

static void lz4jo_exit(struct crypto_tfm *tfm)
{
	struct lz4jo_ctx *ctx = crypto_tfm_ctx(tfm);

	lz4jo_free_ctx(NULL, ctx->lz4jo_comp_mem);
}

static int __lz4jo_compress_crypto(const u8 *src, unsigned int slen,
				   u8 *dst, unsigned int *dlen, void *ctx)
{
	int out_len = LZ4JO_compress_default(src, dst,
		slen, *dlen, ctx);

	if (!out_len)
		return -EINVAL;

	*dlen = out_len;
	return 0;
}

static int lz4jo_scompress(struct crypto_scomp *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen,
			   void *ctx)
{
	return __lz4jo_compress_crypto(src, slen, dst, dlen, ctx);
}

static int lz4jo_compress_crypto(struct crypto_tfm *tfm, const u8 *src,
				 unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct lz4jo_ctx *ctx = crypto_tfm_ctx(tfm);

	return __lz4jo_compress_crypto(src, slen, dst, dlen,
				       ctx->lz4jo_comp_mem);
}

static int __lz4jo_decompress_crypto(const u8 *src, unsigned int slen,
				     u8 *dst, unsigned int *dlen, void *ctx)
{
	int out_len;

#if defined(CONFIG_ARM64) && defined(CONFIG_KERNEL_MODE_NEON)
	out_len = LZ4JO_arm64_decompress_safe(src, dst, slen, *dlen, false);
#else
	out_len = LZ4JO_decompress_safe(src, dst, slen, *dlen);
#endif

	if (out_len < 0)
		return -EINVAL;

	*dlen = out_len;
	return 0;
}

static int lz4jo_sdecompress(struct crypto_scomp *tfm, const u8 *src,
			     unsigned int slen, u8 *dst, unsigned int *dlen,
			     void *ctx)
{
	return __lz4jo_decompress_crypto(src, slen, dst, dlen, NULL);
}

static int lz4jo_decompress_crypto(struct crypto_tfm *tfm, const u8 *src,
				   unsigned int slen, u8 *dst,
				   unsigned int *dlen)
{
	return __lz4jo_decompress_crypto(src, slen, dst, dlen, NULL);
}

static struct crypto_alg alg_lz4jo = {
	.cra_name		= "lz4jo",
	.cra_driver_name	= "lz4jo-generic",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct lz4jo_ctx),
	.cra_module		= THIS_MODULE,
	.cra_init		= lz4jo_init,
	.cra_exit		= lz4jo_exit,
	.cra_u			= { .compress = {
	.coa_compress		= lz4jo_compress_crypto,
	.coa_decompress		= lz4jo_decompress_crypto } }
};

static struct scomp_alg scomp = {
	.alloc_ctx		= lz4jo_alloc_ctx,
	.free_ctx		= lz4jo_free_ctx,
	.compress		= lz4jo_scompress,
	.decompress		= lz4jo_sdecompress,
	.base			= {
		.cra_name	= "lz4jo",
		.cra_driver_name = "lz4jo-scomp",
		.cra_module	 = THIS_MODULE,
	}
};

static int __init lz4jo_mod_init(void)
{
	int ret;

	ret = crypto_register_alg(&alg_lz4jo);
	if (ret)
		return ret;

	ret = crypto_register_scomp(&scomp);
	if (ret) {
		crypto_unregister_alg(&alg_lz4jo);
		return ret;
	}

	return ret;
}

static void __exit lz4jo_mod_fini(void)
{
	crypto_unregister_alg(&alg_lz4jo);
	crypto_unregister_scomp(&scomp);
}

subsys_initcall(lz4jo_mod_init);
module_exit(lz4jo_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LZ4JO Compression Algorithm");
MODULE_ALIAS_CRYPTO("lz4jo");
