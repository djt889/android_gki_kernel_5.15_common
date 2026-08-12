# 04-kshrink_lruvecd

异步 lruvec 回收：KSHRINK_SKIP_TRYLOCK / TRYLOCK_DELAY / 4096 高水位，5 个 page trylock hook。与 kshrink_slabd 同属异步回收系列。引入版本 R2。文件：mm/kshrink_lruvecd.c, include/linux/kshrink_lruvecd.h, mm/page_ext.c
