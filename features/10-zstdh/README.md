# 10-zstdh

**定制 zstd 压缩算法**（R6.3）。基于 zstd 1.5.7 符号重命名魔改（ZSTD_→ZSTDH_），5 项优化：压缩哈希表复用、decodeSequence AArch64(#4418+#4509)、Huffman 4-way(#4413)、COPY8(#4414)、get1BlockSummary 4路累加(#4429)。zram 逐页 4KB 压缩率 ≈75%。文件：lib/zstdh/（完整库）、crypto/zstdh.c、include/linux/zstdh*.h
