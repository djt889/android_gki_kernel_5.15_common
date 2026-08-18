# 12-sew_alloc_adjust

**高阶 DMA-IOMMU 分配标志优化**（R7）。从 OnePlus kswapd_opt 移植，注册 android_vh_adjust_alloc_flags + android_vh_kvmalloc_node_use_vmalloc，order > 3 去掉 __GFP_RECLAIM，避免大块连续分配触发回收卡顿。运行时开关 /sys/kernel/sew_alloc_adjust/enabled。文件：mm/sew_alloc_adjust.c + iommu hook backport
