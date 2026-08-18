# 11-sew_mmap_bypass

**direct-reclaim 节流旁路**（R7）。注册 android_vh_throttle_direct_reclaim_bypass hook，userspace 进程在内存压力下跳过 direct-reclaim throttle 等待，降低 mmap 分配延迟。PF_MEMALLOC 之外放行。文件：mm/sew_mmap_bypass.c + vmscan hook backport
