# Sew Kernel

基于 **hfdem** 内核基线，合并 Android GKI 上游源码，叠加 Sew 定制优化的自定义 Android 内核。

- 基线分支：`android13-5.15-lts-2026-07`
- 上游：Android Common Kernel `android13-5.15-lts`
- 当前版本：Linux 5.15.211（Android 13 GKI）· **R7.2**
- 构建：LLVM=1（Clang），ThinLTO

## 修改与移植特性

### 定制压缩算法
- **zstdh** — 定制 zstd（1.5.7 魔改，符号重命名 ZSTD_→ZSTDH_），5 项优化：
  - 压缩哈希表复用（zram 逐页提速约 26%）
  - 解压 decodeSequence AArch64 优化（上游 #4418 + #4509）
  - Huffman 解压 4-way（#4413）
  - COPY8 优化（#4414）
  - get1BlockSummary 4 路累加（#4429）
  - zram 压缩率 ≈75%（逐页 4KB 场景），比 lz4/lz4hc 好 20-35 个百分点

### 移植的特性（内建）
- **sew_alloc_adjust** — 高阶 DMA-IOMMU 分配标志优化（`android_vh_adjust_alloc_flags` + `android_vh_kvmalloc_node_use_vmalloc` 注册，order > 3 去掉 `__GFP_RECLAIM`，缓解高负载掉帧）。运行时开关 `/sys/kernel/sew_alloc_adjust/enabled`
- **sew_mmap_bypass** — direct-reclaim 节流旁路（`android_vh_throttle_direct_reclaim_bypass`，PF_MEMALLOC 之外放行）
- **mi_sw_sync** — 内建 `/dev/mi_sw_sync` misc 设备
- **binder_sched_opt** — binder UI 调度优化（SurfaceFlinger / com.miui.home FIFO/RT 优先级）
- **kshrink_slabd** — 异步 slab 回收
- **kshrink_lruvecd** — 异步 lruvec 回收（15 项重构，按 THP 页数硬上限）
- **sew_audit LSM** — 模块加载阻断（前缀匹配 binder_prio/moon_/kshrink_，避免与内建功能重复注册 hook）
- **mi_rmap_efficiency** — 高 mapcount 页保护
- **unionpower** — 帧卡顿检测引擎
- **ipset** — netfilter 集合框架
- **BBR** — TCP 拥塞控制（系统默认）

### 修复与调整
- binder_alloc `kcalloc` → `kvcalloc`（8G 大 binder 缓冲避免 OOM）
- 移除 DRM encoder clone 校验（修显示黑屏）
- 修复 LZ4 MIN/MAX 宏冲突（Clang 兼容）
- MLGO regalloc advisor release→default（Debian clang 19 兼容）
- should_be_protected hook 签名升级
- 关闭 F2FS lz4hc（`/data` 分区未用压缩，lz4hc 变体无意义，lz4 保留）

## 来源说明
- **参考社区方案**：binder_sched_opt（借鉴社区 Binder 调度思路，独立实现类似优化）
- **小米 MiCode piano 移植**：kshrink_slabd、mi_rmap、unionpower
- **OnePlus kswapd_opt 移植**：sew_alloc_adjust（alloc_adjust_flags + kvmalloc_adjust_flags）
- **Sew 自研**：zstdh 压缩算法、sew_audit LSM
- **原生改造**：mi_sw_sync
- 详细分类见 `kernel-customizations-docs` 分支

## 构建

```bash
make O=out ARCH=arm64 LLVM=1 -j$(nproc) Image
```

工具链：Android Clang。刷机包使用 AnyKernel3，仅替换 boot 分区 Image.gz。

## 致谢
- **@hfdem** — Android 13 GKI 基线维护者
- **@Amktiao（酷安）** 及模块来源贡献者
- **小米 MiCode piano** — 特性移植来源
- **OnePlus OSS** — kswapd_opt 优化来源
- Android Common Kernel 上游
