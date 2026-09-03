# Sew Kernel

基于 **hfdem** 内核基线，合并 Android GKI 上游源码，叠加 Sew 定制优化的自定义 Android 内核。

- 基线分支：`android13-5.15-lts-2026-07`
- 上游：Android Common Kernel `android13-5.15-lts`（R7.6 完整合并上游 57 提交）
- 当前版本：Linux 5.15.211（Android 13 GKI）· **R8**（2026-09-03）
- 内核版本串：`5.15.211-Sew-R8-20260903`（刷后 `uname -r` 可验证）
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
- **sew_mmap_bypass** — direct-reclaim 节流旁路（`android_vh_throttle_direct_reclaim_bypass`，PF_MEMALLOC 之外放行；R7.3 起收窄到四个 cpuset 组）
- **mi_sw_sync** — 内建 `/dev/mi_sw_sync` misc 设备
- **binder_sched_opt** — binder 调度优化（uclamp 方案）：`android_vh_binder_transaction_received` 触发时为 binder 线程提升 `uclamp_min` 频率下限，`android_vh_binder_restore_priority` 成对恢复。运行时参数 `/sys/module/binder_sched_opt/parameters/{enabled,mode,uclamp_min}`：mode 0 关闭 / 1 uclamp floor（默认）/ 2 RT 提升（历史行为 A/B），uclamp_min 默认 256；诊断接口 `/proc/binder_sched_opt_status`
- **kshrink_slabd** — 异步 slab 回收（R8 可选升级：VIP 回调合并 + 频率感知强度，默认关闭）
- **kshrink_lruvecd** — 异步 lruvec 回收（15 项重构，按 THP 页数硬上限）
- **sew_audit LSM** — 模块加载阻断（前缀匹配 binder_prio/moon_/kshrink_，避免与内建功能重复注册 hook）
- **mi_rmap_efficiency** — 高 mapcount 页保护
- **unionpower** — 帧卡顿检测引擎
- **ipset** — netfilter 集合框架（R7.7 起由 fragment 改入 gki_defconfig 持久化）
- **BBR** — TCP 拥塞控制（系统默认，同上持久化）

### R8 可选模块（默认关闭）
OS4 移植 wave1+wave2 合入，全部 `default n`，需手动开启 CONFIG；**R8 默认行为与 R7.9 零差异**：
- **sew_yield_penalty** — yield 换帧边界睡眠（uid 护栏）
- **sew_qos_inherit** — futex 等待链 QOS 继承（uclamp 兜底）
- **sew_rtload** — RT 策略请求统计（kprobe）
- **sew_unfairmem** — SF/场景任务水位放宽（默认 LOWER 方向）
- **sew_mi_reclaim** — 回收路径纯观测（零行为修改）
- **sew_scene_swappiness** — 场景 swappiness（默认 passthrough，不覆盖附加模块）
- **sew_dynamic_readahead** — uid 预读窗口
- **sew_rss_monitor** — RSS 探测
- **sew_bootmonitor** — boot 锚点 + console-ramoops 持久化
- **MI_BOOT_TIME** — 开机耗时统计（开源树逐字移植）
- 另含 4 个新 vendor hook（mm/sched/vmscan）与 `task_work_add` 新增 EXPORT

### 修复与调整
- binder_alloc `kcalloc` → `kvcalloc`（8G 大 binder 缓冲避免 OOM）
- 修复 boeffla wakelock blocker 三处 1 字节越界写（R7.9 FIX-001，崩溃审计发现：`len >` → `>=` 两处 + 匹配缓冲 52→53）
- 移除 DRM encoder clone 校验（修显示黑屏）
- 修复 LZ4 MIN/MAX 宏冲突（Clang 兼容）
- MLGO regalloc advisor release→default（Debian clang 19 兼容）
- should_be_protected hook 签名升级
- 关闭 F2FS lz4hc（`/data` 分区未用压缩，lz4hc 变体无意义，lz4 保留）

## 版本演进
- **R7.3** — binder 运行时开关 + policy-mask 准入修复；mmap_bypass 收窄到四个 cpuset 组；sew_audit 补 /data/adb/modules 与 /system_dlkm 路径
- **R7.4** — 回收记账 / hook ABI / MGLRU 交接六项修复（mmap_bypass cgroup_mutex 死锁、page_ext_ops 顺序、NR_ISOLATED 记账、slabd 节流竞态等）
- **R7.5** — 删 SF RT 提升、恢复 PAC/BTI、去第三方构建开关（Polly/O3）、binder_alloc kvfree 位置补齐
- **R7.6** — 完整合并上游 android13-5.15-lts 57 提交（Binder UAF/F2FS 死锁/PSI/I2C 修复）；binder_sched_opt 重写为 uclamp 方案；正式构建恢复 ThinLTO
- **R7.7** — ipset + BBR 从 fragment（静默失效 17 天）改写 gki_defconfig 持久化
- **R7.9** — FIX-001：boeffla wakelock blocker 三处 1 字节越界写修复
- **R8**（2026-09-03）— OS4 移植 wave1+wave2 合入：8 个新调度/内存模块 + sew_bootmonitor + MI_BOOT_TIME + slabd 频率感知升级 + 4 新 vendor hook，全部默认 n

## 来源说明
- **参考社区方案**：binder_sched_opt（社区 Binder 调度思路为启发起点，独立实现并经多轮演进为 uclamp 方案）
- **小米 MiCode piano 移植**：kshrink_slabd、mi_rmap、unionpower
- **OnePlus kswapd_opt 移植**：sew_alloc_adjust（alloc_adjust_flags + kvmalloc_adjust_flags）
- **OS4 移植（R8）**：sew_yield_penalty 等 8 模块 + sew_bootmonitor + MI_BOOT_TIME（默认关闭）
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
- **OS4** — R8 可选模块移植来源
- Android Common Kernel 上游
