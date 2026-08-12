# JiuXia Kernel

基于 **hfdem** 内核基线，并合并 Android GKI 上游源码构建的自定义 Android 内核。

- 基线分支：`android13-5.15-lts-2026-07`
- 上游：Android Common Kernel `android13-5.15-lts`
- 当前基线版本：Linux 5.15.211（Android 13 GKI）
- 本仓库在上游与 hfdem 基线之上进行定制与优化合并

## 来源与范围

本文按 Git 历史区分 hfdem 基线与 JiuXia 后续增量。“hfdem 基线已有内容”指 JiuXia R1 的父提交 `43f7d63d` 中已经存在、且可由本仓库历史复核的配置、补丁或组件；不代表全部为 hfdem 原创，也不保证在所有设备、配置或负载下产生相同收益。

`43f7d63d` 同时合并了 Android Common Kernel LTS，因此该基线包含上游、Android、回移及第三方来源的内容。下列项目只说明其在 JiuXia 之前的 hfdem 基线中已存在，不将它们笼统归为 hfdem 独有实现。

## hfdem 基线已有内容

### 调度、I/O 与运行时

- **SSG I/O 调度器**：已内建并设为默认可用（历史提交：`a8b7c1f`、`cbf9873`）。
- **schedhorizon**：基线中已启用 CPUFreq 调度能力（`5624117`）。
- **RCU 与工作队列策略**：包含 `RCU_LAZY`（`0a0bb60`）与 `wq_power_efficient`（`8cbdcc2`）配置。
- **运行时配置**：包含 wakelock blocker 相关补丁（`0d7b0bb`）及 `CONFIG_HZ=250`（`122a7fc`）。

### 内存、压缩与数据路径

- **ZRAM**：已内建，历史中包含 Xiaomi ZRAM 相关补丁（`66c4cfc`、`f0635b9`）。
- **压缩与同步路径**：历史中包含 LZ4、Zstd 更新，以及 DMA-BUF `sync_file` ioctl 路径优化。

### 构建相关

- 基线历史包含 LLVM Polly（`0373515`）、`-O3`（`6cafdb4`）及面向 Cortex-A510 的编译优化相关配置或补丁。

### 安全、性能与兼容性取舍

基线历史中包含关闭 Spectre-BHB 缓解（`1cccc27`）以及关闭 BTI/PAC（`97151dd`）的配置/修改。这些属于安全性、性能和兼容性之间的取舍，可能降低针对相应攻击面的缓解能力；不应视为无条件推荐的性能特性。请根据设备、ROM、威胁模型和安全要求自行评估。

## 当前版本

**JiuXia-Kernel-R2-20260729**

R2 完整继承 R1，并将四项酷安 5.15 通用优化模块移植为内核内建，去除对预编译 `.ko` 的依赖。

## JiuXia 后续增量

### R1 变更（R2 全部继承）

R1 提交 `c99f25a` 相对 hfdem 基线仅修改以下内容：

- **显示兼容性调整**：移除 `drivers/gpu/drm/drm_atomic_helper.c` 中的 `drm_atomic_check_valid_clones()`。
- **LZ4 编译兼容性**：在 `lib/lz4/lz4hc.c` 中先 `#undef MIN` / `#undef MAX`，再定义 LZ4 宏，避免 Clang 环境的宏冲突。
- **版本标识**：设置 `CONFIG_LOCALVERSION = -hfdem-JiuXia-R1-20260727-033206`。

### R2 内建移植

以下四项功能由 R2 提交 `5504757` 以源码方式引入或内建；它们属于 JiuXia R2 的后续增量，**不是 hfdem 基线原有的内建功能**。

1. **mi_sw_sync** — 内建 `mi_sw_sync` misc 设备
   - 提供 `SW_SYNC_IOC_CREATE_FENCE` / `SW_SYNC_IOC_INC` ioctl。
   - 解除 `SW_SYNC` 对 `DEBUG_FS` 的依赖。
   - 源码：`drivers/dma-buf/sw_sync.c`、`sync_debug.{c,h}`。

2. **moon_binder** — Binder UI 调度优化
   - 注册三个 Android vendor hook：`binder_trans` / `binder_set_priority` / `binder_proc_transaction_finish`。
   - 针对 SurfaceFlinger 事务及 `com.miui.home` 等关键 UI 线程调整 FIFO/RT 调度优先级。
   - 暴露 `/proc/binder_sched_opt_status` 状态节点。
   - 源码：`drivers/android/binder_sched_opt.c`。

3. **moon_kshrink_slabd** — 异步 Slab 回收
   - 通过 `shrink_slab_bypass` vendor hook 调整 Slab 回收路径。
   - 249 jiffies（`0xf9`）节流间隔，并排除 `com.miui.home`。
   - 使用可冻结内核线程异步执行回收。
   - 源码：`mm/slabd.{c,h}`。

4. **moon_kshrink_lruvecd** — 异步 LRUvec 回收
   - 定义 `KSHRINK_SKIP_TRYLOCK` / `KSHRINK_TRYLOCK_DELAY` 标志。
   - 使用 5 个 page trylock 相关 vendor hook，并以 4096 为迁移队列高水位限制。
   - 源码：`mm/kshrink_lruvecd.c`、`include/linux/kshrink_lruvecd.h`。

### 构建调整

- MLGO 寄存器分配 advisor：`release` → `default`（兼容 Debian clang 19）。

## 构建

```bash
make O=out ARCH=arm64 LLVM=1 \
  KCFLAGS="-mllvm -regalloc-enable-advisor=default \
           -Wno-error=unused-but-set-variable \
           -Wno-error=unused-const-variable \
           -Wno-error=unused-variable" \
  -j$(nproc)
```

工具链：Android Clang `clang-r547379`。

刷机包使用 AnyKernel3 打包，仅替换 boot 分区 `Image.gz`，不含 DTB/DTBO/vendor_boot/init_boot/ramdisk。

## 致谢

- **@hfdem** — 本项目所用 Android 13 GKI 基线的维护者；其基线在 JiuXia 变更前已包含本文列出的调度、I/O、内存、压缩及构建相关配置/补丁。
- **@Amktiao（酷安）** 及四项模块的外部来源贡献者 — 按模块来源信息致谢；本仓库完成 R2 内建移植。
- Android Common Kernel 上游与各子系统维护者。
