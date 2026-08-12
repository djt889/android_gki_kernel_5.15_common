# JiuXia Kernel

基于 **hfdem** 内核基线，合并 Android GKI 上游源码，叠加 JiuXia 定制优化的自定义 Android 内核。

- 基线分支：`android13-5.15-lts-2026-07`
- 上游：Android Common Kernel `android13-5.15-lts`
- 当前版本：Linux 5.15.211（Android 13 GKI）· **R6.1**
- 构建：LLVM=1（Clang），ThinLTO

## 修改与移植特性

### 移植的特性（内建）
- **mi_sw_sync** — 内建 `/dev/mi_sw_sync` misc 设备（SW_SYNC_IOC_CREATE_FENCE/INC），与 DEBUG_FS 解耦
- **binder_sched_opt** — binder UI 调度优化（酷安/Moon）：SurfaceFlinger 与 com.miui.home 的 FIFO/RT 优先级提升
- **kshrink_slabd** — 异步 slab 回收（249 jiffies 节流，freezable kthread）
- **kshrink_lruvecd** — 异步 lruvec 回收（4096 高水位，page trylock hooks）
- **r3_audit LSM** — binder_prio 模块加载阻断 + 审计（仅阻断 system 分区路径，放行 recovery）
- **mi_rmap_efficiency** — 高 mapcount 页保护（≥32 不回收），动态 keep 阈值（小米 piano 移植）
- **unionpower** — 帧卡顿检测引擎（小米 MIUI 移植）
- **ipset** — netfilter 集合框架（16 种 set 类型，内建）
- **BBR** — TCP 拥塞控制（设为系统默认）

### 修复与调整
- 移除 DRM encoder clone 校验（修显示黑屏）
- 修复 LZ4 MIN/MAX 宏冲突（Clang 兼容）
- MLGO regalloc advisor release→default（Debian clang 19 兼容）
- should_be_protected hook 签名升级（支持动态优先级阈值）
- 新增 `arch/arm64/configs/jiuxia_r6.fragment` 可复现配置

## 来源说明
- **酷安优化**：binder_sched_opt（Moon Binder）
- **小米 MiCode piano 移植**：kshrink_slabd、mi_rmap、unionpower
- **JiuXia 自研**：r3_audit LSM
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
- Android Common Kernel 上游
