# JiuXia Kernel 修改整理（正式版 R1 → R6）

> 本分支（kernel-customizations-docs）按**特性**整理正式版（android13-5.15-lts-2026-07）相对基线 43f7d63d83ca 的全部修改。
> 每个特性一个文件夹，含**修改过的完整代码文件** + 说明。排除 folio 实验分支。
> 更新日期：2026-08-13

## 目录结构

    kernel-customizations-docs (orphan, 无完整内核)
    ├── README.md            # 本文件（总览）
    ├── update.sh            # 自动更新脚本
    └── features/            # 按特性分类
        ├── 01-mi_sw_sync/
        ├── 02-coolapk-binder_sched_opt/
        ├── 03-xiaomi-kshrink_slabd/
        ├── 04-kshrink_lruvecd/
        ├── 05-jiuxia-r3_audit_lsm/
        ├── 06-xiaomi-mi_rmap/
        ├── 07-xiaomi-unionpower/
        ├── 08-builtin-ipset_bbr/
        └── 09-base-fixes/

## 特性总览

| # | 特性 | 来源 | 版本 | 说明 |
|---|---|---|---|---|
| 01 | mi_sw_sync | 原生改造 | R2 | 内建 /dev/mi_sw_sync misc 设备 |
| 02 | binder_sched_opt | **酷安** (Moon) | R2 | binder 调度优化 (SF/桌面 FIFO-RT) |
| 03 | kshrink_slabd | **小米 piano** | R2 | 异步 slab 回收 |
| 04 | kshrink_lruvecd | 异步回收系列 | R2 | 异步 lruvec 回收 |
| 05 | r3_audit LSM | **JiuXia 自研** | R3 | binder_prio 阻断 + 审计 |
| 06 | mi_rmap | **小米 piano** | R5 | 高 mapcount 页保护 |
| 07 | unionpower | **小米 MIUI** | R5 | 帧卡顿检测 |
| 08 | ipset + BBR | 内建 | R6 | 网络优化 |
| 09 | 基础修复 | — | R1-R6 | DRM/LZ4/MLGO/defconfig |

## 来源说明（重要）

- **酷安优化**：仅 binder_sched_opt（Moon Binder 调度）确认来自酷安。
- **小米 piano 移植**：kshrink_slabd、mi_rmap、unionpower 确认来自小米 MiCode piano。
- **kshrink_lruvecd**：来源无明确标记，与 kshrink_slabd 同属异步回收系列（待确认，可能酷安/小米）。
- **mi_sw_sync**：基于内核原生 sw_sync 改造。
- **r3_audit LSM**：JiuXia 自研。

## 更新方法（每次正式分支修改后）

    bash ./update.sh <新版本标签>   # 例: R7
    # 自动: 从正式分支提取最新修改文件到 features/ → 更新 → commit → push

## 拉取方法

    git fetch origin kernel-customizations-docs
    git checkout kernel-customizations-docs
