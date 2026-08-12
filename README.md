# JiuXia Kernel 修改整理（正式版 R1 → R6）

> 本分支（`kernel-customizations-docs`）只包含**修改过的代码文件**（完整内容，保持内核原路径）。
> 基线：`43f7d63d83ca`（android13-5.15-lts + hfdem，2026-07-27 合并）。
> 排除 folio 实验分支（独立不推送）。更新日期：2026-08-13

## 目录结构
```
├── README.md           # 本文件（修改分类总览）
├── update.sh           # 自动更新脚本
└── modified/           # 修改过的完整代码文件（35个，保持内核原路径）
```

## 一、特性移植（新增内建，来自酷安/小米 piano）

| 特性 | 文件 | 引入版本 | 说明 |
|---|---|---|---|
| **mi_sw_sync** | `drivers/dma-buf/sw_sync.c` `sync_debug.{c,h}` `Kconfig` | R2 | 内建 /dev/mi_sw_sync misc 设备（SW_SYNC_IOC_CREATE_FENCE/INC），与 DEBUG_FS 解耦 |
| **binder_sched_opt** | `drivers/android/binder_sched_opt.c` `Kconfig` `Makefile` | R2 | binder 事务调度优化，SF + com.miui.home FIFO/RT 优先级提升 |
| **kshrink_slabd** | `mm/slabd.{c,h}` `mm/Kconfig` `mm/Makefile` | R2 | 异步 slab 回收（Piano 移植），shrink_slab_bypass hook，249 jiffies 节流 |
| **kshrink_lruvecd** | `mm/kshrink_lruvecd.c` `include/linux/kshrink_lruvecd.h` `mm/page_ext.c` | R2 | 异步 lruvec 回收，KSHRINK_SKIP_TRYLOCK，4096 高水位 |
| **r3_audit LSM** | `security/r3_audit_lsm.c` `Kconfig` `Makefile` | R3 | binder_prio 阻断 LSM（R5-fix 改为仅阻断 system 分区路径） |
| **mi_rmap_efficiency** | `mm/mi_rmap_efficiency.c` `include/trace/hooks/mm.h` | R5 | 高 mapcount 页保护（≥32 不回收），动态 keep 阈值 |
| **unionpower** | `drivers/mihw/unionpower/*`(5文件) `drivers/{Kconfig,Makefile}` | R5 | 帧卡顿检测引擎（Power_UnionPowerCore） |
| **ipset + BBR** | `arch/arm64/configs/jiuxia_r6.fragment` | R6 | 内建 ipset 集合框架 + BBR 拥塞控制（默认） |

## 二、系统级修改 / bug 修复

| 修改 | 文件 | 版本 | 说明 |
|---|---|---|---|
| **DRM encoder clone 校验移除** | `drivers/gpu/drm/drm_atomic_helper.c` | R1 | 移除 `drm_atomic_check_valid_clones()`，修显示黑屏 |
| **LZ4 MIN/MAX 宏冲突修复** | `lib/lz4/lz4hc.c` | R1 | `#undef MIN/MAX` 适配 Clang |
| **MLGO regalloc 默认** | `Makefile` | R2 | MLGO regalloc advisor release→default（Debian clang 19 兼容） |
| **vmscan should_be_protected hook** | `mm/vmscan.c` | R5 | hook 签名升级，支持动态优先级阈值 |
| **gki_defconfig 配置开关** | `arch/arm64/configs/gki_defconfig` | 各版 | 启用上述特性的 CONFIG 开关 |

## 三、DDR（DRM）校验移除 — 已确认

> 用户所指 "DDR 校验移除"实际是 **DRM encoder clone 校验移除**（drm 与 ddr 拼写相近）。
> - **文件**：drivers/gpu/drm/drm_atomic_helper.c
> - **版本**：R1（c99f25ab5f0a）
> - **内容**：移除 drm_atomic_check_valid_clones() 函数（26 行）
> - **效果**：不移除会导致校验失败（encoder_mask 与 possible_clones 不匹配返回 -EINVAL）→ atomic commit 失败 → **黑屏但系统可点击**；移除后显示正常

## 四、更新方法（每次正式分支修改后）

```bash
bash ./update.sh <新版本标签>   # 例: R7
# 自动: 提取最新修改文件到 modified/ → 更新 README → commit → push
```

## 五、拉取方法
```bash
git fetch origin kernel-customizations-docs
git checkout kernel-customizations-docs
```
