# 14-os4port-mm

**MIUI OS4 内存管理移植集**（dada 设备 vendor 模块，R8 合入）。六个 SEW_*
特性全部 default n；三个 vendor hook 中两个为自设计（hook 名对齐 6.6 的
同名 hook），一个沿用 OS4 原路径。

## sew_unfairmem（~170 行，CONFIG_SEW_UNFAIRMEM）

SF / 场景任务的分配水位 VIP：**下探**储备——把 `android_vh_get_page_wmark`
算出的水位下调，放宽的比例上限 50%（`mark - mark * relax_pct / 100`，且
不低于 mark/2）。

- **方向是 LOWER 不是抬高**：`__zone_watermark_ok()` 的通过条件是空闲页
  *超过* 水位，抬 mark 反而把 VIP 更早推进 slowpath（reviewer 实证的方向
  反转已修）
- 参数节点 `/proc/sew_unfairmem`（sf_pid / scene_tid / relax_pct）

## sew_mi_reclaim（~110 行，CONFIG_SEW_MI_RECLAIM）

回收路径纯观测：`android_vh_alloc_pages_slowpath_start` 计数 +
`android_vh_direct_reclaim_end` 回收结局统计。**零行为修改**。

## sew_scene_swappiness（188 行，CONFIG_SEW_SCENE_SWAPPINESS）

按场景（default/game/camera/browser）切 swappiness，写
`/proc/sew_scene_swappiness/scene`。**默认 passthrough 是硬约束**：scene
为 default（开机态）时不写 *swappiness——附加模块会把 vm.swappiness 设为
1，覆盖它会造成全局行为漂移。场景表用 -1 表示不干预。

## sew_dynamic_readahead（106 行，CONFIG_SEW_DYNAMIC_READAHEAD）

per-uid 的 fault_around 黑名单 + 预读窗口缩放。原版的 ra_order bypass 已
裁掉（依赖的 hook 在闭源模块里）。

## sew_rss_monitor（306 行，CONFIG_SEW_RSS_MONITOR）

动态探测 sched_stat_runtime tracepoint 采样 RSS / 运行时，512MB 阈值
（`rss_threshold_kb` 默认 524288）+ tgid 白名单触发报告。

## sew_bootmonitor（213 行，CONFIG_SEW_BOOTMONITOR）

OS4 bootmonitor 精简移植：boot 事件锚点表 + console-ramoops 持久化，
`/proc/sew_bootmonitor` 按序写锚点、读锚点表。**=m 时锚点时间相对
modprobe**（Kconfig help 已明示），要抓全启动过程需 =y。

## slabd 升级（CONFIG_KSHRINK 基础上）

- VIP 单消费者合并：`sew_slabd_vip_check` 函数指针注册制——built-in 代码若
  直接引用模块符号会链接死结，改由模块注册判定回调
- 频率感知强度：按 P-state 微调回收 priority

## hook 与符号约定（血泪教训）

- 三个 hook：`android_vh_get_page_wmark` /
  `android_vh_alloc_pages_slowpath_start` / `android_vh_direct_reclaim_end`
- **EXPORT 必须放在各头文件 CREATE_TRACE_POINTS 的定义宿主**：mm 侧 hook
  的导出统一在 `drivers/android/vendor_hooks.c`（放 mm/ 下会 duplicate
  symbol `__traceiter_*`）
- C89 坑：trace 调用必须放在全部变量声明之后
  （-Wdeclaration-after-statement 两次实锤）

文件：`mm/sew_unfairmem.c`, `sew_mi_reclaim.c`, `sew_scene_swappiness.c`,
`sew_dynamic_readahead.c`, `sew_rss_monitor.c`, `sew_bootmonitor.c`,
`slabd.c`, `page_alloc.c`, `vmscan.c`, `mm/Kconfig`, `mm/Makefile`,
`include/trace/hooks/mm.h`, `init/Kconfig`。
