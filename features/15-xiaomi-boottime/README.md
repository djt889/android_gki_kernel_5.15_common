# 15-xiaomi-boottime

**MIUI 开机耗时锚点**（CONFIG_MI_BOOT_TIME，default n）。来自 MIUI
dada-v-oss 的 `drivers/xiaomi/boottime/`，**逐字拷入**：boottime.h 与
Makefile 零差异；boottime.c 仅两处 Sew 注记 + rmmod 泄漏修复；
Kconfig 仅补 help 文案。

## 机制

- 探测 `initcall` tracepoint（start/finish），把 kernel 各 initcall 的
  耗时逐条记录进锚点表
- `/proc/bootprof` 输出耗时报告，也可写入用户态锚点
- 每条记录写入内核 log ring，配合 console-ramoops 在重启后仍可读取
  （失败启动同样能看到已触达的锚点）

## =m 时机限制（与 14-sew_bootmonitor 同款约束）

initcall tracepoint 在 modprobe 之前就已全部触发，编成模块时锚点时间
相对 modprobe 起算、initcall 段为空，只剩 /proc/bootprof 写接口可用。
**要抓全 initcall 耗时必须 =y**（Kconfig help 已明示）。

## 挂载方式

- `drivers/Kconfig` 顶层 source `drivers/xiaomi/Kconfig`
- `drivers/Makefile` 加 `obj-y += xiaomi/`

文件：`drivers/xiaomi/boottime/boottime.c`, `boottime.h`, `Kconfig`,
`Makefile`, `drivers/xiaomi/Kconfig`, `drivers/xiaomi/Makefile`,
`drivers/Kconfig`, `drivers/Makefile`。
