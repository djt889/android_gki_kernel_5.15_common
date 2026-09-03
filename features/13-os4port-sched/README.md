# 13-os4port-sched

**MIUI OS4 调度移植三件套**（dada 设备 vendor 模块，R8 合入）。三个特性均
default n，配置统一放在 `init/Kconfig`（`kernel/sched/` 没有自己的 Kconfig）。

## sew_yield_penalty（~275 行，CONFIG_SCHED_YIELD_PENALTY）

把目标 pid 的 sched_yield() 换成有界睡眠，睡到下一个帧边界：帧长
`NSEC_PER_SEC / target_fps`，上界再按 `headroom_pct` 放大。

- uid 护栏：只接受 Android app uid 区间 10000-19999 的目标；系统 pid 写
  参数直接 -EPERM（防伪造 target 把系统线程睡死）
- 探针 `android_rvh_before_do_sched_yield`（restricted 形态，
  tracepoint_probe_register 直接注册），写 `@unused` 非零使 yield 系统调用
  提前返回
- **睡眠必须经 task_work**：探针在 tracepoint 原子区，直接 usleep 会
  BUG: scheduling while atomic（reviewer 第一轮 blocker 实证）。实际做法是
  `task_work_add(TWA_RESUME)`，在返回用户态的路上于普通进程上下文执行
  `usleep_range`；任务若中途 exit，exit_task_work() 兜底，最多偏一个帧窗
  （60fps 下 ~18ms）
- 统计用 atomic64（yield 计数 / 累计睡眠 ns），sysfs 可调 target_pid /
  target_fps / headroom_pct

## sew_qos_inherit（~211 行，CONFIG_SEW_QOS_INHERIT）

futex 等待链 QOS 继承（OS4 xr_qi 精简版）：VIP tgid 的 futex 等待者垫
uclamp_min，只作用于锁继承链。`uclamp_bucket_id` 的算法内联自
`core.c:1328`（5.15 无可直接调用的导出）；tid 键 save/restore 用 16 槽
自旋锁表。

## sew_rtload（196 行，CONFIG_SEW_RTLOAD）

kprobe 挂 `__sched_setscheduler` 统计 SCHED_FIFO/SCHED_RR 策略请求，misc
设备读数。纯观测、零行为修改；kprobe 注册失败时全部回滚。

## 基础设施改动

- `kernel/sched/vendor_hooks.c`：新增 `android_rvh_before_do_sched_yield`
  restricted hook 的注册与导出
- `kernel/task_work.c`：`task_work_add` 新增 EXPORT_SYMBOL_GPL（KMI 审计
  注记：ksymtab 增项）
- `include/trace/hooks/sched.h` / `kernel/sched/core.c` /
  `kernel/sched/Makefile`：hook 声明、QOS_INHERIT 接入、三个 obj 编译行

文件：`kernel/sched/sew_yield_penalty.c`, `sew_qos_inherit.c`, `sew_rtload.c`,
`core.c`, `vendor_hooks.c`, `Makefile`, `include/trace/hooks/sched.h`,
`kernel/task_work.c`。
