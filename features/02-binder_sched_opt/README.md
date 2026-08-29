# 02-binder_sched_opt

binder 调度优化特性。演进历程：

- R2 初版参考了酷安社区 Moon Binder 的调度思路（与原实现已无代码关系）
- R7 修复过度 RT 提升（perfetto 崩溃/LSPosed 安全模式）
- R7.3 加运行时开关并修 policy-mask 准入 bug
- R7.6 重写为 transaction_received / restore_priority hook 路径，
  不再依赖初版的三条 vendor hook

文件：`drivers/android/binder_sched_opt.c`, Kconfig, Makefile。
（目录曾名 02-coolapk-binder_sched_opt，为纠正来源口径已改名。）

## 现状（R7.5 起）：三个 hook 全部不做优先级提升

这个特性最初移植了 ko 的三个 vendor hook，目标是给 SurfaceFlinger 和
`com.miui.home` 相关线程做 FIFO/RT 优先级提升。经逐版本审计，三条路径都已停用，
原因分别如下。

### android_vh_binder_trans —— R7.5 移除整个 hook

R2 的移植把 `{SCHED_FIFO, prio 98}` 写进了 `target_proc->default_priority`，
而 ko 原本写的是事务自己的优先级槽，这是两个不同的东西：

- `default_priority` 也会被 `binder_thread_read()` 在 binder 线程回去等待
  进程级工作时读到，那条路调用 `binder_restore_priority()` →
  `binder_do_set_priority(verify=false)`，跳过 `RLIMIT_RTPRIO` 校验直接
  `sched_setscheduler_nocheck(SCHED_FIFO|SCHED_RESET_ON_FORK)`。它**不经过**
  `binder_transaction_priority()`，所以 `node->inherit_rt` 拦不住。
  结果是 SurfaceFlinger 线程池里每个 binder 线程都变成实时线程并常驻，
  抢占 system_server，阻塞在 CFS 线程持有的用户态 futex 上时造成优先级反转，
  而且作为 RT 任务绕过 EAS 选核与 uclamp。
- 数值也是反的：`binder_priority.prio` 是内核优先级，`to_userspace_prio()`
  把 RT 内核优先级 98 映射为用户态 RT 优先级 `99 - 98 = 1`，最低的一档。

这是 R2→R7.4 期间唯一原样存在于每个卡锁屏版本里的自研改动，R7.5 移除。
`__traceiter_android_vh_binder_trans` 仍然导出，厂商模块 KMI 不受影响。

### android_vh_binder_set_priority / proc_transaction_finish —— R7.3 起为 no-op

两者最终都调用 `binder_sched_opt_ko_sched()`。R2 的实现用
`low_policy = task->policy & 0x3` 做准入，配 `rt_task()` 排除已是 RT 的任务。
真值表显示这两道门的实际效果与设计意图不符：

| 策略 | 值 | `&0x3` | 门1 通过 | `rt_task` | 最终准入 |
|---|---|---|---|---|---|
| SCHED_NORMAL | 0 | 0 | 否 | — | **否** |
| SCHED_FIFO | 1 | 1 | 是 | 是→拒 | 否 |
| SCHED_RR | 2 | 2 | 是 | 是→拒 | 否 |
| SCHED_BATCH | 3 | 3 | 否 | — | 否 |
| SCHED_IDLE | 5 | 1 | 是 | 否 | **是** |
| SCHED_DEADLINE | 6 | 2 | 是 | 是→拒 | 否 |

`SCHED_NORMAL = 0` 被 `low_policy < 1` 直接拒掉，而名单里的
`system_server` / `android.anim` / `com.miui.home` / `.globallauncher`
全是 SCHED_NORMAL。唯一能通过的是 `SCHED_IDLE`：`5&3=1` 过门 1，prio 139
不算 RT 过门 2，然后被提成 `SCHED_FIFO | RESET_ON_FORK`、优先级
`clamp(99-139, 1, 99) = 1`。

也就是说这段代码从未提升过任何正常 CFS 线程，实际效果是把系统降到
SCHED_IDLE 的低优线程反向提成最低档实时线程。R7.3 用显式策略白名单替换了
位掩码（`6bbafaeedc67`），此后函数体为空。

R7 曾先收窄名单（`665451cccf09`）：删掉 `RenderThread` 和 `main` 两个过宽前缀
（任何应用的主线程/渲染线程都会命中），并给 `transaction_finish` 补上
SurfaceFlinger 目标检查。名单其余 13 项保留至今。

## 仍然保留的部分

- 运行时开关 `/sys/module/binder_sched_opt/parameters/enabled`（默认 1）
- 诊断节点 `/proc/binder_sched_opt_status`
- 两个 hook 的注册链与 `binder_sched_opt_is_sf()` / `_match()` 判定逻辑

## 如果要重做 binder 优化

建议用 uclamp 而非切换调度类：在 `set_priority` 时提升 `uclamp_min`、在
`transaction_finish` 时成对恢复（`sched_setattr_nocheck` 配
`SCHED_FLAG_UTIL_CLAMP_MIN`）。线程留在 CFS，抢占关系不变、不会反转，
调频器仍会按提升后的利用率给频率。要点：范围收窄到
`surfaceflinger` 与 `android.anim`；数值与 sew-sched 的 uclamp 档位对齐；
异常终止路径也必须恢复，否则会退化成永久提升。
