# folio 完整移植计划（本地实验分支 r5-folio-experiment）

## 目标
在 5.15 内核完整移植 folio 回收体系（shrink_folio_list + helper + 接线），不改变内核版本号。此前卡 MI logo，需先二分定位根因，修复后完整移植并验证。

## 约束
- 仅本地 git（r5-folio-experiment），不推送 GitHub
- 出错可回滚
- 98% 以上自信交付
- 不改变内核版本号

## Stories（有序目标）

### G001：定位卡 MI logo 根因
- 状态：进行中
- 已确认：Diag1（reclaim_pages+evict_pages 都回退）能开机 → 根因在 folio 回收接线
- 进行中：Diag2（只回退 reclaim_pages，evict_pages 用 folio）区分是哪个接线点
- 证据：Folio-Diag1 zip 刷机开机成功

### G002：修复 folio 回收 bug
- 待 Diag2 定位后，修复具体 bug（reclaim_pages 或 evict_pages 的 folio 化问题）
- 循环验证 5 遍以上

### G003：完整移植 folio 并验证
- 修复后完整接线 folio（reclaim_pages + evict_pages + 可能的 shrink_lruvec）
- 编译通过 + 刷机不卡屏 + 内存回收正常

### G004：清理与收尾
- 去掉 debug prints
- 跟进 R7 的 43 个 commit（zstdh 修复、sew 模块等）
- 最终验证 + 代码审查
