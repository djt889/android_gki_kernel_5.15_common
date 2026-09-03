#!/bin/bash
# Sew Kernel Customizations - 文档分支同步脚本（v2，2026-08-22 重写修复空壳问题）
# 用法: bash ./update.sh <正式分支tag或分支名> [--check]
#       默认: 同步 + 提交 + 推送；--check: 只报告漂移，不写文件不提交不推送
#       （在任意分支执行，脚本自动切换，结束回到正式分支）
# 功能: 按映射表从正式分支提取最新文件到 docs 分支 features/，提交并推送，最后回到正式分支
set -e
REF="${1:?用法: bash ./update.sh <tag或分支>}"
KERNEL=/root/work/android_gki_kernel_5.15_common
FORMAL=android13-5.15-lts-2026-07
DOCS=kernel-customizations-docs
# BASE 保留作历史参考（原 diff 逻辑的基线）；新同步逻辑按内容比对，不再依赖它。
BASE=43f7d63d83ca

# feature 目录 -> 正式分支文件 映射表（新增 feature 时在此登记）
MAPPING=(
  "01-mi_sw_sync:drivers/dma-buf/sw_sync.c drivers/dma-buf/sync_debug.c drivers/dma-buf/sync_debug.h drivers/dma-buf/Kconfig"
  "02-binder_sched_opt:drivers/android/binder_sched_opt.c drivers/android/Kconfig drivers/android/Makefile"
  "03-xiaomi-kshrink_slabd:mm/slabd.c mm/slabd.h mm/Kconfig mm/Makefile"
  "04-kshrink_lruvecd:mm/kshrink_lruvecd.c include/linux/kshrink_lruvecd.h mm/page_ext.c mm/Kconfig mm/Makefile"
  "05-jiuxia-sew_audit_lsm:security/sew_audit_lsm.c security/Kconfig security/Makefile"
  "06-xiaomi-mi_rmap:mm/mi_rmap_efficiency.c mm/vmscan.c include/trace/hooks/mm.h"
  "07-xiaomi-unionpower:drivers/mihw/ drivers/Kconfig drivers/Makefile"
  "08-builtin-ipset_bbr:arch/arm64/configs/jiuxia_r6.fragment"
  "09-base-fixes:arch/arm64/configs/gki_defconfig drivers/gpu/drm/drm_atomic_helper.c lib/lz4/lz4hc.c Makefile"
  "10-zstdh:crypto/zstdh.c crypto/Kconfig include/linux/zstdh.h include/linux/zstdh_errors.h include/linux/zstdh_lib.h lib/zstdh/"
  "11-sew_mmap_bypass:mm/sew_mmap_bypass.c include/trace/hooks/vmscan.h"
  "12-sew_alloc_adjust:mm/sew_alloc_adjust.c"
  "13-os4port-sched:kernel/sched/sew_yield_penalty.c kernel/sched/sew_qos_inherit.c kernel/sched/sew_rtload.c kernel/sched/core.c kernel/sched/vendor_hooks.c kernel/sched/Makefile include/trace/hooks/sched.h kernel/task_work.c"
  "14-os4port-mm:mm/sew_unfairmem.c mm/sew_mi_reclaim.c mm/sew_scene_swappiness.c mm/sew_dynamic_readahead.c mm/sew_rss_monitor.c mm/sew_bootmonitor.c mm/slabd.c mm/page_alloc.c mm/vmscan.c mm/Kconfig mm/Makefile include/trace/hooks/mm.h init/Kconfig"
  "15-xiaomi-boottime:drivers/xiaomi/ drivers/Kconfig drivers/Makefile"
)

cd "$KERNEL"
git status --short | grep . && { echo "工作区不干净，中止"; exit 1; }

# trap 保证任何失败都回到正式分支
trap 'git checkout "$FORMAL" >/dev/null 2>&1 || true' EXIT
git checkout -q "$DOCS"

CHECK_ONLY=0
[ "${2:-}" = "--check" ] && CHECK_ONLY=1

updated=0
for entry in "${MAPPING[@]}"; do
    dir="features/${entry%%:*}"
    files="${entry#*:}"
    for f in $files; do
        # 用 ls-tree 枚举 REF 上该路径(或目录)的全部文件，再按内容比对。
        # 旧逻辑用 git diff BASE..REF 找变更文件，最后一次改动早于 BASE 的
        # 文件不会被报出，docs 分支里的旧副本因此永远刷不新。
        for src in $(git ls-tree -r --name-only "$REF" -- "$f"); do
            want="$dir/$src"
            if [ -f "$want" ] && git show "$REF:$src" | cmp -s - "$want"; then
                continue
            fi
            if [ "$CHECK_ONLY" = "1" ]; then
                echo "[drift] $src"
            else
                mkdir -p "$(dirname "$want")"
                git show "$REF:$src" > "$want"
                echo "[sync] $src -> $dir/"
            fi
            updated=$((updated+1))
        done
    done
done

if [ "$CHECK_ONLY" = "1" ]; then
    echo "检查完成: $updated 个文件需要同步（未做任何修改）"
    git checkout -q "$FORMAL"
    exit 0
fi

if [ "$updated" -gt 0 ]; then
    git add features
    git commit -q -m "docs: sync from $REF ($updated files)" || echo "(无新改动)"
    git push origin "$DOCS"
    echo "完成: 已同步 $updated 个文件并推送"
else
    echo "无需要同步的文件"
fi

git checkout -q "$FORMAL"
echo "已回到正式分支 $FORMAL"
