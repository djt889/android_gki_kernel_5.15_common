#!/bin/bash
# JiuXia Kernel Customizations - 更新脚本
# 用法: bash ./update.sh <新版本标签>   (在 kernel-customizations-docs 分支执行)
# 功能: 从正式分支提取最新修改文件到 modified/, 提交并推送
set -e
VERSION="${1:-R7}"
FORMAL=android13-5.15-lts-2026-07
BASE=43f7d63d83ca
KERNEL=/root/work/android_gki_kernel_5.15_common

# 1. 从正式分支提取修改文件
cd $KERNEL
git checkout $FORMAL
FILES=$(git diff --name-only $BASE..HEAD)
echo "修改文件数: $(echo "$FILES" | wc -l)"
# 回到文档分支
git checkout kernel-customizations-docs
# 清空 modified 并重新提取
rm -rf modified
mkdir -p modified
for f in $FILES; do
    mkdir -p "modified/$(dirname $f)"
    git show $FORMAL:$f > "modified/$f"
done
echo "已提取到 modified/"

# 2. 提交并推送
git add -A
git commit -m "update $VERSION: $(echo "$FILES" | wc -l) modified files" || echo "(无新改动)"
git push origin kernel-customizations-docs
echo "完成: kernel-customizations-docs 已更新"
