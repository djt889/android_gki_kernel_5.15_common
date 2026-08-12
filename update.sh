#!/bin/bash
# JiuXia Kernel Customizations - 更新脚本
# 用法: bash ./update.sh <新版本标签>   (在 kernel-customizations-docs 分支执行)
# 功能: 从正式分支提取最新修改文件到 features/, 提交并推送
# 注意: 拉取谷歌上游(android.googlesource.com)不在本脚本内, 单独执行 git fetch google
set -e
VERSION="R7"
FORMAL=android13-5.15-lts-2026-07
BASE=43f7d63d83ca
KERNEL=/root/work/android_gki_kernel_5.15_common

# 1. 从正式分支提取修改文件
cd 
git checkout 
FILES=
echo "修改文件数: 1"

# 2. 回到文档分支
git checkout kernel-customizations-docs

# 3. 清空 features 并按原路径重新提取（保持 modified 兼容）
rm -rf features
mkdir -p features
for f in ; do
    mkdir -p "features/"
    git show : > "features/"
done
echo "已提取到 features/"

# 4. 提交并推送
git add -A
git commit -m "update : 1 modified files" || echo "(无新改动)"
git push origin kernel-customizations-docs
echo "完成: kernel-customizations-docs 已更新"
