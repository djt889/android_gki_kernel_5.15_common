# 08-builtin-ipset_bbr

**R6 内建优化**。ipset 集合框架（netfilter）+ BBR 拥塞控制（设为默认）。

## 生效方式变迁（重要）

- **R6（2026-08-12）**：配置写在 `arch/arm64/configs/jiuxia_r6.fragment`，当时
  编译流程合并了 fragment，特性**生效**（R6 产物 .config 中 IP_SET=y、BBR=y）。
- **R7.0 – R7.6（静默失效期）**：编译流程改为直接 `make gki_defconfig`，该流程
  **从不合并 fragment**，R7 系全部正式版编译产物中 IP_SET/BBR 均未开启——
  特性静默丢失约 17 天。
- **R7.7（2026-08-29，修复）**：20 项配置直接持久化进 `gki_defconfig`，并补上
  `CONFIG_TCP_CONG_ADVANCED=y` 门控——不开此项时 TCP_CONG_BBR 符号在 Kconfig
  展开中不可见，写在 defconfig 也会被静默丢弃（这就是"写了却不生效"的第二层
  原因）。修复后 BBR 为默认拥塞算法（DEFAULT_TCP_CONG=bbr）。

最新 defconfig 见 `../09-base-fixes/arch/arm64/configs/gki_defconfig`。
