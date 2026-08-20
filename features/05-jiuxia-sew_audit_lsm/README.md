# 05-jiuxia-sew_audit_lsm

**JiuXia 自研** LSM。模块加载阻断（前缀匹配：binder_prio/moon_/kshrink_），含审计日志。R3 引入，R4 按名拦截，R5-fix 改为仅阻断 system 分区路径（放行 recovery）。文件：security/sew_audit_lsm.c, security/Kconfig, security/Makefile
