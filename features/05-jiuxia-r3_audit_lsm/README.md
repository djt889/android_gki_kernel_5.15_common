# 05-jiuxia-r3_audit_lsm

**JiuXia 自研** LSM。binder_prio 模块加载阻断（按文件名匹配），含审计日志。R3 引入，R4 按名拦截，R5-fix 改为仅阻断 system 分区路径（放行 recovery）。文件：security/r3_audit_lsm.c, security/Kconfig, security/Makefile
