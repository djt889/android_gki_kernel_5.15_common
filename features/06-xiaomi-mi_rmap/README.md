# 06-xiaomi-mi_rmap

来自**小米 piano**（MiCode）。高 mapcount 页保护：mapcount≥32 的共享页不回收(ACTIVATE)，动态 keep 阈值，nr_skipped 防抖动。升级 vmscan should_be_protected hook 签名。引入版本 R5。文件：mm/mi_rmap_efficiency.c, include/trace/hooks/mm.h, mm/vmscan.c
