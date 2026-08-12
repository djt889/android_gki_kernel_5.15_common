# 03-xiaomi-kshrink_slabd

来自**小米 piano**（MiCode, drivers/xiaomi/kshrink_slabd/）。异步 slab 回收：shrink_slab_bypass hook，249 jiffies 节流，freezable kthread 异步回收。引入版本 R2（R4 忠实重写对齐 piano 语义）。文件：mm/slabd.{c,h}, mm/Kconfig, mm/Makefile
