# 01-mi_sw_sync

基于内核原生 sw_sync.c 改造为 mi_sw_sync misc 设备（/dev/mi_sw_sync），提供 SW_SYNC_IOC_CREATE_FENCE / SW_SYNC_IOC_INC ioctl，与 DEBUG_FS 解耦。引入版本 R2。文件：drivers/dma-buf/sw_sync.c, sync_debug.{c,h}, Kconfig
