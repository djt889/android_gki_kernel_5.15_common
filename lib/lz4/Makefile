ccflags-y += -O3 \
    -DLZ4_FREESTANDING=1 \
    -DLZ4_FAST_DEC_LOOP=1

obj-y += lz4.o lz4hc.o lz4jo.o

obj-$(CONFIG_ARM64) += $(addprefix lz4armv8/, lz4accel.o lz4armv8.o)

CFLAGS_lz4jo.o += -DLZ4JO_FREESTANDING=1 -DLZ4JO_FAST_DEC_LOOP=1
