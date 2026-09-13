# SPDX-License-Identifier: GPL-2.0
# Single module: core bus + sensors linked into millet.ko so the whole
# subsystem loads/unloads atomically (millet_core.o is a component here,
# not a standalone module).
obj-$(CONFIG_MILLET) += millet.o
millet-y := millet_core.o millet_sig.o millet_hs.o millet_pkg.o millet_oem_cgroup.o millet_binder.o
