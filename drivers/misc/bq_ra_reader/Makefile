# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_BQ_RA_READER) += bq_ra_reader.o
obj-$(CONFIG_RA_READER) += raR.o

# 设备内核（MT6895Z）KASAN_HW_TAGS/MTE 开启后，sp_el0 在模块 init 时
# 可能不是 current 指针，stack protector 序言读 current->stack_canary
# 会访问到用户地址被 PAN 拦截而崩溃（"Unable to handle kernel access
# to user memory" at init_module+0x24）。本模块无需栈保护，关掉它。
ccflags-y += -fno-stack-protector