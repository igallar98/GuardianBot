# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern
USER_TARGETS := xdp_loader
USER_TARGETS += xdp_stats
USER_LIBS=-lpcap

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o
COMMON_OBJS += $(COMMON_DIR)/shared_memory.o
COMMON_OBJS += $(COMMON_DIR)/checker.o
COMMON_OBJS += $(COMMON_DIR)/trace.o
COMMON_OBJS += $(COMMON_DIR)/config.o


include $(COMMON_DIR)/common.mk
