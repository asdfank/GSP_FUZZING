# nvidia_fuzzer/harness/Makefile

CC      := gcc
CFLAGS  := -O2 -g -Wall -Wextra -fno-omit-frame-pointer -DGSP_SILENT
LDFLAGS :=

# ----------------------
# 路径配置
# ----------------------
# 当前: harness/
# TOP_DIR: nvidia_fuzzer/
TOP_DIR      := ..
# NYX_DIR: linux-user/libnyx_agent/
NYX_DIR      := $(TOP_DIR)/../libnyx_agent
# SHAREDIR: nvidia_fuzzer/sharedir/
SHAREDIR     := $(TOP_DIR)/sharedir

# 修正点 1: nyx_api.h 在 examples/ 目录下，也就是 harness 的 "爷爷的爸爸" 目录
# harness(.) -> nvidia_fuzzer(..) -> linux-user(../..) -> examples(../../..)
KAFL_EXAMPLES_DIR := $(TOP_DIR)/../..

# ----------------------
# 输出文件配置
# ----------------------
HARNESS_BIN  := $(TOP_DIR)/fuzz_nvidia
HARNESS_SRCS := nvidia_harness.c gsp_workload.c
HARNESS_OBJS := $(HARNESS_SRCS:.c=.o)

HOOK_SO_LOCAL:= libnv_ioctl_hook_kafl.so
HOOK_SO      := $(SHAREDIR)/libnv_ioctl_hook_kafl.so

LIBNYX_A     := $(NYX_DIR)/libnyx_agent.a
HARNESS_LIBS := -lpthread -lnvidia-ml -ldl


# 修正点 2: 添加 KAFL_EXAMPLES_DIR 到头文件搜索路径
INCLUDES     := -I$(NYX_DIR)/src -I$(KAFL_EXAMPLES_DIR) -I.


.PHONY: all clean install links

all: $(HARNESS_BIN) $(HOOK_SO) install

# ----------------------
# 编译规则
# ----------------------

# 通用 .c → .o 规则（一定要有这一段，编译才会带上 INCLUDES）
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# 1. 编译 libnyx_agent (如果还没编译)
$(LIBNYX_A):
	@echo "[*] Building libnyx_agent..."
	$(MAKE) -C $(NYX_DIR)

# 2. 编译 Harness (nvidia_harness.c)
# 注意: Harness 现在不需要 -ldl，除非你代码里还有 dlopen
$(HARNESS_BIN): $(HARNESS_OBJS) $(LIBNYX_A)
	@echo "[*] Compiling Harness..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HARNESS_OBJS) $(LIBNYX_A) $(HARNESS_LIBS)

# 3. 编译 Hook (.so)
# 注意: Hook 必须链接 -ldl 用于 dlsym
$(HOOK_SO_LOCAL): ioctl_hook_kafl.c
	@echo "[*] Compiling Hook..."
	$(CC) -fPIC -shared $(CFLAGS) $(INCLUDES) -o $@ $< -ldl
# 4. 部署 .so 到 sharedir
$(HOOK_SO): $(HOOK_SO_LOCAL)
	@mkdir -p $(SHAREDIR)
	cp -f $< $@

# 5. 部署全部到 sharedir
install: $(HARNESS_BIN) $(HOOK_SO)
	@echo "[*] Installing to $(SHAREDIR)..."
	@mkdir -p $(SHAREDIR)
	cp -f $(HARNESS_BIN) $(SHAREDIR)/fuzz_nvidia
	chmod +x $(SHAREDIR)/fuzz_nvidia
	@echo "[+] Build success!"

links: install

clean:
	rm -f $(HARNESS_BIN) $(HOOK_SO_LOCAL) $(HARNESS_OBJS)
	rm -f $(SHAREDIR)/fuzz_nvidia $(SHAREDIR)/libnv_ioctl_hook_kafl.so

