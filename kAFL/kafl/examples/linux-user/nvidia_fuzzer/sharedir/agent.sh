#!/bin/sh
set -eu

log=/sharedir/log/nvidia-agent.log
echo "[agent] start" | tee -a "$log"

# 1) 确保 /sharedir 已挂载
modprobe 9pnet_virtio 9p 2>/dev/null || true
mkdir -p /sharedir
mountpoint -q /sharedir || mount -t 9p -o trans=virtio sharedir /sharedir || true

# 2) 确保 /dev/nvidia* 存在：先试 nvidia-modprobe，不行就 mknod 兜底
echo "[agent] ensure nvidia devnodes via nvidia-modprobe" | tee -a "$log"
if ! command -v nvidia-modprobe >/dev/null 2>&1; then
  apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nvidia-modprobe || true
fi

i=0
until [ -e /dev/nvidiactl ] || [ $i -ge 10 ]; do
  nvidia-modprobe -u -c=0 || true
  sleep 1
  i=$((i+1))
done

if [ ! -e /dev/nvidiactl ]; then
  echo "[agent] fallback mknod /dev/nvidiactl /dev/nvidia0" | tee -a "$log"
  mknod -m 666 /dev/nvidiactl c 195 255 2>/dev/null || true
  mknod -m 666 /dev/nvidia0   c 195   0 2>/dev/null || true
fi

# UVM 节点（可选）
if [ ! -e /dev/nvidia-uvm ]; then
  mknod -m 666 /dev/nvidia-uvm       c 234 0 2>/dev/null || true
  mknod -m 666 /dev/nvidia-uvm-tools c 234 1 2>/dev/null || true
fi

ls -l /dev/nvidia* 2>/dev/null | tee -a "$log"

# =========================================================================
# 3. 环境终极净化 (新增逻辑: 杀光噪音)
# =========================================================================
echo "[agent] ===== Environment Cleanup Begin =====" | tee -a "$log"

# 3.1 强制切到纯文本模式
if command -v systemctl >/dev/null 2>&1; then
    echo "[agent] Isolating to multi-user.target..." | tee -a "$log"
    systemctl isolate multi-user.target || true
fi

# 3.2 停掉常见的图形/GPU服务
echo "[agent] Stopping GPU-related services..." | tee -a "$log"
for svc in \
    gdm3 sddm lightdm display-manager \
    nvidia-persistenced nvidia-powerd \
    upower thermald; do
    # 检查服务是否存在再停止，避免报错刷屏
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
        echo "[agent] Stopping ${svc}..." | tee -a "$log"
        systemctl stop "${svc}" 2>/dev/null || true
    fi
done

# 3.3 暴力查杀残留进程
echo "[agent] Killing leftover GUI / NVIDIA processes..." | tee -a "$log"
killall -q -9 \
    Xorg Xwayland \
    gnome-shell kwin_wayland plasmashell \
    compiz \
    nvidia-persistenced nvidia-settings \
    || true

# =========================================================================
# 4. 净化效果验证
# =========================================================================
echo "[agent] ===== Checking Environment Cleanliness =====" | tee -a "$log"

echo "[agent] Loaded NVIDIA modules:" | tee -a "$log"
lsmod | grep -i nvidia || echo "  (WARNING: no nvidia modules loaded!)" 

echo "[agent] Processes holding /dev/nvidia* (Expect EMPTY):" | tee -a "$log"
if command -v lsof >/dev/null 2>&1; then
    # 这里的输出应该是空的，或者是 harmless 的系统进程
    lsof /dev/nvidia* 2>/dev/null || echo "  [OK] No processes using NVIDIA devices." | tee -a "$log"
else
    echo "  (lsof not installed, skipping check)" | tee -a "$log"
fi

echo "[agent] ===== Cleanup Done, Starting Fuzzer =====" | tee -a "$log"

# 新增：检查 nv_gsp_ranges.rel 是否存在
if [ ! -f /sharedir/nv_gsp_ranges.rel ]; then
  echo "[agent] ERROR: /sharedir/nv_gsp_ranges.rel not found!" | tee -a "$log"
  exit 1
fi
echo "[agent] nv_gsp_ranges.rel found, proceeding" | tee -a "$log"

# 3) 等 Host 放闸 READY
echo "[agent] waiting READY..." | tee -a "$log"
while [ ! -f /sharedir/READY ]; do sleep 0.2; done
echo "[agent] READY seen, exec harness" | tee -a "$log"

SEED_PATH="/sharedir/seed.bin"

export NVIDIA_INJECT_SEED="$SEED_PATH"
export LD_PRELOAD="/sharedir/libnv_ioctl_hook_kafl.so"


# 4) 启动 harness（nvidia_harness）
exec /sharedir/fuzz_nvidia
