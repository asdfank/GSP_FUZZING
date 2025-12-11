#!/bin/bash
set -euo pipefail  # 严格模式: 未定义变量/命令失败/管道失败时退出

# 获取 libioctl_hook.so 的绝对路径 (从bazel-bin，确保build后存在)
HOOK_SO="$(pwd)/bazel-bin/tools/ioctl_sniffer/libioctl_hook.so"

# 确保目录存在
mkdir -p logs seeds

# --- 命令配置 ---
IOCTL_TOOLS=(
    # 修正: 'nvidia-smi -q' 本身就是查询所有信息，'-d ALL' 是无效语法
    "nvidia-smi -q;logs/sniff_smi_all.txt;seeds/smi_all"
    
    # 修正: '-d SUPPORTED' 是无效语法。已替换为 '-d MEMORY'
    "nvidia-smi -q -d MEMORY;logs/sniff_smi_supported.txt;seeds/smi_supported"
    
    # 以下命令语法正确，保持不变
    "nvidia-smi -q -d UTILIZATION;logs/sniff_smi_util.txt;seeds/smi_util"
    "nvidia-smi -q -d POWER;logs/sniff_smi_power.txt;seeds/smi_power"
    "nvidia-smi -q -d SUPPORTED_CLOCKS;logs/sniff_smi_clocks.txt;seeds/smi_clocks"
)

X_TOOLS=(
    "xvfb-run -a --server-args='-screen 0 1024x768x24' nvidia-settings -q all;logs/sniff_settings_all.txt;seeds/settings_all"  # dummy X for settings
)

BUG_REPORT_TOOLS=(
    "nvidia-bug-report.sh;logs/sniff_bug_report.txt;seeds/bug_report"
)

# --- 统一的执行函数 ---
run_one_task() {
    local cmd_string="$1"
    local log_file="$2"
    local seed_dir="$3"
    local use_sudo="${4:-false}"

    echo "========================================================================"
    echo "Running Command: $cmd_string"
    echo "Log File: $log_file"
    echo "Seed Directory: $seed_dir"
    echo "========================================================================"

    # 清理旧的dump文件 (避免append旧数据)
    rm -f /tmp/ioctl_raw_dump.bin

    # 设置env (关键: dump file + enforce + verbose optional)
    export GVISOR_IOCTL_DUMP_FILE=/tmp/ioctl_raw_dump.bin
    export GVISOR_IOCTL_SNIFFER_ENFORCE_COMPATIBILITY=REPORT

    # bazelisk命令: 移除--sandbox_network=1 (未知option), 加--remote_timeout=300; -verbose=true optional (加细节log，如果需要设VERBOSE=true)
    local verbose_flag=""
    if [ "${VERBOSE:-false}" = true ]; then
        verbose_flag="-verbose=true"
    fi
    local sniffer_cmd="bazelisk run //tools/ioctl_sniffer:run_sniffer -- \
        $verbose_flag -- \
        bash -c '$cmd_string'"

    if [ "$use_sudo" = true ]; then
        sudo -E bash -c "$sniffer_cmd" > "$log_file" 2>&1  # -E保留env; bash -c包防sudo问题
    else
        eval "$sniffer_cmd" > "$log_file" 2>&1
    fi

    # 检查结果并提取种子 (即使fail，也尝试)
    if [ -s /tmp/ioctl_raw_dump.bin ]; then
        python3 extract_seeds.py /tmp/ioctl_raw_dump.bin "$seed_dir"
        echo "Extracted seeds to $seed_dir"
    else
        echo "Warning: No dump file generated (check if control/alloc ioctls triggered)."
        echo "Last 10 lines of log:"
        tail -n 10 "$log_file"
    fi
    echo -e "\n"
    sleep 1  # 加sleep防driver panic累积
}

# --- 执行所有任务 ---
# 先build一次，确保libioctl_hook.so存在
bazelisk build //tools/ioctl_sniffer:run_sniffer

for item in "${IOCTL_TOOLS[@]}"; do
    IFS=';' read -r cmd log seed <<<"$item"
    run_one_task "$cmd" "$log" "$seed"
done
for item in "${X_TOOLS[@]}"; do
    IFS=';' read -r cmd log seed <<<"$item"
    run_one_task "$cmd" "$log" "$seed"
done
for item in "${BUG_REPORT_TOOLS[@]}"; do
    IFS=';' read -r cmd log seed <<<"$item"
    run_one_task "$cmd" "$log" "$seed" true
done
echo "All tasks completed."