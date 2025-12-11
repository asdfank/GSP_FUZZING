#!/bin/bash

RESULTS_DIR="results"
SEED_DIR="/sharedir/seeds" # 确认这是你虚拟机中存放所有种子的目录

# 脚本开始前，确保结果目录存在
mkdir -p "$RESULTS_DIR"
echo "测试结果将保存在 '$RESULTS_DIR' 目录中..."

# 清理上一次的汇总文件
rm -f "$RESULTS_DIR/summary.csv"

# 检查种子目录
if [ ! -d "$SEED_DIR" ]; then
    echo "错误：找不到种子目录 '$SEED_DIR'！"
    exit 1
fi

# 遍历所有种子文件
for seed_path in "$SEED_DIR"/*.bin; do
    [ -f "$seed_path" ] || continue

    echo "-----------------------------------------"
    echo "正在测试种子: $seed_path"
    
    seed_basename=$(basename "$seed_path")
    log_file="$RESULTS_DIR/${seed_basename}.log"

    # 使用 sudo 运行 test_inject
    sudo ./test_inject "$seed_path" > "$log_file" 2>&1
    
    # 使用 sudo 运行 dmesg
    echo -e "\n--- dmesg log ---" >> "$log_file"
    sudo dmesg | tail -20 >> "$log_file"
    
    # 将结果汇总到 csv 文件
    echo -n "File,$seed_basename," >> "$RESULTS_DIR/summary.csv"
    
    # grep Result, ret, errno, status 并组合
    result_line=$(grep -m 1 "Result:" "$log_file" || echo "Result line not found")
    ioctl_line=$(grep -m 1 "ioctl ret=" "$log_file" || echo "")
    
    if [ -n "$ioctl_line" ]; then
        # 提取 ret/errno/status
        ret=$(echo "$ioctl_line" | sed 's/.*ret=\([0-9-]*\).*/\1/')
        errno=$(echo "$ioctl_line" | sed 's/.*errno=\([0-9]*\).*/\1/')
        status=$(echo "$ioctl_line" | sed 's/.*status=\(0x[0-9a-f]*\).*/\1/')
        
        # grep params_size from the Request line
        params_line=$(grep -m 1 "params_size=" "$log_file" || echo "")
        params_size=""
        if [ -n "$params_line" ]; then
            params_size=$(echo "$params_line" | sed 's/.*params_size=\([0-9]*\).*/\1/')
        fi
        
        echo "$result_line,ret=$ret errno=$errno status=$status,params_size=$params_size" >> "$RESULTS_DIR/summary.csv"
    else
        echo "$result_line" >> "$RESULTS_DIR/summary.csv"
    fi
done

echo "-----------------------------------------"
echo "所有种子测试完毕。请查看 '$RESULTS_DIR/summary.csv' 文件获取汇总结果。"

# 更改结果文件的所有权，以便普通用户可以读取
sudo chown -R $(logname):$(logname) "$RESULTS_DIR"