import struct
import os
import sys
import hashlib

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <dump_file> <output_seed_directory>")
    sys.exit(1)

dump_file = sys.argv[1]
seed_dir = sys.argv[2]
# --- 新增代码 ---
# 移除末尾可能存在的路径分隔符 (e.g., "seeds/smi_clocks/" -> "seeds/smi_clocks")
cleaned_seed_dir = seed_dir.rstrip(os.path.sep)
# 提取路径的最后一部分作为前缀 (e.g., "seeds/smi_clocks" -> "smi_clocks")
prefix = os.path.basename(cleaned_seed_dir)
# --- 新增代码结束 ---

os.makedirs(seed_dir, exist_ok=True)

seen_hashes = set()  # 防重复seed
control_count = 0
alloc_count = 0

with open(dump_file, 'rb') as f:
    i = 0
    while True:
        header = f.read(24)
        if len(header) < 20:  # 至少20B
            break
        if len(header) == 20:  # 兼容旧
            magic, request, ret, arg_size = struct.unpack('<I Q I I', header)
            subclass = 0
        else:
            magic, request, ret, subclass, arg_size = struct.unpack('<I Q I I I', header)
        if magic != 0x4E564944:
            print(f"Invalid magic at offset {f.tell() - len(header)}, skipping")
            continue
        arg_data = f.read(arg_size)
        if len(arg_data) < arg_size:
            print("Incomplete arg_data, stopping")
            break
        
        # hash防重复
        seed_hash = hashlib.sha256(header + arg_data).hexdigest()
        if seed_hash in seen_hashes:
            print(f"Skipped duplicate seed at offset {f.tell() - 24 - arg_size}")
            continue
        seen_hashes.add(seed_hash)
        
        # 推type
        if request == 0xc030462b:  # NV_ESC_RM_ALLOC
            alloc_count += 1
            type_str = "Alloc"
        elif request == 0xc020462a:  # NV_ESC_RM_CONTROL
            control_count += 1
            type_str = "Control"
        else:
            type_str = "Unknown"
        # --- 修改此行 ---
        # 使用新的前缀来命名 (e.g., "smi_clocks_000000.bin")
        seed_path = os.path.join(seed_dir, f'{prefix}_{i:06d}.bin')
        # --- 修改结束 ---
        with open(seed_path, 'wb') as s:
            full_header = struct.pack('<I Q I I I', magic, request, ret, subclass, arg_size)
            s.write(full_header + arg_data)
        print(f"Saved seed {i}: type={type_str}, request={hex(request)}, subclass={hex(subclass)}, arg_size={arg_size}")
        i += 1

print(f"Extracted {i} seeds to {seed_dir} (Control: {control_count}, Alloc: {alloc_count})")