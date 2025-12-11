import struct
import sys
import os

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <path_to_seed_file>")
    sys.exit(1)

seed_path = sys.argv[1]

if not os.path.exists(seed_path):
    print(f"Error: File not found at {seed_path}")
    sys.exit(1)

with open(seed_path, 'rb') as f:
    header = f.read(24)
    if len(header) < 24:
        print(f"Error: Seed file is too small. Size: {len(header)} bytes.")
        sys.exit(1)

    # 解析24B Header
    magic, request, ret, subclass, arg_size = struct.unpack('<I Q I I I', header)
    
    if magic != 0x4E564944:
        print("Error: Invalid magic (expected 0x4E564944)")
        sys.exit(1)
    
    arg_data = f.read()
    if len(arg_data) != arg_size:
        print(f"Error: Incomplete arg_data (expected {arg_size}, got {len(arg_data)})")
        sys.exit(1)
    
    # 推type
    if request == 0xc030462b:
        ioctl_type = "Alloc"
    elif request == 0xc020462a:
        ioctl_type = "Control"
    else:
        ioctl_type = "Unknown"

    print("="*40)
    print(f"Seed File:      {seed_path}")
    print(f"Type:           {ioctl_type}")
    print(f"Magic:          {hex(magic)} (NVID)")
    print(f"Request Code:   {hex(request)}")
    print(f"Return Value:   {ret} ({hex(ret)})")
    print(f"Subclass:       {hex(subclass)}")
    print(f"Argument Size:  {arg_size} bytes")
    print("="*40)

    # hexdump前64B data
    print("Argument Data (first 64 bytes):")
    if arg_size > 0:
        for i in range(min(64, arg_size)):
            if i % 16 == 0 and i != 0:
                print()
            print(f"{arg_data[i]:02x}", end=' ')
        print("\n")
    else:
        print(" (No argument data)")