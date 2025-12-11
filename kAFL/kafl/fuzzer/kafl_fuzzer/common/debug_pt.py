import sys
import logging
# 引入当前目录下的 self_check 模块
import self_check

# 配置日志输出，否则你看不到 logger.error 的信息
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

print("[-] 开始调用 check_vmx_pt()...")
# 调用主检查函数
is_supported = self_check.check_vmx_pt()
print(f"[-] check_vmx_pt 返回结果: {is_supported}")

print("\n[-] 开始调用 vmx_pt_get_addrn() 查看原始 ioctl 返回值...")
# 调用获取地址范围数量的函数（这个函数直接返回 ioctl 的整数结果）
addr_n = self_check.vmx_pt_get_addrn()
print(f"[-] vmx_pt_get_addrn (ioctl) 返回值: {addr_n}")

if addr_n == 0:
    print("\n[!] 结论验证: 返回值为 0，说明 KVM 驱动认为当前模式不支持 PT (pt_mode=0)。")
    print("[!] 这正是 Python 脚本报错，而 C 代码(只检查了-1/-2) 误报通过的原因。")
