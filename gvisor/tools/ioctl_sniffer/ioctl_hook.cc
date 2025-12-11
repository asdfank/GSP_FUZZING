// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE 1  // Needed for access to RTLD_NEXT
#include "tools/ioctl_sniffer/ioctl_hook.h"

#include <asm/ioctl.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tools/ioctl_sniffer/ioctl.pb.h"
#include "tools/ioctl_sniffer/sniffer_bridge.h"

using gvisor::Ioctl;

libc_ioctl libc_ioctl_handle = nullptr;

void init_libc_ioctl_handle() {
  if (libc_ioctl_handle) {
    return;
  }

  libc_ioctl_handle = (libc_ioctl)dlsym(RTLD_NEXT, "ioctl");
  if (!libc_ioctl_handle) {
    std::cerr << "Failed to hook ioctl: " << dlerror() << "\n";
    exit(1);
  }
}

// NVOS54_PARAMETERS 结构体定义（基于 gVisor abi/nvgpu，64-bit 小端，size=32B）
struct NVOS54_PARAMETERS {
  uint32_t hClient;     // offset 0
  uint32_t hObject;     // 4
  uint32_t cmd;         // 8
  uint32_t flags;       // 12
  void* params;         // 16 (pointer, 8B)
  uint32_t paramsSize;  // 24
  uint32_t status;      // 28
};

// NV_ESC_RM_CONTROL 的 NR (从 linux IOC_NR 和 gVisor 代码)
const uint32_t NV_ESC_RM_CONTROL_NR = 0x2a;


// 新增：NVOS64_PARAMETERS 结构体定义 (Alloc)
// size=48B (基于 64-bit 布局)
struct NVOS64_PARAMETERS {
  uint32_t hRoot;
  uint32_t hObjectParent;
  uint32_t hObjectNew;
  uint32_t hClass;
  void* pRightsRequested; // 8B pointer
  void* pAllocParms;      // 8B pointer (二级参数)
  uint32_t flags;
  uint32_t status;
  uint64_t padding;       // 填充至 48B
};

// 新增：Alloc 的 NR 编号
const uint32_t NV_ESC_RM_ALLOC_NR = 0x2b;

extern "C" {

int ioctl(int fd, unsigned long request, void *argp) {
  if (!libc_ioctl_handle) {
    init_libc_ioctl_handle();
  }

  // 1. 先resolve fd_path
  char file_name[PATH_MAX + 1];
  std::string fd_link = absl::StrCat("/proc/self/fd/", fd);
  ssize_t n = readlink(fd_link.c_str(), file_name, sizeof(file_name) - 1);
  if (n < 0) {
    return libc_ioctl_handle(fd, request, argp);
  }
  file_name[n] = '\0';

  // 非NVIDIA直接放行
  if (!absl::StartsWith(file_name, "/dev/nvidia")) {
    return libc_ioctl_handle(fd, request, argp);
  }

  // 2. 计算arg_size (非UVM)
  bool is_uvm = absl::StartsWith(file_name, "/dev/nvidia-uvm");
  uint32_t arg_size = is_uvm ? 0 : _IOC_SIZE(request);

  // 3. 复制pre_arg_data (只在非UVM且合理size)
  std::vector<char> pre_arg_data;
  if (arg_size > 0 && arg_size <= 1048576 && argp != nullptr) {  // <1MB
    pre_arg_data.resize(arg_size);
    memcpy(pre_arg_data.data(), argp, arg_size);
  }

  // 4. 组pre proto
  Ioctl pre_info;
  pre_info.set_fd_path(file_name);
  pre_info.set_request(request);
  pre_info.set_ret(-1);  // pre标识
  if (!pre_arg_data.empty()) {
    pre_info.set_arg_data(pre_arg_data.data(), pre_arg_data.size());
  }

  // 5. CONTROL: 抓pre_params + set_subclass
  if (absl::StartsWith(file_name, "/dev/nvidiactl") &&
      _IOC_NR(request) == NV_ESC_RM_CONTROL_NR &&
      pre_arg_data.size() == sizeof(NVOS54_PARAMETERS)) {
    NVOS54_PARAMETERS* w = reinterpret_cast<NVOS54_PARAMETERS*>(pre_arg_data.data());
    pre_info.set_subclass(w->cmd);  // 从wrapper取cmd
    if (w->params != nullptr && w->paramsSize > 0 && w->paramsSize <= 1048576) {
      std::vector<char> pre_params_data(w->paramsSize);
      memcpy(pre_params_data.data(), w->params, w->paramsSize);
      pre_info.set_params_data(pre_params_data.data(), pre_params_data.size());
    }
  }

  // [新增代码] 5.5. ALLOC: 抓pre_params (pAllocParms) + set_subclass (hClass)
  if (absl::StartsWith(file_name, "/dev/nvidiactl") &&
      _IOC_NR(request) == NV_ESC_RM_ALLOC_NR &&
      pre_arg_data.size() == sizeof(NVOS64_PARAMETERS)) {
    
    // 安全读取: 防止指针转换导致的对齐问题
    NVOS64_PARAMETERS w;
    memcpy(&w, pre_arg_data.data(), sizeof(w));
    
    pre_info.set_subclass(w.hClass);
    // --- 新增：打印原始 Hex 数据 ---
    std::cerr << "[Hook Alloc Hex] ";
    unsigned char* p = (unsigned char*)&w;
    for(size_t i=0; i<sizeof(w); i++) {
        char buf[8];
        snprintf(buf, sizeof(buf), "%02x", p[i]);
        std::cerr << buf << " ";
        // 在关键偏移处打印分隔符，方便肉眼检查
        if (i == 15) std::cerr << "| "; // hClass 结束
        if (i == 23) std::cerr << "| "; // pRightsRequested 结束
        if (i == 31) std::cerr << "| "; // pAllocParms 结束
    }
    std::cerr << "\n";
    // -----------------------------
    // 调试日志: 输出到 stderr (会被重定向到日志文件)
    // 这样我们就能确切知道 pAllocParms 到底是不是 NULL
    std::cerr << "[Hook Alloc] hClass=0x" << std::hex << w.hClass 
              << " pAllocParms=" << w.pAllocParms << std::dec << "\n";

    if (w.pAllocParms != nullptr) {
        size_t guess_size = 512; 
        std::vector<char> pre_params_data(guess_size);
        // 盲读
        memcpy(pre_params_data.data(), w.pAllocParms, guess_size);
        pre_info.set_params_data(pre_params_data.data(), pre_params_data.size());
    }
  }
  
  WriteIoctlProto(pre_info);

  // 6. 真实call
  int ret = libc_ioctl_handle(fd, request, argp);

  // 7. post proto (可选，调试)
  Ioctl post_info;
  post_info.set_fd_path(file_name);
  post_info.set_request(request);
  post_info.set_ret(ret);
  post_info.set_arg_data(argp, arg_size);
  // ... (类似post params, 无需set_subclass)
  WriteIoctlProto(post_info);

  return ret;
}

}  // extern "C"