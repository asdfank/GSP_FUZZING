#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/ioctl.h>
#include <fcntl.h> // for open/O_RDONLY
#include <stdarg.h>
// ==========================================
// 结构体与宏定义
// ==========================================

// NVOS54 定义 (必须与 Harness/内核 ABI 严格一致)
// 64位系统下，params 为 64位指针，整体大小为 32 字节
typedef struct {
    uint32_t hClient;
    uint32_t hObject;
    uint32_t cmd;
    uint32_t flags;
    uint64_t params;      // 用户态缓冲区的地址 (uint64_t to hold pointer)
    uint32_t paramsSize;
    uint32_t status;
} NVOS54_PARAMETERS;

_Static_assert(sizeof(NVOS54_PARAMETERS) == 32, "NVOS54 size mismatch");

// 2. NVOS64 (ALLOC)
typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectNew;
    uint32_t hClass;
    uint64_t pRightsRequested; // 8B
    uint64_t pAllocParms;      // 8B - 原本是注入目标，现在我们注入整个结构体
    uint32_t flags;
    uint32_t status;
    uint64_t padding;          // 8B padding 到 48B
} NVOS64_PARAMETERS;

_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "NVOS64 size mismatch");

typedef struct __attribute__((packed)) {
    uint32_t magic;      // "NVID" 0x4E564944
    uint64_t request;    // ioctl request
    uint32_t ret;        // 固定0
    uint32_t subclass;   // CONTROL: cmd; ALLOC: hClass
    uint32_t arg_size;   // body大小
} seed_hdr_t;

_Static_assert(sizeof(seed_hdr_t) == 24, "seed_hdr_t size mismatch");

// NVIDIA Control IOCTL 定义
#define NV_ESC_RM_CONTROL       0x4620
#define NV_ESC_RM_CONTROL_NR    _IOC_NR(NV_ESC_RM_CONTROL)

#define NV_ESC_RM_ALLOC_NR      0x2b // 0xc030462b 的 NR 部分

// 原始 ioctl 函数指针
static int (*real_ioctl)(int, unsigned long, ...) = NULL;

// ==========================================
// 辅助函数
// ==========================================

// 获取文件描述符对应的路径
// 用于判断是否为 /dev/nvidiactl
static int get_fd_path(int fd, char* buf, size_t buflen) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, buflen - 1);
    if (n < 0) return -1;
    buf[n] = '\0';
    return 0;
}

// 从文件加载 Seed
// 成功返回 0，并设置 *body_out (需要调用者 free)
static int load_seed(const char* path, seed_hdr_t* hdr, unsigned char** body_out) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        // 使用 stderr 打印日志，方便在 kAFL console 或 hprintf 中捕获
        // 但要注意不要打印太频繁以免刷屏
        // fprintf(stderr, "[hook] fopen seed failed: %s\n", path);
        return -1;
    }

    if (fread(hdr, sizeof(*hdr), 1, f) != 1) {
        fprintf(stderr, "[hook] read seed hdr failed\n");
        fclose(f);
        return -1;
    }

    if (hdr->magic != 0x4E564944) { // "NVID"
        fprintf(stderr, "[hook] bad seed magic=0x%x\n", hdr->magic);
        fclose(f);
        return -1;
    }

    unsigned char* body = NULL;
    if (hdr->arg_size > 0) {
        body = (unsigned char*)malloc(hdr->arg_size);
        if (!body) { 
            fclose(f); 
            return -1; 
        }
        if (fread(body, 1, hdr->arg_size, f) != hdr->arg_size) {
            fprintf(stderr, "[hook] read seed body failed\n");
            free(body);
            fclose(f);
            return -1;
        }
    }
    
    fclose(f);
    *body_out = body;
    return 0;
}

// 核心注入逻辑
static void maybe_inject_from_seed(const char* fd_path,
                                   unsigned long request,
                                   void* argp) {
    // 1. 路径过滤
    if (!fd_path) return;
    if (strncmp(fd_path, "/dev/nvidiactl", 14) != 0) return;
    if (!argp) return;

    int nr = _IOC_NR(request);

    // 2. 仅处理 CONTROL 和 ALLOC
    if (nr != NV_ESC_RM_CONTROL_NR && nr != NV_ESC_RM_ALLOC_NR) return;

    // 3. 获取 Seed 路径
    const char* seed_path = getenv("NVIDIA_INJECT_SEED");
    if (!seed_path || !seed_path[0]) return;

    // 4. 加载 Seed
    seed_hdr_t hdr;
    unsigned char* body = NULL;
    if (load_seed(seed_path, &hdr, &body) < 0) {
        return;
    }
    
    if (hdr.arg_size == 0) {
        if (body) free(body);
        return;
    }

    // 5. 匹配 Request
    if (hdr.request != request) { free(body); return; }

    // 6. 分类处理
    if (nr == NV_ESC_RM_CONTROL_NR) {
        // --- CONTROL 逻辑 (保持不变，注入二级参数) ---
        NVOS54_PARAMETERS* w = (NVOS54_PARAMETERS*)argp;
        
        if (hdr.subclass != w->cmd) { free(body); return; }
        if (w->params == 0 || w->paramsSize == 0) { free(body); return; }
        
        if (hdr.arg_size > w->paramsSize) {
            free(body);
            return;
        }

        memcpy((void*)(uintptr_t)w->params, body, hdr.arg_size);
        w->paramsSize = hdr.arg_size;
        
    } else if (nr == NV_ESC_RM_ALLOC_NR) {
        // --- ALLOC 逻辑 (修改：直接注入一级参数 NVOS64_PARAMETERS) ---
        NVOS64_PARAMETERS* w = (NVOS64_PARAMETERS*)argp;

        // 匹配 hClass (Subclass)
        if (hdr.subclass != w->hClass) { free(body); return; }

        // 安全检查：确保种子大小不超过结构体大小 (NVOS64 是 48 字节)
        // 因为我们不再注入 pAllocParms 指向的区域，而是覆盖结构体本身，所以必须防止越界覆盖
        if (hdr.arg_size > sizeof(NVOS64_PARAMETERS)) {
             // fprintf(stderr, "[hook] ALLOC seed too big: %u\n", hdr.arg_size);
             free(body); 
             return; 
        }

        // 注入：直接覆盖 NVOS64_PARAMETERS 结构体本身
        // 这会覆盖 hRoot, hObjectParent, hClass 等所有字段
        memcpy(w, body, hdr.arg_size);
        
        // 调试日志 (可选)
        // fprintf(stderr, "[hook] injected ALLOC struct hClass=0x%x size=%u\n", w->hClass, hdr.arg_size);
    }

    free(body);
}

// ==========================================
// Hook 入口
// ==========================================

// 构造函数：库加载时自动查找原始 ioctl
__attribute__((constructor))
static void init_real_ioctl(void) {
    real_ioctl = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    if (!real_ioctl) {
        fprintf(stderr, "[hook] dlsym RTLD_NEXT(ioctl) failed\n");
        // 在构造函数中直接退出可能会导致宿主挂掉，但在 LD_PRELOAD 场景下这是致命错误
        _exit(1);
    }
}

// 拦截 ioctl
int ioctl(int fd, unsigned long request, ...) {
    if (!real_ioctl) {
        init_real_ioctl();
    }

    // 1. 取出第三个参数 argp
    va_list ap;
    void *argp = NULL;

    va_start(ap, request);
    argp = va_arg(ap, void*);
    va_end(ap);

    // 2. 可选：如果没有 argp（例如某些奇怪调用），直接走原始 ioctl
    if (!argp) {
        return real_ioctl(fd, request);
    }

    // 3. 获取 fd 对应路径，尝试注入
    char path[256] = {0};
    if (get_fd_path(fd, path, sizeof(path)) == 0) {
        maybe_inject_from_seed(path, request, argp);
    }

    // 4. 调用真实 ioctl
    return real_ioctl(fd, request, argp);
}