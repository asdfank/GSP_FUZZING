// test_inject_logged.c
// Build: gcc -std=c11 -O2 -Wall -Wextra -o test_inject_logged test_inject_logged.c
// Usage: sudo ./test_inject_logged seed.bin [/dev/nvidiactl]
//
// 说明：这是在 test_inject 基础上加了 harness_log 的单次注入器，
// 会把每一步执行过程（打开设备、分配 ROOT/NV2080、注入 ALLOC/CONTROL、返回码/errno、dmesg 尾部）写入日志。
// 日志位置：优先使用环境变量 HARNESS_LOG，未设置则写 /var/log/nvidia_harness.log，
// 如无权限则回落到 /tmp/nvidia_harness.log。

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <time.h>

// ----------------------------- Logging ----------------------------------

static const char* resolve_log_path(void){
    const char* p = getenv("HARNESS_LOG");
    if (p && *p) return p;
    return "/sharedir/log/nvidia_inject.log";
}

static void harness_log(const char *fmt, ...) {
    const char* log_path = resolve_log_path();
    FILE *log = fopen(log_path, "a");
    if (!log) {
        log = fopen("/sharedir/log/nvidia_inject.log", "a");
        if (!log) return;
    }
    // UTC 时间戳
    time_t now = time(NULL);
    struct tm tm_info;
    gmtime_r(&now, &tm_info);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    fprintf(log, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log, fmt, ap);
    va_end(ap);
    fputc('\n', log);
    fflush(log);
    fclose(log);
}

static void hexdump_log(const void* data, size_t len, size_t max_len){
    const unsigned char* p = (const unsigned char*)data;
    size_t n = len < max_len ? len : max_len;
    char line[3*16 + 32];
    for (size_t i = 0; i < n; i += 16){
        int off = 0;
        off += snprintf(line+off, sizeof(line)-off, "%04zx: ", i);
        for (size_t j=0;j<16 && i+j<n;j++){
            off += snprintf(line+off, sizeof(line)-off, "%02x ", p[i+j]);
        }
        harness_log("[hexdump] %s", line);
    }
    if (len > n) harness_log("[hexdump] ... (%zu bytes total, %zu shown)", len, n);
}

// --------------------------- NV structures ------------------------------

// CONTROL: 32B (ioctl 0xc020462a)
typedef struct {
    uint32_t hClient;
    uint32_t hObject;
    uint32_t cmd;
    uint32_t flags;
    uint64_t params;
    uint32_t paramsSize;
    uint32_t reserved;
} NVOS54_CTRL; // size 32
_Static_assert(sizeof(NVOS54_CTRL) == 32, "NVOS54_CTRL size mismatch");

// ALLOC: 48B (ioctl 0xc030462b)
typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectNew;
    uint32_t hClass;
    uint64_t pRightsRequested;
    uint64_t pAllocParms;
    uint32_t flags;
    uint32_t status;
    uint64_t padding;
} NVOS64_PARAMETERS;
_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "NVOS64 size mismatch");

// 种子头：24B -> [request:8][arg_size:4][reserved:4][subclass:8]
typedef struct {
    uint64_t request;
    uint32_t arg_size;
    uint32_t reserved;
    uint64_t subclass; // for CONTROL
} seed_hdr_t;
_Static_assert(sizeof(seed_hdr_t) == 24, "seed_hdr_t size mismatch");

// ioctl 常量（常见值）
#define NV_ESC_RM_CONTROL 0xc020462aULL
#define NV_ESC_RM_ALLOC   0xc030462bULL
#define NV01_ROOT_CLIENT  0x00000001u
// NV2080 设备类（不同代卡可能不同，这里使用常见的 0x20800100）
#define NV2080_DEVICE     0x20800100u

// ------------------------------- Helpers --------------------------------

static int read_seed(const char* path, seed_hdr_t* hdr, void** body_out){
    FILE* f = fopen(path, "rb");
    if (!f){
        harness_log("[ENV_FAIL] open seed '%s' errno=%d", path, errno);
        return -1;
    }
    size_t rd = fread(hdr, 1, sizeof(*hdr), f);
    if (rd != sizeof(*hdr)){
        harness_log("[INPUT_FAIL] short read header: got=%zu need=%zu", rd, sizeof(*hdr));
        fclose(f);
        return -1;
    }
    harness_log("seed header: request=0x%llx arg_size=%u subclass=0x%llx",
                (unsigned long long)hdr->request, hdr->arg_size,
                (unsigned long long)hdr->subclass);
    if (hdr->arg_size > (256u<<20)){ // 256MB 防呆
        harness_log("[INPUT_FAIL] arg_size too large: %u", hdr->arg_size);
        fclose(f);
        return -1;
    }
    void* buf = NULL;
    if (hdr->arg_size){
        buf = malloc(hdr->arg_size);
        if (!buf){
            harness_log("[ENV_FAIL] malloc body size=%u failed", hdr->arg_size);
            fclose(f);
            return -1;
        }
        rd = fread(buf, 1, hdr->arg_size, f);
        if (rd != hdr->arg_size){
            harness_log("[INPUT_FAIL] short read body: got=%zu need=%u", rd, hdr->arg_size);
            free(buf);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    *body_out = buf;
    return 0;
}

static void log_dmesg_tail(void){
    FILE* p = popen("dmesg | tail -n 20", "r");
    if (!p){
        harness_log("popen dmesg failed errno=%d", errno);
        return;
    }
    char line[512];
    harness_log("--- dmesg tail begin ---");
    while (fgets(line, sizeof(line), p)){
        size_t L = strlen(line);
        while (L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L] = 0;
        harness_log("%s", line);
    }
    harness_log("--- dmesg tail end ---");
    pclose(p);
}

// --------------------------------- Main ---------------------------------

int main(int argc, char** argv){
    if (argc < 2){
        fprintf(stderr, "Usage: %s <seed.bin> [device=/dev/nvidiactl]\n", argv[0]);
        return 2;
    }
    const char* dev = (argc >= 3) ? argv[2] : "/dev/nvidiactl";
    seed_hdr_t hdr;
    void* body = NULL;

    harness_log("========== test_inject_logged start ==========");
    harness_log("argv[1]=seed='%s' device='%s'", argv[1], dev);

    if (read_seed(argv[1], &hdr, &body) != 0){
        harness_log("read_seed failed; exit");
        return 1;
    }
    harness_log("seed body hexdump (first 64 bytes):");
    hexdump_log(body, hdr.arg_size, 64);

    // 打开设备
    int fd = open(dev, O_RDWR);
    if (fd < 0){
        harness_log("[ENV_FAIL] open %s errno=%d", dev, errno);
        free(body);
        return 1;
    }
    harness_log("open(%s) ok fd=%d", dev, fd);

    // 分配 NV01_ROOT_CLIENT
    NVOS64_PARAMETERS alloc = {0};
    alloc.hRoot = 0;
    alloc.hObjectParent = 0;
    alloc.hObjectNew = 0;
    alloc.hClass = NV01_ROOT_CLIENT;
    alloc.pRightsRequested = 0;
    alloc.pAllocParms = 0;
    alloc.flags = 0;
    alloc.status = 0;
    int r = ioctl(fd, NV_ESC_RM_ALLOC, &alloc);
    harness_log("ALLOC ROOT ret=%d errno=%d status=0x%x hNew=0x%x",
                r, errno, alloc.status, alloc.hObjectNew);
    if (r != 0 || alloc.status != 0 || alloc.hObjectNew == 0){
        harness_log("[ENV_FAIL] alloc root failed -> exit");
        close(fd);
        free(body);
        return 1;
    }
    uint32_t hClient = alloc.hObjectNew;

    // 分配 NV2080 device（固定 flags=0）
    memset(&alloc, 0, sizeof(alloc));
    alloc.hRoot = hClient;
    alloc.hObjectParent = hClient;
    alloc.hClass = NV2080_DEVICE;
    r = ioctl(fd, NV_ESC_RM_ALLOC, &alloc);
    harness_log("ALLOC NV2080 ret=%d errno=%d status=0x%x hNew=0x%x",
                r, errno, alloc.status, alloc.hObjectNew);
    if (r != 0 || alloc.status != 0 || alloc.hObjectNew == 0){
        harness_log("[ENV_FAIL] alloc NV2080 failed -> exit");
        close(fd);
        free(body);
        return 1;
    }
    uint32_t hObject = alloc.hObjectNew;

    // 根据 request 分派
    if (hdr.request == NV_ESC_RM_CONTROL){
        NVOS54_CTRL ctrl;
        memset(&ctrl, 0, sizeof(ctrl));
        ctrl.hClient = hClient;
        ctrl.hObject = hObject;
        ctrl.cmd = (uint32_t)(hdr.subclass & 0xffffffffu);
        ctrl.flags = 0;
        ctrl.params = (uintptr_t)body;
        ctrl.paramsSize = hdr.arg_size;
        harness_log("CONTROL begin: hC=0x%x hO=0x%x cmd=0x%x size=%u",
                    ctrl.hClient, ctrl.hObject, ctrl.cmd, ctrl.paramsSize);
        r = ioctl(fd, NV_ESC_RM_CONTROL, &ctrl);
        harness_log("CONTROL end: ret=%d errno=%d (cmd=0x%x size=%u)",
                    r, errno, ctrl.cmd, ctrl.paramsSize);
        printf("Result: %s\n", (r==0) ? "success" : "fail");

    } else if (hdr.request == NV_ESC_RM_ALLOC){
        if (hdr.arg_size != sizeof(NVOS64_PARAMETERS)){
            harness_log("[INPUT_DROP] ALLOC arg_size=%u != %zu", hdr.arg_size, sizeof(NVOS64_PARAMETERS));
            printf("Result: fail\n");
        } else {
            NVOS64_PARAMETERS w;
            memcpy(&w, body, sizeof(w));
            // 安全覆写：避免将种子中的外部 root/指针传入内核
            w.hRoot = hClient;
            if (w.hObjectParent == 0) w.hObjectParent = hClient;
            w.pRightsRequested = 0;
            w.pAllocParms = 0;
            harness_log("ALLOC begin: class=0x%x parent=0x%x flags=0x%x", w.hClass, w.hObjectParent, w.flags);
            r = ioctl(fd, NV_ESC_RM_ALLOC, &w);
            harness_log("ALLOC end: ret=%d errno=%d status=0x%x hNew=0x%x", r, errno, w.status, w.hObjectNew);
            printf("Result: %s\n", (r==0 && w.status==0) ? "success" : "fail");
        }

    } else {
        harness_log("[INPUT_DROP] Unsupported request=0x%llx", (unsigned long long)hdr.request);
        printf("Result: fail\n");
    }

    log_dmesg_tail();
    close(fd);
    free(body);
    harness_log("========== test_inject_logged end ==========");
    return 0;
}
