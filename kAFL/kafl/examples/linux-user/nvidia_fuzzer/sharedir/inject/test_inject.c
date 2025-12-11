#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <inttypes.h> // 为 PRIx64 等
#include <assert.h> // 为 _Static_assert
// === added: harness_log and HARNESS_PRINTF ===
#include <stdarg.h>
#include <time.h>

static const char* _resolve_log_path(void){
    const char* p = getenv("HARNESS_LOG");
    if (p && *p) return p;
    return "/sharedir/log/nvidia_inject2.log";
}

static void harness_log(const char *fmt, ...) {
    const char* log_path = _resolve_log_path();
    FILE *log = fopen(log_path, "a");
    if (!log) {
        log = fopen("/sharedir/log/nvidia_inject2.log", "a");
        if (!log) return;
    }
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

#define HARNESS_PRINTF(...) do { printf(__VA_ARGS__); harness_log(__VA_ARGS__); } while(0)
// === end added ===

// CONTROL: 32B (基于 gVisor NVOS54, 确认大小/对齐)
typedef struct {
    uint32_t hClient;     // 0
    uint32_t hObject;     // 4
    uint32_t cmd;         // 8
    uint32_t flags;       // 12
    uintptr_t params;     // 16 (8B)
    uint32_t paramsSize;  // 24
    uint32_t status;      // 28
} NVOS54_PARAMETERS;
_Static_assert(sizeof(NVOS54_PARAMETERS) == 32, "NVOS54 size mismatch");

typedef struct {
    uint32_t hRoot;            // 偏移 0
    uint32_t hObjectParent;    // 4
    uint32_t hObjectNew;       // 8
    uint32_t hClass;           // 12
    uint64_t pAllocParms;      // 16 (先 pAllocParms)
    uint64_t pRightsRequested; // 24 (后 pRightsRequested)
    uint32_t paramsSize;       // 32
    uint32_t flags;            // 36
    uint32_t status;           // 40
    uint32_t pad0;             // 44 (补齐到48B)
} NVOS64_PARAMETERS;
_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "NVOS64 size mismatch");

// ALLOC 字段偏移宏 (基于典型布局，按字节；从你的 harness 确认)
#define OFF_HROOT           0
#define OFF_HOBJECTPARENT   4
#define OFF_HOBJECTNEW      8
#define OFF_HCLASS          12
#define OFF_PALLOCParms     16 // 8B
#define OFF_PRIGHTSREQUESTED 24 // 8B
#define OFF_PARAMSSIZE      32
#define OFF_FLAGS           36
#define OFF_STATUS          40
#define OFF_PAD0            44 

#define NV_ESC_RM_ALLOC 0xc030462bULL // unsigned long
#define NV_ESC_RM_CONTROL 0xc020462aULL // unsigned long
#define NV01_ROOT_CLIENT 0x00000001
#define NV2080_DEVICE 0x20800100UL // 示例
// NV2080 / subdevice 相关
#define NV01_DEVICE_0    0x00000080u
#define NV20_SUBDEVICE_0 0x00002080u

typedef struct {
    uint32_t deviceId;        // 设备实例号，一般从 0 开始
    uint32_t hClientShare;    // 共享的 client（裸机可以为0）
    uint32_t hTargetClient;   // 目标 client（通常同上或0）
    uint32_t hTargetDevice;   // 目标 device（通常0）
    uint32_t flags;           // 分配 flags，先用 0
    uint32_t pad0;            // 对齐
    uint64_t vaSpaceSize;     // VA 空间大小，0=让 RM 选默认
    uint64_t vaStartInternal; // 限制 VA 起始，配合 flags 使用
    uint64_t vaLimitInternal; // 限制 VA 结束
    uint32_t vaMode;          // VA 模式，0 = 默认
    uint32_t pad1;            // 对齐
} NV0080_ALLOC_PARAMETERS;

_Static_assert(sizeof(NV0080_ALLOC_PARAMETERS) == 56,
               "NV0080_ALLOC_PARAMETERS size mismatch");

typedef struct {
    uint32_t subDeviceId;
} NV2080_ALLOC_PARAMETERS;

_Static_assert(sizeof(NV2080_ALLOC_PARAMETERS) == 4, "NV2080_ALLOC_PARAMETERS size mismatch");


int main(int argc, char **argv) {
    if (argc < 2) {
        HARNESS_PRINTF("Usage: %s <seed_file>\n", argv[0]);
        return 1;
    }
    // 读取 seed
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen seed"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(size ? size : 1);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, size, f);
    fclose(f);
    HARNESS_PRINTF("Loaded seed: %zu bytes\n", size);
    if (size < 24) { HARNESS_PRINTF("Seed too small\n"); free(data); return 0; }
    // 安全解析24B头 (用 memcpy 防未对齐 UB)
    uint32_t magic, ret, subclass, arg_size;
    uint64_t request;
    memcpy(&magic, data + 0, sizeof(uint32_t));
    memcpy(&request, data + 4, sizeof(uint64_t));
    memcpy(&ret, data + 12, sizeof(uint32_t));
    memcpy(&subclass, data + 16, sizeof(uint32_t));
    memcpy(&arg_size, data + 20, sizeof(uint32_t));
    uint8_t *params_data = data + 24;
    if (magic != 0x4E564944) { HARNESS_PRINTF("Invalid magic: 0x%" PRIx32 "\n", magic); free(data); return 6; }
    if (ret != 0) { HARNESS_PRINTF("Invalid ret: 0x%" PRIx32 " (expect 0)\n", ret); free(data); return 7; }
    if (arg_size != size - 24) { HARNESS_PRINTF("Size mismatch: header %" PRIu32 ", file %zu\n", arg_size, size - 24); free(data); return 8; }
    if (arg_size > 1048576) { HARNESS_PRINTF("Arg too large: %" PRIu32 " (>1MB)\n", arg_size); free(data); return 9; } // 防 OOM
    int fd = open("/dev/nvidiactl", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open /dev/nvidiactl"); free(data); return 2; }
    
    // Alloc root client
    NVOS64_PARAMETERS alloc;
    memset(&alloc, 0, sizeof(alloc));  // 显式清零，确保无垃圾/残留
    alloc.hRoot = 0;
    alloc.hObjectParent = 0;
    alloc.hClass = NV01_ROOT_CLIENT;
    alloc.paramsSize = 0;  // 默认0，无额外parms
    alloc.flags = 0;
    alloc.pRightsRequested = 0;
    alloc.pAllocParms = 0;
    alloc.status = 0;  
    int r = ioctl(fd, (unsigned long)NV_ESC_RM_ALLOC, &alloc);
    if (r < 0 || alloc.status != 0 || alloc.hObjectNew == 0) {  // 保持严格检查
        HARNESS_PRINTF("Alloc root failed: ret=%d errno=%d status=0x%" PRIx32 " hNew=0x%" PRIx32 "\n",
                       r, errno, alloc.status, alloc.hObjectNew);
        close(fd); free(data); return 3;
    }
    uint32_t hClient = alloc.hObjectNew;
    HARNESS_PRINTF("Allocated hClient: 0x%" PRIx32 " (status=0x%" PRIx32 ", errno=%d)\n",
                   hClient, alloc.status, errno);

    // Alloc device
    NV0080_ALLOC_PARAMETERS dev0080;
    memset(&dev0080, 0, sizeof(dev0080));

    dev0080.deviceId      = 0;        // 先假设第0个 GPU，如果你只有一张卡，这通常是对的
    dev0080.hClientShare  = hClient;        // 裸机环境下，0 = 使用全局 VA space
    dev0080.hTargetClient = 0;        // 没有特殊共享需求，先置0
    dev0080.hTargetDevice = 0;        // 同上
    dev0080.flags         = 0;        // 不限制 reserved valimits / 不启用特殊标志
    dev0080.vaSpaceSize   = 0;        // 0 = 让 RM 选择默认 VA 大小
    dev0080.vaStartInternal = 0;      // 未启用 RESTRICT_RESERVED_VALIMITS 时可为0
    dev0080.vaLimitInternal = 0;      // 同上
    dev0080.vaMode        = 0;        // 默认 VA 模式
    // pad0 / pad1 已经通过 memset 归零
    // 填 NVOS64_PARAMETERS，指向 dev0080
    memset(&alloc, 0, sizeof(alloc));
    alloc.hRoot         = hClient;
    alloc.hObjectParent = hClient;
    alloc.hClass        = NV01_DEVICE_0;
    alloc.pAllocParms   = (uint64_t)(uintptr_t)&dev0080;
    alloc.paramsSize    = sizeof(dev0080);
    alloc.pRightsRequested = 0;
    alloc.flags         = 0;
    alloc.status        = 0;

    r = ioctl(fd, (unsigned long)NV_ESC_RM_ALLOC, &alloc);

    if (r < 0 || alloc.status != 0 || alloc.hObjectNew == 0 || alloc.hObjectNew == hClient) {
        HARNESS_PRINTF("Alloc NV01_DEVICE_0 failed: ret=%d errno=%d status=0x%" PRIx32 " hNew=0x%" PRIx32 "\n",
                    r, errno, alloc.status, alloc.hObjectNew);
        close(fd);
        free(data);
        return 4;
    }

    uint32_t hDevice = alloc.hObjectNew;
    HARNESS_PRINTF("Allocated hDevice: 0x%" PRIx32 " (status=0x%" PRIx32 ", errno=%d)\n",
               hDevice, alloc.status, errno);



    // 再 Alloc NV20_SUBDEVICE_0 (NV2080 subdevice，对应 NV2080 控制命令)
    NV2080_ALLOC_PARAMETERS sub_params;
    memset(&sub_params, 0, sizeof(sub_params));
    sub_params.subDeviceId = 0;   // 通常 0 就是这个 GPU 的第一个 subdevice

    memset(&alloc, 0, sizeof(alloc));
    alloc.hRoot         = hClient;
    alloc.hObjectParent = hDevice;          // 关键：parent = device handle
    alloc.hClass        = NV20_SUBDEVICE_0;
    alloc.pAllocParms   = (uint64_t)(uintptr_t)&sub_params;
    alloc.paramsSize    = sizeof(sub_params);
    alloc.pRightsRequested = 0;
    alloc.flags         = 0;
    alloc.status        = 0;

    r = ioctl(fd, (unsigned long)NV_ESC_RM_ALLOC, &alloc);
    if (r < 0 || alloc.status != 0 || alloc.hObjectNew == 0 || alloc.hObjectNew == hClient) {
        HARNESS_PRINTF("Alloc subdevice failed: ret=%d errno=%d status=0x%" PRIx32 " hNew=0x%" PRIx32 "\n",
                       r, errno, alloc.status, alloc.hObjectNew);
        close(fd); free(data); return 5;
    }

    uint32_t hObject = alloc.hObjectNew;  // 这里 hObject 就是 NV20_SUBDEVICE_0
    HARNESS_PRINTF("Allocated hObject: 0x%" PRIx32 " (status=0x%" PRIx32 ", errno=%d)\n",
                   hObject, alloc.status, errno);

    HARNESS_PRINTF("Request=0x%" PRIx64 ", subclass=0x%" PRIx32 ", params_size=%" PRIu32 "\n", request, subclass, arg_size);
    // Hex dump 前 64B params (调试)
    HARNESS_PRINTF("Params hex (first 64B): ");
    for (size_t i = 0; i < 64 && i < arg_size; i++) HARNESS_PRINTF("%02x ", params_data[i]);
    HARNESS_PRINTF("\n");
    if (request == NV_ESC_RM_CONTROL) {
        NVOS54_PARAMETERS wrapper = {0};
        wrapper.hClient = hClient;
        wrapper.hObject = hObject;
        wrapper.cmd = subclass; // 从头取
        wrapper.flags = 0;
        void *userbuf = NULL;
        if (arg_size) {
            userbuf = malloc(arg_size);
            if (!userbuf) { perror("malloc userbuf"); close(fd); free(data); return 5; }
            memcpy(userbuf, params_data, arg_size);
            wrapper.params = (uintptr_t)userbuf;
            wrapper.paramsSize = arg_size;
        }
        r = ioctl(fd, (unsigned long)request, &wrapper);
        HARNESS_PRINTF("ioctl ret=%d errno=%d status=0x%" PRIx32 "\n", r, errno, wrapper.status);
        HARNESS_PRINTF("Result: %s\n", (r == 0 && wrapper.status == 0) ? "success" : "fail");
        if (userbuf) free(userbuf);
    } else if (request == NV_ESC_RM_ALLOC) {
        if (arg_size != sizeof(NVOS64_PARAMETERS)) {
            HARNESS_PRINTF("ALLOC arg_size mismatch: expect 48, got %" PRIu32 "\n", arg_size);
            close(fd); free(data); return 9;
        }
        NVOS64_PARAMETERS wrapper = {0};
        // 逐字段填写 (防布局不完全匹配；基于 OFF_宏，按你的 harness 偏移调整)
        memcpy(&wrapper.hRoot, params_data + OFF_HROOT, sizeof(uint32_t));
        memcpy(&wrapper.hObjectParent, params_data + OFF_HOBJECTPARENT, sizeof(uint32_t));
        memcpy(&wrapper.hObjectNew, params_data + OFF_HOBJECTNEW, sizeof(uint32_t));
        memcpy(&wrapper.hClass, params_data + OFF_HCLASS, sizeof(uint32_t));
        memcpy(&wrapper.pAllocParms, params_data + 16, sizeof(uint64_t));  // 新偏移
        memcpy(&wrapper.pRightsRequested, params_data + 24, sizeof(uint64_t));
        memcpy(&wrapper.paramsSize, params_data + 32, sizeof(uint32_t));
        memcpy(&wrapper.flags, params_data + 36, sizeof(uint32_t));
        memcpy(&wrapper.status, params_data + 40, sizeof(uint32_t));
        memcpy(&wrapper.pad0, params_data + 44, sizeof(uint32_t));
        // 安全重写：hRoot=hClient, if hObjectParent==0 set hClient, pRightsRequested/pAllocParms=0
        wrapper.hRoot = hClient;
        if (wrapper.hObjectParent == 0) wrapper.hObjectParent = hClient;
        wrapper.pRightsRequested = 0;
        wrapper.pAllocParms = 0;
        r = ioctl(fd, (unsigned long)request, &wrapper);
        HARNESS_PRINTF("ALLOC ioctl ret=%d errno=%d status=0x%" PRIx32 "\n", r, errno, wrapper.status);
        HARNESS_PRINTF("Result: %s\n", (r == 0 && wrapper.status == 0) ? "success" : "fail");
    } else {
        HARNESS_PRINTF("Unsupported request: 0x%" PRIx64 "\n", request);
        HARNESS_PRINTF("Result: fail\n");
    }
    // 添加 dmesg tail 检查 error
    HARNESS_PRINTF("\n--- dmesg tail ---\n");
    system("dmesg | tail -10");
    close(fd);
    free(data);
    sleep(1); // 防批量 panic
    return 0;
}
