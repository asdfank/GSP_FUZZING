/*
 * nvidia_harness.c
 * ... (header comments remain the same) ...
 */

// ... (existing includes) ...
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <inttypes.h>

// >>> 新增: 为了文件日志功能，需要包含以下头文件 <<<
#include <stdarg.h>
#include <time.h>

/* ... (existing includes like linux/mman.h) ... */
#ifdef __linux__
#include <linux/mman.h>
#endif

/* nyx / kAFL agent API headers (present in your repo) */
#include "nyx_api.h"
#include "nyx_agent.h"

/* ... (existing defines like HYPERCALL_KAFL_GET_PAYLOAD, MAP_ANONYMOUS, etc.) ... */
#ifndef HYPERCALL_KAFL_GET_PAYLOAD
#error "nyx_api.h missing expected defines - ensure include path is correct"
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef HYPERCALL_KAFL_RANGE_SUBMIT
#define HYPERCALL_KAFL_RANGE_SUBMIT 29 
#endif
#define MAX_PT_RANGES 4  // Intel PT 支持的最大范围数

// >>> 新增: 文件日志函数 <<<
/**
 * @brief 将带时间戳的格式化日志消息追加到 /var/log/nvidia_harness.log
 */
void harness_log(const char *format, ...) {
    // 使用追加模式 "a" 打开日志文件
    FILE *log_file = fopen("/var/log/nvidia_harness.log", "a");
    if (!log_file) {
        // 如果日志文件都打不开，我们也无能为力了
        return;
    }

    // 1. 写入时间戳
    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(log_file, "[%s] ", time_buf);

    // 2. 写入用户提供的日志消息
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    // 3. 写入换行符
    fprintf(log_file, "\n");

    // 4. 关键：立即刷新缓冲区到磁盘，防止因崩溃而丢失日志
    fflush(log_file);

    // 5. 关闭文件
    fclose(log_file);
}

// NVOS54_PARAMETERS (不变)
typedef struct {
    uint32_t hClient;
    uint32_t hObject;
    uint32_t cmd;
    uint32_t flags;
    void* params;
    uint32_t paramsSize;
    uint32_t status;
} NVOS54_PARAMETERS;

// NVOS21_PARAMETERS for ALLOC (简化)
typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectNew;
    uint32_t hClass;
    uint32_t status;
    // ... (add if need, total 48B)
} NVOS21_PARAMETERS;
// Requests and classes
#define NV_ESC_RM_ALLOC 0xc030462b
#define NV_ESC_RM_CONTROL 0xc020462a
#define NV01_ROOT_CLIENT 0x00000001  // hClass for root client
#define NV2080_DEVICE 0x20800100    // 示例 hClass for device object

static kAFL_payload *my_kafl_agent_init(int verbose)
{
    harness_log("Entering my_kafl_agent_init().");
    host_config_t host_cfg;
    memset(&host_cfg, 0, sizeof(host_cfg));

    harness_log("Requesting host config via HYPERCALL_KAFL_GET_HOST_CONFIG.");
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_cfg);
    harness_log("Host config received: magic=0x%x, version=0x%x.", host_cfg.host_magic, host_cfg.host_version);

    if (verbose) {
        hprintf("[agent_init] host_magic=0x%x host_version=0x%x bitmap_size=%u payload_buffer_size=%u worker_id=%u\n",
                host_cfg.host_magic, host_cfg.host_version, host_cfg.bitmap_size,
                host_cfg.payload_buffer_size, host_cfg.worker_id);
    }
    
    // ... (rest of my_kafl_agent_init is the same, I've just added logging) ...
    if (host_cfg.host_magic != NYX_HOST_MAGIC) {
        harness_log("FATAL: HOST_MAGIC mismatch!");
        habort("HOST_MAGIC mismatch (incompatible host/agent)");
        return NULL;
    }
    
    agent_config_t agent_cfg;
    memset(&agent_cfg, 0, sizeof(agent_cfg));
    agent_cfg.agent_magic = NYX_AGENT_MAGIC;
    agent_cfg.agent_version = NYX_AGENT_VERSION;
    agent_cfg.input_buffer_size = 0;
    agent_cfg.agent_non_reload_mode = 1;
    agent_cfg.agent_tracing = 0;
    agent_cfg.trace_buffer_vaddr = 0;
    agent_cfg.coverage_bitmap_size = 0;

    harness_log("Submitting agent config: non_reload_mode=1, agent_tracing=0.");
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_cfg);
    harness_log("Agent config submitted.");
    
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    if (page_size <= 0) page_size = 4096;
    size_t num_pages = (host_cfg.payload_buffer_size+ page_size - 1) / page_size;
    if (num_pages == 0) num_pages = 1;

    harness_log("Allocating resident pages for payload buffer.");
    void *buf = malloc_resident_pages(num_pages);
    if (!buf) {
        harness_log("FATAL: malloc_resident_pages failed.");
        habort("malloc_resident_pages failed");
        return NULL;
    }
    harness_log("Payload buffer allocated at %p.", buf);
    
    memset(buf, 0, num_pages * page_size);
    
    harness_log("Registering payload buffer via HYPERCALL_KAFL_GET_PAYLOAD.");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)buf);
    harness_log("Payload buffer registered.");

    if (verbose) {
        hprintf("[agent_init] allocated payload buffer at %p (%zu pages, %zu bytes)\n",
                buf, num_pages, num_pages * (size_t)page_size);
    }

    harness_log("Leaving my_kafl_agent_init().");
    return (kAFL_payload *)buf;
}

static void submit_gsp_ranges(void) {
    harness_log("Entering submit_gsp_ranges().");
    FILE *fp;
    char line[128];
    uint64_t text_base = 0;
    int range_count = 0;

    harness_log("Attempting to open /sys/module/nvidia/sections/.text");
    fp = fopen("/sys/module/nvidia/sections/.text", "r");
    if (!fp) {
        harness_log("FATAL: fopen failed for /sys/module/nvidia/sections/.text");
        habort("[harness] FATAL: Cannot read /sys/module/nvidia/sections/.text");
        return;
    }
    harness_log("Successfully opened /sys/module/nvidia/sections/.text");
    
    if (fscanf(fp, "%" SCNx64, &text_base) != 1) {
        fclose(fp);
        harness_log("FATAL: Failed to parse .text base address.");
        habort("[harness] FATAL: Failed to parse .text base address");
        return;
    }
    fclose(fp);
    harness_log("Parsed NVIDIA .text base: 0x%" PRIx64, text_base);
    hprintf("[harness] NVIDIA .text base: 0x%" PRIx64 "\n", text_base);

    // ... (rest of the function is the same, just with logging) ...
    harness_log("Attempting to open /sharedir/nv_gsp_ranges.rel");
    fp = fopen("/sharedir/nv_gsp_ranges.rel", "r");
    if (!fp) {
        harness_log("WARNING: Cannot open /sharedir/nv_gsp_ranges.rel. Proceeding without PT filters.");
        hprintf("[harness] WARNING: Cannot open /sharedir/nv_gsp_ranges.rel. Proceeding without PT filters.\n");
        return;
    }
    harness_log("Successfully opened /sharedir/nv_gsp_ranges.rel");

    while (fgets(line, sizeof(line), fp) && range_count < MAX_PT_RANGES) {
        long long start_off, end_off;  
        if (sscanf(line, "+0x%llx-+0x%llx", &start_off, &end_off) == 2) {
            // ... (your existing logic for range checking) ...
            if (start_off < 0 || end_off < 0) {
                hprintf("[harness] WARNING: Negative offset skipped: +0x%llx - +0x%llx\n", start_off, end_off);
                continue;
            }
            uint64_t abs_start = text_base + (uint64_t)start_off;
            uint64_t abs_end = text_base + (uint64_t)end_off;
            // ...
            if (abs_start >= abs_end) {
                hprintf("[harness] WARNING: Invalid range skipped (start >= end)\n");
                continue;
            }
            uint64_t range_submission[3] = {abs_start, abs_end, (uint64_t)range_count};
            
            harness_log("Submitting range[%d]: 0x%" PRIx64 " - 0x%" PRIx64, range_count, abs_start, abs_end);
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)range_submission);
            
            hprintf("[harness] Submitted PT range[%d]: 0x%" PRIx64 " - 0x%" PRIx64 "\n", range_count, abs_start, abs_end);
            range_count++;
        }
    }
    fclose(fp);
    if (range_count > 0) 
    {
        harness_log("Finished processing ranges file. Total submitted: %d.", range_count);
    }
    else
    {
        hprintf("[harness] Submitted %d GSP ranges to host.\n", range_count);
    }
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    
    // 清空旧日志，开始新的会话
    remove("/var/log/nvidia_harness.log");
    harness_log("Harness main() started.");
    
    hprintf("[harness] main() has been started.\n");

    harness_log("Calling my_kafl_agent_init().");
    kAFL_payload *payload = my_kafl_agent_init(1);
    if (!payload) {
        harness_log("FATAL: my_kafl_agent_init() returned NULL.");
        return 1;
    }
    harness_log("my_kafl_agent_init() successful.");

    harness_log("Calling submit_gsp_ranges().");
    submit_gsp_ranges();
    harness_log("submit_gsp_ranges() successful.");

    harness_log("Attempting to open /dev/nvidiactl...");
    int fd = -1;
    const int max_tries = 60;
    int tries = 0;
    while (tries < max_tries) {
        fd = open("/dev/nvidiactl", O_RDWR);
        if (fd >= 0) break;
        tries++;
        hprintf("[nvidia_harness] waiting for /dev/nvidiactl (attempt %d) errno=%d\n", tries, errno);
        sleep(1);
    }
    if (fd < 0) {
        harness_log("FATAL: Failed to open /dev/nvidiactl after %d tries.", max_tries);
        habort("Failed to open /dev/nvidiactl");
        return 2;
    }
    harness_log("Successfully opened /dev/nvidiactl, fd=%d.", fd);
    hprintf("[nvidia_harness] opened /dev/nvidiactl fd=%d\n", fd);
    
    // >>> 新增: 动态 alloc hClient 和 hObject <<<
    uint32_t hClient = 0;
    uint32_t hObject = 0;

    // Alloc root client (hClient)
    NVOS21_PARAMETERS alloc_params = {0};
    alloc_params.hRoot = 0;
    alloc_params.hObjectParent = 0;
    alloc_params.hClass = NV01_ROOT_CLIENT;
    int r = ioctl(fd, NV_ESC_RM_ALLOC, &alloc_params);
    if (r < 0 || alloc_params.status != 0) {
        harness_log("FATAL: Alloc root client failed: ret=%d status=0x%x", r, alloc_params.status);
        close(fd);
        return 3;
    }
    hClient = alloc_params.hObjectNew;
    harness_log("Allocated hClient (root): 0x%x", hClient);

    // Alloc device object (hObject) under hClient
    alloc_params.hRoot = hClient;
    alloc_params.hObjectParent = hClient;
    alloc_params.hClass = NV2080_DEVICE;  // 示例, 从 log hClass=0xc640? 调整为匹配你的 (0x41 or 0xc640)
    r = ioctl(fd, NV_ESC_RM_ALLOC, &alloc_params);
    if (r < 0 || alloc_params.status != 0) {
        harness_log("FATAL: Alloc device object failed: ret=%d status=0x%x", r, alloc_params.status);
        close(fd);
        return 3;
    }
    hObject = alloc_params.hObjectNew;
    harness_log("Allocated hObject (device): 0x%x", hObject);
    
    harness_log("Entering main fuzzing loop.");
    while (1) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	harness_log("Processing payload, size=%zu", payload->size);
	//hprintf("Processing payload, size=%zu\n", payload->size);
        if (payload->size < 12) {
            goto release_and_continue;
        }

        uint64_t request;
        uint32_t subclass;
        memcpy(&request, payload->data, 8);
        memcpy(&subclass, &payload->data[8], 4);
        
        uint32_t cmd = (uint32_t)request;
        void* seed_data = &payload->data[12];
        size_t seed_size = payload->size - 12;

        void *argp_to_ioctl = NULL;
        r = -1;

        if (cmd == 0xc020462a) { // NV_ESC_RM_CONTROL
            NVOS54_PARAMETERS* wrapper = (NVOS54_PARAMETERS*)malloc(sizeof(NVOS54_PARAMETERS) + seed_size);
            if (!wrapper) {
                goto release_and_continue;
            }

            wrapper->hClient = hClient;  // 动态句柄
            wrapper->hObject = hObject;  // 动态句柄
            wrapper->cmd = subclass;     // 从种子
            wrapper->flags = 0;
            wrapper->paramsSize = seed_size;
            wrapper->status = 0;

            if (seed_size > 0) {
                wrapper->params = (void*)(wrapper + 1);
                memcpy(wrapper->params, seed_data, seed_size);
            } else {
                wrapper->params = NULL;
            }

            argp_to_ioctl = wrapper;
            r = ioctl(fd, cmd, argp_to_ioctl);
            harness_log("CONTROL ioctl subclass=0x%x ret=%d status=0x%x errno=%d size=%zu", subclass, r, wrapper->status, errno, seed_size);
            free(wrapper);
        } else { // 其他
            argp_to_ioctl = seed_data;
            r = ioctl(fd, cmd, argp_to_ioctl);
            harness_log("OTHER ioctl cmd=0x%x ret=%d errno=%d size=%zu", cmd, r, errno, seed_size);
        }

    release_and_continue:
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    close(fd);
    return 0;
}
