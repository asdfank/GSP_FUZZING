/*
 * nvidia_harness.c
 *
 * User-space harness for kAFL that exercises /dev/nvidiactl via ioctls.
 * This file inlines the agent initialization logic (GET_HOST_CONFIG, SET_AGENT_CONFIG,
 * allocate resident payload buffer and register it with hypervisor).
 *
 * Build: make (in examples/linux-user/nvidia_fuzzer after running `make env` in kAFL root)
 *
 * Requirements:
 *  - libnyx_agent headers & library available (nyx_api.h, nyx_agent.h, malloc_resident_pages, ...)
 *  - payload_size in kafl.yaml must match the buffer size derived from host_config (we assume 8192)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
/* 部分环境需要 POSIX 宏来解锁 mmap/mlock 原型 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

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

// >>> 新增: 为了文件日志功能，需要包含以下头文件 <<<
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>

/* 某些老环境对 MAP_* 宏比较奇葩，保险起见可以兜底： */
#ifdef __linux__
#include <linux/mman.h>
#endif


/* nyx / kAFL agent API headers (present in your repo) */
#include "nyx_api.h"
#include "nyx_agent.h"

/* Ensure we include the kAFL payload type from nyx_api.h */
#ifndef HYPERCALL_KAFL_GET_PAYLOAD
#error "nyx_api.h missing expected defines - ensure include path is correct"
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
/* Helper: initialize agent, set agent config, allocate resident payload buffer and register it.
 * Returns pointer to kAFL_payload or NULL on failure (calls habort on fatal errors).
 *
 * This function:
 *   - queries host config via HYPERCALL_KAFL_GET_HOST_CONFIG
 *   - sets an agent config via HYPERCALL_KAFL_SET_AGENT_CONFIG (minimal fields)
 *   - allocates resident pages via malloc_resident_pages()
 *   - registers the payload buffer with HYPERVISOR via HYPERCALL_KAFL_GET_PAYLOAD
 */
 
void harness_log(const char *format, ...) {
    FILE *log_file = fopen("/var/log/nvidia_harness.log", "a");
    if (!log_file) { return; }

    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(log_file, "[%s] ", time_buf);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file); // 关键：立即刷新，防止丢失日志
    fclose(log_file);
}

static kAFL_payload *my_kafl_agent_init(int verbose)
{
    host_config_t host_cfg;
    memset(&host_cfg, 0, sizeof(host_cfg));

    /* get host config */
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_cfg);

    if (verbose) {
        hprintf("[agent_init] host_magic=0x%x host_version=0x%x bitmap_size=%u payload_buffer_size=%u worker_id=%u\n",
                host_cfg.host_magic, host_cfg.host_version, host_cfg.bitmap_size,
                host_cfg.payload_buffer_size, host_cfg.worker_id);
    }

    /* Basic checks */
    if (host_cfg.host_magic != NYX_HOST_MAGIC) {
        habort("HOST_MAGIC mismatch (incompatible host/agent)");
        return NULL;
    }

    /* prepare agent config */
    agent_config_t agent_cfg;
    memset(&agent_cfg, 0, sizeof(agent_cfg));
    agent_cfg.agent_magic = NYX_AGENT_MAGIC;
    agent_cfg.agent_version = NYX_AGENT_VERSION;

    /* 建议：bitmap 可以跟 host，OK */
    //agent_cfg.coverage_bitmap_size = host_cfg.bitmap_size ? host_cfg.bitmap_size : 0;
    /* 关键：新 ABI 要求这里必须为 0，由 Host 决定缓冲区大小 */
    agent_cfg.input_buffer_size = 0;
    /* 关键：告诉主机“我不要 reload 模式” */
    agent_cfg.agent_non_reload_mode = 1;   /* <<< 加上这一行 */
    agent_cfg.agent_tracing = 1;
    /* dump_payloads flag will be set by host if needed; leave zero for now */
    size_t bitmap_size = host_cfg.bitmap_size;
    if (bitmap_size == 0) {
        habort("Host did not provide a valid bitmap_size!");
        return NULL;
    }

    long pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) pagesz = 4096;
    size_t aligned_size = (bitmap_size + (pagesz - 1)) & ~(pagesz - 1);
    harness_log("Allocating trace buffer (size %zu) via mmap.", aligned_size);
    void *trace_buffer = mmap(NULL, aligned_size,
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (trace_buffer == MAP_FAILED) {
        hprintf("mmap for trace_buffer failed: %s\n", strerror(errno));
        habort("mmap for trace_buffer failed");
        return NULL;
    }
    harness_log("Trace buffer allocated at %p.", trace_buffer);

    memset(trace_buffer, 0, aligned_size);

    if (mlock(trace_buffer, aligned_size) != 0) {
        hprintf("[agent_init] Warning: mlock(trace_buffer) failed: %s\n", strerror(errno));
    }

    agent_cfg.trace_buffer_vaddr = (uint64_t)(uintptr_t)trace_buffer;
    agent_cfg.coverage_bitmap_size = (uint32_t)bitmap_size;

    hprintf("[agent_init] Allocated trace buffer: vaddr=%p size=%zu aligned=%zu\n",
            trace_buffer, bitmap_size, aligned_size);
    harness_log("Submitting agent config.");
    /* tell host about this agent */
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_cfg);

    /* compute page count and allocate resident pages */
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    size_t num_pages = (host_cfg.payload_buffer_size + page_size - 1) / page_size;
    if (num_pages == 0) num_pages = 1;
    harness_log("Allocating resident pages for payload buffer.");
    void *buf = malloc_resident_pages(num_pages);
    if (!buf) {
        habort("malloc_resident_pages failed");
        return NULL;
    }
    harness_log("Payload buffer allocated at %p.", buf);
    /* zero-initialize payload buffer first page for safety */
    memset(buf, 0, num_pages * page_size);

    /* register payload buffer with hypervisor/host (host will write payloads into it) */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)buf);
    harness_log("Payload buffer registered successfully.");

    if (verbose) {
        hprintf("[agent_init] allocated payload buffer at %p (%zu pages, %zu bytes)\n",
                buf, num_pages, num_pages * (size_t)page_size);
    }
    harness_log("Leaving my_kafl_agent_init().");
    return (kAFL_payload *)buf;
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

    harness_log("Entering main fuzzing loop.");
    while (1) {
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        if (payload->size >= 4) {
            uint32_t cmd = 0;
            memcpy(&cmd, payload->data, sizeof(cmd));
            void *arg = (payload->size > 4) ? (void *)&payload->data[4] : NULL;
            ioctl(fd, cmd, arg);
        }
        
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    
    close(fd);
    return 0;
}


