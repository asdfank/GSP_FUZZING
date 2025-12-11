#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <nvml.h>
#include "gsp_workload.h"

/* fuzz 时想静默就编译时加 -DGSP_SILENT */
#ifndef GSP_SILENT
# define PRINTF(...)  printf(__VA_ARGS__)
#else
# define PRINTF(...)  do {} while (0)
#endif

/* 兼容老头文件：有些宏在特别老的 nvml.h 里没有定义 */
#ifndef NVML_DEVICE_NAME_BUFFER_SIZE
#define NVML_DEVICE_NAME_BUFFER_SIZE 64
#endif

#ifndef NVML_DEVICE_UUID_BUFFER_SIZE
#define NVML_DEVICE_UUID_BUFFER_SIZE 80
#endif

#ifndef NVML_GSP_FIRMWARE_VERSION_BUF_SIZE
#define NVML_GSP_FIRMWARE_VERSION_BUF_SIZE 80
#endif

static void log_nvml(const char *func, nvmlReturn_t r) {
    if (r == NVML_SUCCESS)
        return;

    if (r == NVML_ERROR_NOT_SUPPORTED) {
        fprintf(stderr, "%s: not supported\n", func);
        return;
    }

    fprintf(stderr, "%s failed: %s\n", func, nvmlErrorString(r));
}

/* --- GSP 相关函数用 dlsym 动态解析，避免头文件版本不够新 --- */

typedef nvmlReturn_t (*PFN_nvmlDeviceGetGspFirmwareVersion)(
    nvmlDevice_t device, char *version, unsigned int length);

typedef nvmlReturn_t (*PFN_nvmlDeviceGetGspFirmwareMode)(
    nvmlDevice_t device, unsigned int *isEnabled, unsigned int *isDefault);

static PFN_nvmlDeviceGetGspFirmwareVersion p_nvmlDeviceGetGspFirmwareVersion = NULL;
static PFN_nvmlDeviceGetGspFirmwareMode    p_nvmlDeviceGetGspFirmwareMode    = NULL;

static void init_dynamic_gsp_symbols(void) {
    void *handle = dlopen("libnvidia-ml.so.1", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("libnvidia-ml.so", RTLD_LAZY);
    }
    if (!handle) {
        fprintf(stderr, "dlopen libnvidia-ml failed: %s\n", dlerror());
        return;
    }

    p_nvmlDeviceGetGspFirmwareVersion =
        (PFN_nvmlDeviceGetGspFirmwareVersion)dlsym(
            handle, "nvmlDeviceGetGspFirmwareVersion");
    p_nvmlDeviceGetGspFirmwareMode =
        (PFN_nvmlDeviceGetGspFirmwareMode)dlsym(
            handle, "nvmlDeviceGetGspFirmwareMode");
}

/* --------- 全局状态：在 harness 进程内复用 --------- */

#define GSP_MAX_DEVICES 16

static int            g_initialized  = 0;
static unsigned int   g_dev_count    = 0;
static nvmlDevice_t   g_devices[GSP_MAX_DEVICES];

/* --- 单个 GPU 的一次 probe（最核心的 ioctl 负载） --- */

static void probe_device_once(nvmlDevice_t dev, unsigned int index) {
    nvmlReturn_t r;

    /* --- 基本信息 --- */
    char name[NVML_DEVICE_NAME_BUFFER_SIZE] = {0};
    r = nvmlDeviceGetName(dev, name, sizeof(name));
    log_nvml("nvmlDeviceGetName", r);

    char uuid[NVML_DEVICE_UUID_BUFFER_SIZE] = {0};
    r = nvmlDeviceGetUUID(dev, uuid, sizeof(uuid));
    log_nvml("nvmlDeviceGetUUID", r);

    nvmlPciInfo_t pci;
    memset(&pci, 0, sizeof(pci));
    r = nvmlDeviceGetPciInfo(dev, &pci);
    log_nvml("nvmlDeviceGetPciInfo", r);

    /* --- GSP 相关（如果运行时有符号） --- */
    char gspVer[NVML_GSP_FIRMWARE_VERSION_BUF_SIZE] = {0};
    unsigned int gspEnabled = 0, gspDefault = 0;
    int hasGspApi = 0;

    if (p_nvmlDeviceGetGspFirmwareVersion) {
        r = p_nvmlDeviceGetGspFirmwareVersion(dev, gspVer, sizeof(gspVer));
        log_nvml("nvmlDeviceGetGspFirmwareVersion", r);
        hasGspApi = 1;
    }

    if (p_nvmlDeviceGetGspFirmwareMode) {
        r = p_nvmlDeviceGetGspFirmwareMode(dev, &gspEnabled, &gspDefault);
        log_nvml("nvmlDeviceGetGspFirmwareMode", r);
        hasGspApi = 1;
    }

    /* --- 内存 / 温度 / 功耗 / 利用率 --- */
    nvmlMemory_t mem;
    memset(&mem, 0, sizeof(mem));
    r = nvmlDeviceGetMemoryInfo(dev, &mem);
    log_nvml("nvmlDeviceGetMemoryInfo", r);

    unsigned int gpuTemp = 0;
    r = nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, &gpuTemp);
    log_nvml("nvmlDeviceGetTemperature(GPU)", r);

#ifdef NVML_TEMPERATURE_MEMORY
    unsigned int memTemp = 0;
    r = nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_MEMORY, &memTemp);
    log_nvml("nvmlDeviceGetTemperature(MEM)", r);
#else
    unsigned int memTemp = 0;
#endif

    unsigned int power = 0;
    r = nvmlDeviceGetPowerUsage(dev, &power);
    log_nvml("nvmlDeviceGetPowerUsage", r);

    nvmlUtilization_t util;
    memset(&util, 0, sizeof(util));
    r = nvmlDeviceGetUtilizationRates(dev, &util);
    log_nvml("nvmlDeviceGetUtilizationRates", r);

    /* --- 风扇 / PCIe / BAR1 --- */
    unsigned int fanSpeed = 0;
    r = nvmlDeviceGetFanSpeed(dev, &fanSpeed);
    log_nvml("nvmlDeviceGetFanSpeed", r);

    unsigned int maxGen = 0, maxWidth = 0, curGen = 0, curWidth = 0;
    r = nvmlDeviceGetMaxPcieLinkGeneration(dev, &maxGen);
    log_nvml("nvmlDeviceGetMaxPcieLinkGeneration", r);
    r = nvmlDeviceGetMaxPcieLinkWidth(dev, &maxWidth);
    log_nvml("nvmlDeviceGetMaxPcieLinkWidth", r);
    r = nvmlDeviceGetCurrPcieLinkGeneration(dev, &curGen);
    log_nvml("nvmlDeviceGetCurrPcieLinkGeneration", r);
    r = nvmlDeviceGetCurrPcieLinkWidth(dev, &curWidth);
    log_nvml("nvmlDeviceGetCurrPcieLinkWidth", r);

    nvmlBAR1Memory_t bar1;
    memset(&bar1, 0, sizeof(bar1));
    r = nvmlDeviceGetBAR1MemoryInfo(dev, &bar1);
    log_nvml("nvmlDeviceGetBAR1MemoryInfo", r);

    /* --- 时钟 / Pstate / 应用时钟 --- */
    unsigned int smClock = 0, memClock = 0, maxSmClock = 0;

    r = nvmlDeviceGetClockInfo(dev, NVML_CLOCK_SM, &smClock);
    log_nvml("nvmlDeviceGetClockInfo(SM)", r);

    r = nvmlDeviceGetClockInfo(dev, NVML_CLOCK_MEM, &memClock);
    log_nvml("nvmlDeviceGetClockInfo(MEM)", r);

    r = nvmlDeviceGetMaxClockInfo(dev, NVML_CLOCK_SM, &maxSmClock);
    log_nvml("nvmlDeviceGetMaxClockInfo(SM)", r);

    nvmlPstates_t pstate;
    r = nvmlDeviceGetPerformanceState(dev, &pstate);
    log_nvml("nvmlDeviceGetPerformanceState", r);

    unsigned int appSmClock = 0, appMemClock = 0;
    r = nvmlDeviceGetApplicationsClock(dev, NVML_CLOCK_SM, &appSmClock);
    log_nvml("nvmlDeviceGetApplicationsClock(SM)", r);

    r = nvmlDeviceGetApplicationsClock(dev, NVML_CLOCK_MEM, &appMemClock);
    log_nvml("nvmlDeviceGetApplicationsClock(MEM)", r);

    /* --- ECC / 电源限制 --- */
    nvmlEnableState_t eccCur = 0, eccPending = 0;
    r = nvmlDeviceGetEccMode(dev, &eccCur, &eccPending);
    log_nvml("nvmlDeviceGetEccMode", r);

    unsigned int minLimit = 0, maxLimit = 0;
    r = nvmlDeviceGetPowerManagementLimitConstraints(dev, &minLimit, &maxLimit);
    log_nvml("nvmlDeviceGetPowerManagementLimitConstraints", r);

    unsigned int enforced = 0;
    r = nvmlDeviceGetEnforcedPowerLimit(dev, &enforced);
    log_nvml("nvmlDeviceGetEnforcedPowerLimit", r);

    /* --- FieldValues：多打一发 ioctl --- */
    nvmlFieldValue_t fields[4];
    memset(fields, 0, sizeof(fields));
    int fidx = 0;

#ifdef NVML_FI_DEV_MEMORY_TEMP
    fields[fidx++].fieldId = NVML_FI_DEV_MEMORY_TEMP;
#endif
#ifdef NVML_FI_DEV_TOTAL_ENERGY_CONSUMPTION
    fields[fidx++].fieldId = NVML_FI_DEV_TOTAL_ENERGY_CONSUMPTION;
#endif
#ifdef NVML_FI_DEV_PCIE_REPLAY_COUNTER
    fields[fidx++].fieldId = NVML_FI_DEV_PCIE_REPLAY_COUNTER;
#endif

    if (fidx > 0) {
        r = nvmlDeviceGetFieldValues(dev, fidx, fields);
        log_nvml("nvmlDeviceGetFieldValues", r);
    }

    /* --- 打印 summary（fuzz 时可以 -DGSP_SILENT 关掉） --- */
    PRINTF(
        "GPU %u: %s, PCI=%s, UUID=%s\n"
        "  Temp: GPU=%uC, MEM=%uC, Fan=%u%%\n"
        "  Power: %.1fW (limit %u-%u, enforced %u)\n"
        "  Util: GPU=%u%%, MEM=%u%%\n"
        "  Clocks: SM=%uMHz, MEM=%uMHz, SM_max=%uMHz, Pstate=P%d, appClk=%u/%u MHz\n"
        "  PCIe: max Gen%d x%d, cur Gen%d x%d\n"
        "  BAR1: used=%llu MiB, total=%llu MiB\n"
        "  GSP: %s (enabled=%u, default=%u)\n",
        index,
        (name[0] ? name : "unknown"),
        pci.busId,
        uuid,
        gpuTemp, memTemp, fanSpeed,
        power / 1000.0,
        minLimit / 1000, maxLimit / 1000, enforced / 1000,
        util.gpu, util.memory,
        smClock, memClock, maxSmClock, (int)pstate, appSmClock, appMemClock,
        maxGen, maxWidth, curGen, curWidth,
        (unsigned long long)(bar1.bar1Used / (1024ULL * 1024ULL)),
        (unsigned long long)(bar1.bar1Total / (1024ULL * 1024ULL)),
        hasGspApi ? gspVer : "N/A",
        hasGspApi ? gspEnabled : 0,
        hasGspApi ? gspDefault : 0
    );
}

/* 每块 GPU 可以循环多次，循环次数由 GSP_LOOP 控制 */
static void probe_device(nvmlDevice_t dev, unsigned int index) {
    int iterations = 1;
    const char *env = getenv("GSP_LOOP");
    if (env) {
        int v = atoi(env);
        if (v > 0 && v < 10000)
            iterations = v;
    }

    for (int i = 0; i < iterations; ++i) {
        probe_device_once(dev, index);
    }
}

/* --------- 对外导出的三个库函数实现 --------- */

int gsp_init(void) {
    if (g_initialized)
        return 0;

    nvmlReturn_t r = nvmlInit_v2();
    if (r != NVML_SUCCESS) {
        fprintf(stderr, "nvmlInit_v2 failed: %s\n", nvmlErrorString(r));
        return -1;
    }

    init_dynamic_gsp_symbols();

    char driver[80] = {0};
    char nvmlVer[80] = {0};
    r = nvmlSystemGetDriverVersion(driver, sizeof(driver));
    log_nvml("nvmlSystemGetDriverVersion", r);

    r = nvmlSystemGetNVMLVersion(nvmlVer, sizeof(nvmlVer));
    log_nvml("nvmlSystemGetNVMLVersion", r);

    PRINTF("Driver=%s, NVML=%s\n", driver, nvmlVer);

    unsigned int count = 0;
    r = nvmlDeviceGetCount(&count);
    if (r != NVML_SUCCESS || count == 0) {
        fprintf(stderr, "nvmlDeviceGetCount failed or no devices: %s\n",
                nvmlErrorString(r));
        nvmlShutdown();
        return -1;
    }

    if (count > GSP_MAX_DEVICES)
        count = GSP_MAX_DEVICES;

    for (unsigned int i = 0; i < count; ++i) {
        r = nvmlDeviceGetHandleByIndex(i, &g_devices[i]);
        if (r != NVML_SUCCESS) {
            log_nvml("nvmlDeviceGetHandleByIndex", r);
            /* 简单起见：少一块就少一块 */
            continue;
        }
        g_dev_count++;
    }

    if (g_dev_count == 0) {
        fprintf(stderr, "No usable GPU devices found\n");
        nvmlShutdown();
        return -1;
    }

    g_initialized = 1;
    return 0;
}

void gsp_run_once(void) {
    if (!g_initialized) {
        if (gsp_init() != 0)
            return;
    }

    for (unsigned int i = 0; i < g_dev_count; ++i) {
        probe_device(g_devices[i], i);
    }
}

void gsp_shutdown(void) {
    if (!g_initialized)
        return;

    nvmlShutdown();
    g_initialized = 0;
    g_dev_count   = 0;
}

/* --------- 可选：保留 standalone 可执行，方便你手动 time 测试 --------- */

#ifdef GSP_WORKLOAD_STANDALONE
int main(void) {
    if (gsp_init() != 0)
        return 1;

    gsp_run_once();

    gsp_shutdown();
    return 0;
}
#endif
