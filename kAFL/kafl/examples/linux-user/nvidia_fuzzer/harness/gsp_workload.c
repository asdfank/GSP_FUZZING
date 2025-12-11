#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <nvml.h>

/* ---------------------------
 * 打印控制：
 *  - 默认有输出（方便你手工跑 ./gsp_workload）
 *  - 编译时加 -DGSP_SILENT 就会把 PRINTF 干掉
 * --------------------------- */
#ifdef GSP_SILENT
#  define PRINTF(...) do { } while (0)
#else
#  define PRINTF(...)  printf(__VA_ARGS__)
#endif

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
#ifndef GSP_SILENT
    if (r == NVML_ERROR_NOT_SUPPORTED) {
        fprintf(stderr, "%s: not supported\n", func);
        return;
    }
    fprintf(stderr, "%s failed: %s\n", func, nvmlErrorString(r));
#endif
}

/* --- GSP 相关函数用 dlsym 动态解析，避免头文件过旧时编译不过 --- */

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
#ifndef GSP_SILENT
        fprintf(stderr, "dlopen libnvidia-ml failed: %s\n", dlerror());
#endif
        return;
    }

    p_nvmlDeviceGetGspFirmwareVersion =
        (PFN_nvmlDeviceGetGspFirmwareVersion)dlsym(
            handle, "nvmlDeviceGetGspFirmwareVersion");
    p_nvmlDeviceGetGspFirmwareMode =
        (PFN_nvmlDeviceGetGspFirmwareMode)dlsym(
            handle, "nvmlDeviceGetGspFirmwareMode");
}

/* --- 单次 probe 逻辑：对一个 GPU 打一堆 NVML ioctl --- */

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

    /* --- 电源限制 --- */
    unsigned int minLimit = 0, maxLimit = 0;
    r = nvmlDeviceGetPowerManagementLimitConstraints(dev, &minLimit, &maxLimit);
    log_nvml("nvmlDeviceGetPowerManagementLimitConstraints", r);

    unsigned int enforced = 0;
    r = nvmlDeviceGetEnforcedPowerLimit(dev, &enforced);
    log_nvml("nvmlDeviceGetEnforcedPowerLimit", r);

    /* --- FieldValues：用头文件里有的字段，多打一发 ioctl --- */
    nvmlFieldValue_t fields[4];
    memset(fields, 0, sizeof(fields));
    int idx = 0;

#ifdef NVML_FI_DEV_MEMORY_TEMP
    fields[idx++].fieldId = NVML_FI_DEV_MEMORY_TEMP;
#endif
#ifdef NVML_FI_DEV_TOTAL_ENERGY_CONSUMPTION
    fields[idx++].fieldId = NVML_FI_DEV_TOTAL_ENERGY_CONSUMPTION;
#endif
#ifdef NVML_FI_DEV_PCIE_REPLAY_COUNTER
    fields[idx++].fieldId = NVML_FI_DEV_PCIE_REPLAY_COUNTER;
#endif

    if (idx > 0) {
        r = nvmlDeviceGetFieldValues(dev, idx, fields);
        log_nvml("nvmlDeviceGetFieldValues", r);
    }

    /* --- 打印 summary：fuzz 时可通过 GSP_SILENT 关掉 --- */
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

/* ---------------------------
 * 对外暴露的两个入口
 * --------------------------- */

static int gsp_inited = 0;
static unsigned int gsp_device_count = 0;
#define GSP_MAX_DEVICES 16
static nvmlDevice_t gsp_devices[GSP_MAX_DEVICES];

int gsp_workload_init(void) {
    if (gsp_inited)
        return 0;

    nvmlReturn_t r = nvmlInit_v2();
    if (r != NVML_SUCCESS) {
#ifndef GSP_SILENT
        fprintf(stderr, "nvmlInit_v2 failed: %s\n", nvmlErrorString(r));
#endif
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
#ifndef GSP_SILENT
        fprintf(stderr, "nvmlDeviceGetCount failed or no devices: %s\n",
                nvmlErrorString(r));
#endif
        nvmlShutdown();
        return -1;
    }

    if (count > GSP_MAX_DEVICES)
        count = GSP_MAX_DEVICES;

    for (unsigned int i = 0; i < count; ++i) {
        nvmlDevice_t dev;
        r = nvmlDeviceGetHandleByIndex(i, &dev);
        if (r != NVML_SUCCESS) {
            log_nvml("nvmlDeviceGetHandleByIndex", r);
            continue;
        }
        gsp_devices[gsp_device_count++] = dev;
    }

    if (gsp_device_count == 0) {
#ifndef GSP_SILENT
        fprintf(stderr, "No valid NVML devices after handle collection.\n");
#endif
        nvmlShutdown();
        return -1;
    }

    gsp_inited = 1;
    return 0;
}

int gsp_workload_once(void) {
    if (!gsp_inited) {
        if (gsp_workload_init() != 0)
            return -1;
    }

    for (unsigned int i = 0; i < gsp_device_count; ++i) {
        probe_device_once(gsp_devices[i], i);
    }
    return 0;
}
