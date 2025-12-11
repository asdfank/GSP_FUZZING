#ifndef GSP_WORKLOAD_H
#define GSP_WORKLOAD_H

/* 初始化 NVML 和 GPU 句柄
 * 返回 0 = OK, 非 0 = 失败
 */
int gsp_init(void);

/* 跑一轮负载
 * - 内部会读取环境变量 GSP_LOOP
 *   GSP_LOOP 未设置：每块 GPU 只跑 1 轮
 *   GSP_LOOP=N      ：每块 GPU 跑 N 轮 probe_device_once()
 */
void gsp_run_once(void);

/* 关闭 NVML */
void gsp_shutdown(void);

#endif /* GSP_WORKLOAD_H */
