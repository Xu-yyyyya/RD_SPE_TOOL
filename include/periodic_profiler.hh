#ifndef PERIODIC_PROFILER_H
#define PERIODIC_PROFILER_H

#include <atomic>
#include <string>
#include "monitor.hh"

/**
 * @file periodic_profiler.hh
 * @brief 声明周期性 profiler 的前台控制接口。
 */

/**
 * @brief 控制周期性 profiler 运行模式。
 */
enum perp_mode {
    PERP_OFF = 0,
    PERP_ROOFLINE,
    PERP_NONE,
    PERP_PREFETCH,
};

/**
 * @brief 对 `Monitor` 做周期性启停包装的高层控制器。
 *
 * 该类负责创建后台线程，按固定时间片切分采样窗口，并对外暴露
 * `rd_start()` / `rd_stop()` 语义对应的阶段标签接口。
 */
class PeriodicProfiler
{
public:
    /**
     * @brief 构造一个周期性 profiler。
     *
     * @param profile_name 输出文件名前缀。
     * @param sample_period perf 采样周期。
     * @param mode 运行模式。
     * @param ringbufsize 每线程 ring buffer 大小，单位 MiB。
     * @param auxbufsize 每线程 AUX buffer 大小，单位 MiB。
     * @param is_pin 是否按线程最近运行 CPU 做绑核。
     */
    PeriodicProfiler(const char *profile_name, int sample_period, perp_mode mode,
        int ringbufsize, int auxbufsize, bool is_pin);
    ~PeriodicProfiler();

    /**
     * @brief 打开一个带标签的逻辑阶段。
     *
     * @param tag 用户提供的阶段标签。
     */
    void kernel_start(const char *tag);

    /**
     * @brief 关闭当前逻辑阶段。
     */
    void kernel_stop();

    /** @brief 底层监控器实例。 */
    Monitor _mon;
private:
    /** @brief 控制后台分段线程退出。 */
    std::atomic_bool _stop_thread;
    /** @brief 当前活动阶段标签。 */
    std::string _tag;
    /** @brief 周期性启停 `Monitor` 的后台线程。 */
    std::thread _thread;
    /** @brief 是否启用绑核语义。 */
    bool _is_pin;

    /**
     * @brief 后台线程主循环。
     *
     * 周期性停止并重启监控器，以生成连续的时间片统计。
     */
    void run_thread();
};

#endif
