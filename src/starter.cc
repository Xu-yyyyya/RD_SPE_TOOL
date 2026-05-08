#include <iostream>
#include <fstream>
#include <cstring>
#include <atomic>
#include <unistd.h>
/**
 * @file starter.cc
 * @brief 实现 preload 入口、全局单例管理和 C 接口桥接。
 */

#include "rd_exception.hh"
#include "threads.hh"
#include "rd.h"
#include "periodic_profiler.hh"
#include "pthread_hook.hh"
#include "targeted_rd.hh"

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

static std::atomic<PeriodicProfiler *> lib_perp{nullptr};
static std::atomic<TargetedRdProfiler *> lib_targeted_rd{nullptr};

/**
 * @brief 解析环境变量 `RD_PERIOD`。
 */
static int read_period()
{
    char *env = getenv("RD_PERIOD");
    if (env) {
        return atoi(env);
    }
    return 0;
}

/**
 * @brief 把用户给出的 buffer 大小向下规整为 2 的幂。
 *
 * 环境变量的单位按 MiB 解释；若未设置，则默认返回 1 MiB。
 */
int parse_bufsize(const char* env_bufsize)
{
    int bufsize = atoi(env_bufsize);
    if (bufsize) {
        //Round down to power of 2
        int n = 1;
        while (n <= bufsize) {
            n = n << 1;
        }
        //While loop goes one step too far, shift down one step
        return n >> 1;
    }

    // Return a buffer size of 1 (MiB) by default
    return 1;
}

__attribute__((constructor)) 
/**
 * @brief preload 库构造入口。
 *
 * 该函数负责读取环境变量、过滤目标进程、选择运行模式并创建对应的
 * profiler 单例。
 */
static void lib_init()
{
    if (!getenv("RD_ENABLE"))
        return;

    std::ifstream commf("/proc/self/comm");
    char comm[256];
    commf.get(comm, sizeof(comm));
    commf.close();

    const char *target = getenv("RD_TARGET");
    if (target && *target)
        if (strcmp(comm, target))
            return;

    // Prevent child processes (like OMPI's orted) from being individually
    // tracked and profiled.
    unsetenv("RD_ENABLE");

    uint64_t period = read_period();

    const char *name = getenv("RD_NAME");
    if (!name)
        name = "rd";
    const char *pidname = getenv("RD_PIDNAME");
    if (pidname && atoi(pidname)) {
        int len = strlen(name);
        char *namebuf = (char *)malloc(len + 20);
        memcpy(namebuf, name, len);
        sprintf(namebuf+len, "%d", getpid());
        name = namebuf;
    }

    perp_mode perp_mode = PERP_OFF;
    bool targeted_rd_mode = false;
    const char *mode = getenv("RD_MODE");

    if (mode && *mode) {
        if (!strcmp("perp", mode)) {
            perp_mode = PERP_ROOFLINE;
        } else if (!strcmp("noperp", mode)) {
            perp_mode = PERP_NONE;
        } else if (!strcmp("pf", mode)) {
            perp_mode = PERP_PREFETCH;
        } else if (!strcmp("targeted_rd", mode)) {
            targeted_rd_mode = true;
        } else {
            std::cerr << "rd: unknown mode " << mode << std::endl;
            throw RdException("unknown mode");
        }
    }
    const char *pin = getenv("RD_PIN_CPU");
    bool is_pin = false;
    if (pin && *pin) {
        is_pin = atoi(pin);
    }

    const char *env_ringbufsize = getenv("RD_BUFSIZE");
    int ringbufsize = 1;
    if (env_ringbufsize && *env_ringbufsize) {
        ringbufsize = parse_bufsize(env_ringbufsize);
    }

    const char *env_auxbufsize = getenv("RD_AUXBUFSIZE");
    int auxbufsize = 1;
    if (env_auxbufsize && *env_auxbufsize) {
        auxbufsize = parse_bufsize(env_auxbufsize);
    }

    std::cerr << "===== " <<
        "RD STARTER ENABLED: pid="
        << getpid() << " tid=" << gettid() << " comm=" << comm << " pin_cpu=" << is_pin
        << " period=" << period << " name=" << name << " perp_mode=" << perp_mode
        << " ringbufsize=" << ringbufsize << " [MiB/thread] auxbufsize=" 
        << auxbufsize << " [MiB/thread]"<< " =====" << std::endl;

    if (targeted_rd_mode) {
        lib_targeted_rd.store(new TargetedRdProfiler(name, true), std::memory_order_release);
    } else if (perp_mode) {
        lib_perp.store(new PeriodicProfiler(name, period, perp_mode, ringbufsize, auxbufsize, is_pin),
            std::memory_order_release);
    }
}

__attribute__((destructor)) 
/**
 * @brief preload 库析构入口。
 */
static void lib_deinit()
{
    PeriodicProfiler *profiler = lib_perp.exchange(nullptr, std::memory_order_acq_rel);
    if (profiler)
        delete profiler;
    TargetedRdProfiler *targeted = lib_targeted_rd.exchange(nullptr, std::memory_order_acq_rel);
    if (targeted)
        delete targeted;
}

extern "C"
/**
 * @brief 打开一个带标签的监控窗口。
 */
void rd_start(const char *tag)
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->kernel_start(tag);
    TargetedRdProfiler *targeted = lib_targeted_rd.load(std::memory_order_acquire);
    if (targeted)
        targeted->kernel_start(tag);
}

extern "C"
/**
 * @brief 关闭当前监控窗口。
 */
void rd_stop()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->kernel_stop();
    TargetedRdProfiler *targeted = lib_targeted_rd.load(std::memory_order_acquire);
    if (targeted)
        targeted->kernel_stop();
}

extern "C"
/**
 * @brief 直接向底层 `Monitor` 注册一段感兴趣地址区间。
 */
void rd_tag_addr(const char *tag, void *start, void *end)
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->_mon.tag_addr(tag, start, end);
}

extern "C"
/**
 * @brief 从 `/proc/self/maps` 中查找指定文件并注册其地址区间。
 *
 * 该接口适用于用户只知道映射文件名，不知道虚拟地址区间的场景。
 */
void rd_tag_from_maps(const char *tag, const char *file)
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler) {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            const char *p = line.data();
            void *start = (void *)strtoull(p, (char**)&p, 16);
            p++;
            void *end = (void *)strtoull(p, (char**)&p, 16);
            for (int i = 0; i < 5; i++) {
                while (!isspace(*p))
                    p++;
                while (isspace(*p))
                    p++;
            }
            if (!strcmp(file, p))
                profiler->_mon.tag_addr(tag, start, end);
        }
    }
}

extern "C"
/**
 * @brief 在线程启动时把当前线程接入所有已启用的 profiler。
 */
void rd_on_thread_start()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (!profiler)
        ;
    else {
        try {
            profiler->_mon.register_current_thread();
        } catch (const std::exception& e) {
            std::cerr << "warning: rd_on_thread_start failed: " << e.what() << std::endl;
        }
    }

    TargetedRdProfiler *targeted = lib_targeted_rd.load(std::memory_order_acquire);
    if (!targeted)
        return;
    try {
        targeted->register_current_thread();
    } catch (const std::exception& e) {
        std::cerr << "warning: targeted rd_on_thread_start failed: " << e.what() << std::endl;
    }
}

extern "C"
/**
 * @brief 在线程退出前把当前线程从所有 profiler 中注销。
 */
void rd_on_thread_stop()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (!profiler)
        ;
    else {
        try {
            profiler->_mon.unregister_current_thread();
        } catch (const std::exception& e) {
            std::cerr << "warning: rd_on_thread_stop failed: " << e.what() << std::endl;
        }
    }

    TargetedRdProfiler *targeted = lib_targeted_rd.load(std::memory_order_acquire);
    if (!targeted)
        return;
    try {
        targeted->unregister_current_thread();
    } catch (const std::exception& e) {
        std::cerr << "warning: targeted rd_on_thread_stop failed: " << e.what() << std::endl;
    }
}
