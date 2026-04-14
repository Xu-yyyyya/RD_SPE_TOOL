#include <iostream>
#include <fstream>
#include <cstring>
#include <atomic>
#include <unistd.h>
#include "rd_exception.hh"
#include "threads.hh"
#include "rd.h"
#include "periodic_profiler.hh"
#include "pthread_hook.hh"

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

static std::atomic<PeriodicProfiler *> lib_perp{nullptr};

static int read_period()
{
    char *env = getenv("RD_PERIOD");
    if (env) {
        return atoi(env);
    }
    return 0;
}

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
    const char *mode = getenv("RD_MODE");

    if (mode && *mode) {
        if (!strcmp("perp", mode)) {
            perp_mode = PERP_ROOFLINE;
        } else if (!strcmp("noperp", mode)) {
            perp_mode = PERP_NONE;
        } else if (!strcmp("pf", mode)) {
            perp_mode = PERP_PREFETCH;
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

    if (perp_mode) {
        lib_perp.store(new PeriodicProfiler(name, period, perp_mode, ringbufsize, auxbufsize, is_pin),
            std::memory_order_release);
    }
}

__attribute__((destructor)) 
static void lib_deinit()
{
    PeriodicProfiler *profiler = lib_perp.exchange(nullptr, std::memory_order_acq_rel);
    if (profiler)
        delete profiler;
}

extern "C"
void rd_start(const char *tag)
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->kernel_start(tag);
}

extern "C"
void rd_stop()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->kernel_stop();
}

extern "C"
void rd_tag_addr(const char *tag, void *start, void *end)
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (profiler)
        profiler->_mon.tag_addr(tag, start, end);
}

extern "C"
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
void rd_on_thread_start()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (!profiler)
        return;

    try {
        profiler->_mon.register_current_thread();
    } catch (const std::exception& e) {
        std::cerr << "warning: rd_on_thread_start failed: " << e.what() << std::endl;
    }
}

extern "C"
void rd_on_thread_stop()
{
    PeriodicProfiler *profiler = lib_perp.load(std::memory_order_acquire);
    if (!profiler)
        return;

    try {
        profiler->_mon.unregister_current_thread();
    } catch (const std::exception& e) {
        std::cerr << "warning: rd_on_thread_stop failed: " << e.what() << std::endl;
    }
}
