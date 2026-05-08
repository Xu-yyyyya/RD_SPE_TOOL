#include <time.h>
/**
 * @file clock.cc
 * @brief 实现项目内部统一使用的单调时钟读取函数。
 */

#include "clock.hh"
#include "rd_exception.hh"

/**
 * @brief 读取 `CLOCK_MONOTONIC_RAW` 并转换为纳秒时间戳。
 */
unsigned long nano_clock()
{
    timespec time, res;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) < 0)
        throw RdException("failed clock_gettime");

    if (clock_getres(CLOCK_MONOTONIC_RAW, &res) < 0 || res.tv_sec)
        throw RdException("clock_getres failure (CLOCK_MONOTONIC_RAW)");

    return time.tv_sec * res.tv_nsec*1000000000 + time.tv_nsec * res.tv_nsec;
}
