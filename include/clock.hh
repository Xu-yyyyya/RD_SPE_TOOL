#ifndef CLOCK_H
#define CLOCK_H

/**
 * @file clock.hh
 * @brief 提供运行时统一使用的单调纳秒时钟接口。
 */

/**
 * @brief 读取单调递增的纳秒时钟。
 *
 * 该接口基于 `CLOCK_MONOTONIC_RAW`，用于为采样窗口、阶段标记和
 * 元数据生成稳定时间戳。
 *
 * @return 当前时间，单位为纳秒。
 */
unsigned long nano_clock();

#endif
