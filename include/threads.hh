#ifndef mt_THREADS_H
#define mt_THREADS_H

#include <vector>

/**
 * @file threads.hh
 * @brief 提供当前进程线程枚举辅助函数。
 */

/**
 * @brief 枚举 `/proc/self/task` 中的线程 ID。
 *
 * 返回值按升序排列，可选择忽略一个特定线程 ID，常用于跳过监控器自身
 * 的后台线程。
 *
 * @param ignored 需要忽略的线程 ID；传 0 表示不忽略。
 * @return 当前进程可见的线程 ID 列表。
 */
std::vector<int> get_threads(int ignored = 0);

#endif
