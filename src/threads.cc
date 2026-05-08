#include <algorithm>
#include <dirent.h>
/**
 * @file threads.cc
 * @brief 实现进程内线程枚举辅助函数。
 */

#include "threads.hh"
#include "rd_exception.hh"

/**
 * @brief 从 `/proc/self/task` 枚举当前进程的线程 ID。
 */
std::vector<int> get_threads(int ignored)
{
    DIR *dir = opendir("/proc/self/task");
    if (!dir)
        throw RdException("Cannot open /proc/self/task");

    struct dirent *d;
    std::vector<int> tids;

    while ((d = readdir(dir))) {
        int tid = atoi(d->d_name);
        if (tid != 0 && tid != ignored)
            tids.push_back(tid);
    }

    closedir(dir);

    std::sort(tids.begin(), tids.end());
    return tids;
}
