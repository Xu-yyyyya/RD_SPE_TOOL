#ifndef mt_RD_EXCEPTION_H
#define mt_RD_EXCEPTION_H

#include <string>

/**
 * @file rd_exception.hh
 * @brief 定义项目内部统一使用的轻量异常类型。
 */

/**
 * @brief 表示运行时配置、系统调用或 perf 路径上的错误。
 *
 * 该异常仅携带一条字符串消息，便于在 constructor / destructor /
 * 劫持回调等路径中直接抛出并统一打印。
 */
struct RdException: public std::exception
{
    std::string m;

    /**
     * @brief 使用一条可读错误消息构造异常。
     *
     * @param msg 错误描述。
     */
    RdException(std::string msg)
    {
        m = msg;
    }

    /**
     * @brief 返回异常消息。
     *
     * @return 指向内部错误字符串的只读指针。
     */
    const char* what () const throw ()
    {
        return m.data();
    }
};

#endif
