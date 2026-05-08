#ifndef RD_PTHREAD_HOOK_H
#define RD_PTHREAD_HOOK_H

/**
 * @file pthread_hook.hh
 * @brief 声明 `pthread_create` 劫持层及其线程生命周期回调。
 */

/**
 * @brief 在一个作用域内临时关闭 `pthread_create` 劫持。
 *
 * 该守卫主要用于运行时自身创建后台线程，避免这些内部线程再次走
 * 监控注册逻辑而形成递归。
 */
class PthreadCreateBypassGuard
{
public:
    PthreadCreateBypassGuard();
    ~PthreadCreateBypassGuard();
};

/**
 * @brief 进入“绕过劫持”状态。
 */
void rd_pthread_hook_push_bypass();

/**
 * @brief 退出一层“绕过劫持”状态。
 */
void rd_pthread_hook_pop_bypass();

/**
 * @brief 查询当前线程是否处于“绕过劫持”状态。
 *
 * @return 若当前线程不应再包装新的 `pthread_create` 调用，则返回 true。
 */
bool rd_pthread_hook_bypass_enabled();

/**
 * @brief 在线程真正开始执行用户入口之前调用。
 */
extern "C" void rd_on_thread_start();

/**
 * @brief 在线程退出前调用，用于回收线程相关监控资源。
 */
extern "C" void rd_on_thread_stop();

#endif
