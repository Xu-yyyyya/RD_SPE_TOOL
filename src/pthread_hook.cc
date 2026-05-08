#include <dlfcn.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
/**
 * @file pthread_hook.cc
 * @brief 实现 `pthread_create` 劫持与线程生命周期接入逻辑。
 */

#include "pthread_hook.hh"

namespace {

/** @brief 当前线程的“绕过劫持”嵌套深度。 */
thread_local unsigned g_bypass_depth = 0;

/**
 * @brief 传给 trampoline 的线程入口上下文。
 */
struct thread_start_ctx
{
    void *(*start_routine)(void *);
    void *arg;
};

/**
 * @brief 在线程退出时执行统一清理。
 */
static void cleanup_thread_ctx(void *arg)
{
    thread_start_ctx *ctx = (thread_start_ctx *)arg;
    rd_on_thread_stop();
    delete ctx;
}

/**
 * @brief 包装用户线程入口，在真正执行前后接入 RD 生命周期回调。
 */
static void *thread_start_trampoline(void *arg)
{
    thread_start_ctx *ctx = (thread_start_ctx *)arg;
    void *ret = nullptr;
    pthread_cleanup_push(cleanup_thread_ctx, arg);
    rd_on_thread_start();
    ret = ctx->start_routine(ctx->arg);
    pthread_cleanup_pop(1);
    return ret;
}

using pthread_create_fn = int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

/**
 * @brief 解析 libc 中真实的 `pthread_create` 符号。
 */
static pthread_create_fn resolve_real_pthread_create()
{
    void *sym = dlsym(RTLD_NEXT, "pthread_create");
    if (!sym) {
        std::cerr << "rd: failed to resolve pthread_create: " << dlerror() << std::endl;
        abort();
    }
    return reinterpret_cast<pthread_create_fn>(sym);
}

} // namespace

/** @brief 构造时进入“绕过劫持”状态。 */
PthreadCreateBypassGuard::PthreadCreateBypassGuard()
{
    rd_pthread_hook_push_bypass();
}

/** @brief 析构时退出一层“绕过劫持”状态。 */
PthreadCreateBypassGuard::~PthreadCreateBypassGuard()
{
    rd_pthread_hook_pop_bypass();
}

/** @brief 为当前线程增加一层 bypass 深度。 */
void rd_pthread_hook_push_bypass()
{
    g_bypass_depth += 1;
}

/** @brief 为当前线程减少一层 bypass 深度。 */
void rd_pthread_hook_pop_bypass()
{
    if (g_bypass_depth > 0)
        g_bypass_depth -= 1;
}

/** @brief 判断当前线程是否跳过 `pthread_create` 包装。 */
bool rd_pthread_hook_bypass_enabled()
{
    return g_bypass_depth != 0;
}

extern "C"
/**
 * @brief `pthread_create` 的 interposer 实现。
 *
 * 正常情况下会把用户入口替换为 trampoline，以便在线程开始和结束时
 * 分别触发 `rd_on_thread_start()` / `rd_on_thread_stop()`。
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg)
{
    static pthread_create_fn real_pthread_create = resolve_real_pthread_create();
    if (rd_pthread_hook_bypass_enabled())
        return real_pthread_create(thread, attr, start_routine, arg);

    thread_start_ctx *ctx = new thread_start_ctx;
    ctx->start_routine = start_routine;
    ctx->arg = arg;

    int rc = real_pthread_create(thread, attr, thread_start_trampoline, ctx);
    if (rc != 0)
        delete ctx;
    return rc;
}
