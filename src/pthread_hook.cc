#include <dlfcn.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "pthread_hook.hh"

namespace {

thread_local unsigned g_bypass_depth = 0;

struct thread_start_ctx
{
    void *(*start_routine)(void *);
    void *arg;
};

static void cleanup_thread_ctx(void *arg)
{
    thread_start_ctx *ctx = (thread_start_ctx *)arg;
    rd_on_thread_stop();
    delete ctx;
}

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

PthreadCreateBypassGuard::PthreadCreateBypassGuard()
{
    rd_pthread_hook_push_bypass();
}

PthreadCreateBypassGuard::~PthreadCreateBypassGuard()
{
    rd_pthread_hook_pop_bypass();
}

void rd_pthread_hook_push_bypass()
{
    g_bypass_depth += 1;
}

void rd_pthread_hook_pop_bypass()
{
    if (g_bypass_depth > 0)
        g_bypass_depth -= 1;
}

bool rd_pthread_hook_bypass_enabled()
{
    return g_bypass_depth != 0;
}

extern "C"
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
