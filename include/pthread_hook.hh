#ifndef RD_PTHREAD_HOOK_H
#define RD_PTHREAD_HOOK_H

class PthreadCreateBypassGuard
{
public:
    PthreadCreateBypassGuard();
    ~PthreadCreateBypassGuard();
};

void rd_pthread_hook_push_bypass();
void rd_pthread_hook_pop_bypass();
bool rd_pthread_hook_bypass_enabled();

extern "C" void rd_on_thread_start();
extern "C" void rd_on_thread_stop();

#endif
