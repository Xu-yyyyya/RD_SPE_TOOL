#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static volatile uint64_t g_value = 1;
static volatile uint64_t g_sink;

__attribute__((noinline, aligned(4)))
uint64_t rd_hot_load(uint64_t *p)
{
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

__attribute__((noinline, aligned(4), used))
uint64_t rd_unused_load(uint64_t *p)
{
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

__attribute__((noinline))
static void hot_path(uint64_t iters)
{
    uint64_t local = 0;
    for (uint64_t i = 0; i < iters; i++) {
        local += rd_hot_load((uint64_t *)&g_value);
        local += (i * 17) ^ (local >> 3);
    }
    g_sink += local;
}

__attribute__((noinline))
static void cold_path(uint64_t iters)
{
    uint64_t local = 0;
    for (uint64_t i = 0; i < iters; i++) {
        local += rd_hot_load((uint64_t *)&g_value);
        local += (i * 31) ^ (local >> 5);
    }
    g_sink += local;
}

int main(int argc, char **argv)
{
    uint64_t base = 10000000ULL;
    if (argc > 1)
        base = strtoull(argv[1], NULL, 0);

    hot_path(base * 9);
    cold_path(base);
    printf("sink=%llu\n", (unsigned long long)g_sink);
    return 0;
}
