#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <omp.h>

static volatile uint64_t g_sink = 1;
static volatile uint64_t g_unused_value = 7;

__attribute__((noinline, aligned(4), used))
uint64_t unused_target_load(uint64_t *p)
{
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

__attribute__((noinline))
void hot_leaf_work(size_t n)
{
    uint64_t local = 0;
    for (size_t i = 0; i < n; i++) {
        local += (i ^ (local >> 3)) + g_sink;
    }
    g_sink += local;
}

__attribute__((noinline))
void hot_driver(size_t n)
{
    for (size_t outer = 0; outer < 9; outer++) {
        hot_leaf_work(n);
    }
}

__attribute__((noinline))
void cold_leaf_work(size_t n)
{
    uint64_t local = 0;
    for (size_t i = 0; i < n; i++) {
        local += (i ^ (local >> 5)) + g_sink;
    }
    g_sink += local;
}

__attribute__((noinline))
void cold_driver(size_t n)
{
    for (size_t outer = 0; outer < 1; outer++) {
        cold_leaf_work(n);
    }
}

int main(int argc, char **argv)
{
    size_t n = 20000000ULL;
    if (argc > 1)
        n = strtoull(argv[1], nullptr, 0);

    if (g_unused_value == 0)
        g_sink += unused_target_load((uint64_t *)&g_unused_value);

#pragma omp parallel
    {
#pragma omp single
        {
            hot_driver(n / 4);
            cold_driver(n / 4);
        }

#pragma omp for schedule(static)
        for (int t = 0; t < omp_get_num_threads(); t++) {
            hot_driver(n);
            if ((t & 7) == 0)
                cold_driver(n);
        }
    }

    std::cout << "sink=" << g_sink << std::endl;
    return 0;
}
