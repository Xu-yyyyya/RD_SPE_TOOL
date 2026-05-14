#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rd.h"

/*
 * Two-run workflow:
 * 1. Run without RD_ENABLE to emit a synthetic .hotpc manifest.
 * 2. Run with RD_MODE=targeted_rd and RD_TARGET_FILE pointing to that manifest.
 *
 * This microbenchmark is intentionally compiled with frame pointers and
 * no sibling-call optimization. It creates two predictable call paths so the
 * kernel FP callchain collector can be validated end-to-end.
 */

#define EXPECTED_DELTA 8

static volatile uint64_t g_target_value = 0x1122334455667788ULL;
static volatile uint64_t g_gap_value = 0x0102030405060708ULL;
static volatile uint64_t g_sink = 0;

static uintptr_t g_seed_pc = 0;
static uintptr_t g_reuse_pc = 0;

static void die_errno(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static const char *default_manifest_path(void)
{
    static char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);

    if (len <= 0)
        die_errno("readlink(/proc/self/exe) failed");
    path[len] = '\0';
    if (strlen(path) + strlen(".hotpc") + 1 >= sizeof(path)) {
        fprintf(stderr, "manifest path too long\n");
        exit(1);
    }
    strcat(path, ".hotpc");
    return path;
}

static const char *normalized_self_path(void)
{
    static char path[PATH_MAX];

    if (path[0])
        return path;
    if (!realpath("/proc/self/exe", path))
        die_errno("realpath(/proc/self/exe) failed");
    return path;
}

static uint64_t parse_u64_or_die(const char *text, const char *what)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 0);

    if (!text || !*text || !end || *end != '\0') {
        fprintf(stderr, "bad %s: %s\n", what, text ? text : "(null)");
        exit(1);
    }
    return (uint64_t)value;
}

__attribute__((noinline, used))
static uint64_t seed_load_once(volatile uint64_t *target)
{
    uintptr_t seed_pc = 0;
    uint64_t out = 0;

    asm volatile(
        "adr %x[seed], 1f\n\t"
        "1: ldr x9, [%[target]]\n\t"
        "mov %x[out], x9\n\t"
        : [seed] "=&r"(seed_pc), [out] "=&r"(out)
        : [target] "r"(target)
        : "x9", "memory");

    if (!g_seed_pc)
        g_seed_pc = seed_pc;
    return out;
}

__attribute__((noinline, used))
static uint64_t seed_level2(volatile uint64_t *target)
{
    return seed_load_once(target) ^ 0x2ULL;
}

__attribute__((noinline, used))
static uint64_t seed_level1(volatile uint64_t *target)
{
    return seed_level2(target) ^ 0x1ULL;
}

__attribute__((noinline, used))
static uint64_t seed_driver(volatile uint64_t *target)
{
    return seed_level1(target) ^ 0xd00dULL;
}

__attribute__((noinline, used))
static uint64_t gap_load_once(volatile uint64_t *gap)
{
    uint64_t out = 0;

    asm volatile(
        "ldr x11, [%[gap]]\n\t"
        "mov %x[out], x11\n\t"
        : [out] "=&r"(out)
        : [gap] "r"(gap)
        : "x11", "memory");
    return out;
}

__attribute__((noinline, used))
static uint64_t reuse_load_once(volatile uint64_t *target)
{
    uintptr_t reuse_pc = 0;
    uint64_t out = 0;

    asm volatile(
        "adr %x[reuse], 1f\n\t"
        "1: ldr x12, [%[target]]\n\t"
        "mov %x[out], x12\n\t"
        : [reuse] "=&r"(reuse_pc), [out] "=&r"(out)
        : [target] "r"(target)
        : "x12", "memory");

    if (!g_reuse_pc)
        g_reuse_pc = reuse_pc;
    return out;
}

__attribute__((noinline, used))
static uint64_t reuse_level2(volatile uint64_t *target)
{
    return reuse_load_once(target) ^ 0x20ULL;
}

__attribute__((noinline, used))
static uint64_t reuse_level1(volatile uint64_t *target)
{
    return reuse_level2(target) ^ 0x10ULL;
}

__attribute__((noinline, used))
static uint64_t reuse_driver(volatile uint64_t *target)
{
    return reuse_level1(target) ^ 0xbeefULL;
}

__attribute__((noinline, used))
static uint64_t callchain_pair_once(volatile uint64_t *target, volatile uint64_t *gap)
{
    uint64_t out = 0;

    out ^= seed_driver(target);
    out ^= gap_load_once(gap);
    out ^= reuse_driver(target);
    return out;
}

static void write_manifest(const char *manifest_path, uint64_t synthetic_samples)
{
    Dl_info info = {};
    FILE *fp = NULL;
    char binary_path[PATH_MAX];
    uintptr_t seed_offset = 0;
    uintptr_t reuse_offset = 0;

    if (!g_seed_pc || !g_reuse_pc) {
        fprintf(stderr, "seed/reuse PC not captured before manifest write\n");
        exit(1);
    }
    if (!dladdr((void *)g_seed_pc, &info) || !info.dli_fbase) {
        fprintf(stderr, "dladdr failed for seed pc 0x%" PRIxPTR "\n", g_seed_pc);
        exit(1);
    }
    if (!realpath(info.dli_fname ? info.dli_fname : normalized_self_path(), binary_path))
        die_errno("realpath(binary) failed");

    seed_offset = g_seed_pc - (uintptr_t)info.dli_fbase;
    reuse_offset = g_reuse_pc - (uintptr_t)info.dli_fbase;

    fp = fopen(manifest_path, "w");
    if (!fp)
        die_errno("fopen(manifest) failed");

    fprintf(fp, "hotpc_manifest_version=1\n");
    fprintf(fp, "hotspot_top_k=1\n");
    fprintf(fp, "hotspot_identity=module_offset\n");
    fprintf(fp, "hotspot_scope=main_binary_only\n");
    fprintf(fp, "hotspot_main_binary=%s\n", binary_path);
    fprintf(fp, "hotspot_kind_hint=synthetic_callchain_pair\n");
    fprintf(fp, "hotspot_fields=tid,rank,sample_count,module_id,pc_offset,path\n");
    fprintf(fp, "hotspot_count=1\n");
    fprintf(fp, "hotspot_unmapped_pc_samples=0\n");
    fprintf(fp, "micro_expected_delta=%u\n", EXPECTED_DELTA);
    fprintf(fp, "micro_seed_pc_offset=0x%" PRIxPTR "\n", seed_offset);
    fprintf(fp, "micro_reuse_pc_offset=0x%" PRIxPTR "\n", reuse_offset);
    fprintf(fp, "micro_seed_function=seed_load_once\n");
    fprintf(fp, "micro_reuse_function=reuse_load_once\n");
    fprintf(fp, "micro_expected_seed_chain=seed_load_once,seed_level2,seed_level1,seed_driver,main\n");
    fprintf(fp, "micro_expected_reuse_chain=reuse_load_once,reuse_level2,reuse_level1,reuse_driver,main\n");
    fprintf(fp, "micro_pattern=seed_callchain_then_ignored_seed_hit_then_gap_then_reuse_callchain\n");
    fprintf(fp, "hotspot=1\t1\t%" PRIu64 "\t0\t0x%" PRIxPTR "\t%s\n",
        synthetic_samples, seed_offset, binary_path);

    if (fclose(fp) != 0)
        die_errno("fclose(manifest) failed");
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [iterations] [manifest_path]\n"
        "env overrides:\n"
        "  RD_MICRO_ITERS=<n>\n"
        "  RD_MICRO_HOTPC=<path>\n",
        argv0);
}

int main(int argc, char **argv)
{
    uint64_t iterations = 10000;
    const char *manifest_path = NULL;
    const char *env_iters = getenv("RD_MICRO_ITERS");
    const char *env_manifest = getenv("RD_MICRO_HOTPC");
    volatile uint64_t *target = &g_target_value;
    volatile uint64_t *gap = &g_gap_value;

    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        usage(argv[0]);
        return 0;
    }
    if (env_iters && *env_iters)
        iterations = parse_u64_or_die(env_iters, "RD_MICRO_ITERS");
    if (argc > 1)
        iterations = parse_u64_or_die(argv[1], "iterations");

    manifest_path = (env_manifest && *env_manifest) ? env_manifest : default_manifest_path();
    if (argc > 2)
        manifest_path = argv[2];

    g_sink ^= callchain_pair_once(target, gap);
    write_manifest(manifest_path, iterations);

    rd_start("callchain_pair");
    for (uint64_t i = 0; i < iterations; i++)
        g_sink ^= callchain_pair_once(target, gap);
    rd_stop();

    printf("manifest=%s\n", manifest_path);
    printf("seed_pc=0x%" PRIxPTR " reuse_pc=0x%" PRIxPTR
           " expected_delta=%u iterations=%" PRIu64 "\n",
        g_seed_pc, g_reuse_pc, EXPECTED_DELTA, iterations);
    printf("sink=%" PRIu64 "\n", (uint64_t)g_sink);
    return 0;
}
