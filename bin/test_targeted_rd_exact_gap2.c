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
 * 1. Run this binary once without RD_ENABLE to emit a synthetic .hotpc file.
 * 2. Run it again with RD_MODE=targeted_rd and RD_TARGET_FILE pointing at that
 *    emitted manifest.
 *
 * The exact memory sequence inside exact_gap2_once() is:
 *   load target        -> seed PC written into the synthetic manifest
 *   load target        -> sacrificial self-hit, consumed by ignore-first-hit
 *   load gap0
 *   load target        -> measured reuse
 *
 * Under the current kernel-module semantics
 *   seed_reuse_policy=ignore_first_wp_hit_after_arm
 * the expected measured temporal delta is 2:
 *   1 ignored same-address access + 1 gap load.
 */

static volatile uint64_t g_target_value = 0x1122334455667788ULL;
static volatile uint64_t g_gap_values[1] = {
    0x0102030405060708ULL,
};
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

__attribute__((noinline, used))
static uint64_t exact_gap2_once(volatile uint64_t *target,
    volatile uint64_t *gap0)
{
    uintptr_t seed_pc = 0;
    uintptr_t reuse_pc = 0;
    uint64_t out = 0;

    asm volatile(
        "adr %x[seed], 1f\n\t"
        "adr %x[reuse], 2f\n\t"
        "1: ldr x9, [%[target]]\n\t"
        "ldr x10, [%[target]]\n\t"
        "ldr x11, [%[gap0]]\n\t"
        "2: ldr x12, [%[target]]\n\t"
        "eor x12, x12, x10\n\t"
        "eor x12, x12, x11\n\t"
        "mov %x[out], x12\n\t"
        : [seed] "=&r"(seed_pc), [reuse] "=&r"(reuse_pc), [out] "=&r"(out)
        : [target] "r"(target), [gap0] "r"(gap0)
        : "x9", "x10", "x11", "x12", "memory");

    if (!g_seed_pc) {
        g_seed_pc = seed_pc;
        g_reuse_pc = reuse_pc;
    }
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
    fprintf(fp, "hotspot_kind_hint=synthetic_exact_gap2\n");
    fprintf(fp, "hotspot_fields=tid,rank,sample_count,module_id,pc_offset,path\n");
    fprintf(fp, "hotspot_count=1\n");
    fprintf(fp, "hotspot_unmapped_pc_samples=0\n");
    fprintf(fp, "micro_expected_delta=2\n");
    fprintf(fp, "micro_seed_pc_offset=0x%" PRIxPTR "\n", seed_offset);
    fprintf(fp, "micro_reuse_pc_offset=0x%" PRIxPTR "\n", reuse_offset);
    fprintf(fp, "micro_reuse_kind=ignored_self_hit_then_gap_then_reuse\n");
    fprintf(fp, "hotspot=1\t1\t%" PRIu64 "\t0\t0x%" PRIxPTR "\t%s\n",
        synthetic_samples, seed_offset, binary_path);

    if (fclose(fp) != 0)
        die_errno("fclose(manifest) failed");
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

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [iterations] [manifest_path]\n"
        "env overrides:\n"
        "  RD_MICRO_ITERS=<n>\n"
        "  RD_MICRO_HOTPC=<path>\n"
        "\n"
        "This program emits a synthetic .hotpc manifest and executes a fixed\n"
        "exact-gap microbenchmark whose expected measured temporal delta is 2.\n",
        argv0);
}

int main(int argc, char **argv)
{
    uint64_t iterations = 10000;
    const char *manifest_path = NULL;
    const char *env_iters = getenv("RD_MICRO_ITERS");
    const char *env_manifest = getenv("RD_MICRO_HOTPC");
    volatile uint64_t *target = &g_target_value;
    volatile uint64_t *gap0 = &g_gap_values[0];

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

    /*
     * One warm-up call captures the exact runtime PC addresses and emits a
     * manifest that can be consumed by a later targeted_rd run.
     */
    g_sink ^= exact_gap2_once(target, gap0);
    write_manifest(manifest_path, iterations);

    rd_start("exact_gap2");
    for (uint64_t i = 0; i < iterations; i++)
        g_sink ^= exact_gap2_once(target, gap0);
    rd_stop();

    printf("manifest=%s\n", manifest_path);
    printf("seed_pc=0x%" PRIxPTR " reuse_pc=0x%" PRIxPTR " expected_delta=2 iterations=%" PRIu64 "\n",
        g_seed_pc, g_reuse_pc, iterations);
    printf("sink=%" PRIu64 "\n", (uint64_t)g_sink);
    return 0;
}
