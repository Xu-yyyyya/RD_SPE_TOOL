#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "rd.h"

/*
 * Two-run workflow:
 * 1. Run this binary once without RD_ENABLE to emit a synthetic .hotpc file.
 * 2. Run it again with RD_MODE=targeted_rd and RD_TARGET_FILE pointing at that
 *    emitted manifest.
 *
 * Access sequence:
 *   load target   -> seed
 *   load target   -> sacrificial self-hit candidate
 *   load gap0
 *
 * This binary is intentionally a boundary probe around the current
 * ignore-first-hit semantics. Under the current kernel-module backend on this
 * machine, the observed second-stage result is:
 *   seed_samples > 0
 *   watchpoint_hits = 1
 *   histogram bucket = delta 0
 *
 * In other words, even though user code does not perform an intentional later
 * reuse after the sacrificial access, the current ARM/default-step path still
 * exposes one residual same-address hit. This makes the benchmark useful as a
 * regression probe for control-flow semantics, not as a strict "no-hit"
 * correctness oracle.
 */

static volatile uint64_t g_sink = 0;

static uintptr_t g_seed_pc = 0;

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
static uint64_t no_reuse_once(volatile uint64_t *target, volatile uint64_t *gap0)
{
    uintptr_t seed_pc = 0;
    uint64_t out = 0;

    asm volatile(
        "adr %x[seed], 1f\n\t"
        "1: ldr x9, [%[target]]\n\t"
        "ldr x10, [%[target]]\n\t"
        "ldr x11, [%[gap0]]\n\t"
        "eor x12, x10, x11\n\t"
        "mov %x[out], x12\n\t"
        : [seed] "=&r"(seed_pc), [out] "=&r"(out)
        : [target] "r"(target), [gap0] "r"(gap0)
        : "x9", "x10", "x11", "x12", "memory");

    if (!g_seed_pc)
        g_seed_pc = seed_pc;
    return out;
}

static void write_manifest(const char *manifest_path, uint64_t synthetic_samples)
{
    Dl_info info = {};
    FILE *fp = NULL;
    char binary_path[PATH_MAX];
    uintptr_t seed_offset = 0;

    if (!g_seed_pc) {
        fprintf(stderr, "seed PC not captured before manifest write\n");
        exit(1);
    }
    if (!dladdr((void *)g_seed_pc, &info) || !info.dli_fbase) {
        fprintf(stderr, "dladdr failed for seed pc 0x%" PRIxPTR "\n", g_seed_pc);
        exit(1);
    }
    if (!realpath(info.dli_fname ? info.dli_fname : normalized_self_path(), binary_path))
        die_errno("realpath(binary) failed");

    seed_offset = g_seed_pc - (uintptr_t)info.dli_fbase;

    fp = fopen(manifest_path, "w");
    if (!fp)
        die_errno("fopen(manifest) failed");

    fprintf(fp, "hotpc_manifest_version=1\n");
    fprintf(fp, "hotspot_top_k=1\n");
    fprintf(fp, "hotspot_identity=module_offset\n");
    fprintf(fp, "hotspot_scope=main_binary_only\n");
    fprintf(fp, "hotspot_main_binary=%s\n", binary_path);
    fprintf(fp, "hotspot_kind_hint=synthetic_no_reuse\n");
    fprintf(fp, "hotspot_fields=tid,rank,sample_count,module_id,pc_offset,path\n");
    fprintf(fp, "hotspot_count=1\n");
    fprintf(fp, "hotspot_unmapped_pc_samples=0\n");
    fprintf(fp, "micro_expected_current_impl_watchpoint_hits=1\n");
    fprintf(fp, "micro_expected_current_impl_bucket=delta0\n");
    fprintf(fp, "micro_seed_pc_offset=0x%" PRIxPTR "\n", seed_offset);
    fprintf(fp, "micro_pattern=seed_then_boundary_same_address_probe\n");
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
        "boundary-hit microbenchmark for current ignore-first-hit semantics.\n",
        argv0);
}

int main(int argc, char **argv)
{
    uint64_t iterations = 1;
    const char *manifest_path = NULL;
    const char *env_iters = getenv("RD_MICRO_ITERS");
    const char *env_manifest = getenv("RD_MICRO_HOTPC");
    long page_size = sysconf(_SC_PAGESIZE);
    volatile uint64_t *target = NULL;
    volatile uint64_t *gap0 = NULL;
    void *target_page = NULL;
    void *gap_page = NULL;

    if (page_size <= 0) {
        fprintf(stderr, "bad page size\n");
        return 1;
    }

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

    target_page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target_page == MAP_FAILED)
        die_errno("mmap(target_page) failed");
    gap_page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (gap_page == MAP_FAILED)
        die_errno("mmap(gap_page) failed");

    target = (volatile uint64_t *)target_page;
    gap0 = (volatile uint64_t *)gap_page;
    target[0] = 0x8877665544332211ULL;
    gap0[0] = 0x0102030405060708ULL;

    g_sink ^= no_reuse_once(target, gap0);
    write_manifest(manifest_path, iterations);

    rd_start("no_reuse");
    for (uint64_t i = 0; i < iterations; i++)
        g_sink ^= no_reuse_once(target, gap0);
    rd_stop();

    if (munmap((void *)target, (size_t)page_size) != 0)
        die_errno("munmap(target_page) failed");
    if (munmap((void *)gap0, (size_t)page_size) != 0)
        die_errno("munmap(gap_page) failed");

    printf("manifest=%s\n", manifest_path);
    printf("seed_pc=0x%" PRIxPTR " expected_current_impl_watchpoint_hits=1 iterations=%" PRIu64 "\n",
        g_seed_pc, iterations);
    printf("sink=%" PRIu64 "\n", (uint64_t)g_sink);
    return 0;
}
