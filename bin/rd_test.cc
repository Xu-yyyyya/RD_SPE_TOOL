// rd_test.cc
// Purpose: Generate significant memory pressure and diverse reuse-distance patterns
// Build:   g++ -O3 -march=native -std=c++17 rd_test.cc -o rd_test
// Usage:   ./rd_test [--size-mb=MB] [--seconds=T] [--seed=S] [--zipf-s=1.2] [--mode=streaming|hotset|strided|blocked|zipf]
// Notes:
//  - Default memory size is ~min(50% of RAM, 4096 MB). Use --size-mb to override.
//  - The program exercises multiple access patterns to yield a broad reuse-distance
//    distribution: streaming (no reuse), hot-set (short reuse), strided (varied),
//    blocked (moderate reuse), and Zipf-like random (heavy-tailed reuse).
//  - Writes are mixed with reads to force page allocation and real memory traffic.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

namespace rdtest {

struct Config {
  size_t sizeMb = 0;         // If 0, auto-detect ~min(50% RAM, 4 GiB)
  int durationSeconds = 5;   // Target total run time
  uint64_t seed = 0xC0FFEEULL;
  double zipfS = 1.2;        // Zipf exponent (>1 gives heavy tail)
  std::string mode = "streaming"; // 访问模式，默认仅运行单一模式
};

static inline size_t detectDefaultSizeMb() {
  long pages = sysconf(_SC_PHYS_PAGES);
  long pageSize = sysconf(_SC_PAGESIZE);
  if (pages <= 0 || pageSize <= 0) return 1024; // Fallback 1 GiB
  unsigned long long memBytes = static_cast<unsigned long long>(pages) *
                                static_cast<unsigned long long>(pageSize);
  unsigned long long halfBytes = memBytes / 2ULL;
  unsigned long long capBytes = 4ULL * 1024ULL * 1024ULL * 1024ULL; // 4 GiB
  unsigned long long target = std::min(halfBytes, capBytes);
  if (target < 256ULL * 1024ULL * 1024ULL) target = 256ULL * 1024ULL * 1024ULL; // >=256MB
  return static_cast<size_t>(target / (1024ULL * 1024ULL));
}

static inline bool startsWith(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && std::equal(p.begin(), p.end(), s.begin());
}

static Config parseArgs(int argc, char** argv) {
  Config cfg;
  for (int i = 1; i < argc; ++i) {
    std::string_view a(argv[i]);
    if (startsWith(a, "--size-mb=")) {
      cfg.sizeMb = static_cast<size_t>(std::stoull(std::string(a.substr(10))));
    } else if (startsWith(a, "--seconds=")) {
      cfg.durationSeconds = std::stoi(std::string(a.substr(10)));
    } else if (startsWith(a, "--seed=")) {
      cfg.seed = std::stoull(std::string(a.substr(8)));
    } else if (startsWith(a, "--zipf-s=")) {
      cfg.zipfS = std::stod(std::string(a.substr(9)));
    } else if (startsWith(a, "--mode=")) {
      cfg.mode = std::string(a.substr(7));
    } else if (a == "-h" || a == "--help") {
      std::cout << "用法(Usage): ./rd_test [--size-mb=MB] [--seconds=T] [--seed=S] [--zipf-s=1.2] [--mode=streaming|hotset|strided|blocked|zipf]\n"
                << "参数说明:\n"
                << "  --size-mb=MB     工作集大小(MB)，默认≈min(物理内存50%, 4096MB)\n"
                << "  --seconds=T      总运行时长(秒)\n"
                << "  --seed=S         随机种子\n"
                << "  --zipf-s=X       Zipf指数(>1 为重尾)\n"
                << "  --mode=NAME      访问模式: streaming(流式), hotset(热点集), strided(跨步), blocked(分块复用), zipf(重尾随机)\n";
      std::exit(0);
    }
  }
  if (cfg.sizeMb == 0) cfg.sizeMb = detectDefaultSizeMb();
  if (cfg.durationSeconds < 1) cfg.durationSeconds = 1;
  if (!(cfg.zipfS > 1.0)) cfg.zipfS = 1.2; // Ensure heavy-tail
  return cfg;
}

static inline void compilerFence() {
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

static inline void forceTouch(volatile uint64_t* p, uint64_t& sink, uint64_t value) {
  uint64_t tmp = *p;
  tmp ^= value;
  *p = tmp + 0x9E3779B97F4A7C15ULL; // mix to avoid store-to-load forwarding patterns
  sink += tmp;
}

// Create a coarse Zipf-like sampler over K ranks and map to [0, n)
struct ZipfSampler {
  std::discrete_distribution<int> rankDist;
  int ranks;
  std::mt19937_64& rng;
  explicit ZipfSampler(std::mt19937_64& r, int k, double s) : ranks(k), rng(r) {
    std::vector<double> weights;
    weights.reserve(ranks);
    for (int i = 1; i <= ranks; ++i) {
      weights.push_back(1.0 / std::pow(static_cast<double>(i), s));
    }
    rankDist = std::discrete_distribution<int>(weights.begin(), weights.end());
  }
  size_t sampleIndex(size_t n) {
    int r = rankDist(rng); // r in [0, ranks)
    // Map rank bucket to a subrange in [0, n)
    size_t bucketStart = static_cast<size_t>((static_cast<unsigned long long>(r) * n) / ranks);
    size_t bucketEnd = static_cast<size_t>((static_cast<unsigned long long>(r + 1) * n) / ranks);
    if (bucketEnd <= bucketStart) bucketEnd = std::min(n, bucketStart + 1);
    std::uniform_int_distribution<size_t> inBucket(bucketStart, bucketEnd - 1);
    return inBucket(rng);
  }
};

struct PhaseStats {
  const char* name;
  uint64_t operations = 0;
  double seconds = 0.0;
};

struct Runner {
  Config cfg;
  size_t numElements = 0;
  std::unique_ptr<uint64_t[]> buffer;
  volatile uint64_t* base = nullptr;
  uint64_t checksum = 0;
  std::mt19937_64 rng;

  explicit Runner(const Config& c) : cfg(c), rng(c.seed) {}

  void allocate() {
    // 中文: 分配并触摸内存，确保物理页提交，制造真实内存压力
    const size_t bytes = cfg.sizeMb * 1024ULL * 1024ULL;
    numElements = bytes / sizeof(uint64_t);
    if (numElements == 0) {
      std::cerr << "请求的内存大小过小 (Requested size too small)." << std::endl;
      std::exit(1);
    }
    buffer.reset(new (std::nothrow) uint64_t[numElements]);
    if (!buffer) {
      std::cerr << "内存分配失败 (Allocation failed) : " << cfg.sizeMb << " MB." << std::endl;
      std::exit(2);
    }
    base = buffer.get();
    // Commit pages: write once
    uint64_t local = 0;
    for (size_t i = 0; i < numElements; i += 4096 / sizeof(uint64_t)) {
      forceTouch(base + i, local, static_cast<uint64_t>(i));
    }
    checksum += local;
  }

  template <typename Fn>
  PhaseStats runPhase(const char* name, int seconds, Fn fn) {
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();
    auto deadline = t0 + std::chrono::seconds(seconds);
    uint64_t ops = 0;
    uint64_t local = 0;
    while (clock::now() < deadline) {
      ops += fn(local);
    }
    checksum += local;
    auto t1 = clock::now();
    std::chrono::duration<double> dt = t1 - t0;
    return PhaseStats{name, ops, dt.count()};
  }

  PhaseStats phaseStreaming(int seconds) {
    // 中文: 流式线性访问，基本无数据重用
    const size_t n = numElements;
    return runPhase("streaming", seconds, [&](uint64_t& sink) -> uint64_t {
      uint64_t value = rng();
      size_t ops = 0;
      // Full linear pass
      for (size_t i = 0; i < n; ++i) {
        forceTouch(base + i, sink, value);
        ++ops;
      }
      compilerFence();
      return ops;
    });
  }

  PhaseStats phaseHotset(int seconds) {
    // 中文: 小热点集合内高频随机访问，形成极短重用距离
    const size_t hotBytes = 256 * 1024; // 256 KiB
    const size_t hotN = std::min(numElements, hotBytes / sizeof(uint64_t));
    if (hotN < 1024) return PhaseStats{"hotset", 0, 0.0};
    std::uniform_int_distribution<size_t> pick(0, hotN - 1);
    return runPhase("hotset", seconds, [&](uint64_t& sink) -> uint64_t {
      uint64_t ops = 0;
      for (int rep = 0; rep < 64; ++rep) {
        for (size_t i = 0; i < 1 << 14; ++i) {
          size_t idx = pick(rng);
          forceTouch(base + idx, sink, idx ^ static_cast<size_t>(rep));
          ++ops;
        }
      }
      compilerFence();
      return ops;
    });
  }

  PhaseStats phaseStrided(int seconds) {
    // 中文: 不同步长跨步访问，覆盖缓存线/页/大块，形成多峰分布
    const size_t strides[] = {
        64 / sizeof(uint64_t),     // 64B
        4 * 1024 / sizeof(uint64_t), // 4KiB
        256 * 1024 / sizeof(uint64_t), // 256KiB
        1 * 1024 * 1024 / sizeof(uint64_t) // 1MiB
    };
    const size_t n = numElements;
    return runPhase("strided", seconds, [&](uint64_t& sink) -> uint64_t {
      uint64_t ops = 0;
      uint64_t value = rng();
      for (size_t s : strides) {
        if (s == 0) continue;
        for (size_t offset = 0; offset < s && offset < n; ++offset) {
          for (size_t i = offset; i < n; i += s) {
            forceTouch(base + i, sink, value + i);
            ++ops;
          }
        }
      }
      compilerFence();
      return ops;
    });
  }

  PhaseStats phaseBlocked(int seconds) {
    // 中文: 分块遍历，块内多次重复访问，形成中等重用距离
    const size_t blockBytes = 64 * 1024; // 64 KiB
    const size_t blockN = std::max<size_t>(1, blockBytes / sizeof(uint64_t));
    const size_t n = numElements;
    const size_t numBlocks = (n + blockN - 1) / blockN;
    return runPhase("blocked", seconds, [&](uint64_t& sink) -> uint64_t {
      uint64_t ops = 0;
      uint64_t value = rng();
      for (size_t b = 0; b < numBlocks; ++b) {
        size_t start = b * blockN;
        size_t end = std::min(n, start + blockN);
        // Repeat within a block to force reuse before moving to next block
        for (int r = 0; r < 4; ++r) {
          for (size_t i = start; i < end; ++i) {
            forceTouch(base + i, sink, value + r);
            ++ops;
          }
        }
      }
      compilerFence();
      return ops;
    });
  }

  PhaseStats phaseZipfRandom(int seconds) {
    // 中文: 基于Zipf的重尾随机访问，模拟真实负载的长尾复用
    const size_t n = numElements;
    const int ranks = 200000; // Coarse ranking, ~200k buckets
    ZipfSampler sampler(rng, ranks, cfg.zipfS);
    return runPhase("zipf", seconds, [&](uint64_t& sink) -> uint64_t {
      uint64_t ops = 0;
      for (int rep = 0; rep < 64; ++rep) {
        for (size_t i = 0; i < 1 << 15; ++i) {
          size_t idx = sampler.sampleIndex(n);
          forceTouch(base + idx, sink, static_cast<uint64_t>(idx * 1315423911u + rep));
          ++ops;
        }
      }
      compilerFence();
      return ops;
    });
  }

  void run() {
    allocate();
    // 中文: 打印配置与模式
    std::cout << "配置(Config): size_mb=" << cfg.sizeMb
              << ", seconds=" << cfg.durationSeconds
              << ", seed=" << cfg.seed
              << ", zipf_s=" << cfg.zipfS
              << ", mode=" << cfg.mode << "\n";

    // 中文: 仅运行一个所选模式，将全部时长分配给该模式
    PhaseStats s{"unknown", 0, 0.0};
    if (cfg.mode == "streaming") {
      s = phaseStreaming(cfg.durationSeconds);
    } else if (cfg.mode == "hotset") {
      s = phaseHotset(cfg.durationSeconds);
      if (s.operations == 0) {
        std::cerr << "警告: 热点集规模过小，未产生有效操作；建议增大 --size-mb。\n";
      }
    } else if (cfg.mode == "strided") {
      s = phaseStrided(cfg.durationSeconds);
    } else if (cfg.mode == "blocked") {
      s = phaseBlocked(cfg.durationSeconds);
    } else if (cfg.mode == "zipf") {
      s = phaseZipfRandom(cfg.durationSeconds);
    } else {
      std::cerr << "未知模式(Unknown mode): " << cfg.mode << ". 可选: streaming|hotset|strided|blocked|zipf\n";
      std::exit(3);
    }

    std::cout << "Phase " << s.name << ": ops=" << s.operations
              << ", seconds=" << s.seconds << "\n";
    std::cout << "Total: ops=" << s.operations << ", seconds=" << s.seconds
              << ", checksum=" << checksum << "\n";
  }
};

} // namespace rdtest

int main(int argc, char** argv) {
  using namespace rdtest;
  Config cfg = parseArgs(argc, argv);
  Runner r(cfg);
  r.run();
  return 0;
}


