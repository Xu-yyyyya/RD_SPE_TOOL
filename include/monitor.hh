#ifndef mt_MONITOR_H
#define mt_MONITOR_H

#include <vector>
#include <fstream>
#include <thread>
#include <string>
#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <cstdint>
#include <semaphore.h>

/**
 * @file monitor.hh
 * @brief 声明底层 perf/SPE 监控器的数据结构和接口。
 */

#define SAMPLE_WAKEUP 1024
#define MAX_TAG 64

#define SPE_PACKET_TS_HEADER 0x71
#define SPE_PACKET_PADDING_HEADER 0x00
#define SPE_PACKET_END_HEADER 0x01
#define SPE_PACKET_HEADER_PAYLOAD_SIZE_MASK 0x30
#define SPE_PACKET_SHORT_INDEX_MASK 0x07
#define SPE_PACKET_EVENTS_MASK 0xCF
#define SPE_PACKET_EVENTS_HEADER 0x42
#define SPE_PACKET_ADDRESS_MASK 0xF8
#define SPE_PACKET_ADDRESS_HEADER 0xB0
#define SPE_PACKET_COUNTER_MASK 0xF8
#define SPE_PACKET_COUNTER_HEADER 0x98

#define SPE_ADDR_PKT_HDR_INDEX_INS 0x0
#define SPE_ADDR_PKT_HDR_INDEX_BRANCH 0x1
#define SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT 0x2
#define SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS 0x3
#define SPE_ADDR_PKT_HDR_INDEX_PREV_BRANCH 0x4

#define SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT 0x0
#define SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT 0x1
#define SPE_CNT_PKT_HDR_INDEX_TRANS_LAT 0x2

#define SPE_EVENT_L1D_REFILL 3
#define SPE_EVENT_TLB_WALK 5
#define SPE_EVENT_LLC_MISS 9
#define SPE_EVENT_REMOTE_ACCESS 10

#define SPE_ADDR_PKT_BYTE7_SHIFT 56
#define SPE_ADDR_PKT_EL1 0x1
#define SPE_ADDR_PKT_EL2 0x2

#define SPE_SAMPLE_FLAG_PC_VALID (1ULL << 0)
#define SPE_SAMPLE_FLAG_LAT_TOTAL_VALID (1ULL << 1)
#define SPE_SAMPLE_FLAG_LAT_ISSUE_VALID (1ULL << 2)
#define SPE_SAMPLE_FLAG_LAT_XLAT_VALID (1ULL << 3)
#define SPE_SAMPLE_FLAG_EVENTS_VALID (1ULL << 4)
#define SPE_SAMPLE_FLAG_LAT_EXEC_VALID (1ULL << 5)

/**
 * @brief 描述一组 perf 事件的规格。
 *
 * 三个数组按相同索引对应，用于在同一线程上批量打开 counter 或 sampler。
 */
struct event_spec
{
    const int n;
    const char **event_name;
    const bool *event_leader;
};

/**
 * @brief 保存一次 counter 读取结果及其运行占比。
 */
struct counter_data
{
    uint64_t value;
    double active_time;
};

/**
 * @brief 保存一个采样窗口的聚合统计信息。
 */
struct kinfo
{
    std::string tag;
    size_t num_samples;
    size_t sample_throttles;
    double duration;
    counter_data *counters;
    uint64_t clock_start;
    uint64_t clock_stop;
    bool offloaded;
};

/**
 * @brief 保存用户标记的阶段事件。
 */
struct phase_info
{
    std::string tag;
    uint64_t time;
};

/**
 * @brief 保存用户标记的地址区间。
 */
struct addr_tag
{
    std::string tag;
    void *start;
    void *end;
};

/**
 * @brief 保存一次运行的可执行模块映射快照。
 */
struct module_map_entry
{
    uint32_t module_id;
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t file_offset;
    std::string path;
};

/**
 * @brief 标识一个热点指令的稳定身份。
 *
 * 键值采用“模块 ID + 文件内 PC 偏移”的形式，便于跨运行对齐。
 */
struct hotspot_key
{
    uint32_t module_id;
    uint64_t pc_offset;

    bool operator==(const hotspot_key& other) const
    {
        return module_id == other.module_id && pc_offset == other.pc_offset;
    }
};

/**
 * @brief `hotspot_key` 的哈希函数。
 */
struct hotspot_key_hash
{
    size_t operator()(const hotspot_key& key) const
    {
        size_t h1 = std::hash<uint32_t>{}(key.module_id);
        size_t h2 = std::hash<uint64_t>{}(key.pc_offset);
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }
};

/**
 * @brief 面向落盘与汇总的热点样本统计项。
 */
struct hotspot_summary
{
    int tid;
    uint32_t module_id;
    uint64_t pc_offset;
    uint64_t sample_count;
    uint64_t pareto_front;
    uint64_t candidate_score;
    std::string candidate_metric;
    double avg_mem_latency;
    uint64_t lat_total_sum;
    uint64_t lat_issue_sum;
    uint64_t lat_xlat_sum;
    uint64_t lat_exec_sum;
    uint64_t l1d_refill_count;
    uint64_t llc_miss_count;
    uint64_t tlb_walk_count;
    uint64_t remote_access_count;
    std::string path;
};

/**
 * @brief ARM SPE 第一阶段落盘的指令级样本记录。
 *
 * 该格式不再保存 data VA 和 timestamp，只保存当前 sampled instruction
 * 的 PC、latency counter、event packet 和有效性标记。
 */
struct spe_instruction_sample
{
    uint64_t pc;
    uint64_t lat_total;
    uint64_t lat_issue;
    uint64_t lat_xlat;
    uint64_t event_bits;
    uint64_t flags;
};

/**
 * @brief 第一阶段 cpu-clock 调用栈 cost 采样的固定宽度 raw record。
 *
 * 该布局与后处理脚本 `resolve_callpath_cost.py` 保持一致。第一阶段只负责
 * 保存 perf sample 中的用户态寄存器和栈快照，不在线展开调用栈。
 */
struct callpath_cost_raw_record
{
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint32_t tid;
    uint32_t cpu;
    uint64_t time;
    uint64_t ip;
    uint64_t regs_mask;
    uint64_t regs[33];
    uint32_t stack_size;
    uint32_t dyn_stack_size;
    uint8_t stack[8192];
};

/**
 * @brief 聚合一个热点 PC 的 SPE 指令级统计。
 */
struct hotspot_stats
{
    uint64_t sample_count;
    uint64_t lat_total_sum;
    uint64_t lat_total_count;
    uint64_t lat_issue_sum;
    uint64_t lat_issue_count;
    uint64_t lat_xlat_sum;
    uint64_t lat_xlat_count;
    uint64_t lat_exec_sum;
    uint64_t lat_exec_count;
    uint64_t l1d_refill_count;
    uint64_t llc_miss_count;
    uint64_t tlb_walk_count;
    uint64_t remote_access_count;
};

/**
 * @brief 向二进制样本文件顺序写入原始记录。
 */
class BinaryWriter
{
public:
    BinaryWriter() {}

    /**
     * @brief 打开一个二进制输出文件。
     *
     * @param path 输出文件路径。
     */
    BinaryWriter(const char *path);

    /**
     * @brief 向文件末尾写入一段原始字节。
     *
     * @param a 数据起始地址。
     * @param n 数据长度，单位字节。
     */
    void write(char *a, size_t n);

    /**
     * @brief 返回当前文件写入位置。
     *
     * @return 已写入的字节数。
     */
    size_t tell()
    {
        if (_ofs.is_open())
            return _ofs.tellp();
        else
            return 0;
    }

private:
    std::ofstream _ofs;
};

/**
 * @brief 表示一个 sampler fd 及其映射缓冲区。
 *
 * 对于 ARM SPE，`pending_*` 字段用于跨 packet 拼接一条 sampled
 * instruction 的 `pc + latency + event_bits`，遇到 time/end packet 后
 * flush 到 `.sample0`。
 */
struct sampler_slot
{
    int slot_id;
    int tid;
    int sampler_index;
    int fd;
    void *ringbuf;
    size_t ringbuf_bytes;
    void *auxbuf;
    size_t auxbuf_bytes;
    uint64_t pending_pc;
    uint64_t pending_lat_total;
    uint64_t pending_lat_issue;
    uint64_t pending_lat_xlat;
    uint64_t pending_event_bits;
    uint64_t pending_flags;
};

/**
 * @brief 按线程组织的 perf 资源集合。
 */
struct thread_state
{
    int tid;
    bool active;
    std::vector<int> counter_fds;
    std::vector<BinaryWriter> writers;
    std::vector<sampler_slot> samplers;
    int cost_fd;
    int cost_output_fd;
    void *cost_mmap_base;
    size_t cost_mmap_len;
    size_t cost_data_size;
    uint64_t cost_samples;
    uint64_t cost_lost_samples;
    uint64_t cost_invalid_samples;
    bool cost_epoll_registered;
};

/**
 * @brief 底层 perf/SPE 监控器。
 *
 * 该类统一管理：
 * - per-thread counter fd 和 sampler fd
 * - ring buffer / AUX buffer 映射
 * - 后台 sampler drain 线程
 * - `.info`、`.sample*`、`.hotpc` 输出
 * - 模块映射快照和热点统计
 */
class Monitor
{
public:
    /**
     * @brief 构造监控器并附着到当前进程已有线程。
     *
     * @param counter_spec 普通计数器规格。
     * @param sampler_spec 采样事件规格。
     * @param sample_period 采样周期。
     * @param ringbufsize ring buffer 大小，单位 MiB。
     * @param auxbufsize AUX buffer 大小，单位 MiB。
     * @param name 输出文件名前缀。
     * @param is_pin 是否对线程做跟随式绑核。
     */
    Monitor(const event_spec counter_spec, const event_spec sampler_spec, uint64_t sample_period,
        int ringbufsize, int auxbufsize, const char *name, bool is_pin);
    ~Monitor();

    /** @brief 对所有 fd 执行 `PERF_EVENT_IOC_RESET`。 */
    void reset();

    /**
     * @brief 打开一个新的采样窗口。
     *
     * @param tag 当前窗口标签。
     * @param offloaded 该窗口是否属于 offloaded 场景。
     */
    void start(const char *tag=0, bool offloaded=false);

    /** @brief 关闭当前采样窗口并收集统计。 */
    void stop();

    /**
     * @brief 读取当前累计计数。
     *
     * @param counters 输出数组。
     * @param include_samplers 是否同时读取 sampler 事件计数。
     */
    void read_counters(counter_data *counters, bool include_samplers);

    /** @brief 主动请求后台线程尽快 drain 一轮样本。 */
    void read_samples();

    /**
     * @brief 记录一个用户关心的地址区间。
     */
    void tag_addr(const char *tag, void *start, void *end);

    /**
     * @brief 记录一个逻辑阶段标记。
     */
    void mark_phase(const char *tag);

    /** @brief 注册当前线程的 perf 资源。 */
    void register_current_thread();

    /** @brief 注销当前线程并回收 perf 资源。 */
    void unregister_current_thread();

    /**
     * @brief 返回最近一个采样窗口的统计对象。
     */
    kinfo& last_kinfo()
    {
        return _kinfos.back();
    }

    /**
     * @brief 打开 nonstop 模式。
     *
     * nonstop 模式下窗口之间不主动 disable 事件，而是依赖持续采样与后台
     * drain。
     */
    void set_nonstop()
    {
        _nonstop_mode = true;
    }

private:

    const int _num_counters;
    const int _num_samplers;

    // We assume cpus are numbered [0,n)
    const int _num_cpus;
   
    const uint64_t _sample_period;

    const int _ringbufsize;
    const int _auxbufsize;

    const event_spec _counter_spec;
    const event_spec _sampler_spec;

    /** @brief 是否在窗口切换时保持事件持续启用。 */
    bool _nonstop_mode;

    /** @brief 后台 sampler 线程的线程 ID。 */
    int64_t sampler_tid;
    /** @brief 当前 perf 事件是否处于 enable 状态。 */
    bool _events_enabled;

    /** @brief 最近一次窗口结束时的累计计数快照。 */
    std::vector<uint64_t> _prev_counters;
    /** @brief 已经退役线程贡献的累计计数。 */
    std::vector<uint64_t> _retired_values;
    std::vector<uint64_t> _retired_time_enabled;
    std::vector<uint64_t> _retired_time_running;

    /** @brief 已知线程 ID，保持稳定顺序用于落盘。 */
    std::vector<int> _tids;
    /** @brief 线程 ID 到线程状态的映射。 */
    std::unordered_map<int, thread_state> _threads;
    /** @brief sampler slot ID 到 slot 指针的映射。 */
    std::unordered_map<int, sampler_slot*> _sampler_slots;
    /** @brief 下一个可分配的 sampler slot ID。 */
    int _next_slot_id;
    /** @brief 当前进程累计写出的样本字节数。 */
    uint64_t _written_sample_bytes;
    /** @brief 保护线程状态、fd 和热点表。 */
    std::mutex _state_mutex;

    /** @brief 输出文件名前缀。 */
    std::string _nameprefix;

    /** @brief 后台 sampler drain 线程。 */
    std::thread _sampler_thread;
    /** @brief 是否启用“跟随最近 CPU”绑核。 */
    bool _is_pin;
    /** @brief 用于唤醒/停止后台线程的 eventfd。 */
    int _event_fd;
    /** @brief 监听 sampler fd 与 eventfd 的 epoll fd。 */
    int _epoll_fd;
    /** @brief 是否在第一阶段启用 cpu-clock 调用栈 cost 采样。 */
    bool _callpath_cost_enabled;
    /** @brief cost sampler 的默认采样频率。 */
    uint32_t _cost_sample_freq;
    /** @brief 每个 cost sample 复制的用户栈字节数。 */
    uint32_t _cost_stack_bytes;
    /** @brief 每个线程 cost perf ring 的数据页数。 */
    uint32_t _cost_ring_pages;
    /** @brief drain 线程尽量绑定的 CPU。 */
    int _cost_consumer_cpu;
    /** @brief cost perf fd 到 tid 的路由表。 */
    std::unordered_map<int, int> _cost_fd_to_tid;

    /**
     * @brief 序列化窗口之间的样本 drain。
     *
     * 该信号量既用于保证不同采样窗口之间的样本不会混写，也用于避免主线程
     * 和后台线程并发 drain 同一批缓冲区。
     */
    sem_t _sampler_drain;
    /** @brief `.info` 输出文件流。 */
    std::ofstream _info_file;
    /** @brief 所有已完成窗口的统计列表。 */
    std::vector<kinfo> _kinfos;
    /** @brief 当前窗口起始时刻。 */
    timespec _start_time;
    /** @brief 单位秒转换为内部时钟 tick 的比例。 */
    uint64_t _clock_res;
    /** @brief 用户标记的地址区间。 */
    std::vector<addr_tag> _addr_tags;
    /** @brief 用户标记的阶段事件。 */
    std::vector<phase_info> _phases;
    /** @brief 本次运行采集到的可执行模块映射表。 */
    std::vector<module_map_entry> _module_maps;
    /** @brief 当前主二进制绝对路径。 */
    std::string _main_binary_path;
    /** @brief 每线程热点样本聚合统计。 */
    std::unordered_map<int, std::unordered_map<hotspot_key, hotspot_stats, hotspot_key_hash>> _thread_hotspots;
    /** @brief 每线程导出的热点数上限。 */
    size_t _hotspot_top_k;
    /** @brief 进入帕累托候选的最低样本数。 */
    size_t _hotspot_min_samples;
    /** @brief 进入帕累托候选的最低 latency 样本数。 */
    size_t _hotspot_min_latency_samples;
    /** @brief 无法映射到模块的 PC 样本数。 */
    uint64_t _hotspot_unmapped_samples;
    /** @brief 由 SPE timestamp packet 触发并成功写出的记录数。 */
    uint64_t _spe_time_packet_flush_count;
    /** @brief 由 SPE end packet 触发并成功写出的记录数。 */
    uint64_t _spe_end_packet_flush_count;
    /** @brief flush 时缺少 PC 而丢弃的 pending 记录数。 */
    uint64_t _spe_empty_flush_count;
    /** @brief SPE parser 遇到但无法识别的 packet 数。 */
    uint64_t _spe_unknown_packet_count;

    /** @brief 在持锁状态下注册指定线程。 */
    thread_state& register_thread_locked(int tid);
    /** @brief 在持锁状态下注销指定线程。 */
    void unregister_thread_locked(int tid);
    /** @brief 为一个线程打开所有 perf fd 和映射。 */
    void open_thread_locked(thread_state& state);
    /** @brief disable 一个线程上的所有事件。 */
    void disable_thread_locked(thread_state& state);
    /** @brief enable 一个线程上的所有事件。 */
    void enable_thread_locked(thread_state& state);
    /** @brief 将即将退役线程的计数并入全局累计值。 */
    void accumulate_retired_counts_locked(thread_state& state);
    /** @brief 关闭并回收一个线程上的所有 perf 资源。 */
    void close_thread_locked(thread_state& state);
    /** @brief 查找指定线程状态；未找到则返回空指针。 */
    thread_state *find_thread_locked(int tid);
    /** @brief 对所有活跃 fd 批量执行指定 ioctl。 */
    void fds_ioctl(int request);
    /** @brief 后台 sampler 线程主循环。 */
    void run_sampler_thread();
    /** @brief 按 slot ID 处理一条 sampler 通道。 */
    size_t process_samples(int slot_id);
    /** @brief 按 fd drain 一条 cpu-clock cost 通道。 */
    void process_cost_samples(int fd);
    /** @brief 在持锁状态下 drain 指定 sampler slot。 */
    size_t process_samples_locked(sampler_slot& slot);
    /** @brief 为一个线程创建第一阶段 cpu-clock cost sampler。 */
    void setup_cost_sampler_locked(thread_state& state);
    /** @brief 释放一个线程的第一阶段 cpu-clock cost sampler。 */
    void teardown_cost_sampler_locked(thread_state& state);
    /** @brief 将线程 cost fd 加入 epoll。 */
    void register_cost_fd_epoll_locked(thread_state& state);
    /** @brief 将线程 cost fd 从 epoll 删除。 */
    void unregister_cost_fd_epoll_locked(thread_state& state);
    /** @brief 在持锁状态下 drain 指定线程 cost perf ring。 */
    void consume_cost_samples_locked(thread_state& state);
    /** @brief 将所有统计写入 `.info`。 */
    void write_info(std::ofstream& info);
    /** @brief 判断 sampler 规格中是否包含 ARM SPE。 */
    bool has_arm_spe_samples() const;
    /** @brief 返回单条样本记录的字节数。 */
    size_t sample_record_bytes() const;
    /** @brief 返回样本记录字段名。 */
    const char *sample_record_fields() const;
    /** @brief 当前样本格式中是否携带 PC。 */
    bool sample_pc_present() const;
    /** @brief 抓取一次 `/proc/self/maps` 可执行映射快照。 */
    void snapshot_module_maps();
    /** @brief 记录主二进制路径。 */
    void snapshot_main_binary_path();
    /** @brief 向模块映射表中去重追加一个条目。 */
    void remember_module_map(uint64_t vm_start, uint64_t vm_end, uint64_t file_offset, const std::string& path);
    /** @brief 用一个 PC 在模块映射表中查找归属模块。 */
    const module_map_entry *find_module_map(uint64_t pc) const;
    /** @brief 判断某模块是否为主二进制模块。 */
    bool is_main_binary_module(const module_map_entry& entry) const;
    /** @brief 重置一个 sampler slot 中的 pending SPE 样本。 */
    void reset_pending_spe_sample(sampler_slot& slot) const;
    /** @brief 写出并聚合一个 pending SPE 指令样本。 */
    bool flush_pending_spe_sample_locked(sampler_slot& slot, BinaryWriter& writer, size_t& num_samples,
        bool from_end_packet);
    /** @brief 记录一条热点 PC 样本。 */
    void record_hotspot_sample(int tid, const spe_instruction_sample& sample);
    /** @brief 汇总一个线程的热点列表。 */
    std::vector<hotspot_summary> collect_hotspots_for_thread(int tid) const;
    /** @brief 写出 `.hotpc` manifest。 */
    void write_hotspot_manifest() const;
};

#endif
