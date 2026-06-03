#ifndef TARGETED_RD_H
#define TARGETED_RD_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "uapi/rd_wpctl_ioctl.h"

/**
 * @file targeted_rd.hh
 * @brief 声明二阶段 `targeted_rd` 用户态控制器。
 */

/**
 * @brief 二阶段热点 RD 运行时的用户态控制面。
 *
 * 该类负责读取第一阶段热点清单、预解码热点访存指令、通过 ioctl
 * 配置内核模块，并在进程生命周期内管理线程注册、窗口启停和结果落盘。
 */
class TargetedRdProfiler
{
public:
    /**
     * @brief 描述一条热点访存指令的有效地址计算模板。
     *
     * 模块不在内核里做完整反汇编，而是直接复用用户态预解码得到的
     * 基址/索引/扩展/位移信息来恢复访存地址。
     */
    struct decode_template
    {
        /** @brief AArch64 索引寄存器扩展方式。 */
        enum extend_kind {
            EXT_NONE = RD_EXT_NONE,
            EXT_LSL = RD_EXT_LSL,
            EXT_UXTW = RD_EXT_UXTW,
            EXT_SXTW = RD_EXT_SXTW,
            EXT_UXTX = RD_EXT_UXTX,
            EXT_SXTX = RD_EXT_SXTX,
        };

        /** @brief 访存宽度，单位字节。 */
        int access_size;
        /** @brief 基址寄存器编号，对应 perf regs 编号。 */
        int base_reg;
        /** @brief 基址是否为 `sp`。 */
        bool base_is_sp;
        /** @brief 是否存在立即数偏移。 */
        bool has_imm;
        /** @brief 立即数偏移值。 */
        int64_t imm;
        /** @brief 是否存在索引寄存器。 */
        bool has_index;
        /** @brief 索引寄存器编号。 */
        int index_reg;
        /** @brief 索引寄存器是否按 32 位解释。 */
        bool index_is_32;
        /** @brief 索引寄存器是否是零寄存器。 */
        bool index_is_zero;
        /** @brief 索引扩展方式。 */
        extend_kind extend;
        /** @brief 扩展后的移位量。 */
        uint8_t shift;
    };

    /**
     * @brief 用户态维护的一条热点目标描述。
     */
    struct hot_target
    {
        /** @brief 相对主二进制文件的 PC 偏移。 */
        uint64_t pc_offset;
        /** @brief 当前运行实例中的绝对 PC。 */
        uint64_t abs_pc;
        /** @brief 第一阶段聚合后的样本数。 */
        uint64_t aggregated_samples;
        /** @brief 所属二进制路径。 */
        std::string path;
        /** @brief 反汇编得到的助记符。 */
        std::string mnemonic;
        /** @brief 反汇编得到的操作数文本。 */
        std::string operands;
        /** @brief 内核侧恢复 EA 所需的解码模板。 */
        decode_template decode;
    };

    /**
     * @brief 记录一条被过滤掉的热点目标。
     *
     * 当前版本会过滤掉超出 watchpoint 能力范围或地址模式暂不支持的
     * 热点，并在 `.rd2.info` 中保留原因，避免单个不支持热点导致整轮失败。
     */
    struct rejected_target
    {
        /** @brief 相对主二进制文件的 PC 偏移。 */
        uint64_t pc_offset;
        /** @brief 第一阶段聚合后的样本数。 */
        uint64_t aggregated_samples;
        /** @brief 过滤原因。 */
        std::string reason;
    };

    /**
     * @brief 构造 targeted RD 控制器。
     *
     * @param profile_name 输出文件名前缀。
     * @param is_pin 是否启用“每线程独占 CPU”绑核策略。
     */
    TargetedRdProfiler(const char *profile_name, bool is_pin);
    ~TargetedRdProfiler();

    /**
     * @brief 注册当前线程，使其进入 targeted RD 监控集合。
     */
    void register_current_thread();

    /**
     * @brief 注销当前线程并回收其模块侧资源。
     */
    void unregister_current_thread();

    /**
     * @brief 打开监控窗口。
     *
     * 若当前仍处于 preload 自动 fallback 窗口，则首次显式 `rd_start()`
     * 会先丢弃自动窗口数据，再切换到显式窗口。
     *
     * @param tag 当前实现未使用，但保留接口兼容性。
     */
    void kernel_start(const char *tag);

    /**
     * @brief 关闭监控窗口。
     *
     * 纯 preload fallback 场景下，一次孤立的 `rd_stop()` 不会提前关闭
     * 自动窗口；显式窗口仍按正常语义关闭。
     */
    void kernel_stop();

private:
    /**
     * @brief 用户态记录的线程绑定信息。
     *
     * `scratch` 区域用于给模块提供“空闲 watchpoint 地址”，使模块在 slot
     * idle 时可以把 watchpoint 改写到一段不会影响业务逻辑的私有匿名映射上。
     */
    struct thread_binding
    {
        int tid;
        int cpu;
        void *scratch;
        size_t scratch_bytes;
        uint64_t scratch_base;
        uint64_t scratch_stride;
        bool active;
    };

    /** @brief 控制器对象是否处于有效生命周期内。 */
    bool _running;
    /** @brief 当前任意来源的监控窗口是否已打开。 */
    bool _window_open;
    /** @brief 当前是否存在一个活动中的 preload 自动 fallback 窗口。 */
    bool _auto_fallback_active;
    /** @brief 本次运行是否见过显式 `rd_start()`。 */
    bool _explicit_window_seen;
    /** @brief 是否在首次显式开窗时丢弃过自动窗口数据。 */
    bool _auto_window_discarded_on_first_explicit;
    /** @brief 是否启用绑核语义。 */
    bool _is_pin;
    /** @brief 当前系统可用 CPU 数。 */
    int _num_cpus;
    /** @brief `/dev/rd_wpctl` 设备 fd。 */
    int _device_fd;
    /** @brief 每线程 watchpoint 水库容量。 */
    uint32_t _watchpoint_capacity;
    /** @brief 每线程最多注册的 execute breakpoint 目标 PC 数。 */
    uint32_t _bp_capacity;
    /** @brief execute breakpoint 的稀疏采样周期。 */
    uint64_t _bp_sample_period;
    /** @brief 调用上下文采集模式。 */
    uint32_t _callchain_mode;
    /** @brief DWARF 模式每个快照复制的用户栈字节数。 */
    uint32_t _dwarf_stack_bytes;
    /** @brief DWARF 模式每线程 raw event 容量。 */
    uint32_t _dwarf_event_capacity;
    /** @brief 输出文件名前缀。 */
    std::string _nameprefix;
    /** @brief 输入热点 manifest 路径。 */
    std::string _target_file;
    /** @brief 当前 RD 轴事件名。 */
    std::string _rd_event_name;
    /** @brief 当前运行主二进制路径。 */
    std::string _main_binary_path;
    /** @brief 写入 `.rd2.info` 的指令支持说明。 */
    std::string _instruction_support;
    /** @brief `.hotpc` 聚合后的唯一候选 PC 数。 */
    uint32_t _candidate_target_count;
    /** @brief 因 `_bp_capacity` 限制未下发到内核的候选 PC 数。 */
    uint32_t _capacity_truncated_target_count;
    /** @brief 保护线程绑定与窗口状态。 */
    std::mutex _state_mutex;
    /** @brief 输出 `.rd2.info` 的文件流。 */
    std::ofstream _info_file;

    /** @brief 本次运行装载的热点目标表。 */
    std::vector<hot_target> _targets;
    /** @brief 本次运行中被过滤掉的热点目标表。 */
    std::vector<rejected_target> _rejected_targets;
    /** @brief 记录每个 CPU 是否已被某个线程占用。 */
    std::vector<int> _cpu_owner;
    /** @brief 线程 ID 到绑定信息的映射。 */
    std::unordered_map<int, thread_binding> _threads;

    /** @brief 读取并解析 `.hotpc` 文件。 */
    void load_targets();

    /** @brief 注册构造时已存在的线程。 */
    void register_initial_threads();

    /** @brief 从模块拉取统计并落盘。 */
    void write_info();

    /**
     * @brief 为一个线程写出所有 target 的 log2 直方图。
     *
     * @param stats 模块返回的线程级统计。
     * @param thread_index 模块内部线程索引。
     */
    void write_thread_histograms(const rd_wpctl_thread_stats& stats, uint32_t thread_index);

    /**
     * @brief 为一个线程写出 use-reuse pair 的 log2 直方图。
     *
     * @param stats 模块返回的线程级统计。
     * @param thread_index 模块内部线程索引。
     */
    void write_thread_pair_histograms(const rd_wpctl_thread_stats& stats, uint32_t thread_index);

    /**
     * @brief 为一个线程写出 context_id 到 callchain IP 列表的映射。
     *
     * @param stats 模块返回的线程级统计。
     * @param thread_index 模块内部线程索引。
     */
    void write_thread_contexts(const rd_wpctl_thread_stats& stats, uint32_t thread_index);

    /**
     * @brief 为一个线程写出 DWARF raw event 文件。
     *
     * @param stats 模块返回的线程级统计。
     * @param thread_index 模块内部线程索引。
     */
    void write_thread_dwarf_events(const rd_wpctl_thread_stats& stats, uint32_t thread_index);

    /** @brief 分配一个当前未被占用的 CPU。 */
    int allocate_cpu_locked();

    /** @brief 释放一个此前分配的 CPU。 */
    void release_cpu_locked(int cpu);

    /**
     * @brief 在持锁状态下注册指定线程。
     *
     * @param tid 目标线程 ID。
     * @return 线程绑定状态对象。
     */
    thread_binding& register_thread_locked(int tid);

    /** @brief 在持锁状态下注销指定线程。 */
    void unregister_thread_locked(int tid);

    /** @brief 把当前配置和目标表下发给模块。 */
    void configure_session();

    /** @brief 在持锁状态下打开模块侧监控窗口。 */
    void start_window_locked();

    /** @brief 在持锁状态下关闭模块侧监控窗口。 */
    void stop_window_locked();

    /** @brief 在持锁状态下重置模块中的会话级采样状态。 */
    void reset_session_locked();
};

#endif
