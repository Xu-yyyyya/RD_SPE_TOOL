#ifndef RD_WPCTL_IOCTL_H
#define RD_WPCTL_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * @file rd_wpctl_ioctl.h
 * @brief `targeted_rd` 用户态控制器与内核模块之间的 UAPI 定义。
 */

#define RD_WPCTL_DEVICE "/dev/rd_wpctl"
#define RD_WPCTL_IOCTL_MAGIC 'R'
#define RD_WPCTL_LOG2_BUCKETS 64
#define RD_WPCTL_MAX_PAIR_HISTS 4096
#define RD_WPCTL_MAX_CALLCHAIN_DEPTH 8
#define RD_WPCTL_MAX_CONTEXTS 4096
#define RD_WPCTL_MAX_DWARF_STACK_BYTES 8192

/**
 * @brief targeted_rd 调用上下文采集模式。
 */
enum rd_wpctl_callchain_mode {
	RD_CALLCHAIN_OFF = 0,
	RD_CALLCHAIN_FP = 1,
	RD_CALLCHAIN_DWARF = 2,
};

/**
 * @brief AArch64 索引寄存器扩展方式。
 */
enum rd_wpctl_extend_kind {
	RD_EXT_NONE = 0,
	RD_EXT_LSL = 1,
    RD_EXT_UXTW = 2,
    RD_EXT_SXTW = 3,
    RD_EXT_UXTX = 4,
	RD_EXT_SXTX = 5,
};

/**
 * @brief 单条热点访存指令的有效地址计算模板。
 *
 * 用户态通过反汇编得到该模板，并将其传入内核模块，以便模块在
 * breakpoint 命中时根据 `pt_regs` 恢复访存地址。
 */
struct rd_wpctl_decode {
	__u32 access_size;
	__s32 base_reg;
    __u8 base_is_sp;
    __u8 has_imm;
    __u8 has_index;
    __u8 index_is_32;
    __u8 index_is_zero;
    __u8 extend;
    __u8 shift;
    __u8 reserved0;
    __s32 index_reg;
	__s64 imm;
};

/**
 * @brief 用户态下发给模块的热点目标描述。
 */
struct rd_wpctl_target {
	__u64 pc_offset;
	__u64 abs_pc;
    __u64 aggregated_samples;
	struct rd_wpctl_decode decode;
};

/**
 * @brief 会话级配置。
 */
struct rd_wpctl_session_cfg {
	__u32 wp_capacity;
	__u32 callchain_mode;
	__u64 bp_sample_period;
	__u32 dwarf_stack_bytes;
	__u32 dwarf_event_capacity;
};

/**
 * @brief 批量下发热点目标表的参数。
 */
struct rd_wpctl_target_batch {
	__u64 targets_ptr;
	__u32 count;
	__u32 reserved0;
};

/**
 * @brief 注册一个线程所需的参数。
 *
 * `scratch_base/scratch_stride` 对应用户态为该线程分配的匿名 scratch 区域，
 * 模块用它为 idle watchpoint slot 提供无业务意义的占位地址。
 */
struct rd_wpctl_thread_register {
	__s32 tid;
	__s32 cpu;
    __u64 scratch_base;
	__u64 scratch_stride;
};

/**
 * @brief 仅携带线程 ID 的 ioctl 参数。
 */
struct rd_wpctl_thread_arg {
	__s32 tid;
	__u32 reserved0;
};

/**
 * @brief 返回给用户态的全局布局信息。
 */
struct rd_wpctl_layout {
	__u32 target_count;
	__u32 thread_count;
    __u32 bucket_count;
	__u32 reserved0;
};

/**
 * @brief 线程级统计信息。
 */
struct rd_wpctl_thread_stats {
	__u32 index;
	__s32 tid;
    __s32 cpu;
    __u8 active;
    __u8 reserved0[7];
    __u64 candidate_samples;
    __u64 reservoir_seen;
    __u64 reservoir_accepted;
    __u64 reservoir_rejected;
    __u64 hits;
    __u64 evictions;
	__u64 dropped;
	__u32 pair_hist_used;
	__u32 reserved1;
	__u64 pair_hist_dropped;
	__u32 context_used;
	__u32 reserved2;
	__u64 context_dropped;
	__u64 callchain_failed;
	__u64 callchain_truncated;
	__u32 dwarf_event_used;
	__u32 reserved3;
	__u64 dwarf_event_dropped;
	__u64 dwarf_stack_copy_failed;
	__u64 dwarf_stack_bytes;
};

/**
 * @brief 拉取某个线程、某个目标的 `log2` 直方图。
 */
struct rd_wpctl_hist_req {
	__u32 thread_index;
	__u32 target_index;
	__u64 buckets[RD_WPCTL_LOG2_BUCKETS];
};

/**
 * @brief 拉取某个线程的一条 use-reuse pair `log2` 直方图。
 *
 * key 为 `(seed_pc_offset, reuse_pc)`；`reuse_pc` 第一版保持为命中时
 * 用户态 PC 的 raw virtual address，由后处理结合运行时映射解释。
 */
struct rd_wpctl_pair_hist_req {
	__u32 thread_index;
	__u32 entry_index;
	__u8 used;
	__u8 reserved0[7];
	__u32 seed_context_id;
	__u32 reuse_context_id;
	__u64 seed_pc_offset;
	__u64 reuse_pc;
	__u64 buckets[RD_WPCTL_LOG2_BUCKETS];
};

/**
 * @brief 拉取某个线程的一条调用上下文。
 */
struct rd_wpctl_context_req {
	__u32 thread_index;
	__u32 context_id;
	__u8 used;
	__u8 depth;
	__u8 reserved0[6];
	__u64 ips[RD_WPCTL_MAX_CALLCHAIN_DEPTH];
};

/**
 * @brief DWARF 离线 unwind 所需的一次用户态寄存器和栈快照。
 */
struct rd_wpctl_dwarf_snapshot {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	__u64 stack_base;
	__u32 stack_size;
	__u32 reserved0;
	__u8 stack[RD_WPCTL_MAX_DWARF_STACK_BYTES];
};

/**
 * @brief 拉取 DWARF 模式下的一条 seed/reuse raw event。
 */
struct rd_wpctl_dwarf_event_req {
	__u32 thread_index;
	__u32 event_index;
	__u8 used;
	__u8 bucket;
	__u8 reserved0[6];
	__s32 tid;
	__u32 target_index;
	__u64 seed_pc_offset;
	__u64 seed_pc;
	__u64 reuse_pc;
	__u64 seed_access;
	__u64 hit_access;
	__u64 delta;
	struct rd_wpctl_dwarf_snapshot seed;
	struct rd_wpctl_dwarf_snapshot reuse;
};

/**
 * @brief `RDKIOC_GET_DWARF_EVENT` 的 ioctl 编码使用小结构，实际 arg 仍指向
 * `rd_wpctl_dwarf_event_req`，避免超大结构超过 ioctl size 编码限制。
 */
struct rd_wpctl_dwarf_event_key {
	__u32 thread_index;
	__u32 event_index;
};

/** @brief 配置会话参数。 */
#define RDKIOC_CONFIG_SESSION  _IOW(RD_WPCTL_IOCTL_MAGIC, 1, struct rd_wpctl_session_cfg)
/** @brief 批量加载热点目标表。 */
#define RDKIOC_LOAD_TARGETS    _IOW(RD_WPCTL_IOCTL_MAGIC, 2, struct rd_wpctl_target_batch)
/** @brief 注册一个被监控线程。 */
#define RDKIOC_REGISTER_THREAD _IOW(RD_WPCTL_IOCTL_MAGIC, 3, struct rd_wpctl_thread_register)
/** @brief 注销一个被监控线程。 */
#define RDKIOC_UNREGISTER_THREAD _IOW(RD_WPCTL_IOCTL_MAGIC, 4, struct rd_wpctl_thread_arg)
/** @brief 打开监控窗口。 */
#define RDKIOC_START_WINDOW    _IO(RD_WPCTL_IOCTL_MAGIC, 5)
/** @brief 关闭监控窗口。 */
#define RDKIOC_STOP_WINDOW     _IO(RD_WPCTL_IOCTL_MAGIC, 6)
/** @brief 清空当前会话的采样统计、直方图和活跃 slot 状态。 */
#define RDKIOC_RESET_SESSION   _IO(RD_WPCTL_IOCTL_MAGIC, 10)
/** @brief 获取目标数、线程数和桶数。 */
#define RDKIOC_GET_LAYOUT      _IOR(RD_WPCTL_IOCTL_MAGIC, 7, struct rd_wpctl_layout)
/** @brief 获取一个线程的统计摘要。 */
#define RDKIOC_GET_THREAD_STATS _IOWR(RD_WPCTL_IOCTL_MAGIC, 8, struct rd_wpctl_thread_stats)
/** @brief 获取一个线程上某个 target 的 `log2` 直方图。 */
#define RDKIOC_GET_LOG2_HIST   _IOWR(RD_WPCTL_IOCTL_MAGIC, 9, struct rd_wpctl_hist_req)
/** @brief 获取一个线程上的一条 use-reuse pair `log2` 直方图。 */
#define RDKIOC_GET_PAIR_HIST_ENTRY _IOWR(RD_WPCTL_IOCTL_MAGIC, 11, struct rd_wpctl_pair_hist_req)
/** @brief 获取一个线程上的一条调用上下文。 */
#define RDKIOC_GET_CONTEXT_ENTRY _IOWR(RD_WPCTL_IOCTL_MAGIC, 12, struct rd_wpctl_context_req)
/** @brief 获取一个线程上的一条 DWARF raw event。 */
#define RDKIOC_GET_DWARF_EVENT _IOWR(RD_WPCTL_IOCTL_MAGIC, 13, struct rd_wpctl_dwarf_event_key)

#endif
