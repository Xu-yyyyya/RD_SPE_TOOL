#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>

#include <asm/perf_regs.h>
#include <asm/ptrace.h>

#include "uapi/rd_wpctl_ioctl.h"

/**
 * @file rd_wpctl.c
 * @brief `targeted_rd` 二阶段内核模块实现。
 *
 * 该模块负责：
 * - 维护 per-open session；
 * - 为每个线程创建 `mem_access` 计数器；
 * - 为每个热点 PC 创建 execute breakpoint；
 * - 维护固定容量 watchpoint reservoir；
 * - 在 bp/wp 命中路径中读取 `mem_access` 并更新 temporal RD 直方图；
 * - 通过字符设备 ioctl 向用户态暴露控制面与结果读取接口。
 */

#define RD_IDLE_WP_LEN HW_BREAKPOINT_LEN_8
#define RD_ARM64_MEM_ACCESS_RAW_EVENT 0x13

/** @brief 调试日志预算，非零时记录前若干次 bp/wp 关键事件。 */
static unsigned int rd_debug_budget;
module_param_named(debug_budget, rd_debug_budget, uint, 0644);
MODULE_PARM_DESC(debug_budget,
		 "Emit up to N debug logs for accepted bp seeds and wp hits");

/** @brief 原子化调试日志令牌。 */
static atomic_t rd_debug_tokens = ATOMIC_INIT(0);

/** @brief 前向声明，会话对象定义在后文。 */
struct rd_session;
/** @brief 所有活跃线程上下文的全局 RCU 链表。 */
static LIST_HEAD(rd_live_threads);
/** @brief 保护 `rd_live_threads` 链表。 */
static DEFINE_SPINLOCK(rd_live_threads_lock);

/**
 * @brief 模块内部保存的一条热点目标。
 */
struct rd_target {
	u64 pc_offset;
	u64 abs_pc;
	u64 aggregated_samples;
	struct rd_wpctl_decode decode;
};

/**
 * @brief watchpoint slot 当前状态。
 */
enum rd_wp_state {
	RD_WP_IDLE = 0,
	RD_WP_ARMED = 1,
};

/**
 * @brief 单个线程在模块中的全部运行时状态。
 *
 * 一个线程上下文持有：
 * - 一个 `mem_access` 计数器；
 * - 全部热点 breakpoint；
 * - 固定容量 watchpoint slot；
 * - per-target `log2` 直方图；
 * - reservoir 相关统计。
 */
struct rd_thread_ctx {
	struct list_head node;
	struct list_head live_node;
	struct rd_session *session;
	struct task_struct *task;
	pid_t tid;
	int cpu;
	bool active;
	u64 scratch_base;
	u64 scratch_stride;

	spinlock_t lock;
	struct perf_event *mem_event;
	struct perf_event **bp_events;
	struct perf_event **wp_events;
	u64 *log2_hist;

	enum rd_wp_state *wp_states;
	u64 *wp_idle_addr;
	u64 *wp_seed_va;
	u64 *wp_seed_access;
	u64 *wp_seed_pc_offset;
	u32 *wp_access_size;
	u32 *wp_target_index;
	u32 *wp_generation;
	u8 *wp_skip_first_hit;
	u64 *wp_samples;

	u64 candidate_samples;
	u64 reservoir_seen;
	u64 reservoir_accepted;
	u64 reservoir_rejected;
	u64 hits;
	u64 evictions;
	u64 dropped;
	u64 rng;
};

/**
 * @brief 与一次设备 `open()` 对应的会话对象。
 *
 * 当前设计采用“每次 open 创建一个 session”的模型，不单独分配全局
 * session ID；用户态通过持有设备 fd 来持有这个 session。
 */
struct rd_session {
	struct mutex lock;
	struct list_head threads;
	pid_t owner_tgid;
	bool running;
	bool configured;
	bool targets_loaded;

	u32 wp_capacity;
	u64 bp_sample_period;
	u32 target_count;
	struct rd_target *targets;
};

/**
 * @brief 若调试预算未耗尽，则消费一个令牌。
 */
static bool rd_debug_take_token(void)
{
	int old;

	for (;;) {
		old = atomic_read(&rd_debug_tokens);
		if (old <= 0)
			return false;
		if (atomic_cmpxchg(&rd_debug_tokens, old, old - 1) == old)
			return true;
		cpu_relax();
	}
}

/**
 * @brief 生成一个伪随机数。
 *
 * 该随机流仅用于 reservoir sampling，不承担密码学语义。
 */
static u64 rd_next_random(u64 *state)
{
	u64 x = *state;

	if (!x)
		x = 0x9e3779b97f4a7c15ULL;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

/**
 * @brief 从 `pt_regs` 里按 perf regs 编号读取寄存器值。
 */
static u64 rd_read_perf_reg(const struct pt_regs *regs, int perf_reg, bool is_sp)
{
	if (is_sp || perf_reg == PERF_REG_ARM64_SP)
		return regs->sp;
	if (perf_reg >= PERF_REG_ARM64_X0 && perf_reg <= PERF_REG_ARM64_X29)
		return regs->regs[perf_reg];
	if (perf_reg == PERF_REG_ARM64_LR)
		return regs->regs[30];
	if (perf_reg == PERF_REG_ARM64_PC)
		return regs->pc;
	return 0;
}

/**
 * @brief 依据用户态下发的解码模板恢复有效地址。
 */
static u64 rd_compute_effective_address(const struct rd_wpctl_decode *dec,
					const struct pt_regs *regs)
{
	u64 base = rd_read_perf_reg(regs, dec->base_reg, dec->base_is_sp);
	u64 addr = base;

	if (dec->has_imm)
		addr += dec->imm;

	if (dec->has_index) {
		u64 raw = 0;
		u64 index = 0;

		if (!dec->index_is_zero)
			raw = rd_read_perf_reg(regs, dec->index_reg, false);

		switch (dec->extend) {
		case RD_EXT_NONE:
			index = dec->index_is_32 ? (u32)raw : raw;
			break;
		case RD_EXT_LSL:
			index = dec->index_is_32 ? (u32)raw : raw;
			index <<= dec->shift;
			break;
		case RD_EXT_UXTW:
			index = (u32)raw;
			index <<= dec->shift;
			break;
		case RD_EXT_SXTW:
			index = (u64)((s64)(s32)raw);
			index <<= dec->shift;
			break;
		case RD_EXT_UXTX:
			index = raw << dec->shift;
			break;
		case RD_EXT_SXTX:
			index = (u64)((s64)raw << dec->shift);
			break;
		default:
			index = 0;
			break;
		}
		addr += index;
	}

	return addr;
}

/**
 * @brief 初始化 execute breakpoint 属性。
 */
static void rd_init_bp_attr(struct perf_event_attr *attr, u64 pc, u64 period)
{
	hw_breakpoint_init(attr);
	attr->bp_type = HW_BREAKPOINT_X;
	attr->bp_addr = pc;
	attr->bp_len = HW_BREAKPOINT_LEN_4;
	attr->sample_period = period;
	attr->disabled = 1;
	attr->exclude_kernel = 1;
	attr->exclude_hv = 1;
}

/**
 * @brief 初始化 watchpoint 属性。
 */
static void rd_init_wp_attr(struct perf_event_attr *attr, u64 addr, u32 len)
{
	hw_breakpoint_init(attr);
	attr->bp_type = HW_BREAKPOINT_RW;
	attr->bp_addr = addr;
	attr->bp_len = len;
	attr->sample_period = 1;
	attr->disabled = 1;
	attr->exclude_kernel = 1;
	attr->exclude_hv = 1;
}

/**
 * @brief 初始化 `mem_access` raw perf event 属性。
 */
static void rd_init_mem_attr(struct perf_event_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->type = PERF_TYPE_RAW;
	attr->size = sizeof(*attr);
	attr->config = RD_ARM64_MEM_ACCESS_RAW_EVENT;
	attr->pinned = 1;
	attr->disabled = 1;
	attr->exclude_kernel = 1;
	attr->exclude_hv = 1;
}

/**
 * @brief 计算 temporal RD 的 `log2` 桶编号。
 *
 * 桶语义为：
 * - bucket 0 -> delta = 0
 * - bucket 1 -> delta = 1
 * - bucket 2 -> delta in [2, 3]
 * - 依此类推
 */
static u32 rd_log2_bucket(u64 delta)
{
	u32 bucket;

	if (!delta)
		return 0;
	bucket = fls64(delta);
	if (bucket >= RD_WPCTL_LOG2_BUCKETS)
		bucket = RD_WPCTL_LOG2_BUCKETS - 1;
	return bucket;
}

/**
 * @brief 读取当前线程的 `mem_access` 计数值。
 */
static int rd_read_mem_access(struct rd_thread_ctx *thread, u64 *value)
{
	u64 enabled = 0;
	u64 running = 0;

	if (!thread->mem_event)
		return -EINVAL;
	*value = perf_event_read_value(thread->mem_event, &enabled, &running);
	return 0;
}

/**
 * @brief enable 一个线程上的全部 perf 事件。
 */
static void rd_enable_thread_events(struct rd_thread_ctx *thread)
{
	u32 i;

	if (thread->mem_event)
		perf_event_enable(thread->mem_event);
	for (i = 0; i < thread->session->target_count; i++)
		if (thread->bp_events[i])
			perf_event_enable(thread->bp_events[i]);
	for (i = 0; i < thread->session->wp_capacity; i++)
		if (thread->wp_events[i])
			perf_event_enable(thread->wp_events[i]);
}

/**
 * @brief disable 一个线程上的全部 perf 事件。
 */
static void rd_disable_thread_events(struct rd_thread_ctx *thread)
{
	u32 i;

	for (i = 0; i < thread->session->wp_capacity; i++)
		if (thread->wp_events[i])
			perf_event_disable(thread->wp_events[i]);
	for (i = 0; i < thread->session->target_count; i++)
		if (thread->bp_events[i])
			perf_event_disable(thread->bp_events[i]);
	if (thread->mem_event)
		perf_event_disable(thread->mem_event);
}

/**
 * @brief 原地改写一个 watchpoint slot 的监控地址与宽度。
 */
static int rd_modify_slot(struct rd_thread_ctx *thread, u32 slot_index, u64 addr, u32 len)
{
	struct perf_event_attr attr;

	if (!thread->wp_events[slot_index])
		return -EINVAL;
	rd_init_wp_attr(&attr, addr, len);
	if (thread->session->running && thread->active)
		attr.disabled = 0;
	return modify_user_hw_breakpoint(thread->wp_events[slot_index], &attr);
}

/**
 * @brief 清空一个 slot 的元数据并把它标记为 idle。
 */
static void rd_clear_slot_metadata(struct rd_thread_ctx *thread, u32 slot_index)
{
	thread->wp_states[slot_index] = RD_WP_IDLE;
	thread->wp_seed_va[slot_index] = 0;
	thread->wp_seed_access[slot_index] = 0;
	thread->wp_seed_pc_offset[slot_index] = 0;
	thread->wp_access_size[slot_index] = 0;
	thread->wp_target_index[slot_index] = 0;
	thread->wp_skip_first_hit[slot_index] = 0;
	if (thread->wp_samples)
		thread->wp_samples[slot_index] = 1;
}

/**
 * @brief 重置一个线程的统计、直方图和 watchpoint slot 状态。
 *
 * 该函数只在 session 停窗后调用，因此这里把 slot 改回 idle scratch 地址，
 * 并清空所有采样期状态，而不重建 perf 资源。
 */
static int rd_reset_thread_locked(struct rd_thread_ctx *thread)
{
	unsigned long flags;
	size_t hist_entries;
	size_t hist_bytes;
	u32 i;
	int ret = 0;

	if (thread->active && thread->wp_events && thread->wp_idle_addr) {
		for (i = 0; i < thread->session->wp_capacity; i++) {
			int mod_ret = rd_modify_slot(thread, i, thread->wp_idle_addr[i],
						     RD_IDLE_WP_LEN);

			if (!ret && mod_ret)
				ret = mod_ret;
		}
	}

	hist_entries = (size_t)thread->session->target_count * RD_WPCTL_LOG2_BUCKETS;
	hist_bytes = hist_entries * sizeof(*thread->log2_hist);

	spin_lock_irqsave(&thread->lock, flags);
	thread->candidate_samples = 0;
	thread->reservoir_seen = 0;
	thread->reservoir_accepted = 0;
	thread->reservoir_rejected = 0;
	thread->hits = 0;
	thread->evictions = 0;
	thread->dropped = 0;
	thread->rng = 0x9e3779b97f4a7c15ULL ^ (u64)(u32)thread->tid;
	if (thread->log2_hist && hist_bytes)
		memset(thread->log2_hist, 0, hist_bytes);
	if (thread->wp_states) {
		for (i = 0; i < thread->session->wp_capacity; i++) {
			rd_clear_slot_metadata(thread, i);
			if (thread->wp_generation)
				thread->wp_generation[i] = 0;
		}
	}
	spin_unlock_irqrestore(&thread->lock, flags);

	return ret;
}

/**
 * @brief 选择候选样本要安装到的 watchpoint slot。
 *
 * 策略与 ReuseTracker 的 slot-local replacement 语义一致：idle slot
 * 立即接受候选；所有 slot 都 active 时，每个 slot 用自己的 sample
 * 计数执行 `1 / samples` 概率替换判定。
 */
static bool rd_pick_wp_slot(struct rd_thread_ctx *thread, u32 *slot_index,
			    bool *is_replacement)
{
	u32 i;
	u32 capacity = thread->session->wp_capacity;

	thread->reservoir_seen++;
	if (capacity == 0)
		return false;

	for (i = 0; i < capacity; i++) {
		if (thread->wp_states[i] == RD_WP_IDLE) {
			*slot_index = i;
			*is_replacement = false;
			thread->reservoir_accepted++;
			return true;
		}
	}

	for (i = 0; i < capacity; i++) {
		u64 samples = thread->wp_samples[i] ? thread->wp_samples[i] : 1;
		bool replace = (rd_next_random(&thread->rng) % samples) == 0;

		if (thread->wp_samples[i] != U64_MAX)
			thread->wp_samples[i]++;
		if (replace) {
			*slot_index = i;
			*is_replacement = true;
			thread->reservoir_accepted++;
			return true;
		}
	}

	thread->reservoir_rejected++;
	return false;
}

/**
 * @brief 把一个活跃线程加入全局 RCU 链表。
 *
 * 命中路径依赖该链表做 perf_event -> thread/slot 的反查。
 */
static void rd_add_live_thread(struct rd_thread_ctx *thread)
{
	spin_lock(&rd_live_threads_lock);
	list_add_rcu(&thread->live_node, &rd_live_threads);
	spin_unlock(&rd_live_threads_lock);
}

/**
 * @brief 把一个线程从全局 RCU 链表移除，并等待宽限期结束。
 */
static void rd_remove_live_thread(struct rd_thread_ctx *thread)
{
	spin_lock(&rd_live_threads_lock);
	if (!list_empty(&thread->live_node))
		list_del_rcu(&thread->live_node);
	spin_unlock(&rd_live_threads_lock);
	synchronize_rcu();
	INIT_LIST_HEAD(&thread->live_node);
}

/**
 * @brief 在活跃线程集合中反查某个 breakpoint event 对应的 target。
 */
static bool rd_lookup_bp_site_rcu(struct perf_event *event, struct rd_thread_ctx **thread_out,
				  u32 *target_index_out)
{
	struct rd_thread_ctx *thread;
	u32 i;

	rcu_read_lock();
	list_for_each_entry_rcu(thread, &rd_live_threads, live_node) {
		if (!thread->active || !thread->bp_events)
			continue;
		for (i = 0; i < thread->session->target_count; i++) {
			if (thread->bp_events[i] != event)
				continue;
			*thread_out = thread;
			*target_index_out = i;
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/**
 * @brief 在活跃线程集合中反查某个 watchpoint event 对应的 slot。
 */
static bool rd_lookup_wp_slot_rcu(struct perf_event *event, struct rd_thread_ctx **thread_out,
				  u32 *slot_index_out)
{
	struct rd_thread_ctx *thread;
	u32 i;

	rcu_read_lock();
	list_for_each_entry_rcu(thread, &rd_live_threads, live_node) {
		if (!thread->active || !thread->wp_events)
			continue;
		for (i = 0; i < thread->session->wp_capacity; i++) {
			if (thread->wp_events[i] != event)
				continue;
			*thread_out = thread;
			*slot_index_out = i;
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/**
 * @brief 处理一次稀疏 execute breakpoint 候选样本。
 *
 * 顺序为：
 * 1. 从寄存器恢复 `seed_va`
 * 2. 读取 `seed_access`
 * 3. 执行 reservoir 判定
 * 4. 若接受，则把目标 slot 改写为监控该 `seed_va`
 */
static void rd_handle_bp_hit(struct rd_thread_ctx *thread, u32 target_index, struct pt_regs *regs)
{
	struct rd_target *target;
	unsigned long flags;
	u64 seed_va;
	u64 seed_access = 0;
	bool accepted = false;
	bool is_replacement = false;
	u32 slot_index = 0;
	u32 new_generation = 0;
	u32 access_size = 0;
	int read_ret;
	int mod_ret;

	if (!thread || !regs || !thread->active || !thread->session->running)
		return;

	target = &thread->session->targets[target_index];
	seed_va = rd_compute_effective_address(&target->decode, regs);
	access_size = target->decode.access_size;
	read_ret = rd_read_mem_access(thread, &seed_access);
	if (read_ret)
		return;

	spin_lock_irqsave(&thread->lock, flags);
	thread->candidate_samples++;
	if (rd_pick_wp_slot(thread, &slot_index, &is_replacement)) {
		accepted = true;
		if (is_replacement && thread->wp_states[slot_index] == RD_WP_ARMED)
			thread->evictions++;
		new_generation = thread->wp_generation[slot_index] + 1;
		if (!new_generation)
			new_generation = 1;
		thread->wp_states[slot_index] = RD_WP_ARMED;
		thread->wp_seed_va[slot_index] = seed_va;
		thread->wp_seed_access[slot_index] = seed_access;
		thread->wp_seed_pc_offset[slot_index] = target->pc_offset;
		thread->wp_access_size[slot_index] = access_size;
		thread->wp_target_index[slot_index] = target_index;
		thread->wp_generation[slot_index] = new_generation;
		thread->wp_skip_first_hit[slot_index] = 1;
		if (thread->wp_samples)
			thread->wp_samples[slot_index] = 1;
	}
	spin_unlock_irqrestore(&thread->lock, flags);

	if (!accepted)
		return;

	if (rd_debug_take_token()) {
		pr_info("rd_wpctl: bp-overflow-seed tid=%d cpu=%d target=%u pc_off=0x%llx slot=%u seed_va=0x%llx seed_access=%llu access_size=%u\n",
			thread->tid, thread->cpu, target_index,
			thread->session->targets[target_index].pc_offset,
			slot_index, seed_va, seed_access, access_size);
	}

	mod_ret = rd_modify_slot(thread, slot_index, seed_va, access_size);
	if (mod_ret) {
		spin_lock_irqsave(&thread->lock, flags);
		thread->dropped++;
		rd_clear_slot_metadata(thread, slot_index);
		spin_unlock_irqrestore(&thread->lock, flags);
		rd_modify_slot(thread, slot_index, thread->wp_idle_addr[slot_index], RD_IDLE_WP_LEN);
		return;
	}
}

/**
 * @brief 处理一次 watchpoint 命中。
 *
 * 当前语义中，一个新 arm 的 slot 会忽略首次命中；之后的命中才按 reuse
 * 事件处理，并计算：
 *
 * `delta = hit_access - seed_access - 1`
 */
static void rd_handle_wp_hit(struct rd_thread_ctx *thread, u32 slot_index)
{
	unsigned long flags;
	u64 seed_access = 0;
	u64 hit_access = 0;
	u64 delta = 0;
	u32 target_index = 0;
	u32 bucket = 0;
	size_t hist_index = 0;
	int read_ret;

	if (!thread || !thread->active || !thread->session->running)
		return;

	spin_lock_irqsave(&thread->lock, flags);
	if (slot_index >= thread->session->wp_capacity ||
	    thread->wp_states[slot_index] != RD_WP_ARMED) {
		spin_unlock_irqrestore(&thread->lock, flags);
		return;
	}

	if (thread->wp_skip_first_hit[slot_index]) {
		u64 seed_va = thread->wp_seed_va[slot_index];
		u64 seed_access_local = thread->wp_seed_access[slot_index];
		u32 target_index_local = thread->wp_target_index[slot_index];

		thread->wp_skip_first_hit[slot_index] = 0;
		spin_unlock_irqrestore(&thread->lock, flags);
		if (rd_debug_take_token()) {
			pr_info("rd_wpctl: wp-ignore tid=%d cpu=%d slot=%u target=%u seed_va=0x%llx seed_access=%llu\n",
				thread->tid, thread->cpu, slot_index, target_index_local,
				seed_va, seed_access_local);
		}
		return;
	}

	target_index = thread->wp_target_index[slot_index];
	seed_access = thread->wp_seed_access[slot_index];
	spin_unlock_irqrestore(&thread->lock, flags);

	read_ret = rd_read_mem_access(thread, &hit_access);
	if (!read_ret) {
		delta = hit_access > seed_access ? (hit_access - seed_access - 1) : 0;
		bucket = rd_log2_bucket(delta);
		hist_index = (size_t)target_index * RD_WPCTL_LOG2_BUCKETS + bucket;
		if (rd_debug_take_token()) {
			pr_info("rd_wpctl: wp-hit tid=%d cpu=%d slot=%u target=%u seed_va=0x%llx seed_access=%llu hit_access=%llu delta=%llu bucket=%u\n",
				thread->tid, thread->cpu, slot_index, target_index,
				thread->wp_seed_va[slot_index], seed_access,
				hit_access, delta, bucket);
		}
		spin_lock_irqsave(&thread->lock, flags);
		if (thread->log2_hist &&
		    target_index < thread->session->target_count &&
		    hist_index < (size_t)thread->session->target_count * RD_WPCTL_LOG2_BUCKETS)
			thread->log2_hist[hist_index]++;
		thread->hits++;
		spin_unlock_irqrestore(&thread->lock, flags);
	} else {
		spin_lock_irqsave(&thread->lock, flags);
		thread->dropped++;
		spin_unlock_irqrestore(&thread->lock, flags);
	}

	spin_lock_irqsave(&thread->lock, flags);
	if (slot_index < thread->session->wp_capacity &&
	    thread->wp_states[slot_index] == RD_WP_ARMED)
		rd_clear_slot_metadata(thread, slot_index);
	spin_unlock_irqrestore(&thread->lock, flags);

	rd_modify_slot(thread, slot_index, thread->wp_idle_addr[slot_index], RD_IDLE_WP_LEN);
}

/**
 * @brief 判断一个 perf event 是否是本模块需要的 sampled execute breakpoint。
 */
static bool rd_is_execute_bp_event(struct perf_event *event)
{
	if (!event)
		return false;
	if (event->attr.type != PERF_TYPE_BREAKPOINT)
		return false;
	if (event->attr.bp_type != HW_BREAKPOINT_X)
		return false;
	return true;
}

/**
 * @brief `__perf_event_overflow` 的 kprobe pre_handler。
 *
 * 该入口只在 perf 已对 breakpoint event 消费过 `sample_period` 之后触发，
 * 因此这里看到的是稀疏 candidate 流，而不是每一次硬件断点命中。
 */
static int rd_perf_event_overflow_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct perf_event *event = (struct perf_event *)regs->regs[0];
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[3];
	struct rd_thread_ctx *thread = NULL;
	u32 target_index = 0;

	(void)kp;
	if (!event || !user_regs)
		return 0;
	if (!rd_is_execute_bp_event(event))
		return 0;
	if (!rd_lookup_bp_site_rcu(event, &thread, &target_index))
		return 0;
	if (!thread || current->pid != thread->tid)
		return 0;
	rd_handle_bp_hit(thread, target_index, user_regs);
	return 0;
}

/**
 * @brief `watchpoint_report` 的 kprobe pre_handler。
 *
 * 该入口用于捕获 watchpoint 命中。
 */
static int rd_watchpoint_report_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct perf_event *event = (struct perf_event *)regs->regs[0];
	struct rd_thread_ctx *thread = NULL;
	u32 slot_index = 0;

	(void)kp;
	if (!event)
		return 0;
	if (!rd_lookup_wp_slot_rcu(event, &thread, &slot_index))
		return 0;
	rd_handle_wp_hit(thread, slot_index);
	return 0;
}

/**
 * @brief 按线程 ID 查找一个活跃线程。
 */
static struct rd_thread_ctx *rd_find_active_thread_by_tid(struct rd_session *session, pid_t tid)
{
	struct rd_thread_ctx *thread;

	list_for_each_entry(thread, &session->threads, node) {
		if (thread->tid == tid && thread->active)
			return thread;
	}
	return NULL;
}

/**
 * @brief 按“用户可见顺序”查找第 `index` 个线程。
 *
 * 该顺序对应 `GET_LAYOUT` / `GET_THREAD_STATS` / `GET_LOG2_HIST` 的索引语义。
 */
static struct rd_thread_ctx *rd_find_thread_by_index(struct rd_session *session, u32 index)
{
	struct rd_thread_ctx *thread;
	u32 cur = 0;

	list_for_each_entry(thread, &session->threads, node) {
		if (cur == index)
			return thread;
		cur++;
	}
	return NULL;
}

/**
 * @brief 校验一条用户态下发的热点目标是否合法。
 */
static int rd_validate_target(const struct rd_wpctl_target *target)
{
	if (!target->abs_pc)
		return -EINVAL;
	if (target->decode.access_size != 1 &&
	    target->decode.access_size != 2 &&
	    target->decode.access_size != 4 &&
	    target->decode.access_size != 8)
		return -EINVAL;
	if (target->decode.base_reg < 0 || target->decode.base_reg > PERF_REG_ARM64_SP)
		return -EINVAL;
	if (target->decode.has_index &&
	    !target->decode.index_is_zero &&
	    (target->decode.index_reg < 0 || target->decode.index_reg > PERF_REG_ARM64_LR))
		return -EINVAL;
	if (target->decode.extend > RD_EXT_SXTX)
		return -EINVAL;
	return 0;
}

/**
 * @brief 检查一个线程是否满足“独占单个 CPU”的运行约束。
 */
static int rd_check_thread_affinity(struct task_struct *task, int cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!cpumask_test_cpu(cpu, &task->cpus_mask))
		return -EINVAL;
	if (cpumask_weight(&task->cpus_mask) != 1)
		return -EINVAL;
	return 0;
}

/**
 * @brief 为一个线程分配并初始化全部 perf 资源。
 *
 * 包括：
 * - `mem_access` 计数器
 * - 每个热点目标的 breakpoint
 * - 固定容量 watchpoint slot
 * - per-target `log2` 直方图
 * - slot 元数据数组
 */
static int rd_thread_setup_events(struct rd_thread_ctx *thread)
{
	struct perf_event_attr attr;
	size_t hist_entries;
	u32 i;
	int ret = 0;

	rd_init_mem_attr(&attr);
	thread->mem_event = perf_event_create_kernel_counter(&attr, thread->cpu, thread->task,
							     NULL, NULL);
	if (IS_ERR(thread->mem_event)) {
		ret = PTR_ERR(thread->mem_event);
		thread->mem_event = NULL;
		goto err;
	}

	thread->bp_events = kcalloc(thread->session->target_count, sizeof(*thread->bp_events), GFP_KERNEL);
	thread->wp_events = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_events), GFP_KERNEL);
	hist_entries = (size_t)thread->session->target_count * RD_WPCTL_LOG2_BUCKETS;
	thread->log2_hist = kcalloc(hist_entries, sizeof(*thread->log2_hist), GFP_KERNEL);
	thread->wp_states = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_states), GFP_KERNEL);
	thread->wp_idle_addr = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_idle_addr), GFP_KERNEL);
	thread->wp_seed_va = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_seed_va), GFP_KERNEL);
	thread->wp_seed_access = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_seed_access), GFP_KERNEL);
	thread->wp_seed_pc_offset = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_seed_pc_offset), GFP_KERNEL);
	thread->wp_access_size = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_access_size), GFP_KERNEL);
	thread->wp_target_index = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_target_index), GFP_KERNEL);
	thread->wp_generation = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_generation), GFP_KERNEL);
	thread->wp_skip_first_hit = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_skip_first_hit), GFP_KERNEL);
	thread->wp_samples = kcalloc(thread->session->wp_capacity, sizeof(*thread->wp_samples), GFP_KERNEL);
	if (!thread->bp_events || !thread->wp_events || !thread->log2_hist || !thread->wp_states ||
	    !thread->wp_idle_addr || !thread->wp_seed_va || !thread->wp_seed_access ||
	    !thread->wp_seed_pc_offset ||
	    !thread->wp_access_size || !thread->wp_target_index ||
	    !thread->wp_generation || !thread->wp_skip_first_hit || !thread->wp_samples) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < thread->session->target_count; i++) {
		rd_init_bp_attr(&attr, thread->session->targets[i].abs_pc,
				thread->session->bp_sample_period);
		thread->bp_events[i] = register_user_hw_breakpoint(&attr, NULL, NULL, thread->task);
		if (IS_ERR(thread->bp_events[i])) {
			ret = PTR_ERR(thread->bp_events[i]);
			thread->bp_events[i] = NULL;
			goto err;
		}
	}

	for (i = 0; i < thread->session->wp_capacity; i++) {
		thread->wp_idle_addr[i] = thread->scratch_base + (u64)i * thread->scratch_stride;
		rd_init_wp_attr(&attr, thread->wp_idle_addr[i], RD_IDLE_WP_LEN);
		thread->wp_events[i] = register_user_hw_breakpoint(&attr, NULL, NULL, thread->task);
		if (IS_ERR(thread->wp_events[i])) {
			ret = PTR_ERR(thread->wp_events[i]);
			thread->wp_events[i] = NULL;
			goto err;
		}
		thread->wp_states[i] = RD_WP_IDLE;
		thread->wp_samples[i] = 1;
	}

	return 0;

err:
	return ret;
}

/**
 * @brief 释放一个线程的“活跃态资源”。
 *
 * 该函数负责关闭 perf event、释放数组并释放持有的 `task_struct` 引用。
 * 线程对象本身不在这里释放。
 */
static void rd_thread_free_live(struct rd_thread_ctx *thread)
{
	u32 i;

	if (thread->mem_event) {
		perf_event_disable(thread->mem_event);
		perf_event_release_kernel(thread->mem_event);
		thread->mem_event = NULL;
	}
	if (thread->bp_events) {
		for (i = 0; i < thread->session->target_count; i++) {
			if (thread->bp_events[i]) {
				perf_event_disable(thread->bp_events[i]);
				unregister_hw_breakpoint(thread->bp_events[i]);
				thread->bp_events[i] = NULL;
			}
		}
	}
	if (thread->wp_events) {
		for (i = 0; i < thread->session->wp_capacity; i++) {
			if (thread->wp_events[i]) {
				perf_event_disable(thread->wp_events[i]);
				unregister_hw_breakpoint(thread->wp_events[i]);
				thread->wp_events[i] = NULL;
			}
		}
	}
	kfree(thread->bp_events);
	kfree(thread->wp_events);
	kfree(thread->wp_states);
	kfree(thread->wp_idle_addr);
	kfree(thread->wp_seed_va);
	kfree(thread->wp_seed_access);
	kfree(thread->wp_seed_pc_offset);
	kfree(thread->wp_access_size);
	kfree(thread->wp_target_index);
	kfree(thread->wp_generation);
	kfree(thread->wp_skip_first_hit);
	kfree(thread->wp_samples);
	thread->bp_events = NULL;
	thread->wp_events = NULL;
	thread->wp_states = NULL;
	thread->wp_idle_addr = NULL;
	thread->wp_seed_va = NULL;
	thread->wp_seed_access = NULL;
	thread->wp_seed_pc_offset = NULL;
	thread->wp_access_size = NULL;
	thread->wp_target_index = NULL;
	thread->wp_generation = NULL;
	thread->wp_skip_first_hit = NULL;
	thread->wp_samples = NULL;
	if (thread->task) {
		put_task_struct(thread->task);
		thread->task = NULL;
	}
}

/**
 * @brief 销毁一个线程对象。
 */
static void rd_thread_destroy(struct rd_thread_ctx *thread)
{
	rd_thread_free_live(thread);
	kfree(thread->log2_hist);
	kfree(thread);
}

/**
 * @brief 在持锁状态下注册一个线程。
 */
static int rd_register_thread_locked(struct rd_session *session,
				     const struct rd_wpctl_thread_register *arg)
{
	struct rd_thread_ctx *thread;
	struct task_struct *task;
	int ret;

	if (!session->configured || !session->targets_loaded)
		return -EINVAL;
	if (rd_find_active_thread_by_tid(session, arg->tid))
		return -EEXIST;
	if (!arg->scratch_base || !arg->scratch_stride)
		return -EINVAL;

	task = get_pid_task(find_vpid(arg->tid), PIDTYPE_PID);
	if (!task)
		return -ESRCH;
	if (task->tgid != session->owner_tgid) {
		put_task_struct(task);
		return -EPERM;
	}
	ret = rd_check_thread_affinity(task, arg->cpu);
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	thread = kzalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread) {
		put_task_struct(task);
		return -ENOMEM;
	}

	thread->session = session;
	thread->task = task;
	thread->tid = arg->tid;
	thread->cpu = arg->cpu;
	thread->scratch_base = arg->scratch_base;
	thread->scratch_stride = arg->scratch_stride;
	thread->active = true;
	thread->rng = 0x9e3779b97f4a7c15ULL ^ (u64)(u32)arg->tid;
	spin_lock_init(&thread->lock);
	INIT_LIST_HEAD(&thread->live_node);

	ret = rd_thread_setup_events(thread);
	if (ret) {
		rd_thread_destroy(thread);
		return ret;
	}

	if (session->running)
		rd_enable_thread_events(thread);

	list_add_tail(&thread->node, &session->threads);
	rd_add_live_thread(thread);
	return 0;
}

/**
 * @brief 在持锁状态下注销一个线程。
 *
 * 所有仍处于 armed 状态的 slot 会被记为 `dropped`。
 */
static int rd_unregister_thread_locked(struct rd_session *session, pid_t tid)
{
	struct rd_thread_ctx *thread = rd_find_active_thread_by_tid(session, tid);
	u32 i;

	if (!thread)
		return -ENOENT;
	if (!thread->active)
		return 0;

	for (i = 0; i < session->wp_capacity; i++) {
		if (thread->wp_states && thread->wp_states[i] == RD_WP_ARMED)
			thread->dropped++;
	}

	thread->active = false;
	rd_remove_live_thread(thread);
	rd_thread_free_live(thread);
	return 0;
}

/**
 * @brief 处理 `CONFIG_SESSION`，设置会话级基本参数。
 */
static int rd_session_config_locked(struct rd_session *session,
				    const struct rd_wpctl_session_cfg *cfg)
{
	if (session->configured || session->targets_loaded)
		return -EBUSY;
	if (!cfg->wp_capacity || !cfg->bp_sample_period)
		return -EINVAL;
	session->wp_capacity = cfg->wp_capacity;
	session->bp_sample_period = cfg->bp_sample_period;
	session->configured = true;
	return 0;
}

/**
 * @brief 处理 `LOAD_TARGETS`，把用户态热点目标表复制到内核。
 */
static int rd_load_targets_locked(struct rd_session *session,
				  const struct rd_wpctl_target_batch *batch)
{
	struct rd_wpctl_target *user_targets;
	struct rd_target *targets;
	u32 i;

	if (!session->configured || session->targets_loaded)
		return -EINVAL;
	if (!batch->targets_ptr || !batch->count)
		return -EINVAL;

	user_targets = memdup_user(u64_to_user_ptr(batch->targets_ptr),
				   sizeof(*user_targets) * batch->count);
	if (IS_ERR(user_targets))
		return PTR_ERR(user_targets);

	targets = kcalloc(batch->count, sizeof(*targets), GFP_KERNEL);
	if (!targets) {
		kfree(user_targets);
		return -ENOMEM;
	}

	for (i = 0; i < batch->count; i++) {
		if (rd_validate_target(&user_targets[i])) {
			kfree(targets);
			kfree(user_targets);
			return -EINVAL;
		}
		targets[i].pc_offset = user_targets[i].pc_offset;
		targets[i].abs_pc = user_targets[i].abs_pc;
		targets[i].aggregated_samples = user_targets[i].aggregated_samples;
		targets[i].decode = user_targets[i].decode;
	}

	session->targets = targets;
	session->target_count = batch->count;
	session->targets_loaded = true;
	kfree(user_targets);
	return 0;
}

/**
 * @brief 返回当前 session 的目标数、线程数和桶数。
 */
static long rd_get_layout_locked(struct rd_session *session,
				 struct rd_wpctl_layout __user *uarg)
{
	struct rd_wpctl_layout layout = {};
	struct rd_thread_ctx *thread;

	layout.target_count = session->target_count;
	layout.bucket_count = RD_WPCTL_LOG2_BUCKETS;
	list_for_each_entry(thread, &session->threads, node)
		layout.thread_count++;
	if (copy_to_user(uarg, &layout, sizeof(layout)))
		return -EFAULT;
	return 0;
}

/**
 * @brief 返回指定线程的统计摘要。
 */
static long rd_get_thread_stats_locked(struct rd_session *session,
				       struct rd_wpctl_thread_stats __user *uarg)
{
	struct rd_wpctl_thread_stats req;
	struct rd_thread_ctx *thread;
	unsigned long flags;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	thread = rd_find_thread_by_index(session, req.index);
	if (!thread)
		return -ENOENT;

	{
		u32 index = req.index;

		memset(&req, 0, sizeof(req));
		req.index = index;
	}
	spin_lock_irqsave(&thread->lock, flags);
	req.tid = thread->tid;
	req.cpu = thread->cpu;
	req.active = thread->active ? 1 : 0;
	req.candidate_samples = thread->candidate_samples;
	req.reservoir_seen = thread->reservoir_seen;
	req.reservoir_accepted = thread->reservoir_accepted;
	req.reservoir_rejected = thread->reservoir_rejected;
	req.hits = thread->hits;
	req.evictions = thread->evictions;
	req.dropped = thread->dropped;
	spin_unlock_irqrestore(&thread->lock, flags);
	if (copy_to_user(uarg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

/**
 * @brief 返回指定线程、指定目标的 `log2` 直方图。
 */
static long rd_get_hist_locked(struct rd_session *session,
			       struct rd_wpctl_hist_req __user *uarg)
{
	struct rd_wpctl_hist_req req;
	struct rd_thread_ctx *thread;
	unsigned long flags;
	size_t start;
	size_t count;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	thread = rd_find_thread_by_index(session, req.thread_index);
	if (!thread)
		return -ENOENT;
	if (req.target_index >= session->target_count)
		return -EINVAL;

	memset(req.buckets, 0, sizeof(req.buckets));
	start = (size_t)req.target_index * RD_WPCTL_LOG2_BUCKETS;
	count = RD_WPCTL_LOG2_BUCKETS * sizeof(req.buckets[0]);
	spin_lock_irqsave(&thread->lock, flags);
	if (thread->log2_hist)
		memcpy(req.buckets, &thread->log2_hist[start], count);
	spin_unlock_irqrestore(&thread->lock, flags);

	if (copy_to_user(uarg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

/**
 * @brief 清空当前 session 的采样状态，但保留 target 和线程资源。
 */
static int rd_reset_session_locked(struct rd_session *session)
{
	struct rd_thread_ctx *thread;
	int ret = 0;

	if (session->running)
		return -EBUSY;

	list_for_each_entry(thread, &session->threads, node) {
		int thread_ret = rd_reset_thread_locked(thread);

		if (!ret && thread_ret)
			ret = thread_ret;
	}
	return ret;
}

/**
 * @brief 字符设备 ioctl 分派函数。
 */
static long rd_wpctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rd_session *session = file->private_data;
	long ret = 0;

	if (!session)
		return -EINVAL;

	mutex_lock(&session->lock);
	switch (cmd) {
	case RDKIOC_CONFIG_SESSION: {
		struct rd_wpctl_session_cfg cfg;

		if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
			ret = -EFAULT;
		else
			ret = rd_session_config_locked(session, &cfg);
		break;
	}
	case RDKIOC_LOAD_TARGETS: {
		struct rd_wpctl_target_batch batch;

		if (copy_from_user(&batch, (void __user *)arg, sizeof(batch)))
			ret = -EFAULT;
		else
			ret = rd_load_targets_locked(session, &batch);
		break;
	}
	case RDKIOC_REGISTER_THREAD: {
		struct rd_wpctl_thread_register reg;

		if (copy_from_user(&reg, (void __user *)arg, sizeof(reg)))
			ret = -EFAULT;
		else
			ret = rd_register_thread_locked(session, &reg);
		break;
	}
	case RDKIOC_UNREGISTER_THREAD: {
		struct rd_wpctl_thread_arg reg;

		if (copy_from_user(&reg, (void __user *)arg, sizeof(reg)))
			ret = -EFAULT;
		else
			ret = rd_unregister_thread_locked(session, reg.tid);
		break;
	}
	case RDKIOC_START_WINDOW: {
		struct rd_thread_ctx *thread;

		session->running = true;
		list_for_each_entry(thread, &session->threads, node) {
			if (thread->active)
				rd_enable_thread_events(thread);
		}
		break;
	}
	case RDKIOC_STOP_WINDOW: {
		struct rd_thread_ctx *thread;

		session->running = false;
		list_for_each_entry(thread, &session->threads, node) {
			if (thread->active)
				rd_disable_thread_events(thread);
		}
		break;
	}
	case RDKIOC_RESET_SESSION:
		ret = rd_reset_session_locked(session);
		break;
	case RDKIOC_GET_LAYOUT:
		ret = rd_get_layout_locked(session, (void __user *)arg);
		break;
	case RDKIOC_GET_THREAD_STATS:
		ret = rd_get_thread_stats_locked(session, (void __user *)arg);
		break;
	case RDKIOC_GET_LOG2_HIST:
		ret = rd_get_hist_locked(session, (void __user *)arg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}
	mutex_unlock(&session->lock);
	return ret;
}

/**
 * @brief 设备打开入口。
 *
 * 每次 `open()` 创建一个新的 session，并把当前进程 `tgid` 记为 owner。
 */
static int rd_wpctl_open(struct inode *inode, struct file *file)
{
	struct rd_session *session;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	mutex_init(&session->lock);
	INIT_LIST_HEAD(&session->threads);
	session->owner_tgid = current->tgid;
	file->private_data = session;
	return 0;
}

/**
 * @brief 设备关闭入口。
 *
 * 释放当前 session 下的所有线程对象和目标表。
 */
static int rd_wpctl_release(struct inode *inode, struct file *file)
{
	struct rd_session *session = file->private_data;
	struct rd_thread_ctx *thread, *tmp;

	if (!session)
		return 0;

	mutex_lock(&session->lock);
	list_for_each_entry_safe(thread, tmp, &session->threads, node) {
		list_del(&thread->node);
		if (thread->active)
			rd_remove_live_thread(thread);
		rd_thread_destroy(thread);
	}
	kfree(session->targets);
	mutex_unlock(&session->lock);
	kfree(session);
	file->private_data = NULL;
	return 0;
}

/** @brief `rd_wpctl` 字符设备的 file operations。 */
static const struct file_operations rd_wpctl_fops = {
	.owner = THIS_MODULE,
	.open = rd_wpctl_open,
	.release = rd_wpctl_release,
	.unlocked_ioctl = rd_wpctl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = rd_wpctl_ioctl,
#endif
};

/** @brief 导出到 `/dev/rd_wpctl` 的 miscdevice。 */
static struct miscdevice rd_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "rd_wpctl",
	.fops = &rd_wpctl_fops,
	.mode = 0600,
};

/** @brief 负责截获 sampled execute breakpoint overflow 的 kprobe。 */
static struct kprobe rd_perf_event_overflow_kprobe = {
	.symbol_name = "__perf_event_overflow",
};

/** @brief 负责截获 watchpoint 命中的 kprobe。 */
static struct kprobe rd_watchpoint_report_kprobe = {
	.symbol_name = "watchpoint_report",
};

/**
 * @brief 模块初始化入口。
 *
 * 顺序为：
 * 1. 注册两个 kprobe
 * 2. 注册 miscdevice
 */
static int __init rd_wpctl_init(void)
{
	int ret;

	atomic_set(&rd_debug_tokens, (int)rd_debug_budget);
	rd_perf_event_overflow_kprobe.pre_handler = rd_perf_event_overflow_pre;
	rd_watchpoint_report_kprobe.pre_handler = rd_watchpoint_report_pre;

	ret = register_kprobe(&rd_perf_event_overflow_kprobe);
	if (ret) {
		pr_err("rd_wpctl: register_kprobe(__perf_event_overflow) failed: %d\n", ret);
		return ret;
	}
	ret = register_kprobe(&rd_watchpoint_report_kprobe);
	if (ret) {
		pr_err("rd_wpctl: register_kprobe(watchpoint_report) failed: %d\n", ret);
		unregister_kprobe(&rd_perf_event_overflow_kprobe);
		return ret;
	}
	ret = misc_register(&rd_miscdev);
	if (ret) {
		pr_err("rd_wpctl: misc_register failed: %d\n", ret);
		unregister_kprobe(&rd_watchpoint_report_kprobe);
		unregister_kprobe(&rd_perf_event_overflow_kprobe);
		return ret;
	}
	pr_info("rd_wpctl: sampled bp hook=__perf_event_overflow wp hook=watchpoint_report\n");
	return ret;
}

/**
 * @brief 模块退出入口。
 */
static void __exit rd_wpctl_exit(void)
{
	misc_deregister(&rd_miscdev);
	unregister_kprobe(&rd_watchpoint_report_kprobe);
	unregister_kprobe(&rd_perf_event_overflow_kprobe);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("Kernel control plane for targeted RD watchpoints");

module_init(rd_wpctl_init);
module_exit(rd_wpctl_exit);
