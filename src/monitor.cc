#include <cstring>
#include <cctype>
#include <cerrno>
#include <limits.h>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <stdlib.h>
#include <perfmon/perf_event.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sched.h>
#include "monitor.hh"
#include "threads.hh"
#include "clock.hh"
#include "pthread_hook.hh"
#include "rd_exception.hh"

/**
 * @file monitor.cc
 * @brief 实现底层 perf/SPE 监控器、样本解码和热点导出逻辑。
 */

#define MB (1024*1024)
#define PAGE_SIZE (sysconf(_SC_PAGESIZE))

#define EVENTFD_TOKEN 0U
#define SAMPLER_TOKEN_KIND 1ULL
#define SAMPLER_DRAIN 1
#define SAMPLER_STOP 2
#define DEFAULT_HOTSPOT_TOP_K 12

#ifndef PERF_AUX_FLAG_COLLISION
#define PERF_AUX_FLAG_COLLISION 0x8
#endif

struct read_format {
    uint64_t value;
    uint64_t time_enabled;
    uint64_t time_running;
};

/** @brief 构造 epoll 中 sampler slot 的稳定 token。 */
static uint64_t make_sampler_token(uint32_t slot_id)
{
    return (SAMPLER_TOKEN_KIND << 32) | slot_id;
}

/** @brief 读取一个 perf fd 的 value/time_enabled/time_running。 */
static read_format read_fd(int fd)
{
    read_format count = {};
    ssize_t s = read(fd, &count, sizeof(count));
    if (s != (ssize_t)sizeof(count))
        throw RdException("read() on event fd failed");
    return count;
}

/** @brief 解析项目支持的 ARM SPE 事件名字。 */
uint64_t parse_arm_spe_event(const char* event_name)
{
    if (!strncmp(event_name, "ARM_SPE:LOAD", 13))
        return 0x200000001;
    if (!strncmp(event_name, "ARM_SPE:STORE", 14))
        return 0x400000001;
    if (!strncmp(event_name, "ARM_SPE:LOADSTORE", 18))
        return 0x600000001;
    return 0;
}

/** @brief 判断一个 SPE packet 是否是短格式地址包。 */
static bool is_arm_spe_address_packet(uint8_t header)
{
    return (header & SPE_PACKET_ADDRESS_MASK) == SPE_PACKET_ADDRESS_HEADER;
}

/** @brief 判断一个 SPE packet 是否是短格式 counter 包。 */
static bool is_arm_spe_counter_packet(uint8_t header)
{
    return (header & SPE_PACKET_COUNTER_MASK) == SPE_PACKET_COUNTER_HEADER;
}

/** @brief 判断一个 SPE packet 是否是短格式 events 包。 */
static bool is_arm_spe_events_packet(uint8_t header)
{
    return (header & SPE_PACKET_EVENTS_MASK) == SPE_PACKET_EVENTS_HEADER;
}

/** @brief 取出短格式地址包中的 index 字段。 */
static uint8_t arm_spe_short_index(uint8_t header)
{
    return header & SPE_PACKET_SHORT_INDEX_MASK;
}

/** @brief 根据 header 的 size 字段返回 payload 字节数。 */
static int arm_spe_payload_size(uint8_t header)
{
    return 1 << ((header & SPE_PACKET_HEADER_PAYLOAD_SIZE_MASK) >> 4);
}

/** @brief 读取当前实现支持的最多 8 字节 little-endian payload。 */
static uint64_t read_spe_payload(const char *packet, int payload_size)
{
    uint64_t payload = 0;
    memcpy(&payload, packet + 1, payload_size);
    return payload;
}

/** @brief 取出地址 payload 的低 56 位。 */
static uint64_t arm_spe_addr_get_bytes_0_6(uint64_t payload)
{
    return payload & ((1ULL << SPE_ADDR_PKT_BYTE7_SHIFT) - 1);
}

/**
 * @brief 根据地址包类型还原 ARM SPE 中记录的地址值。
 *
 * 指令地址与数据虚拟地址的清洗规则不同，这里沿用 perf 解码器的
 * 语义：指令地址需要保留高位上下文，数据虚拟地址只取低 56 位。
 */
static uint64_t decode_arm_spe_address_payload(int index, uint64_t payload)
{
    if (index == SPE_ADDR_PKT_HDR_INDEX_INS ||
        index == SPE_ADDR_PKT_HDR_INDEX_BRANCH ||
        index == SPE_ADDR_PKT_HDR_INDEX_PREV_BRANCH) {
        uint64_t ns = (payload >> 63) & 0x1;
        uint64_t el = (payload >> 61) & 0x3;

        payload = arm_spe_addr_get_bytes_0_6(payload);
        if (ns && (el == SPE_ADDR_PKT_EL1 || el == SPE_ADDR_PKT_EL2))
            payload |= 0xffULL << SPE_ADDR_PKT_BYTE7_SHIFT;

        return payload;
    }

    if (index == SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT)
        return arm_spe_addr_get_bytes_0_6(payload);

    return payload;
}

/** @brief 去除一行文本前导空白。 */
static std::string trim_ascii_space(const std::string& s)
{
    size_t pos = 0;
    while (pos < s.size() && std::isspace((unsigned char)s[pos]))
        pos++;
    return s.substr(pos);
}

/** @brief 尽量把绝对路径规范化为真实路径。 */
static std::string normalize_filesystem_path(const std::string& path)
{
    if (path.empty() || path[0] != '/')
        return path;

    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved))
        return resolved;
    return path;
}

/** @brief 读取当前进程主二进制路径。 */
static std::string read_self_exe_path()
{
    char path_buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path_buf, sizeof(path_buf) - 1);
    if (len <= 0)
        return "";
    path_buf[len] = '\0';
    return normalize_filesystem_path(path_buf);
}

/** @brief 读取线程最近一次运行所在 CPU。 */
static int read_thread_last_cpu_stat(int tid)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
    std::ifstream ifs(path);
    if (!ifs.is_open())
        return -1;

    std::string line;
    std::getline(ifs, line);
    ifs.close();
    if (line.empty())
        return -1;

    size_t l = line.find('(');
    size_t r = line.rfind(')');
    if (l == std::string::npos || r == std::string::npos || r <= l)
        return -1;

    std::string tail = line.substr(r + 1);
    std::istringstream iss(tail);
    std::string tok;
    int idx = 0;
    int cpu = -1;
    while (iss >> tok) {
        if (idx == 36) {
            cpu = atoi(tok.c_str());
            break;
        }
        idx++;
    }
    return cpu;
}

/** @brief 判断一组 sampler 事件中是否包含 ARM SPE。 */
int has_arm_spe_event(const char **event_names, const int num_samplers)
{
    int val = 0;
    for (int i = 0; i < num_samplers; i++) {
        val = parse_arm_spe_event(event_names[i]);
        if (val != 0)
            break;
    }
    return val;
}

/**
 * @brief 初始化一个 perf event 属性对象。
 *
 * 该函数统一处理普通 counter、普通 sample 和 ARM SPE 三种路径。
 */
perf_event_attr init_perf_attr(const char *event_name, bool per_thread, uint64_t sample_period)
{
    perf_event_attr attr = {};
    memset(&attr, 0, sizeof(perf_event_attr));
    attr.size = sizeof(perf_event_attr);

    pfm_perf_encode_arg_t arg;
    memset(&arg, 0, sizeof(pfm_perf_encode_arg_t));
    arg.size = sizeof(pfm_perf_encode_arg_t);
    arg.attr = &attr;
    char *fstr;
    arg.fstr = &fstr;

    if (PFM_SUCCESS != pfm_get_os_event_encoding(event_name,
            PFM_PLM0 | PFM_PLM3, PFM_OS_PERF_EVENT, &arg) &&
            !parse_arm_spe_event(event_name)) {
        std::stringstream ss;
        ss << "pfm_get_os_event_encoding " << event_name << " fail";
        throw RdException(ss.str());
    }

    attr.inherit = per_thread ? 0 : 1;

    if (sample_period) {
        attr.sample_period = sample_period;
        attr.sample_type = PERF_SAMPLE_ADDR | PERF_SAMPLE_TIME | PERF_SAMPLE_TID;
        attr.precise_ip = 2;
        attr.wakeup_events = SAMPLE_WAKEUP;
        attr.pinned = 1;
    }

    uint64_t spe_config = parse_arm_spe_event(event_name);
    if (spe_config) {
        int spe_event_type = 0;
        std::ifstream file("/sys/bus/event_source/devices/arm_spe_0/type");
        if (!file.is_open())
            throw RdException("Failed to open the file /sys/bus/event_source/devices/arm_spe_0/type");

        file >> spe_event_type;
        file.close();

        attr.type = spe_event_type;
        attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
            PERF_SAMPLE_DATA_SRC | PERF_SAMPLE_IDENTIFIER;
        attr.config = spe_config;
    }

    attr.disabled = 1;
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC_RAW;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.sample_id_all = 1;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    return attr;
}

/** @brief 按事件规格批量打开一组 perf fd。 */
void open_fds(int pid, bool per_thread, int cpu, const event_spec spec, uint64_t sample_period, int *fds)
{
    int group_fd = -1;

    for (int i = 0; i < spec.n; i++) {
        if (spec.event_leader[i])
            group_fd = -1;

        perf_event_attr attr = init_perf_attr(spec.event_name[i], per_thread, sample_period);
        errno = 0;
        int fd = perf_event_open(&attr, pid, cpu, group_fd, 0);
        if (fd < 0) {
            std::stringstream ss;
            ss << "perf_event_open failed [i=" << i << ", errno=" << strerror(errno) << "]";
            throw RdException(ss.str());
        }

        fds[i] = fd;
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);

        if (group_fd == -1)
            group_fd = fd;
    }
}

/** @brief 构造监控器并接入当前进程已有线程。 */
Monitor::Monitor(const event_spec counter_spec, const event_spec sampler_spec, uint64_t sample_period,
    int ringbufsize, int auxbufsize, const char *name, bool is_pin)
    : _num_counters(counter_spec.n)
    , _num_samplers(sampler_spec.n)
    , _num_cpus(get_nprocs())
    , _sample_period(sample_period)
    , _ringbufsize(ringbufsize)
    , _auxbufsize(auxbufsize)
    , _counter_spec(counter_spec)
    , _sampler_spec(sampler_spec)
    , _nonstop_mode(false)
    , sampler_tid(-1)
    , _events_enabled(false)
    , _next_slot_id(0)
    , _written_sample_bytes(0)
    , _is_pin(is_pin)
    , _event_fd(-1)
    , _epoll_fd(-1)
    , _hotspot_top_k(DEFAULT_HOTSPOT_TOP_K)
    , _hotspot_min_samples(1)
    , _hotspot_min_latency_samples(1)
    , _hotspot_unmapped_samples(0)
    , _spe_time_packet_flush_count(0)
    , _spe_end_packet_flush_count(0)
    , _spe_empty_flush_count(0)
    , _spe_unknown_packet_count(0)
{
    const char *env_hotspot_top_k = getenv("RD_HOTSPOT_TOP_K");
    const char *env_hotspot_min_samples = getenv("RD_HOTPC_MIN_SAMPLES");
    const char *env_hotspot_min_latency_samples = getenv("RD_HOTPC_MIN_LATENCY_SAMPLES");

    if (env_hotspot_top_k && *env_hotspot_top_k) {
        char *end = nullptr;
        unsigned long value = strtoul(env_hotspot_top_k, &end, 10);

        if (!end || *end != '\0' || value == 0)
            throw RdException("RD_HOTSPOT_TOP_K must be a positive integer");
        _hotspot_top_k = (size_t)value;
    }

    if (env_hotspot_min_samples && *env_hotspot_min_samples) {
        char *end = nullptr;
        unsigned long value = strtoul(env_hotspot_min_samples, &end, 10);

        if (!end || *end != '\0' || value == 0)
            throw RdException("RD_HOTPC_MIN_SAMPLES must be a positive integer");
        _hotspot_min_samples = (size_t)value;
    }

    if (env_hotspot_min_latency_samples && *env_hotspot_min_latency_samples) {
        char *end = nullptr;
        unsigned long value = strtoul(env_hotspot_min_latency_samples, &end, 10);

        if (!end || *end != '\0' || value == 0)
            throw RdException("RD_HOTPC_MIN_LATENCY_SAMPLES must be a positive integer");
        _hotspot_min_latency_samples = (size_t)value;
    }

    char fn[128];
    snprintf(fn, sizeof(fn), "%s.info", name);
    _nameprefix = name;
    _info_file = std::ofstream(fn, std::ios::trunc);

    if (PFM_SUCCESS != pfm_initialize())
        throw RdException("PFM init fail!");

    timespec res = {};
    if (clock_getres(CLOCK_MONOTONIC_RAW, &res) < 0 || res.tv_sec)
        throw RdException("clock_getres failure (CLOCK_MONOTONIC_RAW)");
    _clock_res = res.tv_nsec * 1000000000ULL;

    if (_num_samplers > 0) {
        _epoll_fd = epoll_create(1024);
        if (_epoll_fd < 0)
            throw RdException("epoll_create failed");

        _event_fd = eventfd(0, 0);
        if (_event_fd < 0)
            throw RdException("eventfd failed");

        if (sem_init(&_sampler_drain, 0, 1) < 0)
            throw RdException("sem_init");

        {
            PthreadCreateBypassGuard guard;
            _sampler_thread = std::thread(&Monitor::run_sampler_thread, this);
        }

        if (sizeof(sampler_tid) != read(_event_fd, &sampler_tid, sizeof(sampler_tid)))
            throw RdException("eventfd read failed");

        epoll_event ep_event = {};
        ep_event.events = EPOLLIN;
        ep_event.data.u32 = EVENTFD_TOKEN;
        if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _event_fd, &ep_event) < 0)
            throw RdException("epoll_ctl");
    }

    _prev_counters.assign(_num_counters + _num_samplers, 0);
    _retired_values.assign(_num_counters + _num_samplers, 0);
    _retired_time_enabled.assign(_num_counters + _num_samplers, 0);
    _retired_time_running.assign(_num_counters + _num_samplers, 0);

    std::vector<int> threads = get_threads(sampler_tid);
    for (int tid : threads) {
        try {
            register_thread_locked(tid);
        } catch (const std::exception& e) {
            std::cerr << "warning: failed to attach initial tid " << tid << ": " << e.what() << std::endl;
        }
    }

    std::cerr << "Monitor setup, " << _threads.size() << " threads, "
              << _num_counters << " counters/thread, "
              << _num_samplers << " samplers/thread" << std::endl;
}

/** @brief 判断 sampler 规格是否走 ARM SPE 格式。 */
bool Monitor::has_arm_spe_samples() const
{
    return has_arm_spe_event(_sampler_spec.event_name, _num_samplers) != 0;
}

/** @brief 返回单条样本记录的字节数。 */
size_t Monitor::sample_record_bytes() const
{
    return has_arm_spe_samples() ? sizeof(spe_instruction_sample) : sizeof(uint64_t) * 2;
}

/** @brief 返回当前样本记录的字段顺序描述。 */
const char *Monitor::sample_record_fields() const
{
    return has_arm_spe_samples() ? "pc,data_va,lat_total,lat_issue,lat_xlat,event_bits,flags" : "time,addr";
}

/** @brief 判断样本记录中是否显式携带 PC。 */
bool Monitor::sample_pc_present() const
{
    return has_arm_spe_samples();
}

/** @brief 以去重方式记住一次可执行模块映射。 */
void Monitor::remember_module_map(uint64_t vm_start, uint64_t vm_end, uint64_t file_offset, const std::string& path)
{
    const std::string effective_path = path.empty() ? "[anonymous_exec]" : normalize_filesystem_path(path);
    for (const auto& entry : _module_maps) {
        if (entry.vm_start == vm_start &&
            entry.vm_end == vm_end &&
            entry.file_offset == file_offset &&
            entry.path == effective_path)
            return;
    }

    module_map_entry entry = {};
    entry.module_id = (uint32_t)_module_maps.size();
    entry.vm_start = vm_start;
    entry.vm_end = vm_end;
    entry.file_offset = file_offset;
    entry.path = effective_path;
    _module_maps.push_back(entry);
}

/** @brief 记录当前运行的主二进制路径。 */
void Monitor::snapshot_main_binary_path()
{
    if (_main_binary_path.empty())
        _main_binary_path = read_self_exe_path();
}

/** @brief 抓取 `/proc/self/maps` 中所有可执行映射，供热点 PC 离线解释使用。 */
void Monitor::snapshot_module_maps()
{
    if (!sample_pc_present())
        return;

    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open())
        throw RdException("Cannot open /proc/self/maps");

    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        std::string range;
        std::string perms;
        std::string offset_hex;
        std::string dev;
        std::string inode;
        if (!(iss >> range >> perms >> offset_hex >> dev >> inode))
            continue;
        if (perms.size() < 3 || perms[2] != 'x')
            continue;

        std::string path;
        std::getline(iss, path);
        path = trim_ascii_space(path);

        char *range_sep = nullptr;
        uint64_t vm_start = strtoull(range.c_str(), &range_sep, 16);
        if (!range_sep || *range_sep != '-')
            continue;
        uint64_t vm_end = strtoull(range_sep + 1, nullptr, 16);
        uint64_t file_offset = strtoull(offset_hex.c_str(), nullptr, 16);
        remember_module_map(vm_start, vm_end, file_offset, path);
    }
}

/** @brief 通过绝对 PC 查找所属模块映射。 */
const module_map_entry *Monitor::find_module_map(uint64_t pc) const
{
    for (const auto& entry : _module_maps) {
        if (entry.vm_start <= pc && pc < entry.vm_end)
            return &entry;
    }
    return nullptr;
}

/** @brief 判断一条模块映射是否属于当前主二进制。 */
bool Monitor::is_main_binary_module(const module_map_entry& entry) const
{
    return !_main_binary_path.empty() && entry.path == _main_binary_path;
}

static bool spe_sample_has_event(const spe_instruction_sample& sample, int event_bit)
{
    return (sample.flags & SPE_SAMPLE_FLAG_EVENTS_VALID) &&
        (sample.event_bits & (1ULL << event_bit));
}

static uint64_t hotspot_latency_count(const hotspot_stats& stats)
{
    return stats.lat_exec_count ? stats.lat_exec_count : stats.lat_total_count;
}

static uint64_t hotspot_candidate_score(const hotspot_stats& stats)
{
    return stats.lat_exec_count ? stats.lat_exec_sum : stats.lat_total_sum;
}

static const char *hotspot_candidate_metric(const hotspot_stats& stats)
{
    return stats.lat_exec_count ? "lat_exec_sum" : "lat_total_sum";
}

static double hotspot_avg_mem_latency(const hotspot_stats& stats)
{
    if (stats.lat_exec_count)
        return (double)stats.lat_exec_sum / (double)stats.lat_exec_count;
    if (stats.lat_total_count)
        return (double)stats.lat_total_sum / (double)stats.lat_total_count;
    return 0.0;
}

static bool hotspot_dominates(const hotspot_summary& a, const hotspot_summary& b)
{
    bool sample_ge = a.sample_count >= b.sample_count;
    bool latency_ge = a.avg_mem_latency >= b.avg_mem_latency;
    bool sample_gt = a.sample_count > b.sample_count;
    bool latency_gt = a.avg_mem_latency > b.avg_mem_latency;
    return sample_ge && latency_ge && (sample_gt || latency_gt);
}

static bool hotspot_score_before(const hotspot_summary& a, const hotspot_summary& b)
{
    if (a.candidate_score != b.candidate_score)
        return a.candidate_score > b.candidate_score;
    if (a.sample_count != b.sample_count)
        return a.sample_count > b.sample_count;
    if (a.module_id != b.module_id)
        return a.module_id < b.module_id;
    return a.pc_offset < b.pc_offset;
}

/** @brief 记录一次热点 PC 样本，并按“模块 + offset”归并。 */
void Monitor::record_hotspot_sample(int tid, const spe_instruction_sample& sample)
{
    if (!sample_pc_present() || tid <= 0 || sample.pc == 0 ||
        !(sample.flags & SPE_SAMPLE_FLAG_PC_VALID))
        return;

    const module_map_entry *entry = find_module_map(sample.pc);
    if (!entry) {
        _hotspot_unmapped_samples += 1;
        return;
    }
    if (!is_main_binary_module(*entry))
        return;
    hotspot_key key = {};
    key.module_id = entry->module_id;
    key.pc_offset = sample.pc - entry->vm_start + entry->file_offset;

    hotspot_stats& stats = _thread_hotspots[tid][key];
    stats.sample_count += 1;
    if (sample.flags & SPE_SAMPLE_FLAG_LAT_TOTAL_VALID) {
        stats.lat_total_sum += sample.lat_total;
        stats.lat_total_count += 1;
    }
    if (sample.flags & SPE_SAMPLE_FLAG_LAT_ISSUE_VALID) {
        stats.lat_issue_sum += sample.lat_issue;
        stats.lat_issue_count += 1;
    }
    if (sample.flags & SPE_SAMPLE_FLAG_LAT_XLAT_VALID) {
        stats.lat_xlat_sum += sample.lat_xlat;
        stats.lat_xlat_count += 1;
    }
    if (sample.flags & SPE_SAMPLE_FLAG_LAT_EXEC_VALID) {
        uint64_t issue_and_xlat = sample.lat_issue + sample.lat_xlat;
        stats.lat_exec_sum += sample.lat_total - issue_and_xlat;
        stats.lat_exec_count += 1;
    }
    if (spe_sample_has_event(sample, SPE_EVENT_L1D_REFILL))
        stats.l1d_refill_count += 1;
    if (spe_sample_has_event(sample, SPE_EVENT_LLC_MISS))
        stats.llc_miss_count += 1;
    if (spe_sample_has_event(sample, SPE_EVENT_TLB_WALK))
        stats.tlb_walk_count += 1;
    if (spe_sample_has_event(sample, SPE_EVENT_REMOTE_ACCESS))
        stats.remote_access_count += 1;
}

/** @brief 清空 slot 中未完成的 SPE sampled instruction 状态。 */
void Monitor::reset_pending_spe_sample(sampler_slot& slot) const
{
    slot.pending_pc = 0;
    slot.pending_data_va = 0;
    slot.pending_lat_total = 0;
    slot.pending_lat_issue = 0;
    slot.pending_lat_xlat = 0;
    slot.pending_event_bits = 0;
    slot.pending_flags = 0;
}

/** @brief 将 pending SPE 状态写出为一条固定结构的指令级样本。 */
bool Monitor::flush_pending_spe_sample_locked(sampler_slot& slot, BinaryWriter& writer, size_t& num_samples,
    bool from_end_packet)
{
    if (!(slot.pending_flags & SPE_SAMPLE_FLAG_PC_VALID)) {
        reset_pending_spe_sample(slot);
        _spe_empty_flush_count += 1;
        return false;
    }

    spe_instruction_sample sample = {};
    sample.pc = slot.pending_pc;
    sample.data_va = slot.pending_data_va;
    sample.lat_total = slot.pending_lat_total;
    sample.lat_issue = slot.pending_lat_issue;
    sample.lat_xlat = slot.pending_lat_xlat;
    sample.event_bits = slot.pending_event_bits;
    sample.flags = slot.pending_flags;

    const uint64_t latency_flags =
        SPE_SAMPLE_FLAG_LAT_TOTAL_VALID |
        SPE_SAMPLE_FLAG_LAT_ISSUE_VALID |
        SPE_SAMPLE_FLAG_LAT_XLAT_VALID;
    if ((sample.flags & latency_flags) == latency_flags &&
        sample.lat_total >= sample.lat_issue + sample.lat_xlat)
        sample.flags |= SPE_SAMPLE_FLAG_LAT_EXEC_VALID;

    writer.write((char *)&sample, sizeof(sample));
    _written_sample_bytes += sizeof(sample);
    record_hotspot_sample(slot.tid, sample);
    num_samples++;
    if (from_end_packet)
        _spe_end_packet_flush_count += 1;
    else
        _spe_time_packet_flush_count += 1;
    reset_pending_spe_sample(slot);
    return true;
}

/** @brief 生成一个线程的热点摘要列表，并按热度排序。 */
std::vector<hotspot_summary> Monitor::collect_hotspots_for_thread(int tid) const
{
    std::vector<hotspot_summary> all_summaries;
    auto it = _thread_hotspots.find(tid);
    if (it == _thread_hotspots.end())
        return all_summaries;

    all_summaries.reserve(it->second.size());
    for (const auto& kv : it->second) {
        const hotspot_stats& stats = kv.second;
        hotspot_summary summary = {};
        summary.tid = tid;
        summary.module_id = kv.first.module_id;
        summary.pc_offset = kv.first.pc_offset;
        summary.sample_count = stats.sample_count;
        summary.candidate_score = hotspot_candidate_score(stats);
        summary.candidate_metric = hotspot_candidate_metric(stats);
        summary.avg_mem_latency = hotspot_avg_mem_latency(stats);
        summary.lat_total_sum = stats.lat_total_sum;
        summary.lat_issue_sum = stats.lat_issue_sum;
        summary.lat_xlat_sum = stats.lat_xlat_sum;
        summary.lat_exec_sum = stats.lat_exec_sum;
        summary.l1d_refill_count = stats.l1d_refill_count;
        summary.llc_miss_count = stats.llc_miss_count;
        summary.tlb_walk_count = stats.tlb_walk_count;
        summary.remote_access_count = stats.remote_access_count;
        if (summary.module_id < _module_maps.size())
            summary.path = _module_maps[summary.module_id].path;
        else
            summary.path = "[unknown_module]";
        all_summaries.push_back(summary);
    }

    std::vector<hotspot_summary> filtered;
    std::vector<hotspot_summary> fallback;
    for (auto summary : all_summaries) {
        auto stats_it = it->second.find({summary.module_id, summary.pc_offset});
        uint64_t latency_count = 0;
        if (stats_it != it->second.end())
            latency_count = hotspot_latency_count(stats_it->second);

        if (summary.sample_count >= _hotspot_min_samples &&
            latency_count >= _hotspot_min_latency_samples)
            filtered.push_back(summary);
        else
            fallback.push_back(summary);
    }

    std::vector<hotspot_summary> front;
    std::vector<hotspot_summary> non_front;
    for (size_t i = 0; i < filtered.size(); i++) {
        bool dominated = false;
        for (size_t j = 0; j < filtered.size(); j++) {
            if (i == j)
                continue;
            if (hotspot_dominates(filtered[j], filtered[i])) {
                dominated = true;
                break;
            }
        }
        filtered[i].pareto_front = dominated ? 0 : 1;
        if (dominated)
            non_front.push_back(filtered[i]);
        else
            front.push_back(filtered[i]);
    }

    std::sort(front.begin(), front.end(), hotspot_score_before);
    std::sort(non_front.begin(), non_front.end(), hotspot_score_before);
    std::sort(fallback.begin(), fallback.end(), hotspot_score_before);

    std::vector<hotspot_summary> summaries;
    summaries.reserve(std::min(_hotspot_top_k, all_summaries.size()));
    for (const auto& summary : front) {
        if (summaries.size() >= _hotspot_top_k)
            break;
        summaries.push_back(summary);
    }
    for (const auto& summary : non_front) {
        if (summaries.size() >= _hotspot_top_k)
            break;
        summaries.push_back(summary);
    }
    for (auto summary : fallback) {
        if (summaries.size() >= _hotspot_top_k)
            break;
        summary.pareto_front = 0;
        summaries.push_back(summary);
    }

    return summaries;
}

/** @brief 把热点摘要写出为独立 `.hotpc` manifest。 */
void Monitor::write_hotspot_manifest() const
{
    if (!sample_pc_present())
        return;

    std::string manifest_path = _nameprefix + ".hotpc";
    std::ofstream out(manifest_path, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "warning: cannot open hotspot manifest " << manifest_path << std::endl;
        return;
    }

    size_t hotspot_count = 0;
    for (int tid : _tids)
        hotspot_count += collect_hotspots_for_thread(tid).size();

    out << "hotspot_top_k=" << _hotspot_top_k << std::endl;
    out << "hotspot_identity=module_offset" << std::endl;
    out << "hotspot_scope=main_binary_only" << std::endl;
    out << "hotspot_main_binary=" << _main_binary_path << std::endl;
    out << "hotspot_kind_hint=arm_spe_loadstore" << std::endl;
    out << "hotspot_selection_policy=pareto_sample_count_avg_mem_latency" << std::endl;
    out << "hotspot_fields=tid,rank,sample_count,module_id,pc_offset,path,pareto_front,candidate_score,candidate_metric,avg_mem_latency,lat_total_sum,lat_issue_sum,lat_xlat_sum,lat_exec_sum,l1d_refill_count,llc_miss_count,tlb_walk_count,remote_access_count" << std::endl;
    out << "hotspot_count=" << hotspot_count << std::endl;
    out << "hotspot_unmapped_pc_samples=" << _hotspot_unmapped_samples << std::endl;

    for (int tid : _tids) {
        std::vector<hotspot_summary> hotspots = collect_hotspots_for_thread(tid);
        for (size_t rank = 0; rank < hotspots.size(); rank++) {
            const auto& hotspot = hotspots[rank];
            out << "hotspot="
                << hotspot.tid << "\t"
                << (rank + 1) << "\t"
                << hotspot.sample_count << "\t"
                << hotspot.module_id << "\t"
                << "0x" << std::hex << hotspot.pc_offset << std::dec << "\t"
                << hotspot.path << "\t"
                << hotspot.pareto_front << "\t"
                << hotspot.candidate_score << "\t"
                << hotspot.candidate_metric << "\t"
                << hotspot.avg_mem_latency << "\t"
                << hotspot.lat_total_sum << "\t"
                << hotspot.lat_issue_sum << "\t"
                << hotspot.lat_xlat_sum << "\t"
                << hotspot.lat_exec_sum << "\t"
                << hotspot.l1d_refill_count << "\t"
                << hotspot.llc_miss_count << "\t"
                << hotspot.tlb_walk_count << "\t"
                << hotspot.remote_access_count << std::endl;
        }
    }
}

/** @brief 写出 `.info` 文件，作为本次运行的元数据总清单。 */
void Monitor::write_info(std::ofstream& info)
{
    int max_cmdline = 256;
    std::ifstream clf("/proc/self/cmdline");
    char cmdline[256] = {};
    clf.get(cmdline, max_cmdline);
    clf.close();
    for (int i = 0; i < max_cmdline - 1; i++) {
        if (!cmdline[i]) {
            if (cmdline[i + 1])
                cmdline[i] = ' ';
            else
                break;
        }
    }
    info << "cmdline=" << cmdline << std::endl;
    info << "sample_period=" << _sample_period << std::endl;
    info << "bufsize_ring=" << _ringbufsize << std::endl;
    info << "bufsize_aux=" << _auxbufsize << std::endl;
    info << "clock_res=" << 1.0 / _clock_res << std::endl;
    info << "l1_cache_line_size=" << sysconf(_SC_LEVEL1_DCACHE_LINESIZE) << std::endl;
    info << "main_binary=" << _main_binary_path << std::endl;

    if (_num_samplers > 0) {
        info << "sample_record_bytes=" << sample_record_bytes() << std::endl;
        info << "sample_record_fields=" << sample_record_fields() << std::endl;
        info << "sample_pc_present=" << (sample_pc_present() ? 1 : 0) << std::endl;
        if (has_arm_spe_samples()) {
            info << "sample_data_va_present=1" << std::endl;
            info << "sample_time_present=0" << std::endl;
            info << "spe_time_packet_used_as_record_end=1" << std::endl;
            info << "spe_end_packet_used_as_record_end=1" << std::endl;
            info << "spe_sample_flags=pc_valid,lat_total_valid,lat_issue_valid,lat_xlat_valid,events_valid,lat_exec_valid,data_va_valid" << std::endl;
        }
    }

    if (sample_pc_present()) {
        info << "pc_identity=raw_va" << std::endl;
        info << "spe_latency_present=1" << std::endl;
        info << "spe_event_packet_present=1" << std::endl;
        info << "spe_time_packet_flush_count=" << _spe_time_packet_flush_count << std::endl;
        info << "spe_end_packet_flush_count=" << _spe_end_packet_flush_count << std::endl;
        info << "spe_empty_flush_count=" << _spe_empty_flush_count << std::endl;
        info << "spe_unknown_packet_count=" << _spe_unknown_packet_count << std::endl;
        info << "module_map_fields=module_id,path,vm_start,vm_end,file_offset" << std::endl;
        info << "module_map_count=" << _module_maps.size() << std::endl;
        for (const auto& entry : _module_maps) {
            info << "module_map="
                 << entry.module_id << "\t"
                 << entry.path << "\t"
                 << "0x" << std::hex << entry.vm_start << "\t"
                 << "0x" << entry.vm_end << "\t"
                 << "0x" << entry.file_offset << std::dec
                 << std::endl;
        }

        size_t hotspot_count = 0;
        size_t hotspot_thread_count = 0;
        uint64_t hotspot_total_samples = 0;
        for (const auto& tid_and_hotspots : _thread_hotspots) {
            if (!tid_and_hotspots.second.empty())
                hotspot_thread_count += 1;
            for (const auto& kv : tid_and_hotspots.second)
                hotspot_total_samples += kv.second.sample_count;
        }
        for (int tid : _tids)
            hotspot_count += collect_hotspots_for_thread(tid).size();

        info << "hotspot_top_k=" << _hotspot_top_k << std::endl;
        info << "hotspot_min_samples=" << _hotspot_min_samples << std::endl;
        info << "hotspot_min_latency_samples=" << _hotspot_min_latency_samples << std::endl;
        info << "hotspot_identity=module_offset" << std::endl;
        info << "hotspot_scope=main_binary_only" << std::endl;
        info << "hotspot_main_binary=" << _main_binary_path << std::endl;
        info << "hotspot_kind_hint=arm_spe_loadstore" << std::endl;
        info << "hotspot_selection_policy=pareto_sample_count_avg_mem_latency" << std::endl;
        info << "hotspot_score_policy=lat_exec_sum_with_lat_total_sum_fallback" << std::endl;
        info << "hotspot_thread_count=" << hotspot_thread_count << std::endl;
        info << "hotspot_total_samples=" << hotspot_total_samples << std::endl;
        info << "hotspot_unmapped_pc_samples=" << _hotspot_unmapped_samples << std::endl;
        info << "hotspot_manifest=" << _nameprefix << ".hotpc" << std::endl;
        info << "hotspot_fields=tid,rank,sample_count,module_id,pc_offset,path,pareto_front,candidate_score,candidate_metric,avg_mem_latency,lat_total_sum,lat_issue_sum,lat_xlat_sum,lat_exec_sum,l1d_refill_count,llc_miss_count,tlb_walk_count,remote_access_count" << std::endl;
        info << "hotspot_count=" << hotspot_count << std::endl;
        for (int tid : _tids) {
            std::vector<hotspot_summary> hotspots = collect_hotspots_for_thread(tid);
            for (size_t rank = 0; rank < hotspots.size(); rank++) {
                const auto& hotspot = hotspots[rank];
                info << "hotspot="
                     << hotspot.tid << "\t"
                     << (rank + 1) << "\t"
                     << hotspot.sample_count << "\t"
                     << hotspot.module_id << "\t"
                     << "0x" << std::hex << hotspot.pc_offset << std::dec << "\t"
                     << hotspot.path << "\t"
                     << hotspot.pareto_front << "\t"
                     << hotspot.candidate_score << "\t"
                     << hotspot.candidate_metric << "\t"
                     << hotspot.avg_mem_latency << "\t"
                     << hotspot.lat_total_sum << "\t"
                     << hotspot.lat_issue_sum << "\t"
                     << hotspot.lat_xlat_sum << "\t"
                     << hotspot.lat_exec_sum << "\t"
                     << hotspot.l1d_refill_count << "\t"
                     << hotspot.llc_miss_count << "\t"
                     << hotspot.tlb_walk_count << "\t"
                     << hotspot.remote_access_count << std::endl;
            }
        }
    }

    if (_kinfos.size()) {
        info << "tag=" << _kinfos[0].tag;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].tag;
        info << std::endl;

        info << "offloaded=" << _kinfos[0].offloaded;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].offloaded;
        info << std::endl;

        info << "num_samples=" << _kinfos[0].num_samples;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].num_samples;
        info << std::endl;

        info << "sample_throttles=" << _kinfos[0].sample_throttles;
        uint64_t total_throttles = _kinfos[0].sample_throttles;
        for (size_t i = 1; i < _kinfos.size(); i++) {
            info << "," << _kinfos[i].sample_throttles;
            total_throttles += _kinfos[i].sample_throttles;
        }
        info << std::endl;
        if (total_throttles)
            std::cerr << "warning: sampler throttled " << total_throttles << " times" << std::endl;

        info << "duration=" << _kinfos[0].duration;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].duration;
        info << std::endl;

        info << "clock_start=" << _kinfos[0].clock_start;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].clock_start;
        info << std::endl;

        info << "clock_stop=" << _kinfos[0].clock_stop;
        for (size_t i = 1; i < _kinfos.size(); i++)
            info << "," << _kinfos[i].clock_stop;
        info << std::endl;

        info << "counters_are_not_cumulative=1" << std::endl;

        for (int counter = 0; counter < _num_counters; counter++) {
            const char *name = _counter_spec.event_name[counter];
            info << name << "=" << _kinfos[0].counters[counter].value;
            for (size_t i = 1; i < _kinfos.size(); i++)
                info << "," << _kinfos[i].counters[counter].value;
            info << std::endl;

            info << "active_" << name << "=" << _kinfos[0].counters[counter].active_time;
            for (size_t i = 1; i < _kinfos.size(); i++)
                info << "," << _kinfos[i].counters[counter].active_time;
            info << std::endl;
        }

        for (int sampler = 0; sampler < _num_samplers; sampler++) {
            const char *name = _sampler_spec.event_name[sampler];
            if (!parse_arm_spe_event(name)) {
                info << name << "=" << _kinfos[0].counters[_num_counters + sampler].value;
                for (size_t i = 1; i < _kinfos.size(); i++)
                    info << "," << _kinfos[i].counters[_num_counters + sampler].value;
                info << std::endl;
            }
        }
    }

    if (_addr_tags.size()) {
        info << "addr_tags=" << _addr_tags[0].tag << ":" << _addr_tags[0].start << ":" << _addr_tags[0].end;
        for (size_t i = 1; i < _addr_tags.size(); i++)
            info << "," << _addr_tags[i].tag << ":" << _addr_tags[i].start << ":" << _addr_tags[i].end;
        info << std::endl;
    }

    if (_phases.size()) {
        info << "phases=" << _phases[0].tag << ":" << _phases[0].time;
        for (size_t i = 1; i < _phases.size(); i++)
            info << "," << _phases[i].tag << ":" << _phases[i].time;
        info << std::endl;
    }
}

/** @brief 记录一个阶段标记。 */
void Monitor::mark_phase(const char *tag)
{
    _phases.push_back({tag, nano_clock()});
}

/** @brief 析构时停止后台线程、回收资源并落盘所有结果。 */
Monitor::~Monitor()
{
    if (_event_fd != -1) {
        uint64_t efd_cmd = SAMPLER_STOP;
        if (sizeof(efd_cmd) != write(_event_fd, &efd_cmd, sizeof(efd_cmd))) {
            perror("eventfd write");
            abort();
        }
    }

    if (_sampler_thread.joinable())
        _sampler_thread.join();

    {
        std::lock_guard<std::mutex> lock(_state_mutex);
        if (_events_enabled) {
            for (auto& kv : _threads) {
                if (kv.second.active)
                    disable_thread_locked(kv.second);
            }
            _events_enabled = false;
        }

        for (auto& kv : _threads)
            close_thread_locked(kv.second);
    }

    write_info(_info_file);
    _info_file.close();
    write_hotspot_manifest();

    size_t total_samples = 0;
    for (auto& ki : _kinfos)
        total_samples += ki.num_samples;
    if (_num_samplers > 0 && _written_sample_bytes != total_samples * sample_record_bytes()) {
        std::cerr << "warning: written bytes " << _written_sample_bytes
                  << " does not match total samples " << total_samples << std::endl;
    }

    for (auto& ki : _kinfos)
        delete[] ki.counters;

    if (_event_fd != -1)
        close(_event_fd);
    if (_epoll_fd != -1)
        close(_epoll_fd);
    if (_epoll_fd != -1)
        sem_destroy(&_sampler_drain);

    std::cerr << "Monitor::~Monitor done" << std::endl;
}

/** @brief 在持锁状态下查找线程状态。 */
thread_state *Monitor::find_thread_locked(int tid)
{
    auto it = _threads.find(tid);
    if (it == _threads.end())
        return nullptr;
    return &it->second;
}

/** @brief 在持锁状态下注册指定线程。 */
thread_state& Monitor::register_thread_locked(int tid)
{
    thread_state& state = _threads[tid];
    state.tid = tid;
    if (std::find(_tids.begin(), _tids.end(), tid) == _tids.end())
        _tids.push_back(tid);
    if (state.active)
        return state;

    try {
        open_thread_locked(state);
        state.active = true;
    } catch (...) {
        close_thread_locked(state);
        throw;
    }
    return state;
}

/**
 * @brief 为一个线程打开 counter/sampler fd 并建立映射。
 *
 * sampler 路径会创建 per-thread writer，并把每个 sampler slot 注册到
 * epoll 监听集合中。
 */
void Monitor::open_thread_locked(thread_state& state)
{
    if (_is_pin) {
        int cpu = read_thread_last_cpu_stat(state.tid);
        if (cpu >= 0 && cpu < _num_cpus) {
            cpu_set_t set;
            CPU_ZERO(&set);
            CPU_SET(cpu, &set);
            sched_setaffinity(state.tid, sizeof(set), &set);
        }
    }

    if (_num_counters > 0) {
        state.counter_fds.assign(_num_counters, -1);
        open_fds(state.tid, true, -1, _counter_spec, 0, state.counter_fds.data());
    } else {
        state.counter_fds.clear();
    }

    if (_num_samplers == 0)
        return;

    if (state.writers.empty()) {
        state.writers.reserve(_num_samplers);
        for (int sampler = 0; sampler < _num_samplers; sampler++) {
            char fn[128];
            snprintf(fn, sizeof(fn), "%s.t%d.sample%d", _nameprefix.c_str(), state.tid, sampler);
            state.writers.emplace_back(fn);
        }
    } else if ((int)state.writers.size() != _num_samplers) {
        throw RdException("writer vector size mismatch");
    }

    int ring_buffer_pages = (_ringbufsize * MB) / PAGE_SIZE;
    int aux_buffer_pages = (_auxbufsize * MB) / PAGE_SIZE;
    std::vector<int> sampler_fds(_num_samplers, -1);

    if (has_arm_spe_samples()) {
        void *scratch = mmap(NULL, (1 + ring_buffer_pages) * PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (scratch != MAP_FAILED)
            munmap(scratch, (1 + ring_buffer_pages) * PAGE_SIZE);
    }

    open_fds(state.tid, true, -1, _sampler_spec, _sample_period, sampler_fds.data());

    state.samplers.clear();
    state.samplers.reserve(_num_samplers);

    try {
        for (int sampler = 0; sampler < _num_samplers; sampler++) {
            sampler_slot slot = {};
            slot.slot_id = _next_slot_id++;
            slot.tid = state.tid;
            slot.sampler_index = sampler;
            slot.fd = sampler_fds[sampler];
            sampler_fds[sampler] = -1;
            reset_pending_spe_sample(slot);
            slot.ringbuf_bytes = (1 + ring_buffer_pages) * PAGE_SIZE;
            slot.auxbuf_bytes = 0;
            slot.ringbuf = mmap(0, slot.ringbuf_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, slot.fd, 0);
            if (slot.ringbuf == MAP_FAILED) {
                slot.ringbuf = nullptr;
                throw RdException("mapping sampler ring buffer failed");
            }
            slot.auxbuf = nullptr;

            if (parse_arm_spe_event(_sampler_spec.event_name[sampler])) {
                perf_event_mmap_page *p = (perf_event_mmap_page *)slot.ringbuf;
                p->aux_offset = (1 + ring_buffer_pages) * PAGE_SIZE;
                p->aux_size = aux_buffer_pages * PAGE_SIZE;
                slot.auxbuf_bytes = p->aux_size;
                slot.auxbuf = mmap(0, p->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, slot.fd, p->aux_offset);
                if (slot.auxbuf == MAP_FAILED) {
                    slot.auxbuf = nullptr;
                    throw RdException("mapping sampler aux ring buffer failed");
                }

                uint64_t real_aux_offset =
                    (uint64_t)(uintptr_t)slot.auxbuf - (uint64_t)(uintptr_t)slot.ringbuf;
                p->aux_offset = real_aux_offset;
            }

            state.samplers.push_back(slot);
            sampler_slot *slot_ptr = &state.samplers.back();
            _sampler_slots[slot_ptr->slot_id] = slot_ptr;

            if (_epoll_fd != -1) {
                epoll_event ep_event = {};
                ep_event.events = EPOLLIN;
                ep_event.data.u64 = make_sampler_token((uint32_t)slot_ptr->slot_id);
                if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, slot_ptr->fd, &ep_event) < 0)
                    throw RdException("epoll_ctl");
            }
        }
    } catch (...) {
        for (int fd : sampler_fds) {
            if (fd >= 0)
                close(fd);
        }
        throw;
    }
}

/** @brief enable 一个线程上的全部 perf 事件。 */
void Monitor::enable_thread_locked(thread_state& state)
{
    for (int fd : state.counter_fds) {
        if (fd >= 0)
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    }
    for (auto& slot : state.samplers) {
        if (slot.fd >= 0)
            ioctl(slot.fd, PERF_EVENT_IOC_ENABLE, 0);
    }
}

/** @brief disable 一个线程上的全部 perf 事件。 */
void Monitor::disable_thread_locked(thread_state& state)
{
    for (int fd : state.counter_fds) {
        if (fd >= 0)
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    }
    for (auto& slot : state.samplers) {
        if (slot.fd >= 0)
            ioctl(slot.fd, PERF_EVENT_IOC_DISABLE, 0);
    }
}

/** @brief 把即将退役线程的累计 perf 计数合并入全局退役计数。 */
void Monitor::accumulate_retired_counts_locked(thread_state& state)
{
    for (int counter = 0; counter < _num_counters; counter++) {
        if (counter >= (int)state.counter_fds.size() || state.counter_fds[counter] < 0)
            continue;
        read_format count = read_fd(state.counter_fds[counter]);
        _retired_values[counter] += count.value;
        _retired_time_enabled[counter] += count.time_enabled;
        _retired_time_running[counter] += count.time_running;
    }

    for (const auto& slot : state.samplers) {
        if (slot.fd < 0)
            continue;
        read_format count = read_fd(slot.fd);
        int index = _num_counters + slot.sampler_index;
        _retired_values[index] += count.value;
        _retired_time_enabled[index] += count.time_enabled;
        _retired_time_running[index] += count.time_running;
    }

}

/** @brief 关闭并回收一个线程上的所有 perf fd 与映射。 */
void Monitor::close_thread_locked(thread_state& state)
{
    for (auto& slot : state.samplers) {
        _sampler_slots.erase(slot.slot_id);
        if (_epoll_fd != -1 && slot.fd >= 0)
            epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, slot.fd, nullptr);
        if (slot.auxbuf && slot.auxbuf_bytes)
            munmap(slot.auxbuf, slot.auxbuf_bytes);
        if (slot.ringbuf && slot.ringbuf_bytes)
            munmap(slot.ringbuf, slot.ringbuf_bytes);
        if (slot.fd >= 0)
            close(slot.fd);
        slot.fd = -1;
        slot.auxbuf = nullptr;
        slot.ringbuf = nullptr;
    }
    state.samplers.clear();

    for (int fd : state.counter_fds) {
        if (fd >= 0)
            close(fd);
    }
    state.counter_fds.clear();
    state.active = false;
}

/** @brief 在持锁状态下注销一个线程，并先 drain 再关闭。 */
void Monitor::unregister_thread_locked(int tid)
{
    thread_state *state = find_thread_locked(tid);
    if (!state || !state->active)
        return;

    if (_events_enabled)
        disable_thread_locked(*state);

    for (auto& slot : state->samplers)
        process_samples_locked(slot);

    accumulate_retired_counts_locked(*state);
    close_thread_locked(*state);
}

/** @brief 注册当前线程，并在需要时立即 enable。 */
void Monitor::register_current_thread()
{
    if (_num_counters == 0 && _num_samplers == 0)
        return;

    int tid = gettid();
    std::lock_guard<std::mutex> lock(_state_mutex);
    thread_state& state = register_thread_locked(tid);
    if (_events_enabled)
        enable_thread_locked(state);
}

/** @brief 注销当前线程。 */
void Monitor::unregister_current_thread()
{
    if (_num_counters == 0 && _num_samplers == 0)
        return;

    int tid = gettid();
    std::lock_guard<std::mutex> lock(_state_mutex);
    unregister_thread_locked(tid);
}

/**
 * @brief 后台 sampler 线程。
 *
 * 它负责等待 epoll 事件，并在收到 eventfd 指令时执行全量 drain。
 */
void Monitor::run_sampler_thread()
{
    int64_t tid = gettid();
    if (write(_event_fd, &tid, sizeof(tid)) != (ssize_t)sizeof(tid))
        throw RdException("eventfd write failed");

    uint64_t efd_cmd = 0;
    const size_t MAX_EVENTS = 1024;
    epoll_event events[MAX_EVENTS];

    for (;;) {
        for (;;) {
            int n = epoll_wait(_epoll_fd, events, MAX_EVENTS, -1);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                throw RdException("epoll_wait");
            }

            for (int i = 0; i < n; i++) {
                uint64_t token = events[i].data.u64;
                if (token == EVENTFD_TOKEN) {
                    if (sizeof(efd_cmd) != read(_event_fd, &efd_cmd, sizeof(efd_cmd)))
                        throw RdException("eventfd read");
                    goto drain;
                }
                uint32_t kind = (uint32_t)(token >> 32);
                uint32_t value = (uint32_t)(token & 0xffffffffU);
                if (kind == SAMPLER_TOKEN_KIND)
                    process_samples((int)value);
            }
        }

drain:
        size_t extra_samples = 0;
        {
            std::lock_guard<std::mutex> lock(_state_mutex);
            for (auto& kv : _threads) {
                if (!kv.second.active)
                    continue;
                for (auto& slot : kv.second.samplers)
                    extra_samples += process_samples_locked(slot);
            }
        }

        if (efd_cmd == SAMPLER_STOP && extra_samples && !_nonstop_mode)
            std::cerr << "Found extra samples in buffer while stopping, forgot to call rd_stop()?" << std::endl;
        if (efd_cmd != SAMPLER_STOP || extra_samples)
            sem_post(&_sampler_drain);
        if (efd_cmd == SAMPLER_STOP)
            break;
    }
}

/** @brief 通过 slot ID 路由到真正的 sampler slot 处理函数。 */
size_t Monitor::process_samples(int slot_id)
{
    std::lock_guard<std::mutex> lock(_state_mutex);
    auto it = _sampler_slots.find(slot_id);
    if (it == _sampler_slots.end() || !it->second)
        return 0;
    return process_samples_locked(*it->second);
}

/**
 * @brief drain 一个 sampler slot 上的 ring/AUX 数据。
 *
 * 普通 `PERF_RECORD_SAMPLE` 直接写出 `time,addr`；
 * ARM SPE `PERF_RECORD_AUX` 则逐 packet 解码，并在 time/end packet 处
 * 写出当前 sampled instruction 的 `pc + data_va + latency + event_bits + flags`。
 */
size_t Monitor::process_samples_locked(sampler_slot& slot)
{
    perf_event_mmap_page *buf_header = (perf_event_mmap_page *)slot.ringbuf;
    uint64_t data_head = buf_header->data_head;
    uint64_t data_tail = buf_header->data_tail;
    uint64_t aux_offset = buf_header->aux_offset;
    uint64_t aux_size = buf_header->aux_size;

    if (_kinfos.empty()) {
        __sync_synchronize();
        buf_header->data_tail = data_head;
        return 0;
    }

    __sync_synchronize();
    if (data_head == data_tail)
        return 0;

    thread_state *state = find_thread_locked(slot.tid);
    if (!state || slot.sampler_index >= (int)state->writers.size())
        throw RdException("writer missing for sampler slot");
    BinaryWriter& writer = state->writers[slot.sampler_index];

    size_t num_samples = 0;
    while (data_tail < data_head) {
        char *data_start = (char *)slot.ringbuf + buf_header->data_offset;
        size_t data_size = buf_header->data_size;
        perf_event_header *header = (perf_event_header *)(data_start + (data_tail % data_size));

        switch (header->type) {
        case PERF_RECORD_SAMPLE:
        {
            struct {
                uint64_t time;
                uint64_t addr;
            } sample;

            size_t base = data_tail + sizeof(perf_event_header);
            sample.time = *(uint64_t *)(data_start + ((base + 2 * sizeof(uint32_t)) % data_size));
            sample.addr = *(uint64_t *)(data_start +
                ((base + 2 * sizeof(uint32_t) + sizeof(uint64_t)) % data_size));
            writer.write((char *)&sample, sizeof(sample));
            _written_sample_bytes += sizeof(sample);
            num_samples++;
            break;
        }

        case PERF_RECORD_THROTTLE:
            _kinfos.back().sample_throttles += 1;
            break;

        case PERF_RECORD_UNTHROTTLE:
            break;

        case PERF_RECORD_ITRACE_START:
            break;

        case PERF_RECORD_AUX:
        {
            struct sample_id {
                uint32_t pid;
                uint32_t tid;
                uint64_t time;
                uint32_t cpu;
                uint32_t res;
                uint64_t id;
            };

            struct {
                uint64_t aux_offset;
                uint64_t aux_size;
                uint64_t flags;
                struct sample_id sample_id;
            } aux;

            aux.aux_offset = *(uint64_t *)(data_start + ((data_tail + sizeof(perf_event_header)) % data_size));
            aux.aux_size = *(uint64_t *)(data_start +
                ((data_tail + sizeof(perf_event_header) + sizeof(aux.aux_offset)) % data_size));
            aux.flags = *(uint64_t *)(data_start +
                ((data_tail + sizeof(perf_event_header) + sizeof(aux.aux_offset) + sizeof(aux.aux_size)) % data_size));
            aux.sample_id = *(sample_id *)(data_start +
                ((data_tail + sizeof(perf_event_header) + sizeof(aux.aux_offset) +
                  sizeof(aux.aux_size) + sizeof(aux.flags)) % data_size));

            if (aux.flags & PERF_AUX_FLAG_COLLISION)
                _kinfos.back().sample_throttles += 1;

            if (aux.flags != PERF_AUX_FLAG_TRUNCATED) {
                uint64_t it = 0;
                while (it < aux.aux_size) {
                    char *aux_base = (char *)((uintptr_t)slot.ringbuf + aux_offset);
                    char *spe_packet = aux_base + ((aux.aux_offset + it) % aux_size);
                    uint8_t spe_header = *(uint8_t *)spe_packet;
                    int spe_packet_payload_size = 0;
                    int spe_packet_header_size = 1;
                    bool handled_packet = false;

                    if (is_arm_spe_address_packet(spe_header)) {
                        int addr_index = arm_spe_short_index(spe_header);
                        uint64_t raw_addr = read_spe_payload(spe_packet, 8);
                        uint64_t decoded_addr = decode_arm_spe_address_payload(addr_index, raw_addr);

                        if (addr_index == SPE_ADDR_PKT_HDR_INDEX_INS) {
                            slot.pending_pc = decoded_addr;
                            slot.pending_flags |= SPE_SAMPLE_FLAG_PC_VALID;
                        } else if (addr_index == SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT) {
                            slot.pending_data_va = decoded_addr;
                            slot.pending_flags |= SPE_SAMPLE_FLAG_DATA_VA_VALID;
                        }

                        spe_packet_payload_size = 8;
                        handled_packet = true;
                    } else if (is_arm_spe_counter_packet(spe_header)) {
                        int counter_index = arm_spe_short_index(spe_header);
                        spe_packet_payload_size = arm_spe_payload_size(spe_header);
                        uint64_t value = read_spe_payload(spe_packet, spe_packet_payload_size);

                        if (counter_index == SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT) {
                            slot.pending_lat_total = value;
                            slot.pending_flags |= SPE_SAMPLE_FLAG_LAT_TOTAL_VALID;
                        } else if (counter_index == SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT) {
                            slot.pending_lat_issue = value;
                            slot.pending_flags |= SPE_SAMPLE_FLAG_LAT_ISSUE_VALID;
                        } else if (counter_index == SPE_CNT_PKT_HDR_INDEX_TRANS_LAT) {
                            slot.pending_lat_xlat = value;
                            slot.pending_flags |= SPE_SAMPLE_FLAG_LAT_XLAT_VALID;
                        }
                        handled_packet = true;
                    } else if (is_arm_spe_events_packet(spe_header)) {
                        spe_packet_payload_size = arm_spe_payload_size(spe_header);
                        slot.pending_event_bits = read_spe_payload(spe_packet, spe_packet_payload_size);
                        slot.pending_flags |= SPE_SAMPLE_FLAG_EVENTS_VALID;
                        handled_packet = true;
                    }

                    if (!handled_packet) {
                        switch (spe_header) {
                        case SPE_PACKET_PADDING_HEADER:
                            spe_packet_payload_size = 0;
                            break;
                        case SPE_PACKET_END_HEADER:
                            flush_pending_spe_sample_locked(slot, writer, num_samples, true);
                            spe_packet_payload_size = 0;
                            break;
                        case SPE_PACKET_TS_HEADER:
                            flush_pending_spe_sample_locked(slot, writer, num_samples, false);
                            spe_packet_payload_size = 8;
                            break;
                        default:
                            _spe_unknown_packet_count += 1;
                            switch (spe_header & 0b110000) {
                            case 0b000000:
                                spe_packet_payload_size = 1;
                                break;
                            case 0b010000:
                                spe_packet_payload_size = 2;
                                break;
                            case 0b100000:
                                spe_packet_payload_size = 4;
                                break;
                            case 0b110000:
                                spe_packet_payload_size = 8;
                                break;
                            }
                            break;
                        }
                    }

                    it += spe_packet_header_size + spe_packet_payload_size;
                }

                buf_header->aux_tail += aux.aux_size;
            }
            break;
        }

        default:
            std::cerr << "unknown record type " << header->type << std::endl;
            break;
        }

        data_tail += header->size;
    }

    if (data_head != data_tail)
        throw RdException("corrupted samples mapping");

    __sync_synchronize();
    buf_header->data_tail = data_tail;
    _kinfos.back().num_samples += num_samples;
    return num_samples;
}

/** @brief 对所有活跃 fd 批量执行指定 ioctl。 */
void Monitor::fds_ioctl(int request)
{
    std::lock_guard<std::mutex> lock(_state_mutex);
    for (auto& kv : _threads) {
        if (!kv.second.active)
            continue;
        for (int fd : kv.second.counter_fds) {
            if (fd >= 0)
                ioctl(fd, request, 0);
        }
        for (auto& slot : kv.second.samplers) {
            if (slot.fd >= 0)
                ioctl(slot.fd, request, 0);
        }
    }
}

/** @brief 对所有 perf fd 执行 reset。 */
void Monitor::reset()
{
    fds_ioctl(PERF_EVENT_IOC_RESET);
}

/** @brief 打开一个新的采样窗口并在必要时启用所有事件。 */
void Monitor::start(const char *tag, bool offloaded)
{
    _kinfos.push_back({});

    if (tag) {
        if (strpbrk(tag, "=\n")) {
            char s[128];
            snprintf(s, sizeof(s), "Invalid tag '%s'", tag);
            throw RdException(s);
        }
        _kinfos.back().tag.assign(tag);
    } else {
        _kinfos.back().tag.assign("?");
    }

    _kinfos.back().offloaded = offloaded;

    if (!_nonstop_mode && _epoll_fd != -1)
        sem_wait(&_sampler_drain);

    snapshot_main_binary_path();
    if (sample_pc_present())
        snapshot_module_maps();

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &_start_time) < 0)
        throw RdException("failed clock_gettime");

    if (!_events_enabled) {
        std::lock_guard<std::mutex> lock(_state_mutex);
        for (auto& kv : _threads) {
            if (kv.second.active)
                enable_thread_locked(kv.second);
        }
        _events_enabled = true;
    }
}

/** @brief 关闭当前采样窗口、触发 drain 并汇总统计。 */
void Monitor::stop()
{
    if (!_nonstop_mode && _events_enabled) {
        std::lock_guard<std::mutex> lock(_state_mutex);
        for (auto& kv : _threads) {
            if (kv.second.active)
                disable_thread_locked(kv.second);
        }
        _events_enabled = false;
    }

    timespec stop_time = {};
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &stop_time) < 0)
        throw RdException("failed clock_gettime");

    if (!_nonstop_mode && _event_fd != -1) {
        uint64_t val = SAMPLER_DRAIN;
        if (write(_event_fd, &val, sizeof(val)) != (ssize_t)sizeof(val))
            throw RdException("eventfd write failed");
    }

    kinfo& ki = _kinfos.back();
    ki.duration = (stop_time.tv_sec - _start_time.tv_sec) +
        1e-9 * (stop_time.tv_nsec - _start_time.tv_nsec);
    ki.clock_start = _start_time.tv_sec * _clock_res +
        _start_time.tv_nsec * _clock_res / 1000000000ULL;
    ki.clock_stop = stop_time.tv_sec * _clock_res +
        stop_time.tv_nsec * _clock_res / 1000000000ULL;
    ki.counters = new counter_data[_num_counters + _num_samplers];
    read_counters(ki.counters, true);
}

/** @brief 读取所有活跃线程的计数，并与退役线程累计值合并。 */
void Monitor::read_counters(counter_data *counters, bool include_samplers)
{
    std::lock_guard<std::mutex> lock(_state_mutex);

    for (int counter = 0; counter < _num_counters; counter++) {
        uint64_t enabled = _retired_time_enabled[counter];
        uint64_t running = _retired_time_running[counter];
        uint64_t value = _retired_values[counter];

        for (const auto& kv : _threads) {
            if (!kv.second.active || counter >= (int)kv.second.counter_fds.size())
                continue;
            read_format count = read_fd(kv.second.counter_fds[counter]);
            value += count.value;
            enabled += count.time_enabled;
            running += count.time_running;
        }

        counters[counter].value = value - _prev_counters[counter];
        _prev_counters[counter] = value;
        counters[counter].active_time = enabled ? (running / (double)enabled) : 0.0;
    }

    if (!include_samplers)
        return;

    for (int sampler = 0; sampler < _num_samplers; sampler++) {
        int off = _num_counters + sampler;
        uint64_t enabled = _retired_time_enabled[off];
        uint64_t running = _retired_time_running[off];
        uint64_t value = _retired_values[off];

        for (const auto& kv : _threads) {
            if (!kv.second.active || sampler >= (int)kv.second.samplers.size())
                continue;
            read_format count = read_fd(kv.second.samplers[sampler].fd);
            value += count.value;
            enabled += count.time_enabled;
            running += count.time_running;
        }

        counters[off].value = value - _prev_counters[off];
        _prev_counters[off] = value;
        counters[off].active_time = enabled ? (running / (double)enabled) : 0.0;
    }
}

/** @brief 主动向后台线程发送一次 drain 请求。 */
void Monitor::read_samples()
{
    if (_event_fd == -1)
        return;
    uint64_t val = SAMPLER_DRAIN;
    if (write(_event_fd, &val, sizeof(val)) != (ssize_t)sizeof(val))
        throw RdException("eventfd write failed");
}

/** @brief 记录一段用户关心的地址区间。 */
void Monitor::tag_addr(const char *tag, void *start, void *end)
{
    _addr_tags.push_back({tag, start, end});
}

/** @brief 打开一个二进制输出文件。 */
BinaryWriter::BinaryWriter(const char *path)
    : _ofs(path, std::ios::binary | std::ios::trunc)
{
}

/** @brief 顺序写入一段原始二进制记录。 */
void BinaryWriter::write(char *a, size_t n)
{
    _ofs.write(a, n);
}
