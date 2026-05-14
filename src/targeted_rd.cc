#include "targeted_rd.hh"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <asm/perf_regs.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "rd_exception.hh"
#include "threads.hh"

/**
 * @file targeted_rd.cc
 * @brief 实现二阶段 `targeted_rd` 的用户态控制面。
 */

namespace {

constexpr uint32_t DEFAULT_WP_CAPACITY = 4;
constexpr uint64_t DEFAULT_BP_SAMPLE_PERIOD = 1024;
constexpr uint32_t DEFAULT_DWARF_STACK_BYTES = 8192;
constexpr uint32_t DEFAULT_DWARF_EVENT_CAPACITY = 16384;

/** @brief 兼容方式获取当前线程 ID。 */
static int gettid_portable()
{
    return (int)syscall(SYS_gettid);
}

/** @brief 去除字符串首尾 ASCII 空白字符。 */
static std::string trim_ascii_space(const std::string& s)
{
    size_t left = 0;
    while (left < s.size() && isspace((unsigned char)s[left]))
        left++;
    size_t right = s.size();
    while (right > left && isspace((unsigned char)s[right - 1]))
        right--;
    return s.substr(left, right - left);
}

/** @brief 按制表符拆分一行文本。 */
static std::vector<std::string> split_tab(const std::string& line)
{
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(line);
    while (std::getline(iss, cur, '\t'))
        out.push_back(cur);
    return out;
}

/** @brief 按逗号拆分一行文本，并对每一项做 trim。 */
static std::vector<std::string> split_comma(const std::string& line)
{
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(line);
    while (std::getline(iss, cur, ','))
        out.push_back(trim_ascii_space(cur));
    return out;
}

/** @brief 归一化绝对路径，优先解析符号链接。 */
static std::string normalize_filesystem_path(const std::string& path)
{
    if (path.empty() || path[0] != '/')
        return path;

    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved))
        return resolved;
    return path;
}

/** @brief 读取当前进程 `/proc/self/exe` 路径。 */
static std::string read_self_exe_path()
{
    char path_buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path_buf, sizeof(path_buf) - 1);
    if (len <= 0)
        return "";
    path_buf[len] = '\0';
    return normalize_filesystem_path(path_buf);
}

/** @brief 对 shell 参数做单引号转义。 */
static std::string shell_quote(const std::string& s)
{
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    out += "'";
    return out;
}

/** @brief 执行一条命令并抓取其标准输出。 */
static std::string run_command_capture(const std::string& cmd)
{
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp)
        throw RdException("popen failed");

    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp))
        out += buf;

    int status = pclose(fp);
    if (status != 0)
        return "";
    return out;
}

/** @brief 把整数格式化为十六进制字符串。 */
static std::string hex_u64(uint64_t value)
{
    std::ostringstream oss;
    oss << std::hex << value;
    return oss.str();
}

/**
 * @brief 判断一条热点是否应按“当前后端暂不支持”进行过滤。
 *
 * 这里仅过滤能力边界类错误；对 manifest 损坏、反汇编失败、PC 重定位失败
 * 这类基础设施问题仍保持 fail-fast。
 */
static bool is_filterable_hotspot_error(const std::string& reason)
{
    static const std::array<const char *, 5> kPrefixes = {
        "unsupported ",
        "watchpoint only supports accesses up to 8 bytes",
        "missing ",
        "expected ",
        "empty address operand",
    };

    for (const char *prefix : kPrefixes) {
        if (reason.rfind(prefix, 0) == 0)
            return true;
    }
    return false;
}

/** @brief 把指定线程绑到指定 CPU。 */
static void pin_tid_to_cpu(int tid, int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(tid, sizeof(set), &set) < 0)
        throw RdException("sched_setaffinity failed");
}

/** @brief 从 `/proc/self/task/<tid>/stat` 解析线程最近运行 CPU。 */
static int parse_cpu_from_tid_stat(int tid)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
    std::ifstream ifs(path);
    if (!ifs.is_open())
        return -1;

    std::string line;
    std::getline(ifs, line);
    size_t l = line.find('(');
    size_t r = line.rfind(')');
    if (l == std::string::npos || r == std::string::npos || r <= l)
        return -1;

    std::string tail = line.substr(r + 1);
    std::istringstream iss(tail);
    std::string tok;
    int idx = 0;
    while (iss >> tok) {
        if (idx == 36)
            return atoi(tok.c_str());
        idx++;
    }
    return -1;
}

/** @brief 解析形如 `#123` 的立即数字面量。 */
static int parse_scaled_imm(const std::string& token)
{
    if (token.empty())
        throw RdException("missing immediate");
    if (token[0] != '#')
        throw RdException("expected immediate");
    return (int)strtoll(token.c_str() + 1, nullptr, 0);
}

/**
 * @brief 解析 AArch64 通用寄存器名字。
 *
 * 该函数输出 perf regs 视角下的寄存器编号及若干辅助语义标记。
 */
static bool parse_reg_name(const std::string& token, int& reg, bool& is_sp, bool& is_32, bool& is_zero)
{
    std::string t = trim_ascii_space(token);
    reg = -1;
    is_sp = false;
    is_32 = false;
    is_zero = false;

    if (t == "sp") {
        reg = PERF_REG_ARM64_SP;
        is_sp = true;
        return true;
    }
    if (t == "xzr" || t == "wzr") {
        reg = -1;
        is_zero = true;
        is_32 = (t[0] == 'w');
        return true;
    }
    if (t.size() >= 2 && (t[0] == 'x' || t[0] == 'w')) {
        char *end = nullptr;
        long n = strtol(t.c_str() + 1, &end, 10);
        if (end && *end == '\0' && n >= 0 && n <= 29) {
            reg = (int)n;
            is_32 = (t[0] == 'w');
            return true;
        }
        if (t == "x30") {
            reg = PERF_REG_ARM64_LR;
            return true;
        }
    }
    return false;
}

/** @brief 根据目标寄存器类别推断访存宽度。 */
static int parse_access_size_from_dest(const std::string& dest)
{
    std::string t = trim_ascii_space(dest);
    if (t.empty())
        throw RdException("missing destination operand");
    switch (t[0]) {
    case 'b': return 1;
    case 'h': return 2;
    case 'w':
    case 's': return 4;
    case 'x':
    case 'd': return 8;
    case 'q': return 16;
    default: break;
    }
    throw RdException("unsupported destination register class in operand '" + t + "'");
}

/**
 * @brief 从一条反汇编出的访存指令操作数构造 EA 解码模板。
 */
static TargetedRdProfiler::decode_template decode_from_asm_operands(const std::string& mnemonic,
    const std::string& operands)
{
    TargetedRdProfiler::decode_template dec = {};
    dec.base_reg = -1;
    dec.base_is_sp = false;
    dec.has_imm = false;
    dec.imm = 0;
    dec.has_index = false;
    dec.index_reg = -1;
    dec.index_is_32 = false;
    dec.index_is_zero = false;
    dec.extend = TargetedRdProfiler::decode_template::EXT_NONE;
    dec.shift = 0;

    size_t comma = operands.find(',');
    if (comma == std::string::npos)
        throw RdException("unsupported operand shape '" + operands + "'");
    std::string dest = trim_ascii_space(operands.substr(0, comma));
    dec.access_size = parse_access_size_from_dest(dest);
    if (dec.access_size > 8)
        throw RdException("watchpoint only supports accesses up to 8 bytes");

    size_t lb = operands.find('[', comma);
    size_t rb = operands.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb)
        throw RdException("unsupported address operand '" + operands + "'");

    std::vector<std::string> items = split_comma(operands.substr(lb + 1, rb - lb - 1));
    if (items.empty())
        throw RdException("empty address operand");

    bool ignored_32 = false;
    bool ignored_zero = false;
    if (!parse_reg_name(items[0], dec.base_reg, dec.base_is_sp, ignored_32, ignored_zero) || ignored_zero)
        throw RdException("unsupported base register '" + items[0] + "'");

    if (items.size() == 1)
        return dec;

    if (!items[1].empty() && items[1][0] == '#') {
        dec.has_imm = true;
        dec.imm = parse_scaled_imm(items[1]);
        return dec;
    }

    dec.has_index = true;
    if (!parse_reg_name(items[1], dec.index_reg, ignored_32, dec.index_is_32, dec.index_is_zero))
        throw RdException("unsupported index register '" + items[1] + "'");

    if (items.size() == 2) {
        dec.extend = TargetedRdProfiler::decode_template::EXT_NONE;
        return dec;
    }

    std::string ext = trim_ascii_space(items[2]);
    size_t space = ext.find(' ');
    std::string op = space == std::string::npos ? ext : ext.substr(0, space);
    std::string arg = space == std::string::npos ? "" : trim_ascii_space(ext.substr(space + 1));

    if (op == "lsl") {
        dec.extend = TargetedRdProfiler::decode_template::EXT_LSL;
    } else if (op == "uxtw") {
        dec.extend = TargetedRdProfiler::decode_template::EXT_UXTW;
    } else if (op == "sxtw") {
        dec.extend = TargetedRdProfiler::decode_template::EXT_SXTW;
    } else if (op == "uxtx") {
        dec.extend = TargetedRdProfiler::decode_template::EXT_UXTX;
    } else if (op == "sxtx") {
        dec.extend = TargetedRdProfiler::decode_template::EXT_SXTX;
    } else {
        throw RdException("unsupported index extend '" + op + "'");
    }

    if (!arg.empty()) {
        if (arg[0] != '#')
            throw RdException("unsupported shift argument '" + arg + "'");
        dec.shift = (uint8_t)strtoul(arg.c_str() + 1, nullptr, 0);
    }
    return dec;
}

/**
 * @brief 通过 `objdump`/`llvm-objdump` 反汇编一个热点 offset，并解析其访存模板。
 */
static TargetedRdProfiler::hot_target decode_target_via_objdump(const std::string& binary_path, uint64_t pc_offset,
    uint64_t aggregated_samples)
{
    std::array<std::string, 2> tools = {"objdump", "llvm-objdump"};
    std::string output;
    for (const auto& tool : tools) {
        std::ostringstream cmd;
        cmd << tool << " -d --start-address=0x" << std::hex << pc_offset
            << " --stop-address=0x" << (pc_offset + 4) << " "
            << shell_quote(binary_path) << " 2>/dev/null";
        output = run_command_capture(cmd.str());
        if (!output.empty())
            break;
    }
    if (output.empty())
        throw RdException("cannot disassemble hotspot PC offset 0x" + hex_u64(pc_offset));

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        std::string t = trim_ascii_space(line);
        size_t colon = t.find(':');
        if (colon == std::string::npos)
            continue;
        uint64_t addr = strtoull(t.substr(0, colon).c_str(), nullptr, 16);
        if (addr != pc_offset)
            continue;

        std::string rest = trim_ascii_space(t.substr(colon + 1));
        std::istringstream ls(rest);
        std::string bytes;
        std::string mnemonic;
        if (!(ls >> bytes >> mnemonic))
            continue;
        std::string operands;
        std::getline(ls, operands);
        operands = trim_ascii_space(operands);
        if (mnemonic != "ldr" && mnemonic != "str" && mnemonic != "ldur" && mnemonic != "stur")
            throw RdException("unsupported hotspot instruction '" + mnemonic + "' at 0x" + hex_u64(pc_offset));

        TargetedRdProfiler::hot_target target = {};
        target.pc_offset = pc_offset;
        target.abs_pc = 0;
        target.aggregated_samples = aggregated_samples;
        target.path = binary_path;
        target.mnemonic = mnemonic;
        target.operands = operands;
        target.decode = decode_from_asm_operands(mnemonic, operands);
        return target;
    }

    throw RdException("cannot find disassembly for hotspot PC offset 0x" + hex_u64(pc_offset));
}

/**
 * @brief 结合当前运行实例的 `/proc/self/maps`，把文件内 offset 还原为绝对 PC。
 */
static uint64_t resolve_absolute_pc(const std::string& binary_path, uint64_t pc_offset)
{
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open())
        throw RdException("cannot open /proc/self/maps");

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
        path = normalize_filesystem_path(trim_ascii_space(path));
        if (path != binary_path)
            continue;

        char *dash = nullptr;
        uint64_t vm_start = strtoull(range.c_str(), &dash, 16);
        if (!dash || *dash != '-')
            continue;
        uint64_t vm_end = strtoull(dash + 1, nullptr, 16);
        uint64_t file_offset = strtoull(offset_hex.c_str(), nullptr, 16);
        uint64_t span = vm_end - vm_start;
        if (pc_offset < file_offset || pc_offset >= file_offset + span)
            continue;
        return vm_start + (pc_offset - file_offset);
    }

    throw RdException("cannot resolve current absolute PC for hotspot offset 0x" + hex_u64(pc_offset));
}

/** @brief 把用户态模板转换为 ioctl/UAPI 结构。 */
static rd_wpctl_decode to_uapi_decode(const TargetedRdProfiler::decode_template& dec)
{
    rd_wpctl_decode out = {};
    out.access_size = (uint32_t)dec.access_size;
    out.base_reg = dec.base_reg;
    out.base_is_sp = dec.base_is_sp ? 1 : 0;
    out.has_imm = dec.has_imm ? 1 : 0;
    out.has_index = dec.has_index ? 1 : 0;
    out.index_is_32 = dec.index_is_32 ? 1 : 0;
    out.index_is_zero = dec.index_is_zero ? 1 : 0;
    out.extend = (uint8_t)dec.extend;
    out.shift = dec.shift;
    out.index_reg = dec.index_reg;
    out.imm = dec.imm;
    return out;
}

/** @brief 返回 log2 直方图桶的下界。 */
static uint64_t bucket_lo(uint32_t bucket)
{
    if (bucket == 0)
        return 0;
    if (bucket == 1)
        return 1;
    return (1ULL << (bucket - 1));
}

/** @brief 返回 log2 直方图桶的上界。 */
static uint64_t bucket_hi(uint32_t bucket)
{
    if (bucket == 0)
        return 0;
    if (bucket == 1)
        return 1;
    if (bucket >= 63)
        return UINT64_MAX;
    return (1ULL << bucket) - 1ULL;
}

/** @brief 把调用上下文模式转成元数据字符串。 */
static const char *callchain_mode_name(uint32_t mode)
{
    switch (mode) {
    case RD_CALLCHAIN_OFF: return "off";
    case RD_CALLCHAIN_FP: return "fp";
    case RD_CALLCHAIN_DWARF: return "dwarf";
    default: return "unknown";
    }
}

} // namespace

/**
 * @brief 构造 targeted RD 控制器并完成模块侧初始化。
 */
TargetedRdProfiler::TargetedRdProfiler(const char *profile_name, bool is_pin)
    : _running(true)
    , _window_open(false)
    , _auto_fallback_active(false)
    , _explicit_window_seen(false)
    , _auto_window_discarded_on_first_explicit(false)
    , _is_pin(is_pin)
    , _num_cpus(get_nprocs())
    , _device_fd(-1)
    , _watchpoint_capacity(DEFAULT_WP_CAPACITY)
    , _bp_sample_period(DEFAULT_BP_SAMPLE_PERIOD)
    , _callchain_mode(RD_CALLCHAIN_OFF)
    , _dwarf_stack_bytes(DEFAULT_DWARF_STACK_BYTES)
    , _dwarf_event_capacity(DEFAULT_DWARF_EVENT_CAPACITY)
    , _nameprefix(profile_name ? profile_name : "rd")
    , _rd_event_name("mem_access")
    , _instruction_support("aarch64 objdump-parsed ldr/str/ldur/stur with [base], [base,#imm], [base,index{,extend #shift}]")
{
    const char *target_file = getenv("RD_TARGET_FILE");
    if (!target_file || !*target_file)
        throw RdException("RD_TARGET_FILE is required for RD_MODE=targeted_rd");
    _target_file = target_file;

    const char *env_wp = getenv("RD_WP_CAPACITY");
    if (env_wp && *env_wp) {
        long v = strtol(env_wp, nullptr, 10);
        if (v <= 0)
            throw RdException("RD_WP_CAPACITY must be positive");
        _watchpoint_capacity = (uint32_t)v;
    }

    const char *env_bp_sample_period = getenv("RD_BP_SAMPLE_PERIOD");
    if (env_bp_sample_period && *env_bp_sample_period) {
        long long v = strtoll(env_bp_sample_period, nullptr, 10);
        if (v <= 0)
            throw RdException("RD_BP_SAMPLE_PERIOD must be positive");
        _bp_sample_period = (uint64_t)v;
    }

    const char *env_event = getenv("RD_RD_EVENT");
    if (env_event && *env_event)
        _rd_event_name = env_event;
    if (_rd_event_name != "mem_access")
        throw RdException("kernel targeted_rd only supports RD_RD_EVENT=mem_access");

    const char *env_callchain = getenv("RD_CALLCHAIN_MODE");
    if (env_callchain && *env_callchain) {
        std::string mode = env_callchain;
        if (mode == "off")
            _callchain_mode = RD_CALLCHAIN_OFF;
        else if (mode == "fp")
            _callchain_mode = RD_CALLCHAIN_FP;
        else if (mode == "dwarf")
            _callchain_mode = RD_CALLCHAIN_DWARF;
        else
            throw RdException("RD_CALLCHAIN_MODE must be off, fp, or dwarf");
    }

    const char *env_dwarf_stack = getenv("RD_DWARF_STACK_BYTES");
    if (env_dwarf_stack && *env_dwarf_stack) {
        long v = strtol(env_dwarf_stack, nullptr, 10);
        if (v <= 0 || v > RD_WPCTL_MAX_DWARF_STACK_BYTES)
            throw RdException("RD_DWARF_STACK_BYTES must be in [1, " +
                              std::to_string(RD_WPCTL_MAX_DWARF_STACK_BYTES) + "]");
        _dwarf_stack_bytes = (uint32_t)v;
    }

    const char *env_dwarf_capacity = getenv("RD_DWARF_EVENT_CAPACITY");
    if (env_dwarf_capacity && *env_dwarf_capacity) {
        long v = strtol(env_dwarf_capacity, nullptr, 10);
        if (v <= 0)
            throw RdException("RD_DWARF_EVENT_CAPACITY must be positive");
        _dwarf_event_capacity = (uint32_t)v;
    }

    _main_binary_path = read_self_exe_path();
    if (_main_binary_path.empty())
        throw RdException("cannot resolve /proc/self/exe");

    _cpu_owner.assign(_num_cpus, 0);

    std::string info_path = _nameprefix + ".rd2.info";
    _info_file.open(info_path, std::ios::trunc);
    if (!_info_file.is_open())
        throw RdException("cannot open " + info_path);

    _device_fd = open(RD_WPCTL_DEVICE, O_RDWR | O_CLOEXEC);
    if (_device_fd < 0)
        throw RdException(std::string("cannot open ") + RD_WPCTL_DEVICE + ": " + strerror(errno));

    load_targets();
    configure_session();
    register_initial_threads();
    {
        std::lock_guard<std::mutex> lock(_state_mutex);
        start_window_locked();
        _auto_fallback_active = true;
    }
}

/** @brief 析构时关闭窗口、注销线程并写出结果文件。 */
TargetedRdProfiler::~TargetedRdProfiler()
{
    try {
        {
            std::lock_guard<std::mutex> lock(_state_mutex);
            if (_window_open)
                stop_window_locked();
            for (auto& kv : _threads) {
                if (kv.second.active)
                    unregister_thread_locked(kv.first);
            }
        }
        write_info();
    } catch (const std::exception& e) {
        std::cerr << "targeted_rd destructor warning: " << e.what() << std::endl;
    }
    if (_device_fd >= 0)
        close(_device_fd);
    if (_info_file.is_open())
        _info_file.close();
}

/** @brief 向内核模块下发 session 配置和热点目标表。 */
void TargetedRdProfiler::configure_session()
{
    rd_wpctl_session_cfg cfg = {};
    rd_wpctl_target_batch batch = {};
    std::vector<rd_wpctl_target> targets(_targets.size());

    cfg.wp_capacity = _watchpoint_capacity;
    cfg.callchain_mode = _callchain_mode;
    cfg.bp_sample_period = _bp_sample_period;
    cfg.dwarf_stack_bytes = _callchain_mode == RD_CALLCHAIN_DWARF ? _dwarf_stack_bytes : 0;
    cfg.dwarf_event_capacity = _callchain_mode == RD_CALLCHAIN_DWARF ? _dwarf_event_capacity : 0;
    if (ioctl(_device_fd, RDKIOC_CONFIG_SESSION, &cfg) < 0)
        throw RdException(std::string("RDKIOC_CONFIG_SESSION failed: ") + strerror(errno));

    for (size_t i = 0; i < _targets.size(); i++) {
        targets[i].pc_offset = _targets[i].pc_offset;
        targets[i].abs_pc = _targets[i].abs_pc;
        targets[i].aggregated_samples = _targets[i].aggregated_samples;
        targets[i].decode = to_uapi_decode(_targets[i].decode);
    }

    batch.targets_ptr = (uint64_t)(uintptr_t)targets.data();
    batch.count = (uint32_t)targets.size();
    if (ioctl(_device_fd, RDKIOC_LOAD_TARGETS, &batch) < 0)
        throw RdException(std::string("RDKIOC_LOAD_TARGETS failed: ") + strerror(errno));
}

/** @brief 在持锁状态下打开模块侧监控窗口。 */
void TargetedRdProfiler::start_window_locked()
{
    if (_window_open)
        return;
    if (ioctl(_device_fd, RDKIOC_START_WINDOW) < 0)
        throw RdException(std::string("RDKIOC_START_WINDOW failed: ") + strerror(errno));
    _window_open = true;
}

/** @brief 在持锁状态下关闭模块侧监控窗口。 */
void TargetedRdProfiler::stop_window_locked()
{
    if (!_window_open)
        return;
    if (ioctl(_device_fd, RDKIOC_STOP_WINDOW) < 0)
        throw RdException(std::string("RDKIOC_STOP_WINDOW failed: ") + strerror(errno));
    _window_open = false;
}

/** @brief 在持锁状态下重置模块会话中的采样状态。 */
void TargetedRdProfiler::reset_session_locked()
{
    if (_window_open)
        throw RdException("RDKIOC_RESET_SESSION requires closed window");
    if (ioctl(_device_fd, RDKIOC_RESET_SESSION) < 0)
        throw RdException(std::string("RDKIOC_RESET_SESSION failed: ") + strerror(errno));
}

/** @brief 打开模块侧监控窗口。 */
void TargetedRdProfiler::kernel_start(const char *tag)
{
    (void)tag;
    std::lock_guard<std::mutex> lock(_state_mutex);
    if (_auto_fallback_active && !_explicit_window_seen) {
        stop_window_locked();
        reset_session_locked();
        start_window_locked();
        _auto_fallback_active = false;
        _explicit_window_seen = true;
        _auto_window_discarded_on_first_explicit = true;
        return;
    }

    _explicit_window_seen = true;
    _auto_fallback_active = false;
    if (_window_open)
        return;
    start_window_locked();
}

/** @brief 关闭模块侧监控窗口。 */
void TargetedRdProfiler::kernel_stop()
{
    std::lock_guard<std::mutex> lock(_state_mutex);
    if (!_window_open)
        return;
    if (_auto_fallback_active && !_explicit_window_seen)
        return;
    stop_window_locked();
}

/**
 * @brief 解析 `.hotpc` 并构造当前运行的热点目标表。
 *
 * 该函数会完成：
 * - 主二进制一致性校验
 * - 样本数聚合与排序
 * - 指令反汇编与 EA 模板解析
 * - 绝对 PC 重定位
 */
void TargetedRdProfiler::load_targets()
{
    std::ifstream in(_target_file);
    if (!in.is_open())
        throw RdException("cannot open hotspot manifest " + _target_file);

    std::string manifest_main_binary;
    std::unordered_map<uint64_t, uint64_t> aggregated;

    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("hotspot_main_binary=", 0) == 0) {
            manifest_main_binary = normalize_filesystem_path(line.substr(strlen("hotspot_main_binary=")));
            continue;
        }
        if (line.rfind("hotspot=", 0) != 0)
            continue;

        std::vector<std::string> fields = split_tab(line.substr(strlen("hotspot=")));
        if (fields.size() < 6)
            throw RdException("bad hotspot line in manifest");
        uint64_t sample_count = strtoull(fields[2].c_str(), nullptr, 10);
        uint64_t pc_offset = strtoull(fields[4].c_str(), nullptr, 0);
        std::string path = normalize_filesystem_path(fields[5]);
        if (!path.empty() && path != _main_binary_path)
            throw RdException("targeted_rd only supports main binary hotspots; got " + path);
        aggregated[pc_offset] += sample_count;
    }

    if (!manifest_main_binary.empty() && manifest_main_binary != _main_binary_path)
        throw RdException("hotspot manifest main binary does not match current executable");

    if (aggregated.empty())
        throw RdException("no hotspots found in " + _target_file);

    std::vector<std::pair<uint64_t, uint64_t>> order(aggregated.begin(), aggregated.end());
    std::sort(order.begin(), order.end(),
        [](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b) {
            if (a.second != b.second)
                return a.second > b.second;
            return a.first < b.first;
        });

    _targets.clear();
    _rejected_targets.clear();
    _targets.reserve(order.size());
    _rejected_targets.reserve(order.size());
    for (const auto& kv : order) {
        try {
            hot_target target = decode_target_via_objdump(_main_binary_path, kv.first, kv.second);
            target.abs_pc = resolve_absolute_pc(_main_binary_path, kv.first);
            _targets.push_back(target);
        } catch (const RdException& e) {
            if (!is_filterable_hotspot_error(e.what()))
                throw;

            rejected_target rejected = {};
            rejected.pc_offset = kv.first;
            rejected.aggregated_samples = kv.second;
            rejected.reason = e.what();
            _rejected_targets.push_back(std::move(rejected));
        }
    }

    if (_targets.empty()) {
        if (!_rejected_targets.empty())
            throw RdException("no supported hotspots remain after filtering unsupported targets from " + _target_file);
        throw RdException("no supported hotspots found in " + _target_file);
    }
}

/** @brief 注册构造时已存在的线程。 */
void TargetedRdProfiler::register_initial_threads()
{
    std::vector<int> tids = get_threads();
    std::lock_guard<std::mutex> lock(_state_mutex);
    for (int tid : tids)
        register_thread_locked(tid);
}

/** @brief 分配一个当前未占用 CPU。 */
int TargetedRdProfiler::allocate_cpu_locked()
{
    int start = 0;
    if (_is_pin) {
        start = parse_cpu_from_tid_stat(gettid_portable());
        if (start < 0 || start >= _num_cpus)
            start = 0;
    }

    for (int off = 0; off < _num_cpus; off++) {
        int cpu = (start + off) % _num_cpus;
        if (_cpu_owner[cpu] == 0) {
            _cpu_owner[cpu] = 1;
            return cpu;
        }
    }
    throw RdException("targeted_rd cannot pin thread: no free CPU available");
}

/** @brief 释放一个此前分配的 CPU。 */
void TargetedRdProfiler::release_cpu_locked(int cpu)
{
    if (cpu >= 0 && cpu < _num_cpus)
        _cpu_owner[cpu] = 0;
}

/**
 * @brief 注册一个线程并为其准备模块要求的 scratch 区域。
 */
TargetedRdProfiler::thread_binding& TargetedRdProfiler::register_thread_locked(int tid)
{
    auto it = _threads.find(tid);
    if (it != _threads.end() && it->second.active)
        return it->second;

    if (it != _threads.end() && !it->second.active)
        _threads.erase(it);

    thread_binding binding = {};
    binding.tid = tid;
    binding.cpu = allocate_cpu_locked();
    binding.active = false;

    try {
        pin_tid_to_cpu(tid, binding.cpu);

        long page_size = sysconf(_SC_PAGESIZE);
        binding.scratch_stride = (uint64_t)page_size;
        binding.scratch_bytes = (size_t)page_size * _watchpoint_capacity;
        binding.scratch = mmap(nullptr, binding.scratch_bytes, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (binding.scratch == MAP_FAILED)
            throw RdException("mmap scratch watchpoint region failed");
        binding.scratch_base = (uint64_t)(uintptr_t)binding.scratch;

        rd_wpctl_thread_register reg = {};
        reg.tid = tid;
        reg.cpu = binding.cpu;
        reg.scratch_base = binding.scratch_base;
        reg.scratch_stride = binding.scratch_stride;
        if (ioctl(_device_fd, RDKIOC_REGISTER_THREAD, &reg) < 0)
            throw RdException(std::string("RDKIOC_REGISTER_THREAD failed: ") + strerror(errno));
        binding.active = true;
    } catch (...) {
        if (binding.scratch && binding.scratch != MAP_FAILED)
            munmap(binding.scratch, binding.scratch_bytes);
        release_cpu_locked(binding.cpu);
        throw;
    }

    auto inserted = _threads.emplace(tid, binding);
    return inserted.first->second;
}

/** @brief 对当前线程执行注册。 */
void TargetedRdProfiler::register_current_thread()
{
    std::lock_guard<std::mutex> lock(_state_mutex);
    register_thread_locked(gettid_portable());
}

/** @brief 注销一个线程并回收其 scratch 区域与 CPU 绑定。 */
void TargetedRdProfiler::unregister_thread_locked(int tid)
{
    auto it = _threads.find(tid);
    if (it == _threads.end() || !it->second.active)
        return;

    rd_wpctl_thread_arg arg = {};
    arg.tid = tid;
    if (ioctl(_device_fd, RDKIOC_UNREGISTER_THREAD, &arg) < 0)
        throw RdException(std::string("RDKIOC_UNREGISTER_THREAD failed: ") + strerror(errno));

    if (it->second.scratch && it->second.scratch != MAP_FAILED)
        munmap(it->second.scratch, it->second.scratch_bytes);
    release_cpu_locked(it->second.cpu);
    it->second.active = false;
    it->second.scratch = nullptr;
    it->second.scratch_bytes = 0;
}

/** @brief 对当前线程执行注销。 */
void TargetedRdProfiler::unregister_current_thread()
{
    std::lock_guard<std::mutex> lock(_state_mutex);
    unregister_thread_locked(gettid_portable());
}

/**
 * @brief 为一个线程拉取所有 target 的 log2 直方图并落盘。
 */
void TargetedRdProfiler::write_thread_histograms(const rd_wpctl_thread_stats& stats, uint32_t thread_index)
{
    std::string log_path = _nameprefix + ".rd2.t" + std::to_string(stats.tid) + ".hist.log2.txt";
    std::ofstream log(log_path, std::ios::trunc);

    if (!log.is_open())
        throw RdException("cannot open " + log_path);

    log << "pc_offset\tbucket_lo\tbucket_hi\tcount" << std::endl;
    for (uint32_t target_index = 0; target_index < _targets.size(); target_index++) {
        rd_wpctl_hist_req req = {};

        req.thread_index = thread_index;
        req.target_index = target_index;
        if (ioctl(_device_fd, RDKIOC_GET_LOG2_HIST, &req) < 0)
            throw RdException(std::string("RDKIOC_GET_LOG2_HIST failed: ") + strerror(errno));

        for (uint32_t bucket = 0; bucket < RD_WPCTL_LOG2_BUCKETS; bucket++) {
            uint64_t count = req.buckets[bucket];
            if (!count)
                continue;
            log << "0x" << std::hex << _targets[target_index].pc_offset << std::dec << "\t"
                << bucket_lo(bucket) << "\t"
                << bucket_hi(bucket) << "\t"
                << count << std::endl;
        }
    }
}

/**
 * @brief 为一个线程拉取 use-reuse pair 的 log2 直方图并落盘。
 */
void TargetedRdProfiler::write_thread_pair_histograms(const rd_wpctl_thread_stats& stats, uint32_t thread_index)
{
    std::string log_path = _nameprefix + ".rd2.t" + std::to_string(stats.tid) + ".pair.hist.log2.txt";
    std::ofstream log(log_path, std::ios::trunc);

    if (!log.is_open())
        throw RdException("cannot open " + log_path);

    log << "seed_pc_offset\tseed_context_id\treuse_pc\treuse_context_id\tbucket_lo\tbucket_hi\tcount" << std::endl;
    for (uint32_t entry_index = 0; entry_index < RD_WPCTL_MAX_PAIR_HISTS; entry_index++) {
        rd_wpctl_pair_hist_req req = {};

        req.thread_index = thread_index;
        req.entry_index = entry_index;
        if (ioctl(_device_fd, RDKIOC_GET_PAIR_HIST_ENTRY, &req) < 0)
            throw RdException(std::string("RDKIOC_GET_PAIR_HIST_ENTRY failed: ") + strerror(errno));
        if (!req.used)
            continue;

        for (uint32_t bucket = 0; bucket < RD_WPCTL_LOG2_BUCKETS; bucket++) {
            uint64_t count = req.buckets[bucket];
            if (!count)
                continue;
            log << "0x" << std::hex << req.seed_pc_offset << std::dec << "\t"
                << req.seed_context_id << "\t"
                << "0x" << std::hex << req.reuse_pc << std::dec << "\t"
                << req.reuse_context_id << "\t"
                << bucket_lo(bucket) << "\t"
                << bucket_hi(bucket) << "\t"
                << count << std::endl;
        }
    }
}

/**
 * @brief 为一个线程拉取调用上下文表并落盘。
 */
void TargetedRdProfiler::write_thread_contexts(const rd_wpctl_thread_stats& stats, uint32_t thread_index)
{
    std::string log_path = _nameprefix + ".rd2.t" + std::to_string(stats.tid) + ".contexts.txt";
    std::ofstream log(log_path, std::ios::trunc);

    if (!log.is_open())
        throw RdException("cannot open " + log_path);

    log << "context_id\tdepth";
    for (uint32_t i = 0; i < RD_WPCTL_MAX_CALLCHAIN_DEPTH; i++)
        log << "\tip" << i;
    log << std::endl;

    for (uint32_t context_id = 1; context_id <= RD_WPCTL_MAX_CONTEXTS; context_id++) {
        rd_wpctl_context_req req = {};

        req.thread_index = thread_index;
        req.context_id = context_id;
        if (ioctl(_device_fd, RDKIOC_GET_CONTEXT_ENTRY, &req) < 0)
            throw RdException(std::string("RDKIOC_GET_CONTEXT_ENTRY failed: ") + strerror(errno));
        if (!req.used)
            continue;

        log << req.context_id << "\t" << static_cast<uint32_t>(req.depth);
        for (uint32_t i = 0; i < RD_WPCTL_MAX_CALLCHAIN_DEPTH; i++) {
            if (i < req.depth)
                log << "\t0x" << std::hex << req.ips[i] << std::dec;
            else
                log << "\t0x0";
        }
        log << std::endl;
    }
}

/**
 * @brief 为一个线程拉取 DWARF raw events 并落盘。
 */
void TargetedRdProfiler::write_thread_dwarf_events(const rd_wpctl_thread_stats& stats, uint32_t thread_index)
{
    std::string bin_path = _nameprefix + ".rd2.t" + std::to_string(stats.tid) + ".dwarf.raw.bin";
    std::string txt_path = _nameprefix + ".rd2.t" + std::to_string(stats.tid) + ".dwarf.raw.txt";
    std::ofstream bin(bin_path, std::ios::binary | std::ios::trunc);
    std::ofstream txt(txt_path, std::ios::trunc);

    if (!bin.is_open())
        throw RdException("cannot open " + bin_path);
    if (!txt.is_open())
        throw RdException("cannot open " + txt_path);

    txt << "event_index\ttid\ttarget_index\tseed_pc_offset\tseed_pc\treuse_pc\tbucket_lo\tbucket_hi\tdelta\tseed_sp\treuse_sp\tseed_stack_size\treuse_stack_size" << std::endl;
    for (uint32_t event_index = 0; event_index < stats.dwarf_event_used; event_index++) {
        std::unique_ptr<rd_wpctl_dwarf_event_req> req(new rd_wpctl_dwarf_event_req());

        req->thread_index = thread_index;
        req->event_index = event_index;
        if (ioctl(_device_fd, RDKIOC_GET_DWARF_EVENT, req.get()) < 0)
            throw RdException(std::string("RDKIOC_GET_DWARF_EVENT failed: ") + strerror(errno));
        if (!req->used)
            continue;

        bin.write(reinterpret_cast<const char *>(req.get()), sizeof(*req));
        if (!bin.good())
            throw RdException("write failed for " + bin_path);

        txt << req->event_index << "\t"
            << req->tid << "\t"
            << req->target_index << "\t"
            << "0x" << std::hex << req->seed_pc_offset << "\t"
            << "0x" << req->seed_pc << "\t"
            << "0x" << req->reuse_pc << std::dec << "\t"
            << bucket_lo(req->bucket) << "\t"
            << bucket_hi(req->bucket) << "\t"
            << req->delta << "\t"
            << "0x" << std::hex << req->seed.sp << "\t"
            << "0x" << req->reuse.sp << std::dec << "\t"
            << req->seed.stack_size << "\t"
            << req->reuse.stack_size << std::endl;
    }
}

/**
 * @brief 从模块拉取布局、线程统计和直方图，并写出 `.rd2.info`。
 */
void TargetedRdProfiler::write_info()
{
    rd_wpctl_layout layout = {};
    uint64_t total_hits = 0;
    uint64_t total_evictions = 0;
    uint64_t total_dropped = 0;
    uint64_t total_seeds = 0;
    uint64_t total_pair_hist_used = 0;
    uint64_t total_pair_hist_dropped = 0;
    uint64_t total_context_used = 0;
    uint64_t total_context_dropped = 0;
    uint64_t total_callchain_failed = 0;
    uint64_t total_callchain_truncated = 0;
    uint64_t total_dwarf_event_used = 0;
    uint64_t total_dwarf_event_dropped = 0;
    uint64_t total_dwarf_stack_copy_failed = 0;

    if (ioctl(_device_fd, RDKIOC_GET_LAYOUT, &layout) < 0)
        throw RdException(std::string("RDKIOC_GET_LAYOUT failed: ") + strerror(errno));

    _info_file << "mode=targeted_rd" << std::endl;
    _info_file << "targeted_rd_backend=kernel_module" << std::endl;
    _info_file << "targeted_rd_seed_source=execute_breakpoint" << std::endl;
    _info_file << "targeted_rd_rd_source=kernel_perf_event_read_value" << std::endl;
    _info_file << "targeted_rd_binary_patch=0" << std::endl;
    _info_file << "hist_format=log2_only" << std::endl;
    _info_file << "pair_hist_present=1" << std::endl;
    _info_file << "pair_hist_key=seed_pc_offset,seed_context_id,reuse_pc,reuse_context_id" << std::endl;
    _info_file << "pair_hist_reuse_pc_identity=raw_va" << std::endl;
    _info_file << "pair_hist_capacity=" << RD_WPCTL_MAX_PAIR_HISTS << std::endl;
    _info_file << "callchain_present=" << (_callchain_mode == RD_CALLCHAIN_OFF ? 0 : 1) << std::endl;
    _info_file << "callchain_mode=" << callchain_mode_name(_callchain_mode) << std::endl;
    _info_file << "callchain_max_depth=" << RD_WPCTL_MAX_CALLCHAIN_DEPTH << std::endl;
    _info_file << "context_capacity=" << RD_WPCTL_MAX_CONTEXTS << std::endl;
    if (_callchain_mode == RD_CALLCHAIN_DWARF) {
        _info_file << "dwarf_unwind_present=1" << std::endl;
        _info_file << "dwarf_stack_bytes=" << _dwarf_stack_bytes << std::endl;
        _info_file << "dwarf_event_capacity=" << _dwarf_event_capacity << std::endl;
    }
    _info_file << "window_mode=" << (_explicit_window_seen ? "explicit" : "auto_fallback") << std::endl;
    if (_auto_window_discarded_on_first_explicit)
        _info_file << "auto_window_discarded_on_first_explicit=1" << std::endl;
    _info_file << "target_file=" << _target_file << std::endl;
    _info_file << "main_binary=" << _main_binary_path << std::endl;
    _info_file << "instruction_support=" << _instruction_support << std::endl;
    _info_file << "rd_event=" << _rd_event_name << std::endl;
    _info_file << "candidate_source=sparse_execute_breakpoint_samples" << std::endl;
    _info_file << "breakpoint_sample_period=" << _bp_sample_period << std::endl;
    _info_file << "reservoir_capacity=" << _watchpoint_capacity << std::endl;
    _info_file << "watchpoint_count=" << _watchpoint_capacity << std::endl;
    _info_file << "target_filter_policy=drop_unsupported_hotspots" << std::endl;
    _info_file << "requested_target_count=" << (_targets.size() + _rejected_targets.size()) << std::endl;
    _info_file << "rejected_target_count=" << _rejected_targets.size() << std::endl;
    _info_file << "cpu_binding=exclusive_process_local" << std::endl;
    _info_file << "target_count=" << _targets.size() << std::endl;
    for (size_t i = 0; i < _targets.size(); i++) {
        const hot_target& t = _targets[i];
        _info_file << "target=" << i << "\t"
                   << "0x" << std::hex << t.pc_offset << "\t"
                   << "0x" << t.abs_pc << std::dec << "\t"
                   << t.aggregated_samples << "\t"
                   << t.mnemonic << "\t"
                   << t.operands << std::endl;
    }
    for (const rejected_target& t : _rejected_targets) {
        _info_file << "rejected_target="
                   << "0x" << std::hex << t.pc_offset << std::dec << "\t"
                   << t.aggregated_samples << "\t"
                   << t.reason << std::endl;
    }

    _info_file << "thread_count=" << layout.thread_count << std::endl;
    for (uint32_t i = 0; i < layout.thread_count; i++) {
        rd_wpctl_thread_stats stats = {};
        stats.index = i;
        if (ioctl(_device_fd, RDKIOC_GET_THREAD_STATS, &stats) < 0)
            throw RdException(std::string("RDKIOC_GET_THREAD_STATS failed: ") + strerror(errno));
        _info_file << "thread=" << stats.tid << "\t"
                   << stats.cpu << "\t"
                   << stats.candidate_samples << "\t"
                   << stats.reservoir_seen << "\t"
                   << stats.reservoir_accepted << "\t"
                   << stats.reservoir_rejected << "\t"
                   << stats.hits << "\t"
                   << stats.evictions << "\t"
                   << stats.dropped << "\t"
                   << stats.pair_hist_used << "\t"
                   << stats.pair_hist_dropped << "\t"
                   << stats.context_used << "\t"
                   << stats.context_dropped << "\t"
                   << stats.callchain_failed << "\t"
                   << stats.callchain_truncated << "\t"
                   << stats.dwarf_event_used << "\t"
                   << stats.dwarf_event_dropped << "\t"
                   << stats.dwarf_stack_copy_failed << "\t"
                   << stats.dwarf_stack_bytes << std::endl;
        total_hits += stats.hits;
        total_evictions += stats.evictions;
        total_dropped += stats.dropped;
        total_seeds += stats.reservoir_accepted;
        total_pair_hist_used += stats.pair_hist_used;
        total_pair_hist_dropped += stats.pair_hist_dropped;
        total_context_used += stats.context_used;
        total_context_dropped += stats.context_dropped;
        total_callchain_failed += stats.callchain_failed;
        total_callchain_truncated += stats.callchain_truncated;
        total_dwarf_event_used += stats.dwarf_event_used;
        total_dwarf_event_dropped += stats.dwarf_event_dropped;
        total_dwarf_stack_copy_failed += stats.dwarf_stack_copy_failed;
        write_thread_histograms(stats, i);
        write_thread_pair_histograms(stats, i);
        if (_callchain_mode == RD_CALLCHAIN_FP)
            write_thread_contexts(stats, i);
        if (_callchain_mode == RD_CALLCHAIN_DWARF)
            write_thread_dwarf_events(stats, i);
    }
    _info_file << "seed_samples=" << total_seeds << std::endl;
    _info_file << "watchpoint_hits=" << total_hits << std::endl;
    _info_file << "evicted_pending_samples=" << total_evictions << std::endl;
    _info_file << "dropped_pending_samples=" << total_dropped << std::endl;
    _info_file << "pair_hist_used=" << total_pair_hist_used << std::endl;
    _info_file << "pair_hist_dropped=" << total_pair_hist_dropped << std::endl;
    _info_file << "context_used=" << total_context_used << std::endl;
    _info_file << "context_dropped=" << total_context_dropped << std::endl;
    _info_file << "callchain_failed=" << total_callchain_failed << std::endl;
    _info_file << "callchain_truncated=" << total_callchain_truncated << std::endl;
    _info_file << "dwarf_event_used=" << total_dwarf_event_used << std::endl;
    _info_file << "dwarf_event_dropped=" << total_dwarf_event_dropped << std::endl;
    _info_file << "dwarf_stack_copy_failed=" << total_dwarf_stack_copy_failed << std::endl;
}
