#ifndef mt_MONITOR_H
#define mt_MONITOR_H

#include <vector>
#include <fstream>
#include <thread>
#include <string>
#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <semaphore.h>

#define SAMPLE_WAKEUP 1024
#define MAX_TAG 64

#define SPE_PACKET_TS_HEADER 0x71
#define SPE_PACKET_PADDING_HEADER 0x00
#define SPE_PACKET_END_HEADER 0x01
#define SPE_PACKET_SHORT_INDEX_MASK 0x07
#define SPE_PACKET_ADDRESS_MASK 0xF8
#define SPE_PACKET_ADDRESS_HEADER 0xB0

#define SPE_ADDR_PKT_HDR_INDEX_INS 0x0
#define SPE_ADDR_PKT_HDR_INDEX_BRANCH 0x1
#define SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT 0x2
#define SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS 0x3
#define SPE_ADDR_PKT_HDR_INDEX_PREV_BRANCH 0x4

#define SPE_ADDR_PKT_BYTE7_SHIFT 56
#define SPE_ADDR_PKT_EL1 0x1
#define SPE_ADDR_PKT_EL2 0x2

struct event_spec
{
    const int n;
    const char **event_name;
    const bool *event_leader;
};

struct counter_data
{
    uint64_t value;
    double active_time;
};

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

struct phase_info
{
    std::string tag;
    uint64_t time;
};

struct addr_tag
{
    std::string tag;
    void *start;
    void *end;
};

struct module_map_entry
{
    uint32_t module_id;
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t file_offset;
    std::string path;
};

struct hotspot_key
{
    uint32_t module_id;
    uint64_t pc_offset;

    bool operator==(const hotspot_key& other) const
    {
        return module_id == other.module_id && pc_offset == other.pc_offset;
    }
};

struct hotspot_key_hash
{
    size_t operator()(const hotspot_key& key) const
    {
        size_t h1 = std::hash<uint32_t>{}(key.module_id);
        size_t h2 = std::hash<uint64_t>{}(key.pc_offset);
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }
};

struct hotspot_summary
{
    int tid;
    uint32_t module_id;
    uint64_t pc_offset;
    uint64_t sample_count;
    std::string path;
};

class BinaryWriter
{
public:
    BinaryWriter() {}
    BinaryWriter(const char *path);
    void write(char *a, size_t n);

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
    uint64_t pending_time;
    uint64_t pending_addr;
    uint64_t pending_pc;
    uint8_t pending_mask;
};

struct thread_state
{
    int tid;
    bool active;
    std::vector<int> counter_fds;
    std::vector<BinaryWriter> writers;
    std::vector<sampler_slot> samplers;
};

class Monitor
{
public:
    Monitor(const event_spec counter_spec, const event_spec sampler_spec, uint64_t sample_period,
        int ringbufsize, int auxbufsize, const char *name, bool is_pin);
    ~Monitor();
    void reset();
    void start(const char *tag=0, bool offloaded=false);
    void stop();
    void read_counters(counter_data *counters, bool include_samplers);
    void read_samples();
    void tag_addr(const char *tag, void *start, void *end);
    void mark_phase(const char *tag);
    void register_current_thread();
    void unregister_current_thread();

    kinfo& last_kinfo()
    {
        return _kinfos.back();
    }

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

    bool _nonstop_mode;

    int64_t sampler_tid;
    bool _events_enabled;

    std::vector<uint64_t> _prev_counters;
    std::vector<uint64_t> _retired_values;
    std::vector<uint64_t> _retired_time_enabled;
    std::vector<uint64_t> _retired_time_running;

    // Known thread ids in the order used by arrays
    std::vector<int> _tids;
    std::unordered_map<int, thread_state> _threads;
    std::unordered_map<int, sampler_slot*> _sampler_slots;
    int _next_slot_id;
    uint64_t _written_sample_bytes;
    std::mutex _state_mutex;

    // Prefix for output files (the 'name' provided in ctor)
    std::string _nameprefix;

    std::thread _sampler_thread;
    bool _is_pin;
    int _event_fd;
    int _epoll_fd;

    // The purpose of this semaphore is to ensure that samples from different
    // kernel invokations are not mixed together. Also, it acts as a mutex
    // to avoid concurrent access from the sampler thread and main thread.
    sem_t _sampler_drain;
    std::ofstream _info_file;
    std::vector<kinfo> _kinfos;
    timespec _start_time;
    uint64_t _clock_res;
    std::vector<addr_tag> _addr_tags;
    std::vector<phase_info> _phases;
    std::vector<module_map_entry> _module_maps;
    std::string _main_binary_path;
    std::unordered_map<int, std::unordered_map<hotspot_key, uint64_t, hotspot_key_hash>> _thread_hotspots;
    size_t _hotspot_top_k;
    uint64_t _hotspot_unmapped_samples;

    thread_state& register_thread_locked(int tid);
    void unregister_thread_locked(int tid);
    void open_thread_locked(thread_state& state);
    void disable_thread_locked(thread_state& state);
    void enable_thread_locked(thread_state& state);
    void accumulate_retired_counts_locked(const thread_state& state);
    void close_thread_locked(thread_state& state);
    thread_state *find_thread_locked(int tid);
    void fds_ioctl(int request);
    void run_sampler_thread();
    size_t process_samples(int slot_id);
    size_t process_samples_locked(sampler_slot& slot);
    void write_info(std::ofstream& info);
    bool has_arm_spe_samples() const;
    size_t sample_record_bytes() const;
    const char *sample_record_fields() const;
    bool sample_pc_present() const;
    void snapshot_module_maps();
    void snapshot_main_binary_path();
    void remember_module_map(uint64_t vm_start, uint64_t vm_end, uint64_t file_offset, const std::string& path);
    const module_map_entry *find_module_map(uint64_t pc) const;
    bool is_main_binary_module(const module_map_entry& entry) const;
    void record_hotspot_sample(int tid, uint64_t pc);
    std::vector<hotspot_summary> collect_hotspots_for_thread(int tid) const;
    void write_hotspot_manifest() const;
};

#endif
