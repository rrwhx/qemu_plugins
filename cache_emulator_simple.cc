#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <unordered_map>

#include <capstone/capstone.h>
#if CS_NEXT_VERSION < 6
#error "capstone version mismatch"
#endif
extern "C" {
#include "qemu-plugin.h"
}

#include "util.h"

using namespace std;


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;


// 缓存行结构，包括LRU信息
struct CacheLine {
    uint64_t tag;
    bool valid;
    uint64_t last_used;

    CacheLine() : tag(0), valid(false), last_used(0) {}
};

// 获取log2值的编译时函数（要求输入为2的幂）
constexpr size_t log2_constexpr(size_t x, size_t count = 0) {
    return (x <= 1) ? count : log2_constexpr(x / 2, count + 1);
}

// 缓存类模板
template<size_t num_sets, size_t num_ways>
class Cache {
private:
    static_assert((num_sets & (num_sets - 1)) == 0, "num_sets必须是2的幂");
    static_assert((num_ways & (num_ways - 1)) == 0, "num_ways必须是2的幂");

    static constexpr size_t offset_bits = 6; // 64字节 -> 2^6
    static constexpr size_t set_index_bits = log2_constexpr(num_sets);
    static constexpr size_t tag_bits = 64 - set_index_bits - offset_bits;

    // 使用固定大小的二维数组，每个缓存行包含tag, valid和last_used
    std::array<std::array<CacheLine, num_ways>, num_sets> sets;
    uint64_t total_accesses;
    uint64_t hits;

    uint64_t last_line;

    std::string name;

    // 地址解析
    void parse_address(uint64_t address, uint64_t &tag, size_t &index, size_t &offset) const {
        offset = address & ((1UL << offset_bits) - 1);
        index = (address >> offset_bits) & ((1UL << set_index_bits) - 1);
        tag = address >> (offset_bits + set_index_bits);
    }

public:
    // 构造函数
    Cache(const std::string& cache_name) 
        : total_accesses(0),
          hits(0),
          last_line(0),
          name(cache_name)
          {}

    // 访问缓存的方法
    bool access(uint64_t address) {
        total_accesses++; // 更新时间戳
        if (last_line == address >> offset_bits) {
            ++ hits;
            return true;
        }
        last_line = address >> offset_bits;


        uint64_t tag;
        size_t index, offset;
        parse_address(address, tag, index, offset);

        // 搜索组内所有缓存行
        for (size_t way = 0; way < num_ways; ++way) {
            if (sets[index][way].valid && sets[index][way].tag == tag) {
                // 命中，更新LRU信息
                sets[index][way].last_used = total_accesses;
                ++ hits;
                return true;
            }
        }

        // 未命中，需要替换
        // 找到最久未使用的缓存行
        size_t lru_way = 0;
        uint64_t min_timestamp = UINT64_MAX;
        for (size_t way = 0; way < num_ways; ++way) {
            if (!sets[index][way].valid) {
                lru_way = way;
                min_timestamp = 0;
                break;
            }
            if (sets[index][way].last_used < min_timestamp) {
                min_timestamp = sets[index][way].last_used;
                lru_way = way;
            }
        }

        // 替换缓存行
        sets[index][lru_way].tag = tag;
        sets[index][lru_way].valid = true;
        sets[index][lru_way].last_used = total_accesses;

        return false;
    }

    // 打印访问统计信息
    void print_statistics() const {
        char buf[1024];
        sprintf(buf, "%s,num_sets,%ld,num_ways:%ld,access:%ld,hit:%ld,hit_ratio:%.6f%%\n", name.c_str(), num_sets, num_ways, total_accesses, hits, hits * 100.0 / total_accesses);
        qemu_plugin_outs(buf);
    }

    // 获取缓存参数
    size_t get_num_sets() const { return num_sets; }
    size_t get_num_ways() const { return num_ways; }
    size_t get_set_index_bits() const { return set_index_bits; }
    size_t get_offset_bits() const { return offset_bits; }
    size_t get_tag_bits() const { return tag_bits; }
};


Cache<64, 8> dcache("dcache");
Cache<64, 8> icache("icache");

void plugin_exit(qemu_plugin_id_t id, void* p) {
    icache.print_statistics();
    dcache.print_statistics();
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    icache.access((uint64_t)userdata);
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    dcache.access(vaddr);
    // bool is_st = qemu_plugin_mem_is_store(info);
    // printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
            // userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);
    uint64_t last_cache_addr;
    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
        if (i == 0) {
            last_cache_addr = insn_vaddr >> 6;
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)last_cache_addr);
        }
        size_t insn_size = qemu_plugin_insn_size(insn);
        uint64_t cur_insn_end = insn_vaddr + insn_size - 1;

        if (cur_insn_end >> 6 != last_cache_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)cur_insn_end);
            last_cache_addr = cur_insn_end >> 6;
        }

        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, (void*)insn_vaddr);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    // plugin_init(info);

    string logfile_name = find_arg_or_else(argc,argv,"logfile","log.txt");

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

