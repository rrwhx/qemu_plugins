#include <algorithm>
#include <numeric>
#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>
#include <vector>
#include <unordered_map>

#include <fcntl.h>
#include <sys/mman.h>

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

#include <iostream>
#include <vector>
#include <list>
#include <queue>
#include <unordered_map>
#include <memory>
#include <random>
#include <cstdint>
#include <algorithm>
#include <climits>
#include <cassert>

// -----------------------------
// CacheEntry Structure
// -----------------------------

struct CacheEntry {
    uint64_t tag;
    bool valid;

    CacheEntry() : tag(0), valid(false) {}
    CacheEntry(uint64_t t, bool v) : tag(t), valid(v) {}
};

// -----------------------------
// CacheBase Abstract Class
// -----------------------------

class CacheBase {
public:
    virtual void access(uint64_t address) = 0;
    virtual void printStats() const = 0;
    virtual ~CacheBase() {}
};

// -----------------------------
// ReplacementPolicy Abstract Class
// -----------------------------

class ReplacementPolicy {
public:
    virtual void touch(int setIndex, int way) = 0;
    virtual int selectVictim(int setIndex) = 0;
    virtual void addLine(int setIndex, int way) = 0;
    virtual ~ReplacementPolicy() {}
};

// -----------------------------
// LRU Replacement Policy
// -----------------------------

class LRUPolicy : public ReplacementPolicy {
private:
    std::vector<std::vector<uint64_t>> sets_timestamp;
    uint64_t time_stamp;

public:
    LRUPolicy(int numSets, int ways) 
        : sets_timestamp(numSets, std::vector<uint64_t>(ways, 0)), 
            time_stamp(1) {}

    void touch(int setIndex, int way) override {
        ++ time_stamp;
        sets_timestamp[setIndex][way] = time_stamp;
    }

    int selectVictim(int setIndex) override {
        uint64_t lowest_timestamp = sets_timestamp[setIndex][0];
        int lowest_timestamp_index = 0;
        int ways_num = sets_timestamp[setIndex].size();
        for (int i=1; i < ways_num; i++) {
            if (sets_timestamp[setIndex][i] < lowest_timestamp) {
                lowest_timestamp = sets_timestamp[setIndex][i];
                lowest_timestamp_index = i;
            }
        }
        return lowest_timestamp_index;
    }

    void addLine(int setIndex, int way) override {
        ++ time_stamp;
        sets_timestamp[setIndex][way] = time_stamp;
    }
};

// -----------------------------
// LFU Replacement Policy
// -----------------------------

class LFUPolicy : public ReplacementPolicy {
private:
    std::vector<std::vector<uint64_t>> sets_access_num;

public:
    LFUPolicy(int numSets, int ways) : 
        sets_access_num(numSets, std::vector<uint64_t>(ways, 0)) {}

    void touch(int setIndex, int way) override {
        ++ sets_access_num[setIndex][way];
    }

    int selectVictim(int setIndex) override {
        uint64_t lowest_access_num = sets_access_num[setIndex][0];
        int lowest_access_num_index = 0;
        int ways_num = sets_access_num[setIndex].size();
        for (int i=1; i < ways_num; i++) {
            if (sets_access_num[setIndex][i] < lowest_access_num) {
                lowest_access_num = sets_access_num[setIndex][i];
                lowest_access_num_index = i;
            }
        }
        return lowest_access_num_index;
    }

    void addLine(int setIndex, int way) override {
        sets_access_num[setIndex][way] = 1;
    }
};

// -----------------------------
// FIFO Replacement Policy
// -----------------------------

class FIFOPolicy : public ReplacementPolicy {
private:
    std::vector<std::vector<uint64_t>> sets_timestamp;
    uint64_t time_stamp;

public:
    FIFOPolicy(int numSets, int ways) 
        : sets_timestamp(numSets, std::vector<uint64_t>(ways, 0)), 
            time_stamp(1) {}

    void touch(int /*setIndex*/, int /*way*/) override {
        ++ time_stamp;
    }

    int selectVictim(int setIndex) override {
        uint64_t lowest_timestamp = sets_timestamp[setIndex][0];
        int lowest_timestamp_index = 0;
        int ways_num = sets_timestamp[setIndex].size();
        for (int i=1; i < ways_num; i++) {
            if (sets_timestamp[setIndex][i] < lowest_timestamp) {
                lowest_timestamp = sets_timestamp[setIndex][i];
                lowest_timestamp_index = i;
            }
        }
        return lowest_timestamp_index;
    }

    void addLine(int setIndex, int way) override {
        sets_timestamp[setIndex][way] = time_stamp;
    }
};

// -----------------------------
// Random Replacement Policy
// -----------------------------

class RandomPolicy : public ReplacementPolicy {
private:
    std::mt19937 rng;
    int associativity;

public:
    RandomPolicy(int numSets, int ways) : rng(std::random_device{}()), associativity(ways) {}

    void touch(int /*setIndex*/, int /*way*/) override {
        // Random does not need to update on access
    }

    int selectVictim(int /*setIndex*/) override {
        std::uniform_int_distribution<> dis(0, associativity - 1);
        return dis(rng);
    }

    void addLine(int /*setIndex*/, int /*way*/) override {
        // Random does not need to handle additions
    }
};

// -----------------------------
// Second Chance Replacement Policy
// -----------------------------

class SecondChancePolicy : public ReplacementPolicy {
private:
    std::vector<std::vector<std::pair<uint64_t, bool>>> sets_timestamp;
    uint64_t time_stamp;

public:
    SecondChancePolicy(int numSets, int ways)
        : sets_timestamp(numSets, std::vector<std::pair<uint64_t, bool>>(ways, make_pair(0, true))), 
            time_stamp(1) {}

    void touch(int setIndex, int way) override {
        ++ time_stamp;
    }

    int selectVictim(int setIndex) override {
        ++ time_stamp;
        uint64_t lowest_timestamp = sets_timestamp[setIndex][0].first;
        int ways_num = sets_timestamp[setIndex].size();
        int lowest_timestamp_index = 0;
        for (int i=1; i < ways_num; i++) {
            if (sets_timestamp[setIndex][i].second && sets_timestamp[setIndex][i].first < lowest_timestamp) {
                lowest_timestamp = sets_timestamp[setIndex][i].first;
                lowest_timestamp_index = i;
            }
        }

        sets_timestamp[setIndex][lowest_timestamp_index].first = time_stamp;
        sets_timestamp[setIndex][lowest_timestamp_index].second = false;


        lowest_timestamp_index = 0;
        for (int i=1; i < ways_num; i++) {
            if (!sets_timestamp[setIndex][i].second && sets_timestamp[setIndex][i].first < lowest_timestamp) {
                lowest_timestamp = sets_timestamp[setIndex][i].first;
                lowest_timestamp_index = i;
            }
        }

        return lowest_timestamp_index;
    }

    void addLine(int setIndex, int way) override {
        ++ time_stamp;
        sets_timestamp[setIndex][way].first = time_stamp;
        sets_timestamp[setIndex][way].second = true;
    }
};

// -----------------------------
// Approximate LRU Replacement Policy
// -----------------------------


class PseudoLRU_BITS {
private:
    uint64_t bits;

    // Helper function to get directions from way index
    // Returns a vector of 4 directions: 0 for left, 1 for right
    std::vector<int> get_directions(int way) const {
        std::vector<int> directions(4, 0);
        for(int i = 3; i >= 0; --i){
            directions[i] = way & 1;
            way >>=1;
        }
        return directions;
    }

public:
    PseudoLRU_BITS() : bits(0) {}

    // Mark a way as recently used
    void access(int way, int way_num, int way_log) {
        assert(way >=0 && way < way_num && "Way index out of range");

        std::vector<int> directions = get_directions(way);
        int node = 0; // Start at root

        for(int level =0; level < way_log; ++level){
            if(way & (1 << (way_log - 1 - level))){
                // Set the bit to indicate last used direction was right (1)
                bits |= (1 << node);
                node = (node << 1) +2; // Move to right child
            } else{
                // Set the bit to indicate last used direction was left (0)
                bits &= ~(1 << node);
                node = (node << 1) +1; // Move to left child
            }
        }
    }

    // Select the victim way using the pseudo-LRU tree
    int get_victim(int way_num, int way_log) {
        int way =0;
        int node =0;
        std::vector<int> directions(4, 0);
        for(int level=0; level< way_log; ++level){
            int bit = bits & (1 << node);
            // Choose the direction opposite to the last used
            bit = bit ? 0 : 1;
            node = (node << 1) + 1 + bit;
            way |= (bit << (way_log - 1 - level));
        }
        return way;
    }
};

class PLRUPolicy : public ReplacementPolicy {
private:
    // Implementing a simplified pseudo-LRU using a list similar to exact LRU
    std::vector<PseudoLRU_BITS> sets_lrubits;
    int way_num;
    int way_log;

public:
    PLRUPolicy(int numSets, int ways) : 
        sets_lrubits(numSets, PseudoLRU_BITS()),
        way_num(ways),
        way_log(__builtin_ctz(ways))
        {}

    void touch(int setIndex, int way) override {
        sets_lrubits[setIndex].access(way, way_num, way_log);
    }

    int selectVictim(int setIndex) override {
        return sets_lrubits[setIndex].get_victim(way_num, way_log);;
    }

    void addLine(int setIndex, int way) override {
        sets_lrubits[setIndex].access(way, way_num, way_log);
    }
};

// -----------------------------
// Cache Class Implementation
// -----------------------------

class Cache : public CacheBase {
private:
    static constexpr int DEFAULT_LINE_SIZE = 64; // in bytes
    int lineSize;
    int numSets;
    int associativity;
    uint64_t accessCount;
    uint64_t hitCount;
    uint64_t evictionCount;
    std::unique_ptr<ReplacementPolicy> policy;
    std::vector<std::vector<CacheEntry>> cacheSets; // [set][way]

    // Calculate number of set index bits and block offset bits
    int setIndexBits;
    int blockOffsetBits;
    std::string name;


public:
    enum PolicyType {
        LRU,
        LFU,
        FIFO,
        RANDOM,
        FIFO2,
        PLRU
    };

    PolicyType policytype;

    Cache(int sets, int ways, PolicyType type, string name = "cache") :
        lineSize(DEFAULT_LINE_SIZE),
        numSets(sets),
        associativity(ways),
        accessCount(0),
        hitCount(0),
        evictionCount(0),
        cacheSets(sets, std::vector<CacheEntry>(ways, CacheEntry())),
        name(name),
        policytype(type)
    {
        // Ensure that sets and ways are powers of two
        assert((numSets & (numSets - 1)) == 0 && "Number of sets must be a power of two");
        assert((associativity & (associativity - 1)) == 0 && "Associativity (ways) must be a power of two");

        // Calculate set index bits and block offset bits
        
        blockOffsetBits = __builtin_ctz(lineSize);
        setIndexBits = __builtin_ctz(numSets);

        // printf("%d %x\n",blockOffsetBits, lineSize);
        // printf("%d %x\n",setIndexBits, numSets);

        // Initialize the appropriate replacement policy
        switch(type){
            case LRU:
                policy = std::make_unique<LRUPolicy>(numSets, associativity);
                break;
            case LFU:
                policy = std::make_unique<LFUPolicy>(numSets, associativity);
                break;
            case FIFO:
                policy = std::make_unique<FIFOPolicy>(numSets, associativity);
                break;
            case RANDOM:
                policy = std::make_unique<RandomPolicy>(numSets, associativity);
                break;
            case FIFO2:
                policy = std::make_unique<SecondChancePolicy>(numSets, associativity);
                break;
            case PLRU:
                policy = std::make_unique<PLRUPolicy>(numSets, associativity);
                break;
            default:
                policy = std::make_unique<LRUPolicy>(numSets, associativity);
        }
    }

    // Calculate set index from address using bitmasking
    int getSetIndex(uint64_t address) const {
        return (address >> blockOffsetBits) & (numSets - 1);
    }

    // Calculate tag from address
    uint64_t getTag(uint64_t address) const {
        return address >> (blockOffsetBits + setIndexBits);
    }

    // Find if the tag exists in the set; return way or -1
    int findWay(int setIndex, uint64_t tag) const {
        for(int way = 0; way < associativity; ++way){
            if(cacheSets[setIndex][way].valid && cacheSets[setIndex][way].tag == tag){
                return way;
            }
        }
        return -1;
    }

    // Find an empty way in the set; return way or -1
    int findEmptyWay(int setIndex) const {
        for(int way = 0; way < associativity; ++way){
            if(!cacheSets[setIndex][way].valid){
                return way;
            }
        }
        return -1;
    }

    void access(uint64_t address) override {
        accessCount++;
        int setIndex = getSetIndex(address);
        uint64_t tag = getTag(address);

        int way = findWay(setIndex, tag);
        if(way != -1){
            // Hit
            hitCount++;
            policy->touch(setIndex, way);
        }
        else{
            // Miss
            int emptyWay = findEmptyWay(setIndex);
            if(emptyWay != -1){
                // Use empty way
                cacheSets[setIndex][emptyWay] = CacheEntry(tag, true);
                policy->addLine(setIndex, emptyWay);
            }
            else{
                // Evict using policy
                evictionCount++;
                int victimWay = policy->selectVictim(setIndex);
                // Replace victim
                cacheSets[setIndex][victimWay].tag = tag;
                cacheSets[setIndex][victimWay].valid = true;
                policy->addLine(setIndex, victimWay);
            }
        }
    }

    const char* replace_policy_str(PolicyType type) const {
        switch (type)
        {
        case LRU: return "LRU";
        case LFU: return "LFU";
        case FIFO: return "FIFO";
        case RANDOM: return "RANDOM";
        case FIFO2: return "FIFO2";
        case PLRU: return "PLRU";
        default:
            assert(0);
        }
        return "NULL";
    }

    void printStats() const override {
        double hitRate = (accessCount > 0) ? ((double)hitCount / accessCount) : 0.0;
        char buf[1024];
        sprintf(buf, "%s,num_sets,%d,num_ways:%d,policy:%s,access:%ld,hit:%ld,hit_ratio:%.6f%%,evictions:%ld\n", name.c_str(), numSets, associativity, replace_policy_str(policytype), accessCount, hitCount, hitRate * 100.0, evictionCount);
        qemu_plugin_outs(buf);
        // std::cout << "Accesses: " << accessCount 
        //           << ", Hits: " << hitCount 
        //           << ", Evictions: " << evictionCount 
        //           << ", Hit Rate: " << (hitRate * 100) << "%" << std::endl;
    }
};

// Cache icache(64, 8, Cache::PLRU);
Cache *icache;
Cache *dcache;

void plugin_exit(qemu_plugin_id_t id, void* p) {
    // icache.printStats();
    dcache->printStats();
}

// static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    // icache.access((uint64_t)userdata);
// }

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    dcache->access(vaddr);
    // bool is_st = qemu_plugin_mem_is_store(info);
    // printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
            // userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);
    // uint64_t last_cache_addr;
    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
        // if (i == 0) {
        //     last_cache_addr = insn_vaddr >> 6;
        //     qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)last_cache_addr);
        // }
        // size_t insn_size = qemu_plugin_insn_size(insn);
        // uint64_t cur_insn_end = insn_vaddr + insn_size - 1;

        // if (cur_insn_end >> 6 != last_cache_addr) {
        //     qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)cur_insn_end);
        //     last_cache_addr = cur_insn_end >> 6;
        // }

        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, (void*)insn_vaddr);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    // plugin_init(info);

    string logfile_name = find_arg_or_else(argc,argv,"logfile","log.txt");

    int set = get_u64_or_else(argc, argv, "set", 64);
    int way = get_u64_or_else(argc, argv, "set", 8);
    
    string replace = find_arg_or_else(argc,argv,"replace","LRU");

    if (replace == "LRU") {
        dcache = new Cache(set, way, Cache::LRU);
    } else if (replace == "LFU") {
        dcache = new Cache(set, way, Cache::LFU);
    } else if (replace == "FIFO") {
        dcache = new Cache(set, way, Cache::FIFO);
    } else if (replace == "RANDOM") {
        dcache = new Cache(set, way, Cache::RANDOM);
    } else if (replace == "FIFO2") {
        dcache = new Cache(set, way, Cache::FIFO2);
    } else if (replace == "PLRU") {
        dcache = new Cache(set, way, Cache::PLRU);
    } else {
        fprintf(stderr, "avaliable: LRU,LFU,FIFO,RANDOM,FIFO2,PLRU. chioce:%s\n", replace.c_str());
        abort();
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

