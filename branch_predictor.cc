#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <map>

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
csh cs_handle;
// branch types
enum branch_type {
  NOT_BRANCH = 0,
  BRANCH_DIRECT_JUMP = 1,
  BRANCH_INDIRECT = 2,
  BRANCH_CONDITIONAL = 3,
  BRANCH_DIRECT_CALL = 4,
  BRANCH_INDIRECT_CALL = 5,
  BRANCH_RETURN = 6,
  BRANCH_OTHER = 7
};

const char* branch_type(int is_branch) {
    switch (is_branch) {
        case NOT_BRANCH:            return "NULL";
        case BRANCH_DIRECT_JUMP:    return "direct_jump";
        case BRANCH_INDIRECT:       return "indirect_jump";
        case BRANCH_CONDITIONAL:    return "conditional";
        case BRANCH_DIRECT_CALL:    return "direct_call";
        case BRANCH_INDIRECT_CALL:  return "indirect_call";
        case BRANCH_RETURN:         return "return";
        case BRANCH_OTHER:          return "other";
    }
    return "NULL";
};

typedef struct {
    uint64_t pc;
    uint64_t size;
    uint64_t num;
    uint64_t hit_num;
    int branch_type;
} InsnData;

map<uint64_t, InsnData> insn_code_data;

// trace_instr_format_t curr_instr;

// int64_t REAL_INSN_COUNT;
// int64_t TRACE_COUNT = 10000;
// int64_t TRACE_SKIP_COUNT = 10000;
// const char* trace_filename;
// int trace_fd;
// uint64_t filesize;
// trace_instr_format_t* trace_buffer;
// int64_t trace_buffer_index = -1;


int x64_insn_is_branch(const cs_insn * insn) {
    switch (insn->id)
    {
    case X86_INS_JAE ... X86_INS_JS:
    case X86_INS_LOOPNE:
    case X86_INS_LOOPE:
    case X86_INS_LOOP:
        return BRANCH_CONDITIONAL;
    case X86_INS_JMP:
        if (insn->detail->x86.operands[0].type == X86_OP_REG) {
            return BRANCH_DIRECT_JUMP;
        } else {
            return BRANCH_INDIRECT;
        }
        return BRANCH_DIRECT_JUMP;
    case X86_INS_CALL:
        if (insn->detail->x86.operands[0].type == X86_OP_REG) {
            return BRANCH_DIRECT_CALL;
        } else {
            return BRANCH_INDIRECT_CALL;
        }
    case X86_INS_LJMP:
    case X86_INS_LCALL:
    case X86_INS_IRET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return BRANCH_DIRECT_JUMP;
    case X86_INS_RET:
        return BRANCH_RETURN;
    default:
        return NOT_BRANCH;
    }
    return NOT_BRANCH;
}

int aarch64_insn_is_branch(const cs_insn * insn) {
    uint32_t code = *(uint32_t*)insn->bytes;
    if (code >> 26 == 5) {
        return BRANCH_DIRECT_JUMP;
    }
    switch (insn->id)
    {
    case AARCH64_INS_BC:
    case AARCH64_INS_CBNZ:
    case AARCH64_INS_CBZ:
    case AARCH64_INS_TBNZ:
    case AARCH64_INS_TBZ:
    case AARCH64_INS_B://cs bug
        return BRANCH_CONDITIONAL;
        // return BRANCH_DIRECT_JUMP;
    case AARCH64_INS_BL:
        return BRANCH_DIRECT_CALL;
    case AARCH64_INS_BLR:
        return BRANCH_INDIRECT_CALL;
    case AARCH64_INS_BR:
        return BRANCH_INDIRECT;
    case AARCH64_INS_RET:
        return BRANCH_RETURN;
    default:
        return NOT_BRANCH;
    }
    return NOT_BRANCH;
}

int riscv64_insn_is_branch(const cs_insn * insn) {
    switch (insn->id)
    {
    case RISCV_INS_C_J:
    case RISCV_INS_C_JAL:
    case RISCV_INS_C_JALR:
    case RISCV_INS_C_JR:
    case RISCV_INS_BEQ:
    case RISCV_INS_BGE:
    case RISCV_INS_BGEU:
    case RISCV_INS_BLT:
    case RISCV_INS_BLTU:
    case RISCV_INS_BNE:
    case RISCV_INS_JAL:
    case RISCV_INS_JALR:
        return 1;
    default:
        return 0;
    }
    return 0;
}

int loongarch64_insn_is_branch(const cs_insn * insn) {
    if (*(uint32_t*)insn->bytes == 0x4c000020) {
            return BRANCH_RETURN;
    }
    switch (insn->id)
    {
    case LOONGARCH_INS_B:
        return BRANCH_DIRECT_JUMP;
    case LOONGARCH_INS_BL:
        return BRANCH_DIRECT_CALL;
    case LOONGARCH_INS_BEQ:
    case LOONGARCH_INS_BEQZ:
    case LOONGARCH_INS_BGE:
    case LOONGARCH_INS_BGEU:
    case LOONGARCH_INS_BLT:
    case LOONGARCH_INS_BLTU:
    case LOONGARCH_INS_BNE:
    case LOONGARCH_INS_BNEZ:
    case LOONGARCH_INS_BCEQZ:
    case LOONGARCH_INS_BCNEZ:
        return BRANCH_CONDITIONAL;
    case LOONGARCH_INS_JIRL:
        if (insn->detail->loongarch.operands[0].reg == LOONGARCH_REG_ZERO && insn->detail->loongarch.operands[1].reg == LOONGARCH_REG_RA) {
            // useless
            return BRANCH_RETURN;
        } else if (insn->detail->loongarch.operands[0].reg == LOONGARCH_REG_RA) {
            return BRANCH_INDIRECT_CALL;
        } else {
            return BRANCH_INDIRECT;
        }
    case LOONGARCH_INS_JISCR0:
    case LOONGARCH_INS_JISCR1:
        return BRANCH_INDIRECT;
    default:
        return NOT_BRANCH;
    }
    return 0;
}

struct target_info{
    const char *name;
    cs_arch arch;
    cs_mode mode;
    int op_max;
    int (*insn_is_branch)(const cs_insn *);
    // void (*disas_log)(const DisasContextBase *db, CPUState *cpu, FILE *f);
};


target_info all_archs[] = {
    { "aarch64",   CS_ARCH_AARCH64, cs_mode(CS_MODE_LITTLE_ENDIAN)                  , AARCH64_INS_ENDING, aarch64_insn_is_branch},
    { "mips64el",  CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,   cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,   cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , x64_insn_is_branch},
    { "riscv32",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING},
    { "riscv64",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, riscv64_insn_is_branch},
    { "loongarch32",   CS_ARCH_LOONGARCH,   cs_mode(CS_MODE_LOONGARCH32)              , LOONGARCH_INS_ENDING, },
    { "loongarch64",   CS_ARCH_LOONGARCH,   cs_mode(CS_MODE_LOONGARCH64)              , LOONGARCH_INS_ENDING, loongarch64_insn_is_branch},
    { NULL }
};

target_info* target;
bool verbose;
bool early_exit;


template<int num_bits>
class SaturatingCounter {
    static_assert(num_bits > 0 && num_bits <= 8, "num_bits must be between 1 and 8");

private:
    // 计算最大值为 (1 << num_bits) - 1
    static const uint8_t MAX_VALUE = (1 << num_bits) - 1;
    static const uint8_t MIN_VALUE = 0;

    // 当前计数器的值
    uint8_t value;

public:
    // 构造函数，初始化计数器为最大值的一半
    SaturatingCounter() : value(MAX_VALUE / 2) {}

    // 使计数器值增加1，但不超过最大值
    void increment() {
        if (value < MAX_VALUE) {
            value++;
        }
    }

    // 使计数器值减少1，但不低于最小值
    void decrement() {
        if (value > MIN_VALUE) {
            value--;
        }
    }

    void update(uint8_t taken) {
        if (taken) {
            increment();
        } else {
            decrement();
        }
    }

    // 获取计数器的当前值
    uint8_t current() const {
        return value;
    }

    // 获取计数器的最大值
    uint8_t max() const {
        return MAX_VALUE;
    }
};


class BranchPredictor {
protected:
    uint64_t total_num;
    uint64_t hit_num;

public:
    BranchPredictor() : total_num(0), hit_num(0) {}

    virtual uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) = 0;
    virtual void dump_info() const = 0;

    // virtual ~BranchPredictor() {}
};


template<int COUNTER_BITS>
class Bimodal : public BranchPredictor {
public:
    vector<SaturatingCounter<COUNTER_BITS>> bimodal_table;
    int BIMODAL_TABLE_SIZE;
    int BIMODAL_PRIME;
    Bimodal(int BIMODAL_TABLE_SIZE = 16384, int BIMODAL_PRIME = 16381) {
        this->BIMODAL_TABLE_SIZE = BIMODAL_TABLE_SIZE;
        this->BIMODAL_PRIME = BIMODAL_PRIME;
        bimodal_table.resize(BIMODAL_TABLE_SIZE);
    }
    uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) override {
        ip >>= 2;
        auto hash = ip % BIMODAL_PRIME;
        auto& value = bimodal_table[hash];
        uint8_t predict_taken = value.current() > (value.max() / 2);

// update
        value.update(taken);

        return predict_taken;
    }

    void dump_info() const override {

    }
};


class Gshare : public BranchPredictor {
public:
    uint64_t GLOBAL_HISTORY_LENGTH_HASH;
    uint64_t GLOBAL_HISTORY_LENGTH_MASK;
    uint64_t GLOBAL_HISTORY_LENGTH_USE;
    uint64_t branch_history_vector;
    uint64_t GS_HISTORY_TABLE_SIZE;
    vector<SaturatingCounter<2>> gs_history_table;
    Gshare(uint64_t GS_HISTORY_TABLE_SIZE = (1 << 20), int GLOBAL_HISTORY_LENGTH_HASH = 16, int GLOBAL_HISTORY_LENGTH_USE = 16) {
        this->GS_HISTORY_TABLE_SIZE = GS_HISTORY_TABLE_SIZE;
        this->GLOBAL_HISTORY_LENGTH_USE = GLOBAL_HISTORY_LENGTH_USE;
        this->GLOBAL_HISTORY_LENGTH_MASK = (1 << GLOBAL_HISTORY_LENGTH_HASH) - 1;
        this->GLOBAL_HISTORY_LENGTH_HASH = GLOBAL_HISTORY_LENGTH_HASH;
        gs_history_table.resize(GS_HISTORY_TABLE_SIZE);
    }

    uint64_t gs_table_hash(uint64_t ip, uint64_t bh_vector) {
        if (GLOBAL_HISTORY_LENGTH_USE == 32) {
            bh_vector ^= (bh_vector >> 16);
        } else if (GLOBAL_HISTORY_LENGTH_USE == 64) {
            bh_vector ^= (bh_vector >> 32);
            bh_vector ^= (bh_vector >> 16);
        }
        uint64_t hash = bh_vector & GLOBAL_HISTORY_LENGTH_MASK;
        hash ^= ip;
        hash ^= ip >> GS_HISTORY_TABLE_SIZE;
        hash ^= ip >> (GS_HISTORY_TABLE_SIZE * 2);
        return hash % GS_HISTORY_TABLE_SIZE;
    }

    uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) override {
        ip >>= 2;
        auto gs_hash = gs_table_hash(ip, branch_history_vector);
        auto& value = gs_history_table[gs_hash];
        uint8_t predict_taken = value.current() > (value.max() / 2);

// update
        value.update(taken);

        // update branch history vector
        branch_history_vector <<= 1;
        branch_history_vector |= taken;
        return predict_taken;
    }

        void dump_info() const override {

    }
};

/////////////////////////////


class GsharePlus : public BranchPredictor  {
public:
    uint64_t GLOBAL_HISTORY_LENGTH_MASK;
    uint64_t branch_history_vector;
    unordered_map<uint64_t, unordered_map<uint64_t, SaturatingCounter<2>>> table;
    GsharePlus(int GLOBAL_HISTORY_LENGTH_USE = 16) {
        this->GLOBAL_HISTORY_LENGTH_MASK = (1 << GLOBAL_HISTORY_LENGTH_USE) - 1;
    }

    uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) override {
        auto gs_hash = branch_history_vector & GLOBAL_HISTORY_LENGTH_MASK;
        auto& value = table[ip][gs_hash];
        uint8_t predict_taken = value.current() > (value.max() / 2);

// update
        value.update(taken);

        // update branch history vector
        branch_history_vector <<= 1;
        branch_history_vector |= taken;
        return predict_taken;
    }

    void dump_info() const override {
        uint64_t sum_ip = 0;
        uint64_t sum_sat = 0;
        for (auto& ip : table) {
            ++ sum_ip;
            sum_sat += ip.second.size();
        }
        fprintf(stderr, "sum_ip,%ld,sum_sat:%ld,ave:%f\n", sum_ip, sum_sat, (double)sum_sat / sum_ip);
    }
};



/////////////////////////////////////////////////////////////////////////////////////////////////////////////

class my_gentry            // TAGE global table entry
{
public:
    __uint128_t ghr;
    uint64_t tag;
    SaturatingCounter<3> ctr;
    int8_t u = 0;
};




struct Tage : public BranchPredictor {
    vector<vector<my_gentry>> tables;
    int table_num;
    size_t table_size;
    vector<size_t> table_ghr_len;
    vector<__uint128_t> table_ghr_mask;
    vector<size_t> table_hashed_ghr;
    vector<size_t> table_hashed_index;
    __int128_t ghr;
    size_t ghr_hash_len;


// stat
    vector<uint64_t> table_info_num_predict;
    vector<uint64_t> table_info_num_u_conflict;
    uint64_t timer_counter;

    Tage (int table_num, size_t table_size) {
        this->table_num = table_num;
        this->table_size = table_size;
        this->tables = vector<vector<my_gentry>>(table_num, vector<my_gentry>(table_size));

        ghr = 0;
        ghr_hash_len = 16;
        table_ghr_len = vector<size_t>(table_size, 0);
        table_ghr_len = {0, 4, 8, 16, 32, 64, 128};
        table_ghr_mask = {0, 0xf, 0xff, 0xffff, 0xffffffff, 0xffffffffffffffff, (__uint128_t)-1};
        table_hashed_ghr = vector<size_t>(table_size, 0);
        table_hashed_index = vector<size_t>(table_size, 0);


        table_info_num_predict = vector<uint64_t>(table_size, 0);
        table_info_num_u_conflict = vector<uint64_t>(table_size, 0);
        timer_counter = 0;
    }

    void update_table_hashed_ghr() {
        for (int i=0; i < table_num; i++) {
            size_t r = 0;
            switch (i) {
                case 0: r = 0x0; break;
                case 1: r = ghr & 0xf; break;
                case 2: r = ghr & 0xff; break;
                case 3: r = ghr & 0xffff; break;
                case 4: r = (ghr ^ ghr >> 16); r &= 0xffff; break;
                case 5: r = (ghr ^ ghr >> 32); r ^= (r >> 16); r &= 0xffff; break;
                case 6: r = (ghr ^ ghr >> 64); r ^= (r >> 32); r ^= (r >> 16); r &= 0xffff; break;
                default: assert(0);
            }
            table_hashed_ghr[i] = r;
        }
    }

    uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) override {
        // int reset_u_index = timer_counter % table_size;
        // for (int i=0; i < table_num; i++) {
        //     tables[i][reset_u_index].u = 0;
        // }
        ++ timer_counter;
        update_table_hashed_ghr();
        int long_index = -1;
        uint8_t predict_taken = 0;
        for (int i=table_num - 1; i >=0; i--) {
            table_hashed_index[i] = ((table_hashed_ghr[i] << 4) ^ (ip >> 2) ^ (ip >> 22)) & 0xfffff;
            if (tables[i][table_hashed_index[i]].tag == ip 
            && tables[i][table_hashed_index[i]].ghr == (table_ghr_mask[i] & ghr)
            ) {
                auto& value = tables[i][table_hashed_index[i]].ctr;
                predict_taken = value.current() > (value.max() / 2);
                long_index = i;
                value.update(taken);
                if (taken == predict_taken) {
                    ++ tables[i][table_hashed_index[i]].u;
                }
                break;
            }
        }

        if (long_index >= 0) {
            ++ table_info_num_predict[long_index];
        }

        if (predict_taken != taken) {
            for (int i=long_index + 1; i < table_num; i++) {
                if (tables[i][table_hashed_index[i]].u == 0 || (timer_counter % 4 == 1)) {
                    tables[i][table_hashed_index[i]].u = 0;
                    tables[i][table_hashed_index[i]].tag = ip;
                    tables[i][table_hashed_index[i]].ghr = (table_ghr_mask[i] & ghr);
                    auto& value = tables[i][table_hashed_index[i]].ctr;
                    value.update(taken);
                    break;
                } else {
                    ++ table_info_num_u_conflict[i];
                }
            }
        }

        ghr <<= 1;
        ghr |= taken;
        return predict_taken;
    }

    void dump_info() const override {
        vector<uint64_t> table_info_num_u(table_size, 0);
        uint64_t sum_table_info_num_predict = accumulate(table_info_num_predict.begin(), table_info_num_predict.end(), 0);
        for (int i=0; i < table_num; i++) {
            for (auto& entry: tables[i]) {
                table_info_num_u[i] += entry.u;
            }
            fprintf(stderr, "%.6f ", (double)table_info_num_u[i] / table_size);
        }
        fprintf(stderr, "\n");
        for (int i=0; i < table_num; i++) {
            fprintf(stderr, "%.6f ", (double)table_info_num_predict[i] / sum_table_info_num_predict);
        }
        fprintf(stderr, "\n");
        for (int i=0; i < table_num; i++) {
            fprintf(stderr, "%8ld ", table_info_num_u_conflict[i]);
        }
        fprintf(stderr, "\n");
    }




};

////////////////////////////////////////////////////////////////////////////////////////////

BranchPredictor* bp;


static void plugin_init(const qemu_info_t* info) {
    // printf("%s\n", info->target_name);
    cs_err err;
    for (int i = 0; all_archs[i].name; i++) {
        if (!strcmp(all_archs[i].name, info->target_name)) {
            target = &all_archs[i];
            err = cs_open(all_archs[i].arch, all_archs[i].mode, &cs_handle);
            if (!err) {
                cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
            } else {
                printf("csopen fail, %s\n", cs_strerror(err));
                abort();
            }
            break;
        }
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

void fill_insn_template(InsnData* insn, uint64_t pc,
                        const uint8_t* data, int size) {
    insn->pc = pc;
    insn->size = size;

    cs_insn *cs_insn;
    size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, pc, 1, &cs_insn);
    cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
    if (count == 1) {
        // int i;
        // fprintf(stderr, "%16lx: %-15s%s\n", addr, cs_insn[j].mnemonic, cs_insn[j].op_str);
        insn->branch_type = target->insn_is_branch(cs_insn);
        cs_err err = cs_regs_access(cs_handle, cs_insn, regs_read, &regs_read_count,
                            regs_write, &regs_write_count);
        if (!err) {
        } else {
            fprintf(stderr, "%s\n",  cs_strerror(err));
        }
        cs_free(cs_insn, count);
    } else {
        fprintf(stderr, "%8lx:", pc);
        for (int i = 0; i < size; i++) {
            fprintf(stderr, "%02x ", data[i]);
        }
        fprintf(stderr, "\n");
        // abort();
    }
}

void plugin_exit(qemu_plugin_id_t id, void* p) {
    uint64_t total_insn_num = 0;
    uint64_t total_num = 0;
    uint64_t total_other = 0;
    uint64_t total_num_hit = 0;
    for (const auto& pair : insn_code_data) {
        total_insn_num += pair.second.num;
        if (pair.second.branch_type == BRANCH_CONDITIONAL) {
            total_num += pair.second.num;
            total_num_hit += pair.second.hit_num;
            // fprintf(stderr, "pc:%lx cnt:%ld %.3f%%\n", pair.second.pc, pair.second.num, pair.second.hit_num / (double)pair.second.num * 100);
        } else if (
            pair.second.branch_type == BRANCH_DIRECT_JUMP ||
            pair.second.branch_type == BRANCH_INDIRECT ||
            pair.second.branch_type == BRANCH_CONDITIONAL ||
            pair.second.branch_type == BRANCH_DIRECT_CALL ||
            pair.second.branch_type == BRANCH_INDIRECT_CALL ||
            pair.second.branch_type == BRANCH_RETURN
        ) {
            total_other += pair.second.num;
        }
    }

    char buf[1024];
    sprintf(buf, "insn_num,%ld,c_branch_num:%ld,c_branch_miss_num:%ld,total_miss_rate,%.6f%%,mpki,%.6f\n", total_insn_num, total_num, (total_num - total_num_hit), (1 - total_num_hit / (double)total_num) * 100, (total_num - total_num_hit) * 1000.0 / total_insn_num);
    bp->dump_info();
    qemu_plugin_outs(buf);
    cs_close(&cs_handle);
}

InsnData initInsnData;
static InsnData* last_br_insn = &initInsnData;
static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    InsnData* current_insn_data = (InsnData*)userdata;
    if (last_br_insn->branch_type == BRANCH_CONDITIONAL) {
        int taken = last_br_insn->pc + last_br_insn->size != current_insn_data->pc;
        last_br_insn->hit_num += bp->predict_branch(last_br_insn->pc, current_insn_data->pc, taken, last_br_insn->branch_type) == taken;
    }
    current_insn_data->num ++;
    last_br_insn = current_insn_data;
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);
    uint8_t insn_binary[16];
    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
        size_t insn_size = qemu_plugin_insn_size(insn);
#if QEMU_PLUGIN_VERSION == 2
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
#else
        if (qemu_plugin_insn_data(insn, insn_binary, insn_size) != insn_size) {
            fprintf(stderr, "lxy:%s:%s:%d qemu_plugin_insn_data failed\n", __FILE__,__func__,__LINE__);
        }
        const uint8_t* data = (uint8_t*)&insn_binary;
#endif
        auto insn_data = insn_code_data.find(insn_vaddr);
        if (insn_data == insn_code_data.end()) {
            auto r = insn_code_data.insert({insn_vaddr, InsnData()});
            insn_data = r.first;
            fill_insn_template(&insn_data->second, insn_vaddr, data, insn_size);
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                QEMU_PLUGIN_CB_NO_REGS,
                                                (void*)&insn_data->second);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    plugin_init(info);

    string bench_name = find_arg_or_else(argc,argv,"bp","bimodal");
    if (bench_name == "bimodal") {
        bp = new Bimodal<2>();
    } else if (bench_name == "gshare") {
        bp = new Gshare();
    } else if (bench_name == "gshare_plus") {
        bp = new GsharePlus();
    } else if (bench_name == "tage") {
        bp = new Tage(7, 1 << 20);
    } else {
        fprintf(stderr, "unknown %s\n", bench_name.c_str());
        fprintf(stderr, "avaliable: bimodal,gshare,gshare_plus,tage. chioce:%s\n", bench_name.c_str());
        abort();
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
