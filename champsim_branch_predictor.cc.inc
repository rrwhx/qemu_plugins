#include <algorithm>
#include <numeric>
#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <deque>
#include <bitset>
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
#include <math.h>

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



class O3_CPU {
public:
    int cpu;
    O3_CPU(int cpu = 0) : cpu(cpu) {};
    void initialize_branch_predictor();
    uint8_t predict_branch(uint64_t pc);
    void last_branch_result(uint64_t pc, uint64_t branch_target, uint8_t taken, uint8_t branch_type);
};



#include CHAMPSIM_BRANCH_PREDICTOR



////////////////////////////////////////////////////////////////////////////////////////////

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
    // bp->dump_info();
    qemu_plugin_outs(buf);
    cs_close(&cs_handle);
}

O3_CPU* cpu;
uint8_t predict_branch(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) {
    uint8_t predict = cpu->predict_branch(ip);
    cpu->last_branch_result(ip, branch_target, taken, branch_type);
    return predict;
}


InsnData initInsnData;
static InsnData* last_br_insn = &initInsnData;
static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    InsnData* current_insn_data = (InsnData*)userdata;
    if (last_br_insn->branch_type == BRANCH_CONDITIONAL) {
        int taken = last_br_insn->pc + last_br_insn->size != current_insn_data->pc;
        last_br_insn->hit_num += predict_branch(last_br_insn->pc, current_insn_data->pc, taken, last_br_insn->branch_type) == taken;
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

    cpu = new O3_CPU();
    cpu->initialize_branch_predictor();

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

