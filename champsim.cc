#include <algorithm>
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

#include <fcntl.h>
#include <sys/mman.h>

#include <capstone/capstone.h>
#if CS_NEXT_VERSION < 6
#error "capstone version mismatch"
#endif
extern "C" {
#include "qemu-plugin.h"
}

#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4

using namespace std;

typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value

    unsigned char is_branch;    // is this branch
    unsigned char branch_taken; // if so, is this taken

    unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
} trace_instr_format_t;


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
csh cs_handle;
uint64_t* reg_count;

enum inst_cat {
    INST_ARITH, // add, sub
    INST_LOGIC, // and, or, xor
    INST_SHIFT, // and, or, xor
    INST_MUL, // mul, div
    INST_REG_MOV, // mov reg2reg
    INST_LOAD, // load
    INST_STORE, // store
    INST_BRANCH, // beq a0, a1, #111
    INST_CAC_CC, // cmp, test
    INST_BRANCH_CC, // je, jg
    INST_DIRECT_CALL, // call 16
    INST_INDIRECT_CALL, // call rax
    INST_RET, // ret, jirl r0, r1, 0
    INST_INDIRECT_JMP, // jmp rax, jirl r0, r11, 0
    INST_VEC_LOAD,
};


// typedef __int128 insn_code;
typedef uint64_t insn_code;

insn_code insn_code_init(uint64_t pc, const uint8_t* data, int size) {
    // insn_code r = 0;
    // for (size_t i = 0; i < size; i++)
    // {
    //     r <<= 8;
    //     r |= data[i];
    // }
    // return r;
    return pc;
}

map<insn_code, void*> insn_code_data;

// trace_instr_format_t curr_instr;

int64_t REAL_INSN_COUNT;
int64_t TRACE_COUNT = 10000;
int64_t TRACE_SKIP_COUNT = 10000;
const char* trace_filename;
int trace_fd;
uint64_t filesize;
trace_instr_format_t* trace_buffer;
int64_t trace_buffer_index = -1;

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

int x64_insn_is_branch(const cs_insn * insn) {
    switch (insn->id)
    {
    case X86_INS_JAE ... X86_INS_JS:
    case X86_INS_LOOPNE:
    case X86_INS_LOOPE:
    case X86_INS_LOOP:

    case X86_INS_JMP:
    case X86_INS_LJMP:
    case X86_INS_CALL:
    case X86_INS_LCALL:
    case X86_INS_RET:
    case X86_INS_IRET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return 1;
    default:
        return 0;
    }
    return 0;
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
    switch (insn->id)
    {
    case LOONGARCH_INS_B:
    case LOONGARCH_INS_BL:
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
    case LOONGARCH_INS_JIRL:
    case LOONGARCH_INS_JISCR0:
    case LOONGARCH_INS_JISCR1:
        return 1;
    default:
        return 0;
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
static void plugin_init(const qemu_info_t* info) {
    fprintf(stderr, "sizeof(trace_instr_format):%zu\n",
            sizeof(trace_instr_format));
    if (getenv("VERBOSE")) {
        verbose = true;
    }
    if (getenv("EARLY_EXIT")) {
        early_exit = true;
    }
    const char* TRACE_COUNT_ENV = getenv("TRACE_COUNT");
    if (TRACE_COUNT_ENV) {
        TRACE_COUNT = atoll(TRACE_COUNT_ENV);
    }

    const char* TRACE_SKIP_COUNT_ENV = getenv("TRACE_SKIP_COUNT");
    if (TRACE_SKIP_COUNT_ENV) {
        TRACE_SKIP_COUNT = atoll(TRACE_SKIP_COUNT_ENV);
    }

    trace_filename = getenv("TRACE_FILENAME");
    if (!trace_filename) {
        trace_filename = "champsim.trace";
    }
    filesize = TRACE_COUNT * sizeof(trace_instr_format_t);
    trace_fd = open(trace_filename, O_RDWR | O_CREAT, (mode_t)0600);
    if (trace_fd < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    int r = ftruncate(trace_fd, TRACE_COUNT * sizeof(trace_instr_format_t));
    if (r < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }

    trace_buffer = (trace_instr_format_t*)mmap(
        0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, trace_fd, 0);

    if (trace_buffer == MAP_FAILED) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    close(trace_fd);

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

void fill_insn_template(trace_instr_format* insn, uint64_t pc,
                        const uint8_t* data, int size) {
    insn->ip = pc;
    insn->branch_taken = size;

    cs_insn *cs_insn;
    size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, pc, 1, &cs_insn);
    cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
    if (count == 1) {
        int i;
        // fprintf(stderr, "%16lx: %-15s%s\n", addr, cs_insn[j].mnemonic, cs_insn[j].op_str);
        insn->is_branch = target->insn_is_branch(cs_insn);
        cs_err err = cs_regs_access(cs_handle, cs_insn, regs_read, &regs_read_count,
                            regs_write, &regs_write_count);
        if (!err) {
            for (i = 0; i < min((int)regs_read_count, NUM_INSTR_SOURCES); i++) {
                insn->source_registers[i] = regs_read[i];
            }
            for (i = 0; i < min((int)regs_write_count, NUM_INSTR_DESTINATIONS); i++) {
                insn->destination_registers[i] = regs_write[i];
            }
            // if (regs_read_count) {
            //     printf("\tRegisters read:");
            //     for (i = 0; i < regs_read_count; i++) {
            //         printf(" %s", cs_reg_name(cs_handle, regs_read[i]));
            //     }
            //     printf("\n");
            // }

            // if (regs_write_count) {
            //     printf("\tRegisters modified:");
            //     for (i = 0; i < regs_write_count; i++) {
            //         printf(" %s", cs_reg_name(cs_handle, regs_write[i]));
            //     }
            //     printf("\n");
            // }
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
    cs_close(&cs_handle);
    if (trace_buffer_index < TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        int r = truncate(trace_filename, min((uint64_t)trace_buffer_index, (uint64_t)TRACE_COUNT) *
                                    sizeof(trace_instr_format_t));
        if (r < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        }
    }
    fprintf(stderr, "plugin fini, trace fini\n");
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    ++ REAL_INSN_COUNT;
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    if (REAL_INSN_COUNT == TRACE_SKIP_COUNT + 1) {
        fprintf(stderr, "trace start\n");
    }
    trace_instr_format* p = (trace_instr_format*)userdata;
    if (trace_buffer_index >= 0 && trace_buffer_index < TRACE_COUNT) {
        trace_instr_format* t = trace_buffer + trace_buffer_index;
        if (t->ip + t->branch_taken != p->ip) {
            t->branch_taken = 1;
        } else {
            t->branch_taken = 0;
        }
        // fprintf(stderr, "cpu:%d, las_pc:%lx, size:%d, curr_pc:%lx, branch_taken:%d\n", vcpu_index, t->ip , t->branch_taken , p->ip, t->branch_taken);
    }
    ++ trace_buffer_index;
    if (trace_buffer_index == TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        fprintf(stderr, "trace fini\n");
        if (early_exit) {
            exit(0);
        }
    } else if (trace_buffer_index < TRACE_COUNT) {
        trace_buffer[trace_buffer_index] = *p;
        if (verbose) {
            printf("cpu:%d, pc:%llx, is_branch:%d\n", vcpu_index, p->ip, p->is_branch);
        }
    }
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    trace_instr_format_t* p = trace_buffer + trace_buffer_index;
    bool is_st = qemu_plugin_mem_is_store(info);
    if (trace_buffer_index < TRACE_COUNT) {
        if (is_st) {
            for (size_t i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
                if (p->destination_memory[i] == 0) {
                    p->destination_memory[i] = vaddr;
                    break;
                }
            }
        } else {
            for (size_t i = 0; i < NUM_INSTR_SOURCES; i++) {
                if (p->source_memory[i] == 0) {
                    p->source_memory[i] = vaddr;
                    break;
                }
            }
        }
        if (verbose) {
            printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
                    userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);

        }
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
#if QEMU_PLUGIN_VERSION == 2
            const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
#else
            uint32_t insn_binary;
            if (qemu_plugin_insn_data(insn, &insn_binary, 4) != 4) {
                fprintf(stderr, "lxy:%s:%s:%d qemu_plugin_insn_data failed\n", __FILE__,__func__,__LINE__);
            }
            const uint8_t* data = (uint8_t*)&insn_binary;
#endif
        int size = qemu_plugin_insn_size(insn);
        insn_code ic = insn_code_init(addr, data, size);
        if (insn_code_data.count(ic) == 0) {
            trace_instr_format* insn_template =
                (trace_instr_format*)aligned_alloc(64,
                                                   sizeof(trace_instr_format));
            memset(insn_template, 0, sizeof(trace_instr_format));
            fill_insn_template(insn_template, addr, data, size);
            insn_code_data[ic] = insn_template;
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                QEMU_PLUGIN_CB_NO_REGS,
                                                (void*)insn_code_data[ic]);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, (void*)addr);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    plugin_init(info);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
