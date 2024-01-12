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

extern "C" {
#include "qemu-plugin.h"
}

#include "loongarch_decode_insns.c.inc"


using namespace std;

#define NUM_INSTR_DESTINATIONS 1
#define NUM_INSTR_SOURCES 3


typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value
    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
    unsigned long long ret_val;
    unsigned int inst;
    //unsigned short op;
    unsigned char is_branch;    // is this branch
    unsigned char branch_taken; // if so, is this taken

    unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers
} trace_instr_format_t;

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
        case NOT_BRANCH:            return "";
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

void dump_trace(trace_instr_format_t& t) {
    const char* taken = "";
    if (t.is_branch) {
        if (t.branch_taken) {
            taken = "taken";
        } else {
            taken = "not taken";
        }
    }
    fprintf(stderr, "ip:%-1llx %-10s %-15s", t.ip, taken, branch_type(t.is_branch));
    string reg_str("register: ");
    for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
        if (t.destination_registers[i]) {
            reg_str += to_string(t.destination_registers[i]);
            reg_str += " ";
        }
    }

    if (t.destination_registers[0]) {
        stringstream stream;
        stream << std::hex << t.ret_val;
        reg_str += "(0x" + stream.str() + ")";
    }

    reg_str += " <= ";
    for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
        if (t.source_registers[i]) {
            reg_str += to_string(t.source_registers[i]);
            reg_str += " ";
        }
    }

    fprintf(stderr, "%-27s ", reg_str.c_str());

    if (t.destination_memory[0]) {
        fprintf(stderr, "write memory:");
        for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
            if (t.destination_memory[i]) {
                fprintf(stderr, "%llx ", t.destination_memory[i]);
            } else {
                fprintf(stderr, " ");
            }
        }
    }

    if (t.source_memory[0]) {
        fprintf(stderr, "read memory:");
        for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
            if (t.source_memory[i]) {
                fprintf(stderr, "%llx ", t.source_memory[i]);
            } else {
                fprintf(stderr, " ");
            }
        }
    }
    fprintf(stderr, "\n");


}


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

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



int la_inst_branch_type(LA_DECODE& la_decode) {
    switch (la_decode.id) {
        case LA_INST_B:
            return BRANCH_DIRECT_JUMP;
        case LA_INST_BCEQZ:
        case LA_INST_BCNEZ:
        case LA_INST_BEQZ:
        case LA_INST_BNEZ:
        case LA_INST_BEQ:
        case LA_INST_BNE:
        case LA_INST_BLT:
        case LA_INST_BGE:
        case LA_INST_BLTU:
        case LA_INST_BGEU:
            return BRANCH_CONDITIONAL;
        case LA_INST_BL:
            return BRANCH_DIRECT_CALL;
        case LA_INST_JIRL:
            if (la_decode.op[0].val == 1) {
                return BRANCH_INDIRECT_CALL;
            } else if (la_decode.op[1].val == 1) {
                return BRANCH_RETURN;
            } else {
                return BRANCH_INDIRECT;
            }
        default:
            return NOT_BRANCH;
    }
    return NOT_BRANCH;
}

bool verbose;
bool early_exit;
static void plugin_init(const qemu_info_t* info) {
    if (strcmp(info->target_name, "loongarch64")!=0) {
        fprintf(stderr, "only support qemu-loongarch64\n");
        exit(0);
    }
#ifndef QEMU_PLUGIN_HAS_ENV_PTR
    fprintf(stderr, "your qemu plugin does not support env_ptr, ret_val can not be record\n");
#endif
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
}

int encode_reg(LA_OP op) {
    if (op.type == LA_OP_GPR) {
        return op.val;
    } else if (op.type == LA_OP_FR || op.type == LA_OP_VR || op.type == LA_OP_XR) {
        return op.val + 32;
    } else if (op.type == LA_OP_FCC) {
        return op.val + 64;
    }
    return 0;
}

void fill_insn_template(trace_instr_format* insn, uint64_t pc,
                        const uint8_t* data, int size) {
    insn->ip = pc;
    insn->branch_taken = size;
    insn->inst = *(uint32_t*)data;
    LA_DECODE la_decode;
    decode(&la_decode, *(uint32_t*)data);
    // char buf[1024];
    // la_inst_str(&la_decode, buf);
    // fprintf(stderr, "%s\n", buf);
    insn->is_branch = la_inst_branch_type(la_decode);
    insn->ret_val = 0;
    if (la_inst_is_branch_not_link(la_decode.id) || la_inst_is_st(la_decode.id)) {
        for (int i = 0; i < min(la_decode.opcnt, NUM_INSTR_SOURCES); i++) {
            insn->source_registers[i] = encode_reg(la_decode.op[i]);
        }
    } else {
        if (la_decode.opcnt >= 1 && la_decode.op[0].type == LA_OP_GPR) {
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
            insn->ret_val = la_decode.op[0].val;
#endif
        }
        if (la_decode.opcnt >= 1) {
            insn->destination_registers[0] = encode_reg(la_decode.op[0]);
        }

        for (int i = 0; i < min(la_decode.opcnt - 1, NUM_INSTR_SOURCES); i++) {
            insn->source_registers[i] = encode_reg(la_decode.op[i + 1]);
        }
    }
}

void plugin_exit(qemu_plugin_id_t id, void* p) {
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
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
        uint64_t* env = (uint64_t*)qemu_plugin_env_ptr();
        t->ret_val = env[t->ret_val];
#endif
        if (verbose) {
            dump_trace(*t);
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
        // if (verbose) {
        //     printf("cpu:%d, pc:%llx, is_branch:%d\n", vcpu_index, p->ip, p->is_branch);
        // }
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
        // if (verbose) {
        //     printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
        //             userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
        // }
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
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
