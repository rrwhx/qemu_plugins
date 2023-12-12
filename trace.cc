#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <map>

#include <fcntl.h>
#include <sys/mman.h>

#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4

using namespace std;

typedef struct qemu_trace {
    __int128_t insn_code;

    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
    unsigned long long int ip;  // instruction pointer (program counter) value
} qemu_trace_t;


typedef __int128 insn_code;
// typedef uint64_t insn_code;

typedef struct {
    uint64_t pc;
    insn_code code;
} InsnData;

insn_code insn_code_init(uint64_t pc, const uint8_t* data, int size) {
    insn_code r = 0;
    memcpy(&r, data, size);
    r |= (__int128)size << 120;
    return r;
}

map<uint64_t, InsnData*> insn_code_data;


int64_t REAL_INSN_COUNT;
int64_t TRACE_COUNT = 10000;
int64_t TRACE_SKIP_COUNT = 10000;
const char* trace_filename;
int trace_fd;
uint64_t filesize;
qemu_trace_t* trace_buffer;
int64_t trace_buffer_index = -1;

static void plugin_init(const qemu_info_t* info) {
    fprintf(stderr, "sizeof(qemu_trace_t):%zu\n", sizeof(qemu_trace_t));
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
        trace_filename = "qemu_trace.data";
    }
    filesize = TRACE_COUNT * sizeof(qemu_trace_t);
    trace_fd = open(trace_filename, O_RDWR | O_CREAT, (mode_t)0600);
    if (trace_fd < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    int r = ftruncate(trace_fd, TRACE_COUNT * sizeof(qemu_trace_t));
    if (r < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }

    trace_buffer = (qemu_trace_t*)mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, trace_fd, 0);

    if (trace_buffer == MAP_FAILED) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    close(trace_fd);
}

void plugin_exit(qemu_plugin_id_t id, void* p) {
    if (trace_buffer_index >=0 && trace_buffer_index < TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        int r = truncate(trace_filename, trace_buffer_index * sizeof(qemu_trace_t));
        if (r < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        }
    }
    fprintf(stderr, "plugin fini, trace ok\n");
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    ++ REAL_INSN_COUNT;
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    InsnData* p = (InsnData*)userdata;
    ++ trace_buffer_index;
    if (trace_buffer_index == TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        fprintf(stderr, "trace ok\n");
    } else if (trace_buffer_index < TRACE_COUNT) {
        trace_buffer[trace_buffer_index].insn_code = p->code;
        trace_buffer[trace_buffer_index].ip = p->pc;
    }
    printf("cpu:%d, pc:%lx\n", vcpu_index, p->pc);
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    qemu_trace_t* p = trace_buffer + trace_buffer_index;
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
    }
    printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
            userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
        int size = qemu_plugin_insn_size(insn);
        insn_code ic = insn_code_init(addr, data, size);
        if (insn_code_data.count(addr) == 0) {
            InsnData* insn_template =
                (InsnData*)malloc(sizeof(InsnData));
            insn_code_data[addr] = insn_template;
        }
        auto& insn_data = insn_code_data[addr];
        insn_data->pc = addr;
        insn_data->code = ic;

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                QEMU_PLUGIN_CB_NO_REGS,
                                                (void*)insn_code_data[addr]);
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
