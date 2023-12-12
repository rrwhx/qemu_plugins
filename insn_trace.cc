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

#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4

using namespace std;


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
uint64_t tb_trans_count;
uint64_t insn_count;
uint64_t ld_count;
uint64_t st_count;

static void plugin_init(const qemu_info_t* info) {
}
static void plugin_exit(qemu_plugin_id_t id, void* p) {
    fprintf(stderr, "tb_trans_count:%ld, insn_count:%ld, ld_count:%ld, st_count:%ld\n", tb_trans_count, insn_count, ld_count, st_count);
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    ++ insn_count;
    printf("cpu:%d, pc:%p\n", vcpu_index, userdata);
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    bool is_st = qemu_plugin_mem_is_store(info);
    if (is_st) {
        ++ st_count;
    } else {
        ++ ld_count;
    }
    printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
            userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    ++ tb_trans_count;
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)addr);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, (void*)addr);
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
