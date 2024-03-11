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
extern "C" {
#include "qemu-plugin.h"
}

using namespace  std;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
#define INSN_SIZE_MAX 16
uint64_t insn_size_info[INSN_SIZE_MAX];
static void plugin_init(const qemu_info_t *info) {

}
void plugin_exit(qemu_plugin_id_t id, void *p) {
    uint64_t icount = 0;
    uint64_t icount_size = 0;
    for (int i = 0; i < INSN_SIZE_MAX; i++) {
        icount += insn_size_info[i];
        icount_size += (i + 1) * insn_size_info[i];
    }
    for (int i = 0; i < INSN_SIZE_MAX; i++) {
        double ratio = (double)insn_size_info[i] / icount;
        // fprintf(stderr, "%2d, %12ld, %.3f\n", i + 1, insn_size_info[i], (double)insn_size_info[i] / icount);
        fprintf(stderr, "%2d, %12ld, %.3f, ", i + 1, insn_size_info[i], ratio);
        for (int i = 0; i < (int)(ratio * 100); i++){
            fprintf(stderr, "|");
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "%ld, %ld, %.3f\n", icount, icount_size, (double)icount_size / icount);
}


static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        size_t size = qemu_plugin_insn_size(insn);
        if (size <= INSN_SIZE_MAX) {
            qemu_plugin_register_vcpu_tb_exec_inline(tb,QEMU_PLUGIN_INLINE_ADD_U64, (void*)(insn_size_info + size - 1), 1);
        } else {
            uint64_t addr = qemu_plugin_insn_vaddr(insn);
            const char* insn_data = (char*)qemu_plugin_insn_data(insn);
            fprintf(stderr, "skip %lx \n", addr);
            for (size_t i = 0; i < size; i++) {
                fprintf(stderr, "%01x\n", insn_data[i]);
            }
            fprintf(stderr, "\n");
        }
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    fprintf(stderr, "cpu %d created\n", vcpu_index);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    plugin_init(info);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    return 0;
}
