#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <mutex>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>
#include <glib.h>
extern "C" {
#include "qemu-plugin.h"
}

using namespace std;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void plugin_init(const qemu_info_t *info) {
}

/* Information about a translated block */
typedef struct {
    uint64_t head_pc;
    uint64_t tail_pc;
    int indirect_type;
} BlockInfo;

thread_local uint64_t ind_cnt;
thread_local uint64_t ind_miss;
thread_local uint64_t call_ind_cnt;
thread_local uint64_t call_ind_miss;
thread_local uint64_t jump_ind_cnt;
thread_local uint64_t jump_ind_miss;
thread_local uint64_t last_pc;

void plugin_exit(qemu_plugin_id_t id, void *p)
{
    char buf[1024];
    sprintf(buf, "%ld,%ld,%ld,%ld\n", call_ind_cnt, call_ind_miss, jump_ind_cnt, jump_ind_miss);qemu_plugin_outs(buf);
}
static void vcpu_tb_exec(unsigned int cpu_index, void *udata) {
    BlockInfo *bi = (BlockInfo *) udata;
    if (last_pc) {
        int ind_type = last_pc & 0x3;
        last_pc &= ~0x3;
        if (ind_type == 1) {
            // ind_miss += (last_pc +4 == bi->head_pc);
            call_ind_miss += (last_pc +4 == bi->head_pc);
        } else if (ind_type == 2) {
            // ind_miss += (last_pc +4 != bi->head_pc);
            jump_ind_miss += (last_pc +4 != bi->head_pc);
        }
    }
    if (bi->indirect_type) {
        // ++ ind_cnt;
        last_pc = bi->tail_pc | bi->indirect_type;
        if (bi->indirect_type == 1) {
            call_ind_cnt ++;
        } else {
            jump_ind_cnt ++;
        }
    } else {
        last_pc = 0;
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);

    vector <struct qemu_plugin_insn*> insn_list;
    vector <uint32_t> insn_code_list;

    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        insn_list.push_back(insn);
        insn_code_list.push_back(*(uint32_t*)qemu_plugin_insn_data(insn));
        // int size = qemu_plugin_insn_size(insn);
    }
    BlockInfo *bi = g_new0(BlockInfo, 1);
    bi->head_pc = qemu_plugin_insn_vaddr(insn_list[0]);
    if (insns >= 5) {
        bi->tail_pc = qemu_plugin_insn_vaddr(insn_list[insns - 1]);
        if (
                (insn_code_list[insns - 5] & 0xfffffc00) == 0x927c2000 &&
                (insn_code_list[insns - 4] & 0xff200000) == 0x8b000000 &&
                (insn_code_list[insns - 3] & 0xffff8000) == 0xa9400000 &&
                (insn_code_list[insns - 2] & 0xffe0fc1f) == 0xeb00001f &&
                (insn_code_list[insns - 1] & 0xff00001f) == 0x54000000
        ) {
            bi->indirect_type = 1;
        }
        if (
                (insn_code_list[insns - 5] & 0xfffffc00) == 0x927e2000 &&
                (insn_code_list[insns - 4] & 0xff200000) == 0x8b000000 &&
                (insn_code_list[insns - 3] & 0xffff8000) == 0xa9400000 &&
                (insn_code_list[insns - 2] & 0xffe0fc1f) == 0xeb00001f &&
                (insn_code_list[insns - 1] & 0xff00001f) == 0x54000001
        ) {
            bi->indirect_type = 2;
        }
    } else {
        bi->tail_pc = 0;
        bi->indirect_type = false;
    }

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, (void *)bi);
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
