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
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

uint64_t icount;
void plugin_exit(qemu_plugin_id_t id, void *p)
{
    char buf[1024];
    sprintf(buf, "%ld\n", icount);
    qemu_plugin_outs(buf);
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    ++ icount;
}

static void vcpu_tb_exec(unsigned int vcpu_index, void* userdata) {
    icount += (intptr_t)userdata;
}

static void tb_record_insn_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
    }
}

static void tb_record_insn_inline(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < insns; i ++) {
        qemu_plugin_register_vcpu_tb_exec_inline(tb,QEMU_PLUGIN_INLINE_ADD_U64, (void*)&icount, 1);
    }
}

static void tb_record_tb_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, (void*)qemu_plugin_tb_n_insns(tb));
}
static void tb_record_tb_inline(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    qemu_plugin_register_vcpu_tb_exec_inline(tb,QEMU_PLUGIN_INLINE_ADD_U64, (void*)&icount, qemu_plugin_tb_n_insns(tb));
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    if (!argc) {
        qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record_tb_inline);
    }
    for (int i = 0; i < argc; i++) {
        qemu_plugin_outs(argv[i]);
        qemu_plugin_outs("\n");
        char *p = strchr(argv[i], '=');
        if (p) {
            if (strncmp(argv[i], "icount", p - argv[i]) == 0){
                ++p;
                if        (strcmp(p, "insn_inline")  == 0) { qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record_insn_inline);
                } else if (strcmp(p, "insn_cb")      == 0) { qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record_insn_cb);
                } else if (strcmp(p, "tb_inline")    == 0) { qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record_tb_inline);
                } else if (strcmp(p, "tb_cb")        == 0) { qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record_tb_cb);
                } else {
                    qemu_plugin_outs("unsupported icount ");
                    qemu_plugin_outs(p);
                    qemu_plugin_outs("\n");
                    qemu_plugin_outs("icount=[insn_inline|insn_cb|tb_inline|tb_cb]");
                    exit(0);
                }
            }
        }
    }
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
