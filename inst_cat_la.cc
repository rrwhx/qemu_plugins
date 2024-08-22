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

#include <glib.h>

extern "C" {
#include "qemu-plugin.h"
}

#include "loongarch_decode_insns.c.inc"


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void xyprintf(const char* format, ...) {
    char buf[1024];
    va_list argptr;

    va_start(argptr, format);
    vsprintf(buf, format, argptr);
    // snprintf(buf, 1024, format, argptr);
    // vfprintf(stderr, format, argptr);
    qemu_plugin_outs(buf);
    va_end(argptr);
}

uint64_t cat_count[LA_INST_END];

static void plugin_init(const qemu_info_t *info) {
    // fprintf(stderr, "%s\n", info->target_name);
}
void plugin_exit(qemu_plugin_id_t id, void *p) {
    for (int i = LA_INST_BEGIN; i < LA_INST_END; i++) {
        xyprintf("%s,%ld\n", la_op_name[i], cat_count[i]);
    }
}

// static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
//     cs_insn* insn = (cs_insn*)userdata;
//     xyprintf("[unknown] %16lx: id:%d %x %-15s%s\n",  insn->address, insn->id, *(int*)(insn->bytes), insn->mnemonic, insn->op_str);
// }

#if QEMU_PLUGIN_VERSION != 2
static void tb_exec_dummy_inline(unsigned int cpu_index, void *udata)
{
    ++ *(uint64_t*)udata;
}
#endif

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
#if QEMU_PLUGIN_VERSION == 2
            const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
#else
            uint32_t insn_binary;
            if (qemu_plugin_insn_data(insn, &insn_binary, 4) != 4) {
                fprintf(stderr, "lxy:%s:%s:%d qemu_plugin_insn_data failed\n", __FILE__,__func__,__LINE__);
            }
            const uint8_t* data = (uint8_t*)&insn_binary;
#endif
        LA_DECODE la_decode = {};
        decode(&la_decode, *data);
#if QEMU_PLUGIN_VERSION == 2
        qemu_plugin_register_vcpu_insn_exec_inline(insn, QEMU_PLUGIN_INLINE_ADD_U64, (void*)&cat_count[la_decode.id], 1);
#else
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_dummy_inline, QEMU_PLUGIN_CB_NO_REGS, (void*)&cat_count[la_decode.id]);
#endif
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
