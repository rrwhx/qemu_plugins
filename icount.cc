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
#include <capstone/capstone.h>
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

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    qemu_plugin_register_vcpu_tb_exec_inline(tb,QEMU_PLUGIN_INLINE_ADD_U64, (void*)&icount, qemu_plugin_tb_n_insns(tb));
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
