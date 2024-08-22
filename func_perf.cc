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
map <string, uint64_t> func_info;

static void plugin_init(const qemu_info_t *info) {

}
// Comparator function to sort pairs
// according to second value
bool cmp(pair<string, uint64_t> a,
        pair<string, uint64_t> b)
{
    return a.second > b.second;
}
 
// Function to sort the map according
// to value in a (key-value) pairs
void sort(map<string, uint64_t>& M)
{
    // Declare vector of pairs
    vector<pair<string, uint64_t> > A;
    // Copy key-value pair from Map
    // to vector of pairs
    for (auto& it : M) {
        A.push_back(it);
    }
    // Sort using comparator function
    stable_sort(A.begin(), A.end(), cmp);
    // Print the sorted value
    for (auto& it : A) {
        // cout << it.first << ' '
            // << it.second << endl;
    char buf[1024];
        sprintf(buf, "%s,%ld\n", it.first.c_str(), it.second);qemu_plugin_outs(buf);
    }
}
void plugin_exit(qemu_plugin_id_t id, void *p) {
    sort(func_info);
}

#if QEMU_PLUGIN_VERSION != 2
static void tb_exec_dummy_inline(unsigned int cpu_index, void *udata)
{
    ++ *(uint64_t*)udata;
}
#endif

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);
    const char* symbol = qemu_plugin_insn_symbol(qemu_plugin_tb_get_insn(tb, 0));

    string ss = "UNKNOW";
    if (symbol) {
        ss = symbol;
    }

    if (!func_info.count(ss)) {
        func_info[ss] = 0;
    }

#if QEMU_PLUGIN_VERSION == 2
    qemu_plugin_register_vcpu_tb_exec_inline(tb,QEMU_PLUGIN_INLINE_ADD_U64, &func_info[ss], insns);
#else
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_dummy_inline, QEMU_PLUGIN_CB_NO_REGS, (void*)&func_info[ss]);
#endif
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
