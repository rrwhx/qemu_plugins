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

#include <sys/stat.h>

extern "C" {
#include "qemu-plugin.h"
}

#include "util.h"

using namespace std;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t interval_size = 100000000;
static std::string bench_name;
static FILE* bbv_file;
static FILE* pc_info_file;
static FILE* log_file;
static FILE* syscall_file;

uint64_t icount;
uint64_t bbcount;
uint64_t unique_trans_id;
static uint64_t inst_end;

static void plugin_init(const qemu_info_t* info)
{
    mkdir(bench_name.c_str(), 0777);
    bbv_file = fopen_nofail((bench_name + "/bbv").c_str(), "w");
    pc_info_file = fopen_nofail((bench_name + "/pc_info.txt").c_str(), "w");
    log_file = fopen_nofail((bench_name + "/log.txt").c_str(), "w");
    syscall_file = fopen_nofail((bench_name + "/syscall.txt").c_str(), "w");
    inst_end = interval_size;

    fprintf(log_file, "target_arch:%s\n",info->target_name);
    fflush(log_file);
}

void plugin_exit(qemu_plugin_id_t id, void *p)
{
    fclose(bbv_file);
    fclose(pc_info_file);
    fprintf(log_file, "icount:%ld\n",icount);
    fprintf(log_file, "tb_count:%ld\n",unique_trans_id);
    fclose(log_file);
    fclose(syscall_file);
    char buf[1024];
    sprintf(buf, "%ld\n", icount);
    qemu_plugin_outs(buf);
}

struct id_count {
    uint64_t id;
    uint64_t bbicount;
    uint64_t count;
};

map <uint64_t, id_count> pc_id_count;

static void dump_bbv(){
    fprintf(bbv_file, "T");
    for(auto i = pc_id_count.begin();i != pc_id_count.end();i ++){
        if(i->second.count > 0){
            fprintf(bbv_file, ":%ld:%ld ", i->second.id, i->second.count *  i->second.bbicount);
            i->second.count = 0;
        }
    }
    fprintf(bbv_file, "\n");
    return;
}

static void tb_exec(unsigned int cpu_index, void *udata)
{
    (*(uint64_t*)udata) ++;
    if (icount >= inst_end) {
        inst_end += interval_size;
        dump_bbv();
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc    = qemu_plugin_tb_vaddr(tb);
    size_t   insns = qemu_plugin_tb_n_insns(tb);
    void* udata = NULL;
    if (!pc_id_count.count(pc)) {
        // ExecCount* inserted = &hotblocks[feat];
        id_count &t = pc_id_count[pc];
        t.count = 0;
        t.bbicount = insns;
        t.id = unique_trans_id;
        unique_trans_id ++;
        fprintf(pc_info_file, "id:%ld, pc:%lx, bb_insn_num:%ld\n", t.id, pc, t.bbicount);
    }
    udata = (void*)&(pc_id_count[pc].count);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &icount, insns);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS, udata);
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    fprintf(syscall_file, "icount:%ld, syscall #%" PRIi64 "\n", icount, num);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    fprintf(syscall_file, "icount:%ld, syscall #%" PRIi64 " returned -> %" PRIi64 "\n", icount, num, ret);
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    fprintf(stderr, "cpu %d created\n", vcpu_index);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    // for (int i = 0; i < argc; i++) {
    //     fprintf(stderr, "%s ", argv[i]);

    // }
    // fprintf(stderr, "\n");

    interval_size = get_u64_or_else(argc,argv,"size", interval_size);
    bench_name    = find_arg_or_else(argc,argv,"name","result");

    plugin_init(info);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    return 0;
}
