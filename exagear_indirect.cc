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
#include <capstone/capstone.h>
extern "C" {
#include "qemu-plugin.h"
}

using namespace std;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
csh cs_handle;
uint64_t* reg_count;

enum inst_cat {
    INST_ARITH, // add, sub
    INST_LOGIC, // and, or, xor
    INST_SHIFT, // and, or, xor
    INST_MUL, // mul, div
    INST_REG_MOV, // mov reg2reg
    INST_LOAD, // load
    INST_STORE, // store
    INST_BRANCH, // beq a0, a1, #111
    INST_CAC_CC, // cmp, test
    INST_BRANCH_CC, // je, jg
    INST_DIRECT_CALL, // call 16
    INST_INDIRECT_CALL, // call rax
    INST_RET, // ret, jirl r0, r1, 0
    INST_INDIRECT_JMP, // jmp rax, jirl r0, r11, 0
    INST_VEC_LOAD,
};


struct target_info{
    const char *name;
    cs_arch arch;
    cs_mode mode;
    int op_max;
    // void (*disas_log)(const DisasContextBase *db, CPUState *cpu, FILE *f);
};
target_info all_archs[] = {
    { "aarch64",   CS_ARCH_ARM64, cs_mode(CS_MODE_LITTLE_ENDIAN)                    , ARM64_INS_ENDING, },
    { "mips64el",  CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,   cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,   cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , },
    { "riscv32",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { "riscv64",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { NULL }
};

target_info* target;
uint64_t imm_count[64];
static void plugin_init(const qemu_info_t *info) {
    // printf("%s\n", info->target_name);
    cs_err err;
    for (int i = 0; all_archs[i].name; i++) {
        if (!strcmp(all_archs[i].name, info->target_name)) {
            target = &all_archs[i];
            err = cs_open(all_archs[i].arch, all_archs[i].mode, &cs_handle);
            if (!err) {
                cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
            } else {
                printf("csopen fail, %s\n", cs_strerror(err));
                abort();
            }
            break;
        }
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
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
    // sprintf(buf, "%ld,%ld,%f\n", ind_cnt, ind_miss, (double)ind_miss/ind_cnt);qemu_plugin_outs(buf);
    // sprintf(buf, "%ld,%ld,%f\n", call_ind_cnt, call_ind_miss, (double)call_ind_miss/call_ind_cnt);qemu_plugin_outs(buf);
    // sprintf(buf, "%ld,%ld,%f\n", jump_ind_cnt, jump_ind_miss, (double)jump_ind_miss/jump_ind_cnt);qemu_plugin_outs(buf);
    sprintf(buf, "%ld,%ld,%ld,%ld\n", call_ind_cnt, call_ind_miss, jump_ind_cnt, jump_ind_miss);qemu_plugin_outs(buf);
    cs_close(&cs_handle);
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

    // for (size_t i = 0; i < insns; i ++) {
    //     struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
    //     int size = qemu_plugin_insn_size(insn);
    //     const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
    //     if (*data >= 0xd8 && *data <= 0xdf) {
    //         cs_insn *cs_insn;
    //         size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, addr, 1, &cs_insn);
    //         if (count > 0) {
    //                         printf("%16lx: %-15s%s\n", addr, cs_insn->mnemonic, cs_insn->op_str);
    //         } else {
    //             printf("%lx disasm failed \n", addr);
    //         }
    //         cs_free(cs_insn, count);
    //     }
    // }
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
