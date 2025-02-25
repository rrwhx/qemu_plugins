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
#if CS_NEXT_VERSION < 6
#error "capstone version mismatch"
#endif
extern "C" {
#include "qemu-plugin.h"
}


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
    { "aarch64",   CS_ARCH_AARCH64, cs_mode(CS_MODE_LITTLE_ENDIAN)                    , AARCH64_INS_ENDING, },
    { "mips64el",  CS_ARCH_MIPS,    cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,    cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,     cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,     cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , },
    { "riscv32",   CS_ARCH_RISCV,   cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { "riscv64",   CS_ARCH_RISCV,   cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { "loongarch32",   CS_ARCH_LOONGARCH,   cs_mode(CS_MODE_LOONGARCH32)              , LOONGARCH_INS_ENDING, },
    { "loongarch64",   CS_ARCH_LOONGARCH,   cs_mode(CS_MODE_LOONGARCH64)              , LOONGARCH_INS_ENDING, },
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
void plugin_exit(qemu_plugin_id_t id, void *p)
{
    char buf[1024];
    for (int i = 1; i < 64; i++) {
        sprintf(buf, "%3d,%ld\n", i - 32, imm_count[i]);qemu_plugin_outs(buf);
    }
    cs_close(&cs_handle);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        int size = qemu_plugin_insn_size(insn);
#if QEMU_PLUGIN_VERSION == 2
            const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
#else
            uint8_t data[16];
            if (qemu_plugin_insn_data(insn, &data, size) != size) {
                fprintf(stderr, "lxy:%s:%s:%d qemu_plugin_insn_data failed\n", __FILE__,__func__,__LINE__);
            }
#endif
        if (*data >= 0xd8 && *data <= 0xdf) {
            uint64_t addr = qemu_plugin_insn_vaddr(insn);
            cs_insn *cs_insn;
            size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, addr, 1, &cs_insn);
            if (count > 0) {
                            printf("%16lx: %-15s%s\n", addr, cs_insn->mnemonic, cs_insn->op_str);
            } else {
                printf("%lx disasm failed \n", addr);
            }
            cs_free(cs_insn, count);
        }
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
