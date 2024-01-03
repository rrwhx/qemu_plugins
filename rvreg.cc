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
csh handle_rv64;
uint64_t reg_count[RISCV_REG_ENDING];
static void plugin_init(void) {
    if (!cs_support(CS_ARCH_RISCV)) {
        printf("riscv not support\n");
    }
    cs_err err;
    err = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC), &handle_rv64); if (err != CS_ERR_OK) { printf("csopen fail, %s\n", cs_strerror(err));abort();}
    cs_option(handle_rv64, CS_OPT_DETAIL, CS_OPT_ON);
}
void plugin_exit(qemu_plugin_id_t id, void *p)
{
    char buf[1024];
    cs_close(&handle_rv64);

    //> General purpose registers
    sprintf(buf, "%s,%ld\n", "RISCV_REG_ZERO", reg_count[RISCV_REG_ZERO]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_RA", reg_count[RISCV_REG_RA]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_SP", reg_count[RISCV_REG_SP]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_GP", reg_count[RISCV_REG_GP]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_TP", reg_count[RISCV_REG_TP]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T0", reg_count[RISCV_REG_T0]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T1", reg_count[RISCV_REG_T1]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T2", reg_count[RISCV_REG_T2]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S0", reg_count[RISCV_REG_S0]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_FP", reg_count[RISCV_REG_FP]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S1", reg_count[RISCV_REG_S1]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A0", reg_count[RISCV_REG_A0]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A1", reg_count[RISCV_REG_A1]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A2", reg_count[RISCV_REG_A2]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A3", reg_count[RISCV_REG_A3]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A4", reg_count[RISCV_REG_A4]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A5", reg_count[RISCV_REG_A5]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A6", reg_count[RISCV_REG_A6]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_A7", reg_count[RISCV_REG_A7]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S2", reg_count[RISCV_REG_S2]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S3", reg_count[RISCV_REG_S3]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S4", reg_count[RISCV_REG_S4]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S5", reg_count[RISCV_REG_S5]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S6", reg_count[RISCV_REG_S6]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S7", reg_count[RISCV_REG_S7]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S8", reg_count[RISCV_REG_S8]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S9", reg_count[RISCV_REG_S9]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S10", reg_count[RISCV_REG_S10]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_S11", reg_count[RISCV_REG_S11]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T3", reg_count[RISCV_REG_T3]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T4", reg_count[RISCV_REG_T4]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T5", reg_count[RISCV_REG_T5]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_T6", reg_count[RISCV_REG_T6]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F0_32", reg_count[RISCV_REG_F0_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F0_64", reg_count[RISCV_REG_F0_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F1_32", reg_count[RISCV_REG_F1_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F1_64", reg_count[RISCV_REG_F1_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F2_32", reg_count[RISCV_REG_F2_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F2_64", reg_count[RISCV_REG_F2_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F3_32", reg_count[RISCV_REG_F3_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F3_64", reg_count[RISCV_REG_F3_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F4_32", reg_count[RISCV_REG_F4_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F4_64", reg_count[RISCV_REG_F4_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F5_32", reg_count[RISCV_REG_F5_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F5_64", reg_count[RISCV_REG_F5_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F6_32", reg_count[RISCV_REG_F6_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F6_64", reg_count[RISCV_REG_F6_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F7_32", reg_count[RISCV_REG_F7_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F7_64", reg_count[RISCV_REG_F7_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F8_32", reg_count[RISCV_REG_F8_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F8_64", reg_count[RISCV_REG_F8_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F9_32", reg_count[RISCV_REG_F9_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F9_64", reg_count[RISCV_REG_F9_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F10_32", reg_count[RISCV_REG_F10_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F10_64", reg_count[RISCV_REG_F10_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F11_32", reg_count[RISCV_REG_F11_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F11_64", reg_count[RISCV_REG_F11_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F12_32", reg_count[RISCV_REG_F12_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F12_64", reg_count[RISCV_REG_F12_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F13_32", reg_count[RISCV_REG_F13_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F13_64", reg_count[RISCV_REG_F13_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F14_32", reg_count[RISCV_REG_F14_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F14_64", reg_count[RISCV_REG_F14_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F15_32", reg_count[RISCV_REG_F15_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F15_64", reg_count[RISCV_REG_F15_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F16_32", reg_count[RISCV_REG_F16_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F16_64", reg_count[RISCV_REG_F16_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F17_32", reg_count[RISCV_REG_F17_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F17_64", reg_count[RISCV_REG_F17_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F18_32", reg_count[RISCV_REG_F18_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F18_64", reg_count[RISCV_REG_F18_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F19_32", reg_count[RISCV_REG_F19_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F19_64", reg_count[RISCV_REG_F19_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F20_32", reg_count[RISCV_REG_F20_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F20_64", reg_count[RISCV_REG_F20_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F21_32", reg_count[RISCV_REG_F21_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F21_64", reg_count[RISCV_REG_F21_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F22_32", reg_count[RISCV_REG_F22_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F22_64", reg_count[RISCV_REG_F22_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F23_32", reg_count[RISCV_REG_F23_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F23_64", reg_count[RISCV_REG_F23_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F24_32", reg_count[RISCV_REG_F24_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F24_64", reg_count[RISCV_REG_F24_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F25_32", reg_count[RISCV_REG_F25_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F25_64", reg_count[RISCV_REG_F25_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F26_32", reg_count[RISCV_REG_F26_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F26_64", reg_count[RISCV_REG_F26_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F27_32", reg_count[RISCV_REG_F27_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F27_64", reg_count[RISCV_REG_F27_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F28_32", reg_count[RISCV_REG_F28_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F28_64", reg_count[RISCV_REG_F28_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F29_32", reg_count[RISCV_REG_F29_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F29_64", reg_count[RISCV_REG_F29_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F30_32", reg_count[RISCV_REG_F30_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F30_64", reg_count[RISCV_REG_F30_64]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F31_32", reg_count[RISCV_REG_F31_32]);qemu_plugin_outs(buf);
    sprintf(buf, "%s,%ld\n", "RISCV_REG_F31_64", reg_count[RISCV_REG_F31_64]);qemu_plugin_outs(buf);
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        int size = qemu_plugin_insn_size(insn);
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        cs_insn *cs_insn;
        size_t count = cs_disasm(handle_rv64, (const uint8_t*)data, size, addr, 1, &cs_insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                // if (size == 4) {
                //     printf("%8lx: %02x %02x %02x %02x\t%s\t\t%s\n", cs_insn[j].address, data[0], data[1], data[2], data[3], cs_insn[j].mnemonic, cs_insn[j].op_str);
                // } else {
                //     printf("%8lx: %02x %02x      \t%s\t\t%s\n", cs_insn[j].address, data[0], data[1], cs_insn[j].mnemonic, cs_insn[j].op_str);
                // }
                for (size_t i = 0; i < cs_insn->detail->riscv.op_count; i++)
                {
                    if (cs_insn->detail->riscv.operands[i].type == RISCV_OP_REG) {
                        qemu_plugin_register_vcpu_insn_exec_inline(insn,QEMU_PLUGIN_INLINE_ADD_U64, reg_count + cs_insn->detail->riscv.operands[i].reg, 1);
                    } else if (cs_insn->detail->riscv.operands[i].type == RISCV_OP_MEM) {
                        qemu_plugin_register_vcpu_insn_exec_inline(insn,QEMU_PLUGIN_INLINE_ADD_U64, reg_count + cs_insn->detail->riscv.operands[i].mem.base, 1);
                    } else if (cs_insn->detail->riscv.operands[i].type == RISCV_OP_IMM) {
                    }
                }
            }
            cs_free(cs_insn, count);
        } else {
            if (size == 4) {
                printf("%8lx: %02x %02x %02x %02x\tERROR ERROR ERROR ERROR ERROR\n", addr,  data[0], data[1], data[2], data[3]);
            } else {
                printf("%8lx: %02x %02x      \tERROR ERROR ERROR ERROR ERROR\n", addr,  data[0], data[1]);
            }
        }
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
