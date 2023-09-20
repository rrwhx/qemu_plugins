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
csh cs_handle;

enum inst_cat {
    INST_CAT_BEGIN,
    INST_UNKNOW,
    INST_CAT_PUSH,
    INST_CAT_POP,
    INST_ARITH, // add, sub
    INST_LOGIC, // and, or, xor
    INST_SHIFT, // sal,sar,shr
    INST_MUL, // mul, div
    INST_REG_MOV, // mov reg2reg
    INST_LOAD_IMM, // load imm
    INST_LOAD, // load
    INST_STORE, // store
    INST_BRANCH, // beq a0, a1, #111
    INST_CAC_CC, // cmp, test
    INST_BRANCH_CC, // je, jg
    INST_CMOV,
    INST_DIRECT_JMP,
    INST_INDIRECT_JMP, // jmp rax, jirl r0, r11, 0
    INST_DIRECT_CALL, // call 16
    INST_INDIRECT_CALL, // call rax
    INST_RET, // ret, jirl r0, r1, 0
    INST_FP_LOAD_32,
    INST_FP_LOAD_64,
    INST_FP_LOAD_128,
    INST_FP_LOAD_256,
    INST_FP_STORE_32,
    INST_FP_STORE_64,
    INST_FP_STORE_128,
    INST_FP_STORE_256,
    INST_FP_ARITH_SS,
    INST_FP_ARITH_SD,
    INST_FP_ARITH_128PS,
    INST_FP_ARITH_128PD,
    INST_FP_ARITH_256PS,
    INST_FP_ARITH_256PD,
    INST_ATOMIC,
    INST_X86_REP,
    INST_CAT_END,
};

const char* inst_cat_name(int cat) {
    switch (cat)
    {

    case INST_CAT_BEGIN: return "cat_begin";
    case INST_CAT_PUSH: return "push";
    case INST_CAT_POP: return "pop";
    case INST_UNKNOW: return "unknow";
    case INST_ARITH: return "arith";
    case INST_LOGIC: return "logic";
    case INST_SHIFT: return "shift";
    case INST_MUL: return "mul";
    case INST_REG_MOV: return "reg_mov";
    case INST_LOAD_IMM: return "load_imm";
    case INST_LOAD: return "load";
    case INST_STORE: return "store";
    case INST_BRANCH: return "branch";
    case INST_CAC_CC: return "cac_cc";
    case INST_BRANCH_CC: return "branch_cc";
    case INST_CMOV: return "cmov";
    case INST_DIRECT_JMP: return "direct_jmp";
    case INST_INDIRECT_JMP: return "indirect_jmp";
    case INST_DIRECT_CALL: return "direct_call";
    case INST_INDIRECT_CALL: return "indirect_call";
    case INST_RET: return "ret";
    case INST_FP_LOAD_32: return "fp_load_32";
    case INST_FP_LOAD_64: return "fp_load_64";
    case INST_FP_LOAD_128: return "fp_load_128";
    case INST_FP_LOAD_256: return "fp_load_256";
    case INST_FP_STORE_32: return "fp_store_32";
    case INST_FP_STORE_64: return "fp_store_64";
    case INST_FP_STORE_128: return "fp_store_128";
    case INST_FP_STORE_256: return "fp_store_256";
    case INST_FP_ARITH_SS: return "fp_arith_ss";
    case INST_FP_ARITH_SD: return "fp_arith_sd";
    case INST_FP_ARITH_128PS: return "fp_arith_128ps";
    case INST_FP_ARITH_128PD: return "fp_arith_128pd";
    case INST_FP_ARITH_256PS: return "fp_arith_256ps";
    case INST_FP_ARITH_256PD: return "fp_arith_256pd";
    case INST_ATOMIC: return "atomic";
    case INST_X86_REP: return "x86_rep";
    case INST_CAT_END: return "cat_end";

    default:
        break;
    }
    return NULL;
}

uint64_t cat_count[INST_CAT_END];


struct target_info{
    const char *name;
    cs_arch arch;
    cs_mode mode;
    int op_max;
    int (*get_insn_cat)(const cs_insn *);
};

static inline bool x86_op_is_imm(cs_x86_op op) {
    return op.type == X86_OP_IMM;
}

static inline bool x86_op_is_mem(cs_x86_op op) {
    return op.type == X86_OP_MEM;
}

static inline bool x86_op_is_reg(cs_x86_op op) {
    return op.type == X86_OP_REG;
}

static inline bool x86_insn_has_rep(const cs_insn *insn) {
    return 
        insn->detail->x86.prefix[0] == X86_PREFIX_REP  ||
        insn->detail->x86.prefix[0] == X86_PREFIX_REPE ||
        insn->detail->x86.prefix[0] == X86_PREFIX_REPNE
    ;
}

static inline bool x86_insn_has_lock(const cs_insn *insn) {
    return 
        insn->detail->x86.prefix[0] == X86_PREFIX_LOCK
    ;
}



int x86_get_insn_cat(const cs_insn * insn) {
    switch (insn->id)
    {
    case X86_INS_PUSH: return INST_CAT_PUSH;
    case X86_INS_POP: return INST_CAT_POP;
    default:
        return INST_UNKNOW;
    }
    if (x86_insn_has_lock(insn)) {
        return INST_ATOMIC;
    }
    switch (insn->id)
    {
    case X86_INS_ADD:
    case X86_INS_ADC:
    case X86_INS_INC:
    case X86_INS_SUB:
    case X86_INS_SBB:
    case X86_INS_DEC:
        return INST_ARITH;
    case X86_INS_AND:
    case X86_INS_OR:
    case X86_INS_XOR:
        return INST_LOGIC;
    case X86_INS_SAL:
    case X86_INS_SAR:
    case X86_INS_SHL:
    case X86_INS_SHR:
        return INST_SHIFT;
    case X86_INS_MUL:
    case X86_INS_IMUL:
    case X86_INS_DIV:
    case X86_INS_IDIV:
        return INST_MUL;
    case X86_INS_PUSH:
        return INST_STORE;
    case X86_INS_POP:
        return INST_LOAD;
    case X86_INS_LEA:
        return INST_LOAD_IMM;
    case X86_INS_MOV:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVZX:
        if (x86_op_is_mem(insn->detail->x86.operands[0])) {
            return INST_STORE;
        } else if (x86_op_is_mem(insn->detail->x86.operands[1])) {
            return INST_LOAD;
        } else if (x86_op_is_reg(insn->detail->x86.operands[0]) && x86_op_is_imm(insn->detail->x86.operands[1])) {
            return INST_LOAD_IMM;
        } else if (x86_op_is_reg(insn->detail->x86.operands[0]) && x86_op_is_reg(insn->detail->x86.operands[1])) {
            return INST_REG_MOV;
        }
        break;
    case X86_INS_JMP:
        if (x86_op_is_imm(insn->detail->x86.operands[0])) {
            return INST_INDIRECT_JMP;
        } else {
            return INST_DIRECT_JMP;
        }
    case X86_INS_CALL:
        if (x86_op_is_imm(insn->detail->x86.operands[0])) {
            return INST_INDIRECT_CALL;
        } else {
            return INST_DIRECT_CALL;
        }
    case X86_INS_MOVAPD:
    case X86_INS_MOVAPS:
    case X86_INS_MOVUPS:
    case X86_INS_MOVUPD:
        if (x86_op_is_mem(insn->detail->x86.operands[0])) {
            return INST_FP_STORE_128;
        } else if (x86_op_is_mem(insn->detail->x86.operands[1])) {
            return INST_FP_LOAD_128;
        }
        break;

    case X86_INS_RET:
        return INST_RET;
    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JRCXZ:
    case X86_INS_JS:
        return INST_BRANCH_CC;
	case X86_INS_CMOVA:
	case X86_INS_CMOVAE:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_FCMOVBE:
	case X86_INS_FCMOVB:
	case X86_INS_CMOVE:
	case X86_INS_FCMOVE:
	case X86_INS_CMOVG:
	case X86_INS_CMOVGE:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_FCMOVNBE:
	case X86_INS_FCMOVNB:
	case X86_INS_CMOVNE:
	case X86_INS_FCMOVNE:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_FCMOVNU:
	case X86_INS_FCMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_FCMOVU:
	case X86_INS_CMOVS:
        return INST_CMOV;
    case X86_INS_CMP:
    case X86_INS_TEST:
        return INST_CAC_CC;
    case X86_INS_ADDSS:
    case X86_INS_SUBSS:
    case X86_INS_MULSS:
    case X86_INS_DIVSS:return INST_FP_ARITH_SS;
    case X86_INS_ADDSD:
    case X86_INS_SUBSD:
    case X86_INS_MULSD:
    case X86_INS_DIVSD:return INST_FP_ARITH_SD;
    case X86_INS_ADDPS:
    case X86_INS_SUBPS:
    case X86_INS_MULPS:
    case X86_INS_DIVPS:return INST_FP_ARITH_128PS;
    case X86_INS_ADDPD:
    case X86_INS_SUBPD:
    case X86_INS_MULPD:
    case X86_INS_DIVPD:return INST_FP_ARITH_128PD;
    default:
        break;
    }

    if (x86_insn_has_rep(insn)) {
        return INST_X86_REP;
    }

    fprintf(stderr, "%16lx: %-15s%s\n", insn->address, insn->mnemonic, insn->op_str);
    return INST_UNKNOW;
}


target_info all_archs[] = {
    { "aarch64",   CS_ARCH_ARM64, cs_mode(CS_MODE_LITTLE_ENDIAN)                    , ARM64_INS_ENDING, },
    { "mips64el",  CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,   cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,   cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , x86_get_insn_cat},
    { "riscv32",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { "riscv64",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { NULL }
};

target_info* target;
static void plugin_init(const qemu_info_t *info) {
    // fprintf(stderr, "%s\n", info->target_name);
    cs_err err;
    for (int i = 0; all_archs[i].name; i++) {
        if (!strcmp(all_archs[i].name, info->target_name)) {
            target = &all_archs[i];
            err = cs_open(all_archs[i].arch, all_archs[i].mode, &cs_handle);
            if (!err) {
                cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
            } else {
                fprintf(stderr, "csopen fail, %s\n", cs_strerror(err));
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
    for (int i = 1; i <= INST_CAT_POP; i++) {
        sprintf(buf, "%20s,%ld\n", inst_cat_name(i), cat_count[i]);
        qemu_plugin_outs(buf);
    }
    cs_close(&cs_handle);
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
        size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, addr, 1, &cs_insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                // fprintf(stderr, "%16lx: %-15s%s\n", addr, cs_insn[j].mnemonic, cs_insn[j].op_str);
                qemu_plugin_register_vcpu_insn_exec_inline(insn,QEMU_PLUGIN_INLINE_ADD_U64, (void*)&cat_count[target->get_insn_cat(cs_insn)], 1);
            }
            cs_free(cs_insn, count);
        } else {
            fprintf(stderr, "%8lx:", addr);
            for (int i = 0; i < size; i++) {
                fprintf(stderr, "%02x ", data[i]);
            }
            fprintf(stderr, "\n");
            // abort();
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
