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

#include <glib.h>

extern "C" {
#include "qemu-plugin.h"
}


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
csh cs_handle;

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

enum inst_cat {
    INST_CAT_BEGIN,
    INST_UNKNOW,
    INST_NOP,
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
    INST_CC_OP, // arm64 ccmn, 
    INST_BRANCH_CC, // je, jg
    INST_CMOV,
    INST_DIRECT_JMP,
    INST_INDIRECT_JMP, // jmp rax, jirl r0, r11, 0
    INST_DIRECT_CALL, // call 16
    INST_INDIRECT_CALL, // call rax
    INST_RET, // ret, jirl r0, r1, 0
    INST_FP_LOAD,
    INST_FP_STORE,
    INST_FP_ARITH,
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
    INST_GR_FR_MOV,
    INST_ATOMIC,
    INST_X86_REP,
    INST_SYSCALL,
    INST_OTHER,
    INST_CAT_END,
};

const char* inst_cat_name(int cat) {
    switch (cat)
    {
    case INST_CAT_BEGIN: return "cat_begin";
    case INST_UNKNOW: return "unknow";
    case INST_NOP: return "nop";
    case INST_CAT_PUSH: return "cat_push";
    case INST_CAT_POP: return "cat_pop";
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
    case INST_CC_OP: return "cc_op";
    case INST_BRANCH_CC: return "branch_cc";
    case INST_CMOV: return "cmov";
    case INST_DIRECT_JMP: return "direct_jmp";
    case INST_INDIRECT_JMP: return "indirect_jmp";
    case INST_DIRECT_CALL: return "direct_call";
    case INST_INDIRECT_CALL: return "indirect_call";
    case INST_RET: return "ret";
    case INST_FP_LOAD: return "fp_load";
    case INST_FP_STORE: return "fp_store";
    case INST_FP_ARITH: return "fp_arith";
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
    case INST_GR_FR_MOV: return "gr_fp_mov";
    case INST_ATOMIC: return "atomic";
    case INST_X86_REP: return "x86_rep";
    case INST_SYSCALL: return "syscall";
    case INST_OTHER: return "other";
    case INST_CAT_END: return "cat_end";

    default:
        break;
    }
    return "cat_unknow2";
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

    xyprintf("%16lx: %-15s%s\n", insn->address, insn->mnemonic, insn->op_str);
    return INST_UNKNOW;
}

int aarch64_op_is_gr(cs_aarch64_op* op) {
    if (op->type == AArch64_OP_REG) {
        switch (op->reg) {
            case AArch64_REG_XZR:
            case AArch64_REG_WZR:
            case AArch64_REG_WSP:
            case AArch64_REG_FP:
            case AArch64_REG_LR:
            case AArch64_REG_SP:
            case AArch64_REG_X0 ... AArch64_REG_X28:
            case AArch64_REG_W0 ... AArch64_REG_W30:
                return true;
            default:
                return false;
        }
    }
    return false;
}

int aarch64_op_is_fr(cs_aarch64_op* op) {
    if (op->type == AArch64_OP_REG) {
        switch (op->reg) {
            case AArch64_REG_H0 ... AArch64_REG_H31:
            case AArch64_REG_B0 ... AArch64_REG_B31:
            case AArch64_REG_S0 ... AArch64_REG_S31:
            case AArch64_REG_D0 ... AArch64_REG_D31:
            case AArch64_REG_Q0 ... AArch64_REG_Q31:
                return true;
            default:
                return false;
        }
    }
    return false;
}

int aarch64_op_is_imm(cs_aarch64_op* op) {
    return op->type == AArch64_OP_IMM;
}

int aarch64_get_insn_cat(const cs_insn * insn) {
    bool first_op_isgr = false;
    bool first_op_isfr = false;
    __attribute__((unused)) bool second_op_isgr = false;
    bool second_op_isfr = false;
    if (insn->detail->aarch64.op_count >= 1) {
        first_op_isgr = aarch64_op_is_gr(&insn->detail->aarch64.operands[0]);
        first_op_isfr = aarch64_op_is_fr(&insn->detail->aarch64.operands[0]);
    }
    if (insn->detail->aarch64.op_count >= 2) {
        second_op_isgr = aarch64_op_is_gr(&insn->detail->aarch64.operands[1]);
        second_op_isfr = aarch64_op_is_fr(&insn->detail->aarch64.operands[1]);
    }
    
    switch (insn->alias_id) {
    case AArch64_INS_ALIAS_NOP:
        return INST_NOP;
    case AArch64_INS_ALIAS_LSL:
    case AArch64_INS_ALIAS_LSR:
    case AArch64_INS_ALIAS_ASR:
        g_assert(first_op_isgr);
        return INST_SHIFT;
    case AArch64_INS_ALIAS_SXTB:
    case AArch64_INS_ALIAS_SXTH:
    case AArch64_INS_ALIAS_SXTW:
    case AArch64_INS_ALIAS_UXTB:
    case AArch64_INS_ALIAS_UXTH:
    case AArch64_INS_ALIAS_UXTW:
    case AArch64_INS_ALIAS_SBFX:
    case AArch64_INS_ALIAS_UBFX:
    case AArch64_INS_ALIAS_SBFIZ:
    case AArch64_INS_ALIAS_UBFIZ:
    case AArch64_INS_ALIAS_BFC:
    case AArch64_INS_ALIAS_BFI:
    case AArch64_INS_ALIAS_BFXIL:
        g_assert(first_op_isgr);
        return INST_ARITH;
    case AArch64_INS_ALIAS_BTI:
        return INST_OTHER;
    case AArch64_INS_ALIAS_MVN:
        if(first_op_isgr) {
            return INST_ARITH;
        } else if(first_op_isfr) {
            return INST_FP_ARITH;
        }
    default:
        break;
    }
    switch (insn->id)
    {
    case AArch64_INS_ADC:
    case AArch64_INS_ADCS:
    case AArch64_INS_ADD:
    case AArch64_INS_ADDS:
    case AArch64_INS_ADR:
    case AArch64_INS_ADRP:
    case AArch64_INS_MADD:
    case AArch64_INS_MSUB:
    case AArch64_INS_MUL:
    case AArch64_INS_NEG:
    case AArch64_INS_SBC:
    case AArch64_INS_SBCS:
    case AArch64_INS_SDIV:
    case AArch64_INS_SMADDL:
    case AArch64_INS_SMSUBL:
    case AArch64_INS_SMULH:
    case AArch64_INS_SMULL:
    case AArch64_INS_SUB:
    case AArch64_INS_SUBS:
    case AArch64_INS_UDIV:
    case AArch64_INS_UMADDL:
    case AArch64_INS_UMSUBL:
    case AArch64_INS_UMULH:
    case AArch64_INS_UMULL:
        if (first_op_isgr) {
            return INST_ARITH;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AArch64_INS_CLS:
    case AArch64_INS_CLZ:
    case AArch64_INS_EXTR:
    case AArch64_INS_RBIT:
    case AArch64_INS_REV:
    case AArch64_INS_REV16:
    case AArch64_INS_REV32:
    case AArch64_INS_SXTB:
    case AArch64_INS_SXTH:
    case AArch64_INS_UXTB:
    case AArch64_INS_UXTH:
    case AArch64_INS_SXTW:
        if (first_op_isgr) {
            return INST_LOGIC;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AArch64_INS_AND:
    case AArch64_INS_ANDS:
    case AArch64_INS_BIC:
    case AArch64_INS_BICS:
    case AArch64_INS_EON:
    case AArch64_INS_EOR:
    case AArch64_INS_MOVK:
    case AArch64_INS_MOVN:
    case AArch64_INS_MOVZ:
    case AArch64_INS_ORN:
    case AArch64_INS_ORR:
        if (first_op_isgr) {
            return INST_LOGIC;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AArch64_INS_ASR:
    case AArch64_INS_LSL:
    case AArch64_INS_LSR:
    case AArch64_INS_ROR:
        if (first_op_isgr) {
            return INST_SHIFT;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AArch64_INS_BC:
    case AArch64_INS_CBNZ:
    case AArch64_INS_CBZ:
    case AArch64_INS_TBNZ:
    case AArch64_INS_TBZ:
    case AArch64_INS_B:
    case AArch64_INS_BL:
    case AArch64_INS_BLR:
    case AArch64_INS_BR:
    case AArch64_INS_RET:
        return INST_BRANCH;

    case AArch64_INS_CASA:
    case AArch64_INS_CASAL:
    case AArch64_INS_CASL:
    case AArch64_INS_CASAB:
    case AArch64_INS_CASALB:
    case AArch64_INS_CASLB:
    case AArch64_INS_CASAH:
    case AArch64_INS_CASALH:
    case AArch64_INS_CASLH:
    case AArch64_INS_CASPA:
    case AArch64_INS_CASPAL:
    case AArch64_INS_CASPL:

    case AArch64_INS_LDADDA:
    case AArch64_INS_LDADDAB:
    case AArch64_INS_LDADDAH:
    case AArch64_INS_LDCLRA:
    case AArch64_INS_LDCLRAB:
    case AArch64_INS_LDCLRAH:
    case AArch64_INS_LDEORA:
    case AArch64_INS_LDEORAB:
    case AArch64_INS_LDEORAH:
    case AArch64_INS_LDSETA:
    case AArch64_INS_LDSETAB:
    case AArch64_INS_LDSETAH:
    case AArch64_INS_LDSMAXA:
    case AArch64_INS_LDSMAXAB:
    case AArch64_INS_LDSMAXAH:
    case AArch64_INS_LDSMINA:
    case AArch64_INS_LDSMINAB:
    case AArch64_INS_LDSMINAH:
    case AArch64_INS_LDUMAXA:
    case AArch64_INS_LDUMAXAB:
    case AArch64_INS_LDUMAXAH:
    case AArch64_INS_LDUMINA:
    case AArch64_INS_LDUMINAB:
    case AArch64_INS_LDUMINAH:

    case AArch64_INS_LDADDAL:
    case AArch64_INS_LDADDALB:
    case AArch64_INS_LDADDALH:
    case AArch64_INS_LDCLRAL:
    case AArch64_INS_LDCLRALB:
    case AArch64_INS_LDCLRALH:
    case AArch64_INS_LDEORAL:
    case AArch64_INS_LDEORALB:
    case AArch64_INS_LDEORALH:
    case AArch64_INS_LDSETAL:
    case AArch64_INS_LDSETALB:
    case AArch64_INS_LDSETALH:
    case AArch64_INS_LDSMAXAL:
    case AArch64_INS_LDSMAXALB:
    case AArch64_INS_LDSMAXALH:
    case AArch64_INS_LDSMINAL:
    case AArch64_INS_LDSMINALB:
    case AArch64_INS_LDSMINALH:
    case AArch64_INS_LDUMAXAL:
    case AArch64_INS_LDUMAXALB:
    case AArch64_INS_LDUMAXALH:
    case AArch64_INS_LDUMINAL:
    case AArch64_INS_LDUMINALB:
    case AArch64_INS_LDUMINALH:

    case AArch64_INS_LDADDL:
    case AArch64_INS_LDADDLB:
    case AArch64_INS_LDADDLH:
    case AArch64_INS_LDCLRL:
    case AArch64_INS_LDCLRLB:
    case AArch64_INS_LDCLRLH:
    case AArch64_INS_LDEORL:
    case AArch64_INS_LDEORLB:
    case AArch64_INS_LDEORLH:
    case AArch64_INS_LDSETL:
    case AArch64_INS_LDSETLB:
    case AArch64_INS_LDSETLH:
    case AArch64_INS_LDSMAXL:
    case AArch64_INS_LDSMAXLB:
    case AArch64_INS_LDSMAXLH:
    case AArch64_INS_LDSMINL:
    case AArch64_INS_LDSMINLB:
    case AArch64_INS_LDSMINLH:
    case AArch64_INS_LDUMAXL:
    case AArch64_INS_LDUMAXLB:
    case AArch64_INS_LDUMAXLH:
    case AArch64_INS_LDUMINL:
    case AArch64_INS_LDUMINLB:
    case AArch64_INS_LDUMINLH:

    case AArch64_INS_SWPA:
    case AArch64_INS_SWPAL:
    case AArch64_INS_SWPL:
    case AArch64_INS_SWPAB:
    case AArch64_INS_SWPALB:
    case AArch64_INS_SWPLB:
    case AArch64_INS_SWPAH:
    case AArch64_INS_SWPALH:
    case AArch64_INS_SWPLH:

    case AArch64_INS_LDAXRB:
    case AArch64_INS_LDAXRH:
    case AArch64_INS_LDAXR:
    case AArch64_INS_LDAXP:
    case AArch64_INS_LDXRB:
    case AArch64_INS_LDXRH:
    case AArch64_INS_LDXR:
    case AArch64_INS_LDXP:
    case AArch64_INS_STXRB:
    case AArch64_INS_STXRH:
    case AArch64_INS_STXR:
    case AArch64_INS_STXP:
    case AArch64_INS_LDLARB:
    case AArch64_INS_LDLARH:
    case AArch64_INS_LDLAR:
    case AArch64_INS_STLXRB:
    case AArch64_INS_STLXRH:
    case AArch64_INS_STLXR:
    case AArch64_INS_STLXP:
    case AArch64_INS_LDARB:
    case AArch64_INS_LDARH:
    case AArch64_INS_LDAR:
    case AArch64_INS_STLRB:
    case AArch64_INS_STLRH:
    case AArch64_INS_STLR:

    case AArch64_INS_DMB:
        return INST_ATOMIC;
    
    case AArch64_INS_CCMN:
    case AArch64_INS_CCMP:
    case AArch64_INS_CSEL:
    case AArch64_INS_CSINC:
    case AArch64_INS_CSINV:
    case AArch64_INS_CSNEG:
        return INST_CC_OP;

    case AArch64_INS_LDP:
    case AArch64_INS_LDPSW:
    case AArch64_INS_LDR:
    case AArch64_INS_LDUR:
    case AArch64_INS_LDRB:
    case AArch64_INS_LDURB:
    case AArch64_INS_LDRH:
    case AArch64_INS_LDURH:
    case AArch64_INS_LDRSB:
    case AArch64_INS_LDURSB:
    case AArch64_INS_LDRSH:
    case AArch64_INS_LDURSH:
    case AArch64_INS_LDRSW:
    case AArch64_INS_LDURSW:
        if (first_op_isgr) {
            return INST_LOAD;
        } else if (first_op_isfr) {
            return INST_FP_LOAD;
        }

    case AArch64_INS_STP:
    case AArch64_INS_STR:
    case AArch64_INS_STUR:
    case AArch64_INS_STRB:
    case AArch64_INS_STURB:
    case AArch64_INS_STRH:
    case AArch64_INS_STURH:
        if (first_op_isgr) {
            return INST_STORE;
        } else if (first_op_isfr) {
            return INST_FP_STORE;
        }
        break;

    case AArch64_INS_SVC:
        return INST_SYSCALL;

    case AArch64_INS_LD1:
    case AArch64_INS_LD2:
    case AArch64_INS_LD3:
    case AArch64_INS_LD4:
    case AArch64_INS_LD1R:
    case AArch64_INS_LD2R:
    case AArch64_INS_LD3R:
    case AArch64_INS_LD4R:
        return INST_FP_LOAD;

    case AArch64_INS_ST1:
    case AArch64_INS_ST2:
    case AArch64_INS_ST3:
    case AArch64_INS_ST4:
        return INST_FP_STORE;

    case AArch64_INS_UMOV:
        return INST_GR_FR_MOV;


    case AArch64_INS_FABD:
    case AArch64_INS_FABS:
    case AArch64_INS_FACGE:
    case AArch64_INS_FACGT:
    case AArch64_INS_FADD:
    case AArch64_INS_FADDP:
    case AArch64_INS_FDIV:
    case AArch64_INS_FMLA:
    case AArch64_INS_FMLAL:
    case AArch64_INS_FMLAL2:
    case AArch64_INS_FMADD:
    case AArch64_INS_FNMADD:
    case AArch64_INS_FMSUB:
    case AArch64_INS_FNMSUB:
    case AArch64_INS_FNEG:
    case AArch64_INS_FMUL:
    case AArch64_INS_FMULX:
    case AArch64_INS_FNMUL:
    case AArch64_INS_FSQRT:
    case AArch64_INS_FSUB:

    case AArch64_INS_FCSEL:

    case AArch64_INS_FRINT32X:
    case AArch64_INS_FRINT32Z:
    case AArch64_INS_FRINT64X:
    case AArch64_INS_FRINT64Z:

    case AArch64_INS_FRINTA:
    case AArch64_INS_FRINTM:
    case AArch64_INS_FRINTN:
    case AArch64_INS_FRINTP:
    case AArch64_INS_FRINTI:
    case AArch64_INS_FRINTZ:

    case AArch64_INS_SCVTF:
    case AArch64_INS_UCVTF:

    case AArch64_INS_FCCMP:
    case AArch64_INS_FCCMPE:
    case AArch64_INS_FCMP:
    case AArch64_INS_FCMPE:

    case AArch64_INS_FCMEQ:
    case AArch64_INS_FCMNE:
    case AArch64_INS_FCMGE:
    case AArch64_INS_FCMLE:
    case AArch64_INS_FCMGT:
    case AArch64_INS_FCMLT:
    case AArch64_INS_FCMUO:

    case AArch64_INS_FMAX:
    case AArch64_INS_FMAXNM:
    case AArch64_INS_FMAXP:
    case AArch64_INS_FMAXNMP:
    case AArch64_INS_FMAXV:
    case AArch64_INS_FMAXNMV:
    case AArch64_INS_FMIN:
    case AArch64_INS_FMINNM:
    case AArch64_INS_FMINP:
    case AArch64_INS_FMINNMP:
    case AArch64_INS_FMINV:
    case AArch64_INS_FMINNMV:

    case AArch64_INS_BFDOT:
    case AArch64_INS_BFMLALB:
    case AArch64_INS_BFMLALT:
    case AArch64_INS_BFMMLA:
    case AArch64_INS_FCADD:
    case AArch64_INS_FCMLA:
    case AArch64_INS_FRECPE:
    case AArch64_INS_FRECPS:
    case AArch64_INS_FRECPX:
    case AArch64_INS_FRSQRTE:
    case AArch64_INS_FRSQRTS:

    case AArch64_INS_ABS:
    case AArch64_INS_ADDP:
    case AArch64_INS_ADDV:
    case AArch64_INS_ADDHN:
    case AArch64_INS_ADDHN2:
    case AArch64_INS_RADDHN:
    case AArch64_INS_RADDHN2:
    case AArch64_INS_SUBHN:
    case AArch64_INS_SUBHN2:
    case AArch64_INS_RSUBHN:
    case AArch64_INS_RSUBHN2:

    case AArch64_INS_SABA:
    case AArch64_INS_UABA:
    case AArch64_INS_SABAL:
    case AArch64_INS_UABAL:
    case AArch64_INS_SABAL2:
    case AArch64_INS_UABAL2:
    case AArch64_INS_SABD:
    case AArch64_INS_UABD:
    case AArch64_INS_SABDL:
    case AArch64_INS_UABDL:
    case AArch64_INS_SABDL2:
    case AArch64_INS_UABDL2:
    case AArch64_INS_SADALP:
    case AArch64_INS_UADALP:
    case AArch64_INS_SADDL:
    case AArch64_INS_UADDL:
    case AArch64_INS_SADDL2:
    case AArch64_INS_UADDL2:
    case AArch64_INS_SADDLP:
    case AArch64_INS_UADDLP:
    case AArch64_INS_SADDLV:
    case AArch64_INS_UADDLV:
    case AArch64_INS_SADDW:
    case AArch64_INS_UADDW:
    case AArch64_INS_SADDW2:
    case AArch64_INS_UADDW2:
    case AArch64_INS_SHSUB:
    case AArch64_INS_UHSUB:
    case AArch64_INS_SQABS:
    case AArch64_INS_SQADD:
    case AArch64_INS_UQADD:
    case AArch64_INS_SQNEG:
    case AArch64_INS_SQSUB:
    case AArch64_INS_UQSUB:
    case AArch64_INS_SQXTN:
    case AArch64_INS_UQXTN:
    case AArch64_INS_SQXTN2:
    case AArch64_INS_UQXTN2:
    case AArch64_INS_SQXTUN:
    case AArch64_INS_SQXTUN2:
    case AArch64_INS_SHADD:
    case AArch64_INS_UHADD:
    case AArch64_INS_SRHADD:
    case AArch64_INS_URHADD:
    case AArch64_INS_SSUBL:
    case AArch64_INS_USUBL:
    case AArch64_INS_SSUBL2:
    case AArch64_INS_USUBL2:
    case AArch64_INS_SSUBW:
    case AArch64_INS_USUBW:
    case AArch64_INS_SSUBW2:
    case AArch64_INS_SUQADD:
    case AArch64_INS_USQADD:

    case AArch64_INS_CMEQ:
    case AArch64_INS_CMGE:
    case AArch64_INS_CMGT:
    case AArch64_INS_CMHI:
    case AArch64_INS_CMHS:
    case AArch64_INS_CMLA:
    case AArch64_INS_CMLE:
    case AArch64_INS_CMLT:
    case AArch64_INS_CMTST:
    case AArch64_INS_SMIN:
    case AArch64_INS_SMINP:
    case AArch64_INS_SMINV:
    case AArch64_INS_UMIN:
    case AArch64_INS_UMINP:
    case AArch64_INS_UMINV:
    case AArch64_INS_SMAX:
    case AArch64_INS_SMAXP:
    case AArch64_INS_SMAXV:
    case AArch64_INS_UMAX:
    case AArch64_INS_UMAXP:
    case AArch64_INS_UMAXV:

    case AArch64_INS_BIF:
    case AArch64_INS_BIT:
    case AArch64_INS_BSL:

    case AArch64_INS_CNT:
    case AArch64_INS_EXT:
    case AArch64_INS_REV64:
    case AArch64_INS_SLI:
    case AArch64_INS_SRI:
    case AArch64_INS_TRN1:
    case AArch64_INS_TRN2:
    case AArch64_INS_UZP1:
    case AArch64_INS_UZP2:
    case AArch64_INS_ZIP1:
    case AArch64_INS_ZIP2:

    case AArch64_INS_FMLS:

    case AArch64_INS_DUP:
    case AArch64_INS_MOVI:
    case AArch64_INS_MVNI:
    case AArch64_INS_TBL:
    case AArch64_INS_TBX:
    case AArch64_INS_XTN:
    case AArch64_INS_XTN2:


    case AArch64_INS_SHRN:
    case AArch64_INS_SHRN2:
    case AArch64_INS_RSHRN:
    case AArch64_INS_RSHRN2:

    case AArch64_INS_SHL:
    case AArch64_INS_SHLL:
    case AArch64_INS_SHLL2:

    case AArch64_INS_SQRSHL:
    case AArch64_INS_UQRSHL:

    case AArch64_INS_SQSHRN:
    case AArch64_INS_UQSHRN:
    case AArch64_INS_SQSHRN2:
    case AArch64_INS_UQSHRN2:
    case AArch64_INS_SQRSHRN:
    case AArch64_INS_UQRSHRN:
    case AArch64_INS_SQRSHRN2:
    case AArch64_INS_UQRSHRN2:

    case AArch64_INS_SQSHRUN:
    case AArch64_INS_SQSHRUN2:
    case AArch64_INS_SQRSHRUN:
    case AArch64_INS_SQRSHRUN2:

    case AArch64_INS_SQSHL:
    case AArch64_INS_UQSHL:
    case AArch64_INS_SQSHLU:

    case AArch64_INS_SSHL:
    case AArch64_INS_SRSHL:
    case AArch64_INS_SSHR:
    case AArch64_INS_SRSHR:
    case AArch64_INS_SSRA:
    case AArch64_INS_SRSRA:
    case AArch64_INS_USHL:
    case AArch64_INS_URSHL:
    case AArch64_INS_USHR:
    case AArch64_INS_URSHR:
    case AArch64_INS_USRA:
    case AArch64_INS_URSRA:


    case AArch64_INS_SSHLL:
    case AArch64_INS_SSHLL2:
    case AArch64_INS_USHLL:
    case AArch64_INS_USHLL2:

    case AArch64_INS_MLA:
    case AArch64_INS_MLS:

    case AArch64_INS_SMLAL:
    case AArch64_INS_SMLSL:
    case AArch64_INS_SMLAL2:
    case AArch64_INS_SMLSL2:
    case AArch64_INS_UMLAL:
    case AArch64_INS_UMLSL:
    case AArch64_INS_UMLAL2:
    case AArch64_INS_UMLSL2:
    case AArch64_INS_SMULL2:
    case AArch64_INS_UMULL2:

    case AArch64_INS_SQDMLAL:
    case AArch64_INS_SQDMLSL:
    case AArch64_INS_SQDMLAL2:
    case AArch64_INS_SQDMLSL2:
    case AArch64_INS_SQDMULL2:
    case AArch64_INS_SQRDMLAH:
    case AArch64_INS_SQRDMLSH:

    case AArch64_INS_SQDMULH:
    case AArch64_INS_SQRDMULH:

        g_assert(first_op_isfr);
        return INST_FP_ARITH;

    case AArch64_INS_BFCVT:
    case AArch64_INS_FCVT:
    case AArch64_INS_FCVTL:
    case AArch64_INS_FCVTL2:
    case AArch64_INS_FCVTN:
    case AArch64_INS_FCVTN2:
    case AArch64_INS_FCVTXN:
    case AArch64_INS_FCVTXN2:
    case AArch64_INS_FCVTAS:
    case AArch64_INS_FCVTMS:
    case AArch64_INS_FCVTNS:
    case AArch64_INS_FCVTPS:
    case AArch64_INS_FCVTZS:
    case AArch64_INS_FCVTAU:
    case AArch64_INS_FCVTMU:
    case AArch64_INS_FCVTNU:
    case AArch64_INS_FCVTPU:
    case AArch64_INS_FCVTZU:
        return INST_FP_ARITH;
    
    case AArch64_INS_FMOV:
        if (first_op_isfr && second_op_isfr) {
            return INST_FP_ARITH;
        } else {
            return INST_GR_FR_MOV;
        }

    default:
        break;
    }
    if (insn->id == AArch64_INS_MOV) {
        if (insn->detail->aarch64.op_count == 2) {
            if (first_op_isfr && aarch64_op_is_fr(&insn->detail->aarch64.operands[1])) {
                return INST_FP_ARITH; 
            }
            if (
                first_op_isgr &&
                (aarch64_op_is_gr(&insn->detail->aarch64.operands[1]) || aarch64_op_is_imm(&insn->detail->aarch64.operands[1]))
            ) {
                return INST_LOGIC; 
            }
        }
    }

    if (insn->alias_id == AArch64_INS_ALIAS_MOV) {
        if (insn->detail->aarch64.op_count == 2) {
            if (first_op_isfr) {
                if (aarch64_op_is_fr(&insn->detail->aarch64.operands[1])) {
                    return INST_FP_ARITH; 
                } else if (aarch64_op_is_gr(&insn->detail->aarch64.operands[1])) {
                    return INST_GR_FR_MOV; 
                }
            }
        }
    }

    if (insn->id == AArch64_INS_MRS) {
        if (insn->detail->aarch64.op_count == 2) {
            if (
                first_op_isgr &&
                (insn->detail->aarch64.operands[1].type == AArch64_OP_SYSREG && insn->detail->aarch64.operands[1].sysop.sub_type == AArch64_OP_REG_MRS)
            ) {
                int r = insn->detail->aarch64.operands[1].sysop.reg.sysreg;
                if (
                    r == AArch64_SYSREG_TPIDR_EL0 ||
                    r == AArch64_SYSREG_FPCR ||
                    r == AArch64_SYSREG_MIDR_EL1 ||
                    r == AArch64_SYSREG_DCZID_EL0
                ) {
                    return INST_OTHER; 
                }
            }
        }
    }

    fprintf(stderr, "[unknown %8d] %16lx:%8x %-15s%s\n", insn->id, insn->address, *(int*)(insn->bytes), insn->mnemonic, insn->op_str);
    // xyprintf("[unknown %8d] %16lx:%8x %-15s%s\n", insn->id, insn->address, *(int*)(insn->bytes), insn->mnemonic, insn->op_str);
    return INST_UNKNOW;
}

int riscv64_insn_is_branch(const cs_insn * insn) {
    switch (insn->id)
    {
    case RISCV_INS_C_J:
    case RISCV_INS_C_JAL:
    case RISCV_INS_C_JALR:
    case RISCV_INS_C_JR:
    case RISCV_INS_BEQ:
    case RISCV_INS_BGE:
    case RISCV_INS_BGEU:
    case RISCV_INS_BLT:
    case RISCV_INS_BLTU:
    case RISCV_INS_BNE:
    case RISCV_INS_JAL:
    case RISCV_INS_JALR:
        return 1;
    default:
        return 0;
    }
    return 0;
}


target_info all_archs[] = {
    { "aarch64",   CS_ARCH_AARCH64, cs_mode(CS_MODE_LITTLE_ENDIAN)                    , AArch64_INS_ENDING, aarch64_get_insn_cat},
    { "mips64el",  CS_ARCH_MIPS,    cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,    cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,     cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,     cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , x86_get_insn_cat},
    { "riscv32",   CS_ARCH_RISCV,   cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
    { "riscv64",   CS_ARCH_RISCV,   cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, },
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
                cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
            } else {
                fprintf(stderr, "csopen fail, %s\n", cs_strerror(err));
                abort();
            }
            break;
        }
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}
void plugin_exit(qemu_plugin_id_t id, void *p) {
    for (int i = INST_UNKNOW; i < INST_CAT_END; i++) {
        xyprintf("%20s,%ld\n", inst_cat_name(i), cat_count[i]);
    }
    cs_close(&cs_handle);
}

// static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
//     cs_insn* insn = (cs_insn*)userdata;
//     xyprintf("[unknown] %16lx: id:%d %x %-15s%s\n",  insn->address, insn->id, *(int*)(insn->bytes), insn->mnemonic, insn->op_str);
// }

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
                // if (target->get_insn_cat(cs_insn) == INST_UNKNOW) {

                //         qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                //                                 QEMU_PLUGIN_CB_NO_REGS,
                //                                 (void*)cs_insn);
                // }
                // xyprintf("%16lx: %-15s%s\n", addr, cs_insn[j].mnemonic, cs_insn[j].op_str);
                qemu_plugin_register_vcpu_insn_exec_inline(insn,QEMU_PLUGIN_INLINE_ADD_U64, (void*)&cat_count[target->get_insn_cat(cs_insn)], 1);
            }
            cs_free(cs_insn, count);
        } else {
            xyprintf("%8lx:", addr);
            for (int i = 0; i < size; i++) {
                xyprintf("%02x ", data[i]);
            }
            xyprintf("\n");
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
