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
    if (op->type == AARCH64_OP_REG) {
        switch (op->reg) {
            case AARCH64_REG_XZR:
            case AARCH64_REG_WZR:
            case AARCH64_REG_WSP:
            case AARCH64_REG_FP:
            case AARCH64_REG_LR:
            case AARCH64_REG_SP:
            case AARCH64_REG_X0 ... AARCH64_REG_X28:
            case AARCH64_REG_W0 ... AARCH64_REG_W30:
                return true;
            default:
                return false;
        }
    }
    return false;
}

int aarch64_op_is_fr(cs_aarch64_op* op) {
    if (op->type == AARCH64_OP_REG) {
        switch (op->reg) {
            case AARCH64_REG_H0 ... AARCH64_REG_H31:
            case AARCH64_REG_B0 ... AARCH64_REG_B31:
            case AARCH64_REG_S0 ... AARCH64_REG_S31:
            case AARCH64_REG_D0 ... AARCH64_REG_D31:
            case AARCH64_REG_Q0 ... AARCH64_REG_Q31:
                return true;
            default:
                return false;
        }
    }
    return false;
}

int aarch64_op_is_imm(cs_aarch64_op* op) {
    return op->type == AARCH64_OP_IMM;
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
    case AARCH64_INS_ALIAS_NOP:
        return INST_NOP;
    case AARCH64_INS_ALIAS_LSL:
    case AARCH64_INS_ALIAS_LSR:
    case AARCH64_INS_ALIAS_ASR:
        g_assert(first_op_isgr);
        return INST_SHIFT;
    case AARCH64_INS_ALIAS_SXTB:
    case AARCH64_INS_ALIAS_SXTH:
    case AARCH64_INS_ALIAS_SXTW:
    case AARCH64_INS_ALIAS_UXTB:
    case AARCH64_INS_ALIAS_UXTH:
    case AARCH64_INS_ALIAS_UXTW:
    case AARCH64_INS_ALIAS_SBFX:
    case AARCH64_INS_ALIAS_UBFX:
    case AARCH64_INS_ALIAS_SBFIZ:
    case AARCH64_INS_ALIAS_UBFIZ:
    case AARCH64_INS_ALIAS_BFC:
    case AARCH64_INS_ALIAS_BFI:
    case AARCH64_INS_ALIAS_BFXIL:
        g_assert(first_op_isgr);
        return INST_ARITH;
    case AARCH64_INS_ALIAS_BTI:
        return INST_OTHER;
    case AARCH64_INS_ALIAS_MVN:
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
    case AARCH64_INS_ADC:
    case AARCH64_INS_ADCS:
    case AARCH64_INS_ADD:
    case AARCH64_INS_ADDS:
    case AARCH64_INS_ADR:
    case AARCH64_INS_ADRP:
    case AARCH64_INS_MADD:
    case AARCH64_INS_MSUB:
    case AARCH64_INS_MUL:
    case AARCH64_INS_NEG:
    case AARCH64_INS_SBC:
    case AARCH64_INS_SBCS:
    case AARCH64_INS_SDIV:
    case AARCH64_INS_SMADDL:
    case AARCH64_INS_SMSUBL:
    case AARCH64_INS_SMULH:
    case AARCH64_INS_SMULL:
    case AARCH64_INS_SUB:
    case AARCH64_INS_SUBS:
    case AARCH64_INS_UDIV:
    case AARCH64_INS_UMADDL:
    case AARCH64_INS_UMSUBL:
    case AARCH64_INS_UMULH:
    case AARCH64_INS_UMULL:
        if (first_op_isgr) {
            return INST_ARITH;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AARCH64_INS_CLS:
    case AARCH64_INS_CLZ:
    case AARCH64_INS_EXTR:
    case AARCH64_INS_RBIT:
    case AARCH64_INS_REV:
    case AARCH64_INS_REV16:
    case AARCH64_INS_REV32:
    case AARCH64_INS_SXTB:
    case AARCH64_INS_SXTH:
    case AARCH64_INS_UXTB:
    case AARCH64_INS_UXTH:
    case AARCH64_INS_SXTW:
        if (first_op_isgr) {
            return INST_LOGIC;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AARCH64_INS_AND:
    case AARCH64_INS_ANDS:
    case AARCH64_INS_BIC:
    case AARCH64_INS_BICS:
    case AARCH64_INS_EON:
    case AARCH64_INS_EOR:
    case AARCH64_INS_MOVK:
    case AARCH64_INS_MOVN:
    case AARCH64_INS_MOVZ:
    case AARCH64_INS_ORN:
    case AARCH64_INS_ORR:
        if (first_op_isgr) {
            return INST_LOGIC;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AARCH64_INS_ASR:
    case AARCH64_INS_LSL:
    case AARCH64_INS_LSR:
    case AARCH64_INS_ROR:
        if (first_op_isgr) {
            return INST_SHIFT;
        } else if (first_op_isfr) {
            return INST_FP_ARITH;
        }
        break;

    case AARCH64_INS_BC:
    case AARCH64_INS_CBNZ:
    case AARCH64_INS_CBZ:
    case AARCH64_INS_TBNZ:
    case AARCH64_INS_TBZ:
    case AARCH64_INS_B:
    case AARCH64_INS_BL:
    case AARCH64_INS_BLR:
    case AARCH64_INS_BR:
    case AARCH64_INS_RET:
        return INST_BRANCH;

    case AARCH64_INS_CASA:
    case AARCH64_INS_CASAL:
    case AARCH64_INS_CASL:
    case AARCH64_INS_CASAB:
    case AARCH64_INS_CASALB:
    case AARCH64_INS_CASLB:
    case AARCH64_INS_CASAH:
    case AARCH64_INS_CASALH:
    case AARCH64_INS_CASLH:
    case AARCH64_INS_CASPA:
    case AARCH64_INS_CASPAL:
    case AARCH64_INS_CASPL:

    case AARCH64_INS_LDADDA:
    case AARCH64_INS_LDADDAB:
    case AARCH64_INS_LDADDAH:
    case AARCH64_INS_LDCLRA:
    case AARCH64_INS_LDCLRAB:
    case AARCH64_INS_LDCLRAH:
    case AARCH64_INS_LDEORA:
    case AARCH64_INS_LDEORAB:
    case AARCH64_INS_LDEORAH:
    case AARCH64_INS_LDSETA:
    case AARCH64_INS_LDSETAB:
    case AARCH64_INS_LDSETAH:
    case AARCH64_INS_LDSMAXA:
    case AARCH64_INS_LDSMAXAB:
    case AARCH64_INS_LDSMAXAH:
    case AARCH64_INS_LDSMINA:
    case AARCH64_INS_LDSMINAB:
    case AARCH64_INS_LDSMINAH:
    case AARCH64_INS_LDUMAXA:
    case AARCH64_INS_LDUMAXAB:
    case AARCH64_INS_LDUMAXAH:
    case AARCH64_INS_LDUMINA:
    case AARCH64_INS_LDUMINAB:
    case AARCH64_INS_LDUMINAH:

    case AARCH64_INS_LDADDAL:
    case AARCH64_INS_LDADDALB:
    case AARCH64_INS_LDADDALH:
    case AARCH64_INS_LDCLRAL:
    case AARCH64_INS_LDCLRALB:
    case AARCH64_INS_LDCLRALH:
    case AARCH64_INS_LDEORAL:
    case AARCH64_INS_LDEORALB:
    case AARCH64_INS_LDEORALH:
    case AARCH64_INS_LDSETAL:
    case AARCH64_INS_LDSETALB:
    case AARCH64_INS_LDSETALH:
    case AARCH64_INS_LDSMAXAL:
    case AARCH64_INS_LDSMAXALB:
    case AARCH64_INS_LDSMAXALH:
    case AARCH64_INS_LDSMINAL:
    case AARCH64_INS_LDSMINALB:
    case AARCH64_INS_LDSMINALH:
    case AARCH64_INS_LDUMAXAL:
    case AARCH64_INS_LDUMAXALB:
    case AARCH64_INS_LDUMAXALH:
    case AARCH64_INS_LDUMINAL:
    case AARCH64_INS_LDUMINALB:
    case AARCH64_INS_LDUMINALH:

    case AARCH64_INS_LDADDL:
    case AARCH64_INS_LDADDLB:
    case AARCH64_INS_LDADDLH:
    case AARCH64_INS_LDCLRL:
    case AARCH64_INS_LDCLRLB:
    case AARCH64_INS_LDCLRLH:
    case AARCH64_INS_LDEORL:
    case AARCH64_INS_LDEORLB:
    case AARCH64_INS_LDEORLH:
    case AARCH64_INS_LDSETL:
    case AARCH64_INS_LDSETLB:
    case AARCH64_INS_LDSETLH:
    case AARCH64_INS_LDSMAXL:
    case AARCH64_INS_LDSMAXLB:
    case AARCH64_INS_LDSMAXLH:
    case AARCH64_INS_LDSMINL:
    case AARCH64_INS_LDSMINLB:
    case AARCH64_INS_LDSMINLH:
    case AARCH64_INS_LDUMAXL:
    case AARCH64_INS_LDUMAXLB:
    case AARCH64_INS_LDUMAXLH:
    case AARCH64_INS_LDUMINL:
    case AARCH64_INS_LDUMINLB:
    case AARCH64_INS_LDUMINLH:

    case AARCH64_INS_SWPA:
    case AARCH64_INS_SWPAL:
    case AARCH64_INS_SWPL:
    case AARCH64_INS_SWPAB:
    case AARCH64_INS_SWPALB:
    case AARCH64_INS_SWPLB:
    case AARCH64_INS_SWPAH:
    case AARCH64_INS_SWPALH:
    case AARCH64_INS_SWPLH:

    case AARCH64_INS_LDAXRB:
    case AARCH64_INS_LDAXRH:
    case AARCH64_INS_LDAXR:
    case AARCH64_INS_LDAXP:
    case AARCH64_INS_LDXRB:
    case AARCH64_INS_LDXRH:
    case AARCH64_INS_LDXR:
    case AARCH64_INS_LDXP:
    case AARCH64_INS_STXRB:
    case AARCH64_INS_STXRH:
    case AARCH64_INS_STXR:
    case AARCH64_INS_STXP:
    case AARCH64_INS_LDLARB:
    case AARCH64_INS_LDLARH:
    case AARCH64_INS_LDLAR:
    case AARCH64_INS_STLXRB:
    case AARCH64_INS_STLXRH:
    case AARCH64_INS_STLXR:
    case AARCH64_INS_STLXP:
    case AARCH64_INS_LDARB:
    case AARCH64_INS_LDARH:
    case AARCH64_INS_LDAR:
    case AARCH64_INS_STLRB:
    case AARCH64_INS_STLRH:
    case AARCH64_INS_STLR:

    case AARCH64_INS_DMB:
        return INST_ATOMIC;
    
    case AARCH64_INS_CCMN:
    case AARCH64_INS_CCMP:
    case AARCH64_INS_CSEL:
    case AARCH64_INS_CSINC:
    case AARCH64_INS_CSINV:
    case AARCH64_INS_CSNEG:
        return INST_CC_OP;

    case AARCH64_INS_LDP:
    case AARCH64_INS_LDPSW:
    case AARCH64_INS_LDR:
    case AARCH64_INS_LDUR:
    case AARCH64_INS_LDRB:
    case AARCH64_INS_LDURB:
    case AARCH64_INS_LDRH:
    case AARCH64_INS_LDURH:
    case AARCH64_INS_LDRSB:
    case AARCH64_INS_LDURSB:
    case AARCH64_INS_LDRSH:
    case AARCH64_INS_LDURSH:
    case AARCH64_INS_LDRSW:
    case AARCH64_INS_LDURSW:
        if (first_op_isgr) {
            return INST_LOAD;
        } else if (first_op_isfr) {
            return INST_FP_LOAD;
        }

    case AARCH64_INS_STP:
    case AARCH64_INS_STR:
    case AARCH64_INS_STUR:
    case AARCH64_INS_STRB:
    case AARCH64_INS_STURB:
    case AARCH64_INS_STRH:
    case AARCH64_INS_STURH:
        if (first_op_isgr) {
            return INST_STORE;
        } else if (first_op_isfr) {
            return INST_FP_STORE;
        }
        break;

    case AARCH64_INS_SVC:
        return INST_SYSCALL;

    case AARCH64_INS_LD1:
    case AARCH64_INS_LD2:
    case AARCH64_INS_LD3:
    case AARCH64_INS_LD4:
    case AARCH64_INS_LD1R:
    case AARCH64_INS_LD2R:
    case AARCH64_INS_LD3R:
    case AARCH64_INS_LD4R:
        return INST_FP_LOAD;

    case AARCH64_INS_ST1:
    case AARCH64_INS_ST2:
    case AARCH64_INS_ST3:
    case AARCH64_INS_ST4:
        return INST_FP_STORE;

    case AARCH64_INS_UMOV:
        return INST_GR_FR_MOV;


    case AARCH64_INS_FABD:
    case AARCH64_INS_FABS:
    case AARCH64_INS_FACGE:
    case AARCH64_INS_FACGT:
    case AARCH64_INS_FADD:
    case AARCH64_INS_FADDP:
    case AARCH64_INS_FDIV:
    case AARCH64_INS_FMLA:
    case AARCH64_INS_FMLAL:
    case AARCH64_INS_FMLAL2:
    case AARCH64_INS_FMADD:
    case AARCH64_INS_FNMADD:
    case AARCH64_INS_FMSUB:
    case AARCH64_INS_FNMSUB:
    case AARCH64_INS_FNEG:
    case AARCH64_INS_FMUL:
    case AARCH64_INS_FMULX:
    case AARCH64_INS_FNMUL:
    case AARCH64_INS_FSQRT:
    case AARCH64_INS_FSUB:

    case AARCH64_INS_FCSEL:

    case AARCH64_INS_FRINT32X:
    case AARCH64_INS_FRINT32Z:
    case AARCH64_INS_FRINT64X:
    case AARCH64_INS_FRINT64Z:

    case AARCH64_INS_FRINTA:
    case AARCH64_INS_FRINTM:
    case AARCH64_INS_FRINTN:
    case AARCH64_INS_FRINTP:
    case AARCH64_INS_FRINTI:
    case AARCH64_INS_FRINTZ:

    case AARCH64_INS_SCVTF:
    case AARCH64_INS_UCVTF:

    case AARCH64_INS_FCCMP:
    case AARCH64_INS_FCCMPE:
    case AARCH64_INS_FCMP:
    case AARCH64_INS_FCMPE:

    case AARCH64_INS_FCMEQ:
    case AARCH64_INS_FCMNE:
    case AARCH64_INS_FCMGE:
    case AARCH64_INS_FCMLE:
    case AARCH64_INS_FCMGT:
    case AARCH64_INS_FCMLT:
    case AARCH64_INS_FCMUO:

    case AARCH64_INS_FMAX:
    case AARCH64_INS_FMAXNM:
    case AARCH64_INS_FMAXP:
    case AARCH64_INS_FMAXNMP:
    case AARCH64_INS_FMAXV:
    case AARCH64_INS_FMAXNMV:
    case AARCH64_INS_FMIN:
    case AARCH64_INS_FMINNM:
    case AARCH64_INS_FMINP:
    case AARCH64_INS_FMINNMP:
    case AARCH64_INS_FMINV:
    case AARCH64_INS_FMINNMV:

    case AARCH64_INS_BFDOT:
    case AARCH64_INS_BFMLALB:
    case AARCH64_INS_BFMLALT:
    case AARCH64_INS_BFMMLA:
    case AARCH64_INS_FCADD:
    case AARCH64_INS_FCMLA:
    case AARCH64_INS_FRECPE:
    case AARCH64_INS_FRECPS:
    case AARCH64_INS_FRECPX:
    case AARCH64_INS_FRSQRTE:
    case AARCH64_INS_FRSQRTS:

    case AARCH64_INS_ABS:
    case AARCH64_INS_ADDP:
    case AARCH64_INS_ADDV:
    case AARCH64_INS_ADDHN:
    case AARCH64_INS_ADDHN2:
    case AARCH64_INS_RADDHN:
    case AARCH64_INS_RADDHN2:
    case AARCH64_INS_SUBHN:
    case AARCH64_INS_SUBHN2:
    case AARCH64_INS_RSUBHN:
    case AARCH64_INS_RSUBHN2:

    case AARCH64_INS_SABA:
    case AARCH64_INS_UABA:
    case AARCH64_INS_SABAL:
    case AARCH64_INS_UABAL:
    case AARCH64_INS_SABAL2:
    case AARCH64_INS_UABAL2:
    case AARCH64_INS_SABD:
    case AARCH64_INS_UABD:
    case AARCH64_INS_SABDL:
    case AARCH64_INS_UABDL:
    case AARCH64_INS_SABDL2:
    case AARCH64_INS_UABDL2:
    case AARCH64_INS_SADALP:
    case AARCH64_INS_UADALP:
    case AARCH64_INS_SADDL:
    case AARCH64_INS_UADDL:
    case AARCH64_INS_SADDL2:
    case AARCH64_INS_UADDL2:
    case AARCH64_INS_SADDLP:
    case AARCH64_INS_UADDLP:
    case AARCH64_INS_SADDLV:
    case AARCH64_INS_UADDLV:
    case AARCH64_INS_SADDW:
    case AARCH64_INS_UADDW:
    case AARCH64_INS_SADDW2:
    case AARCH64_INS_UADDW2:
    case AARCH64_INS_SHSUB:
    case AARCH64_INS_UHSUB:
    case AARCH64_INS_SQABS:
    case AARCH64_INS_SQADD:
    case AARCH64_INS_UQADD:
    case AARCH64_INS_SQNEG:
    case AARCH64_INS_SQSUB:
    case AARCH64_INS_UQSUB:
    case AARCH64_INS_SQXTN:
    case AARCH64_INS_UQXTN:
    case AARCH64_INS_SQXTN2:
    case AARCH64_INS_UQXTN2:
    case AARCH64_INS_SQXTUN:
    case AARCH64_INS_SQXTUN2:
    case AARCH64_INS_SHADD:
    case AARCH64_INS_UHADD:
    case AARCH64_INS_SRHADD:
    case AARCH64_INS_URHADD:
    case AARCH64_INS_SSUBL:
    case AARCH64_INS_USUBL:
    case AARCH64_INS_SSUBL2:
    case AARCH64_INS_USUBL2:
    case AARCH64_INS_SSUBW:
    case AARCH64_INS_USUBW:
    case AARCH64_INS_SSUBW2:
    case AARCH64_INS_SUQADD:
    case AARCH64_INS_USQADD:

    case AARCH64_INS_CMEQ:
    case AARCH64_INS_CMGE:
    case AARCH64_INS_CMGT:
    case AARCH64_INS_CMHI:
    case AARCH64_INS_CMHS:
    case AARCH64_INS_CMLA:
    case AARCH64_INS_CMLE:
    case AARCH64_INS_CMLT:
    case AARCH64_INS_CMTST:
    case AARCH64_INS_SMIN:
    case AARCH64_INS_SMINP:
    case AARCH64_INS_SMINV:
    case AARCH64_INS_UMIN:
    case AARCH64_INS_UMINP:
    case AARCH64_INS_UMINV:
    case AARCH64_INS_SMAX:
    case AARCH64_INS_SMAXP:
    case AARCH64_INS_SMAXV:
    case AARCH64_INS_UMAX:
    case AARCH64_INS_UMAXP:
    case AARCH64_INS_UMAXV:

    case AARCH64_INS_BIF:
    case AARCH64_INS_BIT:
    case AARCH64_INS_BSL:

    case AARCH64_INS_CNT:
    case AARCH64_INS_EXT:
    case AARCH64_INS_REV64:
    case AARCH64_INS_SLI:
    case AARCH64_INS_SRI:
    case AARCH64_INS_TRN1:
    case AARCH64_INS_TRN2:
    case AARCH64_INS_UZP1:
    case AARCH64_INS_UZP2:
    case AARCH64_INS_ZIP1:
    case AARCH64_INS_ZIP2:

    case AARCH64_INS_FMLS:

    case AARCH64_INS_DUP:
    case AARCH64_INS_MOVI:
    case AARCH64_INS_MVNI:
    case AARCH64_INS_TBL:
    case AARCH64_INS_TBX:
    case AARCH64_INS_XTN:
    case AARCH64_INS_XTN2:


    case AARCH64_INS_SHRN:
    case AARCH64_INS_SHRN2:
    case AARCH64_INS_RSHRN:
    case AARCH64_INS_RSHRN2:

    case AARCH64_INS_SHL:
    case AARCH64_INS_SHLL:
    case AARCH64_INS_SHLL2:

    case AARCH64_INS_SQRSHL:
    case AARCH64_INS_UQRSHL:

    case AARCH64_INS_SQSHRN:
    case AARCH64_INS_UQSHRN:
    case AARCH64_INS_SQSHRN2:
    case AARCH64_INS_UQSHRN2:
    case AARCH64_INS_SQRSHRN:
    case AARCH64_INS_UQRSHRN:
    case AARCH64_INS_SQRSHRN2:
    case AARCH64_INS_UQRSHRN2:

    case AARCH64_INS_SQSHRUN:
    case AARCH64_INS_SQSHRUN2:
    case AARCH64_INS_SQRSHRUN:
    case AARCH64_INS_SQRSHRUN2:

    case AARCH64_INS_SQSHL:
    case AARCH64_INS_UQSHL:
    case AARCH64_INS_SQSHLU:

    case AARCH64_INS_SSHL:
    case AARCH64_INS_SRSHL:
    case AARCH64_INS_SSHR:
    case AARCH64_INS_SRSHR:
    case AARCH64_INS_SSRA:
    case AARCH64_INS_SRSRA:
    case AARCH64_INS_USHL:
    case AARCH64_INS_URSHL:
    case AARCH64_INS_USHR:
    case AARCH64_INS_URSHR:
    case AARCH64_INS_USRA:
    case AARCH64_INS_URSRA:


    case AARCH64_INS_SSHLL:
    case AARCH64_INS_SSHLL2:
    case AARCH64_INS_USHLL:
    case AARCH64_INS_USHLL2:

    case AARCH64_INS_MLA:
    case AARCH64_INS_MLS:

    case AARCH64_INS_SMLAL:
    case AARCH64_INS_SMLSL:
    case AARCH64_INS_SMLAL2:
    case AARCH64_INS_SMLSL2:
    case AARCH64_INS_UMLAL:
    case AARCH64_INS_UMLSL:
    case AARCH64_INS_UMLAL2:
    case AARCH64_INS_UMLSL2:
    case AARCH64_INS_SMULL2:
    case AARCH64_INS_UMULL2:

    case AARCH64_INS_SQDMLAL:
    case AARCH64_INS_SQDMLSL:
    case AARCH64_INS_SQDMLAL2:
    case AARCH64_INS_SQDMLSL2:
    case AARCH64_INS_SQDMULL2:
    case AARCH64_INS_SQRDMLAH:
    case AARCH64_INS_SQRDMLSH:

    case AARCH64_INS_SQDMULH:
    case AARCH64_INS_SQRDMULH:

        g_assert(first_op_isfr);
        return INST_FP_ARITH;

    case AARCH64_INS_BFCVT:
    case AARCH64_INS_FCVT:
    case AARCH64_INS_FCVTL:
    case AARCH64_INS_FCVTL2:
    case AARCH64_INS_FCVTN:
    case AARCH64_INS_FCVTN2:
    case AARCH64_INS_FCVTXN:
    case AARCH64_INS_FCVTXN2:
    case AARCH64_INS_FCVTAS:
    case AARCH64_INS_FCVTMS:
    case AARCH64_INS_FCVTNS:
    case AARCH64_INS_FCVTPS:
    case AARCH64_INS_FCVTZS:
    case AARCH64_INS_FCVTAU:
    case AARCH64_INS_FCVTMU:
    case AARCH64_INS_FCVTNU:
    case AARCH64_INS_FCVTPU:
    case AARCH64_INS_FCVTZU:
        return INST_FP_ARITH;
    
    case AARCH64_INS_FMOV:
        if (first_op_isfr && second_op_isfr) {
            return INST_FP_ARITH;
        } else {
            return INST_GR_FR_MOV;
        }

    default:
        break;
    }
    if (insn->id == AARCH64_INS_MOV) {
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

    if (insn->alias_id == AARCH64_INS_ALIAS_MOV) {
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

    if (insn->id == AARCH64_INS_MRS) {
        if (insn->detail->aarch64.op_count == 2) {
            if (
                first_op_isgr &&
                (insn->detail->aarch64.operands[1].type == AARCH64_OP_SYSREG && insn->detail->aarch64.operands[1].sysop.sub_type == AARCH64_OP_REG_MRS)
            ) {
                int r = insn->detail->aarch64.operands[1].sysop.reg.sysreg;
                if (
                    r == AARCH64_SYSREG_TPIDR_EL0 ||
                    r == AARCH64_SYSREG_FPCR ||
                    r == AARCH64_SYSREG_MIDR_EL1 ||
                    r == AARCH64_SYSREG_DCZID_EL0
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
    { "aarch64",   CS_ARCH_AARCH64, cs_mode(CS_MODE_LITTLE_ENDIAN)                    , AARCH64_INS_ENDING, aarch64_get_insn_cat},
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
