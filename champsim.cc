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

#include <fcntl.h>
#include <sys/mman.h>

#include <capstone/capstone.h>
#if CS_NEXT_VERSION < 6
#error "capstone version mismatch"
#endif
extern "C" {
#include "qemu-plugin.h"
}

#define TARGET_IA32E

typedef enum
{
    REG_INVALID_ = 0,
    REG_NONE     = 1,
    REG_FIRST    = 2,

    // base for all kinds of registers (application, machine, pin)
    REG_RBASE,

    // Machine registers are individual real registers on the machine
    REG_MACHINE_BASE = REG_RBASE,

    // Application registers are registers used in the application binary
    // Application registers include all machine registers. In addition,
    // they include some aggregrate registers that can be accessed by
    // the application in a single instruction
    // Essentially, application registers = individual machine registers + aggregrate registers

    REG_APPLICATION_BASE = REG_RBASE,

    /* !@ todo: should save scratch mmx and fp registers */
    // The machine registers that form a context. These are the registers
    // that need to be saved in a context switch.
    REG_PHYSICAL_INTEGER_BASE = REG_RBASE,

    REG_TO_SPILL_BASE = REG_RBASE,

    REG_GR_BASE = REG_RBASE,
#if defined(TARGET_IA32E)
    // Context registers in the Intel(R) 64 architecture
    REG_RDI = REG_GR_BASE,   ///< rdi
    REG_GDI = REG_RDI,       ///< edi on a 32 bit machine, rdi on 64
    REG_RSI,                 ///< rsi
    REG_GSI = REG_RSI,       ///< esi on a 32 bit machine, rsi on 64
    REG_RBP,                 ///< rbp
    REG_GBP = REG_RBP,       ///< ebp on a 32 bit machine, rbp on 64
    REG_RSP,                 ///< rsp
    REG_STACK_PTR = REG_RSP, ///< esp on a 32 bit machine, rsp on 64
    REG_RBX,                 ///< rbx
    REG_GBX = REG_RBX,       ///< ebx on a 32 bit machine, rbx on 64
    REG_RDX,                 ///< rdx
    REG_GDX = REG_RDX,       ///< edx on a 32 bit machine, rdx on 64
    REG_RCX,                 ///< rcx
    REG_GCX = REG_RCX,       ///< ecx on a 32 bit machine, rcx on 64
    REG_RAX,                 ///< rax
    REG_GAX = REG_RAX,       ///< eax on a 32 bit machine, rax on 64
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_GR_LAST = REG_R15,

    REG_SEG_BASE,
    REG_SEG_CS = REG_SEG_BASE,
    REG_SEG_SS,
    REG_SEG_DS,
    REG_SEG_ES,
    REG_SEG_FS,
    REG_SEG_GS,
    REG_SEG_LAST = REG_SEG_GS,

    REG_RFLAGS,              ///< rflags
    REG_GFLAGS = REG_RFLAGS, ///< eflags on a 32 bit machine, rflags on 64
    REG_RIP,
    REG_INST_PTR = REG_RIP,
#else // not defined(TARGET_IA32E)
    // Context registers in the IA-32 architecture
    REG_EDI = REG_GR_BASE,
    REG_GDI = REG_EDI,
    REG_ESI,
    REG_GSI = REG_ESI,
    REG_EBP,
    REG_GBP = REG_EBP,
    REG_ESP,
    REG_STACK_PTR = REG_ESP,
    REG_EBX,
    REG_GBX = REG_EBX,
    REG_EDX,
    REG_GDX = REG_EDX,
    REG_ECX,
    REG_GCX = REG_ECX,
    REG_EAX,
    REG_GAX     = REG_EAX,
    REG_GR_LAST = REG_EAX,

    REG_SEG_BASE,
    REG_SEG_CS = REG_SEG_BASE,
    REG_SEG_SS,
    REG_SEG_DS,
    REG_SEG_ES,
    REG_SEG_FS,
    REG_SEG_GS,
    REG_SEG_LAST = REG_SEG_GS,

    REG_EFLAGS,
    REG_GFLAGS = REG_EFLAGS,
    REG_EIP,
    REG_INST_PTR = REG_EIP,
#endif // not defined(TARGET_IA32E)

    REG_PHYSICAL_INTEGER_END = REG_INST_PTR,
    // partial registers common to both the IA-32 and Intel(R) 64 architectures.
    REG_AL,
    REG_AH,
    REG_AX,

    REG_CL,
    REG_CH,
    REG_CX,

    REG_DL,
    REG_DH,
    REG_DX,

    REG_BL,
    REG_BH,
    REG_BX,

    REG_BP,
    REG_SI,
    REG_DI,

    REG_SP,
    REG_FLAGS,
    REG_IP,

#if defined(TARGET_IA32E)
    // partial registers in the Intel(R) 64 architecture
    REG_EDI,
    REG_DIL,
    REG_ESI,
    REG_SIL,
    REG_EBP,
    REG_BPL,
    REG_ESP,
    REG_SPL,
    REG_EBX,
    REG_EDX,
    REG_ECX,
    REG_EAX,
    REG_EFLAGS,
    REG_EIP,

    REG_R8B,
    REG_R8W,
    REG_R8D,
    REG_R9B,
    REG_R9W,
    REG_R9D,
    REG_R10B,
    REG_R10W,
    REG_R10D,
    REG_R11B,
    REG_R11W,
    REG_R11D,
    REG_R12B,
    REG_R12W,
    REG_R12D,
    REG_R13B,
    REG_R13W,
    REG_R13D,
    REG_R14B,
    REG_R14W,
    REG_R14D,
    REG_R15B,
    REG_R15W,
    REG_R15D,
#endif // not defined(TARGET_IA32E)

    REG_MM_BASE,
    REG_MM0 = REG_MM_BASE,
    REG_MM1,
    REG_MM2,
    REG_MM3,
    REG_MM4,
    REG_MM5,
    REG_MM6,
    REG_MM7,
    REG_MM_LAST = REG_MM7,

    REG_XMM_BASE,
    REG_FIRST_FP_REG = REG_XMM_BASE,
    REG_XMM0         = REG_XMM_BASE,
    REG_XMM1,
    REG_XMM2,
    REG_XMM3,
    REG_XMM4,
    REG_XMM5,
    REG_XMM6,
    REG_XMM7,

#if defined(TARGET_IA32E)
    // additional xmm registers in the Intel(R) 64 architecture
    REG_XMM8,
    REG_XMM9,
    REG_XMM10,
    REG_XMM11,
    REG_XMM12,
    REG_XMM13,
    REG_XMM14,
    REG_XMM15,
    REG_XMM_SSE_LAST = REG_XMM15,
    REG_XMM_AVX_LAST = REG_XMM_SSE_LAST,
    REG_XMM_AVX512_HI16_FIRST,
    REG_XMM16 = REG_XMM_AVX512_HI16_FIRST,
    REG_XMM17,
    REG_XMM18,
    REG_XMM19,
    REG_XMM20,
    REG_XMM21,
    REG_XMM22,
    REG_XMM23,
    REG_XMM24,
    REG_XMM25,
    REG_XMM26,
    REG_XMM27,
    REG_XMM28,
    REG_XMM29,
    REG_XMM30,
    REG_XMM31,
    REG_XMM_AVX512_HI16_LAST = REG_XMM31,
    REG_XMM_AVX512_LAST      = REG_XMM_AVX512_HI16_LAST,
    REG_XMM_LAST             = REG_XMM_AVX512_LAST,
#else // not TARGET_IA32E
    REG_XMM_SSE_LAST    = REG_XMM7,
    REG_XMM_AVX_LAST    = REG_XMM_SSE_LAST,
    REG_XMM_AVX512_LAST = REG_XMM_AVX_LAST,
    REG_XMM_LAST        = REG_XMM_AVX512_LAST,
#endif // not TARGET_IA32E

    REG_YMM_BASE,
    REG_YMM0 = REG_YMM_BASE,
    REG_YMM1,
    REG_YMM2,
    REG_YMM3,
    REG_YMM4,
    REG_YMM5,
    REG_YMM6,
    REG_YMM7,

#if defined(TARGET_IA32E)
    // additional ymm registers in the Intel(R) 64 architecture
    REG_YMM8,
    REG_YMM9,
    REG_YMM10,
    REG_YMM11,
    REG_YMM12,
    REG_YMM13,
    REG_YMM14,
    REG_YMM15,
    REG_YMM_AVX_LAST = REG_YMM15,
    REG_YMM_AVX512_HI16_FIRST,
    REG_YMM16 = REG_YMM_AVX512_HI16_FIRST,
    REG_YMM17,
    REG_YMM18,
    REG_YMM19,
    REG_YMM20,
    REG_YMM21,
    REG_YMM22,
    REG_YMM23,
    REG_YMM24,
    REG_YMM25,
    REG_YMM26,
    REG_YMM27,
    REG_YMM28,
    REG_YMM29,
    REG_YMM30,
    REG_YMM31,
    REG_YMM_AVX512_HI16_LAST = REG_YMM31,
    REG_YMM_AVX512_LAST      = REG_YMM_AVX512_HI16_LAST,
    REG_YMM_LAST             = REG_YMM_AVX512_LAST,
#else // not TARGET_IA32E
    REG_YMM_AVX_LAST    = REG_YMM7,
    REG_YMM_AVX512_LAST = REG_YMM_AVX_LAST,
    REG_YMM_LAST        = REG_YMM_AVX512_LAST,
#endif // not TARGET_IA32E

    REG_ZMM_BASE,
    REG_ZMM0 = REG_ZMM_BASE,
    REG_ZMM1,
    REG_ZMM2,
    REG_ZMM3,
    REG_ZMM4,
    REG_ZMM5,
    REG_ZMM6,
    REG_ZMM7,
#if defined(TARGET_IA32E)
    REG_ZMM8,
    REG_ZMM9,
    REG_ZMM10,
    REG_ZMM11,
    REG_ZMM12,
    REG_ZMM13,
    REG_ZMM14,
    REG_ZMM15,
    REG_ZMM_AVX512_SPLIT_LAST = REG_ZMM15,
    REG_ZMM_AVX512_HI16_FIRST,
    REG_ZMM16 = REG_ZMM_AVX512_HI16_FIRST,
    REG_ZMM17,
    REG_ZMM18,
    REG_ZMM19,
    REG_ZMM20,
    REG_ZMM21,
    REG_ZMM22,
    REG_ZMM23,
    REG_ZMM24,
    REG_ZMM25,
    REG_ZMM26,
    REG_ZMM27,
    REG_ZMM28,
    REG_ZMM29,
    REG_ZMM30,
    REG_ZMM31,
    REG_ZMM_AVX512_HI16_LAST = REG_ZMM31,
    REG_ZMM_AVX512_LAST      = REG_ZMM_AVX512_HI16_LAST,
    REG_ZMM_LAST             = REG_ZMM_AVX512_LAST,
#else // not defined(TARGET_IA32E)
    REG_ZMM_AVX512_SPLIT_LAST = REG_ZMM7,
    REG_ZMM_AVX512_LAST       = REG_ZMM_AVX512_SPLIT_LAST,
    REG_ZMM_LAST              = REG_ZMM_AVX512_LAST,
#endif // not defined(TARGET_IA32E)

    REG_K_BASE,
    REG_K0 = REG_K_BASE,
    // The K0 opmask register cannot be used as the write mask operand of an AVX512 instruction.
    // However the encoding of K0 as the write mask operand is legal and is used as an implicit full mask.
    REG_IMPLICIT_FULL_MASK = REG_K0,
    REG_K1,
    REG_K2,
    REG_K3,
    REG_K4,
    REG_K5,
    REG_K6,
    REG_K7,
    REG_K_LAST = REG_K7,

#if defined(TARGET_IA32E)
    REG_TMM0, ///< tmm0 on a 64 bit machine
    REG_TMM1, ///< tmm1 on a 64 bit machine
    REG_TMM2, ///< tmm2 on a 64 bit machine
    REG_TMM3, ///< tmm3 on a 64 bit machine
    REG_TMM4, ///< tmm4 on a 64 bit machine
    REG_TMM5, ///< tmm5 on a 64 bit machine
    REG_TMM6, ///< tmm6 on a 64 bit machine
    REG_TMM7, ///< tmm7 on a 64 bit machine
    REG_TMM_FIRST = REG_TMM0,
    REG_TMM_LAST  = REG_TMM7,

    /*!
     * Virtual register representing CPU internal tile control register (AMX tile configuration)
     * Contains AMX metadata about palette, tiles sizes and so on.
     * See SDM's LDTILECFG instruction for more details.
     */
    REG_TILECONFIG,

#endif

    REG_MXCSR,
    REG_MXCSRMASK,

// This corresponds to the "orig_eax" register that is visible
// to some debuggers.
#if defined(TARGET_IA32E)
    REG_ORIG_RAX,
    REG_ORIG_GAX = REG_ORIG_RAX,
#else // not defined(TARGET_IA32E)
    REG_ORIG_EAX,
    REG_ORIG_GAX = REG_ORIG_EAX,
#endif // not defined(TARGET_IA32E)

    REG_FPST_BASE,
    REG_FPSTATUS_BASE = REG_FPST_BASE,
    REG_FPCW          = REG_FPSTATUS_BASE,
    REG_FPSW,
    REG_FPTAG, ///< Abridged 8-bit version of x87 tag register.
    REG_FPIP_OFF,
    REG_FPIP_SEL,
    REG_FPOPCODE,
    REG_FPDP_OFF,
    REG_FPDP_SEL,
    REG_FPSTATUS_LAST = REG_FPDP_SEL,

    REG_ST_BASE,
    REG_ST0 = REG_ST_BASE,
    REG_ST1,
    REG_ST2,
    REG_ST3,
    REG_ST4,
    REG_ST5,
    REG_ST6,
    REG_ST7,
    REG_ST_LAST   = REG_ST7,
    REG_FPST_LAST = REG_ST_LAST,

    REG_DR_BASE,
    REG_DR0 = REG_DR_BASE,
    REG_DR1,
    REG_DR2,
    REG_DR3,
    REG_DR4,
    REG_DR5,
    REG_DR6,
    REG_DR7,
    REG_DR_LAST = REG_DR7,

    REG_CR_BASE,
    REG_CR0 = REG_CR_BASE,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4,
    REG_CR_LAST = REG_CR4,
#if defined(TARGET_IA32E)
    REG_CR8,
#endif

    REG_TSSR,
    REG_LDTR,

    REG_TR_BASE,
    REG_TR = REG_TR_BASE,
    REG_TR3,
    REG_TR4,
    REG_TR5,
    REG_TR6,
    REG_TR7,
    REG_TR_LAST = REG_TR7,

    REG_MACHINE_LAST = REG_TR_LAST, /* last machine register */
} REG;


#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4

using namespace std;

typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value

    unsigned char is_branch;    // is this branch
    unsigned char branch_taken; // if so, is this taken

    unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
} trace_instr_format_t;


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


// typedef __int128 insn_code;
typedef uint64_t insn_code;

insn_code insn_code_init(uint64_t pc, const uint8_t* data, int size) {
    // insn_code r = 0;
    // for (size_t i = 0; i < size; i++)
    // {
    //     r <<= 8;
    //     r |= data[i];
    // }
    // return r;
    return pc;
}

map<insn_code, void*> insn_code_data;

// trace_instr_format_t curr_instr;

int64_t REAL_INSN_COUNT;
int64_t TRACE_COUNT = 10000;
int64_t TRACE_SKIP_COUNT = 10000;
const char* trace_filename;
int trace_fd;
uint64_t filesize;
trace_instr_format_t* trace_buffer;
int64_t trace_buffer_index = -1;

// branch types
enum branch_type {
  NOT_BRANCH = 0,
  BRANCH_DIRECT_JUMP = 1,
  BRANCH_INDIRECT = 2,
  BRANCH_CONDITIONAL = 3,
  BRANCH_DIRECT_CALL = 4,
  BRANCH_INDIRECT_CALL = 5,
  BRANCH_RETURN = 6,
  BRANCH_OTHER = 7
};

int x64_insn_is_branch(const cs_insn * insn) {
    switch (insn->id)
    {
    case X86_INS_JAE ... X86_INS_JS:
    case X86_INS_LOOPNE:
    case X86_INS_LOOPE:
    case X86_INS_LOOP:

    case X86_INS_JMP:
    case X86_INS_LJMP:
    case X86_INS_CALL:
    case X86_INS_LCALL:
    case X86_INS_RET:
    case X86_INS_IRET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return 1;
    default:
        return 0;
    }
    return 0;
}

int aarch64_insn_is_branch(const cs_insn * insn) {
    uint32_t code = *(uint32_t*)insn->bytes;
    if (code >> 26 == 5) {
        return BRANCH_DIRECT_JUMP;
    }
    switch (insn->id)
    {
    case AArch64_INS_BC:
    case AArch64_INS_CBNZ:
    case AArch64_INS_CBZ:
    case AArch64_INS_TBNZ:
    case AArch64_INS_TBZ:
    case AArch64_INS_B://cs bug
        return BRANCH_CONDITIONAL;
        // return BRANCH_DIRECT_JUMP;
    case AArch64_INS_BL:
        return BRANCH_DIRECT_CALL;
    case AArch64_INS_BLR:
        return BRANCH_INDIRECT_CALL;
    case AArch64_INS_BR:
        return BRANCH_INDIRECT;
    case AArch64_INS_RET:
        return BRANCH_RETURN;
    default:
        return NOT_BRANCH;
    }
    return NOT_BRANCH;
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

struct target_info{
    const char *name;
    cs_arch arch;
    cs_mode mode;
    int op_max;
    int (*insn_is_branch)(const cs_insn *);
    // void (*disas_log)(const DisasContextBase *db, CPUState *cpu, FILE *f);
};


target_info all_archs[] = {
    { "aarch64",   CS_ARCH_AARCH64, cs_mode(CS_MODE_LITTLE_ENDIAN)                  , AArch64_INS_ENDING, aarch64_insn_is_branch},
    { "mips64el",  CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)   , MIPS_INS_ENDING , },
    { "mips64",    CS_ARCH_MIPS,  cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)      , MIPS_INS_ENDING , },
    { "i386",      CS_ARCH_X86,   cs_mode(CS_MODE_32)                               , X86_INS_ENDING  , },
    { "x86_64",    CS_ARCH_X86,   cs_mode(CS_MODE_64)                               , X86_INS_ENDING  , x64_insn_is_branch},
    { "riscv32",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32 | CS_MODE_RISCVC)         , RISCV_INS_ENDING},
    { "riscv64",   CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCVC)         , RISCV_INS_ENDING, riscv64_insn_is_branch},
    { NULL }
};

target_info* target;
bool verbose;
bool early_exit;
static void plugin_init(const qemu_info_t* info) {
    fprintf(stderr, "sizeof(trace_instr_format):%zu\n",
            sizeof(trace_instr_format));
    if (getenv("VERBOSE")) {
        verbose = true;
    }
    if (getenv("EARLY_EXIT")) {
        early_exit = true;
    }
    const char* TRACE_COUNT_ENV = getenv("TRACE_COUNT");
    if (TRACE_COUNT_ENV) {
        TRACE_COUNT = atoll(TRACE_COUNT_ENV);
    }

    const char* TRACE_SKIP_COUNT_ENV = getenv("TRACE_SKIP_COUNT");
    if (TRACE_SKIP_COUNT_ENV) {
        TRACE_SKIP_COUNT = atoll(TRACE_SKIP_COUNT_ENV);
    }

    trace_filename = getenv("TRACE_FILENAME");
    if (!trace_filename) {
        trace_filename = "champsim.trace";
    }
    filesize = TRACE_COUNT * sizeof(trace_instr_format_t);
    trace_fd = open(trace_filename, O_RDWR | O_CREAT, (mode_t)0600);
    if (trace_fd < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    int r = ftruncate(trace_fd, TRACE_COUNT * sizeof(trace_instr_format_t));
    if (r < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }

    trace_buffer = (trace_instr_format_t*)mmap(
        0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, trace_fd, 0);

    if (trace_buffer == MAP_FAILED) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    close(trace_fd);

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

void fill_insn_template(trace_instr_format* insn, uint64_t pc,
                        const uint8_t* data, int size) {
    insn->ip = pc;
    insn->branch_taken = size;

    cs_insn *cs_insn;
    size_t count = cs_disasm(cs_handle, (const uint8_t*)data, size, pc, 1, &cs_insn);
    cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
    if (count == 1) {
        int i;
        // fprintf(stderr, "%16lx: %-15s%s\n", addr, cs_insn[j].mnemonic, cs_insn[j].op_str);
        insn->is_branch = target->insn_is_branch(cs_insn);
        cs_err err = cs_regs_access(cs_handle, cs_insn, regs_read, &regs_read_count,
                            regs_write, &regs_write_count);
        if (!err) {
            for (i = 0; i < min((int)regs_read_count, NUM_INSTR_SOURCES); i++) {
                insn->source_registers[i] = regs_read[i];
            }
            for (i = 0; i < min((int)regs_write_count, NUM_INSTR_DESTINATIONS); i++) {
                insn->destination_registers[i] = regs_write[i];
            }
            // if (regs_read_count) {
            //     printf("\tRegisters read:");
            //     for (i = 0; i < regs_read_count; i++) {
            //         printf(" %s", cs_reg_name(cs_handle, regs_read[i]));
            //     }
            //     printf("\n");
            // }

            // if (regs_write_count) {
            //     printf("\tRegisters modified:");
            //     for (i = 0; i < regs_write_count; i++) {
            //         printf(" %s", cs_reg_name(cs_handle, regs_write[i]));
            //     }
            //     printf("\n");
            // }
        } else {
            fprintf(stderr, "%s\n",  cs_strerror(err));
        }
        cs_free(cs_insn, count);
    } else {
        fprintf(stderr, "%8lx:", pc);
        for (int i = 0; i < size; i++) {
            fprintf(stderr, "%02x ", data[i]);
        }
        fprintf(stderr, "\n");
        // abort();
    }



}

void plugin_exit(qemu_plugin_id_t id, void* p) {
    cs_close(&cs_handle);
    if (trace_buffer_index < TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        int r = truncate(trace_filename, min((uint64_t)trace_buffer_index, (uint64_t)TRACE_COUNT) *
                                    sizeof(trace_instr_format_t));
        if (r < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        }
    }
    fprintf(stderr, "plugin fini, trace fini\n");
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    ++ REAL_INSN_COUNT;
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    if (REAL_INSN_COUNT == TRACE_SKIP_COUNT + 1) {
        fprintf(stderr, "trace start\n");
    }
    trace_instr_format* p = (trace_instr_format*)userdata;
    if (trace_buffer_index >= 0 && trace_buffer_index < TRACE_COUNT) {
        trace_instr_format* t = trace_buffer + trace_buffer_index;
        if (t->ip + t->branch_taken != p->ip) {
            t->branch_taken = 1;
        } else {
            t->branch_taken = 0;
        }
        // fprintf(stderr, "cpu:%d, las_pc:%lx, size:%d, curr_pc:%lx, branch_taken:%d\n", vcpu_index, t->ip , t->branch_taken , p->ip, t->branch_taken);
    }
    ++ trace_buffer_index;
    if (trace_buffer_index == TRACE_COUNT) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        fprintf(stderr, "trace fini\n");
        if (early_exit) {
            exit(0);
        }
    } else if (trace_buffer_index < TRACE_COUNT) {
        trace_buffer[trace_buffer_index] = *p;
        if (verbose) {
            printf("cpu:%d, pc:%llx, is_branch:%d\n", vcpu_index, p->ip, p->is_branch);
        }
    }
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    if (REAL_INSN_COUNT <= TRACE_SKIP_COUNT) {
        return;
    }
    trace_instr_format_t* p = trace_buffer + trace_buffer_index;
    bool is_st = qemu_plugin_mem_is_store(info);
    if (trace_buffer_index < TRACE_COUNT) {
        if (is_st) {
            for (size_t i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
                if (p->destination_memory[i] == 0) {
                    p->destination_memory[i] = vaddr;
                    break;
                }
            }
        } else {
            for (size_t i = 0; i < NUM_INSTR_SOURCES; i++) {
                if (p->source_memory[i] == 0) {
                    p->source_memory[i] = vaddr;
                    break;
                }
            }
        }
        if (verbose) {
            printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
                    userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);

        }
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
        int size = qemu_plugin_insn_size(insn);
        insn_code ic = insn_code_init(addr, data, size);
        if (insn_code_data.count(ic) == 0) {
            trace_instr_format* insn_template =
                (trace_instr_format*)aligned_alloc(64,
                                                   sizeof(trace_instr_format));
            memset(insn_template, 0, sizeof(trace_instr_format));
            fill_insn_template(insn_template, addr, data, size);
            insn_code_data[ic] = insn_template;
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                QEMU_PLUGIN_CB_NO_REGS,
                                                (void*)insn_code_data[ic]);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, (void*)addr);
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
