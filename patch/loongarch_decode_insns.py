#!/bin/python3
import json5
import re

header = '''

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

enum LA_OP_TYPE {
    LA_OP_GPR,
    LA_OP_FR,
    LA_OP_VR,
    LA_OP_XR,
    LA_OP_FCC,
    LA_OP_FCSR,
    LA_OP_CSR,
    LA_OP_IMM,
};

const char* la_op_type_name[] = {
    [LA_OP_GPR] = "r",
    [LA_OP_FR] = "f",
    [LA_OP_VR] = "vr",
    [LA_OP_XR] = "xr",
    [LA_OP_FCC] = "fcc",
    [LA_OP_FCSR] = "fcsr",
    [LA_OP_CSR] = "csr",
    [LA_OP_IMM] = "",
};

typedef struct LA_OP {
    int type;
    int val;
}LA_OP;

typedef struct LA_DECODE {
    int id;
    int opcnt;
    LA_OP op[4];
}LA_DECODE;


#define DisasContext LA_DECODE


/**
 * extract32:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 32 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 32 bit word. It is valid to request that
 * all 32 bits are returned (ie @length 32 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.
 */
static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

/**
 * extract8:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 8 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 8 bit word. It is valid to request that
 * all 8 bits are returned (ie @length 8 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.
 */
static inline uint8_t extract8(uint8_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 8 - start);
    return extract32(value, start, length);
}

/**
 * extract16:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 16 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 16 bit word. It is valid to request that
 * all 16 bits are returned (ie @length 16 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.
 */
static inline uint16_t extract16(uint16_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 16 - start);
    return extract32(value, start, length);
}

/**
 * extract64:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 64 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 64 bit word. It is valid to request that
 * all 64 bits are returned (ie @length 64 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.
 */
static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

/**
 * sextract32:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 32 bit input @value the bit field specified by the
 * @start and @length parameters, and return it, sign extended to
 * an int32_t (ie with the most significant bit of the field propagated
 * to all the upper bits of the return value). The bit field must lie
 * entirely within the 32 bit word. It is valid to request that
 * all 32 bits are returned (ie @length 32 and @start 0).
 *
 * Returns: the sign extended value of the bit field extracted from the
 * input value.
 */
static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

/**
 * sextract64:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 64 bit input @value the bit field specified by the
 * @start and @length parameters, and return it, sign extended to
 * an int64_t (ie with the most significant bit of the field propagated
 * to all the upper bits of the return value). The bit field must lie
 * entirely within the 64 bit word. It is valid to request that
 * all 64 bits are returned (ie @length 64 and @start 0).
 *
 * Returns: the sign extended value of the bit field extracted from the
 * input value.
 */
static inline int64_t sextract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int64_t)(value << (64 - length - start))) >> (64 - length);
}

/**
 * deposit32:
 * @value: initial value to insert bit field into
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 * @fieldval: the value to insert into the bit field
 *
 * Deposit @fieldval into the 32 bit @value at the bit field specified
 * by the @start and @length parameters, and return the modified
 * @value. Bits of @value outside the bit field are not modified.
 * Bits of @fieldval above the least significant @length bits are
 * ignored. The bit field must lie entirely within the 32 bit word.
 * It is valid to request that all 32 bits are modified (ie @length
 * 32 and @start 0).
 *
 * Returns: the modified @value.
 */
static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

/**
 * deposit64:
 * @value: initial value to insert bit field into
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 * @fieldval: the value to insert into the bit field
 *
 * Deposit @fieldval into the 64 bit @value at the bit field specified
 * by the @start and @length parameters, and return the modified
 * @value. Bits of @value outside the bit field are not modified.
 * Bits of @fieldval above the least significant @length bits are
 * ignored. The bit field must lie entirely within the 64 bit word.
 * It is valid to request that all 64 bits are modified (ie @length
 * 64 and @start 0).
 *
 * Returns: the modified @value.
 */
static inline uint64_t deposit64(uint64_t value, int start, int length,
                                 uint64_t fieldval)
{
    uint64_t mask;
    assert(start >= 0 && length > 0 && length <= 64 - start);
    mask = (~0ULL >> (64 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

static inline int plus_1(DisasContext *ctx, int x)
{
    return x + 1;
}

static inline int shl_1(DisasContext *ctx, int x)
{
    return x << 1;
}

static inline int shl_2(DisasContext *ctx, int x)
{
    return x << 2;
}

static inline int shl_3(DisasContext *ctx, int x)
{
    return x << 3;
}


static int handle_arg_c_offs(LA_DECODE* la_decode, arg_c_offs* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FCC; la_decode->op[0].val = a->cj;
    la_decode->op[1].type = LA_OP_IMM; la_decode->op[1].val = a->offs;
    return true;
}
static int handle_arg_cf(LA_DECODE* la_decode, arg_cf* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FCC; la_decode->op[0].val = a->cd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    return true;
}
static int handle_arg_cff_fcond(LA_DECODE* la_decode, arg_cff_fcond* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_FCC; la_decode->op[0].val = a->cd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    la_decode->op[2].type = LA_OP_FR; la_decode->op[2].val = a->fk;
    la_decode->op[3].type = LA_OP_IMM; la_decode->op[3].val = a->fcond;
    return true;
}
static int handle_arg_cop_r_i(LA_DECODE* la_decode, arg_cop_r_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->cop;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_cr(LA_DECODE* la_decode, arg_cr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FCC; la_decode->op[0].val = a->cd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    return true;
}
static int handle_arg_cv(LA_DECODE* la_decode, arg_cv* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FCC; la_decode->op[0].val = a->cd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    return true;
}
static int handle_arg_empty(LA_DECODE* la_decode, arg_empty* a, int id) {
    la_decode->id = id; la_decode->opcnt = 0;
    return true;
}
static int handle_arg_fc(LA_DECODE* la_decode, arg_fc* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_FCC; la_decode->op[1].val = a->cj;
    return true;
}
static int handle_arg_fcsrd_r(LA_DECODE* la_decode, arg_fcsrd_r* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FCSR; la_decode->op[0].val = a->fcsrd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    return true;
}
static int handle_arg_ff(LA_DECODE* la_decode, arg_ff* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    return true;
}
static int handle_arg_fff(LA_DECODE* la_decode, arg_fff* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    la_decode->op[2].type = LA_OP_FR; la_decode->op[2].val = a->fk;
    return true;
}
static int handle_arg_fffc(LA_DECODE* la_decode, arg_fffc* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    la_decode->op[2].type = LA_OP_FR; la_decode->op[2].val = a->fk;
    la_decode->op[2].type = LA_OP_FCC; la_decode->op[2].val = a->ca;
    return true;
}
static int handle_arg_ffff(LA_DECODE* la_decode, arg_ffff* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    la_decode->op[2].type = LA_OP_FR; la_decode->op[2].val = a->fk;
    la_decode->op[3].type = LA_OP_FR; la_decode->op[3].val = a->fa;
    return true;
}
static int handle_arg_fr(LA_DECODE* la_decode, arg_fr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    return true;
}
static int handle_arg_fr_i(LA_DECODE* la_decode, arg_fr_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_frr(LA_DECODE* la_decode, arg_frr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_FR; la_decode->op[0].val = a->fd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_hint_r_i(LA_DECODE* la_decode, arg_hint_r_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->hint;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_hint_rr(LA_DECODE* la_decode, arg_hint_rr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->hint;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_i(LA_DECODE* la_decode, arg_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 1;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->imm;
    return true;
}
static int handle_arg_i_rr(LA_DECODE* la_decode, arg_i_rr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->imm;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_j_i(LA_DECODE* la_decode, arg_j_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rj;
    la_decode->op[1].type = LA_OP_IMM; la_decode->op[1].val = a->imm;
    return true;
}
static int handle_arg_offs(LA_DECODE* la_decode, arg_offs* a, int id) {
    la_decode->id = id; la_decode->opcnt = 1;
    la_decode->op[0].type = LA_OP_IMM; la_decode->op[0].val = a->offs;
    return true;
}
static int handle_arg_r_csr(LA_DECODE* la_decode, arg_r_csr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_CSR; la_decode->op[1].val = a->csr;
    return true;
}
static int handle_arg_r_fcsrs(LA_DECODE* la_decode, arg_r_fcsrs* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_FCSR; la_decode->op[1].val = a->fcsrs;
    return true;
}
static int handle_arg_r_i(LA_DECODE* la_decode, arg_r_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_IMM; la_decode->op[1].val = a->imm;
    return true;
}
static int handle_arg_r_offs(LA_DECODE* la_decode, arg_r_offs* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rj;
    la_decode->op[1].type = LA_OP_IMM; la_decode->op[1].val = a->offs;
    return true;
}
static int handle_arg_rc(LA_DECODE* la_decode, arg_rc* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_FCC; la_decode->op[1].val = a->cj;
    return true;
}
static int handle_arg_rf(LA_DECODE* la_decode, arg_rf* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_FR; la_decode->op[1].val = a->fj;
    return true;
}
static int handle_arg_rr(LA_DECODE* la_decode, arg_rr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    return true;
}
static int handle_arg_rr_csr(LA_DECODE* la_decode, arg_rr_csr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_CSR; la_decode->op[2].val = a->csr;
    return true;
}
static int handle_arg_rr_i(LA_DECODE* la_decode, arg_rr_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_rr_jk(LA_DECODE* la_decode, arg_rr_jk* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rj;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rk;
    return true;
}
static int handle_arg_rr_ms_ls(LA_DECODE* la_decode, arg_rr_ms_ls* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->ms;
    la_decode->op[3].type = LA_OP_IMM; la_decode->op[3].val = a->ls;
    return true;
}
static int handle_arg_rr_offs(LA_DECODE* la_decode, arg_rr_offs* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->offs;
    return true;
}
static int handle_arg_rrr(LA_DECODE* la_decode, arg_rrr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_rrr_sa(LA_DECODE* la_decode, arg_rrr_sa* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    la_decode->op[3].type = LA_OP_IMM; la_decode->op[3].val = a->sa;
    return true;
}
static int handle_arg_rv_i(LA_DECODE* la_decode, arg_rv_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_GPR; la_decode->op[0].val = a->rd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_v_i(LA_DECODE* la_decode, arg_v_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_IMM; la_decode->op[1].val = a->imm;
    return true;
}
static int handle_arg_vr(LA_DECODE* la_decode, arg_vr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    return true;
}
static int handle_arg_vr_i(LA_DECODE* la_decode, arg_vr_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_vr_ii(LA_DECODE* la_decode, arg_vr_ii* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    la_decode->op[3].type = LA_OP_IMM; la_decode->op[3].val = a->imm2;
    return true;
}
static int handle_arg_vrr(LA_DECODE* la_decode, arg_vrr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_GPR; la_decode->op[1].val = a->rj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_vv(LA_DECODE* la_decode, arg_vv* a, int id) {
    la_decode->id = id; la_decode->opcnt = 2;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    return true;
}
static int handle_arg_vv_i(LA_DECODE* la_decode, arg_vv_i* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_IMM; la_decode->op[2].val = a->imm;
    return true;
}
static int handle_arg_vvr(LA_DECODE* la_decode, arg_vvr* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_GPR; la_decode->op[2].val = a->rk;
    return true;
}
static int handle_arg_vvv(LA_DECODE* la_decode, arg_vvv* a, int id) {
    la_decode->id = id; la_decode->opcnt = 3;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_VR; la_decode->op[2].val = a->vk;
    return true;
}
static int handle_arg_vvv_fcond(LA_DECODE* la_decode, arg_vvv_fcond* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_VR; la_decode->op[2].val = a->vk;
    la_decode->op[3].type = LA_OP_IMM; la_decode->op[3].val = a->fcond;
    return true;
}
static int handle_arg_vvvv(LA_DECODE* la_decode, arg_vvvv* a, int id) {
    la_decode->id = id; la_decode->opcnt = 4;
    la_decode->op[0].type = LA_OP_VR; la_decode->op[0].val = a->vd;
    la_decode->op[1].type = LA_OP_VR; la_decode->op[1].val = a->vj;
    la_decode->op[2].type = LA_OP_VR; la_decode->op[2].val = a->vk;
    la_decode->op[3].type = LA_OP_VR; la_decode->op[3].val = a->va;
    return true;
}

static bool la_inst_is_ist(int id) {
    switch (id) {
        case LA_INST_ST_B:
        case LA_INST_ST_H:
        case LA_INST_ST_W:
        case LA_INST_ST_D:
        case LA_INST_STX_B:
        case LA_INST_STX_H:
        case LA_INST_STX_W:
        case LA_INST_STX_D:
        case LA_INST_STPTR_W:
        case LA_INST_STPTR_D:
        case LA_INST_STGT_B:
        case LA_INST_STGT_H:
        case LA_INST_STGT_W:
        case LA_INST_STGT_D:
        case LA_INST_STLE_B:
        case LA_INST_STLE_H:
        case LA_INST_STLE_W:
        case LA_INST_STLE_D:
            return true;
        default:
            return false;
    }
    return false;
}

static bool la_inst_is_fst(int id) {
    switch (id) {
        case LA_INST_FST_S:
        case LA_INST_FST_D:
        case LA_INST_FSTX_S:
        case LA_INST_FSTX_D:
        case LA_INST_FSTGT_S:
        case LA_INST_FSTGT_D:
        case LA_INST_FSTLE_S:
        case LA_INST_FSTLE_D:
        case LA_INST_VST:
        case LA_INST_VSTX:
        case LA_INST_VSTELM_D:
        case LA_INST_VSTELM_W:
        case LA_INST_VSTELM_H:
        case LA_INST_VSTELM_B:
        case LA_INST_XVST:
        case LA_INST_XVSTX:
        case LA_INST_XVSTELM_D:
        case LA_INST_XVSTELM_W:
        case LA_INST_XVSTELM_H:
        case LA_INST_XVSTELM_B:
            return true;
        default:
            return false;
    }
    return false;
}

static bool la_inst_is_st(int id) {
    return la_inst_is_ist(id) || la_inst_is_fst(id);
}

static bool la_inst_is_ild(int id) {
    switch (id) {
        case LA_INST_LD_B:
        case LA_INST_LD_H:
        case LA_INST_LD_W:
        case LA_INST_LD_D:
        case LA_INST_LD_BU:
        case LA_INST_LD_HU:
        case LA_INST_LD_WU:
        case LA_INST_LDX_B:
        case LA_INST_LDX_H:
        case LA_INST_LDX_W:
        case LA_INST_LDX_D:
        case LA_INST_LDX_BU:
        case LA_INST_LDX_HU:
        case LA_INST_LDX_WU:
        case LA_INST_LDPTR_W:
        case LA_INST_LDPTR_D:
        case LA_INST_LDGT_B:
        case LA_INST_LDGT_H:
        case LA_INST_LDGT_W:
        case LA_INST_LDGT_D:
        case LA_INST_LDLE_B:
        case LA_INST_LDLE_H:
        case LA_INST_LDLE_W:
        case LA_INST_LDLE_D:
            return true;
        default:
            return false;
    }
    return false;
}

static bool la_inst_is_fld(int id) {
    switch (id) {
        case LA_INST_FLD_S:
        case LA_INST_FLD_D:
        case LA_INST_FLDX_S:
        case LA_INST_FLDX_D:
        case LA_INST_FLDGT_S:
        case LA_INST_FLDGT_D:
        case LA_INST_FLDLE_S:
        case LA_INST_FLDLE_D:
        case LA_INST_VLD:
        case LA_INST_VLDX:
        case LA_INST_VLDREPL_D:
        case LA_INST_VLDREPL_W:
        case LA_INST_VLDREPL_H:
        case LA_INST_VLDREPL_B:
        case LA_INST_XVLD:
        case LA_INST_XVLDX:
        case LA_INST_XVLDREPL_D:
        case LA_INST_XVLDREPL_W:
        case LA_INST_XVLDREPL_H:
        case LA_INST_XVLDREPL_B:
            return true;
        default:
            return false;
    }
    return false;
}





static bool la_inst_is_ld(int id) {
    return la_inst_is_ild(id) || la_inst_is_fld(id);
}

static bool la_inst_is_branch(int id) {
    switch (id) {
        case LA_INST_BCEQZ:
        case LA_INST_BCNEZ:
        case LA_INST_B:
        case LA_INST_BEQZ:
        case LA_INST_BNEZ:
        case LA_INST_BEQ:
        case LA_INST_BNE:
        case LA_INST_BLT:
        case LA_INST_BGE:
        case LA_INST_BLTU:
        case LA_INST_BGEU:
        case LA_INST_BL:
        case LA_INST_JIRL:
            return true;
        default:
            return false;
    }
    return false;
}

static bool la_inst_is_branch_not_link(int id) {
    switch (id) {
        case LA_INST_BCEQZ:
        case LA_INST_BCNEZ:
        case LA_INST_B:
        case LA_INST_BEQZ:
        case LA_INST_BNEZ:
        case LA_INST_BEQ:
        case LA_INST_BNE:
        case LA_INST_BLT:
        case LA_INST_BGE:
        case LA_INST_BLTU:
        case LA_INST_BGEU:
            return true;
        default:
            return false;
    }
    return false;
}

static bool la_inst_str(LA_DECODE *la_decode, char* dst) {
    sprintf(dst, "%-12s", la_op_name[la_decode->id]);
    char buf[1024];
    for (int i = 0; i < la_decode->opcnt; i ++) {
        const char* prefix = i ? ", " : "  ";
        if (la_decode->op[i].type == LA_OP_IMM) {
            if (la_decode->id == LA_INST_ANDI || la_decode->id == LA_INST_ORI || la_decode->id == LA_INST_XORI) {
                sprintf(buf, "%s0x%x", prefix, la_decode->op[i].val);
            } else {
                sprintf(buf, "%s%d", prefix, la_decode->op[i].val);
            }
        } else {
            sprintf(buf, "%s%s%d", prefix, la_op_type_name[la_decode->op[i].type], la_decode->op[i].val);
        }
        strcat(dst, buf);
    }
    return false;
}

'''

f = open("/home/lxy/qemu/build/libqemu-loongarch64-linux-user.fa.p/decode-insns.c.inc", "r")
lines = list(f.readlines())

m = {}

for line in lines:
    if line.startswith("typedef arg_"):
        linesp = line[:-2].split()
        m[linesp[2]] = linesp[1]

# print(m)

inst  = set()


body = []

for line in lines:
    r = re.search("if \(trans_(.*)\(ctx, (.*)\)\)", line)
    if r:
        # print(r.span()[0])
        # print(r.group(0), r.group(1), r.group(2), sep="===")
        # print(r.group(2)[5:])
        s = "if (handle_arg_" + r.group(2)[5:] + "(ctx, " + r.group(2) + ", LA_INST_" + r.group(1).upper() + "))"
        # print(s)
        line = line[0:r.span()[0]] + s + line[r.span()[1]:]
        inst.add("LA_INST_" + r.group(1).upper())
    body.append(line)


print("enum {")
print("LA_INST_BEGIN,")
for i in inst:
    print(i + ",")
print("LA_INST_END,")
print("};")

print("const char* la_op_name[] = {")
print('[LA_INST_BEGIN] = "begin",')
for i in inst:
    print('[%s] = "%s",' % (i, i[8:].lower()), end='')
print('\n[LA_INST_END] = "end",')
print("};")

decode_ = 0
for index,line in enumerate(body):
    if line.startswith("typedef arg_") or line.startswith("static bool trans_"):
        continue
    if line.startswith("static void decode_"):
        decode_ = index
        break
    print(line, end="")


print(header)


for i in body[decode_:]:
    print(i, end="")
