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

#include "util.h"


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// static qemu_plugin_id_t plugin_id;

/* Plugins need to take care of their own locking */
// static std::mutex lock;

// static const int trace_mode_simpt  = 0;
// static const int trace_mode_range  = 1;

// static std::string bench_name;
// // mode=<simpt|range>
// static int      trace_mode    = trace_mode_simpt;
// // size=... 
// static uint64_t interval_size = 100000000;
// static uint64_t preheat_size  = 0;

// // mode simpt
// static std::ifstream simpts_file;
// static std::vector<uint64_t> interval_set; // change into ordered vector
// // mode range
// static uint64_t inst_start = 0;
// static uint64_t inst_stop  = 0;
// static int      pool_capa  = 0;

// static int      pool_size_cur = 0;
// static int      pool_size_all = 0;
// // mode random

// // generic
// FILE*           trace_log   = nullptr;
// static uint64_t trace_start = 0;
// static uint64_t inst_count  = 0; /* executed instruction count */
// static uint64_t inst_end    = 0; /* inst num where status may be changed */

// static uint64_t interval_id = 0;

// static bool tracing_enabled = false;

// static const bool debug_print = true;

// gzFile   pc_trace;
// uint64_t pc_trace_buffer[1<<17];
// uint64_t pc_trace_head;

// typedef struct trace_node
// {
//     uint64_t pc_s;
//     uint64_t pc_e;
//     uint64_t info;
// } trace_node_t;

// static trace_node_t node_buffer;
// static bool node_buffer_valid = false;
// static std::vector<trace_node_t> trace_buffer;

// void la_cpu_pc_trace_write(uint64_t pc_s,uint64_t pc_e,uint64_t info){
//     assert(pc_trace != NULL);
//     pc_trace_buffer[pc_trace_head  ] = pc_s;
//     pc_trace_buffer[pc_trace_head+1] = pc_e;
//     pc_trace_buffer[pc_trace_head+2] = info;
//     pc_trace_head+=3;
//     if(pc_trace_head>=(1<<15)){
//         gzwrite(pc_trace,pc_trace_buffer,pc_trace_head<<3);
//         pc_trace_head = 0;
//     }
// }

// void la_cpu_pc_trace_close(){
//     if(node_buffer_valid){
//         la_cpu_pc_trace_write(node_buffer.pc_s,node_buffer.pc_e,node_buffer.info);
//         node_buffer_valid = false;
//     }
//     if(pc_trace == NULL)return;
//     if(pc_trace_head>0)gzwrite(pc_trace,pc_trace_buffer,pc_trace_head<<3);
//     gzclose(pc_trace);
//     pc_trace_head = 0;
//     pc_trace = NULL;
// }




// static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata) { 
//     if(tracing_enabled){
//         trace_node_t node = trace_buffer[(uint64_t)udata];
//         if(node_buffer_valid){
//             if(node_buffer.pc_e+0x4!=node.pc_s) node_buffer.info |= 0x1;
//             la_cpu_pc_trace_write(node_buffer.pc_s,node_buffer.pc_e,node_buffer.info);
//         }
//         node_buffer.pc_s = node.pc_s; node_buffer.pc_e = node.pc_e;node_buffer.info = node.info;   
//         node_buffer_valid = true;
//     }
// }

// static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

// static void callback_reset(qemu_plugin_id_t id)
// {
//     qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
// }

// static void pc_tracing_open(){
//     int loc = (inst_count - trace_start) / interval_size;
//     assert(loc <= 0);
//     std::string trace_name;

//     if(loc < 0){
//         trace_name = bench_name
//                    + "." 
//                    + std::to_string(interval_id) 
//                    + ".pc_trace.preheat."
//                    + std::to_string(-loc)
//                    + ".gz";
//         inst_end = trace_start + (loc + 1) * interval_size;
//     }
//     else{ // loc == 0
//         if(trace_mode == trace_mode_simpt){
//             trace_name = bench_name + "." + std::to_string(interval_id++) + ".pc_trace.gz";
//         }
//         else if(trace_mode == trace_mode_range){
//             if(pool_capa == 0 || pool_size_cur < pool_capa){
//                 trace_name = bench_name + "." + std::to_string(pool_size_cur++) + ".pc_trace.gz";
//             }
//             else{
//                 trace_name = bench_name + "." + std::to_string(rand() % pool_capa) + ".pc_trace.gz";
//             }
//         }
//         inst_end = trace_start + interval_size;
//     }

//     if(trace_log != nullptr){
//         fprintf(trace_log, "%lu ", inst_count);
//     }
//     tracing_enabled = true;
//     pc_trace = gzopen(trace_name.c_str(),"wb");
//     if(debug_print){
//         fprintf(stderr,"Opened trace \"%s\" @ inst %lu\n",trace_name.c_str(),inst_count);
//     }
// }

// static void pc_tracing_exit(){
//     if(debug_print){
//         fprintf(stderr,"Reached end @ inst %lu, exit.\n", inst_count);
//     }
//     exit(0);
// }

// static void pc_tracing_close(){
//     la_cpu_pc_trace_close();
//     tracing_enabled = false;
//     qemu_plugin_reset(plugin_id, callback_reset);
//     trace_buffer.clear();
//     if(trace_log != nullptr){
//         fprintf(trace_log, "%lu\n", inst_count);
//     }
//     if(debug_print){
//         fprintf(stderr,"Closed trace @ inst: %lu\n",inst_count);
//     }
//     if(trace_mode == trace_mode_simpt){
//         if(interval_id==interval_set.size()){
//             pc_tracing_exit(); // does not return
//         }
//         trace_start = interval_set[interval_id] * interval_size;
//     }
//     else if(trace_mode == trace_mode_range){
//         if(inst_stop > inst_start && inst_count >= inst_stop){
//             pc_tracing_exit(); // does not return
//         }
//         pool_size_all ++;
//         if(pool_capa != 0 && pool_size_cur >= pool_capa){
//             while((rand() % pool_size_all) != 0){
//                 pool_size_all ++;
//             }
//         }
//         trace_start = inst_start + pool_size_all * interval_size;
//     }
//     inst_end = trace_start - preheat_size * interval_size;
// }

// static void tb_exec(unsigned int cpu_index, void *udata)
// {
//     lock.lock();

//     if(inst_count >= inst_end){
//         if(tracing_enabled){
//             pc_tracing_close();
//             if(inst_count >= inst_end){
//                 pc_tracing_open();
//             }
//         }else{
//             pc_tracing_open();
//         }
//     }

//     lock.unlock();
// }

// static uint64_t encode_info(uint32_t opcode)
// {
//     //decoding opcode according to the LISA
//     // jirl  |  op[31:26] == 01_0011
//     // b     |  op[31:26] == 01_0100
//     // bl    |  op[31:26] == 01_0101
    
//     // beqz  |  op[31:26] == 01_0000
//     // bnez  |  op[31:26] == 01_0001
//     // bceqz |  op[31:26] == 01_0010 && op[9:8] == 00
//     // bcnez |  op[31:26] == 01_0010 && op[9:8] == 01
    
//     // beq   |  op[31:26] == 01_0110
//     // bne   |  op[31:26] == 01_0111
//     // blt   |  op[31:26] == 01_1000
//     // bge   |  op[31:26] == 01_1001
//     // bltu  |  op[31:26] == 01_1010
//     // bgeu  |  op[31:26] == 01_1011
    
//     char op_31_26 = (opcode>>26) & 0x3f;
//     char op_31_30 = (opcode>>30) & 0x3 ;

//     bool is_syscal = (opcode>>15)==0x56;
//     bool is_break  = (opcode>>15)==0x54;
//     bool is_branch = op_31_30 == 0x1;
//     bool is_jirl   = op_31_26 == 0x13;
//     bool is_bl     = op_31_26 == 0x15;     
//     bool is_b16    = 0x16<=op_31_26 && op_31_26<=0x1b;
//     bool is_b21    = 0x10<=op_31_26 && op_31_26<=0x12;
//     bool is_b26    = 0x14<=op_31_26 && op_31_26<=0x15;

//     uint64_t info_bit7 = is_branch;
//     uint64_t info_bit5 = (is_b21 && (opcode&0x10 )    )
//                       || (is_b26 && (opcode&0x200)    )
//                       || (is_b16 && (opcode&0x2000000));
//     uint64_t info_bit4 = is_jirl && opcode != 0x4c000020;
//     uint64_t info_bit3 = opcode == 0x4c000020;
//     uint64_t info_bit2 = is_b16 || is_b21;
//     uint64_t info_bit1 = is_bl || (is_jirl && ((opcode&0x1f) == 0x1));
//     uint64_t info_bit0 = info_bit2 ? 0x0 : 0x1;
//     //bit0to be decided
//     uint64_t info = ((uint64_t)opcode) << 32;
//     if(is_branch) info |= info_bit7<<7 | info_bit5<<5 | info_bit4<<4 | info_bit3<<3 | info_bit2<<2 | info_bit1<<1 | info_bit0;
//     else if(is_syscal) info |= 0xb;
//     else if(is_break) info |= 0xc;
//     else info |= 0xc0;
//     return info;
// }

static std::map<uint32_t, void*> insn_cnt;

void plugin_exit(qemu_plugin_id_t id, void *p)
{
    char buf[1024];
    for(auto [k,v] : insn_cnt) {
        sprintf(buf, "%08x,%ld\n", k, *(uint64_t*)v);
        qemu_plugin_outs(buf);
    }
}
static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i ++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        int size = qemu_plugin_insn_size(insn);
        const void* data = qemu_plugin_insn_data(insn);
        uint32_t insn_data;
        if (size == 2) {
            insn_data = (uint32_t)*(uint16_t*)data;
        } else {
            insn_data = *(uint32_t*)data;
        }
        if (!insn_cnt.count(insn_data)) {
            uint64_t* p = (uint64_t*)malloc(sizeof(uint64_t));
            *p = 0;
            insn_cnt[insn_data] = p;
        }
        qemu_plugin_register_vcpu_insn_exec_inline(insn,QEMU_PLUGIN_INLINE_ADD_U64, insn_cnt[insn_data], 1);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    bool a = plugin_args_get_bool_or_else(argc, argv, "op1", false);
    uint64_t b = plugin_args_get_u64_or_else(argc, argv, "op2", 100);
    char *p = plugin_args_get(argc, argv, "123");
    printf("0   %x\n", a);
    printf("1   %lx\n", b);
    printf("2   %s\n", p);
exit(0);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
