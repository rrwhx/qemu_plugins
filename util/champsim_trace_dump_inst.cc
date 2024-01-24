#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <map>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

using namespace std;

#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4
typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value

    unsigned char is_branch;    // is this branch
    unsigned char branch_taken; // if so, is this taken

    unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
} trace_instr_format_t;

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

const char* branch_type(int is_branch) {
    switch (is_branch) {
        case NOT_BRANCH:            return "";
        case BRANCH_DIRECT_JUMP:    return "direct_jump";
        case BRANCH_INDIRECT:       return "indirect_jump";
        case BRANCH_CONDITIONAL:    return "conditional";
        case BRANCH_DIRECT_CALL:    return "direct_call";
        case BRANCH_INDIRECT_CALL:  return "indirect_call";
        case BRANCH_RETURN:         return "return";
        case BRANCH_OTHER:          return "other";
    }
    return "NULL";
};

// void dump_trace(trace_instr_format_t& t) {
//     const char* taken = "";
//     if (t.is_branch) {
//         if (t.branch_taken) {
//             taken = "taken";
//         } else {
//             taken = "not taken";
//         }
//     }
//     fprintf(stderr, "ip:%-11llx %s %s\n", t.ip, taken, branch_type(t.is_branch));
//     fprintf(stderr, "write register:");
//     for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
//         if (t.destination_registers[i]) {
//             fprintf(stderr, "%d ", t.destination_registers[i]);
//         }
//     }
//     fprintf(stderr, "\n");

//     fprintf(stderr, "read  register:");
//     for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
//         if (t.source_registers[i]) {
//             fprintf(stderr, "%d ", t.source_registers[i]);
//         }
//     }
//     fprintf(stderr, "\n");

//     fprintf(stderr, "write memory  :");
//     for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
//         if (t.destination_memory[i]) {
//             fprintf(stderr, "%llx ", t.destination_memory[i]);
//         }
//     }
//     fprintf(stderr, "\n");

//     fprintf(stderr, "read  memory  :");
//     for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
//         if (t.source_memory[i]) {
//             fprintf(stderr, "%llx ", t.source_memory[i]);
//         }
//     }
//     fprintf(stderr, "\n");
//     fprintf(stderr, "\n");


// }

// void dump_trace(trace_instr_format_t& t) {
//     const char* taken = "";
//     if (t.is_branch) {
//         if (t.branch_taken) {
//             taken = "taken";
//         } else {
//             taken = "not taken";
//         }
//     }
//     fprintf(stderr, "ip:%-1llx %-10s %-15s", t.ip, taken, branch_type(t.is_branch));
//     fprintf(stderr, "write register:");
//     for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
//         if (t.destination_registers[i]) {
//             fprintf(stderr, "%4d ", t.destination_registers[i]);
//         } else {
//             fprintf(stderr, "     ");
//         }
//     }

//     fprintf(stderr, "read register:");
//     for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
//         if (t.source_registers[i]) {
//             fprintf(stderr, "%4d ", t.source_registers[i]);
//         } else {
//             fprintf(stderr, "     ");
//         }
//     }

//     fprintf(stderr, "write memory:");
//     for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
//         if (t.destination_memory[i]) {
//             fprintf(stderr, "%llx ", t.destination_memory[i]);
//         } else {
//             fprintf(stderr, " ");
//         }
//     }

//     fprintf(stderr, "read  memory:");
//     for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
//         if (t.source_memory[i]) {
//             fprintf(stderr, "%llx ", t.source_memory[i]);
//         } else {
//             fprintf(stderr, " ");
//         }
//     }
//     fprintf(stderr, "\n");


// }

void dump_trace(trace_instr_format_t& t) {
    const char* taken = "";
    if (t.is_branch) {
        if (t.branch_taken) {
            taken = "taken";
        } else {
            taken = "not taken";
        }
    }
    fprintf(stderr, "ip:%-1llx %-10s %-15s", t.ip, taken, branch_type(t.is_branch));
    string reg_str("register: ");
    for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
        if (t.destination_registers[i]) {
            reg_str += to_string(t.destination_registers[i]);
            reg_str += " ";
        }
    }

    reg_str += " <= ";
    for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
        if (t.source_registers[i]) {
            reg_str += to_string(t.source_registers[i]);
            reg_str += " ";
        }
    }

    fprintf(stderr, "%-28s ", reg_str.c_str());

    fprintf(stderr, "write memory:");
    for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
        if (t.destination_memory[i]) {
            fprintf(stderr, "%llx ", t.destination_memory[i]);
        } else {
            fprintf(stderr, " ");
        }
    }

    fprintf(stderr, "read  memory:");
    for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
        if (t.source_memory[i]) {
            fprintf(stderr, "%llx ", t.source_memory[i]);
        } else {
            fprintf(stderr, " ");
        }
    }
    fprintf(stderr, "\n");


}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: ./champsim_trace_dump trace_filename\n");
        exit(0);
    }
    char* trace_filename = argv[1];
    struct stat st;
    int trace_fd = open(trace_filename, O_RDWR, (mode_t)0600);
    if (trace_fd < 0) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    fstat(trace_fd, &st);
    int64_t filesize = st.st_size;
    int trace_item_size = sizeof(trace_instr_format_t);
    if (filesize % trace_item_size) {
        fprintf(stderr, "%s not a illegal champsim trace\n", trace_filename);
        exit(EXIT_FAILURE);
    }
    int64_t trace_count = filesize / trace_item_size;
    trace_instr_format_t* trace_buffer = (trace_instr_format_t*)mmap(0, filesize, PROT_READ, MAP_SHARED, trace_fd, 0);
    if (trace_buffer == MAP_FAILED) {
        fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        exit(EXIT_FAILURE);
    }
    close(trace_fd);

    for (int64_t i = 0; i < trace_count; i++) {
        dump_trace(trace_buffer[i]);
    }

    return 0;
}
