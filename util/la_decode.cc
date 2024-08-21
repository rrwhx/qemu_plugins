#include "../loongarch_decode_insns.c.inc"

#include <stdlib.h>

int main(int argc, char** argv) {
    uint32_t a = 0x02bffc0d;

    if (argc > 1) {
        a = strtol(argv[1], NULL, 0);
    }

    LA_DECODE la_decode;
    decode(&la_decode, a);
    char r[1024];
    la_inst_str(&la_decode, r);
    puts(r);

    return 0;
}