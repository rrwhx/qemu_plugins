#include "../loongarch_decode_insns.c.inc"


int main() {
    uint32_t a = 0x02bffc0d;

    LA_DECODE la_decode;
    decode(&la_decode, a);
    char r[1024];
    la_inst_str(&la_decode, r);
    puts(r);

    return 0;
}