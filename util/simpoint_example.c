#include <stdio.h>
long self_ptr = (long)&self_ptr;
__attribute__ ((noinline, aligned(4096))) unsigned add_chain(unsigned a) {
    register long i = 1000000000;
    register unsigned r = a;
    do {
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
        r <<= r;
    } while (--i);
    return r;
}

__attribute__ ((noinline, aligned(4096))) long ptr_chain(long ptr) {
    register long i = 1000000000;
    volatile register long* p = (long*)ptr;
    do {
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
        p = (long*)*p;
    } while (--i);
    return (long)p;
}


int main(int argc, char **argv) {
    printf("begin add chain\n");
    printf("end add chain trash:%x\n", add_chain(1));
    printf("begin ptr chasing\n");
    printf("end ptr chasing :%lx\n", ptr_chain(self_ptr));
    return 0;
}