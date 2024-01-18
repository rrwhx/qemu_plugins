#pragma once
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>

char* find_arg(char *arg, const char* key){
    for(int i=0;arg[i] != 0;i += 1){
        if(key[i] == 0){
            return arg[i] == '=' ? arg + i + 1 : nullptr;
        }
        if(arg[i] != key[i]) return nullptr;
    }
    return nullptr;
}

char* find_arg(int argc, char **argv, const char* key){
    for(int i=0;i < argc;i += 1){
        char* res = find_arg(argv[i],key);
        if(res != nullptr){
            return res;
        }
    }
    return nullptr;
}

const char* find_arg_or_else(int argc, char **argv, const char* key, const char* value){
    for(int i=0;i < argc;i += 1){
        char* res = find_arg(argv[i],key);
        if(res != nullptr){
            return res;
        }
    }
    return value;
}

uint64_t get_u64_or_else(int argc, char **argv, const char* key, uint64_t default_value){
    for(int i=0;i < argc;i += 1){
        char* res = find_arg(argv[i],key);
        if(res != nullptr){
            uint64_t value = default_value;
            sscanf(res,"%lu",&value);
            return value;
        }
    }
    return default_value;
}


static inline FILE* fopen_nofail(const char *__restrict __filename, const char *__restrict __modes) {
    FILE* f = fopen(__filename, __modes);
    if (!f) {
        perror(__filename);
        abort();
    }
    return f;
}
