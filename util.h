#pragma once
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include <string.h>

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
char* plugin_args_find_arg(char *arg, const char* key){
    char *p = strchr(arg, '=');
    if (p && strncmp(arg, key, p - arg) == 0) {
        return p + 1;
    }
    return NULL;
}

char* plugin_args_get(int argc, char **argv, const char* key){
    for (int i = 0; i < argc; i++)
    {
        char *p = plugin_args_find_arg(argv[i], key);
        if (p) {
            return p;
        }
    }
    return NULL;
}

static unsigned long strtoul_suffix(const char *__restrict __nptr,
			char **__restrict __endptr, int __base)
{
    char *p;
    int shift = 0;
    unsigned long val;

    val = strtol(__nptr, &p, __base);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'm':
    case 'M':
        shift = 20;
        break;
    case 'g':
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = val;
        p++;
        val <<= shift;
        if (val >> shift != unshifted) {
            fprintf(stderr, "%s too big\n", __nptr);
            exit(EXIT_FAILURE);
        }
    }
    if (*p && *p != ':') {
        fprintf(stderr, "Unrecognised size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
    if (__endptr) *__endptr = p;
    return val;
}

long atol_suffix(const char *nptr) {
    return strtoul_suffix(nptr, NULL, 0);
}

uint64_t plugin_args_get_u64_or_else(int argc, char **argv, const char* key, uint64_t default_value){
    char* p = plugin_args_get(argc, argv, key);
    if (p) {
        return strtoul_suffix(p, NULL, 0);
    }
    return default_value;
}

//    on|yes|true|off|no|false
bool plugin_args_get_bool_or_else(int argc, char **argv, const char* key, uint64_t default_value){
    char* p = plugin_args_get(argc, argv, key);
    if (p) {
        if (
            strcmp(p, "1") == 0 ||
            strcmp(p, "on") == 0 ||
            strcmp(p, "yes") == 0 ||
            strcmp(p, "true") == 0
        ) {
            return true;
        } else if (
            strcmp(p, "0") == 0 ||
            strcmp(p, "off") == 0 ||
            strcmp(p, "no") == 0 ||
            strcmp(p, "false") == 0
        ) {
            return false;
        } else {
            fprintf(stderr, "cannot prase %s as bool\n", p);
        }
    }
    return default_value;
}