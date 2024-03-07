#include "../loongarch_decode_insns.c.inc"

#include <limits.h>

#include <bits/stdc++.h>

#include <elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>



using namespace std;

#define ELF_CLASS ELFCLASS64

#ifdef ELF_CLASS
#if ELF_CLASS == ELFCLASS32

#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_note	elf32_note
#define elf_shdr	elf32_shdr
#define elf_sym		elf32_sym
#define elf_addr_t	Elf32_Off
#define elf_rela  elf32_rela

#ifdef ELF_USES_RELOCA
# define ELF_RELOC      Elf32_Rela
#else
# define ELF_RELOC      Elf32_Rel
#endif

#else

#define elfhdr		Elf64_Ehdr
#define elf_phdr	Elf64_Phdr
#define elf_note	Elf64_Nhdr
#define elf_shdr	Elf64_Shdr
#define elf_sym		Elf64_Sym
#define elf_addr_t	Elf64_Off
#define elf_rela  Elf64_Rela

#ifdef ELF_USES_RELOCA
# define ELF_RELOC      Elf64_Rela
#else
# define ELF_RELOC      Elf64_Rel
#endif

#endif /* ELF_CLASS */

#ifndef ElfW
# if ELF_CLASS == ELFCLASS32
#  define ElfW(x)  Elf32_ ## x
#  define ELFW(x)  ELF32_ ## x
# else
#  define ElfW(x)  Elf64_ ## x
#  define ELFW(x)  ELF64_ ## x
# endif
#endif

#endif /* ELF_CLASS */

#define lsassert(cond)                                                  \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr,                                             \
                    "\033[31m assertion failed in <%s> %s:%d \033[m\n", \
                    __FUNCTION__, __FILE__, __LINE__);                  \
            abort();                                                    \
        }                                                               \
    } while (0)

#define lsassertm(cond, ...)                                                  \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "\033[31m assertion failed in <%s> %s:%d \033[m", \
                    __FUNCTION__, __FILE__, __LINE__);                        \
            fprintf(stderr, __VA_ARGS__);                                     \
            abort();                                                          \
        }                                                                     \
    } while (0)

void *mm_malloc(int size)
{
    lsassertm(size, "LATX-ERR %s size = 0!\n", __func__);
    void *retval = malloc(size);
    lsassertm(retval != NULL, "dbt: cannot allocate memory (%d bytes)\n", size);
    return retval;
}

void *mm_calloc(int num, int size)
{
    lsassertm(size, "LATX-ERR %s size = 0!\n", __func__);
    void *retval = calloc(num, size);
    lsassertm((retval != NULL) && size ,
        "%d dbt: cannot allocate memory (%d bytes)\n", getpid(), size);
    return retval;
}

void *mm_realloc(void *ptr, int size)
{
    lsassertm(size, "LATX-ERR %s size = 0!\n", __func__);
    void *retval = realloc(ptr, size);
    lsassertm(retval != NULL, "dbt: cannot allocate memory (%d bytes)\n", size);
    return retval;
}

void mm_free(void *ptr) { free(ptr); }

char* elf;
uint64_t elf_size;
uint64_t last_ir1_entry;
uint64_t last_jmp_entry;
elf_shdr* exec_sections;
uint64_t exec_sections_num;


LA_DECODE* last_ir1_list;
int last_ir1_num;


static char* readfile(const char* filename, uint64_t* length) {
    // int r;
    char * buffer;
    FILE * f = fopen (filename, "rb");
    lsassertm(f, "can not open %s, error:%s", filename, strerror(errno));
    fseek (f, 0, SEEK_END);
    *length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = (char*)aligned_alloc(64, *length);
    lsassert(buffer != NULL);
    size_t r = fread(buffer, *length, 1, f);
    lsassert(r == 1);
    fclose (f);
    return buffer;
}

static char* writefile(const char* filename, const char* content, long length) {
    int fd = open(filename, O_RDWR | O_CREAT, 0777);
    lsassert(fd >= 0);
    ssize_t r = write(fd, content, length);
    lsassertm(r == length, "%ld %ld\n", r, length);
    return NULL;
}

static int exec_sections_disassemble(void) {
    uint64_t pc;
    uint64_t offset;
    uint64_t section_addr;

    uint64_t exec_code_size = 0;
    for (size_t i = 0; i < exec_sections_num; i++) {
        exec_code_size += exec_sections[i].sh_size;
    }

    for (size_t i = 1; i < exec_sections_num; i++) {
        if (exec_sections[i].sh_addr < (exec_sections[i - 1].sh_addr + exec_sections[i - 1].sh_size)) {
            fprintf(stderr, "sections were not sorted %zu\n", i);
            exit(EXIT_FAILURE);
        }
    }

    last_ir1_list = (LA_DECODE*)calloc(exec_code_size, sizeof(LA_DECODE));

    for (size_t i = 0; i < exec_sections_num; i++) {
        section_addr = exec_sections[i].sh_addr;
        offset = exec_sections[i].sh_offset;
        pc = section_addr;
        printf("disassemble sections %lx-%lx\n", exec_sections[i].sh_offset, exec_sections[i].sh_offset + exec_sections[i].sh_size);
        while (offset < (exec_sections[i].sh_offset + exec_sections[i].sh_size)) {
            if (decode(last_ir1_list + last_ir1_num, *(uint32_t*)(elf + offset))) {
                char r[1024];
                la_inst_str(last_ir1_list + last_ir1_num, r);
                printf("%lx %08x ", pc, *(uint32_t*)(elf + offset));
                puts(r);
            } else {
                printf("%lx %08x unknown op\n", pc, *(uint32_t*)(elf + offset));
            }
            offset += 4;
            pc += 4;
            last_ir1_num ++;
        }
    }
    last_ir1_list = (LA_DECODE*)realloc(last_ir1_list, last_ir1_num * sizeof(LA_DECODE));
    return 1;
}

static char get_section_flag_name (unsigned int flag) {
    switch (flag)
    {
        case SHF_WRITE:             return 'W'; break;
        case SHF_ALLOC:             return 'A'; break;
        case SHF_EXECINSTR:         return 'X'; break;
        // case SHF_MERGE:             return 'M'; break;
        // case SHF_STRINGS:           return 'S'; break;
        // case SHF_INFO_LINK:         return 'I'; break;
        // case SHF_LINK_ORDER:        return 'L'; break;
        // case SHF_OS_NONCONFORMING:  return 'O'; break;
        // case SHF_GROUP:             return 'G'; break;
        // case SHF_TLS:               return 'T'; break;
        // case SHF_EXCLUDE:           return 'E'; break;
        // case SHF_COMPRESSED:        return 'C'; break;
        default:
            return 0;
    }
}

static uint64_t get_section_flags (unsigned int flag) {
    uint64_t r = 0;
    int index = 0;
    for (size_t i = 0; i < 16; i++) {
        int t = 1 << i;
        if (flag & t) {
            r |= get_section_flag_name(t) << index;
            index += 8;
            if (index > 50) {
                return r;
            }
        }
    }
    return r;
}

static const char * get_section_type_name (unsigned int sh_type) {
  switch (sh_type)
    {
        case SHT_NULL:            return "NULL";
        case SHT_PROGBITS:        return "PROGBITS";
        case SHT_SYMTAB:          return "SYMTAB";
        case SHT_STRTAB:          return "STRTAB";
        case SHT_RELA:            return "RELA";
        // case SHT_RELR:         return "RELR";
        case SHT_HASH:            return "HASH";
        case SHT_DYNAMIC:         return "DYNAMIC";
        case SHT_NOTE:            return "NOTE";
        case SHT_NOBITS:          return "NOBITS";
        case SHT_REL:             return "REL";
        case SHT_SHLIB:           return "SHLIB";
        case SHT_DYNSYM:          return "DYNSYM";
        case SHT_INIT_ARRAY:      return "INIT_ARRAY";
        case SHT_FINI_ARRAY:      return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY:   return "PREINIT_ARRAY";
        // case SHT_GNU_HASH:        return "GNU_HASH";
        case SHT_GROUP:           return "GROUP";
        case SHT_SYMTAB_SHNDX:    return "SYMTAB SECTION INDICES";
        // case SHT_GNU_verdef:      return "VERDEF";
        // case SHT_GNU_verneed:     return "VERNEED";
        // case SHT_GNU_versym:      return "VERSYM";
        case 0x6ffffff0:          return "VERSYM";
        case 0x6ffffffc:          return "VERDEF";
        case 0x7ffffffd:          return "AUXILIARY";
        case 0x7fffffff:          return "FILTER";
        // case SHT_GNU_LIBLIST:     return "GNU_LIBLIST";

        default:
            return "UNKNOWN";
    }
}

static const char* get_segment_type(long p_type) {
    switch (p_type)
    {
        case PT_NULL:	return "NULL";
        case PT_LOAD:	return "LOAD";
        case PT_DYNAMIC:	return "DYNAMIC";
        case PT_INTERP:	return "INTERP";
        case PT_NOTE:	return "NOTE";
        case PT_SHLIB:	return "SHLIB";
        case PT_PHDR:	return "PHDR";
        case PT_TLS:	return "TLS";
        // case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        // case PT_GNU_STACK:	return "GNU_STACK";
        // case PT_GNU_RELRO:  return "GNU_RELRO";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        // case PT_GNU_SFRAME: return "GNU_SFRAME";

        // case PT_OPENBSD_MUTABLE: return "OPENBSD_MUTABLE";
        // case PT_OPENBSD_RANDOMIZE: return "OPENBSD_RANDOMIZE";
        // case PT_OPENBSD_WXNEEDED: return "OPENBSD_WXNEEDED";
        // case PT_OPENBSD_BOOTDATA: return "OPENBSD_BOOTDATA";

        default:
            return "UNKNOWN";
    }
}

static void prase_elf(char* elf, long length) {
    int i, index;
    elfhdr* ehdr = (elfhdr*)elf;
    elf_shdr *shdr = NULL, *sh;

    // lsassert(e_ident[EI_CLASS] == ELFCLASS64);

    printf("Entry point %lx\n", ehdr->e_entry);
    last_ir1_entry = ehdr->e_entry;

    shdr = (elf_shdr*)(elf + ehdr->e_shoff);
    printf("There are %d section headers, starting at offset 0x%lx\n\n", ehdr->e_shnum, ehdr->e_shoff);

    printf("Section Headers:\n");
    printf("  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n");
    for(i = 0; i < ehdr->e_shnum; i++) {
        sh = &shdr[i];
        uint64_t f = get_section_flags(sh->sh_flags);
        printf("  [%2d] %-15s   %-15s %016lx %06lx %06lx 0x%lx %s %x %x %lx\n",
                i,
                "NAME",
                get_section_type_name(sh->sh_type),
                sh->sh_addr,
                sh->sh_offset,
                sh->sh_size,
                sh->sh_entsize,
                (char*)&f,
                sh->sh_link,
                sh->sh_info,
                sh->sh_addralign
            );
        if (sh->sh_flags & SHF_EXECINSTR) {
            ++ exec_sections_num;
        }
    }
    exec_sections = (elf_shdr*)malloc(sizeof(elf_shdr) * exec_sections_num);
    index = 0;
    for(i = 0; i < ehdr->e_shnum; i++) {
        sh = &shdr[i];
        if (sh->sh_flags & SHF_EXECINSTR) {
            exec_sections[index] = *sh;
            ++ index;
        }
    }

    printf("\n\n\n");

    elf_phdr *phdr = NULL, *ph;
    phdr = (elf_phdr*)(elf + ehdr->e_phoff);
    printf("There are %d program headers, starting at offset %ld\n\n", ehdr->e_phnum, ehdr->e_phoff);

    printf("Program Headers:\n");
    printf("Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n");
    for(int i = 0; i < ehdr->e_phnum; i++) {
        ph = &phdr[i];
        printf("%-15s0x%06lx 0x%016lx 0x%016lx 0x%06lx 0x%06lx %c%c%c 0x%lx\n",
                get_segment_type(ph->p_type),
                ph->p_offset,
                ph->p_vaddr,
                ph->p_paddr,
                ph->p_filesz,
                ph->p_memsz,
                ph->p_flags & PF_R ? 'R' : ' ',
                ph->p_flags & PF_W ? 'W' : ' ',
                ph->p_flags & PF_X ? 'E' : ' ',
                ph->p_align
            );
    }
}

static int exec_sections_disassemble_bin(uint64_t begin_pc) {
    LA_DECODE la_decode;
    char r[1024];
    for (uint64_t i = 0; i < elf_size; i+=4) {
        uint32_t code = *(uint32_t*)(elf + i);
        if (decode(&la_decode, code)) {
            la_inst_str(&la_decode, r);
            printf("%lx %08x ", begin_pc + i, code);
            puts(r);
        } else {
            printf("%lx %08x unknown op\n", begin_pc + i, code);
        }
    }
    return 0;
}

void last_init_exec_sections(const char* filename, bool is_binary, uint64_t begin_pc) {
    elf = readfile(filename, &elf_size);
    bool is_elf = elf[0] == ELFMAG0 &&
                  elf[1] == ELFMAG1 &&
                  elf[2] == ELFMAG2 &&
                  elf[3] == ELFMAG3;
    if (is_binary || !is_elf) {
        exec_sections_disassemble_bin(begin_pc);
    } else {
        printf("Elf File Size %ld\n", elf_size);
        prase_elf(elf, elf_size);
        exec_sections_disassemble();
    }
}

void usage(void) {
    printf("objdump -d filename [-b -a addr]\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    char* filename = argv[1];
    bool is_binary = false;
    uint64_t begin_pc = 0;
    int c;
    while ((c = getopt(argc, argv, "d:ba:")) != -1) {
        switch (c) {
            case 'a':
                begin_pc = strtol(optarg, NULL, 0);
                break;
            case 'b':
                is_binary = true;
                break;
            case 'd':
                filename = optarg;
                break;
            case '?':
                usage();
                return 1;
            default:
                abort();
        }
    }
    last_init_exec_sections(filename, is_binary, begin_pc);
    return 0;
}