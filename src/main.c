#define _POSIX_C_SOURCE 200809L
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_BREAKPOINTS 32
#define MAX_SYMBOL_NAME 128
#define PROGRAM_PATH "./hello"

typedef struct {
    int id;
    uintptr_t address;
    unsigned char saved_byte;
    int enabled;
    unsigned long hit_count;
    char symbol[MAX_SYMBOL_NAME];
} breakpoint_t;

typedef struct {
    breakpoint_t items[MAX_BREAKPOINTS];
    size_t count;
    int next_id;
} breakpoint_manager_t;

static int get_registers(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        perror("ptrace PTRACE_GETREGS");
        return -1;
    }
    return 0;
}

static int set_registers(pid_t pid, const struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        perror("ptrace PTRACE_SETREGS");
        return -1;
    }
    return 0;
}

static void print_registers(const struct user_regs_struct *regs)
{
    printf("\n===== CPU Registers =====\n");
    printf("RAX = 0x%016llx\n", regs->rax);
    printf("RBX = 0x%016llx\n", regs->rbx);
    printf("RCX = 0x%016llx\n", regs->rcx);
    printf("RDX = 0x%016llx\n", regs->rdx);
    printf("RSI = 0x%016llx\n", regs->rsi);
    printf("RDI = 0x%016llx\n", regs->rdi);
    printf("RBP = 0x%016llx\n", regs->rbp);
    printf("RSP = 0x%016llx\n", regs->rsp);
    printf("R8  = 0x%016llx\n", regs->r8);
    printf("R9  = 0x%016llx\n", regs->r9);
    printf("R10 = 0x%016llx\n", regs->r10);
    printf("R11 = 0x%016llx\n", regs->r11);
    printf("R12 = 0x%016llx\n", regs->r12);
    printf("R13 = 0x%016llx\n", regs->r13);
    printf("R14 = 0x%016llx\n", regs->r14);
    printf("R15 = 0x%016llx\n", regs->r15);
    printf("\nRIP = 0x%016llx\n", regs->rip);
    printf("RFLAGS = 0x%016llx\n", regs->eflags);
    printf("=========================\n\n");
}

static int read_memory_word(pid_t pid, uintptr_t address, unsigned long *word)
{
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);
    if (data == -1 && errno != 0) {
        perror("ptrace PTRACE_PEEKDATA");
        return -1;
    }
    *word = (unsigned long)data;
    return 0;
}

static int write_memory_word(pid_t pid, uintptr_t address, unsigned long word)
{
    if (ptrace(PTRACE_POKEDATA,
               pid,
               (void *)address,
               (void *)(uintptr_t)word) == -1) {
        perror("ptrace PTRACE_POKEDATA");
        return -1;
    }
    return 0;
}

static int print_memory_word(pid_t pid, uintptr_t address)
{
    unsigned long word;
    if (read_memory_word(pid, address, &word) == -1) {
        return -1;
    }

    printf("Memory @ 0x%lx: ", (unsigned long)address);
    for (size_t i = 0; i < sizeof(word); ++i) {
        unsigned int byte = (unsigned int)((word >> (i * 8)) & 0xffUL);
        printf("%02x ", byte);
    }
    printf("\n");
    return 0;
}

static void breakpoint_manager_init(breakpoint_manager_t *manager)
{
    manager->count = 0;
    manager->next_id = 1;
}

static breakpoint_t *breakpoint_manager_find_by_address(
    breakpoint_manager_t *manager,
    uintptr_t address)
{
    for (size_t i = 0; i < manager->count; ++i) {
        if (manager->items[i].address == address) {
            return &manager->items[i];
        }
    }
    return NULL;
}

static breakpoint_t *breakpoint_manager_add(
    breakpoint_manager_t *manager,
    uintptr_t address,
    const char *symbol)
{
    breakpoint_t *existing = breakpoint_manager_find_by_address(manager, address);
    if (existing != NULL) {
        return existing;
    }

    if (manager->count >= MAX_BREAKPOINTS) {
        fprintf(stderr,
                "[minigdb] too many breakpoints (max = %d)\n",
                MAX_BREAKPOINTS);
        return NULL;
    }

    breakpoint_t *bp = &manager->items[manager->count++];
    bp->id = manager->next_id++;
    bp->address = address;
    bp->saved_byte = 0;
    bp->enabled = 0;
    bp->hit_count = 0;
    snprintf(bp->symbol, sizeof(bp->symbol), "%s", symbol);
    return bp;
}

static void breakpoint_manager_print(const breakpoint_manager_t *manager)
{
    printf("\n===== Breakpoints =====\n");
    printf("ID   Symbol               Address             Enabled   Hits\n");

    for (size_t i = 0; i < manager->count; ++i) {
        const breakpoint_t *bp = &manager->items[i];
        printf("%-4d %-20s 0x%016lx %-9s %lu\n",
               bp->id,
               bp->symbol,
               (unsigned long)bp->address,
               bp->enabled ? "yes" : "no",
               bp->hit_count);
    }

    printf("============================================================\n\n");
}

static int breakpoint_enable(pid_t pid, breakpoint_t *bp)
{
    if (bp->enabled) {
        return 0;
    }

    unsigned long word;
    if (read_memory_word(pid, bp->address, &word) == -1) {
        return -1;
    }

    bp->saved_byte = (unsigned char)(word & 0xffUL);
    unsigned long patched = (word & ~0xffUL) | 0xccUL;

    if (write_memory_word(pid, bp->address, patched) == -1) {
        return -1;
    }

    bp->enabled = 1;

    printf("[minigdb] breakpoint #%d enabled at 0x%lx "
           "(saved byte = 0x%02x)\n",
           bp->id,
           (unsigned long)bp->address,
           bp->saved_byte);

    return 0;
}

static int breakpoint_disable(pid_t pid, breakpoint_t *bp)
{
    if (!bp->enabled) {
        return 0;
    }

    unsigned long word;
    if (read_memory_word(pid, bp->address, &word) == -1) {
        return -1;
    }

    unsigned long restored =
        (word & ~0xffUL) | (unsigned long)bp->saved_byte;

    if (write_memory_word(pid, bp->address, restored) == -1) {
        return -1;
    }

    bp->enabled = 0;
    return 0;
}

static int breakpoint_manager_enable_all(pid_t pid, breakpoint_manager_t *manager)
{
    for (size_t i = 0; i < manager->count; ++i) {
        if (breakpoint_enable(pid, &manager->items[i]) == -1) {
            return -1;
        }
    }
    return 0;
}

/*
 * Chapter 6/7: reusable machine-instruction single-step primitive.
 *
 * Exactly one CPU instruction is executed.  The traced process should then
 * stop with SIGTRAP, and we show the RIP transition so the step is visible.
 */
static int single_step_once(pid_t pid, struct user_regs_struct *after_regs)
{
    struct user_regs_struct before;
    if (get_registers(pid, &before) == -1) {
        return -1;
    }

    printf("[minigdb] single-step: RIP before = 0x%llx\n", before.rip);

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_SINGLESTEP");
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr,
                "[minigdb] debuggee did not stop after single-step\n");
        return -1;
    }

    if (WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr,
                "[minigdb] single-step stopped by signal %d instead of SIGTRAP\n",
                WSTOPSIG(status));
        return -1;
    }

    if (get_registers(pid, after_regs) == -1) {
        return -1;
    }

    printf("[minigdb] single-step: RIP after  = 0x%llx\n",
           after_regs->rip);

    return 0;
}

/*
 * Recover a software breakpoint:
 *   1. RIP points one byte past INT3, so rewind it.
 *   2. Restore the original first byte.
 *   3. Single-step the real instruction exactly once.
 *   4. Reinstall INT3 so the breakpoint remains persistent.
 */
static int recover_breakpoint(pid_t pid, breakpoint_t *bp)
{
    struct user_regs_struct regs;
    if (get_registers(pid, &regs) == -1) {
        return -1;
    }

    printf("[minigdb] RIP after INT3 = 0x%llx\n", regs.rip);

    regs.rip = bp->address;
    printf("[minigdb] rewinding RIP to 0x%llx\n", regs.rip);

    if (set_registers(pid, &regs) == -1) {
        return -1;
    }

    if (breakpoint_disable(pid, bp) == -1) {
        return -1;
    }
    printf("[minigdb] breakpoint #%d temporarily disabled\n", bp->id);
    printf("[minigdb] original instruction restored\n");

    struct user_regs_struct after_step;
    if (single_step_once(pid, &after_step) == -1) {
        return -1;
    }

    printf("[minigdb] original instruction executed once\n");

    if (breakpoint_enable(pid, bp) == -1) {
        return -1;
    }
    printf("[minigdb] breakpoint #%d reinstalled\n", bp->id);

    return 0;
}

static int continue_debuggee(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_CONT");
        return -1;
    }
    return 0;
}

/*
 * Chapter 8: ELF64 image + PIE/ASLR runtime-address resolution.
 *
 * Chapter 7 resolved:
 *
 *     symbol name -> Elf64_Sym.st_value
 *
 * That works directly for a traditional ET_EXEC executable.  A PIE executable
 * is normally ET_DYN, and ASLR chooses a different runtime load address on each
 * execution.  For ET_DYN we therefore resolve:
 *
 *     runtime address = load bias + st_value
 *
 * The load bias is recovered by matching one ELF PT_LOAD segment against the
 * corresponding mapping in /proc/<pid>/maps.
 */
typedef struct {
    Elf64_Half type;

    Elf64_Sym *symbols;
    size_t symbol_count;

    char *strtab;
    size_t strtab_size;

    Elf64_Phdr *program_headers;
    size_t program_header_count;
} elf_image_t;

typedef struct {
    char symbol[MAX_SYMBOL_NAME];
    uintptr_t elf_value;
} symbol_request_t;

static void elf_image_destroy(elf_image_t *image)
{
    free(image->symbols);
    free(image->strtab);
    free(image->program_headers);

    memset(image, 0, sizeof(*image));
}

static int read_file_region(FILE *fp, long offset, void *buffer, size_t size)
{
    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("fseek");
        return -1;
    }

    if (size != 0 && fread(buffer, 1, size, fp) != size) {
        fprintf(stderr, "[minigdb] failed to read ELF file region\n");
        return -1;
    }

    return 0;
}

static const char *elf_type_name(Elf64_Half type)
{
    switch (type) {
    case ET_EXEC:
        return "ET_EXEC";
    case ET_DYN:
        return "ET_DYN";
    default:
        return "UNKNOWN";
    }
}

static int elf_image_load(const char *path, elf_image_t *image)
{
    memset(image, 0, sizeof(*image));

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen ELF");
        return -1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)) {
        fprintf(stderr, "[minigdb] failed to read ELF header from %s\n", path);
        fclose(fp);
        return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[minigdb] %s is not an ELF file\n", path);
        fclose(fp);
        return -1;
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "[minigdb] only ELF64 is supported in Chapter 8\n");
        fclose(fp);
        return -1;
    }

    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "[minigdb] only little-endian ELF is supported\n");
        fclose(fp);
        return -1;
    }

    if (ehdr.e_machine != EM_X86_64) {
        fprintf(stderr, "[minigdb] only x86-64 ELF is supported\n");
        fclose(fp);
        return -1;
    }

    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        fprintf(stderr,
                "[minigdb] unsupported ELF type: %u (need ET_EXEC or ET_DYN)\n",
                (unsigned int)ehdr.e_type);
        fclose(fp);
        return -1;
    }

    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
        fprintf(stderr, "[minigdb] unsupported or missing ELF section table\n");
        fclose(fp);
        return -1;
    }

    if (ehdr.e_phoff == 0 || ehdr.e_phnum == 0 ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
        fprintf(stderr, "[minigdb] unsupported or missing ELF program-header table\n");
        fclose(fp);
        return -1;
    }

    Elf64_Shdr *sections =
        calloc((size_t)ehdr.e_shnum, sizeof(Elf64_Shdr));
    if (sections == NULL) {
        perror("calloc section headers");
        fclose(fp);
        return -1;
    }

    size_t sections_size =
        (size_t)ehdr.e_shnum * sizeof(Elf64_Shdr);

    if (read_file_region(fp,
                         (long)ehdr.e_shoff,
                         sections,
                         sections_size) == -1) {
        free(sections);
        fclose(fp);
        return -1;
    }

    Elf64_Phdr *program_headers =
        calloc((size_t)ehdr.e_phnum, sizeof(Elf64_Phdr));
    if (program_headers == NULL) {
        perror("calloc program headers");
        free(sections);
        fclose(fp);
        return -1;
    }

    size_t phdrs_size =
        (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);

    if (read_file_region(fp,
                         (long)ehdr.e_phoff,
                         program_headers,
                         phdrs_size) == -1) {
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    const Elf64_Shdr *symtab_section = NULL;
    for (size_t i = 0; i < (size_t)ehdr.e_shnum; ++i) {
        if (sections[i].sh_type == SHT_SYMTAB) {
            symtab_section = &sections[i];
            break;
        }
    }

    if (symtab_section == NULL) {
        fprintf(stderr,
                "[minigdb] no .symtab/SHT_SYMTAB found in %s\n"
                "[minigdb] the executable may have been stripped.\n",
                path);
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    if (symtab_section->sh_link >= ehdr.e_shnum) {
        fprintf(stderr, "[minigdb] invalid symbol string-table link\n");
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    const Elf64_Shdr *strtab_section =
        &sections[symtab_section->sh_link];

    if (strtab_section->sh_type != SHT_STRTAB) {
        fprintf(stderr, "[minigdb] symbol table does not link to a string table\n");
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    if (symtab_section->sh_entsize != sizeof(Elf64_Sym) ||
        symtab_section->sh_size % sizeof(Elf64_Sym) != 0) {
        fprintf(stderr, "[minigdb] unsupported ELF64 symbol-table layout\n");
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    size_t symbol_count =
        (size_t)(symtab_section->sh_size / sizeof(Elf64_Sym));

    Elf64_Sym *symbols =
        malloc(symbol_count * sizeof(Elf64_Sym));
    if (symbols == NULL && symbol_count != 0) {
        perror("malloc symbols");
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    size_t strtab_size = (size_t)strtab_section->sh_size;
    char *strtab = malloc(strtab_size + 1);
    if (strtab == NULL) {
        perror("malloc string table");
        free(symbols);
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    if (read_file_region(fp,
                         (long)symtab_section->sh_offset,
                         symbols,
                         symbol_count * sizeof(Elf64_Sym)) == -1 ||
        read_file_region(fp,
                         (long)strtab_section->sh_offset,
                         strtab,
                         strtab_size) == -1) {
        free(strtab);
        free(symbols);
        free(program_headers);
        free(sections);
        fclose(fp);
        return -1;
    }

    strtab[strtab_size] = '\0';

    image->type = ehdr.e_type;
    image->symbols = symbols;
    image->symbol_count = symbol_count;
    image->strtab = strtab;
    image->strtab_size = strtab_size;
    image->program_headers = program_headers;
    image->program_header_count = (size_t)ehdr.e_phnum;

    free(sections);
    fclose(fp);

    printf("[minigdb] loaded ELF64 image from %s (%zu symbols, %zu program headers)\n",
           path,
           image->symbol_count,
           image->program_header_count);

    printf("[minigdb] ELF type = %s%s\n",
           elf_type_name(image->type),
           image->type == ET_DYN ? " (PIE/shared-object style image)" : "");

    return 0;
}

static int elf_find_function(
    const elf_image_t *image,
    const char *symbol_name,
    uintptr_t *elf_value)
{
    for (size_t i = 0; i < image->symbol_count; ++i) {
        const Elf64_Sym *sym = &image->symbols[i];

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
            continue;
        }

        if (sym->st_shndx == SHN_UNDEF) {
            continue;
        }

        if ((size_t)sym->st_name >= image->strtab_size) {
            continue;
        }

        const char *name = image->strtab + sym->st_name;
        if (strcmp(name, symbol_name) == 0) {
            *elf_value = (uintptr_t)sym->st_value;
            return 0;
        }
    }

    return -1;
}

static uintptr_t align_down_uintptr(uintptr_t value, uintptr_t alignment)
{
    return value - (value % alignment);
}

/*
 * Read /proc/<pid>/exe instead of trying to guess how the relative path
 * "./hello" appears in /proc/<pid>/maps.  The proc symlink gives us the
 * canonical executable path used by the traced process.
 */
static int get_process_executable_path(
    pid_t pid,
    char *buffer,
    size_t buffer_size)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    ssize_t length = readlink(proc_path, buffer, buffer_size - 1);
    if (length == -1) {
        perror("readlink /proc/<pid>/exe");
        return -1;
    }

    buffer[length] = '\0';
    return 0;
}

/*
 * Match an ELF PT_LOAD segment with the corresponding /proc/<pid>/maps row.
 *
 * For a mapping that corresponds to one PT_LOAD segment:
 *
 *     mapping_start = load_bias + page_align_down(p_vaddr)
 *
 * therefore:
 *
 *     load_bias = mapping_start - page_align_down(p_vaddr)
 */
static int find_runtime_load_bias(
    pid_t pid,
    const elf_image_t *image,
    uintptr_t *load_bias)
{
    if (image->type == ET_EXEC) {
        *load_bias = 0;
        return 0;
    }

    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) {
        fprintf(stderr, "[minigdb] failed to determine page size\n");
        return -1;
    }

    uintptr_t page_size = (uintptr_t)page_size_long;

    char exe_path[PATH_MAX];
    if (get_process_executable_path(pid, exe_path, sizeof(exe_path)) == -1) {
        return -1;
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        perror("fopen /proc/<pid>/maps");
        return -1;
    }

    char line[PATH_MAX + 256];

    while (fgets(line, sizeof(line), maps) != NULL) {
        unsigned long map_start = 0;
        unsigned long map_end = 0;
        unsigned long map_offset = 0;
        unsigned long inode = 0;
        char permissions[5] = {0};
        char device[32] = {0};
        int path_offset = 0;

        int fields = sscanf(line,
                            "%lx-%lx %4s %lx %31s %lu %n",
                            &map_start,
                            &map_end,
                            permissions,
                            &map_offset,
                            device,
                            &inode,
                            &path_offset);

        (void)map_end;
        (void)permissions;
        (void)device;
        (void)inode;

        if (fields != 6 || path_offset <= 0) {
            continue;
        }

        char *mapped_path = line + path_offset;
        while (*mapped_path == ' ' || *mapped_path == '\t') {
            ++mapped_path;
        }

        size_t path_length = strlen(mapped_path);
        while (path_length > 0 &&
               (mapped_path[path_length - 1] == '\n' ||
                mapped_path[path_length - 1] == '\r')) {
            mapped_path[--path_length] = '\0';
        }

        if (strcmp(mapped_path, exe_path) != 0) {
            continue;
        }

        for (size_t i = 0; i < image->program_header_count; ++i) {
            const Elf64_Phdr *phdr = &image->program_headers[i];

            if (phdr->p_type != PT_LOAD) {
                continue;
            }

            uintptr_t segment_file_page =
                align_down_uintptr((uintptr_t)phdr->p_offset, page_size);
            uintptr_t segment_vaddr_page =
                align_down_uintptr((uintptr_t)phdr->p_vaddr, page_size);

            if ((uintptr_t)map_offset != segment_file_page) {
                continue;
            }

            if ((uintptr_t)map_start < segment_vaddr_page) {
                continue;
            }

            *load_bias = (uintptr_t)map_start - segment_vaddr_page;

            printf("[minigdb] matched PT_LOAD: "
                   "file offset 0x%lx, ELF vaddr 0x%lx, map start 0x%lx\n",
                   (unsigned long)segment_file_page,
                   (unsigned long)segment_vaddr_page,
                   map_start);
            printf("[minigdb] executable mapping = %s\n", mapped_path);

            fclose(maps);
            return 0;
        }
    }

    fclose(maps);

    fprintf(stderr,
            "[minigdb] could not match %s PT_LOAD segments with %s\n",
            exe_path,
            maps_path);
    return -1;
}

static uintptr_t elf_value_to_runtime_address(
    const elf_image_t *image,
    uintptr_t elf_value,
    uintptr_t load_bias)
{
    if (image->type == ET_DYN) {
        return load_bias + elf_value;
    }

    return elf_value;
}

int main(int argc, char *argv[])
{
    /*
     * Chapter 8 still accepts function symbol names:
     *
     *     ./minigdb main foo
     *
     * Unlike Chapter 7, ./hello may now be a normal PIE executable.
     */
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <function-symbol> [function-symbol ...]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (argc - 1 > MAX_BREAKPOINTS) {
        fprintf(stderr,
                "[minigdb] too many requested breakpoints (max = %d)\n",
                MAX_BREAKPOINTS);
        return EXIT_FAILURE;
    }

    elf_image_t image;
    if (elf_image_load(PROGRAM_PATH, &image) == -1) {
        return EXIT_FAILURE;
    }

    symbol_request_t requests[MAX_BREAKPOINTS];
    size_t request_count = 0;

    printf("\n[minigdb] ELF symbol values:\n");

    for (int i = 1; i < argc; ++i) {
        uintptr_t elf_value;
        if (elf_find_function(&image, argv[i], &elf_value) == -1) {
            fprintf(stderr,
                    "[minigdb] function symbol not found: %s\n",
                    argv[i]);
            elf_image_destroy(&image);
            return EXIT_FAILURE;
        }

        symbol_request_t *request = &requests[request_count++];
        snprintf(request->symbol, sizeof(request->symbol), "%s", argv[i]);
        request->elf_value = elf_value;

        printf("[minigdb]   %-20s -> 0x%lx\n",
               request->symbol,
               (unsigned long)request->elf_value);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace PTRACE_TRACEME");
            _exit(EXIT_FAILURE);
        }

        execl(PROGRAM_PATH, PROGRAM_PATH, NULL);
        perror("execl");
        _exit(EXIT_FAILURE);
    }

    printf("[minigdb] child pid = %d\n", pid);

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[minigdb] child did not stop after exec\n");
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    printf("[minigdb] initial stop signal = %d\n", WSTOPSIG(status));

    uintptr_t load_bias;
    if (find_runtime_load_bias(pid, &image, &load_bias) == -1) {
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    printf("[minigdb] runtime load bias = 0x%lx\n",
           (unsigned long)load_bias);

    breakpoint_manager_t manager;
    breakpoint_manager_init(&manager);

    printf("\n[minigdb] runtime symbol addresses:\n");

    for (size_t i = 0; i < request_count; ++i) {
        uintptr_t runtime_address =
            elf_value_to_runtime_address(&image,
                                         requests[i].elf_value,
                                         load_bias);

        printf("[minigdb]   %-20s -> 0x%lx "
               "(ELF value 0x%lx)\n",
               requests[i].symbol,
               (unsigned long)runtime_address,
               (unsigned long)requests[i].elf_value);

        breakpoint_t *bp =
            breakpoint_manager_add(&manager,
                                   runtime_address,
                                   requests[i].symbol);
        if (bp == NULL) {
            elf_image_destroy(&image);
            return EXIT_FAILURE;
        }
    }

    elf_image_destroy(&image);

    printf("\n[minigdb] configured breakpoint manager:\n");
    breakpoint_manager_print(&manager);

    for (size_t i = 0; i < manager.count; ++i) {
        printf("Before breakpoint #%d (%s):\n",
               manager.items[i].id,
               manager.items[i].symbol);
        if (print_memory_word(pid, manager.items[i].address) == -1) {
            return EXIT_FAILURE;
        }
    }

    if (breakpoint_manager_enable_all(pid, &manager) == -1) {
        return EXIT_FAILURE;
    }

    printf("\n[minigdb] after enabling all breakpoints:\n");
    breakpoint_manager_print(&manager);

    if (continue_debuggee(pid) == -1) {
        return EXIT_FAILURE;
    }

    printf("[minigdb] child continued\n");

    /*
     * Chapter 6/7/8 event loop:
     * breakpoint handling is unchanged because it only needs runtime addresses.
     */
    for (;;) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return EXIT_FAILURE;
        }

        if (WIFEXITED(status)) {
            printf("\n[minigdb] child exited with code %d\n",
                   WEXITSTATUS(status));
            break;
        }

        if (WIFSIGNALED(status)) {
            printf("\n[minigdb] child terminated by signal %d\n",
                   WTERMSIG(status));
            break;
        }

        if (!WIFSTOPPED(status)) {
            continue;
        }

        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        if (get_registers(pid, &regs) == -1) {
            return EXIT_FAILURE;
        }

        if (sig == SIGTRAP && regs.rip > 0) {
            uintptr_t candidate = (uintptr_t)(regs.rip - 1);
            breakpoint_t *bp =
                breakpoint_manager_find_by_address(&manager, candidate);

            if (bp != NULL && bp->enabled) {
                ++bp->hit_count;

                printf("\n[minigdb] breakpoint #%d hit!\n", bp->id);
                printf("[minigdb] symbol = %s\n", bp->symbol);
                printf("[minigdb] address = 0x%lx\n",
                       (unsigned long)bp->address);
                printf("[minigdb] hit count = %lu\n", bp->hit_count);

                print_registers(&regs);

                if (recover_breakpoint(pid, bp) == -1) {
                    return EXIT_FAILURE;
                }

                if (continue_debuggee(pid) == -1) {
                    return EXIT_FAILURE;
                }

                printf("[minigdb] child continued\n");
                continue;
            }

            printf("\n[minigdb] SIGTRAP at RIP 0x%llx was not caused by "
                   "a managed breakpoint\n",
                   regs.rip);

            if (continue_debuggee(pid) == -1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        printf("\n[minigdb] child stopped by signal %d\n", sig);

        if (ptrace(PTRACE_CONT,
                   pid,
                   NULL,
                   (void *)(intptr_t)sig) == -1) {
            perror("ptrace PTRACE_CONT");
            return EXIT_FAILURE;
        }
    }

    printf("\n[minigdb] final breakpoint statistics:\n");
    breakpoint_manager_print(&manager);

    return EXIT_SUCCESS;
}
