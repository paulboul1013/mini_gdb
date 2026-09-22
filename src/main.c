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
 * Breakpoint-aware user step.
 *
 * If RIP is already sitting on an enabled software breakpoint, memory at RIP
 * contains INT3 (0xCC), not the program's original first byte.  A raw
 * PTRACE_SINGLESTEP would therefore execute INT3 instead of the real
 * instruction.  Temporarily remove that breakpoint, step exactly one original
 * instruction, then reinstall the breakpoint.
 *
 * Reaching another breakpoint address as the result of the stepped instruction
 * is only an arrival at that address; INT3 has not executed yet, so hit_count is
 * intentionally not incremented.
 */
static int step_debuggee(
    pid_t pid,
    breakpoint_manager_t *manager,
    struct user_regs_struct *after_regs)
{
    struct user_regs_struct before;
    if (get_registers(pid, &before) == -1) {
        return -1;
    }

    breakpoint_t *current_bp =
        breakpoint_manager_find_by_address(manager, (uintptr_t)before.rip);
    int temporarily_removed =
        current_bp != NULL && current_bp->enabled;

    if (temporarily_removed) {
        printf("[minigdb] step: RIP is at breakpoint #%d (%s) at 0x%llx\n",
               current_bp->id,
               current_bp->symbol,
               before.rip);
        printf("[minigdb] step: restoring original instruction before stepping\n");

        if (breakpoint_disable(pid, current_bp) == -1) {
            return -1;
        }
    }

    if (single_step_once(pid, after_regs) == -1) {
        /* Best effort: if the process is still stopped, restore debugger state. */
        if (temporarily_removed) {
            (void)breakpoint_enable(pid, current_bp);
        }
        return -1;
    }

    if (temporarily_removed) {
        if (breakpoint_enable(pid, current_bp) == -1) {
            return -1;
        }
        printf("[minigdb] step: breakpoint #%d reinstalled\n",
               current_bp->id);
    }

    breakpoint_t *arrived_bp =
        breakpoint_manager_find_by_address(manager,
                                           (uintptr_t)after_regs->rip);
    if (arrived_bp != NULL && arrived_bp->enabled) {
        printf("[minigdb] step: arrived at breakpoint #%d (%s) address 0x%llx\n",
               arrived_bp->id,
               arrived_bp->symbol,
               after_regs->rip);
        printf("[minigdb] step: INT3 has not executed; hit count remains %lu\n",
               arrived_bp->hit_count);
    }

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

/*
 * Chapter 9.2: convert the address domain used by ptrace/RIP back into the
 * ELF/DWARF address domain.  For a PIE (ET_DYN) image, Chapter 8 established:
 *
 *     runtime = load_bias + elf_value
 *
 * so source lookup needs the inverse mapping:
 *
 *     elf_value = runtime - load_bias
 *
 * A traditional ET_EXEC image needs no relocation here.
 */
static int runtime_address_to_elf_value(
    const elf_image_t *image,
    uintptr_t runtime_address,
    uintptr_t load_bias,
    uintptr_t *elf_value)
{
    uintptr_t candidate = runtime_address;

    if (image->type == ET_DYN) {
        if (runtime_address < load_bias) {
            return -1;
        }
        candidate = runtime_address - load_bias;
    }

    /*
     * Do not mistake an address in ld-linux/libc for an address in the target
     * executable merely because subtraction happened to be possible.  The
     * converted ELF value must fall inside one of this image's PT_LOAD ranges.
     */
    for (size_t i = 0; i < image->program_header_count; ++i) {
        const Elf64_Phdr *phdr = &image->program_headers[i];
        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0) {
            continue;
        }

        uintptr_t start = (uintptr_t)phdr->p_vaddr;
        uintptr_t size = (uintptr_t)phdr->p_memsz;
        if (candidate >= start && candidate - start < size) {
            *elf_value = candidate;
            return 0;
        }
    }

    return -1;
}


/*
 * Chapter 9.1: minimal DWARF v4 .debug_line decoder.
 *
 * Scope of this first step:
 *   - ELF64 little-endian only (already required by MiniGDB)
 *   - DWARF v4 line tables only
 *   - x86-64 style maximum_operations_per_instruction == 1
 *   - decode rows into: ELF address -> source file:line
 *
 * Compile the debuggee with -g -gdwarf-4 for this chapter.
 */
#define DW_LNS_COPY 1
#define DW_LNS_ADVANCE_PC 2
#define DW_LNS_ADVANCE_LINE 3
#define DW_LNS_SET_FILE 4
#define DW_LNS_SET_COLUMN 5
#define DW_LNS_NEGATE_STMT 6
#define DW_LNS_SET_BASIC_BLOCK 7
#define DW_LNS_CONST_ADD_PC 8
#define DW_LNS_FIXED_ADVANCE_PC 9
#define DW_LNS_SET_PROLOGUE_END 10
#define DW_LNS_SET_EPILOGUE_BEGIN 11
#define DW_LNS_SET_ISA 12

#define DW_LNE_END_SEQUENCE 1
#define DW_LNE_SET_ADDRESS 2
#define DW_LNE_DEFINE_FILE 3
#define DW_LNE_SET_DISCRIMINATOR 4

#define MAX_DWARF_DIRS 64
#define MAX_DWARF_FILES 256
#define MAX_SOURCE_PATH 512

typedef struct {
    uintptr_t address;
    uint32_t line;
    uint32_t column;
    int is_stmt;
    int end_sequence;
    char file[MAX_SOURCE_PATH];
} dwarf_line_row_t;

typedef struct {
    dwarf_line_row_t *rows;
    size_t count;
    size_t capacity;
} dwarf_line_table_t;

static void dwarf_line_table_destroy(dwarf_line_table_t *table)
{
    free(table->rows);
    memset(table, 0, sizeof(*table));
}

static int dwarf_line_table_append(
    dwarf_line_table_t *table,
    uintptr_t address,
    const char *file,
    uint32_t line,
    uint32_t column,
    int is_stmt,
    int end_sequence)
{
    if (table->count == table->capacity) {
        size_t new_capacity = table->capacity == 0 ? 64 : table->capacity * 2;
        dwarf_line_row_t *new_rows =
            realloc(table->rows, new_capacity * sizeof(*new_rows));
        if (new_rows == NULL) {
            perror("realloc DWARF line rows");
            return -1;
        }
        table->rows = new_rows;
        table->capacity = new_capacity;
    }

    dwarf_line_row_t *row = &table->rows[table->count++];
    row->address = address;
    row->line = line;
    row->column = column;
    row->is_stmt = is_stmt;
    row->end_sequence = end_sequence;
    snprintf(row->file, sizeof(row->file), "%s", file != NULL ? file : "<unknown>");
    return 0;
}

static int read_u8(const unsigned char **cursor, const unsigned char *end, uint8_t *value)
{
    if (*cursor >= end) {
        return -1;
    }
    *value = *(*cursor)++;
    return 0;
}

static int read_u16_le(const unsigned char **cursor, const unsigned char *end, uint16_t *value)
{
    if ((size_t)(end - *cursor) < 2) {
        return -1;
    }
    const unsigned char *p = *cursor;
    *value = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    *cursor += 2;
    return 0;
}

static int read_u32_le(const unsigned char **cursor, const unsigned char *end, uint32_t *value)
{
    if ((size_t)(end - *cursor) < 4) {
        return -1;
    }
    const unsigned char *p = *cursor;
    *value = (uint32_t)p[0]
           | ((uint32_t)p[1] << 8)
           | ((uint32_t)p[2] << 16)
           | ((uint32_t)p[3] << 24);
    *cursor += 4;
    return 0;
}

static int read_uint_le_n(
    const unsigned char **cursor,
    const unsigned char *end,
    size_t width,
    uint64_t *value)
{
    if (width == 0 || width > 8 || (size_t)(end - *cursor) < width) {
        return -1;
    }

    uint64_t result = 0;
    for (size_t i = 0; i < width; ++i) {
        result |= (uint64_t)(*cursor)[i] << (8 * i);
    }
    *cursor += width;
    *value = result;
    return 0;
}

static int read_uleb128(
    const unsigned char **cursor,
    const unsigned char *end,
    uint64_t *value)
{
    uint64_t result = 0;
    unsigned int shift = 0;

    while (*cursor < end && shift < 64) {
        uint8_t byte = *(*cursor)++;
        result |= (uint64_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0) {
            *value = result;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

static int read_sleb128(
    const unsigned char **cursor,
    const unsigned char *end,
    int64_t *value)
{
    int64_t result = 0;
    unsigned int shift = 0;
    uint8_t byte = 0;

    while (*cursor < end && shift < 64) {
        byte = *(*cursor)++;
        result |= (int64_t)(byte & 0x7fU) << shift;
        shift += 7;
        if ((byte & 0x80U) == 0) {
            if (shift < 64 && (byte & 0x40U) != 0) {
                result |= -((int64_t)1 << shift);
            }
            *value = result;
            return 0;
        }
    }
    return -1;
}

static int read_cstring(
    const unsigned char **cursor,
    const unsigned char *end,
    char *buffer,
    size_t buffer_size)
{
    const unsigned char *start = *cursor;
    const unsigned char *p = start;
    while (p < end && *p != '\0') {
        ++p;
    }
    if (p >= end) {
        return -1;
    }

    size_t length = (size_t)(p - start);
    if (buffer_size > 0) {
        size_t copy_length = length < buffer_size - 1 ? length : buffer_size - 1;
        memcpy(buffer, start, copy_length);
        buffer[copy_length] = '\0';
    }

    *cursor = p + 1;
    return 0;
}

static void join_source_path(
    char *output,
    size_t output_size,
    const char *directory,
    const char *filename)
{
    if (directory != NULL && directory[0] != '\0') {
        snprintf(output, output_size, "%s/%s", directory, filename);
    } else {
        snprintf(output, output_size, "%s", filename);
    }
}

static const char *dwarf_current_file(
    char files[MAX_DWARF_FILES][MAX_SOURCE_PATH],
    size_t file_count,
    uint64_t file_index)
{
    if (file_index == 0 || file_index > file_count) {
        return "<unknown>";
    }
    return files[file_index - 1];
}

static int dwarf_decode_line_unit(
    const unsigned char **cursor,
    const unsigned char *section_end,
    dwarf_line_table_t *table)
{
    uint32_t unit_length = 0;
    if (read_u32_le(cursor, section_end, &unit_length) == -1) {
        return -1;
    }

    if (unit_length == 0xffffffffU) {
        fprintf(stderr, "[minigdb] DWARF64 .debug_line is not supported in Chapter 9.1\n");
        return -1;
    }

    if ((size_t)(section_end - *cursor) < unit_length) {
        fprintf(stderr, "[minigdb] truncated DWARF .debug_line unit\n");
        return -1;
    }

    const unsigned char *unit_end = *cursor + unit_length;

    uint16_t version = 0;
    if (read_u16_le(cursor, unit_end, &version) == -1) {
        return -1;
    }

    if (version != 4) {
        fprintf(stderr,
                "[minigdb] Chapter 9.1 supports DWARF v4 .debug_line only (found v%u).\n"
                "[minigdb] rebuild the debuggee with -g -gdwarf-4.\n",
                (unsigned int)version);
        return -1;
    }

    uint32_t header_length = 0;
    if (read_u32_le(cursor, unit_end, &header_length) == -1) {
        return -1;
    }
    if ((size_t)(unit_end - *cursor) < header_length) {
        return -1;
    }
    const unsigned char *program_start = *cursor + header_length;

    uint8_t minimum_instruction_length = 0;
    uint8_t maximum_operations_per_instruction = 0;
    uint8_t default_is_stmt = 0;
    uint8_t line_base_raw = 0;
    uint8_t line_range = 0;
    uint8_t opcode_base = 0;

    if (read_u8(cursor, program_start, &minimum_instruction_length) == -1 ||
        read_u8(cursor, program_start, &maximum_operations_per_instruction) == -1 ||
        read_u8(cursor, program_start, &default_is_stmt) == -1 ||
        read_u8(cursor, program_start, &line_base_raw) == -1 ||
        read_u8(cursor, program_start, &line_range) == -1 ||
        read_u8(cursor, program_start, &opcode_base) == -1) {
        return -1;
    }

    int8_t line_base = (int8_t)line_base_raw;

    if (maximum_operations_per_instruction != 1) {
        fprintf(stderr,
                "[minigdb] Chapter 9.1 expects max_ops_per_instruction=1, got %u\n",
                (unsigned int)maximum_operations_per_instruction);
        return -1;
    }
    if (line_range == 0 || opcode_base == 0) {
        return -1;
    }

    uint8_t standard_opcode_lengths[256] = {0};
    for (uint16_t opcode = 1; opcode < opcode_base; ++opcode) {
        if (read_u8(cursor, program_start, &standard_opcode_lengths[opcode]) == -1) {
            return -1;
        }
    }

    char directories[MAX_DWARF_DIRS][MAX_SOURCE_PATH];
    size_t directory_count = 0;
    while (*cursor < program_start) {
        char directory[MAX_SOURCE_PATH];
        if (read_cstring(cursor, program_start, directory, sizeof(directory)) == -1) {
            return -1;
        }
        if (directory[0] == '\0') {
            break;
        }
        if (directory_count >= MAX_DWARF_DIRS) {
            fprintf(stderr, "[minigdb] too many DWARF include directories\n");
            return -1;
        }
        snprintf(directories[directory_count++], MAX_SOURCE_PATH, "%s", directory);
    }

    char files[MAX_DWARF_FILES][MAX_SOURCE_PATH];
    size_t file_count = 0;
    while (*cursor < program_start) {
        char filename[MAX_SOURCE_PATH];
        if (read_cstring(cursor, program_start, filename, sizeof(filename)) == -1) {
            return -1;
        }
        if (filename[0] == '\0') {
            break;
        }

        uint64_t directory_index = 0;
        uint64_t modification_time = 0;
        uint64_t file_size = 0;
        if (read_uleb128(cursor, program_start, &directory_index) == -1 ||
            read_uleb128(cursor, program_start, &modification_time) == -1 ||
            read_uleb128(cursor, program_start, &file_size) == -1) {
            return -1;
        }
        (void)modification_time;
        (void)file_size;

        if (file_count >= MAX_DWARF_FILES) {
            fprintf(stderr, "[minigdb] too many DWARF source files\n");
            return -1;
        }

        const char *directory = NULL;
        if (directory_index > 0 && directory_index <= directory_count) {
            directory = directories[directory_index - 1];
        }
        join_source_path(files[file_count], MAX_SOURCE_PATH, directory, filename);
        ++file_count;
    }

    *cursor = program_start;

    uintptr_t address = 0;
    uint64_t file_index = 1;
    int64_t line = 1;
    uint64_t column = 0;
    int is_stmt = default_is_stmt != 0;

    while (*cursor < unit_end) {
        uint8_t opcode = 0;
        if (read_u8(cursor, unit_end, &opcode) == -1) {
            return -1;
        }

        if (opcode == 0) {
            uint64_t extended_length = 0;
            if (read_uleb128(cursor, unit_end, &extended_length) == -1 ||
                extended_length == 0 ||
                (uint64_t)(unit_end - *cursor) < extended_length) {
                return -1;
            }

            const unsigned char *extended_end = *cursor + extended_length;
            uint8_t extended_opcode = 0;
            if (read_u8(cursor, extended_end, &extended_opcode) == -1) {
                return -1;
            }

            switch (extended_opcode) {
            case DW_LNE_END_SEQUENCE:
                if (dwarf_line_table_append(
                        table,
                        address,
                        dwarf_current_file(files, file_count, file_index),
                        line < 0 ? 0U : (uint32_t)line,
                        (uint32_t)column,
                        is_stmt,
                        1) == -1) {
                    return -1;
                }
                address = 0;
                file_index = 1;
                line = 1;
                column = 0;
                is_stmt = default_is_stmt != 0;
                break;

            case DW_LNE_SET_ADDRESS: {
                size_t address_width = (size_t)(extended_end - *cursor);
                uint64_t value = 0;
                if (read_uint_le_n(cursor, extended_end, address_width, &value) == -1) {
                    return -1;
                }
                address = (uintptr_t)value;
                break;
            }

            case DW_LNE_DEFINE_FILE: {
                if (file_count >= MAX_DWARF_FILES) {
                    return -1;
                }
                char filename[MAX_SOURCE_PATH];
                uint64_t directory_index = 0;
                uint64_t ignored = 0;
                if (read_cstring(cursor, extended_end, filename, sizeof(filename)) == -1 ||
                    read_uleb128(cursor, extended_end, &directory_index) == -1 ||
                    read_uleb128(cursor, extended_end, &ignored) == -1 ||
                    read_uleb128(cursor, extended_end, &ignored) == -1) {
                    return -1;
                }
                const char *directory = NULL;
                if (directory_index > 0 && directory_index <= directory_count) {
                    directory = directories[directory_index - 1];
                }
                join_source_path(files[file_count], MAX_SOURCE_PATH, directory, filename);
                ++file_count;
                break;
            }

            case DW_LNE_SET_DISCRIMINATOR: {
                uint64_t ignored = 0;
                if (read_uleb128(cursor, extended_end, &ignored) == -1) {
                    return -1;
                }
                break;
            }

            default:
                break;
            }

            *cursor = extended_end;
            continue;
        }

        if (opcode < opcode_base) {
            switch (opcode) {
            case DW_LNS_COPY:
                if (dwarf_line_table_append(
                        table,
                        address,
                        dwarf_current_file(files, file_count, file_index),
                        line < 0 ? 0U : (uint32_t)line,
                        (uint32_t)column,
                        is_stmt,
                        0) == -1) {
                    return -1;
                }
                break;

            case DW_LNS_ADVANCE_PC: {
                uint64_t operation_advance = 0;
                if (read_uleb128(cursor, unit_end, &operation_advance) == -1) {
                    return -1;
                }
                address += (uintptr_t)(operation_advance * minimum_instruction_length);
                break;
            }

            case DW_LNS_ADVANCE_LINE: {
                int64_t line_increment = 0;
                if (read_sleb128(cursor, unit_end, &line_increment) == -1) {
                    return -1;
                }
                line += line_increment;
                break;
            }

            case DW_LNS_SET_FILE: {
                uint64_t value = 0;
                if (read_uleb128(cursor, unit_end, &value) == -1) {
                    return -1;
                }
                file_index = value;
                break;
            }

            case DW_LNS_SET_COLUMN: {
                uint64_t value = 0;
                if (read_uleb128(cursor, unit_end, &value) == -1) {
                    return -1;
                }
                column = value;
                break;
            }

            case DW_LNS_NEGATE_STMT:
                is_stmt = !is_stmt;
                break;

            case DW_LNS_SET_BASIC_BLOCK:
            case DW_LNS_SET_PROLOGUE_END:
            case DW_LNS_SET_EPILOGUE_BEGIN:
                break;

            case DW_LNS_CONST_ADD_PC: {
                uint8_t adjusted_opcode = (uint8_t)(255U - opcode_base);
                address += (uintptr_t)((adjusted_opcode / line_range) *
                                       minimum_instruction_length);
                break;
            }

            case DW_LNS_FIXED_ADVANCE_PC: {
                uint16_t advance = 0;
                if (read_u16_le(cursor, unit_end, &advance) == -1) {
                    return -1;
                }
                address += advance;
                break;
            }

            case DW_LNS_SET_ISA: {
                uint64_t ignored = 0;
                if (read_uleb128(cursor, unit_end, &ignored) == -1) {
                    return -1;
                }
                break;
            }

            default:
                for (uint8_t i = 0; i < standard_opcode_lengths[opcode]; ++i) {
                    uint64_t ignored = 0;
                    if (read_uleb128(cursor, unit_end, &ignored) == -1) {
                        return -1;
                    }
                }
                break;
            }
            continue;
        }

        uint8_t adjusted_opcode = (uint8_t)(opcode - opcode_base);
        uintptr_t address_increment =
            (uintptr_t)((adjusted_opcode / line_range) * minimum_instruction_length);
        int64_t line_increment =
            (int64_t)line_base + (int64_t)(adjusted_opcode % line_range);

        address += address_increment;
        line += line_increment;

        if (dwarf_line_table_append(
                table,
                address,
                dwarf_current_file(files, file_count, file_index),
                line < 0 ? 0U : (uint32_t)line,
                (uint32_t)column,
                is_stmt,
                0) == -1) {
            return -1;
        }
    }

    *cursor = unit_end;
    return 0;
}

static int dwarf_line_table_load(const char *path, dwarf_line_table_t *table)
{
    memset(table, 0, sizeof(*table));

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen DWARF ELF");
        return -1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)) {
        fclose(fp);
        return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shoff == 0 ||
        ehdr.e_shnum == 0 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr) ||
        ehdr.e_shstrndx == SHN_UNDEF ||
        ehdr.e_shstrndx >= ehdr.e_shnum) {
        fclose(fp);
        return -1;
    }

    Elf64_Shdr *sections = calloc((size_t)ehdr.e_shnum, sizeof(*sections));
    if (sections == NULL) {
        perror("calloc DWARF sections");
        fclose(fp);
        return -1;
    }

    if (read_file_region(fp,
                         (long)ehdr.e_shoff,
                         sections,
                         (size_t)ehdr.e_shnum * sizeof(*sections)) == -1) {
        free(sections);
        fclose(fp);
        return -1;
    }

    const Elf64_Shdr *shstr_section = &sections[ehdr.e_shstrndx];
    size_t shstr_size = (size_t)shstr_section->sh_size;
    char *shstr = malloc(shstr_size + 1);
    if (shstr == NULL) {
        perror("malloc section-name table");
        free(sections);
        fclose(fp);
        return -1;
    }

    if (read_file_region(fp,
                         (long)shstr_section->sh_offset,
                         shstr,
                         shstr_size) == -1) {
        free(shstr);
        free(sections);
        fclose(fp);
        return -1;
    }
    shstr[shstr_size] = '\0';

    const Elf64_Shdr *debug_line_section = NULL;
    for (size_t i = 0; i < (size_t)ehdr.e_shnum; ++i) {
        if ((size_t)sections[i].sh_name >= shstr_size) {
            continue;
        }
        const char *name = shstr + sections[i].sh_name;
        if (strcmp(name, ".debug_line") == 0) {
            debug_line_section = &sections[i];
            break;
        }
    }

    if (debug_line_section == NULL) {
        fprintf(stderr,
                "[minigdb] no .debug_line section found; compile the debuggee with -g -gdwarf-4\n");
        free(shstr);
        free(sections);
        fclose(fp);
        return -1;
    }

    size_t section_size = (size_t)debug_line_section->sh_size;
    unsigned char *data = malloc(section_size);
    if (data == NULL && section_size != 0) {
        perror("malloc .debug_line");
        free(shstr);
        free(sections);
        fclose(fp);
        return -1;
    }

    if (read_file_region(fp,
                         (long)debug_line_section->sh_offset,
                         data,
                         section_size) == -1) {
        free(data);
        free(shstr);
        free(sections);
        fclose(fp);
        return -1;
    }

    free(shstr);
    free(sections);
    fclose(fp);

    const unsigned char *cursor = data;
    const unsigned char *end = data + section_size;
    while (cursor < end) {
        if (dwarf_decode_line_unit(&cursor, end, table) == -1) {
            free(data);
            dwarf_line_table_destroy(table);
            return -1;
        }
    }

    free(data);

    printf("[minigdb] loaded DWARF v4 .debug_line (%zu rows)\n", table->count);
    return 0;
}

static void dwarf_line_table_print(const dwarf_line_table_t *table)
{
    printf("\n===== DWARF Line Table (ELF addresses) =====\n");
    printf("Address            File                              Line   Column  Flags\n");

    for (size_t i = 0; i < table->count; ++i) {
        const dwarf_line_row_t *row = &table->rows[i];
        printf("0x%016lx %-33s %-6u %-7u %s%s\n",
               (unsigned long)row->address,
               row->file,
               row->line,
               row->column,
               row->is_stmt ? "is_stmt" : "",
               row->end_sequence ? " end_sequence" : "");
    }

    printf("=============================================\n\n");
}

/*
 * Chapter 9.2: resolve one ELF address to the source row whose address range
 * contains it.  A normal DWARF line row is the START of a range; it is not
 * merely an exact-address record.
 *
 * Example:
 *
 *     0x1194 -> line 10
 *     0x119c -> line 11
 *
 * means every address in [0x1194, 0x119c) maps to line 10.
 *
 * end_sequence is a hard upper bound.  We never allow a lookup to leak from
 * the end of one DWARF sequence into the next sequence.
 */
static int dwarf_line_lookup_address(
    const dwarf_line_table_t *table,
    uintptr_t elf_address,
    const dwarf_line_row_t **result)
{
    if (table == NULL || result == NULL || table->count == 0) {
        return -1;
    }

    *result = NULL;

    for (size_t i = 0; i < table->count; ++i) {
        const dwarf_line_row_t *row = &table->rows[i];

        if (row->end_sequence) {
            continue;
        }

        /* Find the next row that supplies this row's exclusive upper bound. */
        size_t next_index = i + 1;
        while (next_index < table->count &&
               !table->rows[next_index].end_sequence &&
               table->rows[next_index].address == row->address) {
            ++next_index;
        }

        if (next_index >= table->count) {
            continue;
        }

        const dwarf_line_row_t *next = &table->rows[next_index];
        uintptr_t range_end = next->address;

        if (range_end <= row->address) {
            continue;
        }

        if (elf_address >= row->address && elf_address < range_end) {
            /* If several rows share one address, use the last such row. */
            size_t chosen = next_index - 1;
            *result = &table->rows[chosen];
            return 0;
        }
    }

    return -1;
}

static void print_current_source_location(
    pid_t pid,
    const elf_image_t *image,
    const dwarf_line_table_t *table,
    uintptr_t load_bias)
{
    struct user_regs_struct regs;
    if (get_registers(pid, &regs) == -1) {
        return;
    }

    uintptr_t runtime_rip = (uintptr_t)regs.rip;
    uintptr_t elf_address = 0;

    printf("\n===== Source Location =====\n");
    printf("Runtime RIP : 0x%016lx\n", (unsigned long)runtime_rip);

    if (runtime_address_to_elf_value(
            image, runtime_rip, load_bias, &elf_address) == -1) {
        printf("ELF address : <outside target image>\n");
        printf("Source      : <no source location>\n");
        printf("===========================\n\n");
        return;
    }

    printf("ELF address : 0x%016lx\n", (unsigned long)elf_address);

    const dwarf_line_row_t *row = NULL;
    if (dwarf_line_lookup_address(table, elf_address, &row) == -1) {
        printf("Source      : <no DWARF source location>\n");
        printf("===========================\n\n");
        return;
    }

    printf("Source      : %s:%u", row->file, row->line);
    if (row->column != 0) {
        printf(":%u", row->column);
    }
    printf("\n");
    printf("Range start : 0x%016lx\n", (unsigned long)row->address);
    printf("===========================\n\n");
}


/*
 * Chapter 9.3: reverse Chapter 9.2's lookup direction.
 *
 *     source file:line -> DWARF line row -> ELF address
 *
 * A source line may correspond to more than one line-table row.  For this
 * minimal implementation we prefer the first matching is_stmt row, because
 * DWARF marks it as a useful statement boundary for source-level debugging.
 * If no matching row has is_stmt set, the first ordinary matching row is used
 * as a fallback.  end_sequence rows are markers, not executable source rows,
 * so they are never returned.
 */
static const char *source_path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

static int dwarf_line_lookup_source_pass(
    const dwarf_line_table_t *table,
    const char *file,
    uint32_t line,
    int basename_only,
    const dwarf_line_row_t **result)
{
    const dwarf_line_row_t *fallback = NULL;

    for (size_t i = 0; i < table->count; ++i) {
        const dwarf_line_row_t *row = &table->rows[i];

        if (row->end_sequence || row->line != line) {
            continue;
        }

        int file_matches;
        if (basename_only) {
            file_matches =
                strcmp(source_path_basename(row->file),
                       source_path_basename(file)) == 0;
        } else {
            file_matches = strcmp(row->file, file) == 0;
        }

        if (!file_matches) {
            continue;
        }

        if (fallback == NULL) {
            fallback = row;
        }

        if (row->is_stmt) {
            *result = row;
            return 0;
        }
    }

    if (fallback != NULL) {
        *result = fallback;
        return 0;
    }

    return -1;
}

static int dwarf_line_lookup_source(
    const dwarf_line_table_t *table,
    const char *file,
    uint32_t line,
    const dwarf_line_row_t **result)
{
    if (table == NULL || file == NULL || result == NULL ||
        table->count == 0 || file[0] == '\0' || line == 0) {
        return -1;
    }

    *result = NULL;

    /* Prefer an exact DWARF path match before falling back to basename. */
    if (dwarf_line_lookup_source_pass(
            table, file, line, 0, result) == 0) {
        return 0;
    }

    return dwarf_line_lookup_source_pass(
        table, file, line, 1, result);
}

static int parse_source_location(
    const char *text,
    char *file,
    size_t file_size,
    uint32_t *line)
{
    if (text == NULL || file == NULL || file_size == 0 || line == NULL) {
        return -1;
    }

    const char *colon = strrchr(text, ':');
    if (colon == NULL || colon == text || colon[1] == '\0') {
        return -1;
    }

    size_t file_length = (size_t)(colon - text);
    if (file_length >= file_size) {
        return -1;
    }

    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(colon + 1, &end, 10);
    if (errno != 0 || end == colon + 1 || *end != '\0' ||
        value == 0 || value > UINT32_MAX) {
        return -1;
    }

    memcpy(file, text, file_length);
    file[file_length] = '\0';
    *line = (uint32_t)value;
    return 0;
}

static void print_source_address_lookup(
    const dwarf_line_table_t *table,
    const char *text)
{
    char file[MAX_SOURCE_PATH];
    uint32_t line = 0;

    if (parse_source_location(text, file, sizeof(file), &line) == -1) {
        printf("[minigdb] invalid source location: %s\n", text);
        printf("[minigdb] expected format: <file>:<line>, e.g. hello.c:11\n");
        return;
    }

    const dwarf_line_row_t *row = NULL;
    if (dwarf_line_lookup_source(table, file, line, &row) == -1) {
        printf("[minigdb] no executable DWARF row for %s:%u\n",
               file,
               line);
        return;
    }

    printf("\n===== Source Address =====\n");
    printf("Requested   : %s:%u\n", file, line);
    printf("Resolved    : %s:%u", row->file, row->line);
    if (row->column != 0) {
        printf(":%u", row->column);
    }
    printf("\n");
    printf("ELF address : 0x%016lx\n", (unsigned long)row->address);
    printf("is_stmt     : %s\n", row->is_stmt ? "yes" : "no");
    printf("==========================\n\n");
}

static int parse_runtime_address(const char *text, uintptr_t *address)
{
    const char *number = text;
    if (text[0] == '*') {
        ++number;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(number, &end, 0);

    if (errno != 0 || end == number || *end != '\0') {
        return -1;
    }

    *address = (uintptr_t)value;
    return 0;
}

static void print_help(void)
{
    printf("\nMiniGDB commands:\n");
    printf("  help, h                         Show this help message\n");
    printf("  break, b <symbol|address>       Set a software breakpoint\n");
    printf("                                  Examples: b main, b foo, b 0x401000\n");
    printf("  continue, c                     Continue until next stop/breakpoint\n");
    printf("  step, s                         Execute one original CPU instruction safely\n");
    printf("  regs, r                         Show x86-64 CPU registers\n");
    printf("  x <address|rip>                 Read one machine word from memory\n");
    printf("  info breakpoints, info b        List managed breakpoints\n");
    printf("  info target                     Show target ELF/runtime information\n");
    printf("  info lines                      Show decoded DWARF v4 line table\n");
    printf("  info source                     Map current RIP to source file:line\n");
    printf("  info address <file:line>        Map source file:line to ELF address\n");
    printf("  quit, q                         Kill the debuggee and exit MiniGDB\n");
    printf("\nChapter mapping:\n");
    printf("  regs              Chapter 3 - register inspection\n");
    printf("  x                 Chapter 4 - memory inspection\n");
    printf("  break             Chapter 5 - INT3 software breakpoint\n");
    printf("  step/info b       Chapter 6 - single-step + breakpoint manager\n");
    printf("  break <symbol>    Chapter 7 - ELF symbol resolution\n");
    printf("  info target       Chapter 8 - PIE/ASLR load-bias resolution\n");
    printf("  info lines        Chapter 9.1 - DWARF .debug_line decoding\n");
    printf("  info source       Chapter 9.2 - runtime RIP to source lookup\n");
    printf("  info address      Chapter 9.3 - source file:line to ELF lookup\n\n");
}

static int add_breakpoint_from_text(
    pid_t pid,
    breakpoint_manager_t *manager,
    const elf_image_t *image,
    uintptr_t load_bias,
    const char *text)
{
    uintptr_t runtime_address = 0;
    char display_name[MAX_SYMBOL_NAME];

    if (parse_runtime_address(text, &runtime_address) == 0) {
        snprintf(display_name, sizeof(display_name), "%s", text);
        printf("[minigdb] raw runtime address = 0x%lx\n",
               (unsigned long)runtime_address);
    } else {
        uintptr_t elf_value = 0;
        if (elf_find_function(image, text, &elf_value) == -1) {
            fprintf(stderr, "[minigdb] function symbol not found: %s\n", text);
            return -1;
        }

        runtime_address =
            elf_value_to_runtime_address(image, elf_value, load_bias);

        snprintf(display_name, sizeof(display_name), "%s", text);

        printf("[minigdb] resolved %-20s ELF=0x%lx runtime=0x%lx\n",
               text,
               (unsigned long)elf_value,
               (unsigned long)runtime_address);
    }

    breakpoint_t *existing =
        breakpoint_manager_find_by_address(manager, runtime_address);
    if (existing != NULL) {
        printf("[minigdb] breakpoint #%d already exists at 0x%lx (%s)\n",
               existing->id,
               (unsigned long)existing->address,
               existing->symbol);
        return 0;
    }

    breakpoint_t *bp =
        breakpoint_manager_add(manager, runtime_address, display_name);
    if (bp == NULL) {
        return -1;
    }

    if (print_memory_word(pid, bp->address) == -1) {
        return -1;
    }

    if (breakpoint_enable(pid, bp) == -1) {
        return -1;
    }

    return 0;
}

/*
 * Continue the stopped debuggee until something interesting happens.
 * A managed breakpoint is fully recovered before control returns to the REPL.
 * Therefore the prompt resumes immediately after the original breakpointed
 * instruction has executed once and INT3 has been reinstalled.
 *
 * Returns:
 *   1  debuggee is still alive and stopped
 *   0  debuggee exited/terminated
 *  -1  debugger error
 */
static int continue_until_stop(
    pid_t pid,
    breakpoint_manager_t *manager)
{
    if (continue_debuggee(pid) == -1) {
        return -1;
    }

    printf("[minigdb] child continued\n");

    for (;;) {
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if (WIFEXITED(status)) {
            printf("\n[minigdb] child exited with code %d\n",
                   WEXITSTATUS(status));
            return 0;
        }

        if (WIFSIGNALED(status)) {
            printf("\n[minigdb] child terminated by signal %d\n",
                   WTERMSIG(status));
            return 0;
        }

        if (!WIFSTOPPED(status)) {
            continue;
        }

        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        if (get_registers(pid, &regs) == -1) {
            return -1;
        }

        if (sig == SIGTRAP && regs.rip > 0) {
            uintptr_t candidate = (uintptr_t)(regs.rip - 1);
            breakpoint_t *bp =
                breakpoint_manager_find_by_address(manager, candidate);

            if (bp != NULL && bp->enabled) {
                ++bp->hit_count;

                printf("\n[minigdb] breakpoint #%d hit!\n", bp->id);
                printf("[minigdb] symbol = %s\n", bp->symbol);
                printf("[minigdb] address = 0x%lx\n",
                       (unsigned long)bp->address);
                printf("[minigdb] hit count = %lu\n", bp->hit_count);

                print_registers(&regs);

                if (recover_breakpoint(pid, bp) == -1) {
                    return -1;
                }

                return 1;
            }

            printf("\n[minigdb] SIGTRAP at RIP 0x%llx\n", regs.rip);
            return 1;
        }

        printf("\n[minigdb] child stopped by signal %d\n", sig);
        return 1;
    }
}

static int kill_debuggee(pid_t pid)
{
    if (ptrace(PTRACE_KILL, pid, NULL, NULL) == -1) {
        if (errno == ESRCH) {
            return 0;
        }
        perror("ptrace PTRACE_KILL");
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1 && errno != ECHILD) {
        perror("waitpid");
        return -1;
    }

    return 0;
}

static void trim_newline(char *line)
{
    size_t length = strlen(line);
    while (length > 0 &&
           (line[length - 1] == '\n' || line[length - 1] == '\r')) {
        line[--length] = '\0';
    }
}

int main(int argc, char *argv[])
{
    /*
     * New CLI shape:
     *
     *     ./minigdb ./hello
     *
     * The target executable is no longer hard-coded.  Breakpoints and the
     * execution-control operations are entered interactively in the REPL.
     */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        fprintf(stderr, "Example: %s ./hello\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *program_path = argv[1];

    elf_image_t image;
    if (elf_image_load(program_path, &image) == -1) {
        return EXIT_FAILURE;
    }

    dwarf_line_table_t line_table;
    if (dwarf_line_table_load(program_path, &line_table) == -1) {
        fprintf(stderr,
                "[minigdb] warning: source-line support disabled for this run\n");
        memset(&line_table, 0, sizeof(line_table));
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        dwarf_line_table_destroy(&line_table);
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace PTRACE_TRACEME");
            _exit(EXIT_FAILURE);
        }

        execl(program_path, program_path, NULL);
        perror("execl");
        _exit(EXIT_FAILURE);
    }

    printf("[minigdb] target = %s\n", program_path);
    printf("[minigdb] child pid = %d\n", pid);

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        dwarf_line_table_destroy(&line_table);
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[minigdb] child did not stop after exec\n");
        dwarf_line_table_destroy(&line_table);
        elf_image_destroy(&image);
        return EXIT_FAILURE;
    }

    printf("[minigdb] initial stop signal = %d\n", WSTOPSIG(status));

    uintptr_t load_bias;
    if (find_runtime_load_bias(pid, &image, &load_bias) == -1) {
        dwarf_line_table_destroy(&line_table);
        elf_image_destroy(&image);
        kill_debuggee(pid);
        return EXIT_FAILURE;
    }

    printf("[minigdb] runtime load bias = 0x%lx\n",
           (unsigned long)load_bias);

    breakpoint_manager_t manager;
    breakpoint_manager_init(&manager);

    printf("\n[minigdb] target loaded and stopped. Type 'help' for commands.\n");

    int child_alive = 1;
    char line[512];

    while (child_alive) {
        printf("(minigdb) ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\n");
            break;
        }

        trim_newline(line);

        char *saveptr = NULL;
        char *command = strtok_r(line, " \t", &saveptr);
        if (command == NULL) {
            continue;
        }

        if (strcmp(command, "help") == 0 || strcmp(command, "h") == 0) {
            print_help();
            continue;
        }

        if (strcmp(command, "break") == 0 || strcmp(command, "b") == 0) {
            char *argument = strtok_r(NULL, " \t", &saveptr);
            if (argument == NULL) {
                printf("usage: break <symbol|address>\n");
                continue;
            }

            if (add_breakpoint_from_text(pid,
                                         &manager,
                                         &image,
                                         load_bias,
                                         argument) == -1) {
                printf("[minigdb] failed to create breakpoint\n");
            }
            continue;
        }

        if (strcmp(command, "continue") == 0 || strcmp(command, "c") == 0) {
            int result = continue_until_stop(pid, &manager);
            if (result == -1) {
                child_alive = 0;
            } else if (result == 0) {
                child_alive = 0;
            }
            continue;
        }

        if (strcmp(command, "step") == 0 || strcmp(command, "s") == 0) {
            struct user_regs_struct after;
            if (step_debuggee(pid, &manager, &after) == -1) {
                child_alive = 0;
            }
            continue;
        }

        if (strcmp(command, "regs") == 0 || strcmp(command, "r") == 0) {
            struct user_regs_struct regs;
            if (get_registers(pid, &regs) == -1) {
                child_alive = 0;
            } else {
                print_registers(&regs);
            }
            continue;
        }

        if (strcmp(command, "x") == 0) {
            char *argument = strtok_r(NULL, " \t", &saveptr);
            if (argument == NULL) {
                printf("usage: x <address|rip>\n");
                continue;
            }

            uintptr_t address;
            if (strcmp(argument, "rip") == 0) {
                struct user_regs_struct regs;
                if (get_registers(pid, &regs) == -1) {
                    child_alive = 0;
                    continue;
                }
                address = (uintptr_t)regs.rip;
            } else if (parse_runtime_address(argument, &address) == -1) {
                printf("[minigdb] invalid address: %s\n", argument);
                continue;
            }

            print_memory_word(pid, address);
            continue;
        }

        if (strcmp(command, "info") == 0) {
            char *argument = strtok_r(NULL, " \t", &saveptr);
            if (argument == NULL) {
                printf("usage: info breakpoints | info target | info lines | info source | info address <file:line>\n");
                continue;
            }

            if (strcmp(argument, "breakpoints") == 0 ||
                strcmp(argument, "b") == 0) {
                breakpoint_manager_print(&manager);
                continue;
            }

            if (strcmp(argument, "target") == 0) {
                printf("\n===== Target =====\n");
                printf("Program   : %s\n", program_path);
                printf("PID       : %d\n", pid);
                printf("ELF type  : %s\n", elf_type_name(image.type));
                printf("Load bias : 0x%lx\n", (unsigned long)load_bias);
                printf("Symbols   : %zu\n", image.symbol_count);
                printf("PHDRs     : %zu\n", image.program_header_count);
                printf("DWARF rows: %zu\n", line_table.count);
                printf("==================\n\n");
                continue;
            }

            if (strcmp(argument, "lines") == 0) {
                if (line_table.count == 0) {
                    printf("[minigdb] no decoded DWARF line table is available\n");
                } else {
                    dwarf_line_table_print(&line_table);
                }
                continue;
            }

            if (strcmp(argument, "source") == 0) {
                if (line_table.count == 0) {
                    printf("[minigdb] no decoded DWARF line table is available\n");
                } else {
                    print_current_source_location(
                        pid, &image, &line_table, load_bias);
                }
                continue;
            }

            if (strcmp(argument, "address") == 0) {
                char *location = strtok_r(NULL, " \t", &saveptr);
                if (location == NULL) {
                    printf("usage: info address <file:line>\n");
                } else if (line_table.count == 0) {
                    printf("[minigdb] no decoded DWARF line table is available\n");
                } else {
                    print_source_address_lookup(&line_table, location);
                }
                continue;
            }

            printf("[minigdb] unknown info topic: %s\n", argument);
            continue;
        }

        if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0) {
            break;
        }

        printf("[minigdb] unknown command: %s\n", command);
        printf("[minigdb] type 'help' to list commands\n");
    }

    if (child_alive) {
        kill_debuggee(pid);
    }

    printf("\n[minigdb] final breakpoint statistics:\n");
    breakpoint_manager_print(&manager);

    dwarf_line_table_destroy(&line_table);
    elf_image_destroy(&image);
    return EXIT_SUCCESS;
}
