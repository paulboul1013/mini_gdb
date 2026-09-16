#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>

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
 * Chapter 7: minimal ELF64 symbol-table loader.
 *
 * This chapter deliberately supports non-PIE x86-64 executables only.
 * For ET_EXEC, st_value from .symtab is the runtime virtual address used
 * by the breakpoint engine. PIE/ASLR relocation is intentionally deferred
 * to a later chapter.
 */
typedef struct {
    Elf64_Sym *symbols;
    size_t symbol_count;
    char *strtab;
    size_t strtab_size;
} elf_symbol_table_t;

static void elf_symbol_table_destroy(elf_symbol_table_t *table)
{
    free(table->symbols);
    free(table->strtab);
    table->symbols = NULL;
    table->strtab = NULL;
    table->symbol_count = 0;
    table->strtab_size = 0;
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

static int elf_symbol_table_load(
    const char *path,
    elf_symbol_table_t *table)
{
    memset(table, 0, sizeof(*table));

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
        fprintf(stderr, "[minigdb] only ELF64 is supported in Chapter 7\n");
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

    if (ehdr.e_type != ET_EXEC) {
        fprintf(stderr,
                "[minigdb] Chapter 7 expects a non-PIE ET_EXEC executable.\n"
                "[minigdb] rebuild hello with -fno-pie -no-pie.\n");
        fclose(fp);
        return -1;
    }

    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
        fprintf(stderr, "[minigdb] unsupported or missing ELF section table\n");
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
        free(sections);
        fclose(fp);
        return -1;
    }

    if (symtab_section->sh_link >= ehdr.e_shnum) {
        fprintf(stderr, "[minigdb] invalid symbol string-table link\n");
        free(sections);
        fclose(fp);
        return -1;
    }

    const Elf64_Shdr *strtab_section =
        &sections[symtab_section->sh_link];

    if (strtab_section->sh_type != SHT_STRTAB) {
        fprintf(stderr, "[minigdb] symbol table does not link to a string table\n");
        free(sections);
        fclose(fp);
        return -1;
    }

    if (symtab_section->sh_entsize != sizeof(Elf64_Sym) ||
        symtab_section->sh_size % sizeof(Elf64_Sym) != 0) {
        fprintf(stderr, "[minigdb] unsupported ELF64 symbol-table layout\n");
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
        free(sections);
        fclose(fp);
        return -1;
    }

    size_t strtab_size = (size_t)strtab_section->sh_size;
    char *strtab = malloc(strtab_size + 1);
    if (strtab == NULL) {
        perror("malloc string table");
        free(symbols);
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
        free(sections);
        fclose(fp);
        return -1;
    }

    strtab[strtab_size] = '\0';

    table->symbols = symbols;
    table->symbol_count = symbol_count;
    table->strtab = strtab;
    table->strtab_size = strtab_size;

    free(sections);
    fclose(fp);

    printf("[minigdb] loaded ELF64 symbol table from %s (%zu symbols)\n",
           path,
           table->symbol_count);

    return 0;
}

static int elf_find_function(
    const elf_symbol_table_t *table,
    const char *symbol_name,
    uintptr_t *address)
{
    for (size_t i = 0; i < table->symbol_count; ++i) {
        const Elf64_Sym *sym = &table->symbols[i];

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
            continue;
        }

        if (sym->st_shndx == SHN_UNDEF) {
            continue;
        }

        if ((size_t)sym->st_name >= table->strtab_size) {
            continue;
        }

        const char *name = table->strtab + sym->st_name;
        if (strcmp(name, symbol_name) == 0) {
            *address = (uintptr_t)sym->st_value;
            return 0;
        }
    }

    return -1;
}

int main(int argc, char *argv[])
{
    /*
     * Chapter 7 accepts function symbol names instead of raw addresses:
     *
     *   ./minigdb foo main
     */
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <function-symbol> [function-symbol ...]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    elf_symbol_table_t elf_symbols;
    if (elf_symbol_table_load(PROGRAM_PATH, &elf_symbols) == -1) {
        return EXIT_FAILURE;
    }

    breakpoint_manager_t manager;
    breakpoint_manager_init(&manager);

    printf("\n[minigdb] resolving function symbols:\n");

    for (int i = 1; i < argc; ++i) {
        uintptr_t address;
        if (elf_find_function(&elf_symbols, argv[i], &address) == -1) {
            fprintf(stderr,
                    "[minigdb] function symbol not found: %s\n",
                    argv[i]);
            elf_symbol_table_destroy(&elf_symbols);
            return EXIT_FAILURE;
        }

        printf("[minigdb]   %-20s -> 0x%lx\n",
               argv[i],
               (unsigned long)address);

        breakpoint_t *bp =
            breakpoint_manager_add(&manager, address, argv[i]);
        if (bp == NULL) {
            elf_symbol_table_destroy(&elf_symbols);
            return EXIT_FAILURE;
        }
    }

    elf_symbol_table_destroy(&elf_symbols);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
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
        return EXIT_FAILURE;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[minigdb] child did not stop after exec\n");
        return EXIT_FAILURE;
    }

    printf("[minigdb] initial stop signal = %d\n", WSTOPSIG(status));

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
     * Chapter 6/7 event loop:
     * wait for breakpoint hits until the debuggee exits.
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

        /*
         * For non-SIGTRAP stops, report the signal and deliver it to the
         * debuggee when continuing.  This lets a real crash remain a crash.
         */
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
