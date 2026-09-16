#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>


typedef struct {
    uintptr_t address;
    unsigned char saved_byte;
    int enabled;
} breakpoint_t;


/*
 * 取得 CPU registers。
 */
static int get_registers(
    pid_t pid,
    struct user_regs_struct *regs
)
{
    if (ptrace(
            PTRACE_GETREGS,
            pid,
            NULL,
            regs
        ) == -1) {

        perror("ptrace PTRACE_GETREGS");
        return -1;
    }

    return 0;
}


/*
 * 修改 CPU registers。
 */
static int set_registers(
    pid_t pid,
    const struct user_regs_struct *regs
)
{
    if (ptrace(
            PTRACE_SETREGS,
            pid,
            NULL,
            regs
        ) == -1) {

        perror("ptrace PTRACE_SETREGS");
        return -1;
    }

    return 0;
}


/*
 * 顯示 CPU registers。
 */
static void print_registers(
    const struct user_regs_struct *regs
)
{
    printf("\n");
    printf("===== CPU Registers =====\n");

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

    printf("\n");

    printf("RIP = 0x%016llx\n", regs->rip);
    printf("RFLAGS = 0x%016llx\n", regs->eflags);

    printf("=========================\n\n");
}


/*
 * 讀取 debuggee memory。
 */
static int read_memory_word(
    pid_t pid,
    uintptr_t address,
    unsigned long *word
)
{
    errno = 0;

    long data = ptrace(
        PTRACE_PEEKDATA,
        pid,
        (void *)address,
        NULL
    );

    if (data == -1 && errno != 0) {

        perror("ptrace PTRACE_PEEKDATA");
        return -1;
    }

    *word = (unsigned long)data;

    return 0;
}


/*
 * Chapter 5：
 *
 * 寫入 debuggee memory。
 */
static int write_memory_word(
    pid_t pid,
    uintptr_t address,
    unsigned long word
)
{
    if (ptrace(
            PTRACE_POKEDATA,
            pid,
            (void *)address,
            (void *)(uintptr_t)word
        ) == -1) {

        perror("ptrace PTRACE_POKEDATA");
        return -1;
    }

    return 0;
}


/*
 * 顯示某 address 的 machine word。
 */
static int print_memory_word(
    pid_t pid,
    uintptr_t address
)
{
    unsigned long word;

    if (read_memory_word(
            pid,
            address,
            &word
        ) == -1) {

        return -1;
    }

    printf(
        "Memory @ 0x%lx: ",
        (unsigned long)address
    );

    for (size_t i = 0; i < sizeof(word); i++) {

        unsigned int byte =
            (unsigned int)(
                (word >> (i * 8)) & 0xff
            );

        printf("%02x ", byte);
    }

    printf("\n");

    return 0;
}


/*
 * 插入 INT3 breakpoint。
 */
static int breakpoint_enable(
    pid_t pid,
    breakpoint_t *bp
)
{
    if (bp->enabled) {
        return 0;
    }

    unsigned long word;

    if (read_memory_word(
            pid,
            bp->address,
            &word
        ) == -1) {

        return -1;
    }

    /*
     * 保存原始第一個 byte。
     */
    bp->saved_byte =
        (unsigned char)(word & 0xff);

    /*
     * lowest byte:
     *
     * original -> CC
     */
    unsigned long patched =
        (word & ~0xffUL) | 0xccUL;

    if (write_memory_word(
            pid,
            bp->address,
            patched
        ) == -1) {

        return -1;
    }

    bp->enabled = 1;

    printf(
        "[minigdb] breakpoint enabled at 0x%lx\n",
        (unsigned long)bp->address
    );

    printf(
        "[minigdb] saved original byte: 0x%02x\n",
        bp->saved_byte
    );

    return 0;
}


/*
 * 恢復 breakpoint 原本 instruction byte。
 */
static int breakpoint_disable(
    pid_t pid,
    breakpoint_t *bp
)
{
    if (!bp->enabled) {
        return 0;
    }

    unsigned long word;

    if (read_memory_word(
            pid,
            bp->address,
            &word
        ) == -1) {

        return -1;
    }

    unsigned long restored =
        (word & ~0xffUL)
        | (unsigned long)bp->saved_byte;

    if (write_memory_word(
            pid,
            bp->address,
            restored
        ) == -1) {

        return -1;
    }

    bp->enabled = 0;

    return 0;
}


/*
 * Breakpoint hit 後：
 *
 * 1. RIP -= 1
 * 2. restore original byte
 * 3. single-step original instruction
 * 4. reinstall breakpoint
 */
static int recover_breakpoint(
    pid_t pid,
    breakpoint_t *bp
)
{
    struct user_regs_struct regs;

    if (get_registers(
            pid,
            &regs
        ) == -1) {

        return -1;
    }

    printf(
        "[minigdb] RIP after INT3 = 0x%llx\n",
        regs.rip
    );

    /*
     * INT3 是 1 byte，
     * CPU 已經把 RIP 往前移了一格。
     */
    regs.rip -= 1;

    printf(
        "[minigdb] rewinding RIP to 0x%llx\n",
        regs.rip
    );

    if (set_registers(
            pid,
            &regs
        ) == -1) {

        return -1;
    }

    /*
     * CC → original instruction byte
     */
    if (breakpoint_disable(
            pid,
            bp
        ) == -1) {

        return -1;
    }

    printf(
        "[minigdb] original instruction restored\n"
    );

    /*
     * 只執行原本的那一條 instruction。
     */
    if (ptrace(
            PTRACE_SINGLESTEP,
            pid,
            NULL,
            NULL
        ) == -1) {

        perror("ptrace PTRACE_SINGLESTEP");
        return -1;
    }

    int status;

    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return -1;
    }

    /*
     * 正常情況：
     *
     * single-step 完成 → SIGTRAP
     */
    if (!WIFSTOPPED(status)) {

        fprintf(
            stderr,
            "[minigdb] debuggee did not stop after single-step\n"
        );

        return -1;
    }

    printf(
        "[minigdb] original instruction executed once\n"
    );

    /*
     * 再次：
     *
     * original byte → CC
     */
    if (breakpoint_enable(
            pid,
            bp
        ) == -1) {

        return -1;
    }

    printf(
        "[minigdb] breakpoint reinstalled\n"
    );

    return 0;
}


int main(
    int argc,
    char *argv[]
)
{
    /*
     * Chapter 5 暫時使用 raw address。
     *
     * Example:
     *
     * ./minigdb 0x401126
     */
    if (argc != 2) {

        fprintf(
            stderr,
            "Usage: %s <breakpoint-address>\n",
            argv[0]
        );

        return EXIT_FAILURE;
    }


    /*
     * 把：
     *
     * "0x401126"
     *
     * 轉成 integer address。
     */
    errno = 0;

    char *end = NULL;

    unsigned long long parsed_address =
        strtoull(
            argv[1],
            &end,
            0
        );

    if (errno != 0 ||
        end == argv[1] ||
        *end != '\0') {

        fprintf(
            stderr,
            "Invalid breakpoint address: %s\n",
            argv[1]
        );

        return EXIT_FAILURE;
    }


    breakpoint_t breakpoint = {
        .address = (uintptr_t)parsed_address,
        .saved_byte = 0,
        .enabled = 0
    };


    pid_t pid = fork();

    if (pid < 0) {

        perror("fork");
        return EXIT_FAILURE;
    }


    /*
     * Child = debuggee
     */
    if (pid == 0) {

        if (ptrace(
                PTRACE_TRACEME,
                0,
                NULL,
                NULL
            ) == -1) {

            perror("ptrace PTRACE_TRACEME");
            _exit(EXIT_FAILURE);
        }

        execl(
            "./hello",
            "./hello",
            NULL
        );

        perror("execl");
        _exit(EXIT_FAILURE);
    }


    /*
     * Parent = debugger
     */
    printf(
        "[minigdb] child pid = %d\n",
        pid
    );

    int status;


    /*
     * 等 initial exec SIGTRAP。
     */
    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return EXIT_FAILURE;
    }


    if (!WIFSTOPPED(status)) {

        fprintf(
            stderr,
            "[minigdb] child did not stop after exec\n"
        );

        return EXIT_FAILURE;
    }


    printf(
        "[minigdb] initial stop signal = %d\n",
        WSTOPSIG(status)
    );


    /*
     * 設定 breakpoint 前先看看原始 bytes。
     */
    printf("\nBefore breakpoint:\n");

    if (print_memory_word(
            pid,
            breakpoint.address
        ) == -1) {

        return EXIT_FAILURE;
    }


    /*
     * original byte → CC
     */
    if (breakpoint_enable(
            pid,
            &breakpoint
        ) == -1) {

        return EXIT_FAILURE;
    }


    printf("\nAfter breakpoint:\n");

    if (print_memory_word(
            pid,
            breakpoint.address
        ) == -1) {

        return EXIT_FAILURE;
    }


    /*
     * 讓 debuggee 跑到 breakpoint。
     */
    if (ptrace(
            PTRACE_CONT,
            pid,
            NULL,
            NULL
        ) == -1) {

        perror("ptrace PTRACE_CONT");
        return EXIT_FAILURE;
    }


    printf(
        "\n[minigdb] child continued\n"
    );


    /*
     * 等待 breakpoint SIGTRAP。
     */
    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return EXIT_FAILURE;
    }


    if (!WIFSTOPPED(status)) {

        fprintf(
            stderr,
            "[minigdb] child did not stop at breakpoint\n"
        );

        return EXIT_FAILURE;
    }


    struct user_regs_struct regs;

    if (get_registers(
            pid,
            &regs
        ) == -1) {

        return EXIT_FAILURE;
    }


    /*
     * 判斷是不是我們的 breakpoint。
     *
     * INT3 後：
     *
     * RIP = breakpoint + 1
     */
    if (WSTOPSIG(status) == SIGTRAP &&
        regs.rip - 1 == breakpoint.address) {

        printf(
            "\n[minigdb] breakpoint hit!\n"
        );

        printf(
            "[minigdb] breakpoint address = 0x%lx\n",
            (unsigned long)breakpoint.address
        );

        print_registers(&regs);


        /*
         * Breakpoint recovery。
         */
        if (recover_breakpoint(
                pid,
                &breakpoint
            ) == -1) {

            return EXIT_FAILURE;
        }
    }

    else {

        fprintf(
            stderr,
            "[minigdb] unexpected stop\n"
        );

        return EXIT_FAILURE;
    }


    /*
     * Recovery 完成，
     * 讓程式繼續執行。
     */
    if (ptrace(
            PTRACE_CONT,
            pid,
            NULL,
            NULL
        ) == -1) {

        perror("ptrace PTRACE_CONT");
        return EXIT_FAILURE;
    }


    /*
     * hello 正常情況會 exit。
     */
    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return EXIT_FAILURE;
    }


    if (WIFEXITED(status)) {

        printf(
            "\n[minigdb] child exited with code %d\n",
            WEXITSTATUS(status)
        );
    }

    else if (WIFSIGNALED(status)) {

        printf(
            "\n[minigdb] child terminated by signal %d\n",
            WTERMSIG(status)
        );
    }

    else if (WIFSTOPPED(status)) {

        printf(
            "\n[minigdb] child stopped again by signal %d\n",
            WSTOPSIG(status)
        );
    }


    return EXIT_SUCCESS;
}