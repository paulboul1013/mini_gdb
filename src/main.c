#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>


/*
 * 從 stopped debuggee 取得 CPU registers。
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
 * 顯示 CPU registers。
 */
static void print_registers(
    const struct user_regs_struct *regs
)
{
    printf("\n");
    printf("===== CPU Registers =====\n");

    /*
     * General-purpose registers
     */
    printf("RAX = 0x%016llx\n", regs->rax);
    printf("RBX = 0x%016llx\n", regs->rbx);
    printf("RCX = 0x%016llx\n", regs->rcx);
    printf("RDX = 0x%016llx\n", regs->rdx);

    printf("RSI = 0x%016llx\n", regs->rsi);
    printf("RDI = 0x%016llx\n", regs->rdi);

    /*
     * Stack related registers
     */
    printf("RBP = 0x%016llx\n", regs->rbp);
    printf("RSP = 0x%016llx\n", regs->rsp);

    /*
     * x86-64 additional general-purpose registers
     */
    printf("R8  = 0x%016llx\n", regs->r8);
    printf("R9  = 0x%016llx\n", regs->r9);
    printf("R10 = 0x%016llx\n", regs->r10);
    printf("R11 = 0x%016llx\n", regs->r11);
    printf("R12 = 0x%016llx\n", regs->r12);
    printf("R13 = 0x%016llx\n", regs->r13);
    printf("R14 = 0x%016llx\n", regs->r14);
    printf("R15 = 0x%016llx\n", regs->r15);

    printf("\n");

    /*
     * RIP = instruction pointer
     */
    printf("RIP = 0x%016llx\n", regs->rip);

    /*
     * CPU status flags
     */
    printf("EFLAGS = 0x%016llx\n", regs->eflags);

    printf("=========================\n\n");
}


/*
 * Chapter 4：
 *
 * 從 debuggee 的 virtual memory
 * 讀取一個 machine word。
 *
 * x86-64 Linux 上 long 通常為 8 bytes。
 */
static int read_memory_word(
    pid_t pid,
    unsigned long long address,
    unsigned long *word
)
{
    /*
     * PTRACE_PEEKDATA 有一個特殊點：
     *
     * return -1 不一定代表 error，
     * 因為 -1 本身也可能是合法 memory data。
     *
     * 所以必須先 errno = 0。
     */
    errno = 0;

    long data = ptrace(
        PTRACE_PEEKDATA,
        pid,
        (void *)(uintptr_t)address,
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
 * 讀取 RIP 指向的 memory。
 *
 * RIP 是目前 CPU instruction pointer，
 * 所以這裡通常會讀到 machine-code bytes。
 */
static int print_memory_at_rip(
    pid_t pid,
    const struct user_regs_struct *regs
)
{
    unsigned long word;

    if (read_memory_word(
            pid,
            regs->rip,
            &word
        ) == -1) {

        return -1;
    }

    printf("===== Memory at RIP =====\n");

    printf(
        "Address = 0x%016llx\n",
        regs->rip
    );

    /*
     * 把整個 8-byte word 當成整數顯示。
     */
    printf(
        "Raw     = 0x%016lx\n",
        word
    );

    /*
     * 按照 memory address 順序顯示 byte。
     *
     * x86-64 是 little-endian。
     */
    printf("Bytes   = ");

    for (size_t i = 0; i < sizeof(word); i++) {

        unsigned int byte =
            (unsigned int)(
                (word >> (i * 8)) & 0xff
            );

        printf(
            "%02x ",
            byte
        );
    }

    printf("\n");
    printf("=========================\n\n");

    return 0;
}


/*
 * 統一檢查目前 stopped process。
 *
 * Chapter 3：
 *     registers
 *
 * Chapter 4：
 *     memory at RIP
 */
static int inspect_process(pid_t pid)
{
    struct user_regs_struct regs;

    /*
     * 先取得 CPU snapshot。
     */
    if (get_registers(
            pid,
            &regs
        ) == -1) {

        return -1;
    }

    /*
     * Chapter 3
     */
    print_registers(&regs);

    /*
     * Chapter 4
     */
    if (print_memory_at_rip(
            pid,
            &regs
        ) == -1) {

        return -1;
    }

    return 0;
}


int main(void)
{
    /*
     * fork() 之後：
     *
     * parent -> debugger
     * child  -> debuggee
     */
    pid_t pid = fork();

    if (pid < 0) {

        perror("fork");
        return EXIT_FAILURE;
    }


    /*
     * Child = debuggee
     */
    if (pid == 0) {

        /*
         * 告訴 kernel：
         *
         * parent 可以 trace 我。
         */
        if (ptrace(
                PTRACE_TRACEME,
                0,
                NULL,
                NULL
            ) == -1) {

            perror("ptrace PTRACE_TRACEME");
            _exit(EXIT_FAILURE);
        }

        /*
         * 用 ./hello 取代 child。
         */
        execl(
            "./hello",
            "./hello",
            NULL
        );

        /*
         * exec 成功不會回到這裡。
         */
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
     * 等待 exec 後的 initial stop。
     */
    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return EXIT_FAILURE;
    }


    /*
     * Debuggee 現在 STOPPED。
     */
    if (WIFSTOPPED(status)) {

        printf(
            "[minigdb] child stopped by signal %d\n",
            WSTOPSIG(status)
        );

        /*
         * Chapter 3 + Chapter 4
         *
         * Registers
         * +
         * Memory
         */
        if (inspect_process(pid) == -1) {

            return EXIT_FAILURE;
        }
    }


    /*
     * 讓 child 繼續執行。
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
        "[minigdb] child continued\n"
    );


    /*
     * 等待下一次 process event。
     */
    if (waitpid(
            pid,
            &status,
            0
        ) == -1) {

        perror("waitpid");
        return EXIT_FAILURE;
    }


    /*
     * 正常退出。
     */
    if (WIFEXITED(status)) {

        printf(
            "[minigdb] child exited with code %d\n",
            WEXITSTATUS(status)
        );
    }


    /*
     * 被 signal 終止。
     */
    else if (WIFSIGNALED(status)) {

        printf(
            "[minigdb] child terminated by signal %d\n",
            WTERMSIG(status)
        );
    }


    /*
     * 再次停止。
     */
    else if (WIFSTOPPED(status)) {

        printf(
            "[minigdb] child stopped again by signal %d\n",
            WSTOPSIG(status)
        );

        /*
         * 再次查看：
         *
         * CPU registers
         * +
         * RIP memory
         */
        if (inspect_process(pid) == -1) {

            return EXIT_FAILURE;
        }
    }


    return EXIT_SUCCESS;
}