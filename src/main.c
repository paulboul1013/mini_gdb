#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>


static int print_registers(pid_t pid)
{
    struct user_regs_struct regs;

    /*
     * 從 stopped debuggee 取得目前 CPU registers。
     */
    if (ptrace(
            PTRACE_GETREGS,
            pid,
            NULL,
            &regs
        ) == -1) {

        perror("ptrace PTRACE_GETREGS");
        return -1;
    }

    printf("\n");
    printf("===== CPU Registers =====\n");

    /*
     * General-purpose registers
     */
    printf("RAX = 0x%016llx\n", regs.rax);
    printf("RBX = 0x%016llx\n", regs.rbx);
    printf("RCX = 0x%016llx\n", regs.rcx);
    printf("RDX = 0x%016llx\n", regs.rdx);

    printf("RSI = 0x%016llx\n", regs.rsi);
    printf("RDI = 0x%016llx\n", regs.rdi);

    /*
     * Stack related registers
     */
    printf("RBP = 0x%016llx\n", regs.rbp);
    printf("RSP = 0x%016llx\n", regs.rsp);

    /*
     * x86-64 additional general-purpose registers
     */
    printf("R8  = 0x%016llx\n", regs.r8);
    printf("R9  = 0x%016llx\n", regs.r9);
    printf("R10 = 0x%016llx\n", regs.r10);
    printf("R11 = 0x%016llx\n", regs.r11);
    printf("R12 = 0x%016llx\n", regs.r12);
    printf("R13 = 0x%016llx\n", regs.r13);
    printf("R14 = 0x%016llx\n", regs.r14);
    printf("R15 = 0x%016llx\n", regs.r15);

    printf("\n");

    /*
     * 最重要的 register：
     *
     * RIP = instruction pointer
     *
     * 也就是 CPU 接下來準備執行的位置。
     */
    printf("RIP = 0x%016llx\n", regs.rip);

    /*
     * CPU status flags
     */
    printf("EFLAGS = 0x%016llx\n", regs.eflags);

    printf("=========================\n\n");

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
     * Child
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
         * 用 ./hello 取代目前 child。
         */
        execl(
            "./hello",
            "./hello",
            NULL
        );

        /*
         * exec 成功後不會跑到這裡。
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
     * 等待 child exec 後因 SIGTRAP 停住。
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
     * Debuggee 現在是 STOPPED。
     */
    if (WIFSTOPPED(status)) {

        printf(
            "[minigdb] child stopped by signal %d\n",
            WSTOPSIG(status)
        );

        /*
         * Chapter 3：
         *
         * 讀取 CPU registers。
         */
        if (print_registers(pid) == -1) {
            return EXIT_FAILURE;
        }
    }

    /*
     * 讓 child 繼續。
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
     * 等待下一次狀態改變。
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
     * 又被某個 signal 暫停。
     */
    else if (WIFSTOPPED(status)) {

        printf(
            "[minigdb] child stopped again by signal %d\n",
            WSTOPSIG(status)
        );

        /*
         * 如果再次 STOPPED，
         * 也把 registers 印出來。
         */
        if (print_registers(pid) == -1) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}