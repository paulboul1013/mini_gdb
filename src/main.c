#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>

int main(void)
{
    /*
     * fork() 之後會有兩個 process：
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
         * 「讓我的 parent trace 我。」
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace PTRACE_TRACEME");
            _exit(EXIT_FAILURE);
        }

        /*
         * 用 ./hello 取代目前 child process。
         */
        execl("./hello", "./hello", NULL);

        /*
         * 如果 exec 成功，不可能跑到這裡。
         */
        perror("execl");
        _exit(EXIT_FAILURE);
    }

    /*
     * Parent = debugger
     */

    printf("[minigdb] child pid = %d\n", pid);

    int status;

    /*
     * 等待 child 在 exec 後停止。
     */
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return EXIT_FAILURE;
    }

    if (WIFSTOPPED(status)) {
        printf(
            "[minigdb] child stopped by signal %d\n",
            WSTOPSIG(status)
        );
    }

    /*
     * 要求 child 繼續執行。
     */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_CONT");
        return EXIT_FAILURE;
    }

    printf("[minigdb] child continued\n");

    /*
     * 等待 child 下一次狀態改變。
     *
     * hello 很簡單，所以正常情況就是退出。
     */
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return EXIT_FAILURE;
    }

    /*
     * 正常 exit
     */
    if (WIFEXITED(status)) {
        printf(
            "[minigdb] child exited with code %d\n",
            WEXITSTATUS(status)
        );
    }

    /*
     * 被 signal 終止
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
    }

    return EXIT_SUCCESS;
}