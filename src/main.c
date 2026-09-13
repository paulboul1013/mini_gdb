#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

int main(void)
{
    pid_t pid = fork();

    if (pid<0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        execl("./hello", "./hello", NULL);
        perror("execl");
        _exit(EXIT_FAILURE);
    } 
        
    printf("parent: child pid = %d\n", pid);
    

    return EXIT_SUCCESS;
}