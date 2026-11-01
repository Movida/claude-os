/* Changer son nom (PR_SET_NAME), puis faire une faute : le message du
 * noyau porte le nouveau nom, comme le journal de Linux, qui affiche le
 * `comm` du processus. */
#include <stdio.h>
#include <sys/prctl.h>

int main(void)
{
    puts("[linux] Test : PR_SET_NAME, puis une faute.");
    fflush(stdout);
    prctl(PR_SET_NAME, "nouveau-nom");
    *(volatile int *)0 = 1;
    return 1;
}
