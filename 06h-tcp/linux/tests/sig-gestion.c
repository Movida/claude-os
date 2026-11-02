/* Un gestionnaire de SIGUSR1, puis raise(SIGUSR1) : le gestionnaire est
 * appelé, puis le programme continue après raise, et sort avec 0, sous
 * Linux comme chez nous (depuis 6f ; avant, notre noyau l'arrêtait,
 * code 138). */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void gestionnaire(int sig)
{
    (void)sig;
    static const char m[] = "[linux] sig-gestion : gestionnaire appele\n";
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = gestionnaire;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire de SIGUSR1, puis raise(SIGUSR1).");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-gestion : apres le gestionnaire");
    return 0;
}
