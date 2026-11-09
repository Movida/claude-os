/* Le gestionnaire de SIGSEGV fait lui-même une faute : SIGSEGV y est bloqué
 * (sans SA_NODEFER), le noyau ne peut pas le livrer, et la faute tue le
 * programme (`force_sig_info_to_task` : un signal de faute bloqué remet
 * l'action par défaut), code 139, sous Linux comme chez nous. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile int *nul;

static void gestionnaire(int sig)
{
    (void)sig;
    static const char m[] = "[linux] sig-refaute : dans le gestionnaire, une seconde faute\n";
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
    *nul = 2;
    _exit(1);
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = gestionnaire;
    sigaction(SIGSEGV, &a, NULL);
    puts("[linux] Test : une faute dans le gestionnaire de la meme faute.");
    fflush(stdout);
    *nul = 1;
    return 1;
}
