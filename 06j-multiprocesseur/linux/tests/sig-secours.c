/* Une pile de secours de 2048 octets (MINSIGSTKSZ) : le cadre de SIGUSR1 y
 * tient, mais celui de SIGUSR2, envoyé depuis le gestionnaire de SIGUSR1
 * et lui aussi en SA_ONSTACK, n'y tient plus. Le noyau ne déborde pas de
 * la pile de secours (« overflowed sigaltstack ») : SIGSEGV, qui tue
 * (code 139), sous Linux comme chez nous. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char pile[2048] __attribute__((aligned(16)));

static void second(int sig)
{
    static const char m[] = "[linux] sig-secours : ECHEC, le second gestionnaire a tourne\n";
    (void)sig;
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
}

static void premier(int sig)
{
    static const char m[] = "[linux] sig-secours : premier gestionnaire, sur la pile de secours\n";
    (void)sig;
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
    raise(SIGUSR2);
}

int main(void)
{
    stack_t s = { .ss_sp = pile, .ss_flags = 0, .ss_size = sizeof pile };
    sigaltstack(&s, NULL);
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_flags = SA_ONSTACK;
    a.sa_handler = premier;
    sigaction(SIGUSR1, &a, NULL);
    a.sa_handler = second;
    sigaction(SIGUSR2, &a, NULL);
    puts("[linux] Test : une pile de secours de 2048 octets, deux cadres l'un sur l'autre.");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-secours : ECHEC, toujours la");
    return 1;
}
