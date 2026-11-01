/* Le gestionnaire met dans son contexte SS = 0x33, un segment de code, avec
 * UC_STRICT_RESTORE_SS (posé par le noyau) : rt_sigreturn le rend tel quel,
 * iretq le refuse ; le noyau en fait une faute du programme (le « bad
 * iret ») : SIGSEGV, code 139, sous Linux comme chez nous. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>

static void gestionnaire(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    uint16_t *s = (uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS]; s[3] = 0x33;
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = gestionnaire;
    a.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire qui rend SS = 0x33 (un segment de code).");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-retour-ss : ECHEC, toujours la");
    return 1;
}
