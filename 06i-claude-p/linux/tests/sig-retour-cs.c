/* Le gestionnaire met dans son contexte CS = 0x2B, un segment de données :
 * iretq le refuse (faute de protection générale dans le noyau, sur iretq) ;
 * le noyau en fait une faute du programme (le « bad iret » de Linux) :
 * SIGSEGV, code 139, sous Linux comme chez nous. (CS = 0x23 ferait passer
 * Linux en mode 32 bits ; chez nous, ce sélecteur est nul : SIGSEGV aussi.) */
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
    uint16_t *s = (uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS]; s[0] = 0x2b;
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = gestionnaire;
    a.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire qui rend CS = 0x2B (un segment de donnees).");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-retour-cs : ECHEC, toujours la");
    return 1;
}
