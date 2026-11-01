/* Le gestionnaire met dans son contexte un RIP non canonique : sur un vrai
 * processeur, iretq le refuse (le « bad iret » : SIGSEGV) ; QEMU sans
 * accélération ne le vérifie pas, et c'est le chargement de l'instruction,
 * dans le programme, qui fait la faute : SIGSEGV aussi. Code 139, sous Linux
 * comme chez nous. */
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
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)0x8000000000000000ull;
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = gestionnaire;
    a.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire qui rend un RIP non canonique.");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-retour-rip : ECHEC, toujours la");
    return 1;
}
