/* Le gestionnaire met dans son contexte un MXCSR que le processeur refuse
 * (le bit 31, réservé) : rt_sigreturn ne peut pas le rétablir, et le
 * programme meurt de SIGSEGV (code 139), sous Linux comme chez nous, avec
 * ou sans XSAVE (Linux, en 64 bits, refuse ce MXCSR dans les deux cas). */
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
    *(uint32_t *)((char *)uc->uc_mcontext.fpregs + 24) = 0x80001f80u;
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = gestionnaire;
    a.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire qui rend un MXCSR refuse par le processeur.");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-mxcsr : ECHEC, toujours la");
    return 1;
}
