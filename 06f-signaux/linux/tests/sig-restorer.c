/* Un gestionnaire posé par l'appel brut, sans SA_RESTORER (sans l'adresse
 * de retour que donne la glibc) : sur x86_64, le noyau refuse de poser le
 * cadre (`x64_setup_rt_frame`), et force SIGSEGV, qui tue (code 139), sous
 * Linux comme chez nous. */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static void gestionnaire(int sig)
{
    (void)sig;
}

int main(void)
{
    puts("[linux] Test : un gestionnaire sans SA_RESTORER, puis raise(SIGUSR1).");
    fflush(stdout);
    uint64_t action[4] = { (uint64_t)gestionnaire, 0, 0, 0 };
    syscall(SYS_rt_sigaction, SIGUSR1, action, NULL, 8);
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    puts("[linux] sig-restorer : ECHEC, toujours la");
    return 1;
}
