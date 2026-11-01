/* Le programme met dans RSP une adresse où rien n'est projeté, puis
 * s'envoie SIGUSR1, qui a un gestionnaire, comme SIGSEGV : le noyau ne peut
 * pas écrire le cadre de SIGUSR1, et force SIGSEGV ; il ne peut pas écrire
 * celui de SIGSEGV non plus, qui tue donc (`force_sigsegv` : code 139),
 * sous Linux comme chez nous, sans qu'aucun gestionnaire n'ait tourné. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void gestionnaire(int sig)
{
    static const char m[] = "[linux] sig-pile-perdue : ECHEC, un gestionnaire a tourne\n";
    (void)sig;
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = gestionnaire;
    sigaction(SIGUSR1, &a, NULL);
    sigaction(SIGSEGV, &a, NULL);
    puts("[linux] Test : RSP a 0x10000 (rien n'y est projete), puis tgkill(SIGUSR1).");
    fflush(stdout);
    long pid = getpid(), tid = syscall(SYS_gettid);
    __asm__ volatile("mov $0x10000, %%rsp\n\t"
                     "syscall\n\t"
                     "ud2"
                     :
                     : "a"(SYS_tgkill), "D"(pid), "S"(tid), "d"(SIGUSR1)
                     : "rcx", "r11", "memory");
    return 1;
}
