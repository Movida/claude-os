/* SIGXCPU ignoré, sous RLIMIT_CPU (1 s, 2 s), et une boucle sans fin. À
 * une seconde, le noyau envoie SIGXCPU (jeté : il est ignoré) et relève la
 * limite courante d'une seconde, comme Linux : getrlimit la relit à 2. À
 * deux secondes, la limite dure : SIGKILL, qui ne s'ignore pas (code 137).
 * Sous Linux comme chez nous.
 *
 * QUAND la limite tombe est vérifié aussi : le temps de calcul lu dès que
 * la limite relevée se voit doit être entre 0,9 et 1,1 s. Chez nous, une
 * seconde et au plus un tic ; sous Linux, un peu MOINS d'une seconde
 * (mesuré : 0,96 s, Linux 6.18 sous WSL2). Sans
 * cela, une limite comptée deux fois trop tard passerait inaperçue : le
 * message du noyau donne la limite, pas le temps mesuré. */
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

int main(void)
{
    signal(SIGXCPU, SIG_IGN);
    struct rlimit l = { 1, 2 };
    setrlimit(RLIMIT_CPU, &l);
    puts("[linux] Test : SIGXCPU ignore, sous RLIMIT_CPU (1 s, 2 s).");
    fflush(stdout);
    int dit = 0;
    for (;;) {
        getrlimit(RLIMIT_CPU, &l);
        if (!dit && l.rlim_cur == 2) {
            struct timespec t;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
            long ms = t.tv_sec * 1000 + t.tv_nsec / 1000000;
            printf("[linux] xcpu-ignore : SIGXCPU ignore, limite courante relevee a 2 s apres 1 s de calcul : %s\n",
                   ms >= 900 && ms < 1100 ? "ok" : "ECHEC");
            fflush(stdout);
            dit = 1;
        }
    }
}
