/* Un programme qui s'envoie SIGTERM (raise : tgkill, au fil), laissé à son
 * action par défaut : il est terminé, code 143 (128 + 15), sous Linux comme
 * chez nous. Le noyau le dit.
 *
 * Avant, il bloque SIGHUP et SIGTERM et s'envoie d'abord SIGHUP par kill,
 * au processus : au déblocage, les deux attendent, et Linux livre ceux du
 * fil avant ceux du processus (dequeue_signal), donc SIGTERM, bien que
 * SIGHUP soit plus petit et arrivé avant (mesuré : 143, pas 129). */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    puts("[linux] Test : kill(SIGHUP) puis raise(SIGTERM), bloques, puis debloques.");
    fflush(stdout);
    sigset_t deux;
    sigemptyset(&deux);
    sigaddset(&deux, SIGHUP);
    sigaddset(&deux, SIGTERM);
    sigprocmask(SIG_BLOCK, &deux, NULL);
    kill(getpid(), SIGHUP);
    raise(SIGTERM);
    sigprocmask(SIG_UNBLOCK, &deux, NULL);
    puts("[linux] sig-term : ECHEC, toujours la apres SIGTERM");
    return 1;
}
