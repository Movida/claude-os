/* Un gestionnaire de SIGSEGV (comme celui de Bun), puis une écriture à
 * l'adresse 0. Sous Linux, le gestionnaire est appelé (il sort avec 0) ;
 * notre noyau arrête le programme comme toute faute, et son message dit
 * qu'un gestionnaire attendait (livraison en 6f) : code 139. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void gestionnaire(int sig)
{
    (void)sig;
    static const char m[] = "[linux] sig-faute : gestionnaire appele (Linux le fait ; notre noyau en 6f)\n";
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
    _exit(0);
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = gestionnaire;
    sigaction(SIGSEGV, &a, NULL);
    puts("[linux] Test : un gestionnaire de SIGSEGV, puis une faute.");
    fflush(stdout);
    *(volatile int *)0 = 1;
    return 1;
}
