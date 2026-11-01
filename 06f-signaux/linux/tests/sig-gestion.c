/* Un gestionnaire de SIGUSR1, puis raise(SIGUSR1). Sous Linux, le
 * gestionnaire est appelé et le programme continue ; notre noyau
 * n'appelle les gestionnaires qu'en 6f : d'ici là, il arrête le programme
 * et le dit (code 138, 128 + 10). */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void gestionnaire(int sig)
{
    (void)sig;
    static const char m[] = "[linux] sig-gestion : gestionnaire appele (Linux le fait ; notre noyau en 6f)\n";
    if (write(1, m, sizeof m - 1) < 0)
        _exit(2);
}

int main(void)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = gestionnaire;
    sigaction(SIGUSR1, &a, NULL);
    puts("[linux] Test : un gestionnaire de SIGUSR1, puis raise(SIGUSR1).");
    fflush(stdout);
    raise(SIGUSR1);
    puts("[linux] sig-gestion : apres le gestionnaire");
    return 0;
}
