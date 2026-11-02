/* abort() de la glibc : débloque SIGABRT, puis se l'envoie (tgkill).
 * Laissé à son action par défaut, il termine le programme (code 134,
 * 128 + 6). Si claude plante un jour, c'est ce qu'on verra. */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    puts("[linux] Test : abort().");
    fflush(stdout);
    abort();
}
