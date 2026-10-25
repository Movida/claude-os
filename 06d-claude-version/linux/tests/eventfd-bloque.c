/* Lire un eventfd vide, en bloquant : avec un seul fil, personne ne
 * l'écrira jamais. Linux laisserait le programme bloqué pour toujours (sur
 * l'hôte, ce programme ne finit pas) ; notre noyau l'arrête et le dit
 * (SIGKILL, code 137), comme un futex attendu sans délai. */
#include <stdint.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>

int main(void)
{
    int e = eventfd(0, 0);
    uint64_t v;
    puts("[linux] Test : read bloquant d'un eventfd vide.");
    fflush(stdout);
    if (read(e, &v, 8) >= 0)
        puts("[linux] eventfd-bloque : ECHEC, lu");
    return 1;
}
