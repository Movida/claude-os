/*
 * Un programme Linux ordinaire, écrit en C et compilé normalement :
 * `gcc -static`, avec la glibc d'Ubuntu. Il ne sait rien de notre OS ; il
 * tourne tel quel sous Linux (`./linux/construits/bonjour-c`), et dans
 * notre noyau, qui doit lui offrir ce que la glibc attend au démarrage :
 * la pile initiale (argc, argv, envp, le vecteur auxiliaire) et une
 * douzaine d'appels système (voir noyau/src/linux.rs).
 *
 * printf passe par le tampon de la sortie standard, puis par write ; le
 * tableau grandit par malloc, donc par brk ; getauxval lit le vecteur
 * auxiliaire que le noyau a posé sur la pile.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>

int main(int argc, char **argv)
{
    printf("[linux] Bonjour depuis un programme C, argc=%d, argv[0]=%s\n", argc, argv[0]);

    /* Assez gros pour que malloc demande de la mémoire au noyau (brk). */
    int n = 10000;
    long *carres = malloc(n * sizeof *carres);
    if (carres == NULL) {
        printf("[linux] malloc a echoue\n");
        return 1;
    }
    long somme = 0;
    for (int i = 0; i < n; i++) {
        carres[i] = (long)i * i;
        somme += carres[i];
    }
    free(carres);
    printf("[linux] Somme des %d premiers carres (malloc) : %ld\n", n, somme);
    printf("[linux] Taille de page (AT_PAGESZ) : %lu\n", getauxval(AT_PAGESZ));
    return 0;
}
