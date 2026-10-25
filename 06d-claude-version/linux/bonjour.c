/*
 * Un programme Linux ordinaire, écrit en C et compilé normalement. Il ne
 * sait rien de notre OS ; il tourne tel quel sous Linux
 * (`./linux/construits/bonjour-c`), et dans notre noyau, qui doit lui
 * offrir ce que la glibc attend au démarrage : la pile initiale (argc,
 * argv, envp, le vecteur auxiliaire) et une douzaine d'appels système
 * (voir noyau/src/linux.rs).
 *
 * Le même source donne plusieurs exécutables (voir le Makefile) :
 * `gcc -static` (un ET_EXEC, à des adresses fixes), `gcc -static-pie` (un
 * ET_DYN qui se reloge lui-même), `gcc` sans option (un ET_DYN qui demande
 * ld-linux et la glibc partagée). Leurs lignes doivent se distinguer, sinon
 * les lignes attendues passeraient dès que l'un d'eux tourne : la dernière
 * ligne donne le chemin du programme et ce qu'il sait de son chargement
 * (AT_BASE, l'adresse de l'interpréteur, nulle sans lui).
 *
 * printf passe par le tampon de la sortie standard, puis par write ; le
 * tableau grandit par malloc, donc par brk ; getauxval lit le vecteur
 * auxiliaire que le noyau a posé sur la pile. Une écriture qui échoue
 * donne le code de sortie 1 : ce qui n'est pas affiché ne doit pas passer
 * pour réussi.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>

/* Le point d'entrée du programme (crt1.o de la glibc). */
extern char _start[];

int main(int argc, char **argv)
{
    int echec = 0;
    echec |= printf("[linux] Bonjour depuis un programme C, argc=%d, argv[0]=%s\n", argc, argv[0]) < 0;

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
    echec |= printf("[linux] Somme des %d premiers carres (malloc) : %ld\n", n, somme) < 0;
    echec |= printf("[linux] Taille de page (AT_PAGESZ) : %lu\n", getauxval(AT_PAGESZ)) < 0;

    /* AT_ENTRY : toujours le point d'entrée du programme, même quand le
     * noyau a commencé par ld-linux (et ld-linux, lancé à la main, le
     * réécrit avant de donner la main). AT_BASE : où est ld-linux, s'il a
     * été chargé par le noyau ; 0 pour un programme statique, ou quand
     * ld-linux est lui-même le programme lancé. */
    int entree = getauxval(AT_ENTRY) == (unsigned long)_start;
    echec |= !entree;
    echec |= printf("[linux] %s : %s, AT_ENTRY = _start : %s.\n", argv[0],
                    getauxval(AT_BASE) ? "AT_BASE non nul (interpreteur charge par le noyau)" : "AT_BASE nul (sans interpreteur)",
                    entree ? "ok" : "ECHEC") < 0;
    echec |= fflush(stdout) != 0 || ferror(stdout);
    return echec;
}
