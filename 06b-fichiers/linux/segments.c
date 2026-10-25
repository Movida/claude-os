/*
 * Les segments d'un programme sont des projections de son fichier (6b) :
 *   - un grand tableau initialisé (2 Mio dans le segment de données, donc
 *     dans le fichier) n'est en mémoire que pour les pages touchées ;
 *   - une page de données écrite est une copie à lui ; MADV_DONTNEED la
 *     rend, et le programme relit la valeur du FICHIER (ce que fait Bun
 *     avec sa section .bun, dans la trace de `claude --version`), pas des
 *     zéros ;
 *   - une page du .bss, elle, se relit à zéro.
 * Il tourne aussi sur l'hôte, où Linux fait de même ; la mesure de la
 * mémoire (sysinfo) n'a de sens que chez nous, seul programme de la
 * machine.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define MIO (1024 * 1024)

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] segments : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* 2 Mio de données initialisées : dans le fichier, octet pour octet. */
static volatile unsigned char grand[2 * MIO] = {[0] = 1, [2 * MIO - 1] = 2};
/* Une page à elle, initialisée à 42 dans le fichier. */
static volatile int valeur[1024] __attribute__((aligned(4096))) = {42};
/* Une page du .bss. */
static volatile int vide[1024] __attribute__((aligned(4096)));

int main(void)
{
    int chez_nous = access("/etc/bonjour.txt", F_OK) == 0;
    struct sysinfo avant, apres;
    sysinfo(&avant);
    unsigned somme = grand[0] + grand[MIO] + grand[2 * MIO - 1];
    sysinfo(&apres);
    verifier(somme == 3, "un tableau de 2 Mio, lu en trois endroits");
    if (chez_nous) {
        long prises = (long)(avant.freeram - apres.freeram) / 4096;
        verifier(prises >= 0 && prises <= 8, "seules les pages touchees sont en memoire");
    }

    valeur[0] = 7;
    vide[0] = 7;
    verifier(valeur[0] == 7 && vide[0] == 7, "ecrire dans ses donnees et son .bss");
    long page = sysconf(_SC_PAGESIZE);
    verifier(madvise((void *)valeur, page, MADV_DONTNEED) == 0 && valeur[0] == 42,
             "MADV_DONTNEED sur une page de donnees : la valeur du fichier revient");
    verifier(madvise((void *)vide, page, MADV_DONTNEED) == 0 && vide[0] == 0,
             "MADV_DONTNEED sur une page du .bss : des zeros");
    printf("[linux] segments : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
