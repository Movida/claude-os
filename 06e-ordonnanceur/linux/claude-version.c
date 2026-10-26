/*
 * La mémoire de `claude --version`, rejouée. Le vrai binaire de Claude Code
 * (2.1.310, Bun 1.4.4) a été tracé par strace sur Linux (la trace est dans
 * les fichiers du projet, etape-06/claude-version.strace : 574 appels) ;
 * ce programme refait, dans le même ordre et avec les mêmes tailles, ses
 * appels de mémoire ANONYME : ceux de ld-linux pour ses bibliothèques, puis
 * ceux de JavaScriptCore, le moteur JavaScript de Bun. Les projections de
 * FICHIERS (les .so) attendent 6b ; le reste est là.
 *
 * Les adresses changent (ASLR sur l'hôte) : on garde les tailles, les
 * drapeaux, les droits, l'adresse suggérée de 1 Gio, et la façon dont
 * JavaScriptCore aligne sa réservation de 8 Gio (réserver large, puis
 * rogner les deux bouts). Puis des pages écrites et relues comme le
 * ferait le ramasse-miettes, et rendues par centaines (MADV_DONTNEED).
 *
 * Il tourne sur l'hôte (sous Linux, la séquence réussit) et dans notre
 * noyau, sur 128 Mio : « [linux] Memoire de claude --version rejouee :
 * ok. » Un échec dit à quelle étape.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>

#define PAGE 4096UL
#define KIO 1024UL
#define MIO (1024 * KIO)
#define GIO (1024 * MIO)

static int echecs;

static void etape(int ok, const char *quoi)
{
    if (!ok) {
        printf("[linux] claude-version : ECHEC a l'etape : %s\n", quoi);
        echecs++;
    }
}

static char *anonyme(void *adresse, size_t longueur, int prot, int drapeaux)
{
    return mmap(adresse, longueur, prot, MAP_PRIVATE | MAP_ANONYMOUS | drapeaux, -1, 0);
}

/* La section .bun de Bun : le programme JavaScript embarqué, dans un
 * segment inscriptible du binaire (176 Mo dans claude, 128 Kio ici : le
 * chargeur lit l'archive au démarrage, chaque Mio coûte un quart de
 * seconde dans QEMU).
 * Initialisée, donc dans le fichier : MADV_DONTNEED doit y laisser son
 * contenu (Linux relit le fichier ; notre noyau, en 6a, n'y touche pas). */
static unsigned char bun[128 * KIO] __attribute__((aligned(4096))) = { [0 ... 128 * KIO - 1] = 0x5a };

/* Des données que le programme remet en lecture seule (mprotect(0x6e30000,
 * 16384, PROT_READ) dans la trace). */
static unsigned char relro[4 * PAGE] __attribute__((aligned(4096))) = { 1 };

/* Ce que fait ld-linux avant main : de petites zones, une zone fixe posée
 * dans une réservation (le .bss d'une bibliothèque), la remise en lecture
 * seule de ses tables (RELRO), un munmap d'une longueur qui n'est pas un
 * multiple de la page. */
static void ld_linux(void)
{
    char *a = anonyme(NULL, 8192, PROT_READ | PROT_WRITE, 0);
    char *b = anonyme(NULL, 8192, PROT_READ | PROT_WRITE, 0);
    char *c = anonyme(NULL, 32768, PROT_READ | PROT_WRITE, 0);
    etape(a != MAP_FAILED && b != MAP_FAILED && c != MAP_FAILED, "petites zones de ld-linux");
    char *bibliotheque = anonyme(NULL, 128 * KIO, PROT_READ, 0);
    char *bss = anonyme(bibliotheque + 64 * KIO, 52624, PROT_READ | PROT_WRITE, MAP_FIXED);
    etape(bss == bibliotheque + 64 * KIO, "zone fixe dans une reservation (MAP_FIXED)");
    bss[52623] = 1;
    etape(mprotect(bibliotheque + 64 * KIO, 16384, PROT_READ) == 0 && bss[52623] == 1, "RELRO");
    char *lu = anonyme(NULL, 44267, PROT_READ, 0);
    etape(lu != MAP_FAILED && munmap(lu, 44267) == 0, "munmap de 44267 octets");
}

/* JavaScriptCore : de quoi se dimensionner, puis ses réservations. */
static void javascriptcore(void)
{
    struct sysinfo s;
    etape(sysinfo(&s) == 0 && s.totalram > 0, "sysinfo");
    int rw = PROT_READ | PROT_WRITE;
    etape(anonyme(NULL, 2359296, rw, MAP_NORESERVE) != MAP_FAILED, "2,25 Mio sans reservation");
    char *suggestion = (char *)0x5547ca00000;
    char *gigaoctet = anonyme(suggestion, GIO, rw, MAP_NORESERVE);
    etape(gigaoctet == suggestion, "1 Gio a l'adresse suggeree");
    etape(anonyme(NULL, 64 * KIO, rw, MAP_NORESERVE) != MAP_FAILED, "64 Kio sans reservation");

    /* Les pages du programme lui-même : deux fautes d'avance, puis 327
     * MADV_WILLNEED de 128 Kio (sur la section .bun dans la trace). */
    etape(madvise(bun, PAGE, MADV_POPULATE_READ) == 0 && madvise(bun + 64 * KIO, PAGE, MADV_POPULATE_READ) == 0,
          "MADV_POPULATE_READ sur le programme");
    int ok = 1;
    for (int i = 0; i < 327; i++)
        ok = ok && madvise(bun, sizeof bun, MADV_WILLNEED) == 0;
    etape(ok, "327 MADV_WILLNEED");

    /* La mémoire du code compilé à la volée : 64 Mio lisibles, inscriptibles
     * ET exécutables, bordés de deux pages sans aucun droit, posées par
     * MAP_FIXED. Puis du code y est écrit et exécuté. */
    size_t taille_jit = 64 * MIO + 2 * PAGE;
    char *jit = anonyme(NULL, taille_jit, rw | PROT_EXEC, MAP_NORESERVE);
    etape(jit != MAP_FAILED, "64 Mio W+X");
    etape(anonyme(jit, PAGE, PROT_NONE, MAP_FIXED) == jit, "page de garde au debut");
    etape(anonyme(jit + taille_jit - PAGE, PAGE, PROT_NONE, MAP_FIXED) == jit + taille_jit - PAGE, "page de garde a la fin");
    etape(madvise(jit + PAGE, 64 * MIO, MADV_DONTFORK) == 0 && madvise(jit + PAGE, 64 * MIO, MADV_NOHUGEPAGE) == 0,
          "MADV_DONTFORK et NOHUGEPAGE sur le code");
    static const unsigned char code[] = { 0xb8, 42, 0, 0, 0, 0xc3 }; /* mov eax, 42 ; ret */
    memcpy(jit + PAGE + 32 * MIO, code, sizeof code);
    int (*fonction)(void) = (int (*)(void))(jit + PAGE + 32 * MIO);
    etape(fonction() == 42, "code compile a la volee, execute");

    /* Le tas des objets : 8 Gio réservés, pour en garder 4 alignés sur
     * 4 Gio ; les deux bouts sont rendus par munmap. */
    char *large = anonyme(NULL, 8 * GIO, rw, MAP_NORESERVE);
    etape(large != MAP_FAILED, "8 Gio sans reservation");
    etape(madvise(large, 8 * GIO, MADV_DONTFORK) == 0 && madvise(large, 8 * GIO, MADV_NOHUGEPAGE) == 0,
          "MADV_DONTFORK et NOHUGEPAGE sur 8 Gio");
    char *tas = (char *)(((uintptr_t)large + 4 * GIO - 1) & ~(4 * GIO - 1));
    size_t avant = tas - large, apres = large + 8 * GIO - (tas + 4 * GIO);
    etape((avant == 0 || munmap(large, avant) == 0) && (apres == 0 || munmap(tas + 4 * GIO, apres) == 0),
          "8 Gio rognes a 4 Gio alignes");
    etape(mprotect(tas + 64 * KIO, 11010048, rw) == 0, "mprotect dans le tas");
    etape(madvise(tas, 4 * GIO, MADV_DOFORK) == 0, "MADV_DOFORK sur 4 Gio");
    char *quatre = anonyme(NULL, 4 * MIO, rw, MAP_NORESERVE);
    etape(quatre != MAP_FAILED && madvise(quatre, 4 * MIO, MADV_NOHUGEPAGE) == 0, "4 Mio");
    etape(mprotect(tas + 0xa90000, 65536, rw) == 0 && mprotect(tas + 0xb10000, 524288, rw) == 0, "mprotect du tas");
    etape(anonyme(NULL, 64 * KIO, rw, MAP_NORESERVE) != MAP_FAILED, "64 Kio de plus");
    etape(mprotect(relro, sizeof relro, PROT_READ) == 0 && relro[0] == 1, "le programme remet ses donnees en lecture seule");
    char *compte = anonyme(NULL, 2121728, rw, 0);
    etape(compte != MAP_FAILED, "2 Mio comptes");

    /* Le ramasse-miettes : des pages écrites un peu partout dans le tas,
     * relues, puis rendues une à une (MADV_DONTNEED) : elles se relisent à
     * zéro, les autres gardent leur contenu. */
    enum { OBJETS = 512 };
    for (int i = 0; i < OBJETS; i++)
        tas[(size_t)i * 7 * MIO / 8 + i] = (char)(i | 1);
    ok = 1;
    for (int i = 0; i < OBJETS; i++)
        ok = ok && tas[(size_t)i * 7 * MIO / 8 + i] == (char)(i | 1);
    etape(ok, "512 pages du tas ecrites puis relues");
    for (int i = 0; i < OBJETS; i += 2) {
        char *page = (char *)((uintptr_t)(tas + (size_t)i * 7 * MIO / 8 + i) & ~(PAGE - 1));
        ok = ok && madvise(page, PAGE, MADV_DONTNEED) == 0;
    }
    for (int i = 0; i < OBJETS; i++)
        ok = ok && tas[(size_t)i * 7 * MIO / 8 + i] == (i % 2 == 0 ? 0 : (char)(i | 1));
    etape(ok, "256 MADV_DONTNEED : relues a zero, les autres intactes");

    /* Bun rend sa section .bun (54 Mo dans la trace) : son contenu doit
     * rester celui du fichier. */
    etape(madvise(bun, sizeof bun, MADV_DONTNEED) == 0, "MADV_DONTNEED sur le programme");
    ok = 1;
    for (size_t i = 0; i < sizeof bun; i += 1021)
        ok = ok && bun[i] == 0x5a;
    etape(ok, "la section .bun garde son contenu");
}

int main(void)
{
    ld_linux();
    javascriptcore();
    if (echecs == 0)
        printf("[linux] Memoire de claude --version rejouee : ok.\n");
    return echecs != 0;
}
