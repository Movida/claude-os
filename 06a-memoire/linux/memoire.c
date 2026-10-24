/*
 * Les appels système de la mémoire (mmap, munmap, mprotect, madvise),
 * contre ce qu'en fait le vrai Linux. Ce programme tourne dans notre noyau
 * ET sous Linux, sur la machine hôte (`make tests-hote` le lance) : chaque
 * ligne doit dire « ok » des deux côtés. C'est la vérification
 * automatique que nos codes d'erreur et nos comportements sont ceux de
 * Linux.
 *
 * Rien ici ne doit dépendre des réglages de la machine hôte : la quantité
 * de mémoire, vm.overcommit_memory, vm.mmap_min_addr (4096 dans un
 * conteneur, 65 536 sur Ubuntu). Les cas qui en dépendent (le
 * surengagement, le tueur OOM) sont testés dans QEMU seulement
 * (linux/tests/). Les adresses de l'hôte changent à chaque lancement
 * (ASLR) : on n'affiche que des faits, jamais d'adresse.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] memoire : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        echecs++;
}

#define PAGE 4096UL
#define GIO (1UL << 30)

/* mmap, et le code d'erreur s'il échoue (0 sinon). */
static char *projeter(void *adresse, size_t longueur, int prot, int drapeaux, int *erreur)
{
    errno = 0;
    char *p = mmap(adresse, longueur, prot, drapeaux, -1, 0);
    *erreur = p == MAP_FAILED ? errno : 0;
    return p;
}

static char *anonyme(void *adresse, size_t longueur, int drapeaux)
{
    int erreur;
    return projeter(adresse, longueur, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | drapeaux, &erreur);
}

/* L'erreur que rend mmap pour ces arguments, ou 0 s'il réussit. */
static int erreur_mmap(void *adresse, size_t longueur, int prot, int drapeaux, int fichier, off_t decalage)
{
    errno = 0;
    void *p = mmap(adresse, longueur, prot, drapeaux, fichier, decalage);
    if (p == MAP_FAILED)
        return errno;
    munmap(p, longueur);
    return 0;
}

static int erreur_de(int resultat)
{
    return resultat == -1 ? errno : 0;
}

/* 8 Gio réservés sans réservation de mémoire (MAP_NORESERVE) : ils ne
 * coûtent que ce qu'on touche. Trois pages écrites loin les unes des
 * autres, relues, puis tout est rendu. Sur une machine de 128 Mio. */
static void huit_gio(void)
{
    size_t taille = 8 * GIO;
    char *p = anonyme(NULL, taille, MAP_NORESERVE);
    int ok = p != MAP_FAILED;
    if (ok) {
        p[0] = 1;
        p[taille / 2] = 2;
        p[taille - 1] = 3;
        ok = p[0] == 1 && p[taille / 2] == 2 && p[taille - 1] == 3 && p[PAGE] == 0;
        ok = ok && munmap(p, taille) == 0;
    }
    verifier(ok, "8 Gio reserves (MAP_NORESERVE), trois pages ecrites loin l'une de l'autre, rendus");
}

/* L'adresse suggérée : suivie si la place est libre, arrondie à la page
 * inférieure, ignorée si la place est prise. MAP_FIXED remplace ce qui
 * est là ; MAP_FIXED_NOREPLACE refuse (EEXIST). */
static void adresses(void)
{
    char *suggestion = (char *)0x200000000;
    char *p = anonyme(suggestion, 2 * PAGE, 0);
    verifier(p == suggestion, "adresse suggeree libre : suivie");
    char *q = anonyme(suggestion, PAGE, 0);
    verifier(q != MAP_FAILED && q != suggestion, "adresse suggeree occupee : ignoree");
    munmap(q, PAGE);
    char *r = anonyme(suggestion + 16 * PAGE + 0x123, PAGE, 0);
    verifier(r == suggestion + 16 * PAGE, "adresse suggeree non alignee : arrondie a la page inferieure");
    munmap(r, PAGE);

    p[0] = 'A';
    p[PAGE] = 'B';
    char *f = anonyme(p, PAGE, MAP_FIXED);
    verifier(f == p && p[0] == 0 && p[PAGE] == 'B', "MAP_FIXED remplace ce qui est la, et seulement cela");
    int erreur;
    projeter(p + PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, &erreur);
    verifier(erreur == EEXIST && p[PAGE] == 'B', "MAP_FIXED_NOREPLACE sur une page prise : EEXIST");
    char *n = projeter(p + 2 * PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, &erreur);
    verifier(n == p + 2 * PAGE, "MAP_FIXED_NOREPLACE sur une page libre : accepte");
    munmap(p, 3 * PAGE);
}

/* Les refus, avec les codes d'erreur de Linux. */
static void erreurs(void)
{
    int rw = PROT_READ | PROT_WRITE, pa = MAP_PRIVATE | MAP_ANONYMOUS;
    verifier(erreur_mmap(NULL, 0, rw, pa, -1, 0) == EINVAL, "mmap de longueur nulle : EINVAL");
    verifier(erreur_mmap(NULL, PAGE, rw, MAP_ANONYMOUS, -1, 0) == EINVAL, "mmap ni prive ni partage : EINVAL");
    verifier(erreur_mmap((void *)0x200000001, PAGE, rw, pa | MAP_FIXED, -1, 0) == EINVAL,
             "MAP_FIXED non aligne : EINVAL");
    verifier(erreur_mmap(NULL, PAGE, rw, pa, -1, 1) == EINVAL, "decalage non aligne : EINVAL");
    verifier(erreur_mmap(NULL, 1UL << 47, rw, pa | MAP_NORESERVE, -1, 0) == ENOMEM, "128 Tio : ENOMEM");
    verifier(erreur_mmap(NULL, PAGE, rw, MAP_PRIVATE, -1, 0) == EBADF, "sans MAP_ANONYMOUS ni fichier : EBADF");
    verifier(erreur_mmap(NULL, PAGE, rw, pa | MAP_FIXED, -1, 0) == EPERM, "MAP_FIXED a l'adresse 0 : EPERM");
    verifier(erreur_mmap((void *)0x7ffffffff000, PAGE, rw, pa | MAP_FIXED, -1, 0) == ENOMEM,
             "MAP_FIXED dans la derniere page : ENOMEM");
    verifier(erreur_de(munmap((void *)0x200000001, PAGE)) == EINVAL, "munmap non aligne : EINVAL");
    verifier(erreur_de(munmap((void *)0x200000000, 0)) == EINVAL, "munmap de longueur nulle : EINVAL");
    verifier(erreur_de(munmap((void *)0x7ffffffff000, PAGE)) == EINVAL, "munmap de la derniere page : EINVAL");
    verifier(munmap((void *)0x500000000, PAGE) == 0, "munmap ou rien n'est projete : 0");
}

/* 64 Gio réservés, une page écrite à chaque bout, puis rendus d'un seul
 * munmap. Le parcours des tables saute ce qui n'est pas projeté : page par
 * page, il ferait seize millions de tours, bien plus que le budget de
 * temps du programme dans QEMU. */
static void soixante_quatre_gio(void)
{
    size_t taille = 64 * GIO;
    char *p = anonyme(NULL, taille, MAP_NORESERVE);
    int ok = p != MAP_FAILED;
    if (ok) {
        p[0] = 1;
        p[taille - 1] = 1;
        ok = munmap(p, taille) == 0;
    }
    verifier(ok, "64 Gio reserves puis rendus d'un seul munmap");
}

/* Un munmap au milieu d'une zone la coupe en deux : les deux bouts
 * restent là, avec leur contenu, et le milieu est libre. */
static void coupe(void)
{
    char *p = anonyme(NULL, 3 * PAGE, 0);
    p[0] = 'a';
    p[PAGE] = 'b';
    p[2 * PAGE] = 'c';
    int ok = munmap(p + PAGE, PAGE) == 0;
    p[0]++;
    p[2 * PAGE]++;
    ok = ok && p[0] == 'b' && p[2 * PAGE] == 'd';
    int erreur;
    char *milieu = projeter(p + PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, &erreur);
    ok = ok && milieu == p + PAGE && milieu[0] == 0;
    verifier(ok, "munmap au milieu d'une zone : deux bouts intacts, un trou");
    munmap(p, 3 * PAGE);
}

/* MAP_POPULATE : les pages sont mises en place d'avance, à zéro. */
static void populate(void)
{
    char *p = anonyme(NULL, 16 * PAGE, MAP_POPULATE);
    int ok = p != MAP_FAILED;
    for (size_t i = 0; ok && i < 16 * PAGE; i += PAGE)
        ok = p[i] == 0;
    if (ok)
        p[15 * PAGE] = 1;
    verifier(ok && munmap(p, 16 * PAGE) == 0, "MAP_POPULATE : 16 pages en place, a zero");
}

/* sysinfo : de quoi se dimensionner. */
static void informations(void)
{
    struct sysinfo s;
    int ok = sysinfo(&s) == 0 && s.mem_unit >= 1 && s.totalram > 0 && s.freeram <= s.totalram;
    verifier(ok, "sysinfo : memoire totale et libre");
}

int main(void)
{
    huit_gio();
    adresses();
    erreurs();
    soixante_quatre_gio();
    coupe();
    populate();
    informations();
    printf("[linux] memoire : %s\n", echecs == 0 ? "toutes les verifications : ok" : "ECHEC");
    return echecs != 0;
}
